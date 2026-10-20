"""Tenant-authenticated API: extension ingest (events, blocklist, auth-events, heartbeat, verify answer)
and SIEM alert intake. See console/README.md for the request/response shapes."""
import hashlib
import re
import uuid
from collections import Counter
from datetime import datetime, timedelta

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from . import config, outbound
from .db import get_db, utcnow
from .eventview import summary as event_summary
from .models import (Alert, AuthEvent, BlockedDomain, Enrollment, Event, FeedDomain, FeedRun, Heartbeat, Install,
                     Tenant, VerifyRequest, audit)
from .security import (client_ip, hash_api_key, new_api_key, new_install_token, require_tenant_key,
                       tenant_auth)
from .verify import apply_answer, process_alert

router = APIRouter(prefix="/v1")
MAX_BATCH = 50
EVENT_TYPES = {"url_blocked", "page_blocked", "page_warned", "credential_reuse_blocked", "phishing_email_detected",
               "user_report_site", "user_report_email", "user_bypass", "user_trusted_site",
               "auth_event", "verify_answer", "device_code_warning"}


def parse_ts(v) -> datetime:
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(v / 1000 if v > 1e11 else v).astimezone()
    if isinstance(v, str) and v:
        try:
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=utcnow().tzinfo)
        except ValueError:
            pass
    return utcnow()


def _s(v, n=255):
    return str(v)[:n] if v not in (None, "") else None


def _batch(body) -> list[dict]:
    items = body.get("events") if isinstance(body, dict) else None
    if not isinstance(items, list):
        raise HTTPException(422, "body must be {\"events\": [ ... ]}")
    if len(items) > MAX_BATCH:
        raise HTTPException(413, f"max {MAX_BATCH} events per batch")
    return [e for e in items if isinstance(e, dict)]


def _pinned(request: Request, given):
    """A self-enrolled token speaks for its own install only: ignore any installId the body claims."""
    return getattr(request.state, "install_id", None) or given


def _as_bool(v) -> bool:
    return v if isinstance(v, bool) else str(v).strip().lower() in ("1", "true", "yes", "on")


def _as_int(v, default: int) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------- installs / binding

def touch_install(db: Session, tenant: Tenant, install_id: str | None, ip=None, user_id=None, version=None,
                  ua=None, browser=None, accounts=None, seen=True) -> Install | None:
    if not install_id:
        return None
    inst = db.scalars(select(Install).where(Install.tenant_id == tenant.id,
                                            Install.install_id == install_id)).first()
    if not inst:
        inst = Install(tenant_id=tenant.id, install_id=_s(install_id, 64), accounts=[], hint_counts={})
        db.add(inst)
        audit(db, f"install:{install_id}", "install_registered", tenant.id, install_id)
    if seen:
        inst.last_seen = utcnow()
        if ip:
            inst.last_ip = ip
    inst.version = _s(version, 32) or inst.version
    inst.ua = _s(ua, 1000) or inst.ua
    inst.browser = _s(browser, 100) or inst.browser
    if isinstance(accounts, list):
        inst.accounts = sorted({str(a).lower() for a in accounts if a and "@" in str(a)})[:20]
    _bind(db, inst, user_id)
    return inst


def _bind(db: Session, inst: Install, policy_user: str | None):
    """Identity binding (§3): policy userId first, then the most frequent successful account hint."""
    old = inst.upn
    if policy_user:
        inst.upn, inst.upn_source = policy_user.lower(), "policy"
    elif inst.upn_source != "policy" and inst.hint_counts:
        upn, _ = Counter(inst.hint_counts).most_common(1)[0]
        inst.upn, inst.upn_source = upn, "account_hint"
    if inst.upn != old:
        audit(db, "system", "install_bound", inst.tenant_id, inst.install_id, upn=inst.upn, source=inst.upn_source,
              previous=old)


def store_auth_events(db: Session, tenant: Tenant, items: list[dict], ip) -> int:
    ids = [str(e.get("id")) for e in items if e.get("id")]
    have = set(db.scalars(select(AuthEvent.event_id).where(AuthEvent.tenant_id == tenant.id,
                                                           AuthEvent.event_id.in_(ids))).all()) if ids else set()
    n = 0
    for e in items:
        eid = str(e.get("id") or "")
        if not eid or eid in have:
            continue
        have.add(eid)
        hint = (_s(e.get("accountHint"), 320) or "").lower() or None
        ae = AuthEvent(tenant_id=tenant.id, event_id=eid[:64], install_id=_s(e.get("installId"), 64),
                       ts=parse_ts(e.get("ts")), idp=(_s(e.get("idp"), 32) or "microsoft").lower(),
                       host=_s(e.get("host")), tenant_hint=_s(e.get("tenantHint")), account_hint=hint,
                       flow=_s(e.get("flow"), 32), outcome=(_s(e.get("outcome"), 32) or "unknown").lower(),
                       referrer_host=_s(e.get("referrerHost")), opener_host=_s(e.get("openerHost")),
                       user_id=_s(e.get("userId"), 320), ip=_s(e.get("ip"), 64) or ip)
        db.add(ae)
        n += 1
        inst = touch_install(db, tenant, ae.install_id, ip=ip, user_id=ae.user_id, version=e.get("version"),
                             ua=e.get("ua"))
        if inst and hint and ae.outcome == "success":
            hc = dict(inst.hint_counts or {})
            hc[hint] = hc.get(hint, 0) + 1
            inst.hint_counts = hc
            _bind(db, inst, ae.user_id)
    return n


# ---------------------------------------------------------------- extension endpoints

@router.post("/events")
def post_events(request: Request, body: dict = Body(...), tenant: Tenant = Depends(tenant_auth),
                db: Session = Depends(get_db)):
    items = _batch(body)
    enr = getattr(request.state, "enrollment", None)
    if enr and enr.reporting == "off":
        return {"ok": True, "accepted": 0, "authEvents": 0, "reporting": "off"}  # user chose "protect only"
    for e in items:
        e["installId"] = _pinned(request, e.get("installId"))
    ip = client_ip(request)
    ids = [str(e.get("id")) for e in items if e.get("id")]
    have = set(db.scalars(select(Event.event_id).where(Event.tenant_id == tenant.id, Event.event_id.in_(ids))).all()) \
        if ids else set()
    stored, auth_items, new = 0, [], []
    for e in items:
        eid = str(e.get("id") or "")
        if not eid or eid in have:
            continue
        have.add(eid)
        etype = _s(e.get("type"), 64) or "unknown"
        sev = (_s(e.get("severity"), 16) or "").lower() or None
        ev = Event(tenant_id=tenant.id, event_id=eid[:64], type=etype, severity=sev,
                   ts=parse_ts(e.get("ts")), host=(_s(e.get("host")) or "").lower() or None,
                   user_id=_s(e.get("userId"), 320), install_id=_s(e.get("installId"), 64), ip=ip, data=e)
        db.add(ev)
        new.append(ev)
        stored += 1
        touch_install(db, tenant, e.get("installId"), ip=ip, user_id=e.get("userId"), version=e.get("version"),
                      ua=e.get("ua"))
        if etype in ("auth_event", "device_code_warning"):
            auth_items.append(dict(e, flow=e.get("flow") or ("device_code" if etype == "device_code_warning" else None)))
        elif etype == "verify_answer" and e.get("verifyId") and e.get("answer") in ("yes", "no"):
            vr = db.get(VerifyRequest, str(e["verifyId"]))
            if vr and vr.tenant_id == tenant.id and vr.status == "pending" and vr.expires_at > utcnow():
                inst = touch_install(db, tenant, e.get("installId"), seen=False)
                if inst and vr.upn in inst.bound_upns():
                    apply_answer(db, vr, e["answer"], inst.install_id, ip)
    db.flush()
    outbound.enqueue(db, tenant, new)  # notifications + SIEM export, sent by the job loop
    auth_n = store_auth_events(db, tenant, auth_items, ip) if auth_items else 0
    return {"ok": True, "accepted": stored, "authEvents": auth_n}


_blocklist_cache: dict[str, tuple] = {}  # tenant -> (signature, domains, etag)


def blocklist_for(db: Session, tenant: Tenant) -> tuple[list[str], str]:
    """Tenant + global entries, plus threat-feed domains when the tenant has feeds on. Rebuilt only when
    the blocklist or a finished feed run changes (cheap signature), so every browser polling every
    15 min does not re-sort ~30k domains."""
    feeds_on = _as_bool(tenant.setting("threat_feeds"))
    scope = or_(BlockedDomain.tenant_id == tenant.id, BlockedDomain.tenant_id.is_(None))
    sig = (feeds_on, tuple(db.execute(select(func.count(BlockedDomain.id), func.max(BlockedDomain.id)).where(scope)).one()),
           db.scalar(select(func.max(FeedRun.id)).where(FeedRun.status.in_(("ok", "partial")))) if feeds_on else None)
    hit = _blocklist_cache.get(tenant.id)
    if hit and hit[0] == sig:
        return hit[1], hit[2]
    rows = set(db.scalars(select(BlockedDomain.domain).where(scope)).all())
    if feeds_on:
        rows.update(db.scalars(select(FeedDomain.domain)).all())
    domains = sorted(rows)
    etag = '"' + hashlib.sha256("\n".join(domains).encode()).hexdigest()[:32] + '"'
    _blocklist_cache[tenant.id] = (sig, domains, etag)
    return domains, etag


@router.get("/blocklist")
def get_blocklist(request: Request, tenant: Tenant = Depends(tenant_auth), db: Session = Depends(get_db)):
    domains, etag = blocklist_for(db, tenant)
    # Cloudflare weakens ETags it compresses (W/"..."), so compare the bare value.
    sent = {t.strip().removeprefix("W/") for t in request.headers.get("if-none-match", "").split(",")}
    if etag in sent:
        return Response(status_code=304, headers={"ETag": etag})
    return JSONResponse({"domains": domains}, headers={"ETag": etag, "Cache-Control": "private, no-cache"})


# ---------------------------------------------------------------- community self-enrollment + remote policy

EXT_POLICY = {  # extension setting -> tenant setting
    "warnThreshold": "ext_warn_threshold", "blockThreshold": "ext_block_threshold",
    "allowUserBypass": "ext_allow_bypass", "credentialGuard": "ext_credential_guard",
    "webmailScanner": "ext_webmail_scanner", "pageScanner": "ext_page_scanner", "domainAgeLookup": "ext_domain_age",
    "verifyEnabled": "ext_verify",
}
NICK_STRIP = re.compile(r"[^\w .@'-]", re.UNICODE)


def policy_for(t: Tenant) -> dict:
    out = {}
    for k, s in EXT_POLICY.items():
        v = t.setting(s)
        out[k] = _as_int(v, 0) if k.endswith("Threshold") else _as_bool(v)
    if t.id == config.COMMUNITY_TENANT:
        out["verifyEnabled"] = False  # community users were promised: no sign-in records
    if not 0 < out["warnThreshold"] < out["blockThreshold"] <= 100:
        out.pop("warnThreshold"), out.pop("blockThreshold")  # bad values: let the extension keep its own
    return out


def community_tenant(db: Session) -> Tenant:
    t = db.get(Tenant, config.COMMUNITY_TENANT)
    if not t:
        # The tenant key is random and never shown: community browsers authenticate with install tokens.
        key = new_api_key()
        t = Tenant(id=config.COMMUNITY_TENANT, name="Community (self-enrolled)", api_key_hash=hash_api_key(key),
                   api_key_hint=key[-4:], settings={})
        db.add(t)
        audit(db, "system", "tenant_created", t.id, t.id, via="community_enroll")
        db.flush()
    return t


@router.post("/enroll")
def enroll(request: Request, body: dict = Body(...), db: Session = Depends(get_db)):
    """Zero-config onboarding: an extension with no configured key asks for its own revocable token."""
    if not config.COMMUNITY_ENROLL:
        raise HTTPException(403, "enrollment is closed")
    iid = str(body.get("installId") or "")
    try:
        iid = str(uuid.UUID(iid))
    except ValueError:
        raise HTTPException(422, "installId must be a UUID")
    ip = client_ip(request)
    tenant = community_tenant(db)
    if ip and (db.scalar(select(func.count(Enrollment.id)).where(
            Enrollment.created_ip == ip, Enrollment.created_at > utcnow() - timedelta(hours=1))) or 0) \
            >= config.ENROLL_MAX_PER_IP_HOUR:
        raise HTTPException(429, "too many enrollments from this network, try again later")
    if (db.scalar(select(func.count(Enrollment.id)).where(
            Enrollment.tenant_id == tenant.id, Enrollment.revoked_at.is_(None))) or 0) >= config.ENROLL_MAX_TOTAL:
        raise HTTPException(403, "community is full")
    if db.scalars(select(Enrollment).where(Enrollment.install_id == iid)).first():
        raise HTTPException(409, "install already enrolled")
    nickname = NICK_STRIP.sub("", str(body.get("nickname") or "")).strip()[:60] or None
    reporting = "off" if body.get("reporting") == "off" else "full"
    token = new_install_token()
    db.add(Enrollment(tenant_id=tenant.id, install_id=iid, token_hash=hash_api_key(token), token_hint=token[-4:],
                      nickname=nickname, reporting=reporting, created_ip=ip))
    touch_install(db, tenant, iid, ip=ip, version=body.get("version"), ua=body.get("ua"), browser=body.get("browser"))
    audit(db, f"install:{iid}", "install_enrolled", tenant.id, iid, nickname=nickname, reporting=reporting)
    return {"ok": True, "token": token, "tenantId": tenant.id, "installId": iid, "reporting": reporting,
            "policy": policy_for(tenant)}


@router.get("/config")
def get_config(request: Request, reporting: str = "", tenant: Tenant = Depends(tenant_auth),
               db: Session = Depends(get_db)):
    """Remote extension policy. Enrolled installs also report their consent choice here."""
    e = getattr(request.state, "enrollment", None)
    if e:
        if reporting in ("full", "off") and e.reporting != reporting:
            e.reporting = reporting
            audit(db, f"install:{e.install_id}", "install_reporting_changed", tenant.id, e.install_id, reporting=reporting)
        touch_install(db, tenant, e.install_id, ip=client_ip(request))
    return {"ok": True, "policy": policy_for(tenant), "reporting": e.reporting if e else "full",
            "threatFeeds": _as_bool(tenant.setting("threat_feeds"))}


@router.post("/auth-events")
def post_auth_events(request: Request, body: dict = Body(...), tenant: Tenant = Depends(tenant_auth),
                     db: Session = Depends(get_db)):
    items = _batch(body)
    enr = getattr(request.state, "enrollment", None)
    if (enr and enr.reporting == "off") or tenant.id == config.COMMUNITY_TENANT:
        return {"ok": True, "accepted": 0, "reporting": "off"}  # no sign-in records for community installs
    for e in items:
        e["installId"] = _pinned(request, e.get("installId"))
    n = store_auth_events(db, tenant, items, client_ip(request))
    return {"ok": True, "accepted": n}


@router.post("/heartbeat")
def post_heartbeat(request: Request, body: dict = Body(...), tenant: Tenant = Depends(tenant_auth),
                   db: Session = Depends(get_db)):
    install_id = _pinned(request, body.get("installId"))
    if not install_id:
        raise HTTPException(422, "installId required")
    if tenant.id == config.COMMUNITY_TENANT:
        raise HTTPException(403, "Verify is not available for community installs")
    ip = client_ip(request)
    inst = touch_install(db, tenant, str(install_id), ip=ip, user_id=body.get("userId"), version=body.get("version"),
                         ua=body.get("ua"), browser=body.get("browser"), accounts=body.get("accounts"))
    db.add(Heartbeat(tenant_id=tenant.id, install_id=inst.install_id, ts=utcnow(), ip=ip))
    now = utcnow()
    upns = inst.bound_upns()
    pending = []
    if upns:
        rows = db.scalars(select(VerifyRequest).where(
            VerifyRequest.tenant_id == tenant.id, VerifyRequest.status == "pending",
            VerifyRequest.expires_at > now, VerifyRequest.upn.in_(sorted(upns))).order_by(VerifyRequest.created_at)).all()
        for vr in rows:
            alert = db.get(Alert, vr.alert_id)
            if not vr.delivered_at:
                vr.delivered_at = now
            if inst.install_id not in (vr.delivered_to or []):
                vr.delivered_to = list(vr.delivered_to or []) + [inst.install_id]
            pending.append({
                "id": vr.id, "upn": vr.upn, "prompt": vr.prompt, "app": alert.app, "idp": alert.idp,
                "ip": alert.ip, "location": alert.location, "clientApp": alert.client_app,
                "signInTime": alert.ts.isoformat().replace("+00:00", "Z"),
                "createdAt": vr.created_at.isoformat().replace("+00:00", "Z"),
                "expiresAt": vr.expires_at.isoformat().replace("+00:00", "Z"),
                "answerUrl": f"/v1/verify/{vr.id}/answer",
            })
    return {
        "ok": True, "serverTime": now.isoformat().replace("+00:00", "Z"), "seenIp": ip,
        "nextHeartbeatSec": config.HEARTBEAT_INTERVAL_SEC,
        "binding": {"upn": inst.upn, "source": inst.upn_source, "accounts": inst.accounts or [],
                    "confirmed": bool(inst.upn)},
        "verifyRequests": pending,
    }


@router.post("/verify/{verify_id}/answer")
def post_verify_answer(verify_id: str, request: Request, body: dict = Body(...),
                       tenant: Tenant = Depends(tenant_auth), db: Session = Depends(get_db)):
    answer = str(body.get("answer", "")).lower()
    if answer not in ("yes", "no"):
        raise HTTPException(422, "answer must be 'yes' or 'no'")
    vr = db.get(VerifyRequest, verify_id)
    if not vr or vr.tenant_id != tenant.id:
        raise HTTPException(404, "unknown verify request")
    inst = db.scalars(select(Install).where(
        Install.tenant_id == tenant.id, Install.install_id == str(_pinned(request, body.get("installId")) or ""))).first()
    if not inst or vr.upn not in inst.bound_upns():
        audit(db, f"install:{body.get('installId')}", "verify_answer_rejected", tenant.id, vr.alert_id,
              reason="install not bound to user")
        raise HTTPException(403, "this browser is not bound to the user being asked")
    if vr.status != "pending" or vr.expires_at <= utcnow():
        raise HTTPException(409, f"verify request is {vr.status if vr.status != 'pending' else 'expired'}")
    apply_answer(db, vr, answer, inst.install_id, client_ip(request))
    alert = db.get(Alert, vr.alert_id)
    return {"ok": True, "verifyId": vr.id, "status": vr.status, "verdict": alert.verdict}


# ---------------------------------------------------------------- SIEM alert intake

def _first(d: dict, *keys):
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return v
    return None


def normalize_alert(p: dict) -> dict:
    upn = _first(p, "upn", "userPrincipalName", "user", "userId", "accountname")
    if not upn:
        raise HTTPException(422, "alert needs upn (or userPrincipalName / user)")
    loc = _first(p, "location")
    if isinstance(loc, dict):
        loc = ", ".join(x for x in [loc.get("city"), loc.get("state"),
                                     loc.get("countryOrRegion") or loc.get("country")] if x)
    loc = loc or ", ".join(x for x in [p.get("city"), p.get("country")] if x) or None
    client_app = _first(p, "clientApp", "clientAppUsed")
    inter = _first(p, "isInteractive", "interactive")
    dev = p.get("deviceDetail") if isinstance(p.get("deviceDetail"), dict) else {}
    device = _first(p, "device") or "/".join(x for x in [dev.get("browser"), dev.get("operatingSystem")] if x) or None
    ticket = p.get("ticket") if isinstance(p.get("ticket"), dict) else {}
    ticket_id = ticket.get("id") or _first(p, "haloTicketId", "ticketId")
    return dict(
        source=(_s(_first(p, "source"), 32) or "generic").lower(),
        external_id=_s(_first(p, "externalId", "id", "incidentId", "correlationId"), 200),
        title=_s(_first(p, "title", "name", "alertName", "policyname"), 500),
        severity=_s(_first(p, "severity"), 32),
        upn=str(upn).strip().lower()[:320],
        ts=parse_ts(_first(p, "ts", "time", "createdDateTime", "eventTime")),
        ip=_s(_first(p, "ip", "ipAddress", "sourceIp"), 64),
        app=_s(_first(p, "app", "appDisplayName", "application"), 200),
        client_app=_s(client_app, 100),
        is_interactive=True if inter is None else (str(inter).lower() not in ("false", "0", "no")),
        idp=(_s(_first(p, "idp"), 32) or "microsoft").lower(),
        location=_s(loc, 200),
        ticket_system=(_s(ticket.get("system"), 32) or ("halopsa" if ticket_id else None)),
        ticket_id=_s(ticket_id, 100),
        raw=dict(p, _device=device),
    )


def alert_json(a: Alert, db: Session) -> dict:
    from .verify import latest_request
    vr = latest_request(db, a.id)
    return {
        "alertId": a.id, "tenantId": a.tenant_id, "source": a.source, "externalId": a.external_id, "upn": a.upn,
        "ts": a.ts.isoformat().replace("+00:00", "Z"), "ip": a.ip, "status": a.status, "verdict": a.verdict,
        "confidence": a.confidence, "suggestedAction": a.suggested_action, "shadowMode": True,
        "verifyRequest": {"id": vr.id, "status": vr.status, "answer": vr.answer,
                          "expiresAt": vr.expires_at.isoformat().replace("+00:00", "Z")} if vr else None,
        "evidence": a.evidence, "evidenceCard": {"markdown": a.card_md, "html": a.card_html},
    }


@router.post("/alerts")
def post_alerts(request: Request, body: dict = Body(...), tenant: Tenant = Depends(tenant_auth),
                db: Session = Depends(get_db)):
    require_tenant_key(request)
    items = body.get("alerts") if isinstance(body.get("alerts"), list) else [body]
    if len(items) > MAX_BATCH:
        raise HTTPException(413, f"max {MAX_BATCH} alerts per request")
    out = []
    for p in items:
        n = normalize_alert(p)
        existing = None
        if n["external_id"]:
            existing = db.scalars(select(Alert).where(Alert.tenant_id == tenant.id, Alert.source == n["source"],
                                                      Alert.external_id == n["external_id"])).first()
        if existing:
            out.append(dict(alert_json(existing, db), duplicate=True))
            continue
        a = Alert(tenant_id=tenant.id, **n)
        db.add(a)
        db.flush()
        audit(db, "api", "alert_received", tenant.id, a.id, source=a.source, externalId=a.external_id, upn=a.upn)
        process_alert(db, a)
        db.flush()
        out.append(alert_json(a, db))
    return out[0] if "alerts" not in body else {"results": out}


@router.get("/events")
def get_events(request: Request, after_id: int = 0, since: str = "", limit: int = 500,
               tenant: Tenant = Depends(tenant_auth), db: Session = Depends(get_db)):
    """SIEM pull: browser events after a cursor (`after_id`, from the previous response's `nextAfterId`)."""
    require_tenant_key(request)
    q = select(Event).where(Event.tenant_id == tenant.id, Event.id > max(0, after_id))
    if since:
        q = q.where(Event.received_at >= parse_ts(since))
    rows = db.scalars(q.order_by(Event.id).limit(max(1, min(limit, 1000)))).all()
    return {"events": [event_summary(e) for e in rows], "nextAfterId": rows[-1].id if rows else max(0, after_id)}


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: str, request: Request, tenant: Tenant = Depends(tenant_auth), db: Session = Depends(get_db)):
    require_tenant_key(request)
    a = db.get(Alert, alert_id)
    if not a or a.tenant_id != tenant.id:
        raise HTTPException(404, "unknown alert")
    audit(db, "api", "evidence_card_view", tenant.id, a.id)
    return alert_json(a, db)
