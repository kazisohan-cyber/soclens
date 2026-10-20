"""Login-protected multi-tenant dashboard: verify queue, verdict mix, coverage, shadow-mode agreement,
tenant/user admin, audit log. RBAC: mssp_admin (everything), analyst (view + feedback),
client_viewer (read-only, own tenant). A user with tenant_id set only sees that tenant."""
import json
import re
import secrets
import statistics
from collections import Counter
from datetime import timedelta
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from . import eventview, feeds, outbound
from .db import get_db, utcnow
from .models import (CONFIRMED_BY_BROWSER, DEFAULT_TENANT_SETTINGS, ROLES, SEVERITY_RANK, USER_CONFIRMED, VERDICTS, Alert,
                     AuditLog, BlockedDomain, ConsoleUser, Enrollment, Event, FeedDomain, FeedRun, Install, Outbound,
                     Tenant, VerifyRequest, WriteBack, audit)
from .security import check_password, client_ip, hash_api_key, hash_password, new_api_key

router = APIRouter(include_in_schema=False)
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
CLOSE_VERDICTS = {CONFIRMED_BY_BROWSER, USER_CONFIRMED}
VERDICT_COLORS = {"CONFIRMED_BY_BROWSER": "#1a7f37", "USER_CONFIRMED": "#4ac26b", "NOT_SEEN_IN_BROWSER": "#bf3989",
                  "USER_DENIED": "#cf222e", "NO_RESPONSE": "#d4a72c", "NO_COVERAGE": "#8c959f"}
templates.env.globals["VERDICT_COLORS"] = VERDICT_COLORS


def _login_redirect():
    raise HTTPException(status_code=303, headers={"Location": "/login"})


def current_user(request: Request, db: Session = Depends(get_db)) -> ConsoleUser:
    uid = request.session.get("uid")
    u = db.get(ConsoleUser, uid) if uid else None
    if not u or not u.active:
        _login_redirect()
    return u


def require(u: ConsoleUser, *roles):
    if u.role not in roles:
        raise HTTPException(403, "not allowed for your role")


def check_csrf(request: Request, token: str):
    if not token or token != request.session.get("csrf"):
        raise HTTPException(400, "bad CSRF token - reload the page")


def visible_tenants(db: Session, u: ConsoleUser) -> list[Tenant]:
    q = select(Tenant).order_by(Tenant.id)
    if u.tenant_id:
        q = q.where(Tenant.id == u.tenant_id)
    return db.scalars(q).all()


def tenant_or_404(db: Session, u: ConsoleUser, tid: str) -> Tenant:
    t = db.get(Tenant, tid)
    if not t or (u.tenant_id and u.tenant_id != tid):
        raise HTTPException(404, "unknown tenant")
    return t


def render(request: Request, name: str, u: ConsoleUser | None, **ctx):
    return templates.TemplateResponse(request, name, {"user": u, "csrf": request.session.get("csrf", ""), **ctx})


# ---------------------------------------------------------------- auth

@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return render(request, "login.html", None, error=None)


@router.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    u = db.scalars(select(ConsoleUser).where(ConsoleUser.username == username)).first()
    if not u or not u.active or not check_password(password, u.password_hash):
        audit(db, username[:100], "login_failed", None, None, ip=client_ip(request))
        return render(request, "login.html", None, error="Invalid username or password")
    request.session.clear()
    request.session.update(uid=u.id, csrf=secrets.token_urlsafe(24))
    audit(db, u.username, "login", u.tenant_id, None)
    return RedirectResponse("/", status_code=303)


@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# ---------------------------------------------------------------- stats

def tenant_stats(db: Session, t: Tenant, days: int = 30) -> dict:
    since = utcnow() - timedelta(days=days)
    alerts = db.scalars(select(Alert).where(Alert.tenant_id == t.id, Alert.received_at >= since)).all()
    mix = {v: 0 for v in VERDICTS}
    for a in alerts:
        if a.verdict in mix:
            mix[a.verdict] += 1
    decided = sum(mix.values())
    pending = db.scalar(select(func.count()).select_from(VerifyRequest).where(
        VerifyRequest.tenant_id == t.id, VerifyRequest.status == "pending")) or 0
    fb = [a for a in alerts if a.analyst_feedback]
    agree = sum(1 for a in fb if a.analyst_feedback == "agree")
    false_close = sum(1 for a in fb if a.analyst_feedback == "disagree" and a.verdict in CLOSE_VERDICTS)
    installs = db.scalars(select(Install).where(Install.tenant_id == t.id)).all()
    active = [i for i in installs if i.last_seen and i.last_seen >= since]
    bound = set().union(*[i.bound_upns() for i in active]) if active else set()
    seen_users = bound | {a.upn for a in alerts}
    denom = int(t.setting("expected_users") or 0) or len(seen_users)
    ttv = [(a.verdict_at - a.received_at).total_seconds() for a in alerts if a.verdict_at and a.verdict in mix]
    vrs = db.scalars(select(VerifyRequest).where(VerifyRequest.tenant_id == t.id,
                                                 VerifyRequest.created_at >= since)).all()
    answered = sum(1 for v in vrs if v.status == "answered")
    expired = sum(1 for v in vrs if v.status == "expired")
    return {
        "tenant": t, "alerts": len(alerts), "mix": mix, "decided": decided, "pending": pending,
        "agreement": (agree / len(fb) * 100) if fb else None, "feedback": len(fb), "false_close": false_close,
        "bound_users": len(bound), "user_denominator": denom, "installs": len(active),
        "coverage": (len(bound) / denom * 100) if denom else None,
        "alert_coverage": ((decided - mix["NO_COVERAGE"]) / decided * 100) if decided else None,
        "median_ttv": statistics.median(ttv) if ttv else None,
        "answer_rate": (answered / (answered + expired) * 100) if (answered + expired) else None,
    }


# ---------------------------------------------------------------- pages

@router.get("/", response_class=HTMLResponse)
def overview(request: Request, u: ConsoleUser = Depends(current_user), db: Session = Depends(get_db)):
    stats = [tenant_stats(db, t) for t in visible_tenants(db, u)]
    return render(request, "overview.html", u, stats=stats, verdicts=VERDICTS)


@router.get("/queue", response_class=HTMLResponse)
def queue(request: Request, tenant: str = "", verdict: str = "", u: ConsoleUser = Depends(current_user),
          db: Session = Depends(get_db)):
    tids = [t.id for t in visible_tenants(db, u)]
    if tenant:
        tids = [x for x in tids if x == tenant]
    pending = db.scalars(select(VerifyRequest).where(VerifyRequest.tenant_id.in_(tids),
                                                     VerifyRequest.status == "pending")
                         .order_by(VerifyRequest.expires_at)).all()
    q = select(Alert).where(Alert.tenant_id.in_(tids)).order_by(Alert.received_at.desc()).limit(200)
    if verdict:
        q = q.where(Alert.verdict == verdict)
    alerts = db.scalars(q).all()
    return render(request, "queue.html", u, pending=pending, alerts=alerts, tenants=tids, tenant=tenant,
                  verdict=verdict, verdicts=VERDICTS + ["PENDING_USER"], now=utcnow())


@router.get("/alerts/{alert_id}", response_class=HTMLResponse)
def alert_page(alert_id: str, request: Request, u: ConsoleUser = Depends(current_user),
               db: Session = Depends(get_db)):
    a = db.get(Alert, alert_id)
    if not a:
        raise HTTPException(404)
    tenant_or_404(db, u, a.tenant_id)
    audit(db, u.username, "evidence_card_view", a.tenant_id, a.id)  # §6: every view is audit-logged
    vrs = db.scalars(select(VerifyRequest).where(VerifyRequest.alert_id == a.id)
                     .order_by(VerifyRequest.created_at)).all()
    wbs = db.scalars(select(WriteBack).where(WriteBack.alert_id == a.id).order_by(WriteBack.id)).all()
    from .models import Verdict
    history = db.scalars(select(Verdict).where(Verdict.alert_id == a.id).order_by(Verdict.id)).all()
    return render(request, "alert.html", u, a=a, vrs=vrs, wbs=wbs, history=history)


@router.post("/alerts/{alert_id}/feedback")
def alert_feedback(alert_id: str, request: Request, feedback: str = Form(...), note: str = Form(""),
                   csrf: str = Form(""), u: ConsoleUser = Depends(current_user), db: Session = Depends(get_db)):
    check_csrf(request, csrf)
    require(u, "mssp_admin", "analyst")
    a = db.get(Alert, alert_id)
    if not a:
        raise HTTPException(404)
    tenant_or_404(db, u, a.tenant_id)
    if feedback not in ("agree", "disagree"):
        raise HTTPException(422)
    a.analyst_feedback, a.analyst_user, a.analyst_note = feedback, u.username, note[:2000] or None
    audit(db, u.username, "analyst_feedback", a.tenant_id, a.id, feedback=feedback, verdict=a.verdict, note=note[:500])
    return RedirectResponse(f"/alerts/{a.id}", status_code=303)


# ---------------------------------------------------------------- tenant admin

SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
SETTING_FIELDS = [k for k in DEFAULT_TENANT_SETTINGS if k != "shadow_mode"]
INT_FIELDS = {"verify_timeout_min", "max_prompts_per_user_per_day", "expected_users", "ext_warn_threshold",
              "ext_block_threshold"}
BOOL_FIELDS = {k for k, v in DEFAULT_TENANT_SETTINGS.items() if isinstance(v, bool) and k != "shadow_mode"}
SECRET_FIELDS = {k for k in DEFAULT_TENANT_SETTINGS if "secret" in k or "token" in k}
SEVERITY_FIELDS = {"notify_min_severity", "siem_min_severity"}


@router.get("/tenants", response_class=HTMLResponse)
def tenants_page(request: Request, u: ConsoleUser = Depends(current_user), db: Session = Depends(get_db)):
    require(u, "mssp_admin")
    return render(request, "tenants.html", u, tenants=visible_tenants(db, u), error=None)


@router.post("/tenants")
def create_tenant(request: Request, slug: str = Form(...), name: str = Form(""), csrf: str = Form(""),
                  u: ConsoleUser = Depends(current_user), db: Session = Depends(get_db)):
    check_csrf(request, csrf)
    require(u, "mssp_admin")
    slug = slug.strip().lower()
    if not SLUG.match(slug) or db.get(Tenant, slug):
        return render(request, "tenants.html", u, tenants=visible_tenants(db, u),
                      error="Tenant id must be 2-63 chars [a-z0-9-] and unique")
    key = new_api_key()
    t = Tenant(id=slug, name=name.strip() or slug, api_key_hash=hash_api_key(key), api_key_hint=key[-4:], settings={})
    db.add(t)
    audit(db, u.username, "tenant_created", slug, slug)
    db.flush()
    return _tenant_render(request, u, db, t, new_key=key)


def _tenant_render(request, u, db, t, new_key=None, saved=False, test_results=None):
    bl = db.scalars(select(BlockedDomain).where(BlockedDomain.tenant_id == t.id).order_by(BlockedDomain.domain)).all()
    installs = db.scalars(select(Install).where(Install.tenant_id == t.id).order_by(Install.last_seen.desc())
                          .limit(200)).all()
    ids = [i.install_id for i in installs]
    enrolled = {e.install_id: e for e in db.scalars(select(Enrollment).where(Enrollment.install_id.in_(ids))).all()}
    ev_counts = dict(db.execute(select(Event.install_id, func.count(Event.id)).where(
        Event.tenant_id == t.id, Event.install_id.in_(ids)).group_by(Event.install_id)).all())
    settings = {k: t.setting(k) for k in SETTING_FIELDS}
    feed_run = db.scalars(select(FeedRun).order_by(FeedRun.id.desc()).limit(1)).first()
    feed_total = db.scalar(select(func.count(FeedDomain.id))) or 0
    return render(request, "tenant.html", u, t=t, settings=settings, new_key=new_key, blocklist=bl,
                  installs=installs, enrolled=enrolled, ev_counts=ev_counts, feed_run=feed_run,
                  feed_total=feed_total, saved=saved, test_results=test_results, can_admin=u.role == "mssp_admin",
                  secret_fields=SECRET_FIELDS)


@router.get("/tenants/{tid}", response_class=HTMLResponse)
def tenant_page(tid: str, request: Request, u: ConsoleUser = Depends(current_user), db: Session = Depends(get_db)):
    t = tenant_or_404(db, u, tid)
    require(u, "mssp_admin", "analyst")
    return _tenant_render(request, u, db, t)


@router.post("/tenants/{tid}/settings")
async def tenant_settings(tid: str, request: Request, u: ConsoleUser = Depends(current_user),
                          db: Session = Depends(get_db)):
    form = await request.form()
    check_csrf(request, form.get("csrf", ""))
    require(u, "mssp_admin")
    t = tenant_or_404(db, u, tid)
    s = dict(t.settings or {})
    for k in SETTING_FIELDS:
        if k not in form:
            continue
        v = str(form[k]).strip()
        if k in SECRET_FIELDS and v == "":
            continue  # blank = keep existing secret
        if k in SECRET_FIELDS and v == "-":
            v = ""    # "-" clears a stored secret
        if k in SEVERITY_FIELDS and v not in SEVERITY_RANK:
            continue
        if k in INT_FIELDS:
            try:
                v = max(0, int(v))
            except ValueError:
                continue
        elif k in BOOL_FIELDS:
            v = v.lower() == "true"
        s[k] = v
    s["shadow_mode"] = True  # MVP: never auto-close
    t.settings = s
    if form.get("name"):
        t.name = str(form["name"])[:200]
    audit(db, u.username, "tenant_settings_changed", t.id, t.id,
          keys=[k for k in SETTING_FIELDS if k in form and k not in SECRET_FIELDS])
    return _tenant_render(request, u, db, t, saved=True)


@router.post("/tenants/{tid}/test-channels")
def test_channels(tid: str, request: Request, csrf: str = Form(""), u: ConsoleUser = Depends(current_user),
                  db: Session = Depends(get_db)):
    check_csrf(request, csrf)
    require(u, "mssp_admin")
    t = tenant_or_404(db, u, tid)
    results = outbound.test_message(t)
    audit(db, u.username, "channels_tested", t.id, t.id, results=results)
    return _tenant_render(request, u, db, t, test_results=results)


@router.post("/tenants/{tid}/rotate-key")
def rotate_key(tid: str, request: Request, csrf: str = Form(""), u: ConsoleUser = Depends(current_user),
               db: Session = Depends(get_db)):
    check_csrf(request, csrf)
    require(u, "mssp_admin")
    t = tenant_or_404(db, u, tid)
    key = new_api_key()
    t.api_key_hash, t.api_key_hint = hash_api_key(key), key[-4:]
    audit(db, u.username, "tenant_key_rotated", t.id, t.id)
    return _tenant_render(request, u, db, t, new_key=key)


@router.post("/tenants/{tid}/installs/{install_id}/revoke")
def revoke_install(tid: str, install_id: str, request: Request, csrf: str = Form(""),
                   u: ConsoleUser = Depends(current_user), db: Session = Depends(get_db)):
    check_csrf(request, csrf)
    require(u, "mssp_admin")
    t = tenant_or_404(db, u, tid)
    e = db.scalars(select(Enrollment).where(Enrollment.tenant_id == t.id, Enrollment.install_id == install_id)).first()
    if e and not e.revoked_at:
        e.revoked_at, e.revoked_by = utcnow(), u.username
        audit(db, u.username, "install_revoked", t.id, install_id, nickname=e.nickname)
    return RedirectResponse(f"/tenants/{t.id}", status_code=303)


@router.post("/tenants/{tid}/blocklist")
def blocklist_edit(tid: str, request: Request, domain: str = Form(...), op: str = Form("add"), csrf: str = Form(""),
                   u: ConsoleUser = Depends(current_user), db: Session = Depends(get_db)):
    check_csrf(request, csrf)
    require(u, "mssp_admin", "analyst")
    t = tenant_or_404(db, u, tid)
    d = domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
    row = db.scalars(select(BlockedDomain).where(BlockedDomain.tenant_id == t.id, BlockedDomain.domain == d)).first()
    if op == "remove" and row:
        db.delete(row)
    elif op == "add" and d and not row:
        db.add(BlockedDomain(tenant_id=t.id, domain=d, added_by=u.username))
    audit(db, u.username, f"blocklist_{op}", t.id, d)
    return RedirectResponse(f"/tenants/{t.id}", status_code=303)


# ---------------------------------------------------------------- browser events + campaigns

EVENT_WINDOWS = {"24h": 1, "7d": 7, "30d": 30, "90d": 90}
EVENTS_PAGE = 100


def _nicknames(db: Session, install_ids) -> dict:
    ids = [i for i in set(install_ids) if i]
    if not ids:
        return {}
    return {e.install_id: e.nickname for e in db.scalars(select(Enrollment).where(Enrollment.install_id.in_(ids))).all()
            if e.nickname}


def _never_block(domain: str) -> bool:
    """Shared platforms and big brands: blocking them would break normal browsing for everyone."""
    return (domain in feeds.SHARED_HOSTS or domain in feeds.HOSTING_ROOTS
            or any(domain == s or domain.endswith("." + s) for s in feeds.PROTECTED_SUFFIXES))


def _add_block(db: Session, u: ConsoleUser, tenant_id: str | None, domain: str, via: str) -> str | None:
    d = domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0].strip(".")
    if not d or "." not in d:
        return "Not a domain"
    if _never_block(d):
        return f"{d} is a shared platform or big brand; blocking it would break normal sites. Block the exact host instead."
    if not db.scalars(select(BlockedDomain).where(BlockedDomain.tenant_id.is_(tenant_id) if tenant_id is None
                                                  else BlockedDomain.tenant_id == tenant_id,
                                                  BlockedDomain.domain == d)).first():
        db.add(BlockedDomain(tenant_id=tenant_id, domain=d, added_by=u.username))
        audit(db, u.username, "blocklist_add", tenant_id, d, via=via)
    return None


@router.get("/events", response_class=HTMLResponse)
def events_page(request: Request, tenant: str = "", type: str = "", severity: str = "", q: str = "",
                site: str = "", sender: str = "", window: str = "7d", page: int = 0,
                u: ConsoleUser = Depends(current_user), db: Session = Depends(get_db)):
    tids = [t.id for t in visible_tenants(db, u)]
    if tenant:
        tids = [x for x in tids if x == tenant]
    stmt = select(Event).where(Event.tenant_id.in_(tids))
    if window in EVENT_WINDOWS:
        stmt = stmt.where(Event.received_at >= utcnow() - timedelta(days=EVENT_WINDOWS[window]))
    if type:
        stmt = stmt.where(Event.type == type)
    if severity:
        stmt = stmt.where(Event.severity == severity)
    if q:
        like = f"%{q.strip().lower()}%"
        stmt = stmt.where(or_(func.lower(Event.host).like(like), func.lower(Event.user_id).like(like),
                              Event.install_id.like(like)))
    if site:
        s = site.strip().lower()
        stmt = stmt.where(or_(Event.host == s, Event.host.like("%." + s)))
    stmt = stmt.order_by(Event.received_at.desc(), Event.id.desc())
    page = max(0, page)
    if sender:  # sender lives in the JSON body: filter in Python over a bounded window
        rows = [e for e in db.scalars(stmt.limit(5000)).all()
                if str(eventview.email_of(e).get("sender") or "").lower() == sender.strip().lower()]
        rows = rows[page * EVENTS_PAGE:(page + 1) * EVENTS_PAGE + 1]
    else:
        rows = db.scalars(stmt.offset(page * EVENTS_PAGE).limit(EVENTS_PAGE + 1)).all()
    more = len(rows) > EVENTS_PAGE
    rows = rows[:EVENTS_PAGE]
    types = sorted(set(eventview.EVENT_LABELS) | set(db.scalars(select(Event.type).distinct()).all()))
    return render(request, "events.html", u, events=[eventview.summary(e) for e in rows], tenants=tids,
                  nick=_nicknames(db, [e.install_id for e in rows]), f=dict(
                      tenant=tenant, type=type, severity=severity, q=q, site=site, sender=sender, window=window),
                  page=page, more=more, types=types, windows=list(EVENT_WINDOWS), labels=eventview.EVENT_LABELS)


def _event_or_404(db: Session, u: ConsoleUser, event_id: int) -> Event:
    e = db.get(Event, event_id)
    if not e or e.tenant_id not in {t.id for t in visible_tenants(db, u)}:
        raise HTTPException(404, "unknown event")
    return e


@router.get("/events/{event_id}", response_class=HTMLResponse)
def event_page(event_id: int, request: Request, error: str = "", u: ConsoleUser = Depends(current_user),
               db: Session = Depends(get_db)):
    e = _event_or_404(db, u, event_id)
    s = eventview.summary(e)
    key = eventview.campaign_key(e)
    same = 0
    if key and key[0] == "domain":
        same = db.scalar(select(func.count(Event.id)).where(
            Event.tenant_id == e.tenant_id, or_(Event.host == key[1], Event.host.like("%." + key[1])))) or 0
    outs = db.scalars(select(Outbound).where(Outbound.event_id == e.id).order_by(Outbound.id)).all()
    return render(request, "event.html", u, e=s, raw=json.dumps(e.data or {}, indent=2, ensure_ascii=False),
                  site=eventview.site_key(e.host) if e.host else "", key=key, same=same, outs=outs,
                  nick=_nicknames(db, [e.install_id]).get(e.install_id), error=error,
                  can_block=u.role in ("mssp_admin", "analyst"))


@router.post("/events/{event_id}/block")
def event_block(event_id: int, request: Request, domain: str = Form(...), csrf: str = Form(""),
                u: ConsoleUser = Depends(current_user), db: Session = Depends(get_db)):
    check_csrf(request, csrf)
    require(u, "mssp_admin", "analyst")
    e = _event_or_404(db, u, event_id)
    err = _add_block(db, u, e.tenant_id, domain, via=f"event:{e.id}")
    if err:
        return RedirectResponse(f"/events/{e.id}?error={quote(err)}", status_code=303)
    return RedirectResponse(f"/tenants/{e.tenant_id}" if u.role == "mssp_admin" else f"/events/{e.id}",
                            status_code=303)


@router.get("/campaigns", response_class=HTMLResponse)
def campaigns_page(request: Request, tenant: str = "", days: int = 7, min_users: int = 2, error: str = "",
                   u: ConsoleUser = Depends(current_user), db: Session = Depends(get_db)):
    """Events grouped by site (or email sender): one phishing site hitting several users is one incident."""
    tids = [t.id for t in visible_tenants(db, u)]
    if tenant:
        tids = [x for x in tids if x == tenant]
    days = max(1, min(days, 90))
    rows = db.scalars(select(Event).where(
        Event.tenant_id.in_(tids), Event.type.in_(eventview.CAMPAIGN_TYPES),
        Event.received_at >= utcnow() - timedelta(days=days)).order_by(Event.received_at.desc()).limit(20000)).all()
    groups: dict = {}
    for e in rows:
        key = eventview.campaign_key(e)
        if not key:
            continue
        g = groups.setdefault(key, {"kind": key[0], "key": key[1], "events": 0, "users": set(), "tenants": set(),
                                    "types": Counter(), "hosts": set(), "first": e.received_at, "last": e.received_at,
                                    "credential": False, "bypass": False})
        g["events"] += 1
        g["users"].add(e.user_id or e.install_id or "?")
        g["tenants"].add(e.tenant_id)
        g["types"][e.type] += 1
        if e.host:
            g["hosts"].add(e.host)
        g["first"], g["last"] = min(g["first"], e.received_at), max(g["last"], e.received_at)
        g["credential"] |= e.type == "credential_reuse_blocked"
        g["bypass"] |= e.type == "user_bypass"
    blocked = set(db.scalars(select(BlockedDomain.domain).where(or_(
        BlockedDomain.tenant_id.in_(tids), BlockedDomain.tenant_id.is_(None)))).all())
    hosts = {h for g in groups.values() for h in g["hosts"]} | {g["key"] for g in groups.values()}
    in_feed = set(db.scalars(select(FeedDomain.domain).where(FeedDomain.domain.in_(hosts))).all()) if hosts else set()
    out = []
    for g in groups.values():
        n_users = len(g["users"])
        if n_users < max(1, min_users) and not g["credential"]:
            continue  # a credential leak is an incident even for one user
        g.update(n_users=n_users, tenants=sorted(g["tenants"]), types=g["types"].most_common(),
                 blocked=g["key"] in blocked, in_feed=g["key"] in in_feed or bool(g["hosts"] & in_feed),
                 hosts=sorted(g["hosts"])[:5], never_block=_never_block(g["key"]))
        out.append(g)
    out.sort(key=lambda g: (not g["credential"], -g["n_users"], -g["events"]))
    return render(request, "campaigns.html", u, campaigns=out[:300], tenants=tids,
                  f=dict(tenant=tenant, days=days, min_users=min_users), error=error, labels=eventview.EVENT_LABELS,
                  can_block=u.role in ("mssp_admin", "analyst"), is_admin=u.role == "mssp_admin")


@router.post("/campaigns/block")
def campaign_block(request: Request, domain: str = Form(...), tenants: str = Form(""), scope: str = Form("tenants"),
                   csrf: str = Form(""), u: ConsoleUser = Depends(current_user), db: Session = Depends(get_db)):
    """Block a campaign's site for the tenants it hit, or (MSSP admin) for every tenant."""
    check_csrf(request, csrf)
    require(u, "mssp_admin", "analyst")
    visible = {t.id for t in visible_tenants(db, u)}
    if scope == "all":
        require(u, "mssp_admin")
        targets = [None]
    else:
        targets = [t for t in tenants.split(",") if t in visible]
    for t in targets:
        err = _add_block(db, u, t, domain, via="campaign")
        if err:
            return RedirectResponse(f"/campaigns?error={quote(err)}", status_code=303)
    return RedirectResponse("/campaigns", status_code=303)


# ---------------------------------------------------------------- users & audit

@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request, u: ConsoleUser = Depends(current_user), db: Session = Depends(get_db)):
    require(u, "mssp_admin")
    users = db.scalars(select(ConsoleUser).order_by(ConsoleUser.username)).all()
    return render(request, "users.html", u, users=users, roles=ROLES, tenants=visible_tenants(db, u), error=None)


@router.post("/users")
def create_user(request: Request, username: str = Form(...), password: str = Form(...), role: str = Form(...),
                tenant_id: str = Form(""), csrf: str = Form(""), u: ConsoleUser = Depends(current_user),
                db: Session = Depends(get_db)):
    check_csrf(request, csrf)
    require(u, "mssp_admin")
    err = None
    if role not in ROLES:
        err = "Unknown role"
    elif role == "client_viewer" and not tenant_id:
        err = "Client viewers must be restricted to one tenant"
    elif len(password) < 12:
        err = "Password must be at least 12 characters"
    elif db.scalars(select(ConsoleUser).where(ConsoleUser.username == username.strip())).first():
        err = "Username exists"
    if err:
        users = db.scalars(select(ConsoleUser).order_by(ConsoleUser.username)).all()
        return render(request, "users.html", u, users=users, roles=ROLES, tenants=visible_tenants(db, u), error=err)
    db.add(ConsoleUser(username=username.strip()[:100], password_hash=hash_password(password), role=role,
                       tenant_id=tenant_id or None))
    audit(db, u.username, "user_created", tenant_id or None, username, role=role)
    return RedirectResponse("/users", status_code=303)


@router.post("/users/{uid}/toggle")
def toggle_user(uid: int, request: Request, csrf: str = Form(""), u: ConsoleUser = Depends(current_user),
                db: Session = Depends(get_db)):
    check_csrf(request, csrf)
    require(u, "mssp_admin")
    target = db.get(ConsoleUser, uid)
    if target and target.id != u.id:
        target.active = not target.active
        audit(db, u.username, "user_toggled", target.tenant_id, target.username, active=target.active)
    return RedirectResponse("/users", status_code=303)


@router.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request, tenant: str = "", u: ConsoleUser = Depends(current_user),
               db: Session = Depends(get_db)):
    require(u, "mssp_admin")
    q = select(AuditLog).order_by(AuditLog.id.desc()).limit(500)
    if tenant:
        q = q.where(AuditLog.tenant_id == tenant)
    return render(request, "audit.html", u, rows=db.scalars(q).all(), tenant=tenant)
