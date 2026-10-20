"""Correlation engine: the §2 decision tree, shadow mode (suggestions only).

    browser sign-in? ── no ──► ASK USER
    bound SOCLens browser? ── no ──► NO_COVERAGE
    matching browser auth event (same UPN, ±3 min, same IdP)?
        yes + IP match (exact / same /24 (/64 v6) / same ASN) ─► CONFIRMED_BY_BROWSER
        yes + IP differs ─► ASK USER
        no + browser online (heartbeat ±10 min) ─► NOT_SEEN_IN_BROWSER + ASK USER
        no + browser offline ─► ASK USER
"""
import ipaddress
import os
from dataclasses import dataclass, field
from datetime import timedelta
from functools import lru_cache

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import config
from .db import utcnow
from .models import (CONFIRMED_BY_BROWSER, NO_COVERAGE, NOT_SEEN_IN_BROWSER, Alert, AuthEvent,
                     Heartbeat, Install)


@lru_cache(maxsize=1)
def _asn_reader():
    path = config.GEOIP_ASN_DB
    if not path or not os.path.exists(path):
        return None
    try:
        import maxminddb
        return maxminddb.open_database(path)
    except Exception:
        return None


def asn_of(ip: str):
    r = _asn_reader()
    if not r:
        return None
    try:
        rec = r.get(ip) or {}
        return rec.get("autonomous_system_number")
    except Exception:
        return None


def ip_match(a: str | None, b: str | None) -> str | None:
    """How strongly two IPs match: exact, same_/24 (v4), same_/64 (v6), same_asn, or None."""
    if not a or not b:
        return None
    try:
        ia, ib = ipaddress.ip_address(a), ipaddress.ip_address(b)
    except ValueError:
        return None
    if ia == ib:
        return "exact"
    if ia.version == ib.version:
        prefix = 24 if ia.version == 4 else 64
        if ipaddress.ip_network(f"{ia}/{prefix}", strict=False) == ipaddress.ip_network(f"{ib}/{prefix}", strict=False):
            return f"same_/{prefix}"
    asn_a, asn_b = asn_of(str(ia)), asn_of(str(ib))
    if asn_a and asn_a == asn_b:
        return "same_asn"
    return None


_RANK = {"exact": 3, "same_/24": 2, "same_/64": 2, "same_asn": 1}


@dataclass
class Decision:
    verdict: str | None = None       # immediate verdict (None while only asking)
    ask_user: bool = False
    settle: bool = False             # re-run later: auth-event batches may still be in flight
    confidence: str | None = None
    reason: str = ""
    trace: list = field(default_factory=list)
    ground_truth: dict = field(default_factory=dict)


def bound_installs(db: Session, tenant_id: str, upn: str) -> list[Install]:
    upn = upn.lower()
    rows = db.scalars(select(Install).where(Install.tenant_id == tenant_id)).all()
    return [i for i in rows if upn in i.bound_upns()]


def _iso(dt):
    return dt.isoformat().replace("+00:00", "Z") if dt else None


def correlate(db: Session, alert: Alert, allow_settle: bool = True) -> Decision:
    d = Decision()
    upn = alert.upn.lower()
    t = alert.ts
    win = timedelta(seconds=config.MATCH_WINDOW_SEC)
    hb_win = timedelta(seconds=config.HEARTBEAT_WINDOW_SEC)

    installs = bound_installs(db, alert.tenant_id, upn)
    install_ids = [i.install_id for i in installs]
    d.ground_truth["installs"] = [
        {"installId": i.install_id, "upn": i.upn, "bindingSource": i.upn_source, "browser": i.browser,
         "lastSeen": _iso(i.last_seen), "lastIp": i.last_ip} for i in installs]

    # Device-code flow seen in the user's browser around the alert time is a phishing signal (§1 #5).
    dc = db.scalars(select(AuthEvent).where(
        AuthEvent.tenant_id == alert.tenant_id, AuthEvent.flow == "device_code",
        AuthEvent.ts >= t - timedelta(minutes=30), AuthEvent.ts <= t + win)).all()
    dc = [e for e in dc if (e.account_hint or "").lower() == upn or e.install_id in install_ids]
    if dc:
        d.ground_truth["deviceCodeEvents"] = [_auth_event_dict(e) for e in dc]
        d.trace.append(f"Device-code sign-in page used in the user's browser at {_iso(dc[0].ts)}"
                       + (f" (came from {dc[0].referrer_host or dc[0].opener_host})" if (dc[0].referrer_host or dc[0].opener_host) else ""))

    client_app = alert.client_app or "Browser"
    if alert.client_app is None:
        d.trace.append("clientApp not provided by the alert source; assumed Browser")
    is_browser = client_app.strip().lower() == "browser" and alert.is_interactive
    if not is_browser:
        d.trace.append(f"Not an interactive browser sign-in (clientApp={client_app!r}, "
                       f"interactive={alert.is_interactive}) - the browser cannot see it")
        if not installs:
            d.trace.append("No SOCLens browser bound to the user - cannot ask them")
            return _final(d, NO_COVERAGE, None, "non-browser sign-in and no bound SOCLens browser")
        d.ask_user, d.reason = True, "non_browser_signin"
        return d

    if not installs:
        d.trace.append(f"No SOCLens browser bound to {upn}")
        return _final(d, NO_COVERAGE, None, "user has no SOCLens browser bound")
    d.trace.append(f"{len(installs)} SOCLens browser(s) bound to {upn}")

    cands = db.scalars(select(AuthEvent).where(
        AuthEvent.tenant_id == alert.tenant_id, AuthEvent.ts >= t - win, AuthEvent.ts <= t + win,
        AuthEvent.idp == (alert.idp or "microsoft"))).all()
    cands = [e for e in cands if e.flow != "device_code" and e.outcome != "failure" and
             ((e.account_hint or "").lower() == upn or e.install_id in install_ids)]

    if cands:
        best, best_kind, best_ip = None, None, None
        for e in cands:
            ips = [e.ip] + [h.ip for h in db.scalars(select(Heartbeat).where(
                Heartbeat.tenant_id == alert.tenant_id, Heartbeat.install_id == e.install_id,
                Heartbeat.ts >= t - hb_win, Heartbeat.ts <= t + hb_win)).all()]
            for ip in ips:
                kind = ip_match(alert.ip, ip)
                if kind and (best_kind is None or _RANK[kind] > _RANK[best_kind]
                             or (_RANK[kind] == _RANK[best_kind] and e.outcome == "success" and best.outcome != "success")):
                    best, best_kind, best_ip = e, kind, ip
        if best is None:
            best = min(cands, key=lambda e: abs((e.ts - t).total_seconds()))
        d.ground_truth["matchedAuthEvent"] = _auth_event_dict(best)
        d.ground_truth["ipMatch"] = {"alertIp": alert.ip, "browserIp": best_ip or best.ip, "kind": best_kind}
        d.trace.append(f"Matching browser sign-in found: {best.idp} at {_iso(best.ts)} "
                       f"(Δ {int(abs((best.ts - t).total_seconds()))}s, flow={best.flow}, outcome={best.outcome})")
        if not alert.ip:
            d.trace.append("Alert carries no IP - never confirm on time alone")
            d.ask_user, d.reason = True, "no_alert_ip"
            return d
        if best_kind and best.outcome == "success":
            d.trace.append(f"IP match: {best_kind} ({alert.ip} vs browser {best_ip})")
            return _final(d, CONFIRMED_BY_BROWSER, "high", "browser sign-in matches user, time and IP")
        if best_kind:
            d.trace.append(f"IP matches ({best_kind}) but sign-in outcome is {best.outcome!r}")
            d.ask_user, d.reason = True, "outcome_unconfirmed"
            return d
        d.trace.append(f"IP differs: alert {alert.ip} vs browser {best.ip} (VPN split tunnel / IPv4-IPv6 / CGNAT?)")
        d.ask_user, d.reason = True, "ip_mismatch"
        return d

    d.trace.append(f"No browser sign-in for {upn} within ±{config.MATCH_WINDOW_SEC // 60} min")
    hbs = db.scalars(select(Heartbeat).where(
        Heartbeat.tenant_id == alert.tenant_id, Heartbeat.install_id.in_(install_ids),
        Heartbeat.ts >= t - hb_win, Heartbeat.ts <= t + hb_win).order_by(Heartbeat.ts)).all()
    if hbs:
        nearest = min(hbs, key=lambda h: abs((h.ts - t).total_seconds()))
        d.ground_truth["heartbeat"] = {"installId": nearest.install_id, "ts": _iso(nearest.ts), "ip": nearest.ip}
        if allow_settle and (utcnow() - t).total_seconds() < config.SETTLE_SEC:
            d.trace.append("Browser online; waiting for in-flight auth events before deciding")
            d.settle = True
            return d
        d.trace.append(f"Browser was online (heartbeat {_iso(nearest.ts)} from {nearest.ip}) but saw no sign-in "
                       "- likely token replay / stolen credentials")
        d.verdict, d.confidence, d.ask_user = NOT_SEEN_IN_BROWSER, "high", True
        d.reason = "browser online, sign-in not seen"
        return d

    d.trace.append(f"Browser offline (no heartbeat within ±{config.HEARTBEAT_WINDOW_SEC // 60} min) - no ground truth")
    d.ask_user, d.reason = True, "browser_offline"
    return d


def _final(d: Decision, verdict, confidence, reason) -> Decision:
    d.verdict, d.confidence, d.reason = verdict, confidence, reason
    return d


def _auth_event_dict(e: AuthEvent) -> dict:
    return {"eventId": e.event_id, "installId": e.install_id, "ts": _iso(e.ts), "idp": e.idp, "host": e.host,
            "flow": e.flow, "outcome": e.outcome, "accountHint": e.account_hint, "tenantHint": e.tenant_hint,
            "ip": e.ip, "referrerHost": e.referrer_host, "openerHost": e.opener_host}
