"""Verify orchestration: run correlation for an alert, ask the user through their own bound
extension (never any other channel), apply answers / timeouts, record verdicts and queue write-backs."""
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import evidence
from .correlate import correlate
from .db import utcnow
from .models import (NO_COVERAGE, NO_RESPONSE, NOT_SEEN_IN_BROWSER, PENDING_USER, USER_CONFIRMED, USER_DENIED,
                     Alert, Tenant, Verdict, VerifyRequest, WriteBack, audit)


def latest_request(db: Session, alert_id: str) -> VerifyRequest | None:
    return db.scalars(select(VerifyRequest).where(VerifyRequest.alert_id == alert_id)
                      .order_by(VerifyRequest.created_at.desc())).first()


def render(db: Session, alert: Alert):
    alert.card_md, alert.card_html = evidence.build(alert, latest_request(db, alert.id))


def _trace(alert: Alert, line: str):
    ev = dict(alert.evidence or {})
    ev["trace"] = list(ev.get("trace", [])) + [line]
    alert.evidence = ev


def set_verdict(db: Session, alert: Alert, verdict: str, confidence, reason: str, final: bool = True,
                actor: str = "system"):
    alert.verdict, alert.confidence = verdict, confidence
    alert.suggested_action = evidence.VERDICT_INFO[verdict][0]
    alert.verdict_at = utcnow()
    if final:
        alert.status = "final"
    db.add(Verdict(tenant_id=alert.tenant_id, alert_id=alert.id, verdict=verdict, confidence=confidence,
                   reason=reason))
    audit(db, actor, "verdict", alert.tenant_id, alert.id, verdict=verdict, confidence=confidence, reason=reason,
          final=final)
    db.flush()
    render(db, alert)
    queue_writebacks(db, alert)


def queue_writebacks(db: Session, alert: Alert):
    t = db.get(Tenant, alert.tenant_id)
    targets = []
    if t.setting("halo_base_url") and alert.ticket_id and (alert.ticket_system or "halopsa") == "halopsa":
        targets.append("halopsa")
    if t.setting("webhook_url"):
        targets.append("webhook")
    for target in targets:
        db.add(WriteBack(tenant_id=alert.tenant_id, alert_id=alert.id, target=target, verdict=alert.verdict))


def prompt_text(alert: Alert) -> str:
    app = alert.app or {"microsoft": "Microsoft 365", "google": "Google", "okta": "Okta"}.get(alert.idp, alert.idp)
    where = f" from {alert.location}" if alert.location else (f" from {alert.ip}" if alert.ip else "")
    device = (alert.raw or {}).get("_device")
    on = f" on {device}" if device else ""
    return f"Sign-in to {app}{where} at {alert.ts.strftime('%H:%M')} UTC{on} - was this you?"


def process_alert(db: Session, alert: Alert):
    d = correlate(db, alert)
    alert.evidence = {"trace": d.trace, "groundTruth": d.ground_truth, "reason": d.reason}
    if d.settle:
        alert.status = "settling"
        render(db, alert)
        return
    if not d.ask_user:
        set_verdict(db, alert, d.verdict, d.confidence, d.reason)
        return

    t = db.get(Tenant, alert.tenant_id)
    since = utcnow() - timedelta(days=1)
    sent_today = db.scalar(select(func.count()).select_from(VerifyRequest).where(
        VerifyRequest.tenant_id == alert.tenant_id, VerifyRequest.upn == alert.upn.lower(),
        VerifyRequest.created_at >= since)) or 0
    limit = int(t.setting("max_prompts_per_user_per_day"))
    if sent_today >= limit:
        _trace(alert, f"Prompt limit reached ({sent_today}/{limit} in 24h, anti-fatigue) - user not asked")
        if d.verdict:
            set_verdict(db, alert, d.verdict, d.confidence, d.reason)
        else:
            set_verdict(db, alert, NO_RESPONSE, None, "prompt rate limit reached")
        return

    vr = VerifyRequest(tenant_id=alert.tenant_id, alert_id=alert.id, upn=alert.upn.lower(),
                       prompt=prompt_text(alert),
                       expires_at=utcnow() + timedelta(minutes=float(t.setting("verify_timeout_min"))))
    db.add(vr)
    _trace(alert, f"Asked the user via their SOCLens browser: \"{vr.prompt}\"")
    audit(db, "system", "verify_request", alert.tenant_id, alert.id, upn=vr.upn, reason=d.reason)
    db.flush()
    alert.status = "pending_user"
    if d.verdict:  # NOT_SEEN_IN_BROWSER: escalate now, refine with the answer later
        set_verdict(db, alert, d.verdict, d.confidence, d.reason, final=False)
    else:
        alert.verdict = PENDING_USER
        render(db, alert)


def apply_answer(db: Session, vr: VerifyRequest, answer: str, install_id: str, ip: str | None):
    now = utcnow()
    vr.status, vr.answer, vr.answered_at = "answered", answer, now
    vr.answered_by_install, vr.answer_ip = install_id, ip
    audit(db, f"install:{install_id}", "verify_answer", vr.tenant_id, vr.alert_id, answer=answer, ip=ip, upn=vr.upn)
    alert = db.get(Alert, vr.alert_id)
    if answer == "no":
        _trace(alert, "User answered: No, not me")
        set_verdict(db, alert, USER_DENIED, "high", "user denied the sign-in")
    elif alert.verdict == NOT_SEEN_IN_BROWSER:
        _trace(alert, "User answered: Yes, it was me - but their SOCLens browser did not see the sign-in; "
                      "keeping NOT_SEEN_IN_BROWSER (check other devices / VPN before closing)")
        set_verdict(db, alert, NOT_SEEN_IN_BROWSER, "medium", "not seen in browser; user says it was them")
    else:
        _trace(alert, "User answered: Yes, it was me")
        set_verdict(db, alert, USER_CONFIRMED, "medium", "user confirmed the sign-in")


def expire_requests(db: Session) -> int:
    now = utcnow()
    rows = db.scalars(select(VerifyRequest).where(VerifyRequest.status == "pending",
                                                  VerifyRequest.expires_at <= now)).all()
    for vr in rows:
        vr.status = "expired"
        alert = db.get(Alert, vr.alert_id)
        audit(db, "system", "verify_expired", vr.tenant_id, vr.alert_id, upn=vr.upn)
        _trace(alert, "No answer from the user before the timeout")
        if alert.verdict == NOT_SEEN_IN_BROWSER:
            set_verdict(db, alert, NOT_SEEN_IN_BROWSER, "high", "not seen in browser; user did not answer")
        else:
            set_verdict(db, alert, NO_RESPONSE, None, "user did not answer in time")
    return len(rows)


def resettle(db: Session) -> int:
    rows = db.scalars(select(Alert).where(Alert.status == "settling")).all()
    for a in rows:
        process_alert(db, a)
    return len(rows)


__all__ = ["process_alert", "apply_answer", "expire_requests", "resettle", "set_verdict", "render", "NO_COVERAGE"]
