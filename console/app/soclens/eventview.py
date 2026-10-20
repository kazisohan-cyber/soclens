"""Shared view of a browser event (the extension's `events` contract): labels, defanged indicators,
campaign grouping key. Used by the dashboard, notifications and SIEM export."""
from .feeds import HOSTING_ROOTS, registrable
from .models import SEVERITY_RANK, Event

EVENT_LABELS = {
    "url_blocked": "Phishing site blocked", "page_blocked": "Fake login page blocked", "page_warned": "Suspicious site warning",
    "credential_reuse_blocked": "Work password typed on outside site (stopped)",
    "phishing_email_detected": "Phishing email detected", "user_report_site": "User reported a site",
    "user_report_email": "User reported an email", "user_bypass": "User bypassed a block",
    "user_trusted_site": "User trusted a site", "auth_event": "Sign-in seen in browser",
    "verify_answer": "Verify answer", "device_code_warning": "Device-code sign-in warning",
}
# Types that point at a phishing campaign (grouped on the Campaigns page).
CAMPAIGN_TYPES = {"url_blocked", "page_blocked", "page_warned", "credential_reuse_blocked", "phishing_email_detected",
                  "user_report_site", "user_report_email", "user_bypass", "device_code_warning"}


def defang(s: str | None) -> str:
    if not s:
        return ""
    return s.replace("http", "hxxp").replace(".", "[.]")


def sev_rank(sev: str | None) -> int:
    return SEVERITY_RANK.get((sev or "").lower(), 0)


def site_key(host: str) -> str:
    """Campaign key for a host: the site owner, i.e. one label below a hosting platform
    (abc.evil.pages.dev -> evil.pages.dev), otherwise the registrable domain."""
    host = (host or "").lower().strip(".")
    for root in HOSTING_ROOTS:
        if host.endswith("." + root):
            return host[: -len(root) - 1].split(".")[-1] + "." + root
    return registrable(host) if host.count(".") >= 1 else host


def email_of(e: Event) -> dict:
    em = (e.data or {}).get("email")
    return em if isinstance(em, dict) else {}


def campaign_key(e: Event) -> tuple[str, str] | None:
    """(kind, key): ('domain', 'evil.pages.dev') or ('sender', 'bad@x.com'); None if not groupable."""
    if e.type in ("phishing_email_detected", "user_report_email"):
        sender = str(email_of(e).get("sender") or "").lower().strip()
        if sender:
            return ("sender", sender)
    if e.host:
        return ("domain", site_key(e.host))
    return None


def summary(e: Event) -> dict:
    """Flat, analyst-facing view of one event (also the SIEM export shape)."""
    d = e.data or {}
    em = email_of(e)
    url = d.get("url") or ""
    return {
        "id": e.id, "eventId": e.event_id, "tenantId": e.tenant_id, "type": e.type,
        "label": EVENT_LABELS.get(e.type, e.type), "severity": e.severity or "",
        "ts": e.ts.isoformat().replace("+00:00", "Z") if e.ts else None,
        "receivedAt": e.received_at.isoformat().replace("+00:00", "Z") if e.received_at else None,
        "user": e.user_id or "", "installId": e.install_id or "", "ip": e.ip or "",
        "host": e.host or "", "hostDefanged": defang(e.host), "urlDefanged": d.get("urlDefanged") or defang(url),
        "score": d.get("score"), "brand": d.get("brand"), "reasons": [str(r) for r in (d.get("reasons") or [])][:10],
        "email": {"sender": em.get("sender"), "senderName": em.get("senderName"), "subject": em.get("subject"),
                  "client": em.get("client")} if em else None,
        "links": [l.get("url") if isinstance(l, dict) else str(l) for l in (d.get("links") or [])][:10],
        "note": d.get("note") or "", "version": d.get("version") or "",
    }
