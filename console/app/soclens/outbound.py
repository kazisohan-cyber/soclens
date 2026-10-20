"""Browser events leaving the console: real-time analyst notifications (Telegram, webhook) and SIEM
export (signed JSON webhook, CEF over syslog). Rows are queued in `outbound` when events arrive and
sent by the job loop with retries, so a slow or broken target never delays the extension API."""
import hashlib
import hmac
import html
import json
import socket
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import VERSION, config
from .db import utcnow
from .eventview import EVENT_LABELS, sev_rank, summary
from .models import Event, Outbound, Tenant, audit

NOTIFY_CHANNELS = ("telegram", "notify_webhook", "mssp_telegram")
SKIP_TYPES = {"auth_event", "verify_answer"}  # high volume, not analyst events
CEF_SEVERITY = {"low": 3, "medium": 5, "high": 8, "critical": 10}
SYSLOG_SEVERITY = {"low": 6, "medium": 4, "high": 3, "critical": 2}


# ------------------------------------------------------------------ queueing

def channels_for(t: Tenant, e: Event) -> list[str]:
    if e.type in SKIP_TYPES:
        return []
    rank = sev_rank(e.severity)
    out = []
    if rank >= sev_rank(t.setting("notify_min_severity")) and rank > 0:
        if t.setting("notify_telegram_bot_token") and t.setting("notify_telegram_chat_id"):
            out.append("telegram")
        if t.setting("notify_webhook_url"):
            out.append("notify_webhook")
    if config.NOTIFY_TELEGRAM_BOT_TOKEN and config.NOTIFY_TELEGRAM_CHAT_ID and rank > 0 \
            and rank >= sev_rank(config.NOTIFY_MSSP_MIN_SEVERITY):
        out.append("mssp_telegram")
    if rank >= sev_rank(t.setting("siem_min_severity")):
        if t.setting("siem_webhook_url"):
            out.append("siem_webhook")
        if t.setting("siem_syslog"):
            out.append("syslog")
    return out


def enqueue(db: Session, t: Tenant, events: list[Event]) -> int:
    n = 0
    for e in events:
        for ch in channels_for(t, e):
            db.add(Outbound(tenant_id=t.id, event_id=e.id, channel=ch))
            n += 1
    return n


# ------------------------------------------------------------------ formatting

def _scrub(msg: str, *secrets) -> str:
    for s in secrets:
        if s:
            msg = msg.replace(s, "***")
    return msg[:1000]


def telegram_text(s: dict) -> str:
    sev = (s["severity"] or "").upper()
    icon = {"CRITICAL": "🚨", "HIGH": "⚠️"}.get(sev, "ℹ️")
    lines = [f"{icon} <b>SOCLens · {html.escape(sev or 'EVENT')}</b>",
             f"<b>{html.escape(s['label'])}</b>",
             f"Tenant: {html.escape(s['tenantId'])} · User: {html.escape(s['user'] or s['installId'][:8] or '–')}"]
    if s["email"] and s["email"].get("sender"):
        lines.append(f"From: <code>{html.escape(str(s['email']['sender']))}</code>")
        lines.append(f"Subject: {html.escape(str(s['email'].get('subject') or ''))[:150]}")
    if s["urlDefanged"] or s["hostDefanged"]:
        lines.append(f"Site: <code>{html.escape((s['urlDefanged'] or s['hostDefanged'])[:200])}</code>")
    if s["reasons"]:
        lines.append("Why: " + html.escape("; ".join(s["reasons"][:3]))[:400])
    if config.CONSOLE_URL:
        lines.append(f'<a href="{config.CONSOLE_URL}/events/{s["id"]}">Open in SOCLens</a>')
    return "\n".join(lines)


def _cef_h(v) -> str:
    return str(v if v is not None else "").replace("\\", "\\\\").replace("|", "\\|")


def _cef_x(v) -> str:
    return str(v if v is not None else "").replace("\\", "\\\\").replace("=", "\\=").replace("\r", " ").replace("\n", " ")


def cef_line(s: dict) -> str:
    sev = (s["severity"] or "low").lower()
    rt = int(datetime.fromisoformat(s["receivedAt"].replace("Z", "+00:00")).timestamp() * 1000) if s["receivedAt"] else ""
    ext = {"rt": rt, "suser": s["user"], "src": s["ip"], "dhost": s["host"], "request": s["urlDefanged"],
           "msg": "; ".join(s["reasons"][:5]), "cs1Label": "tenant", "cs1": s["tenantId"],
           "cs2Label": "installId", "cs2": s["installId"], "externalId": s["eventId"]}
    if s["email"]:
        ext.update(cs3Label="emailSender", cs3=s["email"].get("sender"), cs4Label="emailSubject",
                   cs4=s["email"].get("subject"))
    if s["score"] is not None:
        ext.update(cn1Label="score", cn1=s["score"])
    head = "|".join(_cef_h(x) for x in ("CEF:0", "OpsVantage", "SOCLens", VERSION, s["type"],
                                         EVENT_LABELS.get(s["type"], s["type"]), CEF_SEVERITY.get(sev, 3)))
    return head + "|" + " ".join(f"{k}={_cef_x(v)}" for k, v in ext.items() if v not in (None, ""))


def syslog_frame(s: dict) -> bytes:
    pri = 16 * 8 + SYSLOG_SEVERITY.get((s["severity"] or "low").lower(), 6)  # facility local0
    ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return f"<{pri}>1 {ts} soclens soclens - - - {cef_line(s)}\n".encode("utf-8", "replace")


def _sign(secret: str, body: bytes) -> dict:
    h = {"Content-Type": "application/json", "User-Agent": f"SOCLens-Console/{VERSION}"}
    if secret:
        h["X-SOCLens-Signature"] = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return h


# ------------------------------------------------------------------ sending

def _telegram(client: httpx.Client, token: str, chat: str, text: str):
    r = client.post(f"https://api.telegram.org/bot{token}/sendMessage",
                    json={"chat_id": chat, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True})
    r.raise_for_status()


def _syslog(target: str, frames: list[bytes]):
    u = urlsplit(target if "://" in target else "udp://" + target)
    host, port = u.hostname, u.port or 514
    if not host:
        raise ValueError("syslog target needs a host")
    if u.scheme == "tcp":
        with socket.create_connection((host, port), timeout=10) as s:
            s.sendall(b"".join(frames))
    elif u.scheme == "udp":
        with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM) as s:
            for f in frames:
                s.sendto(f[:8000], (host, port))
    else:
        raise ValueError("syslog target must be udp://host:port or tcp://host:port")


def _mark(row: Outbound, err: Exception | None, *secrets):
    row.attempts += 1
    if err is None:
        row.status, row.sent_at, row.last_error = "sent", utcnow(), None
        return
    row.last_error = _scrub(f"{type(err).__name__}: {err}", *secrets)
    if row.attempts >= config.OUTBOUND_MAX_ATTEMPTS:
        row.status = "failed"


def process_pending(db: Session) -> int:
    rows = db.scalars(select(Outbound).where(Outbound.status == "pending").order_by(Outbound.id).limit(200)).all()
    if not rows:
        return 0
    tenants, events = {}, {}
    for r in rows:
        tenants.setdefault(r.tenant_id, db.get(Tenant, r.tenant_id))
        if r.event_id not in events:
            ev = db.get(Event, r.event_id)
            events[r.event_id] = summary(ev) if ev else None
    hour_ago = utcnow() - timedelta(hours=1)
    sent_hour: dict = {}
    with httpx.Client(timeout=15) as client:
        # SIEM: one signed batch per tenant / one syslog connection per tenant
        for ch in ("siem_webhook", "syslog"):
            by_tenant: dict = {}
            for r in rows:
                if r.channel == ch:
                    by_tenant.setdefault(r.tenant_id, []).append(r)
            for tid, group in by_tenant.items():
                t, live = tenants[tid], [r for r in group if events.get(r.event_id)]
                for r in group:
                    if not events.get(r.event_id):
                        r.status, r.last_error = "failed", "event deleted"
                if not live:
                    continue
                try:
                    if ch == "siem_webhook":
                        body = json.dumps({"type": "soclens.events", "tenantId": tid,
                                           "events": [events[r.event_id] for r in live]}).encode()
                        client.post(t.setting("siem_webhook_url"), content=body,
                                    headers=_sign(t.setting("siem_webhook_secret"), body)).raise_for_status()
                    else:
                        _syslog(t.setting("siem_syslog"), [syslog_frame(events[r.event_id]) for r in live])
                    err = None
                except Exception as e:  # noqa: BLE001 - recorded and retried
                    err = e
                for r in live:
                    _mark(r, err, t.setting("siem_webhook_secret"))
        # Notifications: one message per event, capped per tenant + channel per hour
        for r in rows:
            if r.channel not in NOTIFY_CHANNELS:
                continue
            s, t = events.get(r.event_id), tenants[r.tenant_id]
            if not s:
                r.status, r.last_error = "failed", "event deleted"
                continue
            k = (r.tenant_id if r.channel != "mssp_telegram" else "*", r.channel)
            if k not in sent_hour:
                q = select(func.count(Outbound.id)).where(Outbound.channel == r.channel, Outbound.status == "sent",
                                                          Outbound.sent_at >= hour_ago)
                if r.channel != "mssp_telegram":
                    q = q.where(Outbound.tenant_id == r.tenant_id)
                sent_hour[k] = db.scalar(q) or 0
            if sent_hour[k] >= config.NOTIFY_MAX_PER_HOUR:
                r.status, r.last_error = "suppressed", f"over {config.NOTIFY_MAX_PER_HOUR}/hour"
                continue
            token = ""
            try:
                if r.channel == "telegram":
                    token = t.setting("notify_telegram_bot_token")
                    _telegram(client, token, t.setting("notify_telegram_chat_id"), telegram_text(s))
                elif r.channel == "mssp_telegram":
                    token = config.NOTIFY_TELEGRAM_BOT_TOKEN
                    _telegram(client, token, config.NOTIFY_TELEGRAM_CHAT_ID, telegram_text(s))
                else:
                    body = json.dumps({"type": "soclens.event.alert", "event": s}).encode()
                    client.post(t.setting("notify_webhook_url"), content=body,
                                headers=_sign(t.setting("notify_webhook_secret"), body)).raise_for_status()
                err = None
                sent_hour[k] += 1
            except Exception as e:  # noqa: BLE001
                err = e
            _mark(r, err, token, t.setting("notify_webhook_secret"))
    failed = [r for r in rows if r.status == "failed"]
    if failed:
        audit(db, "system", "outbound_failed", None, None, count=len(failed),
              channels=sorted({r.channel for r in failed}), error=failed[0].last_error)
    return len(rows)


def test_message(t: Tenant) -> list[str]:
    """Dashboard 'Send test': one synthetic critical event to each configured channel."""
    fake = {"id": 0, "eventId": "test", "tenantId": t.id, "type": "credential_reuse_blocked",
            "label": "TEST: " + EVENT_LABELS["credential_reuse_blocked"], "severity": "critical",
            "ts": None, "receivedAt": utcnow().isoformat().replace("+00:00", "Z"), "user": "test@example.com",
            "installId": "", "ip": "203.0.113.7", "host": "login.example-phish.top",
            "hostDefanged": "login[.]example-phish[.]top", "urlDefanged": "hxxps://login[.]example-phish[.]top/",
            "score": 95, "brand": "Microsoft", "reasons": ["Test message from the SOCLens console"],
            "email": None, "links": [], "note": "", "version": VERSION}
    results = []
    with httpx.Client(timeout=15) as client:
        def post(url, secret, payload):
            body = json.dumps(payload).encode()
            client.post(url, content=body, headers=_sign(secret, body)).raise_for_status()

        checks = [
            ("Telegram", t.setting("notify_telegram_bot_token") and t.setting("notify_telegram_chat_id"),
             lambda: _telegram(client, t.setting("notify_telegram_bot_token"), t.setting("notify_telegram_chat_id"),
                               telegram_text(fake)), t.setting("notify_telegram_bot_token")),
            ("Notify webhook", t.setting("notify_webhook_url"),
             lambda: post(t.setting("notify_webhook_url"), t.setting("notify_webhook_secret"),
                          {"type": "soclens.event.alert", "test": True, "event": fake}), ""),
            ("SIEM webhook", t.setting("siem_webhook_url"),
             lambda: post(t.setting("siem_webhook_url"), t.setting("siem_webhook_secret"),
                          {"type": "soclens.events", "test": True, "tenantId": t.id, "events": [fake]}), ""),
            ("Syslog", t.setting("siem_syslog"), lambda: _syslog(t.setting("siem_syslog"), [syslog_frame(fake)]), ""),
        ]
        for name, configured, send, secret in checks:
            if not configured:
                continue
            try:
                send()
                results.append(f"{name}: sent")
            except Exception as e:  # noqa: BLE001
                results.append(f"{name}: FAILED - " + _scrub(f"{type(e).__name__}: {e}", secret))
    return results or ["No channel configured for this tenant."]
