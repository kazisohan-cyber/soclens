"""Write-back of verdict + Evidence Card: HaloPSA private ticket note and a signed generic webhook."""
import hashlib
import hmac
import json

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import config
from .db import utcnow
from .models import Alert, Tenant, WriteBack, audit


def _halo_token(t: Tenant, client: httpx.Client) -> str:
    base = t.setting("halo_base_url").rstrip("/")
    url = t.setting("halo_auth_url") or base + "/auth/token"
    params = {"tenant": t.setting("halo_tenant")} if t.setting("halo_tenant") else None
    r = client.post(url, params=params, data={
        "grant_type": "client_credentials", "client_id": t.setting("halo_client_id"),
        "client_secret": t.setting("halo_client_secret"), "scope": "all"})
    r.raise_for_status()
    return r.json()["access_token"]


def send_halo(t: Tenant, alert: Alert, client: httpx.Client):
    token = _halo_token(t, client)
    base = t.setting("halo_base_url").rstrip("/")
    body = [{
        "ticket_id": int(alert.ticket_id) if str(alert.ticket_id).isdigit() else alert.ticket_id,
        "outcome": t.setting("halo_outcome") or "Private Note",
        "note_html": alert.card_html,
        "hiddenfromuser": True,
        "sendemail": False,
    }]
    r = client.post(base + "/api/actions", json=body, headers={"Authorization": f"Bearer {token}"})
    r.raise_for_status()


def webhook_payload(alert: Alert) -> dict:
    return {
        "type": "soclens.verify.verdict", "shadowMode": True,
        "alertId": alert.id, "tenantId": alert.tenant_id, "source": alert.source, "externalId": alert.external_id,
        "ticket": {"system": alert.ticket_system, "id": alert.ticket_id} if alert.ticket_id else None,
        "upn": alert.upn, "verdict": alert.verdict, "confidence": alert.confidence,
        "suggestedAction": alert.suggested_action, "status": alert.status,
        "verdictAt": alert.verdict_at.isoformat() if alert.verdict_at else None,
        "evidenceCard": {"markdown": alert.card_md, "html": alert.card_html},
    }


def send_webhook(t: Tenant, alert: Alert, client: httpx.Client):
    body = json.dumps(webhook_payload(alert)).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "SOCLens-Console"}
    secret = t.setting("webhook_secret")
    if secret:
        headers["X-SOCLens-Signature"] = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    r = client.post(t.setting("webhook_url"), content=body, headers=headers)
    r.raise_for_status()


def process_pending(db: Session) -> int:
    rows = db.scalars(select(WriteBack).where(WriteBack.status == "pending").order_by(WriteBack.id).limit(50)).all()
    if not rows:
        return 0
    with httpx.Client(timeout=15) as client:
        for wb in rows:
            alert = db.get(Alert, wb.alert_id)
            t = db.get(Tenant, wb.tenant_id)
            wb.attempts += 1
            try:
                (send_halo if wb.target == "halopsa" else send_webhook)(t, alert, client)
                wb.status, wb.sent_at, wb.last_error = "sent", utcnow(), None
                audit(db, "system", "writeback_sent", wb.tenant_id, wb.alert_id, target=wb.target, verdict=wb.verdict)
            except Exception as e:  # noqa: BLE001 - recorded and retried
                wb.last_error = f"{type(e).__name__}: {e}"[:1000]
                if wb.attempts >= config.WRITEBACK_MAX_ATTEMPTS:
                    wb.status = "failed"
                    audit(db, "system", "writeback_failed", wb.tenant_id, wb.alert_id, target=wb.target,
                          error=wb.last_error)
    return len(rows)
