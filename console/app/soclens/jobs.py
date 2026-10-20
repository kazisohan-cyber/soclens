"""Background loop: settle late alerts, expire unanswered verify requests, send write-backs, apply retention."""
import asyncio
import logging
import time
from datetime import timedelta

from sqlalchemy import delete

from . import config, outbound, verify, writeback
from .db import session_scope, utcnow
from .models import AuthEvent, Event, Heartbeat, audit

log = logging.getLogger("soclens.jobs")
_last_purge = 0.0


def purge(db) -> dict:
    """Retention (§4/§6): heartbeats 7 days, auth events 30 days (configurable)."""
    now = utcnow()
    hb = db.execute(delete(Heartbeat).where(
        Heartbeat.ts < now - timedelta(days=config.HEARTBEAT_RETENTION_DAYS))).rowcount
    ae = db.execute(delete(AuthEvent).where(
        AuthEvent.ts < now - timedelta(days=config.AUTH_EVENT_RETENTION_DAYS))).rowcount
    # Community users were promised 30 days (extension welcome page); business tenants keep theirs.
    ce = db.execute(delete(Event).where(
        Event.tenant_id == config.COMMUNITY_TENANT,
        Event.received_at < now - timedelta(days=config.COMMUNITY_EVENT_RETENTION_DAYS))).rowcount
    if hb or ae or ce:
        audit(db, "system", "retention_purge", None, None, heartbeats=hb, auth_events=ae, community_events=ce)
    return {"heartbeats": hb, "auth_events": ae, "community_events": ce}


def tick():
    global _last_purge
    with session_scope() as db:
        verify.resettle(db)
    with session_scope() as db:
        verify.expire_requests(db)
    with session_scope() as db:
        writeback.process_pending(db)
    with session_scope() as db:
        outbound.process_pending(db)
    if time.time() - _last_purge > 3600:
        with session_scope() as db:
            purge(db)
        _last_purge = time.time()


async def run_forever():
    while True:
        try:
            await asyncio.to_thread(tick)
        except Exception:  # noqa: BLE001
            log.exception("background tick failed")
        await asyncio.sleep(config.JOB_INTERVAL_SEC)
