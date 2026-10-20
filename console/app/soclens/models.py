"""Postgres data model (design doc §4): tenants, installs, heartbeats, auth_events, alerts,
verify_requests, verdicts, events - plus console users, audit log, blocklist and write-backs."""
import uuid

from sqlalchemy import (Boolean, ForeignKey, Index, Integer, String, Text, UniqueConstraint)
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base, JSONType, UTCDateTime, utcnow


def _uuid() -> str:
    return str(uuid.uuid4())


# Verdicts (§2)
CONFIRMED_BY_BROWSER = "CONFIRMED_BY_BROWSER"
USER_CONFIRMED = "USER_CONFIRMED"
NOT_SEEN_IN_BROWSER = "NOT_SEEN_IN_BROWSER"
USER_DENIED = "USER_DENIED"
NO_RESPONSE = "NO_RESPONSE"
NO_COVERAGE = "NO_COVERAGE"
PENDING_USER = "PENDING_USER"  # interim: waiting for "was this you?"
VERDICTS = [CONFIRMED_BY_BROWSER, USER_CONFIRMED, NOT_SEEN_IN_BROWSER, USER_DENIED,
            NO_RESPONSE, NO_COVERAGE]

DEFAULT_TENANT_SETTINGS = {
    "verify_timeout_min": 10,
    "max_prompts_per_user_per_day": 5,
    "expected_users": 0,          # licensed seats; 0 = derive from UPNs seen
    "shadow_mode": True,          # MVP: always suggestions only, never auto-close
    "halo_base_url": "",          # e.g. https://clienta.halopsa.com
    "halo_auth_url": "",          # default <base>/auth/token
    "halo_tenant": "",            # hosted Halo ?tenant=
    "halo_client_id": "",
    "halo_client_secret": "",
    "halo_outcome": "Private Note",
    "webhook_url": "",
    "webhook_secret": "",
    # Threat-intel feeds merged into this tenant's blocklist (feeds.py)
    "threat_feeds": True,
    # Extension policy pushed via GET /v1/config (admin policy on the device still wins)
    "ext_warn_threshold": 40,
    "ext_block_threshold": 70,
    "ext_allow_bypass": True,
    "ext_credential_guard": True,
    "ext_webmail_scanner": True,
    "ext_page_scanner": True,
    "ext_domain_age": True,
    "ext_verify": False,          # extension records IdP sign-ins + heartbeats (Verify); needs a SIEM feeding alerts
    # Real-time notification of serious browser events (outbound.py)
    "notify_min_severity": "critical",   # critical|high|medium|low; credential reuse is always critical
    "notify_telegram_bot_token": "",
    "notify_telegram_chat_id": "",
    "notify_webhook_url": "",
    "notify_webhook_secret": "",
    # Export of every browser event to a SIEM (outbound.py) - plus pull via GET /v1/events
    "siem_min_severity": "low",
    "siem_webhook_url": "",
    "siem_webhook_secret": "",
    "siem_syslog": "",            # udp://host:514 or tcp://host:514 (CEF)
}
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # slug = X-SOCLens-Tenant
    name: Mapped[str] = mapped_column(String(200))
    api_key_hash: Mapped[str] = mapped_column(String(64))
    api_key_hint: Mapped[str] = mapped_column(String(16), default="")
    settings: Mapped[dict] = mapped_column(JSONType, default=dict)
    created_at = mapped_column(UTCDateTime, default=utcnow)

    def setting(self, key):
        return (self.settings or {}).get(key, DEFAULT_TENANT_SETTINGS.get(key))


class Install(Base):
    """One browser profile running the extension. Bound to a UPN (policy userId first,
    then the most frequent successful IdP account hint); `accounts` = extra bound UPNs."""
    __tablename__ = "installs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    install_id: Mapped[str] = mapped_column(String(64))
    upn: Mapped[str | None] = mapped_column(String(320), nullable=True, index=True)
    upn_source: Mapped[str | None] = mapped_column(String(32), nullable=True)
    accounts: Mapped[list] = mapped_column(JSONType, default=list)
    hint_counts: Mapped[dict] = mapped_column(JSONType, default=dict)
    first_seen = mapped_column(UTCDateTime, default=utcnow)
    last_seen = mapped_column(UTCDateTime, default=utcnow)
    last_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ua: Mapped[str | None] = mapped_column(Text, nullable=True)
    browser: Mapped[str | None] = mapped_column(String(100), nullable=True)
    __table_args__ = (UniqueConstraint("tenant_id", "install_id"),)

    def bound_upns(self) -> set[str]:
        s = {a.lower() for a in (self.accounts or []) if a}
        if self.upn:
            s.add(self.upn.lower())
        return s


class Heartbeat(Base):
    __tablename__ = "heartbeats"  # 7-day retention
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64))
    install_id: Mapped[str] = mapped_column(String(64))
    ts = mapped_column(UTCDateTime, default=utcnow)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    __table_args__ = (Index("ix_hb_tenant_install_ts", "tenant_id", "install_id", "ts"),
                      Index("ix_hb_ts", "ts"))


class AuthEvent(Base):
    __tablename__ = "auth_events"  # 30-day retention
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64))
    event_id: Mapped[str] = mapped_column(String(64))
    install_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ts = mapped_column(UTCDateTime)
    received_at = mapped_column(UTCDateTime, default=utcnow)
    idp: Mapped[str] = mapped_column(String(32), default="microsoft")
    host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tenant_hint: Mapped[str | None] = mapped_column(String(255), nullable=True)
    account_hint: Mapped[str | None] = mapped_column(String(320), nullable=True)
    flow: Mapped[str | None] = mapped_column(String(32), nullable=True)
    outcome: Mapped[str | None] = mapped_column(String(32), nullable=True)
    referrer_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    opener_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    user_id: Mapped[str | None] = mapped_column(String(320), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)  # egress IP seen on receipt
    __table_args__ = (UniqueConstraint("tenant_id", "event_id"),
                      Index("ix_ae_tenant_ts", "tenant_id", "ts"))


class Event(Base):
    __tablename__ = "events"  # existing extension contract (README)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    event_id: Mapped[str] = mapped_column(String(64))
    type: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    ts = mapped_column(UTCDateTime)
    received_at = mapped_column(UTCDateTime, default=utcnow)
    host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    user_id: Mapped[str | None] = mapped_column(String(320), nullable=True)
    install_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    data: Mapped[dict] = mapped_column(JSONType, default=dict)
    __table_args__ = (UniqueConstraint("tenant_id", "event_id"),)


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    source: Mapped[str] = mapped_column(String(32), default="generic")
    external_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    title: Mapped[str | None] = mapped_column(String(500), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    upn: Mapped[str] = mapped_column(String(320), index=True)
    ts = mapped_column(UTCDateTime)  # sign-in time
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    app: Mapped[str | None] = mapped_column(String(200), nullable=True)
    client_app: Mapped[str | None] = mapped_column(String(100), nullable=True)
    is_interactive: Mapped[bool] = mapped_column(Boolean, default=True)
    idp: Mapped[str] = mapped_column(String(32), default="microsoft")
    location: Mapped[str | None] = mapped_column(String(200), nullable=True)
    ticket_system: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ticket_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    raw: Mapped[dict] = mapped_column(JSONType, default=dict)
    received_at = mapped_column(UTCDateTime, default=utcnow)
    # new -> settling -> pending_user -> final
    status: Mapped[str] = mapped_column(String(20), default="new", index=True)
    verdict: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    confidence: Mapped[str | None] = mapped_column(String(16), nullable=True)
    suggested_action: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[dict] = mapped_column(JSONType, default=dict)  # decision trace + ground truth
    card_md: Mapped[str | None] = mapped_column(Text, nullable=True)
    card_html: Mapped[str | None] = mapped_column(Text, nullable=True)
    verdict_at = mapped_column(UTCDateTime, nullable=True)
    analyst_feedback: Mapped[str | None] = mapped_column(String(16), nullable=True)  # agree|disagree
    analyst_user: Mapped[str | None] = mapped_column(String(100), nullable=True)
    analyst_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    __table_args__ = (UniqueConstraint("tenant_id", "source", "external_id"),)


class VerifyRequest(Base):
    __tablename__ = "verify_requests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id"), index=True)
    upn: Mapped[str] = mapped_column(String(320), index=True)
    prompt: Mapped[str] = mapped_column(Text)
    created_at = mapped_column(UTCDateTime, default=utcnow)
    expires_at = mapped_column(UTCDateTime)
    delivered_at = mapped_column(UTCDateTime, nullable=True)
    delivered_to: Mapped[list] = mapped_column(JSONType, default=list)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)  # pending|answered|expired
    answer: Mapped[str | None] = mapped_column(String(8), nullable=True)  # yes|no
    answered_at = mapped_column(UTCDateTime, nullable=True)
    answered_by_install: Mapped[str | None] = mapped_column(String(64), nullable=True)
    answer_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)


class Verdict(Base):
    """History of every verdict (audit trail); alerts.verdict holds the current one."""
    __tablename__ = "verdicts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id"), index=True)
    verdict: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[str | None] = mapped_column(String(16), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at = mapped_column(UTCDateTime, default=utcnow)


class WriteBack(Base):
    __tablename__ = "writebacks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id"), index=True)
    target: Mapped[str] = mapped_column(String(16))  # halopsa|webhook
    verdict: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)  # pending|sent|failed
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at = mapped_column(UTCDateTime, default=utcnow)
    sent_at = mapped_column(UTCDateTime, nullable=True)


class BlockedDomain(Base):
    __tablename__ = "blocklist"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)  # NULL = all tenants
    domain: Mapped[str] = mapped_column(String(255))
    added_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at = mapped_column(UTCDateTime, default=utcnow)
    __table_args__ = (UniqueConstraint("tenant_id", "domain"),)


class FeedDomain(Base):
    """Host from a public threat-intel feed. Kept while any feed still lists it; expires after
    FEED_EXPIRE_DAYS unseen. Separate from the hand-curated blocklist, which is never auto-pruned."""
    __tablename__ = "feed_domains"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    domain: Mapped[str] = mapped_column(String(255), unique=True)
    sources: Mapped[list] = mapped_column(JSONType, default=list)
    first_seen = mapped_column(UTCDateTime, default=utcnow)
    last_seen = mapped_column(UTCDateTime, default=utcnow, index=True)


class FeedRun(Base):
    __tablename__ = "feed_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    started_at = mapped_column(UTCDateTime, default=utcnow, index=True)
    finished_at = mapped_column(UTCDateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="running")  # running|ok|partial|failed
    trigger: Mapped[str] = mapped_column(String(16), default="schedule")  # schedule|manual
    stats: Mapped[dict] = mapped_column(JSONType, default=dict)


class Enrollment(Base):
    """Self-enrolled extension install (community mode): its own revocable token instead of a shared
    tenant key, so one leaked or abusive install can be cut off alone."""
    __tablename__ = "enrollments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    install_id: Mapped[str] = mapped_column(String(64), unique=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    token_hint: Mapped[str] = mapped_column(String(8), default="")
    nickname: Mapped[str | None] = mapped_column(String(60), nullable=True)
    reporting: Mapped[str] = mapped_column(String(16), default="full")  # full|off
    created_at = mapped_column(UTCDateTime, default=utcnow)
    created_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    revoked_at = mapped_column(UTCDateTime, nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(100), nullable=True)


class Outbound(Base):
    """Outbox for browser events leaving the console: analyst notifications and SIEM export.
    One row per event per channel; retried by the job loop like write-backs."""
    __tablename__ = "outbound"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), index=True)
    channel: Mapped[str] = mapped_column(String(24))  # telegram|notify_webhook|mssp_telegram|siem_webhook|syslog
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)  # pending|sent|failed|suppressed
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at = mapped_column(UTCDateTime, default=utcnow)
    sent_at = mapped_column(UTCDateTime, nullable=True)


ROLES = ["mssp_admin", "analyst", "client_viewer"]


class ConsoleUser(Base):
    __tablename__ = "console_users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(100), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20))
    tenant_id: Mapped[str | None] = mapped_column(String(64), nullable=True)  # set = restricted to it
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at = mapped_column(UTCDateTime, default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts = mapped_column(UTCDateTime, default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(200))  # console user, "system", "install:<id>"
    action: Mapped[str] = mapped_column(String(64))
    tenant_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    target: Mapped[str | None] = mapped_column(String(200), nullable=True)
    detail: Mapped[dict] = mapped_column(JSONType, default=dict)


def audit(db, actor: str, action: str, tenant_id=None, target=None, **detail):
    db.add(AuditLog(actor=actor, action=action, tenant_id=tenant_id, target=target, detail=detail))
