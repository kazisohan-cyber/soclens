import os
import secrets


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./soclens-dev.db")
SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
COOKIE_SECURE = _bool("COOKIE_SECURE", False)

# Where the browser's real egress IP comes from (heartbeats and auth events depend on it):
#   caddy      - last X-Forwarded-For hop (Caddy sets it and ignores client-supplied values
#                unless trusted_proxies is configured)
#   cloudflare - CF-Connecting-IP (set by Cloudflare's edge, passed through by cloudflared)
#   none       - the TCP peer address
# A header is only trustworthy when the console port is reachable through that proxy alone.
# Unset falls back to the legacy TRUST_PROXY switch (true = caddy).
PROXY_MODE = os.environ.get("PROXY_MODE", "").strip().lower() or ("caddy" if _bool("TRUST_PROXY", True) else "none")
if PROXY_MODE not in ("caddy", "cloudflare", "none"):
    raise RuntimeError(f"PROXY_MODE must be caddy, cloudflare or none, not {PROXY_MODE!r}")

# Request body cap, enforced in the app so it holds without Caddy in front (tunnel mode).
MAX_BODY_BYTES = _int("MAX_BODY_BYTES", 2 * 1024 * 1024)

ADMIN_USER = os.environ.get("CONSOLE_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("CONSOLE_ADMIN_PASSWORD", "")
# "slug:apiKey,slug2:apiKey2" - created on startup if missing (dev / first boot only).
BOOTSTRAP_TENANTS = os.environ.get("BOOTSTRAP_TENANTS", "")

# Correlation (§2 / §4 of the design doc)
MATCH_WINDOW_SEC = _int("MATCH_WINDOW_SEC", 180)          # auth event ±3 min
HEARTBEAT_WINDOW_SEC = _int("HEARTBEAT_WINDOW_SEC", 600)  # browser online ±10 min
SETTLE_SEC = _int("SETTLE_SEC", 60)  # wait for late auth-event batches before NOT_SEEN
GEOIP_ASN_DB = os.environ.get("GEOIP_ASN_DB", "/data/GeoLite2-ASN.mmdb")

# Retention (§4 data model / §6 privacy)
HEARTBEAT_RETENTION_DAYS = _int("HEARTBEAT_RETENTION_DAYS", 7)
AUTH_EVENT_RETENTION_DAYS = _int("AUTH_EVENT_RETENTION_DAYS", 30)

HEARTBEAT_INTERVAL_SEC = _int("HEARTBEAT_INTERVAL_SEC", 300)

# Threat-intel feeds (feeds.py): synced at these local hours; the default offset is Malaysia (UTC+8, no DST).
FEEDS_ENABLED = _bool("FEEDS_ENABLED", True)
FEED_SOURCES = [s.strip() for s in os.environ.get("FEED_SOURCES", "phishtank,openphish,urlhaus").split(",") if s.strip()]
FEED_SYNC_HOURS = sorted({int(h) % 24 for h in os.environ.get("FEED_SYNC_HOURS", "0,6,12,18").split(",") if h.strip()})
FEED_TZ_OFFSET_MIN = _int("FEED_TZ_OFFSET_MIN", 480)
FEED_EXPIRE_DAYS = _int("FEED_EXPIRE_DAYS", 7)
FEED_TRANCO_TOP = _int("FEED_TRANCO_TOP", 100000)   # never block the N most popular domains
FEED_MAX_DOMAINS = _int("FEED_MAX_DOMAINS", 100000)
FEED_CACHE_DIR = os.environ.get("FEED_CACHE_DIR", "/tmp/soclens-feeds")

# Community self-enrollment (POST /v1/enroll): extensions with no configured key enroll themselves.
COMMUNITY_ENROLL = _bool("COMMUNITY_ENROLL", False)
COMMUNITY_TENANT = os.environ.get("COMMUNITY_TENANT", "community")
ENROLL_MAX_PER_IP_HOUR = _int("ENROLL_MAX_PER_IP_HOUR", 5)
ENROLL_MAX_TOTAL = _int("ENROLL_MAX_TOTAL", 50)
COMMUNITY_EVENT_RETENTION_DAYS = _int("COMMUNITY_EVENT_RETENTION_DAYS", 30)  # promised on the consent page

# Public URL of this console, used for links in notifications.
CONSOLE_URL = os.environ.get("CONSOLE_URL", "").rstrip("/")
# MSSP-wide Telegram channel: serious events from every tenant (tenants can add their own channels).
NOTIFY_TELEGRAM_BOT_TOKEN = os.environ.get("NOTIFY_TELEGRAM_BOT_TOKEN", "")
NOTIFY_TELEGRAM_CHAT_ID = os.environ.get("NOTIFY_TELEGRAM_CHAT_ID", "")
NOTIFY_MSSP_MIN_SEVERITY = os.environ.get("NOTIFY_MSSP_MIN_SEVERITY", "critical")
NOTIFY_MAX_PER_HOUR = _int("NOTIFY_MAX_PER_HOUR", 20)   # per tenant per channel; the rest is suppressed
OUTBOUND_MAX_ATTEMPTS = _int("OUTBOUND_MAX_ATTEMPTS", 5)
JOB_INTERVAL_SEC = _int("JOB_INTERVAL_SEC", 15)
WRITEBACK_MAX_ATTEMPTS = _int("WRITEBACK_MAX_ATTEMPTS", 5)
