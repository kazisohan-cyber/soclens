"""Threat-intel feed sync: public phishing/malware feeds -> feed_domains, merged into GET /v1/blocklist.

Safety first: the feeds also list abused *shared* hosts (google.com, github.com, docs.google.com, a
company's SharePoint). The extension blocks a host together with all of its subdomains, so those must
never be imported. Every candidate passes `is_protected` (Tranco top-N, shared-service hosts, big-brand
suffixes); without a Tranco list the sync refuses to run instead of importing unfiltered data.
"""
import asyncio
import csv
import io
import ipaddress
import logging
import os
import re
import time
import zipfile
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import httpx
from sqlalchemy import delete, func, select

from . import config
from .db import session_scope, utcnow
from .models import FeedDomain, FeedRun, audit

log = logging.getLogger("soclens.feeds")

UA = "SOCLens-feeds/0.2" + (f" (+{config.CONSOLE_URL})" if config.CONSOLE_URL else "")
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
TRANCO_STRICT = 10000  # subdomains of these sites belong to the site itself (mail.yahoo.com)
SOURCES = {
    # name: (url, format). Licences: URLhaus CC0; PhishTank free with attribution;
    # OpenPhish community feed is non-commercial only (drop it from FEED_SOURCES before selling).
    "phishtank": ("https://data.phishtank.com/data/online-valid.csv", "phishtank_csv"),
    "openphish": ("https://openphish.com/feed.txt", "lines"),
    "urlhaus": ("https://urlhaus.abuse.ch/downloads/text_online/", "lines"),
}
MAX_BYTES = 60 * 1024 * 1024
SHRINK_GUARD = 0.5       # a source returning < 50% of its last good count is treated as broken
RETRY_FAILED_MIN = 30
STALE_RUN_MIN = 30

# Exact hosts where anyone can publish content: abused constantly, never ours to block.
SHARED_HOSTS = {
    "docs.google.com", "drive.google.com", "sites.google.com", "forms.gle", "goo.gl", "storage.googleapis.com",
    "firebasestorage.googleapis.com", "raw.githubusercontent.com", "gist.github.com", "objects.githubusercontent.com",
    "onedrive.live.com", "1drv.ms", "forms.office.com", "forms.microsoft.com", "s3.amazonaws.com",
    "cdn.discordapp.com", "media.discordapp.net", "discord.com", "t.me", "telegram.me", "wa.me",
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "linktr.ee", "lnkd.in",
    "dropbox.com", "www.dropbox.com", "dl.dropboxusercontent.com", "web.archive.org", "archive.org",
    "ipfs.io", "dweb.link", "w3s.link", "cloudflare-ipfs.com", "translate.goog", "docs.zoho.com",
    "app.box.com", "we.tl", "wetransfer.com", "mega.nz", "canva.com", "www.canva.com", "notion.so",
}
# Big brands: every subdomain is theirs (a compromised tenant is still a real customer's site).
PROTECTED_SUFFIXES = (
    "google.com", "googleusercontent.com", "microsoft.com", "microsoftonline.com", "office.com", "office365.com",
    "live.com", "outlook.com", "sharepoint.com", "onedrive.com", "apple.com", "icloud.com", "github.com",
    "amazon.com", "paypal.com", "facebook.com", "instagram.com", "whatsapp.com", "linkedin.com", "yahoo.com",
    "adobe.com", "zoom.us", "dropbox.com", "salesforce.com", "force.com", "translate.goog",
    # form / survey services: forms live under their own hosts and paths
    "qualtrics.com", "typeform.com", "jotform.com", "wufoo.com", "formstack.com", "surveymonkey.com",
)
# User-content platforms: the platform is legitimate, each subdomain is someone else's site.
HOSTING_ROOTS = {
    "pages.dev", "workers.dev", "r2.dev", "trycloudflare.com", "web.app", "firebaseapp.com", "appspot.com",
    "netlify.app", "vercel.app", "onrender.com", "herokuapp.com", "fly.dev", "railway.app", "glitch.me",
    "repl.co", "replit.app", "replit.dev", "codesandbox.io", "csb.app", "stackblitz.io", "ngrok.io",
    "ngrok-free.app", "ngrok.app", "loca.lt", "serveo.net", "github.io", "gitlab.io", "gitbook.io", "framer.app",
    "framer.website", "framer.ai", "webflow.io", "carrd.co", "000webhostapp.com", "wixsite.com", "wixstudio.com",
    "wixstudio.io", "weebly.com", "weeblysite.com", "square.site", "godaddysites.com", "myshopify.com",
    "blogspot.com", "wordpress.com", "azurewebsites.net", "azurestaticapps.net", "web.core.windows.net",
    "blob.core.windows.net", "cloudfront.net", "s3.amazonaws.com", "amplifyapp.com", "surge.sh", "tiiny.site",
    "yolasite.com", "jimdosite.com", "mystrikingly.com", "fleek.co", "on.fleek.co", "notion.site", "canva.site",
    "my.canva.site", "webnode.page", "ukit.me", "site123.me", "hpage.com", "mybluehost.me", "b-cdn.net",
    "myqcloud.com", "aliyuncs.com", "backblazeb2.com", "digitaloceanspaces.com", "linodeobjects.com",
    "duckdns.org", "ddnss.de", "eu.org", "myportfolio.com", "lovable.app", "run.app", "ondigitalocean.app",
    "cloudwaysapps.com", "wpenginepowered.com", "jimdofree.com", "plesk.page", "temporary.site",
    "blogspot.de", "blogspot.ca", "blogspot.fr", "blogspot.co.uk", "blogspot.in", "blogspot.my",
}
# Second-level labels of country-code suffixes: "co.uk" must never be treated as a site.
SLD_LABELS = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "gob", "mil", "nic", "ltd", "plc",
              "sch", "info", "biz", "nom", "gen", "firm", "web", "in", "my"}
HOST_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")


# ------------------------------------------------------------------ parsing / filtering

def host_of(url: str) -> str | None:
    """Host to block for a feed URL: lower-case, punycode, IPv4 kept only when public."""
    url = (url or "").strip()
    if not url or url.startswith("#"):
        return None
    if "://" not in url:
        url = "http://" + url
    try:
        h = urlsplit(url).hostname
    except ValueError:
        return None
    if not h:
        return None
    h = h.strip(".").lower()
    try:
        ip = ipaddress.ip_address(h)
        return str(ip) if ip.version == 4 and ip.is_global else None
    except ValueError:
        pass
    try:
        h = h.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return h if HOST_RE.match(h) else None


def registrable(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in SLD_LABELS and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _under(host: str, suffix: str) -> bool:
    return host == suffix or host.endswith("." + suffix)


def is_protected(host: str, popular: set[str], strict: set[str]) -> bool:
    """True when blocking `host` (and its subdomains) could break a legitimate site."""
    parts = host.split(".")
    if len(parts) == 2 and parts[0] in SLD_LABELS:
        return True  # a public suffix such as co.uk
    if host in SHARED_HOSTS or host in HOSTING_ROOTS:
        return True
    if any(_under(host, s) for s in PROTECTED_SUFFIXES):
        return True
    if any(host.endswith("." + r) for r in HOSTING_ROOTS):
        return False  # someone's site on a hosting platform: safe to block that one host
    bare = host[4:] if host.startswith("www.") else host
    if host in popular or bare in popular:
        return True
    return registrable(host) in strict


def parse(kind: str, data: bytes) -> set[str]:
    text = data.decode("utf-8", "replace")
    if kind == "phishtank_csv":
        urls = (row.get("url", "") for row in csv.DictReader(io.StringIO(text)))
    else:
        urls = text.splitlines()
    return {h for h in map(host_of, urls) if h}


# ------------------------------------------------------------------ fetching

def _get(client: httpx.Client, url: str) -> bytes:
    with client.stream("GET", url) as r:
        r.raise_for_status()
        buf = bytearray()
        for chunk in r.iter_bytes():
            buf += chunk
            if len(buf) > MAX_BYTES:
                raise ValueError(f"response over {MAX_BYTES // 2**20} MB")
    return bytes(buf)


def load_popular(client: httpx.Client) -> tuple[set[str], set[str]]:
    """Tranco top-N (cached a day). Raises when no list is available at all: no filter, no import."""
    path = os.path.join(config.FEED_CACHE_DIR, "tranco-top.txt")
    if not (os.path.exists(path) and time.time() - os.path.getmtime(path) < 86400):
        try:
            with zipfile.ZipFile(io.BytesIO(_get(client, TRANCO_URL))) as z:
                lines = z.read(z.namelist()[0]).decode("utf-8", "replace").splitlines()
            doms = [ln.split(",", 1)[1].strip().lower() for ln in lines[:config.FEED_TRANCO_TOP] if "," in ln]
            if len(doms) < min(1000, config.FEED_TRANCO_TOP):
                raise ValueError(f"Tranco list looks truncated ({len(doms)} rows)")
            os.makedirs(config.FEED_CACHE_DIR, exist_ok=True)
            with open(path + ".tmp", "w", encoding="ascii", errors="ignore") as f:
                f.write("\n".join(doms))
            os.replace(path + ".tmp", path)
        except Exception as e:  # noqa: BLE001
            if not os.path.exists(path):
                raise RuntimeError(f"no Tranco list ({e}); refusing to import unfiltered feeds") from e
            log.warning("Tranco refresh failed, using cached list: %s", e)
    with open(path, encoding="ascii", errors="ignore") as f:
        doms = f.read().split()
    return set(doms), set(doms[:TRANCO_STRICT])


# ------------------------------------------------------------------ sync

def _last_good_counts(db) -> dict[str, int]:
    run = db.scalars(select(FeedRun).where(FeedRun.status.in_(("ok", "partial")))
                     .order_by(FeedRun.id.desc()).limit(1)).first()
    out = {}
    for name, s in ((run.stats or {}).get("sources", {}) if run else {}).items():
        if isinstance(s, dict) and "error" not in s and s.get("kept"):
            out[name] = s["kept"]
    return out


def _store(found: dict[str, set[str]], popular, strict) -> dict:
    now = utcnow()
    added = updated = unprotected = 0
    with session_scope() as db:
        existing = {d.domain: d for d in db.scalars(select(FeedDomain)).all()}
        for dom, row in existing.items():
            if is_protected(dom, popular, strict):  # filter rules or Tranco changed since it was stored
                db.delete(row)
                unprotected += 1
        for h, srcs in found.items():
            row = existing.get(h)
            if row is None:
                db.add(FeedDomain(domain=h, sources=sorted(srcs), first_seen=now, last_seen=now))
                added += 1
            else:
                row.last_seen = now
                merged = sorted(set(row.sources or []) | srcs)
                if merged != row.sources:
                    row.sources = merged
                updated += 1
        db.flush()
        expired = db.execute(delete(FeedDomain).where(
            FeedDomain.last_seen < now - timedelta(days=config.FEED_EXPIRE_DAYS))).rowcount or 0
        total = db.scalar(select(func.count(FeedDomain.id))) or 0
        trimmed = 0
        if total > config.FEED_MAX_DOMAINS:
            cut = db.scalars(select(FeedDomain.id).order_by(FeedDomain.last_seen.desc(), FeedDomain.id.desc())
                             .offset(config.FEED_MAX_DOMAINS)).all()
            trimmed = db.execute(delete(FeedDomain).where(FeedDomain.id.in_(cut))).rowcount or 0
            total -= trimmed
    return {"added": added, "refreshed": updated, "expired": expired, "removed_protected": unprotected,
            "trimmed": trimmed, "total": total}


def sync(trigger: str = "schedule") -> dict:
    with session_scope() as db:
        busy = db.scalars(select(FeedRun).where(
            FeedRun.status == "running", FeedRun.started_at > utcnow() - timedelta(minutes=STALE_RUN_MIN))).first()
        if busy:
            return {"status": "skipped", "reason": f"run {busy.id} still running"}
        run = FeedRun(trigger=trigger)
        db.add(run)
        db.flush()
        run_id = run.id
        prev = _last_good_counts(db)
    stats: dict = {"sources": {}}
    status = "ok"
    try:
        with httpx.Client(headers={"User-Agent": UA}, timeout=90, follow_redirects=True) as client:
            popular, strict = load_popular(client)
            found: dict[str, set[str]] = {}
            for name in config.FEED_SOURCES:
                if name not in SOURCES:
                    stats["sources"][name], status = {"error": "unknown source"}, "partial"
                    continue
                url, kind = SOURCES[name]
                if name == "phishtank":
                    # PhishTank's edge caches its 302 to a signed CDN link longer than the link lives,
                    # so a cached redirect can point at an expired URL (404). A unique query skips that cache.
                    url += f"?t={int(time.time())}"
                try:
                    raw = parse(kind, _get(client, url))
                except Exception as e:  # noqa: BLE001
                    stats["sources"][name], status = {"error": str(e)[:200]}, "partial"
                    continue
                kept = {h for h in raw if not is_protected(h, popular, strict)}
                s = {"hosts": len(raw), "kept": len(kept), "filtered": len(raw) - len(kept)}
                if prev.get(name) and len(kept) < prev[name] * SHRINK_GUARD:
                    s["error"] = f"shrank from {prev[name]} to {len(kept)}; previous data kept"
                    stats["sources"][name], status = s, "partial"
                    continue
                stats["sources"][name] = s
                for h in kept:
                    found.setdefault(h, set()).add(name)
        if not found and status != "ok":
            raise RuntimeError("every source failed")
        stats.update(_store(found, popular, strict))
    except Exception as e:  # noqa: BLE001
        status = "failed"
        stats["error"] = str(e)[:300]
        log.exception("feed sync failed")
    with session_scope() as db:
        run = db.get(FeedRun, run_id)
        run.status, run.finished_at, run.stats = status, utcnow(), stats
        audit(db, "system", "feed_sync", None, None, run=run_id, status=status,
              total=stats.get("total"), added=stats.get("added"), expired=stats.get("expired"),
              error=stats.get("error"))
    log.info("feed sync %s: %s", status, {k: v for k, v in stats.items() if k != "sources"})
    return dict(stats, status=status, run=run_id)


# ------------------------------------------------------------------ schedule

def last_slot(now: datetime) -> datetime | None:
    """Most recent scheduled sync time (local FEED_SYNC_HOURS) at or before `now`, as UTC."""
    if not config.FEED_SYNC_HOURS:
        return None
    tz = timezone(timedelta(minutes=config.FEED_TZ_OFFSET_MIN))
    local = now.astimezone(tz)
    today = [local.replace(hour=h, minute=0, second=0, microsecond=0) for h in config.FEED_SYNC_HOURS]
    past = [s for s in today if s <= local] or [s - timedelta(days=1) for s in today]
    return max(past).astimezone(timezone.utc)


def is_due(db, now: datetime | None = None) -> bool:
    now = now or utcnow()
    slot = last_slot(now)
    if slot is None:
        return False
    last = db.scalars(select(FeedRun).order_by(FeedRun.id.desc()).limit(1)).first()
    if last is None or last.started_at < slot:
        return True
    return last.status == "failed" and last.started_at < now - timedelta(minutes=RETRY_FAILED_MIN)


async def run_forever():
    if not config.FEEDS_ENABLED:
        log.info("threat feeds disabled (FEEDS_ENABLED=false)")
        return
    await asyncio.sleep(20)  # let startup finish first
    while True:
        try:
            with session_scope() as db:
                due = is_due(db)
            if due:
                await asyncio.to_thread(sync, "schedule")
        except Exception:  # noqa: BLE001
            log.exception("feed scheduler tick failed")
        await asyncio.sleep(60)
