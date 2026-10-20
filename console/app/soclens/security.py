import hashlib
import hmac
import ipaddress
import logging
import secrets

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import config
from .db import get_db
from .models import Enrollment, Tenant

log = logging.getLogger("soclens.security")
INSTALL_TOKEN_PREFIX = "sli_"


def require_tenant_key(request: Request):
    """For SIEM/SOAR endpoints: a self-enrolled browser token must never read or create alerts."""
    if getattr(request.state, "install_id", None):
        raise HTTPException(403, "install tokens cannot use this endpoint")


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def new_api_key() -> str:
    return "slk_" + secrets.token_urlsafe(32)


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${dk.hex()}"


def check_password(pw: str, stored: str) -> bool:
    try:
        _, salt, dk = stored.split("$")
        got = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1, dklen=32)
        return hmac.compare_digest(got.hex(), dk)
    except Exception:
        return False


def _ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def client_ip(request: Request) -> str | None:
    """Browser egress IP, read from the header the configured proxy sets (config.PROXY_MODE)."""
    if config.PROXY_MODE == "cloudflare":
        ip = _ip(request.headers.get("cf-connecting-ip", ""))
        if not ip:
            # The peer would be the cloudflared container, never the browser: record nothing rather
            # than a wrong IP (the correlation engine then asks the user instead of matching).
            log.warning("PROXY_MODE=cloudflare but no valid CF-Connecting-IP on %s", request.url.path)
        return ip
    if config.PROXY_MODE == "caddy":
        for part in reversed(request.headers.get("x-forwarded-for", "").split(",")):
            ip = _ip(part)
            if ip:
                return ip
    return request.client.host if request.client else None


class BodyLimit:
    """ASGI middleware: 413 for request bodies over max_bytes, by Content-Length or by counting chunks."""

    def __init__(self, app, max_bytes: int):
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        cl = dict(scope["headers"]).get(b"content-length", b"")
        if cl.isdigit() and int(cl) > self.max_bytes:
            await send({"type": "http.response.start", "status": 413,
                        "headers": [(b"content-type", b"application/json")]})
            return await send({"type": "http.response.body", "body": b'{"detail":"request body too large"}'})
        seen = 0

        async def limited_receive():
            nonlocal seen
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body", b""))
                if seen > self.max_bytes:
                    raise HTTPException(413, "request body too large")
            return msg

        return await self.app(scope, limited_receive, send)


def new_install_token() -> str:
    return INSTALL_TOKEN_PREFIX + secrets.token_urlsafe(32)


def tenant_auth(
    request: Request,
    authorization: str = Header(default=""),
    x_soclens_tenant: str = Header(default=""),
    db: Session = Depends(get_db),
) -> Tenant:
    """Per-tenant API key (`Authorization: Bearer <key>` + `X-SOCLens-Tenant: <slug>`), or a self-enrolled
    install token (`Bearer sli_...`), which pins the request to that one install (request.state.install_id)."""
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing Bearer token")
    key = authorization[7:].strip()
    if key.startswith(INSTALL_TOKEN_PREFIX):
        e = db.scalars(select(Enrollment).where(Enrollment.token_hash == hash_api_key(key))).first()
        if not e:
            raise HTTPException(401, "invalid install token")
        if e.revoked_at:
            raise HTTPException(401, "install revoked")
        request.state.tenant_id, request.state.install_id, request.state.enrollment = e.tenant_id, e.install_id, e
        return db.get(Tenant, e.tenant_id)
    if not x_soclens_tenant:
        raise HTTPException(401, "missing X-SOCLens-Tenant")
    t = db.get(Tenant, x_soclens_tenant.strip())
    if not t or not hmac.compare_digest(t.api_key_hash, hash_api_key(key)):
        raise HTTPException(401, "invalid tenant credentials")
    request.state.tenant_id = t.id
    return t
