import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select, text
from starlette.middleware.sessions import SessionMiddleware

from . import VERSION, config, feeds, jobs
from .api import router as api_router
from .dashboard import router as dash_router
from .db import Base, engine, session_scope
from .models import ConsoleUser, Tenant, audit
from .security import BodyLimit, hash_api_key, hash_password

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("soclens")


def bootstrap():
    Base.metadata.create_all(engine)
    with session_scope() as db:
        if config.ADMIN_PASSWORD and not db.scalars(select(ConsoleUser).limit(1)).first():
            db.add(ConsoleUser(username=config.ADMIN_USER, password_hash=hash_password(config.ADMIN_PASSWORD),
                               role="mssp_admin"))
            audit(db, "system", "user_created", None, config.ADMIN_USER, role="mssp_admin", via="bootstrap")
            log.info("created bootstrap admin %s", config.ADMIN_USER)
        for pair in filter(None, (p.strip() for p in config.BOOTSTRAP_TENANTS.split(","))):
            slug, _, key = pair.partition(":")
            if slug and key and not db.get(Tenant, slug):
                db.add(Tenant(id=slug, name=slug, api_key_hash=hash_api_key(key), api_key_hint=key[-4:], settings={}))
                audit(db, "system", "tenant_created", slug, slug, via="bootstrap")
                log.info("created bootstrap tenant %s", slug)


@asynccontextmanager
async def lifespan(app: FastAPI):
    bootstrap()
    tasks = [asyncio.create_task(jobs.run_forever()), asyncio.create_task(feeds.run_forever())]
    yield
    for task in tasks:
        task.cancel()


app = FastAPI(title="SOCLens Console", version=VERSION, lifespan=lifespan, docs_url="/api/docs",
              redoc_url=None, openapi_url="/api/openapi.json")
app.add_middleware(SessionMiddleware, secret_key=config.SECRET_KEY, session_cookie="soclens_session",
                   same_site="lax", https_only=config.COOKIE_SECURE, max_age=12 * 3600)
app.add_middleware(BodyLimit, max_bytes=config.MAX_BODY_BYTES)

# Set here as well as in the Caddyfile, so they hold behind a Cloudflare Tunnel too.
SECURITY_HEADERS = {"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.update(SECURITY_HEADERS)
    if config.COOKIE_SECURE:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")
app.include_router(api_router)
app.include_router(dash_router)


@app.get("/healthz", include_in_schema=False)
def healthz():
    with engine.connect() as c:
        c.execute(text("select 1"))
    return {"ok": True, "version": VERSION}
