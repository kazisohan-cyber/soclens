"""Admin CLI:  docker compose exec console python -m soclens.cli <command>

  create-tenant <slug> [name]       prints the new API key once
  rotate-key <slug>                 prints the new API key once
  create-user <username> <role> [tenant]   prompts for the password
  purge                              apply retention now
  sync-feeds                         pull the threat-intel feeds now
  revoke-install <install-id>        cut off one self-enrolled browser
"""
import getpass
import json
import sys

from sqlalchemy import select

from . import feeds
from .db import Base, engine, session_scope, utcnow
from .jobs import purge
from .models import ROLES, ConsoleUser, Enrollment, Tenant, audit
from .security import hash_api_key, hash_password, new_api_key


def main(argv):
    if not argv:
        print(__doc__)
        return 1
    Base.metadata.create_all(engine)
    cmd, args = argv[0], argv[1:]
    if cmd == "sync-feeds":
        r = feeds.sync("manual")
        print(json.dumps(r, indent=2, default=str))
        return 0 if r.get("status") in ("ok", "partial", "skipped") else 1
    with session_scope() as db:
        if cmd == "revoke-install" and args:
            e = db.scalars(select(Enrollment).where(Enrollment.install_id == args[0])).first()
            if not e:
                print("no such enrolled install"); return 1
            e.revoked_at, e.revoked_by = utcnow(), "cli"
            audit(db, "cli", "install_revoked", e.tenant_id, e.install_id)
            print(f"revoked {e.install_id} ({e.nickname or 'no nickname'})")
            return 0
        if cmd == "create-tenant" and args:
            if db.get(Tenant, args[0]):
                print("tenant exists"); return 1
            key = new_api_key()
            db.add(Tenant(id=args[0], name=" ".join(args[1:]) or args[0], api_key_hash=hash_api_key(key),
                          api_key_hint=key[-4:], settings={}))
            audit(db, "cli", "tenant_created", args[0], args[0])
            print(f"tenant {args[0]} api key: {key}")
        elif cmd == "rotate-key" and args:
            t = db.get(Tenant, args[0])
            if not t:
                print("no such tenant"); return 1
            key = new_api_key()
            t.api_key_hash, t.api_key_hint = hash_api_key(key), key[-4:]
            audit(db, "cli", "tenant_key_rotated", t.id, t.id)
            print(f"tenant {t.id} new api key: {key}")
        elif cmd == "create-user" and len(args) >= 2 and args[1] in ROLES:
            pw = getpass.getpass("password: ")
            if len(pw) < 12:
                print("password must be 12+ chars"); return 1
            db.add(ConsoleUser(username=args[0], password_hash=hash_password(pw), role=args[1],
                               tenant_id=args[2] if len(args) > 2 else None))
            audit(db, "cli", "user_created", args[2] if len(args) > 2 else None, args[0], role=args[1])
            print("ok")
        elif cmd == "purge":
            print(purge(db))
        else:
            print(__doc__)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
