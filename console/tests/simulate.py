#!/usr/bin/env python3
"""End-to-end simulation against a running SOCLens Console (stdlib only).

Simulates browsers (heartbeats, auth events, verify answers) and SIEM alerts, and checks that
every verdict type comes out of the §2 decision tree:

  CONFIRMED_BY_BROWSER  browser signed in at the same time from the same IP
  NOT_SEEN_IN_BROWSER   browser online, sign-in not seen (token replay)
  USER_DENIED           non-browser sign-in -> "was this you?" -> "No, not me"
  USER_CONFIRMED        browser sign-in but different IP -> ask -> "Yes, it was me"
  NO_COVERAGE           user has no SOCLens browser

Usage (stack from docker-compose.yml, BOOTSTRAP_TENANTS=demo:demo-key-change-me):
  python tests/simulate.py                         # https://localhost, Caddy local CA (not verified)
  python tests/simulate.py --base http://127.0.0.1:8000 --tenant demo --key demo-key-change-me
"""
import argparse
import json
import ssl
import sys
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

p = argparse.ArgumentParser()
p.add_argument("--base", default="https://localhost")
p.add_argument("--tenant", default="demo")
p.add_argument("--key", default="demo-key-change-me")
p.add_argument("--domain", default="clienta.example")
p.add_argument("--verify-tls", action="store_true", help="verify the TLS certificate (off for Caddy's local CA)")
args = p.parse_args()

sys.stdout.reconfigure(errors="replace")  # Windows consoles without UTF-8
CTX = None if args.verify_tls else ssl._create_unverified_context()
RUN = uuid.uuid4().hex[:6]
FAILS = []


def call(method, path, body=None, key=None, tenant=None, expect=200):
    req = urllib.request.Request(args.base.rstrip("/") + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "SOCLens-simulate/0.1")  # Cloudflare blocks the default Python-urllib UA (1010)
    req.add_header("Authorization", "Bearer " + (key or args.key))
    req.add_header("X-SOCLens-Tenant", tenant or args.tenant)
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=20) as r:
            status, data = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, data = e.code, e.read()
    if status != expect:
        raise SystemExit(f"{method} {path} -> {status} (expected {expect}): {data[:300]!r}")
    return json.loads(data) if data else None


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def upn(name):
    return f"{name}.{RUN}@{args.domain}"


def check(label, got, want):
    ok = got == want
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}: {got}" + ("" if ok else f" (expected {want})"))
    if not ok:
        FAILS.append(label)


class Browser:
    def __init__(self, user):
        self.install_id = str(uuid.uuid4())
        self.user = user

    def heartbeat(self):
        return call("POST", "/v1/heartbeat", {
            "installId": self.install_id, "userId": self.user, "accounts": [self.user], "ts": iso(now()),
            "version": "0.3.0", "browser": "Chrome/Windows", "ua": "simulate.py"})

    def auth_event(self, ts, outcome="success", flow="password"):
        return call("POST", "/v1/auth-events", {"events": [{
            "id": str(uuid.uuid4()), "ts": iso(ts), "type": "auth_event", "idp": "microsoft",
            "host": "login.microsoftonline.com", "tenantHint": args.domain, "accountHint": self.user,
            "flow": flow, "outcome": outcome, "referrerHost": "outlook.office.com",
            "tenantId": args.tenant, "userId": self.user, "installId": self.install_id, "version": "0.3.0"}]})

    def answer(self, verify_id, answer, expect=200):
        return call("POST", f"/v1/verify/{verify_id}/answer",
                    {"installId": self.install_id, "answer": answer, "ts": iso(now())}, expect=expect)


def now():
    return datetime.now(timezone.utc)


def alert(user, ts, ip, client_app="Browser", **extra):
    return call("POST", "/v1/alerts", dict({
        "source": "securonix", "externalId": f"SNX-{RUN}-{uuid.uuid4().hex[:6]}",
        "title": "Unusual sign-in location", "severity": "high", "upn": user, "ts": iso(ts), "ip": ip,
        "app": "Microsoft 365", "clientApp": client_app, "isInteractive": True,
        "location": {"city": "Singapore", "countryOrRegion": "SG"}}, **extra))


def main():
    print(f"SOCLens Console simulation against {args.base} (tenant {args.tenant}, run {RUN})")
    print("\n0. API basics")
    call("GET", "/v1/blocklist", key="wrong-key", expect=401)
    print("  [PASS] wrong API key rejected (401)")
    bl = call("GET", "/v1/blocklist")
    print(f"  [PASS] blocklist: {len(bl['domains'])} domain(s)")
    ev = call("POST", "/v1/events", {"events": [{
        "id": str(uuid.uuid4()), "ts": iso(now()), "type": "page_blocked", "severity": "critical",
        "url": "https://evil.example/login", "urlDefanged": "hxxps://evil[.]example/login", "host": "evil.example",
        "score": 90, "reasons": ["brand impersonation"], "brand": "Microsoft", "tenantId": args.tenant,
        "userId": upn("eve"), "installId": str(uuid.uuid4()), "version": "0.1.0", "ua": "simulate.py"}]})
    check("events accepted", ev["accepted"], 1)

    signin = now() - timedelta(minutes=2)   # SIEM alerts arrive a little after the sign-in

    print("\n1. CONFIRMED_BY_BROWSER: browser saw the sign-in, same IP")
    alice = Browser(upn("alice"))
    hb = alice.heartbeat()
    my_ip = hb["seenIp"]
    print(f"  console sees this simulator's egress IP as {my_ip}; binding={hb['binding']['upn']}")
    alice.auth_event(signin + timedelta(seconds=20))
    a = alert(alice.user, signin, my_ip)
    check("verdict", a["verdict"], "CONFIRMED_BY_BROWSER")
    check("confidence", a["confidence"], "high")

    print("\n2. NOT_SEEN_IN_BROWSER: browser online, no sign-in seen, foreign IP (token replay)")
    bob = Browser(upn("bob"))
    bob.heartbeat()
    a = alert(bob.user, signin, "203.0.113.50")
    not_seen_id = a["alertId"]
    check("verdict", a["verdict"], "NOT_SEEN_IN_BROWSER")
    check("user is also asked", bool(a["verifyRequest"]), True)
    pending = bob.heartbeat()["verifyRequests"]
    check("prompt delivered in heartbeat", len(pending), 1)

    print("\n3. USER_DENIED: non-browser sign-in -> ask -> 'No, not me'")
    carol = Browser(upn("carol"))
    carol.heartbeat()
    a = alert(carol.user, signin, "198.51.100.23", client_app="Mobile Apps and Desktop clients")
    check("waiting for user", a["verdict"], "PENDING_USER")
    pending = carol.heartbeat()["verifyRequests"]
    check("prompt delivered in heartbeat", len(pending), 1)
    if pending:
        print(f"  prompt: {pending[0]['prompt']}")
        stranger = Browser(upn("mallory"))
        stranger.heartbeat()
        stranger.answer(pending[0]["id"], "yes", expect=403)
        print("  [PASS] answer from a browser not bound to the user rejected (403)")
        res = carol.answer(pending[0]["id"], "no")
        check("verdict after answer", res["verdict"], "USER_DENIED")
        carol.answer(pending[0]["id"], "yes", expect=409)
        print("  [PASS] second answer rejected (409)")
        final = call("GET", f"/v1/alerts/{a['alertId']}")
        check("Evidence Card mentions P1", "P1" in (final["evidenceCard"]["markdown"] or ""), True)

    print("\n4. NO_COVERAGE: user has no SOCLens browser")
    a = alert(upn("dave"), signin, "192.0.2.10")
    check("verdict", a["verdict"], "NO_COVERAGE")

    print("\n5. USER_CONFIRMED: browser sign-in but IP differs (VPN) -> ask -> 'Yes, it was me'")
    erin = Browser(upn("erin"))
    erin.heartbeat()
    erin.auth_event(signin + timedelta(seconds=30))
    a = alert(erin.user, signin, "198.51.100.77")
    check("waiting for user", a["verdict"], "PENDING_USER")
    pending = erin.heartbeat()["verifyRequests"]
    if pending:
        res = erin.answer(pending[0]["id"], "yes")
        check("verdict after answer", res["verdict"], "USER_CONFIRMED")
    else:
        check("prompt delivered", 0, 1)

    print("\n6. Duplicate alert is not re-processed")
    a1 = alert(upn("frank"), signin, "192.0.2.11", externalId=f"DUP-{RUN}")
    a2 = alert(upn("frank"), signin, "192.0.2.11", externalId=f"DUP-{RUN}")
    check("same alert id", a1["alertId"] == a2["alertId"], True)

    print("\nEvidence Card (NOT_SEEN_IN_BROWSER case, as written back to the ticket):")
    card = call("GET", f"/v1/alerts/{not_seen_id}")["evidenceCard"]["markdown"] or ""
    print("\n".join("  " + line for line in card.splitlines()))

    print("\n" + ("ALL CHECKS PASSED" if not FAILS else f"{len(FAILS)} CHECK(S) FAILED: {', '.join(FAILS)}"))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
