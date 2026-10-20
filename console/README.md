# SOCLens Console

Self-hosted, multi-tenant backend for the SOCLens extension and **SOCLens Verify**
(SOCLens Verify: when the SIEM raises an identity alert, the console checks browser ground truth and can ask the user "was this you?").

Stack: **FastAPI** service + **Postgres 16** + **Caddy** (automatic HTTPS) via Docker Compose.

```
console/
  docker-compose.yml   Caddyfile   .env.example
  app/                 Dockerfile, requirements.txt, soclens/ (the service)
  tests/simulate.py    end-to-end simulation (stdlib only)
  geoip/               optional GeoLite2-ASN.mmdb for same-ASN IP matching
```

## Run it

```bash
cd console
cp .env.example .env      # then edit every value
docker compose up -d --build
python tests/simulate.py  # https://localhost, tenant "demo" from BOOTSTRAP_TENANTS
```

- Dashboard: `https://<CONSOLE_DOMAIN>/` (log in with `CONSOLE_ADMIN_USER` / `CONSOLE_ADMIN_PASSWORD`; that account is only created when no console users exist).
- API docs: `https://<CONSOLE_DOMAIN>/api/docs`.
- With `CONSOLE_DOMAIN=localhost`, Caddy uses its local CA (the simulator skips TLS verification). On the VPS, set `CONSOLE_DOMAIN` to a real hostname whose DNS points at the VPS, and open ports 80 and 443. Caddy then gets a public certificate automatically.
- **Behind a Cloudflare Tunnel instead** (when ports 80/443 already belong to another app on the host): in the Cloudflare Zero Trust dashboard create a tunnel, add a public hostname pointing to `http://console:8000`, and copy the tunnel token. In `.env` set `COMPOSE_PROFILES=tunnel`, `PROXY_MODE=cloudflare` and `CF_TUNNEL_TOKEN=<token>`. No host ports are published, and the console reads the browser IP from `CF-Connecting-IP`. Leave caching off for this hostname: the `/v1/*` API must never be cached.
- `COMPOSE_PROFILES` must be set (`caddy` or `tunnel`), otherwise no front end starts. Security headers and the 2 MB body cap are applied by the app itself, so they hold in both modes.
- Production: remove `BOOTSTRAP_TENANTS` and create tenants in **Tenants** (the key is shown once) or with the CLI:

```bash
docker compose exec console python -m soclens.cli create-tenant client-a "Client A Sdn Bhd"
docker compose exec console python -m soclens.cli create-user analyst1 analyst
docker compose exec console python -m soclens.cli create-user clienta-view client_viewer client-a
```

## Authentication

Every `/v1/*` call carries `Authorization: Bearer <tenant API key>` and `X-SOCLens-Tenant: <tenant id>`. Keys are stored as SHA-256 hashes, and each tenant has one key that can be rotated. The SIEM alert webhook uses the same tenant key.

## API

Times are ISO-8601 UTC. Batches hold at most 50 items. Unknown fields are ignored.

### `POST /v1/events` (existing extension contract, unchanged)
`{ "events": [Event, ...] }` → `{ "ok": true, "accepted": n, "authEvents": n }`. Events are deduplicated on `id`.
For the new v0.3 types the console also does this:
- `auth_event` / `device_code_warning` are also stored as auth events (same fields as below).
- `verify_answer` with `verifyId` + `answer` (`yes`|`no`) is applied like `POST /v1/verify/{id}/answer`.

### `GET /v1/blocklist`
→ `{ "domains": [...] }` (tenant entries plus global entries; managed under Tenants → Blocklist).

### `POST /v1/auth-events`
```json
{ "events": [{
  "id": "uuid", "ts": "2026-10-19T08:00:00Z", "type": "auth_event",
  "idp": "microsoft|google|okta|<corporate>", "host": "login.microsoftonline.com",
  "tenantHint": "clienta.com", "accountHint": "alice@clienta.com",
  "flow": "password|device_code|consent|sso", "outcome": "success|failure|unknown",
  "referrerHost": "mail.google.com", "openerHost": "teams.microsoft.com",
  "tenantId": "client-a", "userId": "alice@clienta.com", "installId": "uuid", "version": "0.3.0", "ua": "..."
}]}
```
→ `{ "ok": true, "accepted": n }`. The console records the request's source IP on every auth event.
Successful `accountHint`s count toward identity binding.

### `POST /v1/heartbeat` (every 5 min)
```json
{ "installId": "uuid", "userId": "alice@clienta.com", "accounts": ["alice@clienta.com", "alice.adm@clienta.com"],
  "ts": "...", "version": "0.3.0", "browser": "Chrome/Windows", "ua": "..." }
```
Response:
```json
{ "ok": true, "serverTime": "...", "seenIp": "203.0.113.5", "nextHeartbeatSec": 300,
  "binding": { "upn": "alice@clienta.com", "source": "policy|account_hint", "accounts": [...], "confirmed": true },
  "verifyRequests": [{
    "id": "uuid", "upn": "alice@clienta.com",
    "prompt": "Sign-in to Microsoft 365 from Singapore, SG at 10:02 UTC on Chrome/Windows - was this you?",
    "app": "Microsoft 365", "idp": "microsoft", "ip": "203.0.113.50", "location": "Singapore, SG",
    "clientApp": "Browser", "signInTime": "...", "createdAt": "...", "expiresAt": "...",
    "answerUrl": "/v1/verify/<id>/answer" }] }
```
- The source IP comes from Caddy's `X-Forwarded-For` (last hop) and is stored as the browser's egress IP.
- **Identity binding:** the policy `userId` wins. Without it, the install binds to the most frequent successful `accountHint`. `accounts` adds more bound UPNs, so one user can have several accounts.
- `verifyRequests` lists only pending requests for UPNs bound to this install. The prompt text is in UTC; use `signInTime` to show local time.

### `POST /v1/verify/{id}/answer`
`{ "installId": "uuid", "answer": "yes" | "no", "ts": "..." }` → `{ "ok": true, "verifyId", "status": "answered", "verdict" }`.
- `403`: the install is not bound to the UPN being asked.
- `409`: the request was already answered or has expired.
- `404`: the verify request is unknown.

### `POST /v1/alerts` (generic SIEM/SOAR webhook: Securonix playbook, Sentinel, HaloPSA, …)
Send one alert object, or `{ "alerts": [ ... ] }`. Entra sign-in field names are accepted as aliases:
```json
{ "source": "securonix", "externalId": "SNX-123", "title": "Unusual sign-in", "severity": "high",
  "upn": "alice@clienta.com", "ts": "2026-10-19T10:02:00Z", "ip": "203.0.113.50",
  "app": "Microsoft 365", "clientApp": "Browser", "isInteractive": true, "idp": "microsoft",
  "location": { "city": "Singapore", "countryOrRegion": "SG" },
  "deviceDetail": { "browser": "Chrome", "operatingSystem": "Windows" },
  "ticket": { "system": "halopsa", "id": "12345" } }
```
| Field | Also accepted as |
|---|---|
| `upn` | `userPrincipalName`, `user` |
| `ts` | `createdDateTime`, `time` |
| `ip` | `ipAddress` |
| `app` | `appDisplayName` |
| `clientApp` | `clientAppUsed` |
| `ticket.id` | `haloTicketId` |

- A missing `clientApp` is treated as `Browser`, and the decision trace says so.
- Alerts are deduplicated on `(source, externalId)`.
- The response is the alert JSON (below), already correlated: `verdict` is final, `PENDING_USER`, or `null` while `status=settling`.

### `GET /v1/alerts/{id}`
→ `{ alertId, status, verdict, confidence, suggestedAction, shadowMode: true, verifyRequest, evidence: {trace, groundTruth}, evidenceCard: {markdown, html} }`.
SOAR tools can poll this endpoint. Every read is audit-logged.

## Correlation (design §2, shadow mode)

| Situation | Result |
|---|---|
| Non-browser or non-interactive sign-in | Ask the user (`NO_COVERAGE` if they have no bound browser) |
| Browser sign-in, no bound browser | `NO_COVERAGE` |
| Matching browser auth event (same UPN, ±3 min, same IdP, `success`, not device-code) **and** IP match (exact, same /24 (/64 for v6), or same ASN with GeoLite2-ASN) | `CONFIRMED_BY_BROWSER` (high) |
| Matching event, IP differs, or outcome not `success`, or alert has no IP | Ask the user. The console never confirms on time alone. |
| No event, browser online (heartbeat ±10 min) | `NOT_SEEN_IN_BROWSER` (high) **and** ask the user |
| No event, browser offline | Ask the user |

What happens after asking:

| Answer | Result |
|---|---|
| "No, not me" | `USER_DENIED` |
| "Yes" | `USER_CONFIRMED` (medium). If the verdict was already `NOT_SEEN_IN_BROWSER`, a "yes" keeps `NOT_SEEN_IN_BROWSER` (medium): a user's word never downgrades a replay signal. |
| No answer within the tenant timeout (default 10 min) | `NO_RESPONSE` |

Other behaviour:
- **Settle window:** if the browser is online but no auth event has arrived yet, the console waits up to `SETTLE_SEC` (60 s) after the sign-in time before deciding `NOT_SEEN_IN_BROWSER`, because event batches can still be in flight.
- **Device-code flow:** if the device-code page was used in the user's browser around the alert time, that is flagged in the Evidence Card (MITRE T1528). That browser event is never used to confirm the sign-in.
- **Anti-fatigue:** the console sends at most N prompts per user per 24 h (tenant setting, default 5). Prompts go only to the user's own bound extension.
- Nothing is ever auto-closed. Verdicts are suggestions; analysts record agree/disagree in the dashboard, and agreement and false closes are tracked.

## Write-back

Each verdict (including the early `NOT_SEEN_IN_BROWSER`, and again when the user answers) is queued and retried up to 5 times:
- **HaloPSA:** `client_credentials` token → `POST {base}/api/actions` adding a private note (`note_html` = Evidence Card, `hiddenfromuser: true`) to the alert's `ticket.id`. Configure this per tenant: base URL, client ID/secret, hosted `tenant`, outcome name.
- **Generic webhook:** POSTs JSON `{type: "soclens.verify.verdict", alertId, externalId, ticket, upn, verdict, confidence, suggestedAction, evidenceCard: {markdown, html}}`, signed `X-SOCLens-Signature: sha256=HMAC(secret, body)`.

## Browser events out: notifications and SIEM export

Every stored browser event is checked against the tenant's channels (Tenants → settings) and queued in `outbound`; the job loop sends it with retries.

| Channel | Who gets what |
|---|---|
| Telegram / notify webhook | Events at or above *Notify from severity* (default `critical`, i.e. credential reuse). At most `NOTIFY_MAX_PER_HOUR` per tenant per channel; the rest are marked `suppressed`. Webhook body: `{type: "soclens.event.alert", event}`, signed `X-SOCLens-Signature`. |
| MSSP Telegram (`NOTIFY_TELEGRAM_*` in `.env`) | Serious events from every tenant. |
| SIEM JSON webhook | One signed batch per tenant per tick: `{type: "soclens.events", tenantId, events: [...]}`. |
| Syslog | `udp://host:514` or `tcp://host:514`, RFC 5424 frame with a CEF payload (`CEF:0|OpsVantage|SOCLens|…`). |
| Pull | `GET /v1/events?after_id=<cursor>&limit=500` with the tenant key → `{events, nextAfterId}`. |

Exported events carry defanged URLs and hosts only. **Send test** on the tenant page pushes one fake critical event to every configured channel.

## Dashboard and RBAC

The dashboard has these pages:
- **Events:** every browser event with filters (tenant, type, severity, time, host/user search, site, sender), a detail view with defanged indicators, raw JSON, where it was sent, and one-click **Block host / Block site** for the tenant.
- **Campaigns:** events grouped by site (one label below a hosting platform such as `evil.pages.dev`) or email sender, with users affected; credential leaks first. Block for the affected tenants or (MSSP admin) all tenants. Shared platforms and big brands are never blockable as a whole.
- **Overview:** per tenant, the verdict mix, users covered (bound browsers vs. expected or seen users), alerts covered by a browser, pending prompts, analyst agreement, false closes, median time from alert to verdict, and user answer rate.
- **Verify queue:** pending prompts and recent alerts.
- **Evidence Card page:** the card plus analyst agree/disagree. Every view is audit-logged.
- **Tenants:** settings, key rotation, blocklist and bound browsers.
- **Users** and **Audit**.

| Role | Access |
|---|---|
| `mssp_admin` | Everything |
| `analyst` | View pages and record feedback |
| `client_viewer` | Read-only, own tenant only |

A user with a tenant set only sees that tenant.

## Privacy and retention

- Heartbeats are kept 7 days and auth events 30 days, purged hourly (`HEARTBEAT_RETENTION_DAYS`, `AUTH_EVENT_RETENTION_DAYS`).
- The console collects only IdP-page auth events and heartbeats; it never receives browsing history.
- The audit log records every verdict, user answer, Evidence Card view, login and admin change.

## Known MVP limits

- Every install in a tenant uses the same tenant API key, so a holder of the key could claim another `installId`. Per-install enrolment tokens are the next step.
- Halo client secret and webhook secret are stored in the tenant settings row (not encrypted at rest).
- Tables are created at startup with `create_all`. Add Alembic before the first schema change in production.
- Run a single app worker: the background loop (settle, expiry, write-back, retention) lives in the app process.
- Entra Graph sign-in poller and native Securonix API are not built yet (build-order step 6).
