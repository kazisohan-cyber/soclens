# Changelog

All notable changes to SOCLens. Versions follow [Semantic Versioning](https://semver.org/).

## [0.5.1] - 2026-10-20

### Added
- **EDR import (SentinelOne):** import Threats, Endpoints or Data Lake CSV exports into client memory. Triaged hashes become benign or malicious notes. Endpoints become hostname notes, with their egress and internal IPs mapped to the hostname. You review before saving, and re-imports update notes instead of duplicating them. Files are read only in the browser.

### Fixed
- **Log field names are no longer treated as domains** (`data.scope`, `data.user.email`, `host.name`, `site.id`). Domains now need a real top-level domain (the IANA root zone list is embedded), and `key=` / `key:` patterns are recognised.
- **Localhost and private-network pages are never flagged as phishing.** This covers OAuth loopback callbacks such as Git Credential Manager, dev servers, and router or NAS admin pages.
- **Legitimate sites that mention a brand** (for example "Google Authenticator", "Sign in with Google") no longer trigger a phishing warning on their own. SSO button logos no longer count as impersonation.
- **Copy buttons work in Chrome's side panel**, with a visible fallback if the browser blocks the clipboard.
- **Long indicators** (hashes, URLs) wrap inside their card.
- **The verdict summary leads with the client note** when one decided the verdict.

### Removed
- `lib/playbooks.js`, an unfinished draft that was never loaded and did not parse.

## [0.5.0] - 2026-10-20

First public release: the analyst panel (right-click Investigate, 15 intel sources, explainable verdicts, ticket notes, email header analysis, safe detonation, IOC highlighting, client memory with expiry), phishing and fake-login protection, webmail scanner, credential guard, and the self-hosted console.
