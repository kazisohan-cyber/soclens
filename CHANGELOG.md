# Changelog

All notable changes to SOCLens. Versions follow [Semantic Versioning](https://semver.org/).

## [0.6.0] - 2026-10-30

### Added
- **Hunt queries:** one click copies a ready query for an indicator, or for all of them, for SentinelOne Deep Visibility, Microsoft Defender, Microsoft Sentinel, Splunk or Securonix Spotter. Values are escaped so text from an alert cannot change the query.
- **Close or escalate suggestion:** after an investigation SOCLens suggests Escalate, Investigate first, Close or Needs more information, with the reasons. It never suggests closing when a lookup failed, when an indicator is unknown, or when an internal asset is not identified. You record your own decision, and it goes on the ticket note.
- **Escalation note:** a short hand-over for L2 with the reason, evidence, next steps, what was and wasn't checked, and your last used hunt query.
- **Your own AI (optional, off by default):** connect OpenAI, Anthropic Claude, Google Gemini, Azure OpenAI, a local model (Ollama, LM Studio) or any OpenAI-compatible endpoint for a summary, next checks or a client email draft. Nothing is sent until you click, you can see exactly what goes out, your pasted alert is never sent, client data is masked by default, and individual clients can be excluded. The AI never changes a verdict.

### Changed
- AI summaries are labelled "AI draft, verify" on ticket notes.

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
