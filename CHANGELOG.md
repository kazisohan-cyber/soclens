# Changelog

All notable changes to IOC Triage (called SOCLens up to 0.6.0). Versions follow [Semantic Versioning](https://semver.org/).

## [0.8.1] - 2026-10-31

### Fixed
- **Real Google country sites are no longer blocked or warned about.** Sites such as `google.com.ar` and `google.com.ua` were replaced by the block page, and `google.co.il` and sites on `.google`, such as `gemini.google`, showed a warning. Domain names are now read with the Public Suffix List, and Google's published list of country domains counts as genuine.
- **Top-level domains run by a brand count as genuine:** `.google`, `.microsoft`, `.apple`, `.amazon` and similar.

### Changed
- **A brand name on a country domain it is not known to use, such as `paypal.com.ar`, now gets a warning.** Some of these were blocked before. A real login form there can still be blocked by the page check.
- **More warnings on free hosting and bare IP addresses:** plain HTTP on free hosting or a public IP address, and a machine-made looking name on free hosting. A real site with such a name can now show a warning.

### Added
- `tests/benchmark.mjs` measures the address check against phishing and top-site lists, without opening any site.

## [0.8.0] - 2026-10-30

### Changed
- **Browsing protection now asks first.** The welcome page says what is read and what can leave the device, and phishing checks, the email scanner, the credential guard and highlighting stay off until you agree. You can withdraw in Settings. A browser policy from an admin counts as the organisation's decision. The analyst panel works either way. After updating, you will be asked once.
- **The welcome page no longer says that nothing is sent to any server.** It now describes domain-age checks and intel lookups.
- **New name: IOC Triage.** Another extension with a very similar name and purpose was already in the stores. Settings and data are unaffected.

### Added
- **Team memory:** export client notes and decision history as an AES-256-GCM encrypted file protected by a passphrase, and merge a colleague's file. No server is involved. You see what a file contains before merging it, and a wrong passphrase or a changed file will not open.
- **MITRE ATT&CK mapping:** possible techniques from the evidence and the alert's wording appear in the panel, on ticket notes and on escalation notes. They are labelled as possible, and benign evidence maps to nothing.
- **Block list export:** flagged indicators as plain lists for firewalls, DNS, web proxies and EDR, a Microsoft Defender indicators CSV, a general CSV or a STIX 2.1 bundle. Benign, internal and unflagged indicators and CVEs are left out, and suspicious ones only on request. You deploy the list yourself.

## [0.7.0] - 2026-10-30

### Added
- **Decision memory:** SOCLens keeps a local record of each investigation and your decision. A result shows what happened last time, for example "Seen 4 times before: 3 closed as benign", and that history goes on the ticket note. After three benign closes it offers to save a client note. History never changes a verdict. Only indicators, verdicts, the ticket reference and the decision are stored, for 180 days.
- **Phishing triage from `.eml` files:** open a reported email on the Email tab for header analysis, links with their real destinations, deceptive link text, attachment SHA-256 hashes and risky file types. Copy the findings or a reply to the person who reported it. The file is read on the device and the email is never displayed.
- **Shift handover:** a new Shift tab builds a report from your investigations, with what still needs attention first. One click copies it.
- **"This is my work site" on the password warning:** after a confirmation, the credential guard stands down on that exact address, for tools such as an EDR console that use the same password. Phishing checks keep running there. It is not offered on suspicious pages or when an admin disallows bypass. Review or remove these sites in Settings under Credential guard data.

### Fixed
- **The password warning no longer says your security team was notified when no console is connected.** It now says the event is recorded on this device only.
- **The credential guard no longer misses a password entered while a page is still loading.** A paste, autofill or quick sign-in now waits for the check, and a field filled without an input event is checked when you submit.

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
