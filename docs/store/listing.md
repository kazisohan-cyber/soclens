# Store listing

Paste each block into the Chrome Web Store developer dashboard. All text is plain, with no HTML or Markdown.

## Title and summary: nothing to paste

The store reads both from `extension/manifest.json`, so they are already set by the package you upload.

| Field | Value | Length | Limit |
|---|---|---|---|
| Title (`name`) | IOC Triage – IOC Lookup, Threat Intel & SOC Analyst Assistant | 61 | 75 |
| Short description (`description`) | Instant verdicts for any IP, domain, URL, hash or CVE, ticket notes, email header analysis, and phishing protection. | 116 | 132 |

To change either one, edit the manifest and upload a new package.

## Store listing tab

**Description**

```text
IOC Triage is a free, open-source browser assistant for spotting and handling phishing and malicious internet indicators. Paste an alert and it checks every IP, domain, URL, file hash, email address and CVE, gives each one a verdict with its reasons, and copies a finished ticket note. It also warns you about fake sites and fake logins as you browse.

FOR SOC ANALYSTS
• Investigate: select text on any page, right-click and choose IOC Triage: Investigate, or paste a whole alert into the side panel. Defanged input is fine.
• Verdicts you can check: every finding names its source, and each result says what to do next.
• Close or escalate: a suggestion with the reasons. It never suggests closing when a lookup failed or something is still unknown. The decision stays yours.
• Ticket notes: one click copies a formatted note, Markdown, or an escalation hand-over for L2.
• Hunt queries: copy a ready query for SentinelOne, Microsoft Defender, Microsoft Sentinel, Splunk or Securonix.
• Reported phishing: open an .eml file on your device for headers, real link destinations and attachment hashes, then copy a reply for the reporter. The email is never displayed.
• Decision memory and shift handover: see what you decided last time for an indicator, and copy a shift report built from your decisions.
• MITRE ATT&CK and block lists: possible techniques on your notes, and flagged indicators exported for firewalls, EDR or STIX 2.1.
• Client memory: record what is normal for each client. Notes show who added them and they expire, so old knowledge is never trusted silently. Share them with your team as an encrypted file.
• Safe detonation: scan a link with urlscan.io, using your own key, without opening it in your browser.
• Highlighting: colours indicators on the analyst sites you choose. No lookup runs until you click.
• Your own AI (optional, off by default): connect your AI provider or a local model for a summary, next checks or a client email draft.

PROTECTION WHILE YOU BROWSE (turned on only after you agree)
• Blocks lookalike and impersonation sites before they load, and warns on suspicious ones.
• Detects fake login pages that copy a known brand.
• Scans email in Gmail and Outlook on the web, shows a warning banner and disables dangerous links.
• Credential guard: if your work password is typed on a site that is not part of your organisation, the field is cleared before it is sent.

WHAT IOC TRIAGE READS AND SENDS
On your device only:
• The address of each page you open, and the content of pages and webmail messages, are analysed locally to detect phishing.
• Your work password is stored only as a salted hash, learned when you sign in on a corporate login page, and is never sent.
• Client notes, decision history, API keys, ticket notes and the activity log stay in this browser. Reported .eml files are read locally and not kept.

Sent only in these cases:
• When you investigate, only that indicator goes directly from your browser to the intel services, such as GreyNoise, Shodan InternetDB, ipinfo, rdap.org, Cloudflare DNS, CISA KEV, FIRST EPSS and NVD, plus VirusTotal, AbuseIPDB, abuse.ch and urlscan.io if you add your own keys.
• For an already suspicious site, its domain name may go to rdap.org to check the domain's age. You can turn this off in Settings.
• If you connect your own AI, computed evidence goes to the provider you chose, only when you click, and you can read it first. Your pasted alert is never sent. Client data is masked by default.
• If you or your admin connect a company IOC Triage console, security events go to your organisation's own server. This is off unless configured.

No IOC Triage server is built in, and no account is needed. There are no analytics, no tracking, no ads and no sale of data.

Privacy policy: https://github.com/kazisohan-cyber/soclens/blob/main/PRIVACY.md
Source code: https://github.com/kazisohan-cyber/soclens
```

| Field | Value |
|---|---|
| Category | Make Chrome Yours > Privacy & Security. If the dashboard shows other names, choose the closest privacy or security category. |
| Language | English |
| Store icon | Upload `extension/icons/icon128.png` (128x128) |
| Screenshots | Upload `screenshots/1-…png` to `5-…png` in order (each 1280x800) |
| Global promo video | The YouTube link, after you record `demo-video-script.md` (optional) |
| Small and marquee promo tiles | Leave empty (optional) |
| Official URL | None, unless you verify a site in Search Console (optional) |
| Homepage URL | `https://kazisohan-cyber.github.io/soclens/` |
| Support URL | `https://github.com/kazisohan-cyber/soclens/issues` |
| Mature content | Off |

## Screenshot captions (for your records; the dashboard has no caption field)

| File | Shows |
|---|---|
| `1-alert-to-verdict.png` | A pasted alert, the overall result, the suggestion to escalate and a verdict with next steps |
| `2-explainable-verdicts.png` | URL, hash, CVE and known-good verdicts with their sources |
| `3-ticket-note.png` | The panel beside the ticket note as it pastes |
| `4-phishing-and-handover.png` | A reported `.eml` file triaged on the device, and the shift handover |
| `5-your-own-ai.png` | "What gets sent" and the AI settings, using a local model |

All five use `tests/analyst-preview.html?demo=1`: documentation IP ranges (RFC 5737), `.example` domains, the EICAR test hash and public CVE data. The capture served no data files, and no request left the machine. To rebuild them after a UI change, run `node docs/store/tools/capture-screenshots.mjs`.

## Test instructions tab

Leave Username and Password empty. **Additional instructions** has a 500-character limit, so paste this block:

```text
No account or API key needed. After install, click Agree and turn on in the welcome page; protection stays off until then.
1. Open https://login.microsoftonline.com.evil.top/ : a block page appears before load.
2. Toolbar icon > Open next to Analyst panel. Paste: CVE-2024-3400 and 8.8.8.8 then click Investigate. Verdicts appear with sources.
3. Click Copy ticket note.
AI, console and keyed lookups are optional and off by default. Source: github.com/kazisohan-cyber/soclens
```

The longer version below is too long for that field. Keep it for a reviewer's questions.

```text
No account, login or API key is needed.

Consent: a welcome page opens after install. Click Agree and turn on, otherwise browsing protection stays off by design.

Phishing block:
1. Open https://login.microsoftonline.com.evil.top/ in a new tab. IOC Triage shows a full-page block before the site loads.

Analyst panel:
2. Click the IOC Triage toolbar icon, then Open next to Analyst panel.
3. Paste this into the box and click Investigate: CVE-2024-3400 and 8.8.8.8
4. You get a verdict for each indicator, with its sources and next steps. These lookups use free public services and send only the indicator.
5. Click Copy ticket note and paste into any text field.

Right-click: select an IP address on any page, right-click and choose IOC Triage: Investigate.

Email: on the Email tab, open a saved .eml file or paste an email's full headers. This runs on the device.

Shift: after step 4, the Shift tab lists that investigation in the handover report.

Features you will not see by default:
- Your own AI is off until a provider is chosen in the panel's Settings tab. It needs the tester's own key or a local model, and it sends only when a button is clicked.
- The company console features (event reporting, sign-in verification and their notifications) run only when an admin or user sets an endpoint. No server is built in.
- VirusTotal, AbuseIPDB, abuse.ch and urlscan.io lookups need the tester's own free keys.

Source code: https://github.com/kazisohan-cyber/soclens
```

## Distribution tab

| Field | Value |
|---|---|
| Payment | Free |
| Visibility | Public, because the goal is adoption |
| Regions | All regions |
| When you submit | Untick automatic publishing if you want to choose the release moment yourself |
