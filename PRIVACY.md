# IOC Triage privacy policy

IOC Triage is a browser extension that protects against phishing and helps security analysts investigate indicators. It works **without an IOC Triage server**, and nothing is sold or used for advertising.

IOC Triage's use of user data complies with the Chrome Web Store User Data Policy, including the Limited Use requirements.

## On your device

Browsing protection stays off until you agree on the welcome page, or your organisation's admin turns it on by policy. These run on your device:

- **Phishing and fake-login detection:** the URL and page are analysed locally.
- **Email scanning in Gmail and Outlook on the web:** email content is never sent anywhere.
- **Credential guard:** your work password is stored only as a salted PBKDF2 hash on this device, and is never sent.
- **Email header analysis, client memory, ticket notes, activity log:** all stay on the device.
- **Reported `.eml` files:** read on the device and not kept. The email is never displayed.
- **Decision history:** the indicators, verdicts, ticket reference, client and decision of each investigation, kept on the device for 180 days. The alert text you pasted is not kept.

There are no analytics, no tracking, no advertising, and no sale of data.

## Lookups you start (analyst panel)

When **you** investigate an indicator (an IP, domain, URL, hash, email address or CVE), IOC Triage sends **only that indicator** directly from your browser to the intel services below. It never sends page content, browsing history or your identity.

| Service | Used for | Key |
|---|---|---|
| GreyNoise, Shodan InternetDB, ipinfo | IP context and reputation | none |
| rdap.org, Cloudflare DNS | Domain age and DNS | none |
| CISA KEV, FIRST EPSS, NVD | CVE data | none |
| VirusTotal, AbuseIPDB, abuse.ch, urlscan.io | Reputation, malware data, safe page scans | your own key |

Each service handles requests under its own privacy policy. API keys you enter are stored only in this browser. **urlscan.io:** "Detonate safely" submits the URL as an *unlisted* scan, which urlscan.io staff and vetted researchers can still see. Do not detonate internal links, or links that contain tokens such as password-reset or file-share links.

When you click **Investigate** on a reported email, its attachment hashes, links and sender details are sent the same way. Links can contain the recipient's address or a token, so check them first.

For phishing checks, IOC Triage may look up the registration date of an already suspicious domain via rdap.org. Only the domain name is sent.

## Optional connections (only if you or your admin turn them on)

- **Your own AI** (off by default, set in the analyst panel's Settings). If you connect a provider, IOC Triage sends data to it only when you click **Summary**, **What to check next** or **Client email** after an investigation, directly from your browser using your own key, under that provider's privacy policy. It sends the computed evidence: indicators, verdicts, findings and the suggested decision. It never sends the alert text you pasted. Masking is on by default and replaces internal IPs and hostnames, mailbox names, client names and values from your client notes, but it cannot recognise every internal name, so check **What gets sent** before clicking. If you turn masking off, the client name, ticket reference and client notes are also sent. You can exclude individual clients, or use a local model so nothing leaves your network. Check that your company and client contracts allow the provider you choose.
- **Company IOC Triage console** (`apiEndpoint`, usually set by your IT admin through browser policy). IOC Triage sends security events to your organisation's own console: sites it blocked or warned about, sites you reported, bypassed or trusted, and for phishing emails the sender, subject and suspicious links. It also sends your browser type, extension version and public IP address. If your admin enables **sign-in verification**, IOC Triage also records sign-ins on identity-provider pages only (Microsoft, Google, Okta and your company's login domains) and sends a periodic heartbeat. Your organisation controls that data and its retention.
- **Community server** (`communityEndpoint`, none is built in). Only after you agree on the welcome page, IOC Triage enrolls with the configured community console. You can choose "Protect only" (nothing shared) or share block reports as listed above.

## Your control

- Turn any feature off in **Settings**, or withdraw your agreement there, which also deletes the learned password hash.
- Delete the learned password hash, or remove sites you allowed your work password on, in **Settings → Credential guard data**.
- Delete client memory notes in the analyst panel, and API keys in its Settings tab.
- Delete decision history with **Clear history** on the panel's Shift tab.
- **Team memory files** contain your notes and decisions, encrypted with the passphrase you choose. IOC Triage never sends them: you decide who receives one.
- Removing the extension deletes all of its local data.

## Contact

Questions about this policy: open an issue on the project's GitHub repository. Security issues: see [SECURITY.md](SECURITY.md).
