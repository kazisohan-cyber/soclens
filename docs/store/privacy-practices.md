# Privacy practices tab

Paste each block into the matching dashboard field. Each block is under 1,000 characters. Answers match `PRIVACY.md` and the 0.8.0 code. `README.md` lists the remaining risks.

## Single purpose description

```text
IOC Triage helps people recognise and respond to phishing and malicious internet indicators in the browser. It warns about phishing sites, fake logins and phishing emails as they appear, and it lets a security analyst check a suspicious IP, domain, URL, file hash, email address or CVE, get a verdict with reasons, and record the result on a ticket. Every feature serves that one focus area.
```

## Permission justifications

**storage**

```text
Saves settings, client notes, decision history, API keys the user enters, cached lookup results, the local activity log and the salted hash used by the credential guard, all in chrome.storage on this device. chrome.storage.session holds per-tab verdicts. chrome.storage.managed lets an organisation's admin set policy through the included managed schema.
```

**webNavigation**

```text
The phishing guard checks each top-level address in onBeforeNavigate, on the device, so a dangerous site is replaced by a warning page before it loads. If an admin enables sign-in verification for a company console, onCommitted and onCreatedNavigationTarget are also used to recognise sign-ins on identity-provider pages. Addresses are not stored as a browsing history and are not sent anywhere for normal sites.
```

**alarms**

```text
Runs periodic background work that survives the service worker stopping: removing expired lookup results from the local cache every 6 hours. If a company console is configured, it also sends queued security events, refreshes the organisation's block list and sends a heartbeat. With no console configured, those three jobs do nothing.
```

**notifications**

```text
Used only for sign-in verification, when an organisation connects a company console and enables that feature. The console can ask whether a sign-in was really the user's, and a notification with Yes and No buttons lets the user answer. No notifications are shown in the default setup and none are used for promotion.
```

**contextMenus**

```text
Adds the right-click items "IOC Triage: Investigate" for selected text, "Investigate this link" for a link, and "Open analyst panel". This is the main way an analyst sends an indicator from a page to the panel, and nothing is read until the user clicks an item.
```

**sidePanel**

```text
The analyst panel (Investigate, Email, Memory, Shift and Settings) opens in Chrome's side panel, so an analyst can work beside the alert or ticket they are reading. It opens only when the user asks, from the toolbar popup or the right-click menu.
```

**clipboardWrite**

```text
Copies what the user asks for when they click a Copy button: ticket notes (formatted and plain), Markdown, escalation notes, shift reports, block lists, defanged indicators and hunt queries. The extension writes to the clipboard only on those clicks and never reads it.
```

**declarativeNetRequestWithHostAccess**

```text
Adds one session rule that removes the Origin header from the extension's own background requests to api.greynoise.io, because that API refuses requests carrying a browser Origin header. The rule is limited to that one domain and to tabId -1, so it never touches web pages or any other request. No other rules exist, and nothing is blocked or redirected through this API.
```

**Host permission: `<all_urls>`**

```text
Phishing can appear on any site, so protection cannot be limited to a list of hosts. Content scripts run on every http and https page to detect fake logins and stop a work password being typed on the wrong site, and this must happen before the user submits, so asking for access per site would come too late. This analysis runs on the device.

Host access also lets the panel call intel services directly from the browser, across origins. These include endpoints the user chooses and that cannot be listed in advance: their own AI provider or local model, and their organisation's console.

Page content, browsing history and passwords are not sent to any intel service. The extension does not read cookies. Only the indicator the user investigates is sent, and for an already suspicious site its domain name may go to rdap.org. The full source is public.
```

## Remote code

Select: **No, I am not using remote code.** No justification is required.

Why this is true, in case a reviewer asks:

- All JavaScript ships in the package, and no page loads a script from another host.
- There is no `eval` or `new Function`. `importScripts` loads only packaged files.
- Remote responses are treated as data and rendered as text. That covers intel results, AI answers, console policy and block lists.
- The urlscan.io screenshot is an image, not code.

## Data usage

Google's form asks what personal and sensitive data you "plan to collect from users now or in the future". Google's User Data FAQ (question 3) says data handled only on the device must also be disclosed. So tick everything IOC Triage handles, even where it stays local. A mismatch between these boxes, the policy and the behaviour can get the whole publisher account suspended, so disclosing more is the safe choice.

| Box | Tick | What it covers |
|---|---|---|
| Personally identifiable information | **Yes** | Email addresses and account names the analyst investigates or saves in client notes, and the analyst's name on notes. Decision history can hold these too. These stay local, except that an investigated email address goes to intel services. With a company console: user ID and the account name typed on identity-provider pages. |
| Health information | No | Not handled. |
| Financial and payment information | No | Not handled. |
| Authentication information | **Yes** | The work password as a salted PBKDF2 hash on the device, never sent. API keys the user enters, stored in this browser and sent only to their own service. |
| Personal communications | **Yes** | Gmail and Outlook web messages scanned on the device, and pasted email headers and opened .eml files analysed on the device. With a company console: sender, subject and suspicious links of phishing emails, never the body. |
| Location | **Yes** | Only with a company console, which receives the public IP address. |
| Web history | **Yes** | Page addresses checked on the device. An already suspicious domain may go to rdap.org. With a company console: sites blocked, warned about, reported, bypassed or trusted. |
| User activity | **Yes** | Password fields are watched for the credential guard, and that value is compared only as a hash on the device. Block, bypass and report actions go in the local log, and to the console if one is connected. |
| Website content | **Yes** | Page text and titles are analysed on the device for fake logins, and text the user selects can be investigated. Only the extracted indicators are sent. |

**Certifications: tick all three.** All are true for 0.8.0.

- I do not sell user data to third parties.
- I do not use or transfer user data for purposes that are unrelated to my item's single purpose.
- I do not use or transfer user data to determine creditworthiness or for lending purposes.

## Privacy policy URL

```text
https://github.com/kazisohan-cyber/soclens/blob/main/PRIVACY.md
```

This URL is live and includes the "Your own AI" section and the Limited Use statement.

## The optional "Your own AI" connection, for a reviewer's questions

```text
Your own AI is off by default and needs the user to choose a provider and enter their own key in Settings. A local model needs no key. It runs only when the user clicks Summary, What to check next or Client email after an investigation. The request goes directly from the browser to the provider the user chose, under that provider's privacy policy, and no IOC Triage server is involved.

Sent: the computed evidence, meaning indicators, verdicts, findings and the suggested decision. The pasted alert is never sent. Masking is on by default and replaces internal IPs and hostnames, mailbox names, client names and values from client notes. If the user turns masking off, the client name, ticket reference and client notes are also sent. A "What gets sent" view shows the exact content before the click. The user can exclude individual clients. Answers are shown as drafts and never change a verdict.
```

| Item | Fact | Where |
|---|---|---|
| Providers | OpenAI, Anthropic Claude, Google Gemini, Azure OpenAI, local (Ollama, LM Studio), any OpenAI-compatible endpoint | `extension/lib/ai.js:10` |
| Transport | https, with plain http only for localhost and private addresses | `extension/lib/ai.js:81` |
| Cookies | None sent (`credentials: 'omit'`, no referrer) | `extension/lib/ai.js:157` |
| Exact payload | `evidence()`, the same function that fills "What gets sent" | `extension/lib/ai.js:55` |
| Built-in browser AI | A separate on-device summary, which uses Chrome's built-in model when available and sends nothing | `extension/pages/analyst.js:478` |
