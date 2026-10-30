# IOC Triage: Chrome Web Store submission pack

Prepared 2026-10-30 and updated for IOC Triage 0.8.0. Nothing has been committed, paid for or submitted.

| File | Use it for |
|---|---|
| [listing.md](listing.md) | Store listing, Test instructions and Distribution tabs |
| [privacy-practices.md](privacy-practices.md) | Privacy tab: single purpose, permissions, remote code, data usage, policy URL, the AI connection |
| [demo-video-script.md](demo-video-script.md) | The 30-second video |
| [screenshots/](screenshots/) | Five 1280x800 PNGs from sample data |
| [tools/capture-screenshots.mjs](tools/capture-screenshots.mjs) | Rebuilds the screenshots |

## Before you submit

The welcome page, consent step and `PRIVACY.md` gaps found earlier are fixed in 0.8.0. These remain.

### 1. Narrow `<all_urls>` (recommended)

Google requires the narrowest permission that works. `<all_urls>` also covers `file://`, but content scripts run only on http and https, and I found no `file:` handling in `background.js` or `lib/`. Replacing it with `http://*/*` and `https://*/*` should lose nothing. It will still count as broad access and is likely to get the same in-depth review. Retest after the change. If you make it, change the permission name in the field heading and in the first paste block; the justification still applies.

### 2. Risks to accept or watch (no action needed to submit)

- **Single purpose.** Phishing protection plus an analyst panel could look like two products to a reviewer. The statement frames both as one focus area, which Google's FAQ allows. If it is rejected as multi-purpose (`Red Magnesium`), the fix is two separate extensions.
- **API keys at rest.** Google's FAQ (question 9) says data at rest should use strong encryption such as AES. API keys sit unencrypted in `chrome.storage.local`, which only this extension can read. The password is a salted PBKDF2 hash, not stored in clear text. Reviewers may never raise this, but I can't rule it out.
- **Icon size.** The artwork in `icon128.png` is 104x112 inside 128x128, and Google suggests about 96x96. This is guidance and shouldn't block anything.
- **Screenshots show only the analyst panel,** as requested. The popup and block page are not shown.

## What you must do yourself

1. Decide on item 1 and, if you change the code, release the new version before packaging.
2. In the [developer dashboard](https://chrome.google.com/webstore/devconsole), register: accept the developer agreement and pay the one-time fee. The docs no longer state the amount, and it has historically been US$5, so the dashboard shows the real figure. Google suggests a dedicated email address, because it can't be changed later.
3. Turn on 2-Step Verification on that Google account, which publishing requires.
4. On the Account page, set the publisher name and verify the contact email. The publisher name appears publicly under "Offered by". The manifest says `OpsVantage`.
5. Build the package from the repo root in PowerShell 7:

   ```powershell
   Compress-Archive -Path extension\* -DestinationPath ioc-triage-extension-v0.6.0.zip -Force
   ```

6. Click **Add new item** and upload the zip. `*.zip` is already ignored by git.
7. Paste [listing.md](listing.md) and [privacy-practices.md](privacy-practices.md) into their tabs, and upload the icon and screenshots.
8. Record the video and upload it to YouTube (optional).
9. Check the data-use boxes against what the form shows. I read them from Google's documentation screenshot, not the live dashboard, because I can't sign in to it. The same applies to the category name and any field length limits.
10. Click **Submit for review**. Expect a longer review because of the broad host access. I found no official figure for how long it takes.
11. After approval, update the README's install section, the website and the policy snippets with the new store extension ID. Developer-mode installs won't update automatically, so those users need to reinstall from the store.

Committing this folder publishes it, because GitHub Pages serves `docs/`. The pack would be readable under `/soclens/store/`. That is harmless, since it holds no secrets, but the choice is yours.

## Requirements checked on 2026-10-30

| Requirement | Pack status | Source |
|---|---|---|
| Name up to 75 characters, description up to 132 | 61 and 116 | [name](https://developer.chrome.com/docs/extensions/reference/manifest/name), [description](https://developer.chrome.com/docs/extensions/reference/manifest/description) |
| Store icon 128x128 PNG | `extension/icons/icon128.png` | [Images](https://developer.chrome.com/docs/webstore/images) |
| 1 to 5 screenshots, 1280x800, square corners, full bleed | 5 at 1280x800 | [Listing](https://developer.chrome.com/docs/webstore/cws-dashboard-listing) |
| No keyword spam, such as more than 5 unnatural repeats or bare brand lists | Checked by count | [Listing requirements](https://developer.chrome.com/docs/webstore/program-policies/listing-requirements) |
| Single purpose, permissions, remote code, data use, policy URL | Answered | [Privacy fields](https://developer.chrome.com/docs/webstore/cws-dashboard-privacy) |
| All logic inside the package | No `eval`, no remote scripts | [MV3 requirements](https://developer.chrome.com/docs/webstore/program-policies/mv3-requirements) |
| Local-only handling still disclosed; consent inside the product | Disclosed in the listing; consent on the welcome page | [User Data FAQ](https://developer.chrome.com/docs/webstore/program-policies/user-data-faq) |
| Data strictly necessary and prominently disclosed | Disclosed in the listing and on the welcome page | [2026 policy update](https://developer.chrome.com/blog/cws-policy-updates-2026) |
| Limited Use statement on your site | In `PRIVACY.md`; live once pushed | [Limited Use](https://developer.chrome.com/docs/webstore/program-policies/limited-use) |
| 2-Step Verification, account set-up | Your steps | [Policies](https://developer.chrome.com/docs/webstore/program-policies/policies), [Set up account](https://developer.chrome.com/docs/webstore/set-up-account) |

## What was tested

- Protection stays off until **Agree and turn on** is clicked, and withdrawing in Settings turns it off and deletes the learned hash.
- The unpacked `extension/` loads in headless Edge as version 0.8.0, and the welcome page opens on install.
- `https://login.microsoftonline.com.evil.top/` is replaced by the block page.
- With live public lookups in the same test, `CVE-2024-3400 and 8.8.8.8` returned CRITICAL and BENIGN, and **Copy ticket note** reported success.
- All five screenshots are 1280x800, and no request left the machine during capture.
- A trial zip has `manifest.json` at its root, every file the manifest names, and no `.csv` or test files.

- Decision memory, `.eml` triage, shift handover and an encrypted team file round trip ran in the real panel with no page errors. Test pages: 211 and 58 cases pass.

Not tested: a real store upload, Chrome with the extension loaded (the test used Edge), the toolbar popup and right-click routes into the panel, and importing the block list files into a real firewall, Defender tenant or STIX platform. The video hasn't been recorded.
