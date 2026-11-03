# Store listing: search-term draft (not applied)

A proposal to help IOC Triage show up in Chrome Web Store search. Nothing here is live. The current text is in `listing.md`.

## Why change it

Store search matches the words people type. Analysts search for what they want to do ("ip lookup", "virustotal", "check hash", "abuseipdb"), not for "SOC analyst assistant". The current title spends its words on "Assistant". The current summary lists features but none of the source names analysts search for.

## Title and short description (these live in the manifest)

Changing either one means editing `extension/manifest.json` and rebuilding the zip, so decide **before** uploading 0.8.3.

| Field | Current | Proposed | Length / limit |
|---|---|---|---|
| Title | IOC Triage – IOC Lookup, Threat Intel & SOC Analyst Assistant | IOC Triage – IP, Domain & Hash Lookup for SOC Analysts | 54 / 75 |
| Short description | Instant verdicts for any IP, domain, URL, hash or CVE, ticket notes, email header analysis, and phishing protection. | Check IPs, domains, URLs, hashes and CVEs against AbuseIPDB, VirusTotal, GreyNoise and more, with one right-click. Free, no account. | 132 / 132 |

Alternative title if phishing searches matter more: `IOC Triage – Threat Intel Lookup & Phishing Checker for SOC` (59).

Naming the sources is a factual description of what the extension queries, which the store allows. Using them in the **title** would read as keyword stuffing, so they stay in the summary and description only. Don't add more: Google's spam policy penalises long keyword lists.

## Description: new opening (store listing tab, no package needed)

Replace only the first paragraph of the description in `listing.md` with:

```text
IOC Triage is a free, open-source IOC lookup and phishing checker for SOC analysts. Right-click any IP address, domain, URL, file hash, email address or CVE, or paste a whole alert, and it checks AbuseIPDB, VirusTotal, GreyNoise, Shodan InternetDB, ipinfo, URLhaus, ThreatFox, MalwareBazaar, urlscan.io, CISA KEV, EPSS and NVD for you (a few need your own free API key). Each indicator gets a verdict with its reasons, and one click copies a finished ticket note. It also warns you about fake sites and fake logins as you browse.
```

Before pasting, check that every source named is still queried by default or with the user's own key (`extension/lib/` sources list). Remove any that are not.

## Homepage URL (optional)

Point the listing's Homepage URL at `https://tools.opsvantage.net/?utm_source=chrome-web-store&utm_medium=listing` instead of the GitHub Pages site, so visitors from the store land on the free tools and show up in Web Analytics. Keep the GitHub link in the description for the source code.

## Decision needed

1. Change title and summary now (rebuild the 0.8.3 zip before upload), or leave them for 0.8.4.
2. Paste the new description opening (any time, no review of code needed, but it does trigger a listing review).
