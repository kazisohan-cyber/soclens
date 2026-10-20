# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report it privately through GitHub: **Security tab → Report a vulnerability** on this repository. Include:

- what is affected (extension version, or console version and deployment type)
- steps to reproduce, or a proof of concept
- the impact you expect (for example: data leaving the browser, bypass of a block, privilege escalation in the console)

You will get an answer within 7 days. Fixes for confirmed issues are released as soon as possible, and you are credited in the release notes unless you ask not to be.

## Scope

In scope:
- the browser extension (`extension/`): anything that sends data the docs say stays on the device, exposes stored API keys or password hashes to web pages, lets a web page trigger privileged extension actions, or bypasses phishing / credential protection
- the self-hosted console (`console/`): authentication, tenant isolation, RBAC, injection, secrets handling

Out of scope:
- vulnerabilities in third-party intel services (VirusTotal, AbuseIPDB, abuse.ch, urlscan.io, GreyNoise, Shodan, ipinfo)
- phishing pages SOCLens does not detect: please report those as a normal issue so detection can be improved
- issues that need an already compromised device or browser profile

## Known limits (by design, documented)

- API keys entered in the analyst panel are stored in the browser's extension storage, readable by anyone with access to that browser profile.
- In the console, every browser of a tenant shares the tenant API key unless it enrolled through the community flow.
- SOCLens proves which browser signed in, not who sits at it. Malware on the device still needs EDR.
