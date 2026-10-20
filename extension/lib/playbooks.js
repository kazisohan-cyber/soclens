/*
 * SOCLens remedy & resolution engine.
 * build(event, cfg) -> {
 *   user: { title, summary, risk, steps: [{ text, link?, urgent? }] },
 *   soc:  { summary, severity, mitre: [{ id, name }], containment: [], investigation: [],
 *           commands: [{ label, lang, code }], queries: [{ label, lang, code }] }
 * }
 * Pure and deterministic: same input -> same playbook. Queries are templates the analyst should review.
 */
(function (root) {
  'use strict';

  const MITRE = {
    link: { id: 'T1566.002', name: 'Phishing: Spearphishing Link' },
    attach: { id: 'T1566.001', name: 'Phishing: Spearphishing Attachment' },
    userLink: { id: 'T1204.001', name: 'User Execution: Malicious Link' },
    paste: { id: 'T1204.004', name: 'User Execution: Malicious Copy and Paste' },
    aitm: { id: 'T1557', name: 'Adversary-in-the-Middle' },
    validAcc: { id: 'T1078', name: 'Valid Accounts (credential at risk)' },
    harvest: { id: 'T1056.003', name: 'Input Capture: Web Portal Capture' }
  };

  // Escape a value for use inside a double-quoted KQL / Spotter string.
  const q = (v) => String(v == null ? '' : v).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  const ps = (v) => String(v == null ? '' : v).replace(/'/g, "''");

  function domainOf(ev) {
    if (ev.host) return ev.host;
    try { return new URL(ev.url).hostname; } catch (_) { return ''; }
  }

  function regDomain(host) {
    const A = root.VSAnalyzer;
    return A ? A.registrableDomain(host) : host;
  }

  function huntQueries(domain, user) {
    const d = q(domain), u = q(user);
    const out = [
      { label: 'Who received mail containing this domain (Defender XDR / Sentinel)', lang: 'kql', code:
`EmailUrlInfo
| where Timestamp > ago(7d)
| where UrlDomain has "${d}"
| join kind=inner EmailEvents on NetworkMessageId
| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, Url, DeliveryAction, DeliveryLocation` },
      { label: 'Who clicked links to this domain', lang: 'kql', code:
`UrlClickEvents
| where Timestamp > ago(7d)
| where Url has "${d}"
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, Workload` },
      { label: 'Devices that connected to this domain', lang: 'kql', code:
`DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "${d}"
| summarize Connections = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceName, InitiatingProcessAccountName` },
      { label: 'Securonix Spotter — pro