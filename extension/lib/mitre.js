/*
 * IOC Triage MITRE ATT&CK mapping: suggests techniques from the evidence for the ticket and for L2.
 * These are possibilities drawn from indicators and keywords, not proof a technique was used, so the
 * panel and the note label them "possible". Benign evidence maps to nothing. Pure functions.
 */
(function (root) {
  'use strict';
  const T = {
    'T1566.001': ['Phishing: Spearphishing Attachment', 'Initial Access'],
    'T1566.002': ['Phishing: Spearphishing Link', 'Initial Access'],
    'T1204.001': ['User Execution: Malicious Link', 'Execution'],
    'T1204.002': ['User Execution: Malicious File', 'Execution'],
    'T1190': ['Exploit Public-Facing Application', 'Initial Access'],
    'T1078': ['Valid Accounts', 'Initial Access'],
    'T1110': ['Brute Force', 'Credential Access'],
    'T1621': ['Multi-Factor Authentication Request Generation', 'Credential Access'],
    'T1003.001': ['OS Credential Dumping: LSASS Memory', 'Credential Access'],
    'T1595': ['Active Scanning', 'Reconnaissance'],
    'T1583.001': ['Acquire Infrastructure: Domains', 'Resource Development'],
    'T1071': ['Application Layer Protocol', 'Command and Control'],
    'T1090.003': ['Proxy: Multi-hop Proxy', 'Command and Control'],
    'T1059.001': ['Command and Scripting Interpreter: PowerShell', 'Execution'],
    'T1021.001': ['Remote Services: Remote Desktop Protocol', 'Lateral Movement'],
    'T1486': ['Data Encrypted for Impact', 'Impact'],
    'T1114.003': ['Email Collection: Email Forwarding Rule', 'Collection'],
    'T1656': ['Impersonation', 'Defense Evasion'],
    'T1036.007': ['Masquerading: Double File Extension', 'Defense Evasion']
  };
  const FLAGGED = new Set(['malicious', 'critical', 'suspicious', 'high']);

  // Words in the pasted alert. Only matched on the device; the text is not kept.
  const KEYWORDS = [
    [/\bpowershell(\.exe)?\b/i, 'T1059.001', 'Alert mentions PowerShell'],
    [/\b(rdp|remote desktop|mstsc)\b/i, 'T1021.001', 'Alert mentions RDP'],
    [/\b(lsass|mimikatz)\b/i, 'T1003.001', 'Alert mentions LSASS or Mimikatz'],
    [/\b(brute.?force|password spray(ing)?|multiple failed (log|sign)-?ins?)\b/i, 'T1110', 'Alert mentions failed sign-ins or brute force'],
    [/\b(mfa fatigue|mfa bombing|push bombing)\b/i, 'T1621', 'Alert mentions repeated MFA prompts'],
    [/\b(ransomware|files? encrypted)\b/i, 'T1486', 'Alert mentions ransomware'],
    [/\b(forwarding rule|inbox rule)\b/i, 'T1114.003', 'Alert mentions a mail forwarding rule'],
    [/\b(impossible travel|unfamiliar sign-?in|risky sign-?in|signed in from)\b/i, 'T1078', 'Alert describes a suspicious sign-in']
  ];

  function url(id) { return 'https://attack.mitre.org/techniques/' + id.replace('.', '/') + '/'; }

  function collector() {
    const seen = new Map();
    return {
      add(id, why) { if (T[id] && !seen.has(id)) seen.set(id, { id, name: T[id][0], tactic: T[id][1], why, url: url(id) }); },
      list() { return [...seen.values()]; }
    };
  }

  /** items: [{ report, a }]. opts.text: the pasted alert. Keywords count only if something is flagged. */
  function map(items, opts) {
    const c = collector();
    let flagged = false;
    for (const it of items || []) {
      if (!FLAGGED.has(it.a.verdict)) continue;
      flagged = true;
      const g = it.report.group;
      const facts = it.a.reasons.filter((r) => r.kind === 'bad').map((r) => r.t).join(' ');
      if (g === 'cve') { c.add('T1190', 'Vulnerability under active exploitation or high priority'); if (/ransomware/i.test(facts)) c.add('T1486', 'CVE used in ransomware campaigns'); continue; }
      if (g === 'hash') c.add('T1204.002', 'Known-bad file');
      if (g === 'url' || g === 'domain') c.add('T1204.001', 'Known-bad or impersonating link');
      if (/impersonation|microsoft name|brand|lookalike/i.test(facts) && (g === 'url' || g === 'domain')) c.add('T1566.002', 'Link impersonates a known brand');
      if (/Domain registered \d+ day/i.test(facts)) c.add('T1583.001', 'Newly registered domain');
      if (/scanner/i.test(facts)) c.add('T1595', 'Source is a known internet scanner');
      if (/tor exit/i.test(facts)) c.add('T1090.003', 'Traffic through a Tor exit node');
      if (/command-and-control|botnet|\bc2\b/i.test(facts)) c.add('T1071', 'Command-and-control infrastructure');
    }
    if (flagged && opts && opts.text) for (const [re, id, why] of KEYWORDS) if (re.test(opts.text)) c.add(id, why);
    return c.list();
  }

  /** Mapping for a reported email (VSEml.analyze result). */
  function forEmail(r) {
    const c = collector();
    if (!r || !r.ok || !FLAGGED.has(r.verdict)) return c.list();
    if (r.attachments.some((a) => a.flags.length)) c.add('T1566.001', 'Email carries a risky attachment');
    if (r.attachments.some((a) => a.flags.some((f) => /double extension/i.test(f)))) c.add('T1036.007', 'Attachment hides its real type');
    if (r.urls.some((u) => u.mismatch || u.level === 'warn' || u.level === 'block')) c.add('T1566.002', 'Email carries a deceptive link');
    if (r.head.reasons.some((x) => x.kind === 'bad' && /display name|reply-to|BEC/i.test(x.t))) c.add('T1656', 'Sender identity is faked');
    return c.list();
  }

  /** "T1566.002 Phishing: Spearphishing Link (Initial Access)" for notes. */
  function label(t) { return `${t.id} ${t.name} (${t.tactic})`; }

  const api = { map, forEmail, label, url };
  root.VSMitre = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
