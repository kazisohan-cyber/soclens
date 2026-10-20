/*
 * Sample data for screenshots and demos (analyst-preview.html?demo=1).
 * IPs come from documentation ranges (RFC 5737) and domains use .example, so no real third party is
 * labelled malicious. Google DNS, the EICAR antivirus test file and CVE-2024-3400 use public facts.
 * The real engine (VSEngine.assess) and client memory turn this data into verdicts.
 */
(function () {
  'use strict';
  const L = (u) => u;
  const FIX = {
    '198.51.100.23': { type: 'ipv4', group: 'ip', sources: {
      abuseipdb: { status: 'ok', link: L('https://www.abuseipdb.com/'), data: { score: 100, reports: 1204, usage: 'Data Center/Web Hosting/Transit', isp: 'Example Hosting B.V.', country: 'NL' } },
      greynoise: { status: 'ok', link: L('https://viz.greynoise.io/'), data: { noise: true, riot: false, classification: 'malicious', name: 'unknown' } },
      internetdb: { status: 'ok', link: L('https://www.shodan.io/'), data: { ports: [22, 3389, 8080], tags: [], vulns: [], hostnames: [] } },
      ipinfo: { status: 'ok', link: L('https://ipinfo.io/'), data: { org: 'AS64500 Example Hosting B.V.', country: 'NL', city: 'Amsterdam' } },
      vt: { status: 'ok', link: L('https://www.virustotal.com/'), data: { malicious: 14, suspicious: 2, harmless: 56, undetected: 22 } },
      threatfox: { status: 'notfound', link: L('https://threatfox.abuse.ch/') } } },
    'https://micros0ft-login.example/auth?u=bob': { type: 'url', group: 'url', analyze: true, sources: {
      rdap: { status: 'ok', data: { ageDays: 3 } },
      dns: { status: 'ok', data: { nx: false, a: ['198.51.100.40'] } },
      vt: { status: 'ok', link: L('https://www.virustotal.com/'), data: { malicious: 9, suspicious: 3, harmless: 60, undetected: 22 } },
      urlhaus: { status: 'notfound', link: L('https://urlhaus.abuse.ch/') },
      threatfox: { status: 'notfound' } } },
    '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f': { type: 'sha256', group: 'hash', sources: {
      vt: { status: 'ok', link: L('https://www.virustotal.com/'), data: { malicious: 61, suspicious: 0, harmless: 0, undetected: 10, label: 'eicar/test', name: 'eicar.com', typeDesc: 'Text' } },
      malwarebazaar: { status: 'notfound' }, threatfox: { status: 'notfound' } } },
    '8.8.8.8': { type: 'ipv4', group: 'ip', sources: {
      greynoise: { status: 'ok', data: { riot: true, name: 'Google Public DNS' } },
      internetdb: { status: 'ok', data: { ports: [53, 443], tags: [], vulns: [], hostnames: ['dns.google'] } },
      ipinfo: { status: 'ok', data: { org: 'AS15169 Google LLC', country: 'US', city: 'Mountain View' } },
      abuseipdb: { status: 'ok', data: { score: 0, reports: 0, whitelisted: true, usage: 'Content Delivery Network' } },
      vt: { status: 'ok', data: { malicious: 0, suspicious: 0, harmless: 66, undetected: 28 } } } },
    'CVE-2024-3400': { type: 'cve', group: 'cve', sources: {
      kev: { status: 'ok', data: { vendor: 'Palo Alto Networks', product: 'PAN-OS', name: 'PAN-OS Command Injection', dateAdded: '2024-04-12', ransomware: 'Known',
        requiredAction: 'Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.' } },
      epss: { status: 'ok', data: { epss: 0.9999, percentile: 1 } },
      nvd: { status: 'ok', data: { score: 10, severity: 'CRITICAL', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        description: 'A command injection as a result of arbitrary file creation vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software may enable an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.' } } } },
    '203.0.113.77': { type: 'ipv4', group: 'ip', sources: {
      ipinfo: { status: 'ok', data: { org: 'AS64501 Example ISP', country: 'BD', city: 'Dhaka' } },
      internetdb: { status: 'notfound' }, greynoise: { status: 'notfound' },
      abuseipdb: { status: 'ok', data: { score: 0, reports: 0, usage: 'Fixed Line ISP' } } } }
  };

  const MEMORY = [
    { id: 'demo-1', kind: 'ioc', ioc: '203.0.113.0/24', client: 'Client A', verdict: 'benign', note: 'Fortinet VPN egress (Dhaka office)', ticket: 'CHG-1042', by: 'L1 Analyst' },
    { id: 'demo-2', kind: 'user', ioc: 'svc-backup', client: 'Client A', verdict: 'benign', note: 'Nightly backup job, signs in around 02:00', by: 'L2 Analyst' },
    { id: 'demo-3', kind: 'host', ioc: 'bkp-srv01', client: 'Client A', verdict: 'note', note: 'Backup server, Veeam', by: 'L2 Analyst' },
    { id: 'demo-4', kind: 'asn', ioc: 'AS62044', client: 'Client A', verdict: 'benign', note: 'Zscaler internet access', by: 'L1 Analyst', ticket: 'INC-3901' }
  ];

  window.SOCLENS_DEMO = {
    text: 'Securonix INC-4711: svc-backup on BKP-SRV01 signed in from 203.0.113.77, then 198.51.100.23. ' +
      'User clicked hxxps://micros0ft-login[.]example/auth?u=bob and dropped 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f. ' +
      'Firewall alert CVE-2024-3400. DNS 8.8.8.8',
    async seed() {
      const now = Date.now();
      await chrome.storage.local.set({
        memory: MEMORY.map((m, i) => Object.assign({ created: now - (i + 3) * 864e5, updated: now - (i + 1) * 864e5, expires: now + (80 - i * 10) * 864e5 }, m)),
        analyst: { keys: { vt: 'demo', abuseipdb: 'demo' }, wizardDone: true, activeClient: 'Client A', analyst: 'L1 Analyst', publicSources: true, highlight: true, ai: false }
      });
    },
    async investigate(value) {
      const I = window.VSIoc, E = window.VSEngine, M = window.VSMemory, A = window.VSAnalyzer;
      const c = I.classify(value);
      const f = FIX[c.value] || { type: c.type, group: c.group, sources: {} };
      const { memory = [], analyst = {} } = await chrome.storage.local.get(['memory', 'analyst']);
      const list = memory.map((m) => M.normalize(m));
      const report = { type: c.type, group: c.group, value: c.value, internal: false, local: {}, sources: f.sources, client: analyst.activeClient };
      if (f.analyze) {
        const dom = I.domainOf(c.type, c.value);
        report.local = { domain: dom, analyzer: A.analyzeUrl(c.value, {}), blocklisted: false };
      }
      report.memory = M.matchIoc(list, c.type, c.value, analyst.activeClient);
      if (c.group === 'ip') report.memory = report.memory.concat(M.matchNetwork(list, M.networkOf(f.sources), analyst.activeClient));
      await new Promise((r) => setTimeout(r, 250 + Math.random() * 500));
      return { report, a: E.assess(report) };
    }
  };
})();
