/*
 * IOC Triage hunt queries: turns indicators into a search the analyst can paste into their SIEM / EDR.
 * Pure functions. Values come from untrusted alert text, so every value is escaped for its query language.
 *
 * iocs = [{ type, group, value }] as produced by VSIoc / the investigate report.
 */
(function (root) {
  'use strict';

  const TOOLS = [
    { id: 's1', name: 'SentinelOne', hint: 'Deep Visibility' },
    { id: 'defender', name: 'Defender', hint: 'Advanced hunting (KQL)' },
    { id: 'sentinel', name: 'Sentinel', hint: 'Log Analytics (KQL)' },
    { id: 'splunk', name: 'Splunk', hint: 'SPL' },
    { id: 'securonix', name: 'Securonix', hint: 'Spotter' }
  ];
  const DAYS = 30;

  const quote = (v) => '"' + String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
  const list = (vals) => vals.map(quote).join(', ');
  const uniq = (a) => [...new Set(a)];

  /** Sort indicators by what each query language can search on. URLs are searched by host. */
  function bucket(iocs) {
    const b = { ips: [], domains: [], md5: [], sha1: [], sha256: [], emails: [], cves: [] };
    for (const x of iocs || []) {
      if (!x || !x.value) continue;
      if (x.group === 'ip') b.ips.push(x.value);
      else if (x.group === 'domain') b.domains.push(x.value);
      else if (x.group === 'url') {
        const d = root.VSIoc && root.VSIoc.domainOf(x.type, x.value);
        if (d) b.domains.push(d);
      } else if (x.group === 'hash' && b[x.type]) b[x.type].push(x.value.toLowerCase());
      else if (x.group === 'email') b.emails.push(x.value);
      else if (x.group === 'cve') b.cves.push(x.value);
    }
    for (const k of Object.keys(b)) b[k] = uniq(b[k]);
    return b;
  }

  function s1(b) {
    const or = [];
    for (const ip of b.ips) or.push(`dst.ip.address = ${quote(ip)}`, `src.ip.address = ${quote(ip)}`);
    for (const d of b.domains) or.push(`url.address contains ${quote(d)}`, `event.dns.request contains ${quote(d)}`);
    for (const t of ['md5', 'sha1', 'sha256']) for (const h of b[t]) or.push(`src.process.image.${t} = ${quote(h)}`, `tgt.file.${t} = ${quote(h)}`);
    return or.length ? or.join(' OR ') : '';
  }

  /** Kusto union over tables that may not exist in every tenant (isfuzzy skips the missing ones). */
  function kql(parts, timeCol, by) {
    if (!parts.length) return '';
    return ['union withsource=Table isfuzzy=true', parts.map((p) => `  (${p})`).join(',\n'),
      `| where ${timeCol} > ago(${DAYS}d)`, `| summarize Hits=count(), FirstSeen=min(${timeCol}), LastSeen=max(${timeCol}) by ${by}`, '| sort by LastSeen desc'].join('\n');
  }

  function hashWhere(b) {
    const or = [];
    if (b.sha256.length) or.push(`SHA256 in~ (${list(b.sha256)})`);
    if (b.sha1.length) or.push(`SHA1 in~ (${list(b.sha1)})`);
    if (b.md5.length) or.push(`MD5 in~ (${list(b.md5)})`);
    return or.join(' or ');
  }

  function defender(b) {
    const parts = [];
    const net = [];
    if (b.ips.length) net.push(`RemoteIP in (${list(b.ips)})`);
    if (b.domains.length) net.push(`RemoteUrl has_any (${list(b.domains)})`);
    if (net.length) parts.push(`DeviceNetworkEvents | where ${net.join(' or ')}`);
    const hw = hashWhere(b);
    if (hw) parts.push(`DeviceProcessEvents | where ${hw}`, `DeviceFileEvents | where ${hw}`);
    if (b.emails.length) parts.push(`EmailEvents | where SenderFromAddress in~ (${list(b.emails)})`);
    if (b.cves.length) parts.push(`DeviceTvmSoftwareVulnerabilities | where CveId in~ (${list(b.cves)}) | extend Timestamp = now()`);
    return kql(parts, 'Timestamp', 'Table, DeviceName = tostring(column_ifexists("DeviceName", ""))');
  }

  function sentinel(b) {
    const parts = [];
    if (b.ips.length) {
      const l = list(b.ips);
      parts.push(`SigninLogs | where IPAddress in (${l})`, `CommonSecurityLog | where SourceIP in (${l}) or DestinationIP in (${l})`, `DeviceNetworkEvents | where RemoteIP in (${l})`);
    }
    if (b.domains.length) {
      const l = list(b.domains);
      parts.push(`DnsEvents | where Name has_any (${l})`, `CommonSecurityLog | where RequestURL has_any (${l}) or DestinationHostName has_any (${l})`, `DeviceNetworkEvents | where RemoteUrl has_any (${l})`);
    }
    const hw = hashWhere(b);
    if (hw) parts.push(`DeviceProcessEvents | where ${hw}`, `DeviceFileEvents | where ${hw}`);
    if (b.emails.length) parts.push(`EmailEvents | where SenderFromAddress in~ (${list(b.emails)})`);
    return kql(parts, 'TimeGenerated', 'Table');
  }

  function terms(b) { return [...b.ips, ...b.domains, ...b.md5, ...b.sha1, ...b.sha256, ...b.emails]; }

  function splunk(b) {
    const t = terms(b);
    if (!t.length) return '';
    return `index=* earliest=-${DAYS}d (${t.map(quote).join(' OR ')})\n| stats count, min(_time) as first_seen, max(_time) as last_seen by index, sourcetype, host\n| convert ctime(first_seen) ctime(last_seen)`;
  }

  function securonix(b) {
    const t = terms(b);
    if (!t.length) return '';
    return `index = activity AND (${t.map((v) => 'rawevent CONTAINS ' + quote(v)).join(' OR ')})`;
  }

  const BUILD = { s1, defender, sentinel, splunk, securonix };

  /** One query for one tool over any number of indicators. '' when the tool cannot search these types. */
  function query(tool, iocs) {
    const fn = BUILD[tool];
    return fn ? fn(bucket(iocs)) : '';
  }

  /** The tools that can search these indicators: [{ id, name, hint, query }]. */
  function queries(iocs) {
    return TOOLS.map((t) => Object.assign({}, t, { query: query(t.id, iocs) })).filter((t) => t.query);
  }

  const api = { TOOLS, DAYS, query, queries, bucket };
  root.VSHunt = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
