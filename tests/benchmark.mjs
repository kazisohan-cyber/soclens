// Measures lib/analyzer.js on URL text only: no page is opened, and no request is made.
// node tests/benchmark.mjs <folder with the lists> [out.json]
// The folder holds phishing-links-ACTIVE.txt, phishing-domains-ACTIVE.txt and top-1m.csv.
// This covers the address check only, not fake login detection or domain age.
import { createRequire } from 'node:module';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const A = createRequire(import.meta.url)('../extension/lib/analyzer.js');
const [dir, out] = process.argv.slice(2);
const lines = (f) => readFileSync(join(dir, f), 'utf8').split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
const defang = (s) => String(s).replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
const pct = (n, d) => (d ? +(100 * n / d).toFixed(2) : 0);

function tally() { return { total: 0, safe: 0, caution: 0, warn: 0, block: 0 }; }
function add(t, level) { t.total++; t[level]++; }
function rates(t) { return { ...t, blockPct: pct(t.block, t.total), warnOrBlockPct: pct(t.warn + t.block, t.total), anyFlagPct: pct(t.total - t.safe, t.total) }; }

const rank = new Map();
for (const row of lines('top-1m.csv')) {
  const i = row.indexOf(',');
  rank.set(row.slice(i + 1).toLowerCase(), +row.slice(0, i));
}

// Legitimate side: the home page of every ranked domain.
const legit = { top10k: tally(), top100k: tally(), top1m: tally() };
const flagged = [];
for (const [domain, r] of rank) {
  const v = A.analyzeUrl('https://' + domain + '/');
  add(legit.top1m, v.level);
  if (r <= 100000) add(legit.top100k, v.level);
  if (r <= 10000) add(legit.top10k, v.level);
  if (v.level === 'warn' || v.level === 'block') flagged.push({ r, d: domain, level: v.level, score: v.score, why: v.reasons });
}
flagged.sort((a, b) => a.r - b.r);

// A popular site on the list is often a hacked or shared host, so those are counted apart.
const popular = (domain) => { const r = rank.get(domain); return r && r <= 100000; };

function scorePhish(items, toUrl) {
  const all = tally(), notPopular = tally(), reasons = new Map(), missed = [];
  let unparsed = 0;
  for (const item of items) {
    const url = toUrl(item);
    if (!/^https?:\/\//i.test(url)) { unparsed++; continue; }
    const v = A.analyzeUrl(url);
    if (!v.host) { unparsed++; continue; }
    add(all, v.level);
    if (!popular(v.domain)) {
      add(notPopular, v.level);
      if (v.level === 'safe' && missed.length < 100000) missed.push(v.host);
    }
    for (const w of v.reasons) { const k = w.replace(/["(:].*$/, '').replace(/\b(Uses the|Domain imitates|Starts with a real)\b.*/, '$1').trim(); reasons.set(k, (reasons.get(k) || 0) + 1); }
  }
  return { all: rates(all), notPopular: rates(notPopular), unparsed, reasons: [...reasons].sort((a, b) => b[1] - a[1]).slice(0, 15), missed };
}

const t0 = Date.now();
const links = scorePhish(lines('phishing-links-ACTIVE.txt'), (u) => u);
const hostList = lines('phishing-domains-ACTIVE.txt');
const hosts = scorePhish(hostList, (d) => 'http://' + d + '/');
const newest = {};
for (const f of ['phishing-links-NEW-today.txt', 'phishing-domains-NEW-today.txt']) {
  if (!existsSync(join(dir, f))) continue;
  const s = scorePhish(lines(f), (x) => (/^[a-z]+:\/\//i.test(x) ? x : 'http://' + x + '/'));
  newest[f] = { all: s.all, notPopular: s.notPopular };
}

// What the feed would do if it were used as a block list as it stands.
const overlap = { exactHost: { top1k: 0, top10k: 0, top100k: 0, top1m: 0 }, sameDomain: { top1k: 0, top10k: 0, top100k: 0, top1m: 0 } };
const exact = [], seenDomains = new Set(), sameDomain = [];
const bump = (o, r) => { if (r <= 1000) o.top1k++; if (r <= 10000) o.top10k++; if (r <= 100000) o.top100k++; o.top1m++; };
for (const h of hostList) {
  const host = h.toLowerCase();
  const direct = rank.get(host);
  if (direct) { bump(overlap.exactHost, direct); exact.push([direct, host]); }
  const d = A.registrableDomain(host);
  const r = rank.get(d);
  if (r && !seenDomains.has(d)) { seenDomains.add(d); bump(overlap.sameDomain, r); sameDomain.push([r, d]); }
}
const byRank = (a, b) => a[0] - b[0];

const every = Math.max(1, Math.floor(hosts.missed.length / 40));
const result = {
  note: 'Address check only. Default thresholds: warn at 40, block at 70.',
  legit: { top10k: rates(legit.top10k), top100k: rates(legit.top100k), top1m: rates(legit.top1m) },
  flaggedTop: flagged.slice(0, 60).map((f) => ({ ...f, d: defang(f.d) })),
  blockedTop: flagged.filter((f) => f.level === 'block').slice(0, 40).map((f) => ({ ...f, d: defang(f.d) })),
  newest,
  overlap,
  overlapExactTop: exact.sort(byRank).slice(0, 25).map(([r, d]) => [r, defang(d)]),
  overlapDomainTop: sameDomain.sort(byRank).slice(0, 25).map(([r, d]) => [r, defang(d)]),
  phishLinks: { ...links, missed: undefined, missedCount: links.missed.length },
  phishHosts: { ...hosts, missed: undefined, missedCount: hosts.missed.length },
  missedSample: hosts.missed.filter((_, i) => i % every === 0).slice(0, 40).map(defang),
  seconds: Math.round((Date.now() - t0) / 1000)
};
if (out) writeFileSync(out, JSON.stringify(result, null, 1));
console.log(JSON.stringify(result, null, 1));
