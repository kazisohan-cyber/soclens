/*
 * IOC Triage decision memory: a local record of each investigation and what the analyst decided.
 * It answers "what did we do last time we saw this?" and writes the shift handover.
 * Pure functions: the panel stores the list. Only indicators, verdicts, the ticket reference and the
 * decision are kept, never the pasted alert. History informs the analyst and never changes a verdict.
 *
 * Case: { id, at, updated, client, ticket, analyst, overall, suggested, decision, iocs: [{ type, value, verdict }] }
 */
(function (root) {
  'use strict';
  const MAX = 2000;
  const KEEP_DAYS = 180;
  const DAY = 864e5;
  const SAME_RUN_MS = 60 * 60e3;
  const REPEAT_BENIGN = 3;      // closes as benign before IOC Triage offers to save a client note

  const isBenignClose = (d) => /^(False positive|Benign true positive)/.test(d || '');
  const isTruePositive = (d) => /^True positive/.test(d || '');
  const needsInfo = (d) => /^Needs more information/.test(d || '');
  const inScope = (c, client) => !client || !c.client || c.client.toLowerCase() === String(client).toLowerCase();
  const signature = (c) => [String(c.client || '').toLowerCase(), String(c.ticket || '').toLowerCase(), c.iocs.map((x) => x.value).sort().join('|')].join('#');

  function normalize(x, now) {
    now = now || Date.now();
    const iocs = (Array.isArray(x.iocs) ? x.iocs : []).slice(0, 50).filter((i) => i && i.value)
      .map((i) => ({ type: String(i.type || ''), value: String(i.value).slice(0, 2048), verdict: String(i.verdict || 'unknown') }));
    return { id: String(x.id || ''), at: Number(x.at) || now, updated: Number(x.updated) || Number(x.at) || now, client: String(x.client || '').trim().slice(0, 60),
      ticket: String(x.ticket || '').trim().slice(0, 200), analyst: String(x.analyst || '').trim().slice(0, 60), overall: String(x.overall || 'unknown'),
      suggested: String(x.suggested || '').slice(0, 80), decision: String(x.decision || '').slice(0, 80), iocs };
  }

  function fromInvestigation(items, opts) {
    opts = opts || {};
    return normalize({ id: opts.id, at: opts.now, updated: opts.now, client: opts.client, ticket: opts.ticket, analyst: opts.analyst, overall: opts.overall, suggested: opts.suggested,
      iocs: (items || []).map((it) => ({ type: it.report.type, value: it.report.value, verdict: it.a.verdict })) }, opts.now);
  }

  function prune(list, now) {
    const cut = (now || Date.now()) - KEEP_DAYS * DAY;
    return list.filter((c) => c.updated >= cut).sort((a, b) => b.at - a.at).slice(0, MAX);
  }

  /** Adds a case. The same alert re-run within the hour updates the existing case and keeps its decision. */
  function upsert(list, item, now) {
    now = now || Date.now();
    const sig = signature(item);
    const prev = list.find((c) => signature(c) === sig && now - c.at < SAME_RUN_MS);
    if (!prev) return { list: prune([item, ...list], now), item };
    const merged = Object.assign({}, item, { id: prev.id, at: prev.at, decision: prev.decision, updated: now });
    return { list: prune(list.map((c) => (c.id === prev.id ? merged : c)), now), item: merged };
  }

  function setDecision(list, id, decision, now) {
    return list.map((c) => (c.id === id ? Object.assign({}, c, { decision: String(decision || '').slice(0, 80), updated: now || Date.now() }) : c));
  }

  /** What was decided before for one indicator. */
  function history(list, value, client, skipId) {
    const h = { total: 0, benign: 0, truePositive: 0, needsInfo: 0, undecided: 0, last: 0, lastDecision: '' };
    const v = String(value).toLowerCase();
    for (const c of list) {
      if (c.id === skipId || !inScope(c, client) || !c.iocs.some((i) => i.value.toLowerCase() === v)) continue;
      h.total++;
      if (isBenignClose(c.decision)) h.benign++;
      else if (isTruePositive(c.decision)) h.truePositive++;
      else if (needsInfo(c.decision)) h.needsInfo++;
      else h.undecided++;
      if (c.at > h.last && c.decision) { h.last = c.at; h.lastDecision = c.decision; }
    }
    return h;
  }

  function ago(ts, now) {
    const d = Math.floor(((now || Date.now()) - ts) / DAY);
    return d <= 0 ? 'today' : d === 1 ? 'yesterday' : `${d} days ago`;
  }

  /** "Seen 4 times before: 3 closed as benign, 1 true positive. Last: False positive: closed, today." */
  function describeHistory(h, now) {
    if (!h.total) return '';
    const parts = [];
    if (h.benign) parts.push(`${h.benign} closed as benign`);
    if (h.truePositive) parts.push(`${h.truePositive} true positive`);
    if (h.needsInfo) parts.push(`${h.needsInfo} needed more information`);
    if (h.undecided) parts.push(`${h.undecided} with no decision`);
    return `Seen ${h.total} time${h.total > 1 ? 's' : ''} before: ${parts.join(', ')}.` + (h.lastDecision ? ` Last: ${h.lastDecision}, ${ago(h.last, now)}.` : '');
  }

  /** Offer a client note only for repeat benign closes that nothing contradicts. */
  function suggestsNote(h, verdict) {
    return h.benign >= REPEAT_BENIGN && !h.truePositive && !['malicious', 'critical', 'suspicious', 'high'].includes(verdict);
  }

  function isOpen(c) { return !isBenignClose(c.decision); }

  function defangOf(i) { return root.VSIoc ? root.VSIoc.defang(i.value, i.type) : i.value; }

  function caseLine(c) {
    const flagged = c.iocs.filter((i) => ['malicious', 'critical', 'suspicious', 'high'].includes(i.verdict));
    const shown = (flagged.length ? flagged : c.iocs).slice(0, 3).map(defangOf).join(', ');
    const more = c.iocs.length > 3 ? ` (${c.iocs.length} indicators)` : '';
    const when = new Date(c.at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    return `${when} ${c.ticket || 'No ticket'}${c.client ? ' · ' + c.client : ''} · ${c.overall.toUpperCase()} · ${c.decision || 'No decision recorded'}: ${shown}${more}`;
  }

  /** The shift report. opts: { from, to, client, analyst, note }. */
  function handover(list, opts) {
    opts = opts || {};
    const to = opts.to || Date.now();
    const from = opts.from || to - DAY;
    const cases = list.filter((c) => c.at >= from && c.at <= to && inScope(c, opts.client)).sort((a, b) => b.at - a.at);
    const counts = { total: cases.length, escalated: 0, contained: 0, closed: 0, needsInfo: 0, undecided: 0 };
    for (const c of cases) {
      if (/escalated/i.test(c.decision)) counts.escalated++;
      else if (isTruePositive(c.decision)) counts.contained++;
      else if (isBenignClose(c.decision)) counts.closed++;
      else if (needsInfo(c.decision)) counts.needsInfo++;
      else counts.undecided++;
    }
    const open = cases.filter(isOpen);
    const closed = cases.filter((c) => !isOpen(c));
    const fmt = (t) => new Date(t).toLocaleString([], { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
    const t = [`SHIFT HANDOVER · ${fmt(from)} to ${fmt(to)}`];
    t.push(`From: ${opts.analyst || '________'}`);
    if (opts.client) t.push(`Client: ${opts.client}`);
    t.push(`Investigations: ${counts.total} · Escalated: ${counts.escalated} · Contained: ${counts.contained} · Closed: ${counts.closed} · Needs information: ${counts.needsInfo} · No decision: ${counts.undecided}`);
    t.push('', 'NEEDS ATTENTION:');
    if (open.length) open.forEach((c) => t.push(`- ${caseLine(c)}`)); else t.push('- Nothing open from this shift');
    t.push('', 'CLOSED:');
    if (closed.length) closed.forEach((c) => t.push(`- ${caseLine(c)}`)); else t.push('- None');
    t.push('', '(Indicators defanged. Generated by IOC Triage from decisions recorded on this device; verify before acting.)');
    return { counts, open, closed, text: t.join('\n') };
  }

  /** Merge an imported list, newest update wins per id. */
  function merge(list, incoming, now) {
    const byId = new Map(list.map((c) => [c.id, c]));
    let added = 0, updated = 0;
    for (const x of Array.isArray(incoming) ? incoming : []) {
      if (!x || !x.id) continue;
      const c = normalize(x, now);
      const cur = byId.get(c.id);
      if (!cur) { byId.set(c.id, c); added++; } else if (c.updated > cur.updated) { byId.set(c.id, c); updated++; }
    }
    return { list: prune([...byId.values()], now), added, updated };
  }

  const api = { MAX, KEEP_DAYS, REPEAT_BENIGN, normalize, fromInvestigation, upsert, setDecision, history, describeHistory, suggestsNote, handover, merge, isBenignClose };
  root.VSCases = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
