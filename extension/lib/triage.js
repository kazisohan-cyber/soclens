/*
 * SOCLens triage: suggests what an analyst should do with the alert, from the verdicts already computed.
 * It only suggests. It sees indicators, not the whole incident, so it never suggests closing when
 * evidence is missing, and the analyst records the real decision.
 *
 * items = [{ report, a }] (engine output). opts.failed = indicators whose lookup failed.
 */
(function (root) {
  'use strict';

  // What the analyst records on the ticket.
  const DECISIONS = ['True positive: escalated', 'True positive: contained', 'False positive: closed', 'Benign true positive: closed', 'Needs more information'];

  const THREAT = new Set(['malicious', 'critical']);
  const WATCH = new Set(['suspicious', 'high']);

  const D = (it) => (root.VSIoc ? root.VSIoc.defang(it.report.value, it.report.type) : it.report.value);
  const bad = (it) => it.a.reasons.filter((r) => r.kind === 'bad').map((r) => r.t)[0];
  const isCve = (it) => it.report.group === 'cve';
  const hasClientNote = (it) => (it.report.memory || []).some((m) => !m.expired && m.verdict === 'benign');

  function decide(items, opts) {
    opts = opts || {};
    const failed = opts.failed || 0;
    if (!items || !items.length) return null;
    const threats = items.filter((it) => THREAT.has(it.a.verdict));
    const watch = items.filter((it) => WATCH.has(it.a.verdict));
    const iocs = items.filter((it) => !isCve(it));
    const unknown = iocs.filter((it) => it.a.verdict === 'unknown' || it.a.verdict === 'low');
    const internal = iocs.filter((it) => it.a.verdict === 'internal');
    const benign = iocs.filter((it) => it.a.verdict === 'benign');

    if (threats.length) {
      const firm = threats.some((it) => isCve(it) || it.a.confidence !== 'low');
      if (firm) {
        return { decision: 'escalate', label: 'Escalate', detail: 'Likely true positive', confidence: threats.some((it) => it.a.confidence === 'high') ? 'high' : 'medium',
          why: threats.slice(0, 3).map((it) => `${D(it)}: ${bad(it) || it.a.verdict}`) };
      }
    }
    if (threats.length || watch.length) {
      const list = threats.concat(watch);
      return { decision: 'investigate', label: 'Investigate first', detail: 'Do not close yet', confidence: 'medium',
        why: list.slice(0, 3).map((it) => `${D(it)}: ${bad(it) || it.a.verdict}`) };
    }
    if (failed) {
      return { decision: 'context', label: 'Needs more information', detail: 'Lookups incomplete', confidence: 'low',
        why: [`${failed} lookup${failed > 1 ? 's' : ''} failed: run it again before deciding`] };
    }
    if (unknown.length || !iocs.length) {
      return { decision: 'context', label: 'Needs more information', detail: 'No evidence either way', confidence: 'low',
        why: [unknown.length ? `No reputation source knows ${unknown.slice(0, 2).map(D).join(', ')}` : 'Only vulnerability data here', 'Decide on the asset, the user, the time and the volume'] };
    }
    const unexplained = internal.filter((it) => !(it.report.memory || []).some((m) => !m.expired));
    if (unexplained.length) {
      return { decision: 'context', label: 'Needs more information', detail: 'Internal asset not identified', confidence: 'low',
        why: [`${D(unexplained[0])} is internal and has no client note`, 'Identify the asset and the process behind it'] };
    }
    const weak = benign.filter((it) => it.a.confidence === 'low');
    if (weak.length) {
      return { decision: 'context', label: 'Needs more information', detail: 'Benign, but on weak evidence', confidence: 'low',
        why: [`${D(weak[0])} looks benign, with low confidence`, 'Add an intel API key or check the context'] };
    }
    const noted = iocs.some(hasClientNote) || internal.length > 0;
    return { decision: 'close', label: noted ? 'Close: benign true positive' : 'Close: likely false positive', detail: noted ? 'Expected for this client' : 'No indicator is flagged',
      confidence: benign.every((it) => it.a.confidence === 'high') ? 'high' : 'medium',
      why: iocs.slice(0, 3).map((it) => `${D(it)}: ${(it.a.reasons.find((r) => r.kind === 'good' || r.src === 'memory') || {}).t || it.a.verdict}`) };
  }

  /** A short hand-over for L2: what was seen, why it was escalated, what was checked, what to do next. */
  function escalationNote(items, suggestion, opts) {
    opts = opts || {};
    const E = root.VSEngine;
    const when = new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
    const ranked = items.slice().sort((x, y) => (E.RANK[y.a.verdict] || 0) - (E.RANK[x.a.verdict] || 0));
    const t = [`ESCALATION TO L2 · ${when}`];
    if (opts.client) t.push(`Client: ${opts.client}`);
    if (opts.context) t.push(`Ticket / alert: ${opts.context}`);
    t.push(`From: ${opts.analyst || '________'}`);
    if (suggestion) t.push(`Reason: ${suggestion.label} (${suggestion.detail}, confidence ${suggestion.confidence})`);
    t.push('', 'Evidence:');
    for (const it of ranked) {
      const r = it.a.reasons.filter((x) => x.kind !== 'info').slice(0, 2).map((x) => x.t);
      t.push(`- ${D(it)}: ${it.a.verdict.toUpperCase()} (confidence ${it.a.confidence})`);
      for (const x of r) t.push(`    ${x}`);
    }
    for (const c of opts.clientContext || []) t.push(`- Client context: ${c}`);
    const actions = [];
    for (const it of ranked) for (const x of it.a.actions.slice(0, 2)) if (!actions.includes(x)) actions.push(x);
    if (actions.length) { t.push('', 'Suggested next steps:'); actions.slice(0, 5).forEach((x) => t.push(`- ${x}`)); }
    if (opts.hunt) t.push('', `Hunt query (${opts.hunt.name}, last ${root.VSHunt ? root.VSHunt.DAYS : 30} days):`, opts.hunt.query);
    const seen = new Set(), missed = new Set();
    for (const it of items) for (const [k, s] of Object.entries(it.report.sources || {})) {
      const nm = (E.SOURCE_NAMES && E.SOURCE_NAMES[k]) || k;
      if (s.status === 'ok' || s.status === 'notfound') seen.add(nm);
      else if (s.status === 'nokey' || s.status === 'ratelimited' || s.status === 'error') missed.add(nm);
    }
    t.push('', `Checked: ${[...seen].join(', ') || 'none'}`);
    const gaps = [...missed].filter((x) => !seen.has(x));
    if (gaps.length) t.push(`Not checked: ${gaps.join(', ')}`);
    t.push('(Indicators defanged. Generated by SOCLens; verify before acting.)');
    return t.join('\n');
  }

  const api = { DECISIONS, decide, escalationNote };
  root.VSTriage = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
