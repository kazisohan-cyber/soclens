/*
 * IOC Triage IOC highlighter (analyst sites only: Securonix, HaloPSA, EDR consoles... see Settings).
 * Colours IPs, domains, URLs, hashes and CVEs using the CSS Custom Highlight API, so the page's own
 * DOM is never modified (safe on React/Angular SOC consoles). Colour comes from client memory, the
 * phishing feed and earlier verdicts; no external lookup runs until the analyst clicks an indicator.
 */
(function () {
  'use strict';
  if (window.top !== window || window.__soclensHl) return;
  window.__soclensHl = true;
  const I = window.VSIoc;
  if (!I || !CSS.highlights || typeof Highlight === 'undefined') return;

  const host = location.hostname.toLowerCase();
  const STATES = ['malicious', 'suspicious', 'benign', 'known', 'internal', 'plain'];
  const COLORS = { malicious: '#d92d20', suspicious: '#dc6803', benign: '#079455', known: '#2e90fa', internal: '#98a2b3', plain: '#98a2b3' };
  const MAX_NODES = 20000, MAX_IOCS = 600;
  let ranges = [];          // { range, value, type, group, state, note }
  let stateOf = new Map();  // value -> { state, note }
  let observer = null, timer = null, enabled = false, pop = null;

  function onList(h, list) { return (list || []).some((d) => h === d || h.endsWith('.' + d)); }

  async function init() {
    const { analyst } = await chrome.storage.local.get('analyst');
    const sites = (analyst && analyst.highlightSites) || ['securonix.net', 'securonix.com', 'halopsa.com', 'haloitsm.com', 'haloservicedesk.com',
      'sentinelone.net', 'security.microsoft.com', 'portal.azure.com', 'app.slack.com', 'teams.microsoft.com'];
    let on = !(analyst && analyst.highlight === false) && onList(host, sites);
    if (on) { const p = await chrome.runtime.sendMessage({ type: 'protectionState' }).catch(() => null); on = !!(p && p.agreed); }
    if (on === enabled) return;
    enabled = on;
    if (enabled) start(); else stop();
  }

  function start() {
    const style = document.createElement('style');
    style.id = 'soclens-hl-style';
    style.textContent = STATES.map((s) => `::highlight(slx-${s}) { text-decoration: ${s === 'plain' ? 'underline dotted' : 'underline wavy'} ${COLORS[s]} ${s === 'plain' ? '1px' : '1.5px'}; text-underline-offset: 3px;${s === 'malicious' ? ' background-color: rgba(217,45,32,.12);' : ''} }`).join('\n');
    (document.head || document.documentElement).append(style);
    scan();
    observer = new MutationObserver((muts) => {
      if (muts.every((m) => pop && pop.contains(m.target))) return;
      clearTimeout(timer);
      timer = setTimeout(scan, 900);
    });
    observer.observe(document.body, { childList: true, subtree: true, characterData: true });
    document.addEventListener('click', onClick, true);
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closePop(); });
  }

  function stop() {
    if (observer) observer.disconnect();
    for (const s of STATES) CSS.highlights.delete('slx-' + s);
    const st = document.getElementById('soclens-hl-style');
    if (st) st.remove();
    document.removeEventListener('click', onClick, true);
    closePop();
    ranges = [];
  }

  const SKIP = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEXTAREA', 'INPUT', 'SELECT', 'OPTION', 'SVG', 'CANVAS', 'IFRAME', 'TEMPLATE']);
  function scan() {
    if (!enabled || !document.body) return;
    const found = [];
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
      acceptNode(n) {
        const p = n.parentElement;
        if (!p || SKIP.has(p.tagName) || p.isContentEditable || (pop && pop.contains(p))) return NodeFilter.FILTER_REJECT;
        return n.nodeValue.length >= 7 ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_SKIP;
      }
    });
    let count = 0;
    for (let n = walker.nextNode(); n && count < MAX_NODES && found.length < MAX_IOCS; n = walker.nextNode(), count++) {
      for (const m of I.extract(n.nodeValue, { strict: true, max: 40 })) {
        const r = document.createRange();
        r.setStart(n, m.start);
        r.setEnd(n, m.end);
        found.push({ range: r, value: m.value, type: m.type, group: m.group });
        if (found.length >= MAX_IOCS) break;
      }
    }
    ranges = found;
    const unknown = [...new Map(found.filter((f) => !stateOf.has(f.value)).map((f) => [f.value, { value: f.value, type: f.type, group: f.group }])).values()];
    paint();
    if (unknown.length) {
      chrome.runtime.sendMessage({ type: 'quickLook', values: unknown.slice(0, 400) }).then((res) => {
        for (const x of res || []) stateOf.set(x.value, { state: x.state || 'plain', note: x.note || '' });
        paint();
      }).catch(() => {});
    }
  }

  function paint() {
    const groups = Object.fromEntries(STATES.map((s) => [s, []]));
    for (const r of ranges) {
      const st = (stateOf.get(r.value) || {}).state || 'plain';
      r.state = groups[st] ? st : 'plain';
      groups[r.state].push(r.range);
    }
    for (const s of STATES) {
      if (groups[s].length) CSS.highlights.set('slx-' + s, new Highlight(...groups[s]));
      else CSS.highlights.delete('slx-' + s);
    }
  }

  function hitAt(x, y) {
    let node, offset;
    if (document.caretPositionFromPoint) { const p = document.caretPositionFromPoint(x, y); if (!p) return null; node = p.offsetNode; offset = p.offset; }
    else if (document.caretRangeFromPoint) { const r = document.caretRangeFromPoint(x, y); if (!r) return null; node = r.startContainer; offset = r.startOffset; }
    if (!node) return null;
    return ranges.find((r) => r.range.startContainer === node && offset >= r.range.startOffset && offset <= r.range.endOffset) || null;
  }

  function onClick(e) {
    if (pop && pop.contains(e.target)) return;
    closePop();
    if (e.button !== 0 || e.target.closest('a,button,[role=button],input,textarea,select')) return;
    if (window.getSelection && String(window.getSelection()).length > 0) return;
    const hit = hitAt(e.clientX, e.clientY);
    if (hit) showPop(hit, e.clientX, e.clientY);
  }

  function closePop() { if (pop) { pop.remove(); pop = null; } }

  function showPop(hit, x, y) {
    pop = document.createElement('div');
    pop.style.cssText = 'position:fixed;z-index:2147483647;left:0;top:0';
    const root = pop.attachShadow({ mode: 'closed' });
    const css = document.createElement('style');
    css.textContent = `:host{all:initial}.b{font:13px/1.45 system-ui,'Segoe UI',sans-serif;color:#16181d;background:#fff;border:1px solid #d0d5dd;border-radius:10px;box-shadow:0 8px 24px rgba(16,24,40,.18);padding:10px 12px;width:320px;max-width:calc(100vw - 24px)}
      .v{font:600 12.5px ui-monospace,Consolas,monospace;word-break:break-all}.t{font-size:11px;color:#5f6672;margin:2px 0 6px}.p{display:inline-block;font:700 10.5px system-ui;letter-spacing:.03em;padding:2px 8px;border-radius:999px;color:#fff;background:#98a2b3}
      .malicious,.critical{background:#d92d20}.suspicious,.high{background:#dc6803}.benign{background:#079455}.known{background:#2e90fa}
      ul{margin:6px 0;padding-left:16px}li{margin:2px 0}button{font:12px system-ui;padding:5px 9px;border-radius:7px;border:1px solid #d0d5dd;background:#fff;cursor:pointer;margin:6px 6px 0 0}
      button.pr{background:#0f766e;color:#fff;border-color:#0f766e}.s{font-size:12.5px;margin-top:6px}.m{color:#5f6672;font-size:12px}
      @media (prefers-color-scheme:dark){.b{background:#1a1d23;color:#eceef2;border-color:#2b3038}button{background:#1a1d23;color:#eceef2;border-color:#2b3038}.t,.m{color:#9aa1ad}}`;
    const b = document.createElement('div');
    b.className = 'b';
    const st = stateOf.get(hit.value) || {};
    const el = (tag, cls, text) => { const x = document.createElement(tag); if (cls) x.className = cls; if (text != null) x.textContent = text; return x; };
    b.append(el('div', 'v', I.defang(hit.value, hit.type)));
    b.append(el('div', 't', (I.LABEL_OF[hit.type] || hit.type) + ' · IOC Triage'));
    if (st.state && st.state !== 'plain') { b.append(el('span', 'p ' + st.state, st.state.toUpperCase())); }
    if (st.note) b.append(el('div', 's', st.note));
    const out = el('div', 's');
    b.append(out);
    const bInv = el('button', 'pr', 'Investigate');
    const bPanel = el('button', '', 'Open in panel');
    const bCopy = el('button', '', 'Copy defanged');
    bInv.onclick = async () => {
      bInv.disabled = true;
      out.textContent = 'Checking sources…';
      const r = await chrome.runtime.sendMessage({ type: 'investigate', value: hit.value }).catch(() => null);
      bInv.disabled = false;
      out.textContent = '';
      if (!r || r.error || !r.a) { out.textContent = (r && r.error) || 'Lookup failed'; return; }
      stateOf.set(hit.value, { state: ['malicious', 'suspicious', 'benign', 'internal'].includes(r.a.verdict) ? r.a.verdict : 'plain', note: '' });
      paint();
      out.append(el('span', 'p ' + r.a.verdict, r.a.verdict.toUpperCase()), el('span', 'm', '  confidence ' + r.a.confidence));
      out.append(el('div', 's', r.a.summary));
      const ul = el('ul');
      for (const x of r.a.reasons.filter((z) => z.kind !== 'info').slice(0, 4)) ul.append(el('li', '', x.t));
      if (ul.children.length) out.append(ul);
    };
    bPanel.onclick = () => { chrome.runtime.sendMessage({ type: 'openPanel', value: hit.value }); closePop(); };
    bCopy.onclick = async () => { try { await navigator.clipboard.writeText(I.defang(hit.value, hit.type)); bCopy.textContent = 'Copied ✓'; } catch (_) { bCopy.textContent = 'Copy blocked'; } };
    b.append(bInv, bPanel, bCopy);
    root.append(css, b);
    document.documentElement.append(pop);
    const w = 330, hgt = 140;
    pop.style.left = Math.max(8, Math.min(x + 8, innerWidth - w - 12)) + 'px';
    pop.style.top = Math.max(8, y + 14 + hgt > innerHeight ? y - hgt - 14 : y + 14) + 'px';
  }

  chrome.storage.onChanged.addListener((ch, area) => {
    if (area !== 'local') return;
    if (ch.analyst || ch.dataConsent) init();
    if (ch.memory && enabled) { stateOf = new Map(); scan(); }
  });
  init();
})();
