/*
 * Rebuilds docs/store/screenshots/*.png from the real side panel with sample data only
 * (tests/analyst-preview.html?demo=1). No dependencies: Node 22+ and an installed Chrome or Edge.
 *
 *   node docs/store/tools/capture-screenshots.mjs
 *
 * It serves the repo on 127.0.0.1 for the length of the run, composes each 1280x800 image around
 * real panels in iframes, and fails if the page tries to reach any other host.
 */
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, extname, join, normalize, resolve, sep } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..', '..', '..');
const OUT = join(ROOT, 'docs', 'store', 'screenshots');
const WIDTH = 1280, HEIGHT = 800;
const PANEL = '/tests/analyst-preview.html?demo=1';

const CSS = `
*{box-sizing:border-box}html,body{margin:0;width:${WIDTH}px;height:${HEIGHT}px;overflow:hidden;background:#0d1014;font-family:"Segoe UI",system-ui,sans-serif;color:#eceef2}
.stage{display:flex;width:${WIDTH}px;height:${HEIGHT}px}
.side{width:392px;flex:none;padding:56px 36px;background:linear-gradient(160deg,#0f766e,#0b3d3a 70%,#0a2b2a);display:flex;flex-direction:column}
.brand{display:flex;align-items:center;gap:10px;font-size:18px;font-weight:600;margin-bottom:64px}.brand img{width:36px;height:36px;padding:4px;background:#fff;border-radius:9px}
h1{font-size:38px;line-height:1.14;margin:0 0 20px;font-weight:700;letter-spacing:-.01em}
p{font-size:17px;line-height:1.5;margin:0;color:#d5efeb}
.foot{margin-top:auto;font-size:13px;color:#9fd3cc}
.cols{flex:1;display:flex;gap:1px;background:#2b3038;min-width:0}
.cols iframe{border:0;flex:1 1 0;min-width:0;height:${HEIGHT}px;background:#111317}
.doc{flex:1.3 1 0;min-width:0;background:#fff;color:#16181d;padding:20px 22px;overflow:hidden;font-size:12.5px;line-height:1.42}
.doc h2{font-size:15px;margin:0 0 2px}.doc .sub{font-size:12px;color:#5f6672;margin-bottom:12px}
.doc #note p{color:inherit;font-size:inherit;line-height:inherit;margin:0 0 6px}.doc #note table{border-collapse:collapse;width:100%;margin:6px 0;table-layout:fixed}.doc #note th:nth-child(1){width:24px}.doc #note th:nth-child(2){width:104px}.doc #note th:nth-child(3){width:50px}.doc #note th:nth-child(4){width:82px}.doc #note td,.doc #note th{border:1px solid #d0d5dd;padding:3px 5px;vertical-align:top;text-align:left}.doc #note td:nth-child(2){overflow-wrap:anywhere}
`;

// Each scene is a caption, the panels it shows, and steps run inside those panels before the capture.
const SCENES = [
  { file: '1-alert-to-verdict.png', title: 'Paste an alert. Get a verdict on every indicator.',
    text: 'IOC Triage pulls out each IP, domain, URL, hash, email and CVE, checks them, and says what to do next.',
    panels: 2, steps: [
      { run: 'investigate', scrollTo: 0 },
      { run: 'investigate', scrollSel: '#results .card:nth-child(2)', gap: 52 }
    ] },
  { file: '2-explainable-verdicts.png', title: 'Verdicts that show their reasons.',
    text: 'Every finding names its source. Client notes add what is normal for that client, and they expire.',
    panels: 2, steps: [
      { run: 'investigate', scrollSel: '#results .card:nth-child(3)', gap: 52 },
      { run: 'investigate', scrollSel: '#results .card:nth-child(5)', gap: 52 }
    ] },
  { file: '3-ticket-note.png', title: 'From alert to ticket note in one click.',
    text: 'Copy a finished note, an escalation hand-over for L2, or a ready hunt query for your SIEM or EDR.',
    panels: 1, doc: true, steps: [{ run: 'investigate', scrollSel: '#triage', gap: 52, note: true }] },
  { file: '4-phishing-and-handover.png', title: 'Triage reported phishing. Hand over your shift.',
    text: 'Open an .eml file on your device for links and attachment hashes, then copy a shift report built from your decisions.',
    panels: 2, steps: [{ eml: true, scrollTo: 0 }, { tab: 'shift', scrollTo: 0 }] },
  { file: '5-your-own-ai.png', title: 'Your own AI, only if you want it.',
    text: 'Off by default. Nothing is sent until you click, you can read exactly what goes out, and client data is masked by default.',
    panels: 2, steps: [
      { ai: true, run: 'investigate', whatGetsSent: true, scrollSel: '#byo', gap: 45 },
      { ai: true, tab: 'settings', scrollSel: '#aiProvider', gap: 110 }
    ] }
];

function composePage(scene) {
  const iframes = Array.from({ length: scene.panels }, () => `<iframe src="${PANEL}"></iframe>`).join('');
  const doc = scene.doc ? '<div class="doc"><h2>Ticket INC-4711</h2><div class="sub">Pasted from IOC Triage (sample data)</div><div id="note"></div></div>' : '';
  return `<!doctype html><meta charset="utf-8"><style>${CSS}</style><div class="stage"><div class="side">
    <div class="brand"><img src="/extension/icons/icon48.png" alt=""><span>IOC Triage</span></div>
    <h1>${scene.title}</h1><p>${scene.text}</p><div class="foot">Sample data shown</div></div>
    <div class="cols">${iframes}${doc}</div></div>`;
}

const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.json': 'application/json', '.jpg': 'image/jpeg' };
let currentScene = null;
const server = createServer((req, res) => {
  const path = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (path === '/__compose') { res.writeHead(200, { 'content-type': 'text/html' }); res.end(composePage(currentScene)); return; }
  const file = normalize(join(ROOT, path));
  // threats.csv and anything else outside the panel's own code is never served.
  const allowed = [join(ROOT, 'extension') + sep, join(ROOT, 'tests') + sep];
  if (!allowed.some((a) => file.startsWith(a)) || !existsSync(file)) { res.writeHead(404); res.end(); return; }
  res.writeHead(200, { 'content-type': MIME[extname(file)] || 'application/octet-stream' });
  res.end(readFileSync(file));
});

function findBrowser() {
  const c = [process.env.CHROME_PATH, 'C:/Program Files/Google/Chrome/Application/chrome.exe', 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    '/usr/bin/google-chrome', '/usr/bin/chromium', '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'].filter(Boolean);
  const hit = c.find((p) => existsSync(p));
  if (!hit) throw new Error('No Chrome or Edge found. Set CHROME_PATH.');
  return hit;
}

class Cdp {
  constructor(ws) { this.ws = ws; this.id = 0; this.wait = new Map(); this.handlers = [];
    ws.addEventListener('message', (m) => {
      const d = JSON.parse(m.data);
      if (d.id && this.wait.has(d.id)) { const { ok, no } = this.wait.get(d.id); this.wait.delete(d.id); d.error ? no(new Error(JSON.stringify(d.error))) : ok(d.result); }
      else this.handlers.forEach((h) => h(d));
    });
  }
  send(method, params = {}, sessionId) { return new Promise((ok, no) => { const id = ++this.id; this.wait.set(id, { ok, no }); this.ws.send(JSON.stringify({ id, method, params, sessionId })); }); }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Runs in the top page: drives the real panel in each iframe.
const PAGE_HELPERS = `
window.__settle = async (w, test, ms = 12000) => { const t = Date.now(); while (Date.now() - t < ms) { if (test(w)) return true; await new Promise((r) => setTimeout(r, 100)); } throw new Error('timed out: ' + test); };
window.__drive = async (frame, step, demoText) => {
  const w = frame.contentWindow;
  await __settle(w, (x) => x.document.getElementById('go') && x.SOCLENS_DEMO && x.VSEngine);
  await new Promise((r) => setTimeout(r, 300));
  const d = w.document, $ = (id) => d.getElementById(id);
  if (step.ai) {
    // The real settings flow, with a local model so no key is involved.
    d.querySelector('[data-tab=settings]').click();
    await __settle(w, () => $('aiProvider').options.length > 1);
    $('aiProvider').value = 'local'; $('aiProvider').dispatchEvent(new w.Event('change', { bubbles: true }));
    $('aiUrl').value = 'http://localhost:11434/v1/chat/completions'; $('aiModel').value = 'llama3.2'; $('aiBlocked').value = 'Client B'; $('sName').value = 'L1 Analyst';
    $('sSave').click();
    await new Promise((r) => setTimeout(r, 400));
    d.querySelector('[data-tab=investigate]').click();
  }
  if (step.run) {
    $('q').value = demoText; $('ctx').value = 'Securonix INC-4711';
    $('q').dispatchEvent(new w.Event('input', { bubbles: true }));
    $('go').click();
    await __settle(w, (x) => { const c = x.document.querySelectorAll('#results .card'); return c.length >= 6 && !x.document.querySelector('#results .spin') && !x.document.getElementById('overall').hidden; }, 20000);
    await new Promise((r) => setTimeout(r, 400));
  }
  if (step.eml) {
    d.querySelector('[data-tab=headers]').click();
    const dt = new w.DataTransfer();
    dt.items.add(new w.File([w.SOCLENS_DEMO.eml], 'reported.eml', { type: 'message/rfc822' }));
    $('emlFile').files = dt.files;
    $('emlFile').dispatchEvent(new w.Event('change', { bubbles: true }));
    await __settle(w, (x) => x.document.querySelector('#hdrOut .card'));
    await new Promise((r) => setTimeout(r, 300));
  }
  if (step.tab) { d.querySelector('[data-tab=' + step.tab + ']').click(); await new Promise((r) => setTimeout(r, 300)); }
  if (step.whatGetsSent) { const det = d.querySelector('#byo details'); det.open = true; await new Promise((r) => setTimeout(r, 200)); }
  if (step.scrollSel) { const el = d.querySelector(step.scrollSel); if (!el) throw new Error('no ' + step.scrollSel); w.scrollTo(0, el.getBoundingClientRect().top + w.scrollY - (step.gap || 0)); }
  else w.scrollTo(0, step.scrollTo || 0);
  if (step.note) {
    let html = '';
    const realSet = w.DataTransfer.prototype.setData;
    w.DataTransfer.prototype.setData = function (t, v) { if (t === 'text/html') html = v; return realSet.call(this, t, v); };
    d.execCommand = () => { d.dispatchEvent(new w.ClipboardEvent('copy', { clipboardData: new w.DataTransfer(), bubbles: true, cancelable: true })); return true; };
    $('copyNote').click();
    w.DataTransfer.prototype.setData = realSet;
    if (!html) throw new Error('ticket note was not captured');
    document.getElementById('note').innerHTML = html;
  }
};`;

async function main() {
  mkdirSync(OUT, { recursive: true });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;
  const profile = mkdtempSync(join(tmpdir(), 'soclens-capture-'));
  const browser = spawn(findBrowser(), ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`, '--no-first-run', '--disable-extensions', '--hide-scrollbars', '--mute-audio', 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
  const wsUrl = await new Promise((ok, no) => {
    let buf = ''; browser.stderr.on('data', (d) => { buf += d; const m = buf.match(/ws:\/\/\S+/); if (m) ok(m[0]); });
    setTimeout(() => no(new Error('browser did not start')), 20000);
  });
  const ws = new WebSocket(wsUrl);
  await new Promise((r) => ws.addEventListener('open', r, { once: true }));
  const cdp = new Cdp(ws);
  const external = [];
  cdp.handlers.push((d) => {
    if (d.method !== 'Network.requestWillBeSent') return;
    const u = d.params.request.url;
    if (!u.startsWith(base) && !u.startsWith('data:') && !u.startsWith('blob:')) external.push(u);
  });
  const failures = [];
  try {
    for (const scene of SCENES) {
      currentScene = scene;
      const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
      const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
      const s = (m, p) => cdp.send(m, p, sessionId);
      await s('Network.enable');
      await s('Page.enable');
      await s('Emulation.setDeviceMetricsOverride', { width: WIDTH, height: HEIGHT, deviceScaleFactor: 1, mobile: false });
      await s('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: 'dark' }] });
      await s('Page.navigate', { url: base + '/__compose' });
      await sleep(800);
      const demoText = "window.frames[0].SOCLENS_DEMO.text";
      const steps = JSON.stringify(scene.steps);
      const expr = `(async () => { ${PAGE_HELPERS}
        const frames = [...document.querySelectorAll('iframe')]; const steps = ${steps};
        await __settle(window, () => frames.every((f) => f.contentWindow.SOCLENS_DEMO));
        const text = ${demoText};
        await Promise.all(frames.map((f, i) => __drive(f, steps[i], text)));
        return 'ok'; })()`;
      const r = await s('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
      if (r.exceptionDetails) { failures.push(scene.file + ': ' + (r.exceptionDetails.exception?.description || r.exceptionDetails.text)); }
      await sleep(600);
      const shot = await s('Page.captureScreenshot', { format: 'png', clip: { x: 0, y: 0, width: WIDTH, height: HEIGHT, scale: 1 } });
      writeFileSync(join(OUT, scene.file), Buffer.from(shot.data, 'base64'));
      console.log('wrote', scene.file);
      await cdp.send('Target.closeTarget', { targetId });
    }
  } finally {
    browser.kill(); server.close(); ws.close();
    await sleep(500);
    try { rmSync(profile, { recursive: true, force: true }); } catch (_) { /* browser still releasing files */ }
  }
  if (external.length) failures.push('Requests left this machine:\n  ' + external.join('\n  '));
  if (failures.length) { console.error(failures.join('\n')); process.exit(1); }
  console.log('No request left this machine.');
}
main().catch((e) => { console.error(e); process.exit(1); });
