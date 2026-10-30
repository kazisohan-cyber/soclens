/*
 * Rebuilds the README and website images (docs/screenshots/*.jpg, docs/og-image.png) from the real
 * panel, popup and highlighter with sample data only. No dependencies: Node 22+ and Chrome or Edge.
 *
 *   node docs/store/tools/capture-site-images.mjs
 *
 * It serves the repo on 127.0.0.1 for the length of the run and fails if a page reaches any other host.
 */
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, extname, join, normalize, resolve, sep } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const OUT = join(ROOT, 'docs', 'screenshots');
const PANEL = '/tests/analyst-preview.html?demo=1';

const OG = `<!doctype html><meta charset="utf-8"><style>
*{box-sizing:border-box}html,body{margin:0;width:1280px;height:640px;overflow:hidden;background:#0d1014;color:#eceef2;font-family:"Segoe UI",system-ui,sans-serif}
.l{position:absolute;left:74px;top:82px;width:600px}.b{display:flex;align-items:center;gap:22px}.b img{width:72px;height:72px}.b h1{margin:0;font-size:74px;font-weight:700;letter-spacing:-.01em;white-space:nowrap}
h2{margin:22px 0 28px;font-size:34px;line-height:1.25;font-weight:400;color:#2dd4bf}p{margin:0;font-size:26px;line-height:1.46;color:#c9ced6}
.c{display:flex;gap:12px;margin:28px 0 34px}.c span{border:1px solid #4a505a;border-radius:999px;padding:7px 15px;font-size:22px;color:#c9ced6}.u{font-size:22px;color:#858c97}
iframe{position:absolute;left:750px;top:40px;width:440px;height:760px;border:1px solid #2b3038;border-radius:14px;background:#111317}
</style><div class="l"><div class="b"><img src="/extension/icons/icon128.png" alt=""><h1>IOC Triage</h1></div>
<h2>SOC analyst assistant &amp;<br>phishing protection</h2>
<p>Paste an alert for an explainable verdict on every<br>indicator, then copy the ticket note. Decisions,<br>phishing triage and shift handover in your browser.</p>
<div class="c"><span>Free &amp; open source</span><span>Runs locally</span><span>Chrome · Edge</span></div>
<div class="u">github.com/kazisohan-cyber/soclens</div></div><iframe src="${PANEL}"></iframe>`;

const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.json': 'application/json' };
const server = createServer((req, res) => {
  const path = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (path === '/__og') { res.writeHead(200, { 'content-type': 'text/html' }); res.end(OG); return; }
  const file = normalize(join(ROOT, path));
  const allowed = [join(ROOT, 'extension') + sep, join(ROOT, 'tests') + sep];
  if (!allowed.some((a) => file.startsWith(a)) || !existsSync(file)) { res.writeHead(404); res.end(); return; }
  res.writeHead(200, { 'content-type': MIME[extname(file)] || 'application/octet-stream' });
  res.end(readFileSync(file));
});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Runs in the panel window. Scripted through the real controls.
const HELP = `
window.__wait = async (test, ms = 15000) => { const t = Date.now(); while (Date.now() - t < ms) { if (test()) return true; await new Promise((r) => setTimeout(r, 100)); } throw new Error('timed out: ' + test); };
window.__run = async () => {
  await __wait(() => document.getElementById('go') && window.VSEngine);
  await new Promise((r) => setTimeout(r, 300));
  const $ = (id) => document.getElementById(id);
  $('q').value = SOCLENS_DEMO.text; $('ctx').value = 'Securonix INC-4711'; $('q').dispatchEvent(new Event('input', { bubbles: true })); $('go').click();
  await __wait(() => document.querySelectorAll('#results .card').length >= 6 && !document.querySelector('#results .spin') && !$('overall').hidden);
  await new Promise((r) => setTimeout(r, 500));
};
window.__rect = (a, b) => { const x = document.querySelector(a).getBoundingClientRect(), y = document.querySelector(b || a).getBoundingClientRect(); return { top: x.top + scrollY, bottom: y.bottom + scrollY }; };`;

async function main() {
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const profile = mkdtempSync(join(tmpdir(), 'ioc-triage-capture-'));
  const exe = [process.env.CHROME_PATH, 'C:/Program Files/Google/Chrome/Application/chrome.exe', 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', '/usr/bin/google-chrome', '/usr/bin/chromium'].filter(Boolean).find((p) => existsSync(p));
  if (!exe) throw new Error('No Chrome or Edge found. Set CHROME_PATH.');
  const browser = spawn(exe, ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`, '--no-first-run', '--disable-extensions', '--hide-scrollbars', 'about:blank'], { stdio: 'ignore' });
  let wsUrl;
  for (let i = 0; i < 60 && !wsUrl; i++) { await sleep(500); try { const [p, path] = readFileSync(join(profile, 'DevToolsActivePort'), 'utf8').split(/\r?\n/); wsUrl = `ws://127.0.0.1:${p}${path}`; } catch (_) { /* not yet */ } }
  const ws = new WebSocket(wsUrl);
  await new Promise((r) => ws.addEventListener('open', r, { once: true }));
  let id = 0; const wait = new Map(); const external = [];
  ws.addEventListener('message', (m) => {
    const d = JSON.parse(m.data);
    if (d.id && wait.has(d.id)) { wait.get(d.id)(d); wait.delete(d.id); return; }
    if (d.method === 'Network.requestWillBeSent') { const u = d.params.request.url; if (!u.startsWith(base) && !/^(data|blob):/.test(u)) external.push(u); }
  });
  const send = (method, params = {}, sessionId) => new Promise((r) => { const i = ++id; wait.set(i, r); ws.send(JSON.stringify({ id: i, method, params, sessionId })); });

  /** Opens a page in its own tab, runs setup, returns the clip. */
  async function shot(file, { url, width, height, scale = 1, dark = true, setup, clip, png }) {
    const { result: { targetId } } = await send('Target.createTarget', { url: 'about:blank' });
    const { result: { sessionId: s } } = await send('Target.attachToTarget', { targetId, flatten: true });
    await send('Network.enable', {}, s); await send('Page.enable', {}, s);
    await send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: scale, mobile: false }, s);
    await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: dark ? 'dark' : 'light' }] }, s);
    await send('Page.navigate', { url: base + url }, s);
    await sleep(1000);
    const ev = async (expression) => {
      const r = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }, s);
      if (r.result.exceptionDetails) throw new Error(file + ': ' + (r.result.exceptionDetails.exception?.description || r.result.exceptionDetails.text));
      return r.result.result.value;
    };
    await ev(HELP + ';1');
    if (setup) await setup(ev, s);
    await sleep(500);
    const rect = clip ? await ev(clip) : { top: 0, bottom: height };
    const params = { format: png ? 'png' : 'jpeg', captureBeyondViewport: true, clip: { x: rect.x || 0, y: rect.top, width: rect.width || width, height: rect.bottom - rect.top, scale: 1 } };
    if (!png) params.quality = 88;
    const r = await send('Page.captureScreenshot', params, s);
    writeFileSync(file, Buffer.from(r.result.data, 'base64'));
    console.log('wrote', file.slice(ROOT.length + 1));
    await send('Target.closeTarget', { targetId });
  }

  const panel = { url: PANEL, width: 438, height: 900, scale: 1.6 };
  try {
    await shot(join(OUT, '01-investigate.jpg'), { ...panel, setup: (ev) => ev('__run()'), clip: "(() => ({ top: 0, bottom: __rect('#overall').bottom + 10 }))()" });
    await shot(join(OUT, '02-verdicts.jpg'), { ...panel, setup: (ev) => ev('__run()'), clip: "(() => { const r = __rect('#results .card:nth-child(3)', '#results .card:nth-child(5)'); return { top: r.top - 8, bottom: r.bottom + 2 }; })()" });
    await shot(join(OUT, '03-email-headers.jpg'), { ...panel, setup: (ev) => ev(`(async () => {
      await __wait(() => document.getElementById('emlFile') && window.SOCLENS_DEMO && window.VSEml); await new Promise((r) => setTimeout(r, 300));
      document.querySelector('[data-tab=headers]').click();
      const dt = new DataTransfer(); dt.items.add(new File([SOCLENS_DEMO.eml], 'reported.eml', { type: 'message/rfc822' }));
      const f = document.getElementById('emlFile'); f.files = dt.files; f.dispatchEvent(new Event('change', { bubbles: true }));
      await __wait(() => document.querySelectorAll('#hdrOut .card').length >= 2);
    })()`), clip: "(() => { const r = __rect('#hdrOut'); return { top: r.top - 8, bottom: r.bottom + 12 }; })()" });
    await shot(join(OUT, '04-client-memory.jpg'), { ...panel, setup: (ev) => ev(`(async () => {
      await __wait(() => document.getElementById('mList') && window.VSEngine); await new Promise((r) => setTimeout(r, 300));
      document.querySelector('[data-tab=memory]').click(); await __wait(() => document.querySelector('#mList .card'));
    })()`), clip: "(() => ({ top: 0, bottom: __rect('#mList').bottom + 12 }))()" });
    await shot(join(OUT, '05-popup.jpg'), { url: '/tests/popup-preview.html?site=phish&enrolled=1', width: 420, height: 900, setup: (ev) => ev("document.getElementById('ver').hidden = true"), clip: "(() => { const r = document.body.getBoundingClientRect(); return { x: r.left, width: r.width, top: r.top + scrollY, bottom: r.bottom + scrollY }; })()" });
    await shot(join(OUT, '06-highlighting.jpg'), { url: '/tests/highlight-preview.html', width: 776, height: 420, dark: false, setup: async (ev, s) => {
      await sleep(800);
      const p = await ev(`(() => { const w = document.createTreeWalker(document.getElementById('app'), NodeFilter.SHOW_TEXT); let n; while ((n = w.nextNode())) { const i = n.data.indexOf('203.0.113.77'); if (i >= 0) { const r = document.createRange(); r.setStart(n, i); r.setEnd(n, i + 12); const b = r.getBoundingClientRect(); return { x: b.left + b.width / 2, y: b.top + b.height / 2 }; } } return null; })()`);
      for (const type of ['mousePressed', 'mouseReleased']) await send('Input.dispatchMouseEvent', { type, x: p.x, y: p.y, button: 'left', clickCount: 1 }, s);
      await sleep(800);
    }, clip: "(() => ({ top: 0, bottom: document.getElementById('app').getBoundingClientRect().bottom + 12 }))()" });
    await shot(join(ROOT, 'docs', 'og-image.png'), { url: '/__og', width: 1280, height: 640, png: true, setup: (ev) => ev(`(async () => {
      const f = document.querySelector('iframe'); await __wait(() => f.contentWindow.SOCLENS_DEMO);
      f.contentWindow.eval(HELPTEXT); await f.contentWindow.__run();
    })()`.replace('HELPTEXT', JSON.stringify(HELP))) });
  } finally {
    browser.kill(); server.close(); ws.close();
    await sleep(500);
    try { rmSync(profile, { recursive: true, force: true }); } catch (_) { /* browser still releasing files */ }
  }
  if (external.length) { console.error('Requests left this machine:\n  ' + external.join('\n  ')); process.exit(1); }
  console.log('No request left this machine.');
}
main().catch((e) => { console.error(e); process.exit(1); });
