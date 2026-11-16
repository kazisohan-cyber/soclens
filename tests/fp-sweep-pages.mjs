// False-positive sweep for the sign-in page check: opens real login pages in headless Edge,
// collects the same signals as content/page-guard.js, and scores them with lib/analyzer.js.
// Prints every page that is not "safe". Opens each listed site once; sends nothing to them.
// node tests/fp-sweep-pages.mjs [--only substring]
import { spawn } from 'node:child_process';
import { readFileSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const req = createRequire(import.meta.url);
globalThis.self = globalThis; globalThis.window = globalThis;
req('../extension/lib/public-suffixes.js');
const A = req('../extension/lib/analyzer.js');

// The page's own collect() from page-guard.js, so the sweep tests the shipped code, not a copy.
const guard = readFileSync(new URL('../extension/content/page-guard.js', import.meta.url), 'utf8');
const chunk = guard.slice(guard.indexOf('  const visible = '), guard.indexOf('  async function scan()'));
if (!chunk.includes('function collect()')) throw new Error('collect() not found in page-guard.js');
const COLLECT = `(() => {\n${chunk}\nreturn collect(); })()`;

// Legitimate sign-in pages: global SaaS, banks, HR / payroll and other business portals, Asia-first.
const PAGES = [
  'https://github.com/login', 'https://gitlab.com/users/sign_in', 'https://id.atlassian.com/login', 'https://slack.com/signin',
  'https://www.notion.so/login', 'https://login.salesforce.com/', 'https://accounts.zoho.com/signin', 'https://app.hubspot.com/login',
  'https://www.canva.com/login', 'https://www.figma.com/login', 'https://trello.com/login', 'https://app.asana.com/-/login',
  'https://auth.monday.com/login', 'https://accounts.shopify.com/login', 'https://wordpress.com/log-in', 'https://medium.com/m/signin',
  'https://www.quora.com/', 'https://stackoverflow.com/users/login', 'https://www.twitch.tv/login', 'https://discord.com/login',
  'https://accounts.spotify.com/en/login', 'https://signin.ebay.com/', 'https://login.aliexpress.com/', 'https://account.booking.com/sign-in',
  'https://www.airbnb.com/login', 'https://auth.uber.com/', 'https://shopee.com.my/buyer/login', 'https://member.lazada.com.my/user/login',
  'https://www.daraz.com.bd/', 'https://www.foodpanda.com.bd/login', 'https://www.freshworks.com/login/', 'https://www.zendesk.com/login/',
  'https://app.intercom.com/admins/sign_in', 'https://dashboard.stripe.com/login', 'https://www.xero.com/login/', 'https://app.qbo.intuit.com/',
  'https://www.mailchimp.com/login/', 'https://app.sendgrid.com/login', 'https://dash.cloudflare.com/login', 'https://app.netlify.com/login',
  'https://vercel.com/login', 'https://www.digitalocean.com/login', 'https://my.contabo.com/', 'https://www.namecheap.com/myaccount/login/',
  'https://sso.godaddy.com/', 'https://www.linode.com/login', 'https://portal.azure.com/', 'https://app.jumpcloud.com/login',
  'https://usea1.sentinelone.net/', 'https://www.halopsa.com/', 'https://app.bamboohr.com/login.php', 'https://www.zoho.com/people/login.html',
  'https://app.greythr.com/', 'https://www.keka.com/login', 'https://app.darwinbox.com/', 'https://www.zinghr.com/',
  'https://live.digisme.in/LoginV2.aspx', 'https://www.payrollhero.com/login', 'https://app.swingvy.com/login', 'https://app.talenox.com/login',
  'https://my.jobstreet.com/login', 'https://www.naukri.com/nlogin/login', 'https://bdjobs.com/login.asp', 'https://www.maybank2u.com.my/home/m2u/common/login.do',
  'https://www.cimbclicks.com.my/clicks/', 'https://internet-banking.dbs.com.sg/', 'https://www.bkash.com/', 'https://ibanking.bracbank.com/',
  'https://www.citytouch.com.bd/', 'https://app.wise.com/login', 'https://www.coursera.org/?authMode=login', 'https://www.udemy.com/join/login-popup/',
  'https://www.netacad.com/', 'https://learn.microsoft.com/', 'https://www.credly.com/users/sign_in', 'https://www.edx.org/login'
];

const only = process.argv.includes('--only') ? process.argv[process.argv.indexOf('--only') + 1] : null;
const list = only ? PAGES.filter((u) => u.includes(only)) : PAGES;

const prof = join(tmpdir(), 'ioc-fp-sweep-' + Date.now()), port = 9341;
const edge = spawn('C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', ['--headless=new', `--remote-debugging-port=${port}`,
  `--user-data-dir=${prof}`, '--inprivate', '--disable-extensions', '--disable-sync', '--no-first-run', '--window-size=1366,900', 'about:blank'], { stdio: 'ignore' });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let targets; for (let i = 0; i < 50 && !targets; i++) { try { targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json(); } catch { await sleep(200); } }
const ws = new WebSocket(targets.find((x) => x.type === 'page').webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener('open', r));
let id = 0; const pend = new Map();
ws.addEventListener('message', (e) => { const m = JSON.parse(e.data); if (pend.has(m.id)) { pend.get(m.id)(m); pend.delete(m.id); } });
const send = (method, params = {}) => new Promise((r) => { const i = ++id; pend.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
const ev = async (x) => { const r = await send('Runtime.evaluate', { expression: x, returnByValue: true }); return r.result?.result?.value; };
await send('Page.enable');

const rows = []; let noForm = 0, failed = 0;
for (const u of list) {
  try {
    await send('Page.navigate', { url: u });
    await sleep(6000);
    const href = await ev('location.href');
    const s = await ev(COLLECT);
    if (!s) { failed++; console.log('ERR  ', u); continue; }
    if (!s.hasPassword) noForm++;
    const v = A.analyzePage(A.analyzeUrl(href), s);
    const tag = s.hasPassword ? 'pw' : 'no-pw';
    console.log(v.level.padEnd(7), String(v.score).padStart(3), tag.padEnd(5), href.slice(0, 90));
    if (v.level !== 'safe') rows.push([v.level, v.score, href, v.reasons.join('; ')]);
  } catch (e) { failed++; console.log('ERR  ', u, String(e).slice(0, 80)); }
}
ws.close(); edge.kill();
await sleep(500); try { rmSync(prof, { recursive: true, force: true }); } catch { /* Edge may still hold files */ }
console.log(`\npages ${list.length}, without a visible password box ${noForm}, errors ${failed}, flagged ${rows.length}`);
for (const r of rows) console.log('FLAG', r.join(' | '));
process.exitCode = rows.length ? 1 : 0;
