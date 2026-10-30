/*
 * IOC Triage email header analyzer: paste raw headers, get SPF / DKIM / DMARC, the delivery path,
 * sender mismatches (BEC patterns), the originating IP and a verdict. Runs fully on the device.
 * Uses VSAnalyzer (brands, registrable domains) and VSIoc when loaded.
 */
(function (root) {
  'use strict';

  function unfold(raw) {
    const head = String(raw || '').replace(/\r\n/g, '\n').split(/\n\s*\n/)[0];
    const out = [];
    for (const line of head.split('\n')) {
      if (/^[ \t]/.test(line) && out.length) out[out.length - 1].value += ' ' + line.trim();
      else {
        const m = line.match(/^([!-9;-~]+):\s?(.*)$/);
        if (m) out.push({ name: m[1], lname: m[1].toLowerCase(), value: m[2].trim() });
      }
    }
    return out;
  }

  function addrOf(v) {
    const m = String(v || '').match(/<([^<>@\s]+@[^<>\s]+)>/) || String(v || '').match(/([^\s<>"']+@[^\s<>"',;]+)/);
    return m ? m[1].toLowerCase().replace(/[>.]+$/, '') : '';
  }
  function nameOf(v) {
    const s = String(v || '');
    const i = s.indexOf('<');
    return (i > 0 ? s.slice(0, i) : '').replace(/^["'\s]+|["'\s]+$/g, '').trim();
  }
  function domOf(addr) { return (addr.split('@')[1] || '').toLowerCase(); }
  function reg(d) { const A = root.VSAnalyzer; return A ? A.registrableDomain(d) : d.split('.').slice(-2).join('.'); }
  function sameOrg(a, b) { return !!a && !!b && reg(a) === reg(b); }

  function parseReceived(v) {
    const semi = v.lastIndexOf(';');
    const date = semi >= 0 ? Date.parse(v.slice(semi + 1).trim().replace(/\s*\(.*\)$/, '')) : NaN;
    const body = semi >= 0 ? v.slice(0, semi) : v;
    const from = (body.match(/\bfrom\s+([^\s(;]+)/i) || [])[1] || '';
    const by = (body.match(/\bby\s+([^\s(;]+)/i) || [])[1] || '';
    const withP = (body.match(/\bwith\s+([^\s(;]+)/i) || [])[1] || '';
    const ips = [];
    const re = /\[?((?:\d{1,3}\.){3}\d{1,3})\]?|\[(?:IPv6:)?([0-9a-f:]{3,})\]/gi;
    const fromPart = body.split(/\bby\s/i)[0];
    let m;
    while ((m = re.exec(fromPart))) ips.push((m[1] || m[2]).toLowerCase());
    return { from, by, with: withP, ip: ips[0] || '', date: isNaN(date) ? null : date, raw: v };
  }

  function authResults(headers) {
    const res = { spf: '', dkim: '', dmarc: '', compauth: '', dkimDomain: '', spfDomain: '', dmarcFrom: '' };
    const vals = headers.filter((h) => h.lname === 'authentication-results' || h.lname === 'arc-authentication-results').map((h) => h.value);
    for (const v of vals) {
      const get = (k) => (v.match(new RegExp('\\b' + k + '=([a-z]+)', 'i')) || [])[1];
      res.spf = res.spf || (get('spf') || '').toLowerCase();
      res.dkim = res.dkim || (get('dkim') || '').toLowerCase();
      res.dmarc = res.dmarc || (get('dmarc') || '').toLowerCase();
      res.compauth = res.compauth || (get('compauth') || '').toLowerCase();
      res.dkimDomain = res.dkimDomain || ((v.match(/header\.d=([^\s;]+)/i) || [])[1] || '').toLowerCase();
      res.spfDomain = res.spfDomain || ((v.match(/smtp\.mailfrom=([^\s;]+)/i) || [])[1] || '').toLowerCase().replace(/^.*@/, '');
      res.dmarcFrom = res.dmarcFrom || ((v.match(/header\.from=([^\s;]+)/i) || [])[1] || '').toLowerCase();
    }
    const rspf = headers.find((h) => h.lname === 'received-spf');
    if (!res.spf && rspf) res.spf = (rspf.value.match(/^([a-z]+)/i) || [])[1].toLowerCase();
    const sig = headers.find((h) => h.lname === 'dkim-signature');
    if (!res.dkimDomain && sig) res.dkimDomain = ((sig.value.match(/\bd=([^\s;]+)/i) || [])[1] || '').toLowerCase();
    return res;
  }

  function analyze(raw) {
    const H = unfold(raw);
    const one = (n) => (H.find((h) => h.lname === n) || {}).value || '';
    const I = root.VSIoc;
    const A = root.VSAnalyzer;
    const reasons = [];
    let score = 0;
    const add = (pts, t, kind) => { score += pts; reasons.push({ t, kind: kind || (pts > 0 ? 'bad' : pts < 0 ? 'good' : 'info') }); };

    if (!H.length) return { ok: false, error: 'No headers found. Paste the full header block (Outlook: File > Properties; Gmail: Show original).' };

    const from = one('from'), fromAddr = addrOf(from), fromDom = domOf(fromAddr), display = nameOf(from);
    const replyTo = addrOf(one('reply-to')), returnPath = addrOf(one('return-path'));
    const msgId = one('message-id'), msgIdDom = ((msgId.match(/@([^>\s]+)/) || [])[1] || '').toLowerCase();
    const auth = authResults(H);

    // Authentication
    if (auth.spf === 'pass') add(-5, 'SPF pass'); else if (auth.spf === 'fail') add(25, 'SPF fail: sending server not allowed for the envelope domain');
    else if (auth.spf === 'softfail') add(12, 'SPF softfail'); else if (auth.spf) add(4, `SPF ${auth.spf}`);
    if (auth.dkim === 'pass') add(-5, `DKIM pass${auth.dkimDomain ? ' (d=' + auth.dkimDomain + ')' : ''}`); else if (auth.dkim === 'fail') add(20, 'DKIM fail: message altered or forged signature');
    else if (auth.dkim === 'none' || (!auth.dkim && !auth.dkimDomain)) add(6, 'No DKIM signature');
    if (auth.dmarc === 'pass') add(-15, 'DMARC pass: From domain is authenticated'); else if (auth.dmarc === 'fail') add(30, 'DMARC fail: From domain is not authenticated (spoofing pattern)');
    else if (auth.dmarc) add(5, `DMARC ${auth.dmarc}`);
    if (auth.compauth === 'fail') add(15, 'Microsoft composite authentication failed');
    if (!auth.spf && !auth.dkim && !auth.dmarc) add(0, 'No Authentication-Results header (internal mail, or headers trimmed)', 'info');
    if (auth.dkimDomain && fromDom && auth.dkim === 'pass' && !sameOrg(auth.dkimDomain, fromDom)) add(6, `DKIM signed by ${auth.dkimDomain}, not by the From domain ${fromDom} (third-party sender)`, 'info');

    // Sender mismatches
    if (replyTo && fromDom && !sameOrg(domOf(replyTo), fromDom)) add(25, `Reply-To (${replyTo}) goes to a different domain than From (${fromDom}): classic BEC pattern`);
    if (returnPath && fromDom && !sameOrg(domOf(returnPath), fromDom)) add(auth.dmarc === 'pass' ? 0 : 8, `Envelope sender ${returnPath} differs from From domain`, auth.dmarc === 'pass' ? 'info' : 'bad');
    const dispAddr = (display.match(/[^\s<>"']+@[^\s<>"']+/) || [])[0];
    if (dispAddr && dispAddr.toLowerCase() !== fromAddr) add(25, `Display name shows another address (${dispAddr}) than the real sender (${fromAddr})`);
    if (A && display && fromDom) {
      const low = display.toLowerCase();
      for (const b of A.BRANDS) {
        if (b.keywords.some((k) => k.length > 3 && low.includes(k)) && !A.hostInList(fromDom, b.domains)) {
          add(25, `Display name says "${display}" (${b.name}) but the sender domain is ${fromDom}`); break;
        }
      }
      const lv = A.analyzeUrl('https://' + fromDom + '/', {});
      if (!lv.allow && lv.level !== 'safe') add(Math.min(30, lv.score), `Sender domain ${fromDom}: ${lv.reasons.slice(0, 2).join('; ')}`);
    }
    if (msgIdDom && fromDom && !sameOrg(msgIdDom, fromDom) && !/(outlook|google|gmail|amazonses|sendgrid|mailgun|protection)/.test(msgIdDom))
      add(3, `Message-ID created by ${msgIdDom}`, 'info');

    // Spam verdicts from the receiving gateway
    const scl = (one('x-ms-exchange-organization-scl') || (one('x-forefront-antispam-report').match(/SCL:(-?\d)/) || [])[1] || '').toString().trim();
    if (scl !== '' && Number(scl) >= 5) add(10, `Microsoft spam confidence level ${scl} (spam)`);
    if (/SFV:SPM|SFV:BLK/i.test(one('x-forefront-antispam-report'))) add(10, 'Microsoft filter verdict: spam');
    if (/^yes/i.test(one('x-spam-flag')) || /^yes/i.test(one('x-spam-status'))) add(10, 'Gateway marked it as spam');

    // Delivery path (oldest first)
    const hops = H.filter((h) => h.lname === 'received').map((h) => parseReceived(h.value)).reverse();
    hops.forEach((h, i) => { h.delay = i && h.date && hops[i - 1].date ? Math.round((h.date - hops[i - 1].date) / 1000) : null; });
    const pub = (ip) => ip && I && !I.isPrivateIp(ip);
    const origin = one('x-originating-ip').replace(/[[\]]/g, '') || (hops.find((h) => pub(h.ip)) || {}).ip || '';
    const slow = hops.filter((h) => h.delay != null && h.delay > 3600);
    if (slow.length) add(0, `Slow hop: ${Math.round(slow[0].delay / 60)} min at ${slow[0].by || 'a relay'}`, 'info');
    if (hops.some((h) => h.delay != null && h.delay < -300)) add(3, 'Hop timestamps go backwards (forged Received headers or clock skew)', 'info');

    const mailer = one('x-mailer') || one('user-agent');
    if (mailer && /(phpmailer|swiftmailer|python|curl|massmail|sendblaster|atomic)/i.test(mailer)) add(10, `Sent with a bulk / script mailer (${mailer})`);

    const verdict = score >= 45 ? 'malicious' : score >= 18 ? 'suspicious' : score <= -15 ? 'benign' : 'unknown';
    const iocs = [];
    const push = (type, value, why) => { if (value && !iocs.some((x) => x.value === value)) iocs.push({ type, value, why }); };
    if (origin) push(origin.includes(':') ? 'ipv6' : 'ipv4', origin, 'Originating IP');
    hops.filter((h) => pub(h.ip)).forEach((h) => push(h.ip.includes(':') ? 'ipv6' : 'ipv4', h.ip, 'Relay ' + (h.from || '')));
    if (fromDom) push('domain', fromDom, 'From domain');
    if (replyTo) push('email', replyTo, 'Reply-To');
    if (returnPath && domOf(returnPath) !== fromDom) push('domain', domOf(returnPath), 'Envelope sender domain');

    return {
      ok: true, verdict, score, reasons,
      summary: { from, fromAddr, display, replyTo, returnPath, to: one('to'), subject: one('subject'), date: one('date'), messageId: msgId, mailer },
      auth, hops, origin, iocs
    };
  }

  const api = { analyze, unfold, parseReceived };
  root.VSHeaders = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
