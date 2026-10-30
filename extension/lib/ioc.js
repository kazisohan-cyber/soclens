/*
 * IOC Triage IOC toolkit: find indicators in text (fanged or defanged), refang/defang them,
 * classify a single value, and tell private from public IPs.
 * Pure functions (no chrome.*): shared by the service worker, the analyst panel, the page
 * highlighter and the test page.
 */
(function (root) {
  'use strict';

  // Defang tokens analysts use: [.] (.) {.} [dot] (dot) and hxxp / [:]
  const DOT = '(?:\\.|\\[\\.\\]|\\(\\.\\)|\\{\\.\\}|\\[dot\\]|\\(dot\\))';
  const LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
  const TLD = '(?:[a-z]{2,24}|xn--[a-z0-9-]{2,59})';
  const OCTET = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';

  const RE = {
    url: new RegExp('(?:https?|hxxps?|fxp|ftp)(?::\\/\\/|\\[:\\]\\/\\/|\\[:\\/\\/\\])[^\\s"\'<>`]+', 'gi'),
    email: new RegExp('[a-z0-9._%+-]+(?:@|\\[@\\]|\\(@\\)|\\[at\\])(?:' + LABEL + DOT + ')+' + TLD + '(?![a-z0-9-])', 'gi'),
    ipv4: new RegExp('(?<![\\d.])' + OCTET + '(?:' + DOT + OCTET + '){3}(?:\\/(?:3[0-2]|[12]?\\d))?(?![\\d]|\\.\\d)', 'g'),
    ipv6: /(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])/gi,
    sha256: /(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])/gi,
    sha1: /(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])/gi,
    md5: /(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])/gi,
    cve: /\bCVE-\d{4}-\d{4,7}\b/gi,
    domain: new RegExp('(?<![a-z0-9@._-])(?:' + LABEL + DOT + ')+' + TLD + '(?![a-z0-9-]|' + DOT + '[a-z0-9])', 'gi')
  };
  const ORDER = ['url', 'email', 'ipv4', 'ipv6', 'sha256', 'sha1', 'md5', 'cve', 'domain'];

  // In "strict" mode (auto-highlighting pages) these look like file names or code, not domains.
  const FILE_LIKE = new Set(['js', 'ts', 'css', 'html', 'htm', 'php', 'asp', 'aspx', 'jsp', 'json', 'xml', 'yml', 'yaml',
    'txt', 'log', 'csv', 'md', 'py', 'rb', 'pl', 'sh', 'ps', 'ps1', 'psm1', 'bat', 'cmd', 'vbs', 'exe', 'dll', 'sys', 'msi',
    'bin', 'dat', 'tmp', 'ini', 'cfg', 'conf', 'lnk', 'jpg', 'jpeg', 'png', 'gif', 'svg', 'ico', 'bmp', 'webp', 'pdf', 'doc',
    'docx', 'xls', 'xlsx', 'xlsm', 'ppt', 'pptx', 'rtf', 'odt', 'zip', 'rar', '7z', 'gz', 'tar', 'tgz', 'iso', 'img', 'vhd',
    'vhdx', 'mov', 'mp3', 'mp4', 'avi', 'wav', 'java', 'class', 'jar', 'cs', 'go', 'rs', 'cpp', 'hpp', 'lua', 'sql', 'db',
    'sqlite', 'bak', 'old', 'eml', 'msg', 'pst', 'ost', 'evtx', 'pcap', 'pcapng', 'local', 'internal', 'lan', 'corp', 'home',
    'localdomain', 'arpa', 'example', 'invalid', 'test', 'name', 'map', 'min', 'prototype', 'length', 'value', 'id', 'to']);
  // ...unless the "file name" is clearly a host (www., several labels, common SaaS words).
  const COMMON_TLD = new Set(['com', 'net', 'org', 'io', 'co', 'ai', 'app', 'dev', 'info', 'biz', 'xyz', 'top', 'online',
    'site', 'shop', 'store', 'club', 'live', 'click', 'link', 'cloud', 'tech', 'pro', 'me', 'us', 'uk', 'my', 'sg', 'au',
    'in', 'id', 'hk', 'jp', 'de', 'fr', 'ru', 'cn', 'br', 'nl', 'eu', 'gov', 'edu', 'mil', 'int', 'sbs', 'icu', 'cfd',
    'buzz', 'work', 'support', 'help', 'services', 'digital', 'email', 'run', 'page', 'website', 'space', 'fun', 'cc', 'tk',
    'ml', 'ga', 'cf', 'gq', 'ws', 'tv', 'gg', 'ly', 'su', 'kr', 'tw', 'th', 'vn', 'ph', 'nz', 'ca', 'mx', 'es', 'it',
    'pl', 'ch', 'se', 'no', 'fi', 'dk', 'be', 'at', 'cz', 'tr', 'ir', 'ua', 'za', 'ng', 'ke', 'ae', 'sa', 'pk', 'bd']);

  // Every top-level domain in the IANA root zone (version 2026102000, data.iana.org/TLD/tlds-alpha-by-domain.txt).
  // "data.scope" is not a domain because .scope is not a TLD.
  const IANA_TLDS = new Set((
    'aaa aarp abb abbott abbvie abc able abogado abudhabi ac academy accenture accountant accountants aco actor ad ' +
    'ads adult ae aeg aero aetna af afl africa ag agakhan agency ai aig airbus airforce airtel akdn al alibaba ' +
    'alipay allfinanz allstate ally alsace alstom am amazon americanexpress americanfamily amex amfam amica ' +
    'amsterdam analytics android anquan anz ao aol apartments app apple aq aquarelle ar arab aramco archi army arpa ' +
    'art arte as asda asia associates at athleta attorney au auction audi audible audio auspost author auto autos ' +
    'aw aws ax axa az azure ba baby baidu banamex band bank bar barcelona barclaycard barclays barefoot bargains ' +
    'baseball basketball bauhaus bayern bb bbc bbt bbva bcg bcn bd be beats beauty beer berlin best bestbuy bet bf ' +
    'bg bh bharti bi bible bid bike bing bingo bio biz bj black blackfriday blockbuster blog bloomberg blue bm bms ' +
    'bmw bn bnpparibas bo boats boehringer bofa bom bond boo book booking bosch bostik boston bot boutique box br ' +
    'bradesco bridgestone broadway broker brother brussels bs bt build builders business buy buzz bv bw by bz bzh ' +
    'ca cab cafe cal call calvinklein cam camera camp canon capetown capital capitalone car caravan cards care ' +
    'career careers cars casa case cash casino cat catering catholic cba cbn cbre cc cd center ceo cern cf cfa cfd ' +
    'cg ch chanel channel charity chase chat cheap chintai christmas chrome church ci cipriani circle cisco citadel ' +
    'citi citic city ck cl claims cleaning click clinic clinique clothing cloud club clubmed cm cn co coach codes ' +
    'coffee college cologne com commbank community company compare computer comsec condos construction consulting ' +
    'contact contractors cooking cool coop corsica country coupon coupons courses cpa cr credit creditcard ' +
    'creditunion cricket crown crs cruise cruises cu cuisinella cv cw cx cy cymru cyou cz dad dance data date ' +
    'dating datsun day dclk dds de deal dealer deals degree delivery dell deloitte delta democrat dental dentist ' +
    'desi design dev dhl diamonds diet digital direct directory discount discover dish diy dj dk dm dnp do docs ' +
    'doctor dog domains dot download drive dtv dubai dupont durban dvag dvr dz earth eat ec eco edeka edu education ' +
    'ee eg email emerck energy engineer engineering enterprises epson equipment er ericsson erni es esq estate et ' +
    'eu eurovision eus events exchange expert exposed express extraspace fage fail fairwinds faith family fan fans ' +
    'farm farmers fashion fast fedex feedback ferrari ferrero fi fidelity fido film final finance financial fire ' +
    'firestone firmdale fish fishing fit fitness fj fk flickr flights flir florist flowers fly fm fo foo food ' +
    'football ford forex forsale forum foundation fox fr free fresenius frl frogans frontier ftr fujitsu fun fund ' +
    'furniture futbol fyi ga gal gallery gallo gallup game games gap garden gay gb gbiz gd gdn ge gea gent genting ' +
    'george gf gg ggee gh gi gift gifts gives giving gl glass gle global globo gm gmail gmbh gmo gmx gn godaddy ' +
    'gold goldpoint golf goodyear goog google gop got gov gp gq gr grainger graphics gratis green gripe grocery ' +
    'group gs gt gu gucci guge guide guitars guru gw gy hair hamburg hangout haus hbo hdfc hdfcbank health ' +
    'healthcare help helsinki here hermes hiphop hisamitsu hitachi hiv hk hkt hm hn hockey holdings holiday ' +
    'homedepot homegoods homes homesense honda horse hospital host hosting hot hotels hotmail house how hr hsbc ht ' +
    'hu hughes hyatt hyundai ibm icbc ice icu id ie ieee ifm ikano il im imamat imdb immo immobilien in inc ' +
    'industries infiniti info ing ink institute insurance insure int international intuit investments io ipiranga ' +
    'iq ir irish is ismaili ist istanbul it itau itv jaguar java jcb je jeep jetzt jewelry jio jll jm jmp jnj jo ' +
    'jobs joburg jot joy jp jpmorgan jprs juegos kaufen kddi ke kerryhotels kerryproperties kfh kg kh ki kia kids ' +
    'kim kindle kitchen kiwi km kn koeln komatsu kosher kp kpmg kpn kr krd kred kuokgroup kw ky kyoto kz la lacaixa ' +
    'lamborghini lamer land landrover lanxess lasalle lat latino latrobe law lawyer lb lc lds lease leclerc lefrak ' +
    'legal lego lexus lgbt li lidl life lifeinsurance lifestyle lighting like lilly limited limo lincoln link live ' +
    'living lk llc llp loan loans locker locus lol london lotte lotto love lpl lplfinancial lr ls lt ltd ltda lu ' +
    'lundbeck luxe luxury lv ly ma madrid maif maison makeup man management mango map market marketing markets ' +
    'marriott marshalls mattel mba mc mckinsey md me med media meet melbourne meme memorial men menu merck merckmsd ' +
    'mg mh miami microsoft mil mini mint mit mitsubishi mk ml mlb mls mm mma mn mo mobi mobile moda moe moi mom ' +
    'monash money monster mormon mortgage moscow moto motorcycles mov movie mp mq mr ms msd mt mtn mtr mu museum ' +
    'music mv mw mx my mz na nab nagoya name navy nba nc ne nec net netbank netflix network neustar new news next ' +
    'nextdirect nexus nf nfl ng ngo nhk ni nico nike nikon ninja nissan nissay nl no nokia norton now nowruz nowtv ' +
    'np nr nra nrw ntt nu nyc nz obi observer office okinawa olayan olayangroup ollo om omega one ong onl online ' +
    'ooo open oracle orange org organic origins osaka otsuka ott ovh pa page panasonic paris pars partners parts ' +
    'party pay pccw pe pet pf pfizer pg ph pharmacy phd philips phone photo photography photos physio pics pictet ' +
    'pictures pid pin ping pink pioneer pizza pk pl place play playstation plumbing plus pm pn pnc pohl poker ' +
    'politie porn post pr praxi press prime pro prod productions prof progressive promo properties property ' +
    'protection pru prudential ps pt pub pw pwc py qa qpon quebec quest racing radio re read realestate realtor ' +
    'realty recipes red redumbrella rehab reise reisen reit reliance ren rent rentals repair report republican rest ' +
    'restaurant review reviews rexroth rich richardli ricoh ril rio rip ro rocks rodeo rogers room rs rsvp ru rugby ' +
    'ruhr run rw rwe ryukyu sa saarland safe safety sakura sale salon samsclub samsung sandvik sandvikcoromant ' +
    'sanofi sap sarl sas save saxo sb sbi sbs sc scb schaeffler schmidt scholarships school schule schwarz science ' +
    'scot sd se search seat secure security seek select sener services seven sew sex sexy sfr sg sh shangrila sharp ' +
    'shell shia shiksha shoes shop shopping shouji show si silk sina singles site sj sk ski skin sky skype sl sling ' +
    'sm smart smile sn sncf so soccer social softbank software sohu solar solutions song sony soy spa space sport ' +
    'spot sr srl ss st stada staples star statebank statefarm stc stcgroup stockholm storage store stream studio ' +
    'study style su sucks supplies supply support surf surgery suzuki sv swatch swiss sx sy sydney systems sz tab ' +
    'taipei talk taobao target tatamotors tatar tattoo tax taxi tc tci td tdk team tech technology tel temasek ' +
    'tennis teva tf tg th thd theater theatre tiaa tickets tienda tips tires tirol tj tjmaxx tjx tk tkmaxx tl tm ' +
    'tmall tn to today tokyo tools top toray toshiba total tours town toyota toys tr trade trading training travel ' +
    'travelers travelersinsurance trust trv tt tube tui tunes tushu tv tvs tw tz ua ubank ubs ug uk unicom ' +
    'university uno uol ups us uy uz va vacations vana vanguard vc ve vegas ventures verisign versicherung vet vg ' +
    'vi viajes video vig viking villas vin vip virgin visa vision viva vivo vlaanderen vn vodka volvo vote voting ' +
    'voto voyage vu wales walmart walter wang wanggou watch watches weather weatherchannel web webcam weber website ' +
    'wed wedding weibo weir wf whoswho wien wiki williamhill win windows wine winners wme woodside work works world ' +
    'wow ws wtc wtf xbox xerox xihuan xin xn--11b4c3d xn--1ck2e1b xn--1qqw23a xn--2scrj9c xn--30rr7y xn--3bst00m ' +
    'xn--3ds443g xn--3e0b707e xn--3hcrj9c xn--3pxu8k xn--42c2d9a xn--45br5cyl xn--45brj9c xn--45q11c xn--4dbrk0ce ' +
    'xn--4gbrim xn--54b7fta0cc xn--55qw42g xn--55qx5d xn--5su34j936bgsg xn--5tzm5g xn--6frz82g xn--6qq986b3xl ' +
    'xn--80adxhks xn--80ao21a xn--80aqecdr1a xn--80asehdb xn--80aswg xn--8y0a063a xn--90a3ac xn--90ae xn--90ais ' +
    'xn--9dbq2a xn--9et52u xn--9krt00a xn--b4w605ferd xn--bck1b9a5dre4c xn--c1avg xn--c2br7g xn--cck2b3b ' +
    'xn--cckwcxetd xn--cg4bki xn--clchc0ea0b2g2a9gcd xn--czr694b xn--czrs0t xn--czru2d xn--d1acj3b xn--d1alf ' +
    'xn--e1a4c xn--eckvdtc9d xn--efvy88h xn--fct429k xn--fhbei xn--fiq228c5hs xn--fiq64b xn--fiqs8s xn--fiqz9s ' +
    'xn--fjq720a xn--flw351e xn--fpcrj9c3d xn--fzc2c9e2c xn--fzys8d69uvgm xn--g2xx48c xn--gckr3f0f xn--gecrj9c ' +
    'xn--gk3at1e xn--h2breg3eve xn--h2brj9c xn--h2brj9c8c xn--hxt814e xn--i1b6b1a6a2e xn--imr513n xn--io0a7i ' +
    'xn--j1aef xn--j1amh xn--j6w193g xn--jlq480n2rg xn--jvr189m xn--kcrx77d1x4a xn--kprw13d xn--kpry57d xn--kput3i ' +
    'xn--l1acc xn--lgbbat1ad8j xn--mgb9awbf xn--mgba3a3ejt xn--mgba3a4f16a xn--mgba7c0bbn0a xn--mgbaam7a8h ' +
    'xn--mgbab2bd xn--mgbah1a3hjkrd xn--mgbai9azgqp6j xn--mgbayh7gpa xn--mgbbh1a xn--mgbbh1a71e xn--mgbc0a9azcg ' +
    'xn--mgbca7dzdo xn--mgbcpq6gpa1a xn--mgberp4a5d4ar xn--mgbgu82a xn--mgbi4ecexp xn--mgbpl2fh xn--mgbt3dhd ' +
    'xn--mgbtx2b xn--mgbx4cd0ab xn--mix891f xn--mk1bu44c xn--mxtq1m xn--ngbc5azd xn--ngbe9e0a xn--ngbrx xn--node ' +
    'xn--nqv7f xn--nqv7fs00ema xn--nyqy26a xn--o3cw4h xn--ogbpf8fl xn--otu796d xn--p1acf xn--p1ai xn--pgbs0dh ' +
    'xn--pssy2u xn--q7ce6a xn--q9jyb4c xn--qcka1pmc xn--qxa6a xn--qxam xn--rhqv96g xn--rovu88b xn--rvc1e0am3e ' +
    'xn--s9brj9c xn--ses554g xn--t60b56a xn--tckwe xn--tiq49xqyj xn--unup4y xn--vermgensberater-ctb ' +
    'xn--vermgensberatung-pwb xn--vhquv xn--vuq861b xn--w4r85el8fhu5dnra xn--w4rs40l xn--wgbh1c xn--wgbl6a ' +
    'xn--xhq521b xn--xkc2al3hye2a xn--xkc2dl3a5ee0h xn--y9a3aq xn--yfro4i67o xn--ygbi2ammx xn--zfr164b xxx xyz ' +
    'yachts yahoo yamaxun yandex ye yodobashi yoga yokohama you youtube yt yun za zappos zara zero zip zm zone ' +
    'zuerich zw '
  ).trim().split(' '));

  // Log / JSON field paths look like domains ("data.user.email", "host.name", "src.process.name").
  const FIELD_PREFIX = new Set(['data', 'event', 'events', 'src', 'dst', 'tgt', 'source', 'destination', 'target', 'user', 'users', 'process',
    'parent', 'file', 'agent', 'endpoint', 'network', 'net', 'http', 'dns', 'url', 'host', 'device', 'os', 'cloud', 'observer', 'log', 'threat',
    'alert', 'rule', 'actor', 'client', 'server', 'session', 'request', 'response', 'account', 'identity', 'site', 'group', 'tenant', 'indicator',
    'meta', 'metadata', 'payload', 'record', 'resource', 'object', 'item', 'entity', 'asset', 'policy', 'detection', 'attributes', 'properties']);
  const FIELD_SUFFIX = new Set(['email', 'name', 'id', 'type', 'path', 'user', 'value', 'size', 'status', 'count', 'domain', 'address', 'ip',
    'port', 'time', 'hash', 'sha1', 'sha256', 'md5', 'url', 'uid', 'version', 'code', 'action', 'result', 'category', 'tags', 'info', 'data',
    'app', 'link', 'title', 'host', 'login', 'phone', 'country', 'city', 'region', 'zone', 'mobi', 'one', 'new', 'ltd', 'group', 'site', 'pro',
    'cloud', 'storage', 'agency', 'team', 'network', 'services', 'center', 'company', 'directory', 'events', 'media', 'tools', 'live', 'run']);

  function refang(s) {
    return String(s == null ? '' : s).trim()
      .replace(/^hxxp/i, 'http').replace(/^fxp/i, 'ftp')
      .replace(/\[:\]\/\//g, '://').replace(/\[:\/\/\]/g, '://')
      .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, '.')
      .replace(/\[@\]|\(@\)|\[at\]/gi, '@')
      .replace(/\[:\]/g, ':');
  }

  function defang(value, type) {
    const v = String(value || '');
    if (!v) return v;
    type = type || classify(v).type;
    if (type === 'url') {
      return v.replace(/^http/i, 'hxxp').replace(/^ftp/i, 'fxp').replace(/^(\w+:\/\/)([^/?#]+)/, (m, s, h) => s.replace('://', '[://]') + h.replace(/\./g, '[.]'));
    }
    if (type === 'domain' || type === 'ipv4') return v.replace(/\./g, '[.]');
    if (type === 'ipv6') return v.replace(/:/g, '[:]');
    if (type === 'email') return v.replace('@', '[@]').replace(/\.(?=[^@]*$)/g, '[.]');
    return v;
  }

  function trimUrl(u) {
    // Trailing punctuation from prose / markdown, and unbalanced closing brackets.
    let s = u.replace(/[.,;:!?'"»”’]+$/, '');
    for (const [o, c] of [['(', ')'], ['[', ']'], ['{', '}']]) {
      while (s.endsWith(c) && (s.split(o).length < s.split(c).length)) s = s.slice(0, -1);
    }
    return s.replace(/[.,;:!?]+$/, '');
  }

  function validIpv6(s) {
    if (!s.includes('::') && s.split(':').length !== 8) return false;
    if (/^\d{1,2}:\d{2}(:\d{2})?$/.test(s)) return false;            // clock time
    if (/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(s)) return false;       // MAC address
    if (!/[0-9a-f]/i.test(s.replace(/:/g, '')) && s !== '::') return false;
    try { return new URL('http://[' + s + ']/').hostname.length > 2; } catch (_) { return false; }
  }

  function tldOf(domain) { const p = domain.split('.'); return p[p.length - 1]; }

  /** "data.user.email", "host.name", "site.id": a field prefix + a field-name ending, made of plain words. */
  function looksLikeField(labels) {
    if (labels.length < 2 || labels.length > 5) return false;
    if (!labels.every((l) => /^[a-z]+$/.test(l))) return false; // real hosts often carry digits or hyphens
    return FIELD_PREFIX.has(labels[0]) && FIELD_SUFFIX.has(labels[labels.length - 1]);
  }

  /** Text right after a match: "data.scope=", "event.type: x" or "'site.id':" mean a field key, not a host. */
  function followedByKeySep(text, end) {
    return /^\s*['"]?\s*(?:=(?!=)|:(?!\d|\/\/))/.test(text.slice(end, end + 6));
  }

  function plausibleDomain(d, strict) {
    const labels = d.split('.');
    if (labels.length < 2 || d.length > 253) return false;
    const tld = tldOf(d);
    if (/^\d+$/.test(tld) || !IANA_TLDS.has(tld)) return false;
    if (looksLikeField(labels)) return false;
    if (!strict) return true;
    if (FILE_LIKE.has(tld) && !(labels.length >= 3 && (labels[0] === 'www' || COMMON_TLD.has(labels[labels.length - 2])))) return false;
    // Unknown long TLDs in prose (e.g. "object.property") only when it otherwise looks like a host.
    if (!COMMON_TLD.has(tld) && tld.length > 2 && !tld.startsWith('xn--') && labels.length < 3) return false;
    if (labels.every((l) => /^[a-z]+$/i.test(l)) && labels.length === 2 && labels[0].length <= 2 && !COMMON_TLD.has(tld)) return false;
    return true;
  }

  function isPrivateIp(ip) {
    ip = String(ip || '').split('/')[0];
    if (ip.includes(':')) {
      const s = ip.toLowerCase();
      return s === '::1' || s === '::' || /^f[cd]/.test(s) || /^fe[89ab]/.test(s) || s.startsWith('::ffff:10.') || s.startsWith('::ffff:192.168.');
    }
    const o = ip.split('.').map(Number);
    if (o.length !== 4 || o.some((n) => isNaN(n))) return false;
    return o[0] === 10 || o[0] === 127 || o[0] === 0 || (o[0] === 172 && o[1] >= 16 && o[1] <= 31) || (o[0] === 192 && o[1] === 168)
      || (o[0] === 169 && o[1] === 254) || (o[0] === 100 && o[1] >= 64 && o[1] <= 127) || o[0] >= 224
      || (o[0] === 192 && o[1] === 0 && o[2] === 2) || (o[0] === 198 && o[1] === 51 && o[2] === 100) || (o[0] === 203 && o[1] === 0 && o[2] === 113)
      || (o[0] === 198 && (o[1] === 18 || o[1] === 19));
  }

  const GROUP = { url: 'url', domain: 'domain', ipv4: 'ip', ipv6: 'ip', email: 'email', md5: 'hash', sha1: 'hash', sha256: 'hash', cve: 'cve' };
  const LABEL_OF = { url: 'URL', domain: 'Domain', ipv4: 'IPv4', ipv6: 'IPv6', email: 'Email', md5: 'MD5', sha1: 'SHA-1', sha256: 'SHA-256', cve: 'CVE' };

  function normalize(type, raw) {
    let v = refang(raw);
    if (type === 'url') v = trimUrl(v);
    if (type === 'ipv4') v = v.split('/')[0];
    if (type === 'domain' || type === 'email') v = v.toLowerCase().replace(/\.$/, '');
    if (type === 'md5' || type === 'sha1' || type === 'sha256' || type === 'ipv6') v = v.toLowerCase();
    if (type === 'cve') v = v.toUpperCase();
    return v;
  }

  /**
   * Find IOCs in text. Returns [{ type, group, value, raw, start, end }] in text order,
   * non-overlapping, earlier ORDER types win (a URL hides the domain inside it).
   * opts.strict: page highlighting mode (fewer false positives).
   */
  function extract(text, opts) {
    const strict = !!(opts && opts.strict);
    const max = (opts && opts.max) || 500;
    text = String(text || '');
    const taken = [];
    const out = [];
    const overlaps = (s, e) => taken.some(([a, b]) => s < b && e > a);
    for (const type of ORDER) {
      const re = RE[type];
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text)) && out.length < max) {
        let raw = m[0];
        if (type === 'url') raw = trimUrl(raw);
        const start = m.index, end = m.index + raw.length;
        if (!raw || overlaps(start, end)) continue;
        const value = normalize(type, raw);
        if (type === 'ipv6' && !validIpv6(value)) continue;
        if (type === 'domain' && (!plausibleDomain(value, strict) || followedByKeySep(text, end))) continue;
        if (strict && (type === 'md5' || type === 'sha1' || type === 'sha256') && (/^\d+$/.test(value) || /^[a-f]+$/.test(value))) continue;
        if (type === 'url') { try { new URL(value); } catch (_) { continue; } }
        taken.push([start, end]);
        out.push({ type, group: GROUP[type], value, raw, start, end });
      }
    }
    return out.sort((a, b) => a.start - b.start);
  }

  /** Unique IOCs (by value) from free text, in first-seen order. */
  function unique(text, opts) {
    const seen = new Set();
    return extract(text, opts).filter((x) => !seen.has(x.type + '|' + x.value) && seen.add(x.type + '|' + x.value));
  }

  /** Classify a single typed / pasted value. Returns { type, group, value } (type 'unknown' if none). */
  function classify(input) {
    const s = refang(input);
    if (!s) return { type: 'unknown', group: 'unknown', value: '' };
    const all = extract(s, { strict: false });
    const whole = all.find((x) => x.start === 0 && x.end >= s.replace(/[.,;]+$/, '').length);
    if (whole) return { type: whole.type, group: whole.group, value: whole.value };
    if (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(s)) return { type: 'domain', group: 'domain', value: s.toLowerCase() };
    return { type: 'unknown', group: 'unknown', value: s };
  }

  /** Registrable-ish domain of a URL / email / domain (for domain-level lookups). */
  function domainOf(type, value) {
    if (type === 'url') { try { return new URL(value).hostname.toLowerCase(); } catch (_) { return ''; } }
    if (type === 'email') return value.split('@')[1] || '';
    if (type === 'domain') return value;
    return '';
  }

  function ipInCidr(ip, cidr) {
    if (!ip || !cidr || ip.includes(':') || cidr.includes(':')) return ip === cidr;
    const [net, bitsS] = cidr.split('/');
    const bits = bitsS == null ? 32 : Number(bitsS);
    const toInt = (a) => a.split('.').reduce((n, o) => (n << 8) + Number(o), 0) >>> 0;
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip) || !/^\d+\.\d+\.\d+\.\d+$/.test(net) || !(bits >= 0 && bits <= 32)) return false;
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return (toInt(ip) & mask) === (toInt(net) & mask);
  }

  const api = { extract, unique, classify, refang, defang, isPrivateIp, domainOf, ipInCidr, GROUP, LABEL_OF };
  root.VSIoc = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
