// url-normalizer.js: reads web addresses safely.
//
// Every other check works on what parseUrl() returns, never on the raw text,
// because scammers write addresses in strange ways on purpose:
//   HTTPS://WWW.PayPal.COM./x            capitals and a dot at the end
//   https://www.paypal.com@evil.example   the real website is evil.example
//   http://3232235777                     a number address written as one big number
//   https://pay%70al.example              letters written as codes
// We use the browser's own address reader (URL), so we see each address
// exactly the way the browser will when it opens it.
//
// Never decide who owns an address with a simple "contains" check:
// "paypal.com.fake-domain.example" contains "paypal.com" but belongs to
// fake-domain.example. Use isSameOrSubdomain() and registrableDomain().

(function () {
  'use strict';
  const core = globalThis.GranblockCore = globalThis.GranblockCore || {};

  // Website endings with more than one part, where everything just in front
  // belongs to a different owner: "bbc.co.uk" and "evil.co.uk" are unrelated.
  // This is a hand-picked part of the Public Suffix List (publicsuffix.org),
  // covering common countries and the free hosting sites scammers use most.
  // If a check gets a country or host wrong, add its ending here.
  const COUNTRY_ENDINGS = [
    'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'ac.uk', 'gov.uk', 'nhs.uk', 'police.uk', 'sch.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'asn.au', 'id.au',
    'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz',
    'co.za', 'org.za', 'gov.za', 'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in',
    'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp', 'co.kr', 'or.kr', 'go.kr',
    'com.br', 'net.br', 'org.br', 'gov.br', 'com.mx', 'org.mx', 'gob.mx', 'com.ar', 'gob.ar', 'com.co', 'com.pe',
    'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'com.hk', 'com.tw', 'com.sg', 'gov.sg', 'edu.sg', 'com.my', 'com.ph',
    'co.id', 'or.id', 'go.id', 'ac.id', 'co.th', 'go.th', 'in.th', 'com.vn', 'gov.vn',
    'com.tr', 'gov.tr', 'co.il', 'org.il', 'gov.il', 'com.sa', 'com.eg', 'com.ng', 'gov.ng', 'com.pk', 'co.ke', 'com.ua', 'gov.ua',
  ];

  // Free hosting: anyone can make a website under these in minutes, so
  // scammers do. A real bank never has its sign-in page on one.
  const FREE_HOSTING = new Set([
    'github.io', 'gitlab.io', 'blogspot.com', 'wordpress.com', 'wixsite.com', 'weebly.com', 'square.site',
    'netlify.app', 'vercel.app', 'herokuapp.com', 'pages.dev', 'workers.dev', 'web.app', 'firebaseapp.com',
    'appspot.com', 'azurewebsites.net', 'cloudfront.net', 's3.amazonaws.com', 'glitch.me', 'ngrok.io',
    'ngrok-free.app', 'onrender.com', 'fly.dev', 'surge.sh', '000webhostapp.com', 'duckdns.org',
    'myshopify.com', 'webflow.io', 'godaddysites.com', 'carrd.co', 'notion.site',
  ]);

  const MULTI_PART_ENDINGS = new Set([...COUNTRY_ENDINGS, ...FREE_HOSTING]);

  // Well-known services that pass you through to another website, with the
  // real destination written in the link: https://www.google.com/url?q=REAL_LINK
  // Only these are followed. Each "host" check must match the service's OWN
  // website exactly: "google.evil.example" is not Google.
  // We never open a link to find out where it goes (see url-rules.js).
  const REDIRECTORS = [
    { host: h => /^(www\.)?google\./.test(h) && registrableDomain(h) === `google.${publicSuffix(h)}` && !FREE_HOSTING.has(publicSuffix(h)), path: /^\/url$/, params: ['q', 'url'] },
    { host: h => /(^|\.)safelinks\.protection\.outlook\.com$/.test(h), path: /^\/$/, params: ['url'] },
    { host: h => h === 'l.facebook.com' || h === 'l.messenger.com', path: /^\/l\.php$/, params: ['u'] },
    { host: h => h === 'l.instagram.com', path: /^\/$/, params: ['u'] },
    { host: h => h === 'www.youtube.com' || h === 'youtube.com', path: /^\/redirect$/, params: ['q'] },
    { host: h => h === 'slack-redir.net', path: /^\/link$/, params: ['url'] },
    // Google ad clicks, when the ad's destination is written in the link.
    { host: h => h === 'www.googleadservices.com' || h === 'googleadservices.com', path: /^\/pagead\/aclk$/, params: ['adurl'] },
    { host: h => /^(googleads\.g|adclick\.g)\.doubleclick\.net$/.test(h), path: /^\/(pagead\/)?aclk$/, params: ['adurl'] },
  ];

  const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

  // Reads an address. Returns { ok: false, reason } if it can't be read.
  //   hostname   lower case, no dot at the end, "www." kept
  //   host       hostname without "www." (what we show and compare)
  //   isWeb      http or https
  //   isIp       a number address instead of a name
  //   username   anything written before an "@" in the address
  //   password   anything after a ":" in that part
  function parseUrl(raw, base) {
    if (typeof raw !== 'string' || !raw.trim()) return { ok: false, reason: 'empty' };
    let url;
    try {
      url = base ? new URL(raw.trim(), base) : new URL(raw.trim());
    } catch (e) {
      return { ok: false, reason: 'invalid' };
    }
    const isWeb = url.protocol === 'http:' || url.protocol === 'https:';
    const hostname = url.hostname.toLowerCase().replace(/\.+$/, '');
    let pathname = url.pathname;
    try { pathname = decodeURIComponent(url.pathname); } catch (e) { /* keep it encoded */ }
    return {
      ok: true,
      href: url.href,
      protocol: url.protocol,
      isWeb,
      hostname,
      host: hostname.replace(/^www\./, ''),
      isIp: IPV4.test(hostname) || hostname.startsWith('['),
      username: decodeSafely(url.username),
      password: decodeSafely(url.password),
      pathname,
      searchParams: url.searchParams,
    };
  }

  function decodeSafely(text) {
    try { return decodeURIComponent(text); } catch (e) { return text; }
  }

  // Follows pass-through links to where they really go (up to 3 steps).
  function unwrapRedirect(parsed, depth = 0) {
    if (!parsed.ok || !parsed.isWeb || depth >= 3) return parsed;
    for (const r of REDIRECTORS) {
      if (!r.host(parsed.hostname) || !r.path.test(parsed.pathname)) continue;
      for (const name of r.params) {
        const inner = parsed.searchParams.get(name);
        const next = inner ? parseUrl(inner) : null;
        if (next && next.ok && next.isWeb) return unwrapRedirect(next, depth + 1);
      }
    }
    return parsed;
  }

  // Reads an address and follows pass-through links. Use this for every link.
  function normalizeUrl(raw, base) {
    return unwrapRedirect(parseUrl(raw, base));
  }

  // Other web addresses written inside a link, like ?next=https://... (up to 3).
  // A website that isn't a known pass-through service MAY send you on to them,
  // or may not: never treat them as the real destination, only as extra places
  // to check.
  function embeddedUrls(parsed) {
    if (!parsed.ok || !parsed.isWeb) return [];
    const found = [];
    for (const value of parsed.searchParams.values()) {
      if (found.length >= 3) break;
      if (!/^https?:\/\//i.test(value.trim())) continue;
      const inner = parseUrl(value);
      if (inner.ok && inner.isWeb) found.push(inner);
    }
    return found;
  }

  // Is this website on a free hosting service?
  function isFreeHosting(hostname) {
    return FREE_HOSTING.has(publicSuffix((hostname || '').toLowerCase()));
  }

  // The website ending: "com", "co.uk", or "github.io".
  function publicSuffix(hostname) {
    const labels = hostname.split('.');
    for (let i = 1; i < labels.length; i++) {
      const candidate = labels.slice(i).join('.');
      if (MULTI_PART_ENDINGS.has(candidate)) return candidate;
    }
    return labels[labels.length - 1];
  }

  // The part of an address one owner controls:
  //   "login.secure.paypal.com"         -> "paypal.com"
  //   "news.bbc.co.uk"                  -> "bbc.co.uk"
  //   "paypal.com.fake-domain.example"  -> "fake-domain.example"
  //   "someone.github.io"               -> "someone.github.io"
  function registrableDomain(hostname) {
    const host = (hostname || '').toLowerCase().replace(/\.+$/, '');
    if (!host || IPV4.test(host) || host.startsWith('[')) return host;
    const suffix = publicSuffix(host);
    if (host === suffix) return host;
    const front = host.slice(0, -(suffix.length + 1)).split('.');
    return `${front[front.length - 1]}.${suffix}`;
  }

  // Is this address that website, or a part of it? Exact comparison only.
  //   ("www.paypal.com", "paypal.com")                  -> true
  //   ("paypal.com.fake-domain.example", "paypal.com")  -> false
  //   ("notpaypal.com", "paypal.com")                   -> false
  function isSameOrSubdomain(hostname, domain) {
    const host = (hostname || '').toLowerCase().replace(/\.+$/, '');
    const d = (domain || '').toLowerCase();
    return !!d && (host === d || host.endsWith('.' + d));
  }

  // Do two addresses belong to the same owner?
  function sameSite(hostA, hostB) {
    return !!hostA && !!hostB && registrableDomain(hostA) === registrableDomain(hostB);
  }

  // Finds a website name written in text, like a link that SAYS "www.chase.com".
  // Email addresses don't count. Returns '' if there isn't one.
  function findDomainInText(text) {
    const withoutEmails = (text || '').replace(/\S+@\S+/g, '');
    const match = withoutEmails.match(/\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b/i);
    if (!match) return '';
    const parsed = parseUrl('http://' + match[1]);
    return parsed.ok ? parsed.host : '';
  }

  // ---------- letters from other alphabets ----------
  // "pаypal.com" with a Cyrillic "а" looks identical to "paypal.com".
  // Browsers store it as "xn--pypal-4ve.com" (Punycode). toLookalikeAscii()
  // turns it back and replaces look-alike letters with the plain ones.

  const CONFUSABLES = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd',
    'һ': 'h', 'ӏ': 'l', 'ո': 'n', 'ս': 'u',
    'α': 'a', 'ο': 'o', 'ν': 'v', 'ρ': 'p', 'ι': 'i', 'κ': 'k', 'τ': 't', 'υ': 'u', 'ε': 'e',
    'ı': 'i', 'ł': 'l', 'ø': 'o', 'ß': 'ss',
  };

  // Decodes one Punycode label ("pypal-4ve" -> "pаypal"). RFC 3492.
  function punycodeDecode(input) {
    const BASE = 36, T_MIN = 1, T_MAX = 26, SKEW = 38, DAMP = 700;
    const adapt = (delta, numPoints, firstTime) => {
      delta = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
      delta += Math.floor(delta / numPoints);
      let k = 0;
      while (delta > ((BASE - T_MIN) * T_MAX) >> 1) {
        delta = Math.floor(delta / (BASE - T_MIN));
        k += BASE;
      }
      return k + Math.floor(((BASE - T_MIN + 1) * delta) / (delta + SKEW));
    };
    const digitOf = c => (c >= 48 && c <= 57 ? c - 22 : c >= 65 && c <= 90 ? c - 65 : c >= 97 && c <= 122 ? c - 97 : BASE);

    const output = [];
    const basic = Math.max(input.lastIndexOf('-'), 0);
    for (let j = 0; j < basic; j++) output.push(input.charCodeAt(j));
    let n = 128, bias = 72, i = 0;
    for (let index = basic > 0 ? basic + 1 : 0; index < input.length;) {
      const oldi = i;
      let w = 1;
      for (let k = BASE; ; k += BASE) {
        if (index >= input.length) throw new Error('bad punycode');
        const digit = digitOf(input.charCodeAt(index++));
        if (digit >= BASE) throw new Error('bad punycode');
        i += digit * w;
        const t = k <= bias ? T_MIN : k >= bias + T_MAX ? T_MAX : k - bias;
        if (digit < t) break;
        w *= BASE - t;
      }
      const length = output.length + 1;
      bias = adapt(i - oldi, length, oldi === 0);
      n += Math.floor(i / length);
      i %= length;
      output.splice(i++, 0, n);
    }
    return String.fromCodePoint(...output);
  }

  // "xn--pypal-4ve.com" -> "pаypal.com" (with the Cyrillic letter).
  function toUnicodeHost(hostname) {
    return hostname.split('.').map(label => {
      if (!label.startsWith('xn--')) return label;
      try { return punycodeDecode(label.slice(4)); } catch (e) { return label; }
    }).join('.');
  }

  // "xn--pypal-4ve.com" -> "paypal.com" (plain letters). '' if nothing changed.
  function toLookalikeAscii(hostname) {
    if (!/(^|\.)xn--/.test(hostname)) return '';
    const plain = [...toUnicodeHost(hostname).normalize('NFD').replace(/[̀-ͯ]/g, '')]
      .map(ch => CONFUSABLES[ch] || ch).join('');
    return plain !== hostname && /^[a-z0-9.-]+$/.test(plain) ? plain : '';
  }

  core.urlNormalizer = {
    parseUrl, normalizeUrl, unwrapRedirect, embeddedUrls, isFreeHosting, publicSuffix, registrableDomain, isSameOrSubdomain, sameSite,
    findDomainInText, punycodeDecode, toUnicodeHost, toLookalikeAscii,
  };
  if (typeof module !== 'undefined') module.exports = core.urlNormalizer;
})();
