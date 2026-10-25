// safe-browsing.js: Google Safe Browsing (API v5, "hashes:search") for one address.
//
// Privacy: the address is NEVER sent. The address is turned into up to 30 "expressions"
// (the website with fewer and fewer parts of its name, the path with fewer and fewer folders),
// each expression is hashed (SHA-256), and only the FIRST 4 BYTES of each hash go to Google.
// Google answers with every listed address whose hash starts with those bytes, and the match is
// decided here by comparing the full hashes. So Google sees short fingerprints that many unrelated
// addresses share, plus this computer's address and the API key, not which website was visited.
//
// The API key is the person's own (saved on the settings page on this computer only). It is
// never in this code. https://developers.google.com/safe-browsing/reference
//
// No chrome.* calls here, so tests can run it directly. Needs crypto.subtle (service worker, Node 18+).

(function () {
  'use strict';
  const bg = globalThis.GranblockBackground = globalThis.GranblockBackground || {};

  const ENDPOINT = 'https://safebrowsing.googleapis.com/v5/hashes:search';
  const MAX_PREFIXES = 30;
  // Safe Browsing v5 answers in protocol buffers (binary), not JSON. Only the fields we need are read:
  //   SearchHashesResponse { repeated FullHash full_hashes = 1; }
  //   FullHash             { bytes full_hash = 1; repeated FullHashDetail full_hash_details = 2; }
  //   FullHashDetail       { ThreatType threat_type = 1; repeated ThreatAttribute attributes = 2; }
  const THREAT_NAMES = { 1: 'MALWARE', 2: 'SOCIAL_ENGINEERING', 3: 'UNWANTED_SOFTWARE', 4: 'POTENTIALLY_HARMFUL_APPLICATION' };
  // Threats we warn about. (Potentially harmful apps are about phone apps, not websites.)
  const THREAT_TYPES = new Set(['SOCIAL_ENGINEERING', 'MALWARE', 'UNWANTED_SOFTWARE']);
  // Attributes that mean "do not enforce on a whole page": 1 CANARY (a test entry), 2 FRAME_ONLY, 0 unknown.
  const SKIP_ATTRIBUTES = new Set([0, 1, 2]);

  const userFacing = message => Object.assign(new Error(message), { userFacing: true }); // message is shown to the person
  const latin1ToBytes = text => Uint8Array.from(text, c => c.charCodeAt(0));
  const toBase64 = bytes => btoa(String.fromCharCode(...bytes));
  const hex = n => n.toString(16).toUpperCase().padStart(2, '0');

  // Replaces %XX with the byte it stands for (as one character 0-255), over and over until nothing changes.
  function unescapeFully(text) {
    let previous;
    let guard = 0;
    do {
      previous = text;
      text = text.replace(/%([0-9a-fA-F]{2})/g, (m, h) => String.fromCharCode(parseInt(h, 16)));
    } while (text !== previous && ++guard < 20);
    return text;
  }
  // The reverse for the few bytes the specification wants escaped: <= space, >= 127, "#" and "%".
  const escapeBytes = text => text.replace(/[\x00-\x20\x7f-￿#%]/g, c => '%' + hex(c.charCodeAt(0) & 0xff));

  // "Canonical" form of an address, as the Safe Browsing documentation describes it.
  // Returns { host, isIp, path, query } or null for anything that is not a web address.
  function canonicalize(raw) {
    let url;
    try { url = new URL(String(raw).trim().replace(/[\t\r\n]/g, '')); } catch (e) { return null; }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    // The WHATWG parser already lower-cases the name, turns number addresses into dotted decimal,
    // removes default ports and resolves "." and ".." in the path.
    let host = url.hostname.replace(/^\.+|\.+$/g, '').replace(/\.{2,}/g, '.');
    if (!host) return null;
    const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':');
    const path = escapeBytes(unescapeFully(url.pathname).replace(/\/{2,}/g, '/')) || '/';
    const query = url.search.length > 1 ? escapeBytes(unescapeFully(url.search.slice(1))) : null;
    return { host, isIp, path, query };
  }

  // Every "host/path" expression to look up, at most 30, exact address first.
  function expressions(canonical) {
    const { host, isIp, path, query } = canonical;
    const hosts = [host];
    if (!isIp) {
      const parts = host.split('.');
      for (let i = Math.max(1, parts.length - 5); i < parts.length - 1; i++) hosts.push(parts.slice(i).join('.'));
    }
    const paths = [];
    if (query !== null) paths.push(`${path}?${query}`);
    paths.push(path);
    const folders = path.split('/').slice(0, -1); // "/a/b/c.html" -> ["", "a", "b"]
    let prefix = '';
    for (let i = 0; i < folders.length && i < 4; i++) {
      prefix += `${folders[i]}/`;
      if (prefix !== path) paths.push(prefix);
    }
    const out = [];
    for (const h of [...new Set(hosts)]) for (const p of [...new Set(paths)]) out.push(`${h}${p}`);
    return out.slice(0, MAX_PREFIXES);
  }

  // Minimal protobuf reader: calls onField(fieldNumber, wireType, value) for each field.
  // value is a number (varint) or a Uint8Array (length-delimited). Throws on anything malformed.
  function readFields(bytes, onField) {
    let i = 0;
    const varint = () => {
      let result = 0;
      for (let shift = 0; shift < 35; shift += 7) {
        if (i >= bytes.length) throw new Error('unreadable answer');
        const b = bytes[i++];
        result += (b & 0x7f) * 2 ** shift;
        if (!(b & 0x80)) return result;
      }
      throw new Error('unreadable answer');
    };
    while (i < bytes.length) {
      const tag = varint();
      const field = Math.floor(tag / 8);
      const wire = tag % 8;
      if (wire === 0) onField(field, wire, varint());
      else if (wire === 2) {
        const length = varint();
        if (i + length > bytes.length) throw new Error('unreadable answer');
        onField(field, wire, bytes.subarray(i, i + length));
        i += length;
      } else if (wire === 1) { if (i + 8 > bytes.length) throw new Error('unreadable answer'); i += 8; }
      else if (wire === 5) { if (i + 4 > bytes.length) throw new Error('unreadable answer'); i += 4; }
      else throw new Error('unreadable answer');
    }
  }

  // The answer's bytes -> [{ fullHash (base64), details: [{ threatType, attributes: [number] }] }]
  function parseResponse(bytes) {
    const found = [];
    readFields(bytes, (field, wire, value) => {
      if (field !== 1 || wire !== 2) return;
      const entry = { fullHash: '', details: [] };
      readFields(value, (f, w, v) => {
        if (f === 1 && w === 2) entry.fullHash = toBase64(v);
        if (f === 2 && w === 2) {
          const detail = { threatType: '', attributes: [] };
          readFields(v, (df, dw, dv) => {
            if (df === 1 && dw === 0) detail.threatType = THREAT_NAMES[dv] || '';
            if (df === 2 && dw === 0) detail.attributes.push(dv);
            if (df === 2 && dw === 2) readFields(new Uint8Array([...dv].flatMap(b => [0x10, b])), (_f, _w, n) => detail.attributes.push(n)); // packed list of small numbers
          });
          entry.details.push(detail);
        }
      });
      found.push(entry);
    });
    return found;
  }

  async function sha256(text) {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', latin1ToBytes(text)));
  }

  // options: { apiKey, fetch } (fetch is replaced in tests). The standard provider shape, see threat-lookup.js.
  function safeBrowsingProvider({ apiKey = '', fetch: fetchFn } = {}) {
    return {
      name: 'Google Safe Browsing',
      trusted: true, // Google's own list: a match may stop the person
      async lookup(parsed, { signal } = {}) {
        if (!apiKey) throw userFacing('Google Safe Browsing: no key saved yet');
        const canonical = canonicalize(parsed.href);
        if (!canonical) return { matched: false };
        const hashes = await Promise.all(expressions(canonical).map(sha256));
        const ours = new Set(hashes.map(toBase64));
        const query = [`key=${encodeURIComponent(apiKey)}`, ...new Set(hashes.map(h => `hashPrefixes=${encodeURIComponent(toBase64(h.slice(0, 4)))}`))].join('&');
        const response = await (fetchFn || globalThis.fetch)(`${ENDPOINT}?${query}`, {
          method: 'GET', signal, credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer',
        });
        if (response.status === 400 || response.status === 403) throw userFacing('Google Safe Browsing: Google did not accept the key (is the Safe Browsing API turned on for it?)');
        if (response.status === 429) throw userFacing('Google Safe Browsing: the free limit was reached, try again later');
        if (!response.ok) throw userFacing(`Google Safe Browsing: Google answered ${response.status}`);
        for (const found of parseResponse(new Uint8Array(await response.arrayBuffer()))) {
          if (!ours.has(found.fullHash)) continue; // same first 4 bytes, a different address
          const detail = found.details.find(d => THREAT_TYPES.has(d.threatType) && !d.attributes.some(a => SKIP_ATTRIBUTES.has(a)));
          if (detail) return { matched: true, threatType: detail.threatType };
        }
        return { matched: false };
      },
    };
  }

  bg.safeBrowsing = { ENDPOINT, canonicalize, expressions, parseResponse, safeBrowsingProvider };
  if (typeof module !== 'undefined') module.exports = bg.safeBrowsing;
})();
