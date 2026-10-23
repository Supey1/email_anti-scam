// ad-signals.js: finds likely advertisements on a page and describes them as EVIDENCE.
// It does not judge whether an ad is a scam (that is the analyzer's job), and it never
// hides, removes, or changes an ad. Most ads are legitimate.
//
// An element counts as an ad only when it carries a recognizable marker: an ad attribute, an
// ad-style class or id, an "Advertisement" label, rel="sponsored", an ad-network link, and so on.
// Ads with no marker, ads drawn as images or canvas, ads in shadow DOM, and ads in cross-origin
// frames can't be identified from the page, so they are not covered. See docs/ad-support-matrix.md.
//
// Describing an ad gives: { signals: [why we think it's an ad], text: offer text, link: { text, url } | null }

const AdSignals = (() => {
  'use strict';

  const LIMITS = { maxText: 400, maxLinkText: 100, maxContainerText: 1500, maxContainerLinks: 10, maxExamined: 3000, depth: 6 };

  const LABELS = /^(sponsored|advertisement|advertisements|advert|ad|ads|promoted|paid partnership)$/i;
  const CLASS_TOKENS = new Set([
    'ad', 'ads', 'advert', 'advertisement', 'adslot', 'ad-slot', 'ad-unit', 'adunit', 'ad-container', 'ad-banner',
    'banner-ad', 'sponsored', 'sponsor', 'sponsored-content', 'promoted', 'adsbygoogle', 'ad-frame', 'adframe',
  ]);
  const ID_START = /^(google_ads|div-gpt-ad|ad[-_]|ads[-_]|advert|sponsored)/i;
  const AD_ATTRIBUTES = ['data-ad', 'data-ad-slot', 'data-ad-client', 'data-ad-unit'];
  const ARIA_AD = /\b(advertisement|sponsored)\b/i;
  const NETWORK = /(^|\.)(googleadservices\.com|doubleclick\.net|googlesyndication\.com|adservice\.google\.com|taboola\.com|outbrain\.com|adnxs\.com|criteo\.com|amazon-adsystem\.com)$/;
  const LABEL_TAGS = 'span, small, div, p, em, b, i, label';
  const CANDIDATES = '[data-ad], [data-ad-slot], [data-ad-client], [data-ad-unit], [class*="ad" i], [id*="ad" i], ' +
    '[class*="sponsor" i], [class*="promo" i], [aria-label*="advert" i], [aria-label*="sponsor" i], a[rel~="sponsored"], iframe';

  const collapse = text => text.replace(/\s+/g, ' ').trim();

  // The reasons this ONE element looks like an ad (not counting what is inside it).
  function ownSignals(el) {
    const signals = [];
    if (!el || el.nodeType !== Node.ELEMENT_NODE) return signals;
    for (const name of AD_ATTRIBUTES) if (el.hasAttribute(name)) signals.push(`attribute:${name}`);
    for (const token of el.classList) if (CLASS_TOKENS.has(token.toLowerCase())) signals.push(`class:${token.toLowerCase()}`);
    if (el.id && ID_START.test(el.id)) signals.push(`id:${el.id.slice(0, 30)}`);
    const aria = el.getAttribute('aria-label') || el.getAttribute('title') || '';
    if (ARIA_AD.test(aria)) signals.push(`label:${aria.slice(0, 30)}`);
    if (el.localName === 'a') {
      if (/\bsponsored\b/i.test(el.getAttribute('rel') || '')) signals.push('rel:sponsored');
      if (NETWORK.test(el.hostname || '')) signals.push(`network:${el.hostname}`);
    }
    if (el.localName === 'iframe') {
      try { if (NETWORK.test(new URL(el.src, location.href).hostname)) signals.push('network:frame'); } catch (e) { /* no address */ }
    }
    return signals;
  }

  function isLabel(el) {
    return el.children.length === 0 && LABELS.test(collapse(el.textContent || ''));
  }

  // An ad unit must be small enough to be one ad, and not contain forms.
  function sizeOk(el) {
    return (el.textContent || '').length <= LIMITS.maxContainerText &&
      el.querySelectorAll('a[href]').length <= LIMITS.maxContainerLinks &&
      !el.querySelector('form, input, textarea');
  }

  // Does this element hold a small "Sponsored" / "Advertisement" label?
  function holdsLabel(el) {
    let n = 0;
    for (const child of el.querySelectorAll(LABEL_TAGS)) {
      if (++n > 40) return false;
      if (isLabel(child)) return true;
    }
    return false;
  }

  // The ad (if any) that `el` is part of: the OUTERMOST ad-marked ancestor that is still small enough to be
  // one ad unit. (The innermost marked element can be just the link, such as <a id="ad-link">, which has
  // none of the ad's words.) A small "Sponsored" label counts for the ancestor that holds it and a link.
  function containerFor(el) {
    let node = el && el.nodeType === Node.TEXT_NODE ? el.parentElement : el;
    let best = null;
    for (let i = 0; node && i <= LIMITS.depth; i++, node = node.parentElement) {
      if (node.localName === 'body' || node.localName === 'html') break;
      if (!sizeOk(node)) { if (best) break; continue; } // a bigger ancestor cannot be one ad unit
      if (ownSignals(node).length) best = node;
      else if (node.localName !== 'a' && node.querySelector('a[href]') && holdsLabel(node)) best = node;
    }
    return best;
  }

  // Every ad unit under (or around) the given elements. Outermost units win over nested ones.
  function find(roots) {
    const found = new Set();
    let examined = 0;
    for (const root of roots) {
      if (root.nodeType !== Node.ELEMENT_NODE && root.nodeType !== Node.TEXT_NODE) continue;
      const own = containerFor(root);
      if (own) found.add(own);
      if (root.nodeType !== Node.ELEMENT_NODE) continue;
      for (const el of root.querySelectorAll(CANDIDATES)) {
        if (++examined > LIMITS.maxExamined) break;
        if (el.localName === 'iframe') continue; // frames are handled separately
        if (ownSignals(el).length && sizeOk(el)) found.add(el);
      }
      for (const el of root.querySelectorAll(LABEL_TAGS)) {
        if (++examined > LIMITS.maxExamined) break;
        if (isLabel(el)) { const c = containerFor(el); if (c) found.add(c); }
      }
    }
    const all = [...found];
    return all.filter(c => !all.some(other => other !== c && other.contains(c)));
  }

  // Everything that points to `container` being an ad, including labels and links inside it.
  function signalsOf(container) {
    const signals = new Set(ownSignals(container));
    const anchors = container.localName === 'a' ? [container] : [...container.querySelectorAll('a[href]')].slice(0, 20);
    for (const a of anchors) for (const s of ownSignals(a)) signals.add(s);
    for (const el of container.querySelectorAll(LABEL_TAGS)) {
      if (isLabel(el)) { signals.add(`label:${collapse(el.textContent)}`); break; }
    }
    return [...signals].slice(0, 6);
  }

  function linkText(a) {
    const text = collapse(a.textContent || '');
    if (text) return text.slice(0, LIMITS.maxLinkText);
    const img = a.querySelector('img[alt]');
    return collapse(a.getAttribute('aria-label') || a.title || (img && img.alt) || '').slice(0, LIMITS.maxLinkText);
  }

  // The ad's advertised destination: the first link to another website, else the first link.
  function mainLink(container) {
    const anchors = (container.localName === 'a' ? [container] : [...container.querySelectorAll('a[href]')])
      .filter(a => /^https?:$/.test(a.protocol));
    const chosen = anchors.find(a => a.origin !== location.origin) || anchors[0];
    return chosen ? { text: linkText(chosen), url: chosen.href } : null;
  }

  function describe(container) {
    const raw = container.innerText !== undefined ? container.innerText : container.textContent;
    return { signals: signalsOf(container), text: collapse(raw || '').slice(0, LIMITS.maxText), link: mainLink(container) };
  }

  // Context for the analyzer when a link is clicked: is it part of an ad, and what did the ad say?
  // The words around an element: the largest surrounding box that still holds only a few sentences and no OTHER
  // link, so a neighbouring ad's words are never mixed into this one's.
  function surroundingText(el) {
    let text = '';
    for (let node = el; node && node !== document.documentElement; node = node.parentElement) {
      if (node.querySelectorAll('a[href]').length > 1) break;
      const t = (node.innerText || '').replace(/\s+/g, ' ').trim();
      if (t.length > LIMITS.maxText) break;
      text = t;
    }
    return text;
  }

  function contextFor(el) {
    const container = containerFor(el);
    if (!container) return null;
    const ad = describe(container);
    // A link that is itself the marked thing (an ad-network link) holds almost no words of its own: the ad's words
    // are the box around it, so read those. (Otherwise a scam ad's wording never reaches the engine.)
    const text = container === el ? (surroundingText(el) || ad.text) : ad.text;
    return { text, signals: ad.signals };
  }

  // Is this <iframe> an ad frame? (Its contents are usually unreadable; the scanner only counts it.)
  function isAdFrame(frame) {
    return ownSignals(frame).length > 0 || !!containerFor(frame.parentElement);
  }

  return { find, describe, contextFor, containerFor, isAdFrame, ownSignals, LIMITS };
})();
