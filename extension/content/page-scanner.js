// page-scanner.js: collects EVIDENCE from an ordinary webpage. It never decides whether
// the evidence looks like a scam; that is the analyzer's job (see docs/interfaces.md).
//
// Evidence has the shape of the analyzer input:
//   { source: 'webpage', pageUrl, pageTitle, visibleText, links: [{ text, url }],
//     forms: [{ action, method, fieldCount, hasPassword, hasPayment }], context: {...} }
//
// Privacy: the scanner never reads what a person typed. It does not read the `value` of any
// input, and it skips text inside inputs, text boxes, drop-downs, and editable areas. For
// forms it records only that a password or payment field EXISTS.
//
// Two passes:
//   initial scan: the whole page, once, when the scanner starts
//   dynamic scan: only newly added content, gathered by a MutationObserver. At most one
//                 scan per `debounceMs` however busy the page is, and anything already
//                 reported is skipped.
// Every scan is bounded (see DEFAULT_LIMITS) so busy pages with thousands of links or
// constantly rotating ads can't slow the browser down.

const PageScanner = (() => {
  'use strict';

  const DEFAULT_LIMITS = {
    maxTextChars: 20000,       // visible text per scan
    maxNodesVisited: 5000,     // page elements and text pieces examined per scan
    maxLinks: 100,             // links reported per scan
    maxLinksExamined: 1000,    // links looked at per scan, before choosing which to report
    maxLinkTextChars: 100,
    maxForms: 20,
    maxAds: 20,                // advertisements reported per scan
    maxTitleChars: 300,
    maxAddedNodesPerScan: 200, // new elements examined per dynamic scan
    maxDynamicScans: 100,      // after this many, stop watching the page
    maxSeen: 2000,             // remembered links, forms, so repeats are not sent again
    debounceMs: 1500,
    maxMergedText: 40000,      // limits for merge()
    maxMergedLinks: 300,
    maxMergedAds: 50,
  };

  const OWN_HOST_ID = 'email-anti-scam-warning'; // our own warning card: never scan it
  const SKIP_TAGS = new Set(['script', 'style', 'noscript', 'template', 'textarea', 'select', 'option', 'input', 'iframe', 'svg', 'canvas']);
  const PAYMENT_NAME = /card.?(number|num|no)|cc.?num|cvv|cvc|security.?code/i;

  const collapse = text => text.replace(/\s+/g, ' ').trim();

  // ---------- small helpers ----------

  // Adds to a Set, forgetting the oldest entry when full. Returns true if the key was new.
  function remember(set, key, max) {
    if (set.has(key)) return false;
    set.add(key);
    if (set.size > max) set.delete(set.values().next().value);
    return true;
  }

  function isVisible(el) {
    if (typeof el.checkVisibility !== 'function') return true;
    return el.checkVisibility({ visibilityProperty: true, checkVisibilityCSS: true, opacityProperty: true, checkOpacity: true });
  }

  // Text inside these places is skipped entirely.
  function isSkippedElement(el) {
    return SKIP_TAGS.has(el.localName) || el.id === OWN_HOST_ID || el.isContentEditable === true;
  }

  // Like insideSkipped(), but the element itself (an <input>) does not count.
  function insideSkippedAncestor(el) {
    return !!el.parentElement && insideSkipped(el.parentElement);
  }

  function insideSkipped(el) {
    for (let node = el; node; node = node.parentElement) if (isSkippedElement(node)) return true;
    return false;
  }

  // ---------- text ----------

  // Visible text under `root`, shortest-first-come, within the limits.
  // `skip` is a Set of elements (advertisements) whose text is reported separately, not as page text.
  function collectText(root, limits, skip = new Set()) {
    const parts = [];
    let length = 0;
    let visited = 0;
    let truncated = false;

    if (root.nodeType === Node.TEXT_NODE) {
      const parent = root.parentElement;
      if (parent && !insideSkipped(parent) && isVisible(parent)) {
        const text = collapse(root.data);
        if (text) return { text: text.slice(0, limits.maxTextChars), truncated: text.length > limits.maxTextChars };
      }
      return { text: '', truncated: false };
    }
    if (insideSkipped(root) || !isVisible(root) || skip.has(root)) return { text: '', truncated: false };

    const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        if (node.nodeType === Node.ELEMENT_NODE) {
          // REJECT skips the element and everything inside it.
          return isSkippedElement(node) || skip.has(node) || !isVisible(node) ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_SKIP;
        }
        return node.data.trim() ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_SKIP;
      },
    });
    while (walker.nextNode()) {
      if (++visited > limits.maxNodesVisited) { truncated = true; break; }
      const text = collapse(walker.currentNode.data);
      parts.push(text);
      length += text.length + 1;
      if (length >= limits.maxTextChars) { truncated = true; break; }
    }
    return { text: parts.join(' ').slice(0, limits.maxTextChars), truncated };
  }

  // ---------- links ----------

  function linkText(a, limits) {
    const text = collapse(a.textContent || '');
    if (text) return text.slice(0, limits.maxLinkTextChars);
    const img = a.querySelector('img[alt]');
    return collapse(a.getAttribute('aria-label') || a.title || (img && img.alt) || '').slice(0, limits.maxLinkTextChars);
  }

  // Links under (or equal to) each root. Links to other websites come first, because those
  // are the ones that matter most if the page has more links than the limit.
  function collectLinks(roots, limits, seen) {
    const anchors = [];
    for (const root of roots) {
      if (root.nodeType !== Node.ELEMENT_NODE) continue;
      if (root.matches('a[href]')) anchors.push(root);
      for (const a of root.querySelectorAll('a[href]')) {
        anchors.push(a);
        if (anchors.length >= limits.maxLinksExamined) break;
      }
      if (anchors.length >= limits.maxLinksExamined) break;
    }

    const here = location.origin + location.pathname + location.search;
    const outside = [];
    const inside = [];
    for (const a of anchors) {
      if (!/^https?:$/.test(a.protocol) || insideSkipped(a) || !isVisible(a)) continue;
      // A link to a spot on this same page is not a destination.
      if (a.hash && a.origin + a.pathname + a.search === here) continue;
      const link = { text: linkText(a, limits), url: a.href };
      if (!remember(seen, `${link.text}\u0000${link.url}`, limits.maxSeen)) continue;
      (a.origin === location.origin ? inside : outside).push(link);
    }
    const all = outside.concat(inside);
    return { links: all.slice(0, limits.maxLinks), truncated: all.length > limits.maxLinks || anchors.length >= limits.maxLinksExamined };
  }

  // ---------- forms (never any typed values) ----------

  // Looks at a field's kind and name only, never its value.
  const isPaymentField = f => /^cc-/.test(f.autocomplete || '') || PAYMENT_NAME.test(`${f.name} ${f.id}`);

  function describeForm(action, method, fields) {
    return {
      action,
      method,
      fieldCount: fields.length,
      hasPassword: fields.some(f => f.type === 'password'),
      hasPayment: fields.some(isPaymentField),
    };
  }

  function collectForms(roots, limits, seen) {
    const forms = [];
    const add = description => {
      const key = [description.action, description.method, description.fieldCount, description.hasPassword, description.hasPayment].join('|');
      if (forms.length < limits.maxForms && remember(seen, key, limits.maxSeen)) forms.push(description);
    };
    for (const root of roots) {
      if (root.nodeType !== Node.ELEMENT_NODE) continue;
      const found = root.localName === 'form' ? [root] : [];
      found.push(...root.querySelectorAll('form'));
      for (const form of found) {
        if (!insideSkipped(form)) add(describeForm(form.action || location.href, (form.method || 'get').toLowerCase(), [...form.querySelectorAll('input, select, textarea')]));
      }
      // Pages built with scripts often have password or card boxes that are not inside any <form>.
      const inputs = [...root.querySelectorAll('input')];
      if (root.localName === 'input') inputs.push(root);
      const loose = inputs.filter(i => !i.form && !insideSkippedAncestor(i));
      const sensitive = loose.filter(i => i.type === 'password' || isPaymentField(i));
      if (sensitive.length) add(describeForm(location.href, 'get', loose));
    }
    return forms;
  }

  // ---------- advertisements ----------
  // Evidence only: what the ad says, where it leads, and why we think it is an ad.
  // Same-origin ad frames are read; cross-origin ad frames can't be, so they are only counted.

  function collectAds(roots, limits, seen) {
    if (typeof AdSignals === 'undefined') return { ads: [], frames: { readable: 0, unreadable: 0 }, containers: new Set() };
    const ads = [];
    const frames = { readable: 0, unreadable: 0 };
    const add = (container, inFrame) => {
      if (ads.length >= limits.maxAds) return;
      const ad = AdSignals.describe(container);
      if (!ad.link && !ad.text) return;
      const key = `${ad.link ? ad.link.url : ''}\u0000${ad.text.slice(0, 80)}`;
      if (remember(seen, key, limits.maxSeen)) ads.push({ ...ad, signals: inFrame ? ['frame:ad-frame', ...ad.signals].slice(0, 6) : ad.signals, frame: inFrame });
    };
    const containers = new Set(AdSignals.find(roots));
    for (const container of containers) add(container, false);

    for (const root of roots) {
      if (root.nodeType !== Node.ELEMENT_NODE) continue;
      const list = root.localName === 'iframe' ? [root] : [];
      list.push(...root.querySelectorAll('iframe'));
      for (const frame of list) {
        if (!AdSignals.isAdFrame(frame)) continue;
        let doc = null;
        try { doc = frame.contentDocument; } catch (e) { doc = null; }
        if (!doc || !doc.body) { frames.unreadable++; continue; }
        frames.readable++;
        const inside = AdSignals.find([doc.body]);
        // A whole ad frame is one ad even if nothing inside carries a marker.
        for (const container of inside.length ? inside : [doc.body]) add(container, true);
      }
    }
    return { ads, frames, containers };
  }

  // ---------- evidence ----------

  function makeEvidence(scan, text, links, forms, truncated, adInfo) {
    return {
      source: 'webpage',
      pageUrl: location.href,
      pageTitle: collapse(document.title || ''),
      visibleText: text,
      links,
      forms,
      context: { scan, truncated, ads: adInfo.ads, adFrames: adInfo.frames },
    };
  }

  // Combines the page's evidence so far with a dynamic scan's new evidence, within limits.
  function merge(base, delta, limits = DEFAULT_LIMITS) {
    const keys = new Set(base.links.map(l => `${l.text}\u0000${l.url}`));
    const links = base.links.concat(delta.links.filter(l => !keys.has(`${l.text}\u0000${l.url}`))).slice(0, limits.maxMergedLinks);
    const text = delta.visibleText ? `${base.visibleText} ${delta.visibleText}` : base.visibleText;
    return {
      ...base,
      pageUrl: delta.pageUrl,
      pageTitle: delta.pageTitle,
      visibleText: text.slice(0, limits.maxMergedText),
      links,
      forms: base.forms.concat(delta.forms).slice(0, limits.maxForms * 2),
      context: {
        ...base.context,
        ads: (base.context.ads || []).concat(delta.context.ads || []).slice(0, limits.maxMergedAds),
        adFrames: {
          readable: ((base.context.adFrames || {}).readable || 0) + ((delta.context.adFrames || {}).readable || 0),
          unreadable: ((base.context.adFrames || {}).unreadable || 0) + ((delta.context.adFrames || {}).unreadable || 0),
        },
        scan: delta.context.scan,
        truncated: { text: base.context.truncated.text || delta.context.truncated.text, links: base.context.truncated.links || delta.context.truncated.links },
      },
    };
  }

  // ---------- the scanner ----------

  // options = { onEvidence(evidence), onError(error), limits: {...overrides} }
  // Returns { scanNow(), stop(), stats() }.
  function start(options) {
    const limits = { ...DEFAULT_LIMITS, ...(options.limits || {}) };
    const seenLinks = new Set();
    const seenForms = new Set();
    const seenAds = new Set();
    let knownText = '';
    const queue = new Set();
    let timer = null;
    let observer = null;
    let dynamicScans = 0;
    let stopped = false;

    function emit(evidence) {
      try { options.onEvidence(evidence); } catch (error) { if (options.onError) options.onError(error); }
    }

    function initialScan() {
      const root = document.body || document.documentElement;
      // Ads are judged on their own (with the "this is an ad" context), so their text is kept out of the page text.
      const adInfo = collectAds([document.documentElement], limits, seenAds);
      const { text, truncated: textTruncated } = collectText(root, limits, adInfo.containers);
      const { links, truncated: linksTruncated } = collectLinks([document.documentElement], limits, seenLinks);
      const forms = collectForms([document.documentElement], limits, seenForms);
      knownText = text;
      emit(makeEvidence('initial', text, links, forms, { text: textTruncated, links: linksTruncated }, adInfo));
    }

    function dynamicScan() {
      timer = null;
      if (stopped) return;
      if (document.hidden) return; // picked up again when the tab becomes visible
      if (++dynamicScans > limits.maxDynamicScans) { stop(); return; }

      const added = [...queue].filter(n => n.isConnected);
      queue.clear();
      // A new element that is inside another new element is covered by its parent.
      const roots = added.filter(n => !added.some(other => other !== n && other.nodeType === Node.ELEMENT_NODE && other.contains(n)));

      const adInfo = collectAds(roots, limits, seenAds);
      let text = '';
      let textTruncated = false;
      for (const root of roots) {
        if (typeof AdSignals !== 'undefined' && AdSignals.containerFor(root)) continue; // new content inside an ad: reported as an ad
        const piece = collectText(root, limits, adInfo.containers);
        textTruncated = textTruncated || piece.truncated;
        if (piece.text && !knownText.includes(piece.text) && text.length < limits.maxTextChars) text += (text ? ' ' : '') + piece.text;
      }
      text = text.slice(0, limits.maxTextChars);
      if (knownText.length < limits.maxMergedText) knownText += ' ' + text;

      const { links, truncated: linksTruncated } = collectLinks(roots, limits, seenLinks);
      const forms = collectForms(roots, limits, seenForms);
      if (!text && !links.length && !forms.length && !adInfo.ads.length && !adInfo.frames.unreadable) return; // nothing new
      emit(makeEvidence('dynamic', text, links, forms, { text: textTruncated, links: linksTruncated }, adInfo));
    }

    function schedule() {
      // Not reset by each new change: a page that changes constantly is still scanned
      // once per debounce period instead of never.
      if (!timer && !stopped) timer = setTimeout(dynamicScan, limits.debounceMs);
    }

    function onMutations(records) {
      for (const record of records) {
        const nodes = record.type === 'attributes' ? [record.target] : record.addedNodes;
        for (const node of nodes) {
          if (node.nodeType !== Node.ELEMENT_NODE && node.nodeType !== Node.TEXT_NODE) continue;
          const element = node.nodeType === Node.ELEMENT_NODE ? node : node.parentElement;
          if (!element || insideSkipped(element)) continue;
          if (queue.size < limits.maxAddedNodesPerScan) queue.add(node);
        }
      }
      if (queue.size) schedule();
    }

    function onVisible() {
      if (!document.hidden && queue.size) schedule();
    }

    function stop() {
      stopped = true;
      if (observer) observer.disconnect();
      if (timer) clearTimeout(timer);
      document.removeEventListener('visibilitychange', onVisible);
      document.removeEventListener('load', onFrameLoad, true);
      queue.clear();
      timer = null;
    }

    try { initialScan(); } catch (error) { if (options.onError) options.onError(error); }
    observer = new MutationObserver(onMutations);
    observer.observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['href'] });
    document.addEventListener('visibilitychange', onVisible);
    // An ad frame's content arrives after the frame is inserted: look again when it finishes loading.
    const onFrameLoad = event => {
      if (event.target && event.target.localName === 'iframe' && !stopped && queue.size < limits.maxAddedNodesPerScan) {
        queue.add(event.target);
        schedule();
      }
    };
    document.addEventListener('load', onFrameLoad, true);

    return {
      scanNow: () => { queue.clear(); initialScan(); },
      stop,
      stats: () => ({ dynamicScans, queued: queue.size, seenLinks: seenLinks.size, stopped }),
    };
  }

  return { start, merge, DEFAULT_LIMITS };
})();

// Lets tests load this file with Node. Chrome ignores this.
if (typeof module !== 'undefined') {
  module.exports = PageScanner;
}
