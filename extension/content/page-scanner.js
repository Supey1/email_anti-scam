// page-scanner.js: collects EVIDENCE from an ordinary webpage. It never decides whether
// the evidence looks like a scam; that is the analyzer's job (see docs/interfaces.md).
//
// Evidence is exactly the analyzer input in docs/interfaces.md (checked by tests/contract.js):
//   { source: 'webpage', pageUrl, pageTitle, visibleText, links: [{ text, url }],
//     forms: [{ action, hasPassword, hasPaymentField }], context: { mainHeadings } }
// Extra facts about a scan (which pass it was, whether a size limit cut something off) are NOT part of the
// evidence: they come as a second argument, onEvidence(evidence, meta).
//
// Privacy: the scanner never reads what a person typed. It does not read the `value` of any
// input, and it skips text inside inputs, text boxes, drop-downs, and editable areas. For
// forms it records only that a password or payment field EXISTS.
//
// Advertisements are not treated separately here: their words are part of the page text and their links are
// page links, and the engine judges them with everything else. (content/ad-signals.js recognizes ads only to
// describe the words around a clicked link.)
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
    maxTextChars: 40000,       // visible text per scan (the contract allows 50,000)
    maxNodesVisited: 5000,     // page elements and text pieces examined per scan
    maxLinks: 100,             // links reported per scan
    maxLinksExamined: 1000,    // links looked at per scan, before choosing which to report
    maxLinkTextChars: 100,
    maxForms: 20,
    maxTitleChars: 300,
    maxAddedNodesPerScan: 200, // new elements examined per dynamic scan
    maxDynamicScans: 100,      // after this many, stop watching the page
    maxSeen: 2000,             // remembered links, forms, so repeats are not sent again
    debounceMs: 1500,
    maxMergedText: 50000,      // limits for merge(): the contract's limit
    maxMergedLinks: 300,
    keepHeadChars: 10000,      // when merged text is too long, the middle is trimmed: new text arrives at the END and matters most
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

  function describeForm(action, fields) {
    return {
      action,
      hasPassword: fields.some(f => f.type === 'password'),
      hasPaymentField: fields.some(isPaymentField),
    };
  }

  function collectForms(roots, limits, seen) {
    const forms = [];
    const add = description => {
      // The contract asks only for forms with something sensitive in them: a password or a card number.
      if (!description.hasPassword && !description.hasPaymentField) return;
      const key = [description.action, description.hasPassword, description.hasPaymentField].join('|');
      if (forms.length < limits.maxForms && remember(seen, key, limits.maxSeen)) forms.push(description);
    };
    for (const root of roots) {
      if (root.nodeType !== Node.ELEMENT_NODE) continue;
      const found = root.localName === 'form' ? [root] : [];
      found.push(...root.querySelectorAll('form'));
      for (const form of found) {
        if (!insideSkipped(form)) add(describeForm(form.action || location.href, [...form.querySelectorAll('input, select, textarea')]));
      }
      // Pages built with scripts often have password or card boxes that are not inside any <form>.
      const inputs = [...root.querySelectorAll('input')];
      if (root.localName === 'input') inputs.push(root);
      const loose = inputs.filter(i => !i.form && !insideSkippedAncestor(i));
      const sensitive = loose.filter(i => i.type === 'password' || isPaymentField(i));
      if (sensitive.length) add(describeForm(location.href, loose));
    }
    return forms;
  }

  // ---------- evidence ----------

  // Practice pages opened as files say which website they pretend to be (data-practice-url); real pages never do.
  const practiceUrl = () => (location.protocol === 'file:' && document.documentElement.getAttribute('data-practice-url')) || '';

  // The page's main headings (up to 3): a fake sign-in page often names the company in its heading.
  function mainHeadings(limits) {
    return [...document.querySelectorAll('h1')]
      .filter(h => isVisible(h) && !insideSkipped(h))
      .map(h => collapse(h.textContent || '').slice(0, 120))
      .filter(Boolean)
      .slice(0, 3);
  }

  function makeEvidence(text, links, forms, limits) {
    return {
      source: 'webpage',
      pageUrl: practiceUrl() || location.href,
      pageTitle: collapse(document.title || '').slice(0, limits.maxTitleChars),
      visibleText: text,
      links,
      forms,
      context: { mainHeadings: mainHeadings(limits) },
    };
  }

  // Joins text, keeping the NEWEST text when it is too long: a scam pop-up added late sits at the end.
  function joinText(base, added, limits) {
    const all = added ? `${base} ${added}` : base;
    if (all.length <= limits.maxMergedText) return all;
    return all.slice(0, limits.keepHeadChars) + ' ' + all.slice(all.length - (limits.maxMergedText - limits.keepHeadChars - 1));
  }

  // Combines the page's evidence so far with a dynamic scan's new evidence, within limits.
  function merge(base, delta, limits = DEFAULT_LIMITS) {
    const keys = new Set(base.links.map(l => `${l.text}\u0000${l.url}`));
    const links = base.links.concat(delta.links.filter(l => !keys.has(`${l.text}\u0000${l.url}`))).slice(0, limits.maxMergedLinks);
    const formKey = f => `${f.action}|${f.hasPassword}|${f.hasPaymentField}`;
    const seenForms = new Set(base.forms.map(formKey));
    return {
      ...base,
      pageUrl: delta.pageUrl,
      pageTitle: delta.pageTitle,
      visibleText: joinText(base.visibleText, delta.visibleText, limits),
      links,
      forms: base.forms.concat(delta.forms.filter(f => !seenForms.has(formKey(f)))).slice(0, limits.maxForms * 2),
      context: { mainHeadings: base.context.mainHeadings.length ? base.context.mainHeadings : delta.context.mainHeadings },
    };
  }

  // ---------- the scanner ----------

  // options = { onEvidence(evidence), onError(error), limits: {...overrides} }
  // Returns { scanNow(), stop(), stats() }.
  function start(options) {
    const limits = { ...DEFAULT_LIMITS, ...(options.limits || {}) };
    const seenLinks = new Set();
    const seenForms = new Set();
    let knownText = '';
    const queue = new Set();
    let timer = null;
    let observer = null;
    let dynamicScans = 0;
    let stopped = false;

    function emit(evidence, meta) {
      try { options.onEvidence(evidence, meta); } catch (error) { if (options.onError) options.onError(error); }
    }

    function initialScan() {
      const root = document.body || document.documentElement;
      const { text, truncated: textTruncated } = collectText(root, limits);
      const { links, truncated: linksTruncated } = collectLinks([document.documentElement], limits, seenLinks);
      const forms = collectForms([document.documentElement], limits, seenForms);
      knownText = text;
      emit(makeEvidence(text, links, forms, limits), { scan: 'initial', truncated: { text: textTruncated, links: linksTruncated } });
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

      let text = '';
      let textTruncated = false;
      for (const root of roots) {
        const piece = collectText(root, limits);
        textTruncated = textTruncated || piece.truncated;
        if (piece.text && !knownText.includes(piece.text) && text.length < limits.maxTextChars) text += (text ? ' ' : '') + piece.text;
      }
      text = text.slice(0, limits.maxTextChars);
      if (knownText.length < limits.maxMergedText) knownText += ' ' + text;

      const { links, truncated: linksTruncated } = collectLinks(roots, limits, seenLinks);
      const forms = collectForms(roots, limits, seenForms);
      if (!text && !links.length && !forms.length) return; // nothing new
      emit(makeEvidence(text, links, forms, limits), { scan: 'dynamic', truncated: { text: textTruncated, links: linksTruncated } });
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
      queue.clear();
      timer = null;
    }

    try { initialScan(); } catch (error) { if (options.onError) options.onError(error); }
    observer = new MutationObserver(onMutations);
    observer.observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['href'] });
    document.addEventListener('visibilitychange', onVisible);
    return {
      scanNow: () => { queue.clear(); seenLinks.clear(); seenForms.clear(); initialScan(); },
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
