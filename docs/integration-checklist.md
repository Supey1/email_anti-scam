# Integration checklist

Short and shared. Add an item instead of editing the other person's code. Tick it when it is merged with its tests.

## Contract gaps (current code vs `docs/interfaces.md`)

- [ ] **A:** `analyzePage` / `analyzeLink` return `verdict: "allow"`; the contract says `no_warning_signs` (and `unknown` on failure).
- [ ] **A:** `reasons` are plain strings; the contract wants `{ code, title, explanation }`.
- [ ] **A:** Result needs `schemaVersion: 1` and `recommendedAction` as an enum code, not a sentence.
- [ ] **A:** `analyzer.js` input uses `url` / `title` / `links[].href`; contract uses `pageUrl` / `pageTitle` / `links[].url`, plus `source` and `context`. (The scanner already emits the contract shape.)
- [ ] **A:** Add `tests/fixtures/inputs/` and `tests/fixtures/results/` per the interfaces doc.
- [x] `analyze(evidence)` is now the single entry point and accepts the contract's input shape for webpages and emails; `page.js` no longer has an adapter. (Added by B as a stopgap in `analyzer.js`; **A** owns it from here: please review, and move the result to the structured output.)
- [ ] **B:** `click-guard.js` and `page.js` still branch on the old verdict `allow`. `ui/explain.js` already accepts both shapes; remove its "TEMPORARY" normalization once the analyzer returns the contract.
- [ ] **B:** Map reason `code`s to any custom wording or icons (everything falls back to `title` / `explanation` today).

## Done (Phase 6, Person B)

- [x] `extension/settings.js`, `ui/popup.*`, `ui/options.*`, `ui/status.js`. Settings gate scanning, click guarding, Gmail checking, and blocking rules; badge shows OFF when protection is off. Tests: `tests/settings.test.js`, `tests/browser/settings.test.js`.
- [x] Text size and read-aloud choices apply to the in-page card, the warning page, and the Gmail panel.
- [ ] **B (Web Store):** Chrome still grants `<all_urls>` at install; the "Websites" setting only controls where we look. To request the narrowest permission, move web access to `optional_host_permissions` and register the webpage content scripts at runtime with `chrome.scripting` after `chrome.permissions.request` (needs a user click, so it can't be covered by the current automated browser tests; verify by hand).
- [ ] **B:** Auto read-aloud inside the in-page card shares code with the warning page (tested there), but Chrome may block speech until the page has been clicked. Check by hand on real sites.
- [ ] **B:** Popup and settings page checked with keyboard and ARIA only; try a real screen reader and Chrome's zoom at 200%.
- [ ] **Deferred by decision:** "Ask someone I trust" (sharing an email or link with another person). Design consent, what is shared, and sensitive-data handling first.
- [ ] **B:** Incognito: extensions are off there unless the person allows it; the settings page says so but there is no in-extension check.

## Done (Phases 4 and 5, Person B)

- [x] `extension/content/ad-signals.js`; scanner reports `context.ads` and `context.adFrames`; ads reuse the shared analyzer (`analyzeAd`, `analyzeLink(link, {ad})`). Matrix: `docs/ad-support-matrix.md`.
- [x] `extension/content/gmail-adapter.js` (all Gmail selectors) and `content/gmail.js` (glue); the old `content.js` is gone. Tests: `tests/browser/gmail-adapter.test.js` on `tests/fake-gmail.html`.
- [x] The Gmail panel now uses the shared warning interface, so email and webpages explain the same verdict the same way.
- [ ] **A:** Email maps the rule score to `block` / `warn` / `allow` in `analyzeEmailEvidence`. Confirm that is the intended meaning of `block` for email (documented in `interfaces.md`).
- [ ] **A:** Ad detection judges by the same link/wording rules as pages; add ad-specific reason codes when the structured output arrives.
- [ ] **B + A:** Cross-origin ad frames are not inspected. Reading them needs `all_frames` content scripts and a wider privacy review; decide before the Web Store listing.
- [ ] **B:** Gmail selectors are the original ones plus tests on a Gmail-shaped page, not verified against live Gmail. Try it with a real test account and update `GmailAdapter.SELECTORS`.
- [ ] **B:** Real Gmail renders links through redirects in some views; confirm hidden-destination checks behave.

## Done (Phases 2 and 3, Person B)

- [x] `extension/content/click-guard.js` and the extension-owned `extension/ui/warning.html`; limits in `docs/click-guard-limits.md`.
- [x] Shared interface (`ui/explain.js`, `ui/warning-view.js`): large headline with icon and word, top 3 reasons plus "show more", Go back to safety, read aloud, false-alarm report (`chrome.storage.local`), Continue only for `warn`, keyboard focus, labels, high contrast.
- [x] Tests: `tests/explain.test.js`, `tests/browser/click-guard.test.js`.
- [ ] **B:** Screen-reader behavior is checked through ARIA attributes only; try a real screen reader.
- [ ] **B:** Read-aloud can't be verified in headless tests; check it by hand.
- [x] Saved false-alarm reports can be counted, saved, and deleted on the settings page.

## Done (Phase 1, Person B)

- [x] `extension/content/page-scanner.js`: initial scan, debounced and de-duplicated dynamic scan, size limits, no typed values. Tests: `tests/scanner-merge.test.js`, `tests/browser/scanner.test.js`.
- [ ] **B:** Scanner does not look inside iframes or shadow DOM; decide whether ads need that (Phase 6).
- [ ] **B:** `dynamic-ad.html` and the other practice pages are only checked by hand; add them to the browser tests.

## Permissions and privacy

- [ ] **B:** `<all_urls>` host access: confirm each use is needed and write the justification for the Web Store listing.
- [ ] **B:** New `storage` permission is used only for false-alarm reports (host, verdict, up to 5 reason sentences, source, time; last 100 kept; never leaves the browser). Disclose in the listing.
- [ ] **Both:** README Privacy section matches what is actually sent anywhere (nothing, until a threat provider is added).

## Testing

- [x] **B:** Browser test that a suspicious click is stopped before navigation.
- [x] **B:** Unusual click paths: new tab, keyboard, modified clicks, SVG, shadow DOM. Scripted navigation is a documented limit.
- [ ] **Both:** Measure scams caught and safe pages wrongly flagged on a larger example set.
