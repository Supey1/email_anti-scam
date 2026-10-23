# Integration checklist

Short and shared. Add an item instead of editing the other person's code. Tick it when it is merged with its tests.

## Contract gaps (current code vs `docs/interfaces.md`)

- [ ] **A:** `analyzePage` / `analyzeLink` return `verdict: "allow"`; the contract says `no_warning_signs` (and `unknown` on failure).
- [ ] **A:** `reasons` are plain strings; the contract wants `{ code, title, explanation }`.
- [ ] **A:** Result needs `schemaVersion: 1` and `recommendedAction` as an enum code, not a sentence.
- [ ] **A:** `analyzer.js` input uses `url` / `title` / `links[].href`; contract uses `pageUrl` / `pageTitle` / `links[].url`, plus `source` and `context`. (The scanner already emits the contract shape.)
- [ ] **A:** Add `tests/fixtures/inputs/` and `tests/fixtures/results/` per the interfaces doc.
- [ ] **A:** Accept the scanner's evidence directly, then **B** deletes `toAnalyzerInput()` in `page.js` (temporary adapter).
- [ ] **B:** `panel.js` and `guard.js` read the old result shape; switch to the contract and render by `code`, falling back to `title` / `explanation`.
- [ ] **B:** `guard.js` currently branches on `result.verdict === 'allow'`.
- [ ] **B:** `content.js` (Gmail) still calls `analyzeEmail()` directly and does its own level mapping; route it through the shared analyzer as an email adapter.

## Done (Phase 1, Person B)

- [x] `extension/content/page-scanner.js`: initial scan, debounced and de-duplicated dynamic scan, size limits, no typed values. Tests: `tests/scanner-merge.test.js`, `tests/browser/scanner.test.js`.
- [ ] **B:** Scanner does not look inside iframes or shadow DOM; decide whether ads need that (Phase 6).
- [ ] **B:** `dynamic-ad.html` and the other practice pages are only checked by hand; add them to the browser tests.

## Permissions and privacy

- [ ] **B:** `<all_urls>` host access: confirm each use is needed and write the justification for the Web Store listing.
- [ ] **Both:** README Privacy section matches what is actually sent anywhere (nothing, until a threat provider is added).

## Testing

- [ ] **B:** Browser test that a suspicious click is stopped before navigation (the smoke test used in development is not yet committed).
- [ ] **B:** Check unusual click paths: new tab, keyboard, scripted navigation.
- [ ] **Both:** Measure scams caught and safe pages wrongly flagged on a larger example set.
