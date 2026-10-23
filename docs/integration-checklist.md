# Integration checklist

Short and shared. When something in the other person's area needs to change, add it here instead of editing their code. Tick it off when the fix is merged with its tests.

## Decide first

- [ ] **Both:** Two versions of the same features exist: `claude/friendly-mayer-hx20bc` (`rules.js` + `warning.js` + `gmail.js`) and `claude/new-session-yy3c1k` (`analyzer.js` + `panel.js` + `docs/interfaces.md`). Pick one as the base, carry over anything worth keeping from the other, and delete the other branch. Don't merge both.

## Phase 0: the contract (`docs/interfaces.md`)

- [ ] **Both:** Confirm the "Decisions to confirm" list at the bottom of `interfaces.md`. Nothing below starts until this is done.
- [x] **Both:** Fixed inputs (`tests/fixtures/inputs/`) and fixed results (`tests/fixtures/results/`), checked by `node tests/contract.test.js`.

## Moving the current code to the contract

The code was written before the contract. Today `rules.js` takes three different input shapes and returns `level` / `action` / `score` / plain-sentence `reasons`.

- [x] **A:** One entry point, `analyze(input)` in `rules.js`, taking the contract input for all three sources. It returns the contract result and never throws (`unknown` on failure).
- [x] **A:** Every reason returns `{ code, title, explanation }` using the codes in the table. No `score` or `level` in the contract result.
- [x] **A:** Verdicts and actions: known dangerous → `block` + `GO_BACK`; 5+ points → `warn` + `GO_BACK` (links, email, pages without a password or card box) or `DO_NOT_ENTER_INFO` (pages with one); 1–4 points → `warn` + `VERIFY_INDEPENDENTLY`; nothing → `no_warning_signs` + `NONE`.
- [x] **A:** Return `evidence` items `{ kind, value, reasonCode }`.
- [x] **A:** Each input fixture is paired with its expected verdict in `tests/rules.test.js`, and every result there is checked with `validateResult`.
- [ ] **A:** Remove `analyzeEmail` / `analyzeLink` / `analyzePage` from `rules.js` once B no longer calls them. Until then they wrap `analyze()` and return the old shape, so nothing in B's code had to change.
- [ ] **B:** `gmail.js`, `page.js`, and `guard.js` build the contract input (`source`, `pageUrl`, `pageTitle`, `visibleText`, `links[].url`, `forms[]`, `context`) and call `analyze()`. `page.js` sends `forms` as `{ action, hasPassword, hasPaymentField }` instead of `hasPassword` / `formActions`.
- [ ] **B:** `guard.js` and `page.js` interrupt only for `GO_BACK` / `DO_NOT_ENTER_INFO`, never by reading reason codes or counting reasons.
- [ ] **B:** `warning.js` and the Gmail panel show `title` / `explanation` per reason, may style by `code`, and show unknown codes from `title` / `explanation`. Gmail says "No warning signs found", never "safe". `unknown` is not shown as no warning signs.
- [ ] **B:** Rename the frame-to-main-page message from `granblock-warning` to `SHOW_WARNING` / `SHOW_WARNING_RESULT` with `schemaVersion` and `navigation`.
- [ ] **B:** Test the scanner's real output with `validateInput` from `tests/contract.js`, including that no field values are ever collected.

## Load order (A touched B's files: please review)

- [ ] **B:** Phase 1 split the engine into `extension/core/*.js`. Those files must load before `rules.js`, so A added them to the script lists in `extension/manifest.json`, `tests/fake-gmail.html`, and `tests/practice-*.html`. Nothing else in those files changed (separate commit). Check that you're happy with it, or move them where you prefer.

## Phase 2: known threats (A changed `threat-list.js`; B's blocking needs to follow)

- [ ] **B:** `threat-list.js` now has `KNOWN_THREAT_URLS` (single dangerous addresses on otherwise-normal websites). The engine already stops clicks on them, but `service-worker.js` only blocks `KNOWN_THREAT_DOMAINS` in Chrome, so a typed or redirected visit to a listed address isn't blocked yet. Add browser rules for these too, matching the address and everything below it, nothing else on the website.
- [ ] **B:** `threat-list.js` now has `KNOWN_THREAT_SOURCE.trusted`. The engine only says `block` for a trusted source (otherwise a strong warning the person can go past). `service-worker.js` should only install hard-block rules when the source is trusted.
- [ ] **B:** `page.js` should send `hasPaymentField` for card-number boxes, so payment pages get the same checks as sign-in pages (free hosting, sent elsewhere, sent without encryption).

## Tests

- [ ] **B:** Commit a browser test proving a risky click is stopped before navigation, including a click inside an ad frame and a typed known-dangerous address. (This was checked by hand in Chromium, but the test isn't in the repo yet.)
- [ ] **B:** Test the less common ways of opening a link: right-click "Open in new tab", keyboard, pages that navigate with their own code.
- [ ] **Both:** Measure scams caught and false alarms on a set of examples nobody tuned the rules on.

## Permissions and privacy (Chrome Web Store)

- [ ] **B:** Access to all `http`/`https` websites: write the justification for the store listing, and check whether optional per-site access would be enough for any feature.
- [ ] **B:** `declarativeNetRequest`: needed for blocking known dangerous websites before they load. Write the justification.
- [ ] **Both:** Before adding a threat-lookup service or AI: update the README Privacy section with exactly what is sent, to whom, and when.
