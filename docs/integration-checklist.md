# Integration checklist

Short and shared. When something in the other person's area needs to change, add it here instead of editing their code. Tick it off when the fix is merged with its tests.

## Decide first

- [x] **Both:** Two versions of the same features existed. Decision (see "Merge of the two builds" below): the detection engine, background, settings page and contract come from `claude/friendly-mayer-hx20bc` (main); the browser layer (scanner, click guard, Gmail adapter, warning interface, popup) and the test, metrics, and usability work come from `claude/new-session-yy3c1k`, rewired to the engine's `analyze()`. The older `analyzer.js`, `threats.js`, `settings.js` (mine), `guard.js`, `warning.js`, and the first `gmail.js` are gone.

## Merge of the two builds (what changed, and what to review)

- [ ] **A (please review):** B touched A's files, additively: `background/messages.js` now accepts `newTab` and `linkText` on `OPEN_WARNING_PAGE` (a click that would open a new tab gets the warning in a new tab; the warning page shows what the link said next to where it really goes) and a new `REPORT_FALSE_ALARM` message (a short note saved in `storage.local`, last 100). `background/content-scripts.js` lists the merged scripts. `tests/service-worker.test.js` has tests for all three. `docs/interfaces.md` documents them.
- [x] The engine's input is now exactly what `tests/contract.js` allows: the scanner reports only forms with a password or card box (`hasPaymentField`), `context.mainHeadings`, and nothing else. Advertisements are no longer reported separately; their words are part of the page text and the words around a clicked link go in `context.nearbyText`.
- [ ] **A:** Engine false alarm that interrupts (found by testing): an anti-scam newsletter ("never pay with gift cards", "act now", "congratulations to our winner") with a member login gets `DO_NOT_ENTER_INFO`. The text rules read "never pay with gift cards" as a payment demand. Corpus case `L-P11`, page `tests/pages/fake-legitimate-advice.html`, test "KNOWN FALSE POSITIVE". Fix it, then set `interruptedLegitimateMax` in `tests/metrics.js` to 0 and flip the test.
- [ ] **A:** Weak warnings (`VERIFY_INDEPENDENTLY`) on legitimate cases are common (about 4 in 10 in the labelled set: real senders' wording, shortened and tracking links). They never interrupt, but see `docs/findings.md` for candidates.
- [ ] **A:** Hard scams with no usual wording are not flagged (6 of 8 in the labelled set).
- [ ] **Both:** Lost in the merge on purpose: my per-website on/off lists and the "only websites I choose" mode (website access is now Chrome's optional permission, which is narrower), and the settings page I wrote (main's `settings.html` is the one). The popup replaces the per-site toggle with "Open Settings" when access is missing.
- [ ] **B:** Not done: holding a click for a remote lookup (`whenToLookUp`), right-click "Open in new tab" (can't be tested by the test browser), a real screen reader, real Gmail, usability sessions with older adults (`docs/usability-testing.md`).

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
- [x] **B:** `gmail.js`, `page.js`, and `guard.js` build the contract input (`source`, `pageUrl`, `pageTitle`, `visibleText`, `links[].url`, `forms[]`, `context`) and call `analyze()`. `page.js` sends `forms` as `{ action, hasPassword, hasPaymentField }` instead of `hasPassword` / `formActions`.
- [x] **B:** `guard.js` and `page.js` interrupt only for `GO_BACK` / `DO_NOT_ENTER_INFO`, never by reading reason codes or counting reasons.
- [x] **B:** `warning.js` and the Gmail panel show `title` / `explanation` per reason, may style by `code`, and show unknown codes from `title` / `explanation`. Gmail says "No warning signs found", never "safe". `unknown` is not shown as no warning signs.
- [x] **B:** The old frame-to-main-page message is gone: the click guard runs in every frame and asks the service worker for the extension's own warning page (`OPEN_WARNING_PAGE`), which covers the whole tab. `SHOW_WARNING` is still answered by the service worker but nothing sends it.
- [x] **B:** Test the scanner's real output with `validateInput` from `tests/contract.js`, including that no field values are ever collected.

## Load order (A touched B's files: please review)

- [x] **B:** The engine's files load before `rules.js` in every list: `background/content-scripts.js` (BASE), `blocked.html`, `tests/fake-gmail.html`, and `tests/practice-*.html`.

## Phase 2: known threats (A changed `threat-list.js`; B's blocking needs to follow)

- [x] **A (Phase 5):** Chrome rules for `KNOWN_THREAT_URLS`: that address and everything below it, nothing else on the website.
- [x] **A (Phase 5):** only trusted entries become Chrome hard blocks.
- [x] **B:** `page.js` should send `hasPaymentField` for card-number boxes, so payment pages get the same checks as sign-in pages (free hosting, sent elsewhere, sent without encryption).

## Phase 3: connecting the branches

- [ ] **Both:** The two `docs/interfaces.md` files disagree. Running the other branch's real `page-scanner.js` output through this branch's contract checker gives 7 problems on a sign-in page:
  - `forms[].hasPayment` there, `hasPaymentField` here (the engine accepts both for now). Suggestion: keep `hasPayment`, because the scanner and its tests already use it, and only the doc, `tests/contract.js`, and fixtures change here.
  - `forms[].method` and `forms[].fieldCount`: add them to the contract as optional.
  - `context.scan` and `context.truncated` (webpage): add them as optional.
  - `context.mainHeadings`: the scanner doesn't send it. The engine copes (title only), but headings make fake sign-in pages easier to spot.
  - `visibleText` length: the scanner sends up to 40,000 characters. The contract now allows 50,000.
- [x] **B (this branch):** `page.js` reads only the first 5,000 characters of a page, so a scam pop-up added to the end of a LONG page is missed. The engine reads up to 50,000. Shown as a KNOWN ISSUE by `tests/browser/acceptance.test.js`; turn it into a normal test once fixed. (The other branch's scanner doesn't have this problem.)
- [ ] **B:** When a remote lookup is added, follow "Remote lookups" in `docs/interfaces.md`: hold the click when `whenToLookUp()` says `before_opening`, show "Checking this link…", and never let a slow or failed lookup open the link by itself.

## Phase 5: service worker and threat lookups (A built the service worker)

- [ ] **B (please review):** to support the service worker, A touched B's files: `manifest.json` (added the `storage` permission and `threat-sync.js`), and `blocked.html` / `blocked.js` (they can now show any analyzer result from `OPEN_WARNING_PAGE`: title, reasons, and "Open it anyway" for a warning only). Restyle or replace with your warning page as you see fit; keep the `?t=` token flow.
- [ ] **B:** `content/click-guard.js`: when `whenToLookUp(result)` says `before_opening` and remote lookups are on, hold the click, show "Checking this link…", send `LOOKUP_URL`, and pass the answer to `analyze(input, { lookup })`. On `error`, show the local warning and let the person choose: never open the link by itself, and never say it was "checked" or "safe".
- [ ] **B:** consider `OPEN_WARNING_PAGE` for `block` results: a website can hide or fake an in-page warning, but not the extension's own page.
- [x] **A (Phase 6):** the settings page (`settings.html`): protection on/off, website access, reading and text, permissions explained, the false-positive list. Remote lookups get a switch only once a real provider is chosen.
- [ ] **Both:** choose the threat-intelligence provider and privacy model (`docs/threat-intelligence.md`) before adding one.

## Phase 6: permissions, settings, and reading aloud (A, touching B's files: please review)

- [x] **B:** page scripts are registered by the service worker (`background/content-scripts.js`). `BASE` and `desiredScripts()` now list the merged scripts (`content/*`, `ui/*`, `panel.js`, `page.js`); `tests/service-worker.test.js` checks every listed file exists.
- [x] **B:** reading aloud goes through `speech.js` in `ui/warning-view.js` (so in the in-page card, the Gmail panel, and `blocked.js`); text size comes from `settings-sync.js` (`card font-size = 24px x zoom`).
- [x] **B:** stopped clicks (warn and block) open the extension's own warning page; the in-page card is used for page-level warnings, the Gmail panel, and as a fallback if the extension can't be reached.

## Tests

- [x] **Both:** Browser test proving a risky click is stopped before the browser asks for the address, including a click inside an ad frame and a typed known-dangerous address: `tests/browser/acceptance.test.js` (Phase 3 acceptance).
- [x] **B:** Less common ways of opening a link are tested (`tests/browser/systematic.test.js`, `click-matrix.test.js`): keyboard, modified clicks, SVG, shadow DOM, frames, and pages that navigate with their own code. Right-click "Open in new tab" cannot be driven by the test browser; check it by hand.
- [ ] **Both:** Measure scams caught and false alarms on a set of examples nobody tuned the rules on.

## Permissions and privacy (Chrome Web Store)

- [ ] **B:** Access to all `http`/`https` websites: write the justification for the store listing, and check whether optional per-site access would be enough for any feature.
- [ ] **B:** `declarativeNetRequest`: needed for blocking known dangerous websites before they load. Write the justification.
- [ ] **Both:** Before adding a threat-lookup service or AI: update the README Privacy section with exactly what is sent, to whom, and when.
