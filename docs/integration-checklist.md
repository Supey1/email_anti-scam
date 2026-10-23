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

- [x] **A (Phase 5):** Chrome rules for `KNOWN_THREAT_URLS`: that address and everything below it, nothing else on the website.
- [x] **A (Phase 5):** only trusted entries become Chrome hard blocks.
- [ ] **B:** `page.js` should send `hasPaymentField` for card-number boxes, so payment pages get the same checks as sign-in pages (free hosting, sent elsewhere, sent without encryption).

## Phase 3: connecting the branches

- [ ] **Both:** The two `docs/interfaces.md` files disagree. Running the other branch's real `page-scanner.js` output through this branch's contract checker gives 7 problems on a sign-in page:
  - `forms[].hasPayment` there, `hasPaymentField` here (the engine accepts both for now). Suggestion: keep `hasPayment`, because the scanner and its tests already use it, and only the doc, `tests/contract.js`, and fixtures change here.
  - `forms[].method` and `forms[].fieldCount`: add them to the contract as optional.
  - `context.scan` and `context.truncated` (webpage): add them as optional.
  - `context.mainHeadings`: the scanner doesn't send it. The engine copes (title only), but headings make fake sign-in pages easier to spot.
  - `visibleText` length: the scanner sends up to 40,000 characters. The contract now allows 50,000.
- [ ] **B (this branch):** `page.js` reads only the first 5,000 characters of a page, so a scam pop-up added to the end of a LONG page is missed. The engine reads up to 50,000. Shown as a KNOWN ISSUE by `tests/browser/acceptance.test.js`; turn it into a normal test once fixed. (The other branch's scanner doesn't have this problem.)
- [ ] **B:** When a remote lookup is added, follow "Remote lookups" in `docs/interfaces.md`: hold the click when `whenToLookUp()` says `before_opening`, show "Checking this link…", and never let a slow or failed lookup open the link by itself.

## Phase 5: service worker and threat lookups (A built the service worker)

- [ ] **B (please review):** to support the service worker, A touched B's files: `manifest.json` (added the `storage` permission and `threat-sync.js`), and `blocked.html` / `blocked.js` (they can now show any analyzer result from `OPEN_WARNING_PAGE`: title, reasons, and "Open it anyway" for a warning only). Restyle or replace with your warning page as you see fit; keep the `?t=` token flow.
- [ ] **B:** `guard.js`: when `whenToLookUp(result)` says `before_opening` and remote lookups are on, hold the click, show "Checking this link…", send `LOOKUP_URL`, and pass the answer to `analyze(input, { lookup })`. On `error`, show the local warning and let the person choose: never open the link by itself, and never say it was "checked" or "safe".
- [ ] **B:** consider `OPEN_WARNING_PAGE` for `block` results: a website can hide or fake an in-page warning, but not the extension's own page.
- [x] **A (Phase 6):** the settings page (`settings.html`): protection on/off, website access, reading and text, permissions explained, the false-positive list. Remote lookups get a switch only once a real provider is chosen.
- [ ] **Both:** choose the threat-intelligence provider and privacy model (`docs/threat-intelligence.md`) before adding one.

## Phase 6: permissions, settings, and reading aloud (A, touching B's files: please review)

- [ ] **B (please review):** page scripts are no longer in `manifest.json`. The service worker registers them (`background/content-scripts.js`) only for the website access the person has given, and removes them when protection is off or access is taken away. To add or move a page script, change `BASE` / `desiredScripts()` there, not the manifest.
- [ ] **B (please review):** reading aloud now goes through `speech.js` in `warning.js`, `gmail.js`, and `blocked.js` (one "Read to me" / "Stop reading" button, no restart when a panel redraws, a visible message when speech fails). Text size comes from `settings-sync.js` (`zoom` on the warning, the Gmail panel, and the warning page). The practice pages load the two new files.
- [ ] **B:** the Gmail panel and the in-page warning could use the extension's warning page for `block` results (not changed).

## Phase 7: what testing found (A)

Fixed in the engine, each with a regression case in `tests/fixtures/regression/`:
- [x] False stops on scam-awareness newsletters (a bank's "we'll never ask for gift cards", a senior center's scam alert) and false notes on real bank alerts, marketing deadlines, and tracked newsletter links.
- [x] Missed or under-rated: link text showing a company's real website but going elsewhere, other-alphabet look-alikes, misspellings inside longer names, the "refund" scam, "your PC may be at risk" ads, "Hi Mom, new number".
- [x] Explanations: "a the Post Office", "a Apple", "real prizes" on delivery fees, duplicate gift-card reasons, the fee-before-or-after-prize wording.
- [x] Security: a 1 MB link text could freeze the checks for about half an hour (a scam email could freeze the Gmail tab); invisible and full-width letters could hide a company name; "nothing to check" was reported as "no warning signs" instead of "unknown".

For B:
- [x] **B (verified in the browser):** a hostile email's sender name, subject, and link text show as plain text in the panel and the warning (no HTML runs).
- [ ] **B:** `page.js` still cuts page text at 5,000 characters (the KNOWN ISSUE in the browser test).

## Tests

- [x] **Both:** Browser test proving a risky click is stopped before the browser asks for the address, including a click inside an ad frame and a typed known-dangerous address: `tests/browser/acceptance.test.js` (Phase 3 acceptance).
- [ ] **B:** Test the less common ways of opening a link: right-click "Open in new tab", keyboard, pages that navigate with their own code.
- [ ] **Both:** Measure scams caught and false alarms on a set of examples nobody tuned the rules on.

## Permissions and privacy (Chrome Web Store)

- [ ] **B:** Access to all `http`/`https` websites: write the justification for the store listing, and check whether optional per-site access would be enough for any feature.
- [ ] **B:** `declarativeNetRequest`: needed for blocking known dangerous websites before they load. Write the justification.
- [ ] **Both:** Before adding a threat-lookup service or AI: update the README Privacy section with exactly what is sent, to whom, and when.
