# Integration checklist

Short and shared. When something in the other person's area needs to change, add it here instead of editing their code. Tick it off when the fix is merged with its tests.

## Decide first

- [ ] **Both:** Two versions of the same features exist: `claude/friendly-mayer-hx20bc` (`rules.js` + `warning.js` + `gmail.js`) and `claude/new-session-yy3c1k` (`analyzer.js` + `panel.js` + `docs/interfaces.md`). Pick one as the base, carry over anything worth keeping from the other, and delete the other branch. Don't merge both.

## Phase 0: the contract (`docs/interfaces.md`)

- [ ] **Both:** Confirm the "Decisions to confirm" list at the bottom of `interfaces.md`. Nothing below starts until this is done.
- [x] **Both:** Fixed inputs (`tests/fixtures/inputs/`) and fixed results (`tests/fixtures/results/`), checked by `node tests/contract.test.js`.

## Moving the current code to the contract

The code was written before the contract. Today `rules.js` takes three different input shapes and returns `level` / `action` / `score` / plain-sentence `reasons`.

- [ ] **A:** One entry point, `analyze(input)`, taking the contract input for all three sources. It returns the contract result and never throws (`unknown` on failure). Keep `analyzeEmail` / `analyzeLink` / `analyzePage` internal, or remove them.
- [ ] **A:** Every reason returns `{ code, title, explanation }` using the codes in the table. Remove `score` and `level` from the output.
- [ ] **A:** Map the old actions to verdicts: `block` → `block` + `GO_BACK`; strong `warn` → `warn` + `GO_BACK` (links, email) or `DO_NOT_ENTER_INFO` (pages); weak signs (today's "medium") → `warn` + `VERIFY_INDEPENDENTLY`; nothing → `no_warning_signs` + `NONE`.
- [ ] **A:** Return `evidence` items `{ kind, value, reasonCode }`.
- [ ] **A:** Pair each input fixture with the result it should get, and test the engine's real output with `validateResult` from `tests/contract.js`.
- [ ] **B:** `gmail.js`, `page.js`, and `guard.js` build the contract input (`source`, `pageUrl`, `pageTitle`, `visibleText`, `links[].url`, `forms[]`, `context`) and call `analyze()`. `page.js` sends `forms` as `{ action, hasPassword, hasPaymentField }` instead of `hasPassword` / `formActions`.
- [ ] **B:** `guard.js` and `page.js` interrupt only for `GO_BACK` / `DO_NOT_ENTER_INFO`, never by reading reason codes or counting reasons.
- [ ] **B:** `warning.js` and the Gmail panel show `title` / `explanation` per reason, may style by `code`, and show unknown codes from `title` / `explanation`. Gmail says "No warning signs found", never "safe". `unknown` is not shown as no warning signs.
- [ ] **B:** Rename the frame-to-main-page message from `granblock-warning` to `SHOW_WARNING` / `SHOW_WARNING_RESULT` with `schemaVersion` and `navigation`.
- [ ] **B:** Test the scanner's real output with `validateInput` from `tests/contract.js`, including that no field values are ever collected.

## Tests

- [ ] **B:** Commit a browser test proving a risky click is stopped before navigation, including a click inside an ad frame and a typed known-dangerous address. (This was checked by hand in Chromium, but the test isn't in the repo yet.)
- [ ] **B:** Test the less common ways of opening a link: right-click "Open in new tab", keyboard, pages that navigate with their own code.
- [ ] **Both:** Measure scams caught and false alarms on a set of examples nobody tuned the rules on.

## Permissions and privacy (Chrome Web Store)

- [ ] **B:** Access to all `http`/`https` websites: write the justification for the store listing, and check whether optional per-site access would be enough for any feature.
- [ ] **B:** `declarativeNetRequest`: needed for blocking known dangerous websites before they load. Write the justification.
- [ ] **Both:** Before adding a threat-lookup service or AI: update the README Privacy section with exactly what is sent, to whom, and when.
