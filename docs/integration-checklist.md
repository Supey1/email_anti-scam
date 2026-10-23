# Integration checklist

Short and shared. When something in the other person's area needs to change, add it here instead of editing their code. Tick it off when the fix is merged with its tests.

## Decide first

- [ ] **Both:** Two versions of the same features exist: `claude/friendly-mayer-hx20bc` (`rules.js` + `warning.js` + `gmail.js`) and `claude/new-session-yy3c1k` (`analyzer.js` + `panel.js` + `docs/interfaces.md`). Pick one as the base, carry over anything worth keeping from the other, and delete the other branch. Don't merge both.

## Analyzer interface

- [ ] **A:** Give each reason a stable code (for example `{ code: 'LOOKALIKE_DOMAIN', text, kind, points }`) so Person B can decide how each reason looks without matching on its sentence. Keep `text` as the fallback, so a new rule still shows up without an interface change.
- [ ] **A:** Add static JSON fixtures of collected evidence (`tests/fixtures/evidence/*.json`) and run them in `tests/rules.test.js`.
- [ ] **B:** Add fixed mock results (`tests/fixtures/results/block.json`, `warn.json`, `allow.json`) for building and testing the warning interface without the analyzer.
- [ ] **B:** Once codes exist, `warning.js` and the Gmail panel choose the wording or icon per code, falling back to `text`.

## Tests

- [ ] **B:** Commit a browser test proving a risky click is stopped before navigation, including a click inside an ad frame and a typed known-dangerous address. (This was checked by hand in Chromium, but the test isn't in the repo yet.)
- [ ] **B:** Test the less common ways of opening a link: right-click "Open in new tab", keyboard, pages that navigate with their own code.
- [ ] **Both:** Measure scams caught and false alarms on a set of examples nobody tuned the rules on.

## Permissions and privacy (Chrome Web Store)

- [ ] **B:** Access to all `http`/`https` websites: write the justification for the store listing, and check whether optional per-site access would be enough for any feature.
- [ ] **B:** `declarativeNetRequest`: needed for blocking known dangerous websites before they load. Write the justification.
- [ ] **Both:** Before adding a threat-lookup service or AI: update the README Privacy section with exactly what is sent, to whom, and when.
