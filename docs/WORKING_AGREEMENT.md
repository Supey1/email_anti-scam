# Working agreement

How the two of us build this together without stepping on each other.

| | Workstream | Owns |
|---|---|---|
| **Person A** | Detection engine | `rules.js`, `analyzer.js`, `threats.js`, rule tests, threat intelligence |
| **Person B** | Browser protection | `page.js`, `content.js` (Gmail extraction), `guard.js`, `panel.js`, `panel-styles.js`, `service-worker.js`, `blocked.*`, `manifest.json`, settings, accessibility, read-aloud |

## Rules

1. **One feature branch per workstream**, for example `feature/detection-engine` and `feature/browser-protection`. Nobody commits directly to the main branch.
2. **Stay in your lane.** Person A never edits Person B's warning-panel code to add a rule. Person A returns a new structured reason through the analyzer interface, and Person B decides how that reason looks.
3. **No second scoring engine.** Person B never writes scam-scoring logic in `content.js` (or `page.js`, `guard.js`, or the panel). Collect evidence, pass it to the shared analyzer, and display what comes back.
4. **Never wait for each other.** Until the analyzer is ready, Person B develops against fixed mock results. Until the webpage scanner is ready, Person A develops against static JSON fixtures (`tests/fixtures/`).
5. **The contract is in `docs/interfaces.md`.** Changing it needs a pull request that both of us review. Bump `schemaVersion` for breaking changes.
6. **Tests before merge.** Every completed feature includes its tests and is merged only when they pass:
   ```
   node tests/rules.test.js
   node tests/analyzer.test.js
   node tests/scanner-merge.test.js
   node tests/browser/scanner.test.js   # needs Playwright: npm i playwright
   ```
   Add browser-level checks for anything that changes click interception or the warning interface.
7. **Keep a short shared checklist** of integration problems in `docs/integration-checklist.md` instead of making overlapping edits on the main branch.
8. **Privacy and permissions are part of development, not a publishing step.** The Chrome Web Store requires accurate disclosure of data handling and the narrowest permissions the features need. So:
   - Any change to `manifest.json` permissions or host access says why in the pull request.
   - Any new data leaving the browser (threat lookups, AI) is recorded in the README's Privacy section in the same pull request.
   - The scanner never collects values typed into password or other sensitive fields. It may record that a field exists, never what is in it.
9. **Manifest V3.** Content scripts inspect pages, the service worker handles extension events, and `declarativeNetRequest` blocks or redirects matching requests. The service worker can stop when idle, so keep persistent state in storage, never only in memory.
10. **Be honest in wording.** `no_warning_signs` is never described as "safe". Do not claim an interception works until it has been tested for that navigation path.

## Order of execution

1. Agree on the analyzer input/output contract and write `docs/interfaces.md`.
2. A builds the analyzer and automated rule tests; B builds generic webpage extraction against mock results.
3. A finishes URL and domain rules; B builds click interception and the warning interface.
4. Integrate both and prove that a suspicious click is stopped before navigation.
5. Add Gmail as one adapter inside the same architecture, not a separate product.
6. Expand to advertisements and dynamic page content, then add browser-level blocking and a real threat-intelligence provider.
7. Add settings, permission handling, accessibility, and read-aloud.
8. Run the full automated and browser test suites, fix false positives, and run usability tests with older adults.
9. Finish the demo, verify every privacy claim, and update the README to match what is actually implemented.

## Phase 0 (both of us, before splitting)

Agree on one data structure connecting the webpage scanner, the detection engine, and the warning interface. It is recorded in [`interfaces.md`](interfaces.md). Both workstreams build against it from day one.
