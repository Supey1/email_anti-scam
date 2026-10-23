# Working agreement

How the two of us build this together without stepping on each other.

## Who owns what

Neither person blocks the other because both build against the Phase 0 contract ([`interfaces.md`](interfaces.md)) and its fixtures, not against each other's code.

### Person A: detection and security (`feature/detection-engine`)

Owns URL analysis, domain rules, the risk policy, explanations, the automated detection tests, and threat intelligence and network blocking.

| Files | What |
|---|---|
| `extension/core/` | The engine: addresses, domain rules, wording rules, risk policy, explanations, analyzer |
| `extension/rules.js` | The engine's front door (`analyze()`, and the helpers the screens use: `checkWebpage`, `checkLinkClick`, `checkEmail`, `stopsPerson`) |
| `extension/data/` | Facts the engine uses, kept apart from the rules: companies and their official websites, email services and ad networks, web-address lists, the known-threat list |
| `extension/service-worker.js`, `extension/background/` | Threat lookups, Chrome's blocking rules, settings storage, and registering page scripts |
| `extension/threat-sync.js` | Hands the service worker's threat list to the engine in each page |
| `tests/rules.test.js`, `tests/regression.test.js` + `tests/fixtures/regression/`, `tests/robustness.test.js`, `tests/service-worker.test.js`, `tests/screens.test.js`, `tests/browser/blocking.test.js`, `docs/regression-cases.md`, `docs/threat-intelligence.md` | Detection and security tests, and their documents |

### Person B: browser protection and the interface (`feature/browser-protection`)

Owns collecting evidence, stopping clicks, and everything the person sees. (These are Person B's own files from the merge; Person A's earlier screens were retired in their favor.)

| Files | What |
|---|---|
| `extension/content/` (`page-scanner.js`, `ad-signals.js`, `click-guard.js`, `gmail-adapter.js`, `gmail.js`), `extension/page.js` | Collect evidence (pages, ads, clicks, Gmail) and call the engine |
| `extension/ui/` (`explain.js`, `warning-view.js`, `warning.html` + `warning.js`, `popup.*`, `options.*`, `status.js`, `ui.css`), `extension/panel.js`, `extension/panel-styles.js` | How warnings look and behave; the popup and the settings and welcome page; reading aloud and text size |
| `extension/settings.js` | The person's choices, shared by every part |
| `extension/manifest.json` | Permissions and the extension's description |
| `tests/browser/` (except `blocking.test.js`), `tests/explain.test.js`, `tests/settings.test.js`, `tests/scanner-merge.test.js`, `tests/metrics.js` + `tests/corpus/`, `tests/usability-*`, `tests/pages/`, `tests/fake-gmail.html`, `docs/testing.md`, `docs/usability-*.md`, `docs/ad-support-matrix.md`, `docs/click-guard-limits.md` | Interface and browser tests, practice pages, accuracy and usability measures |

### Shared (changed only by a pull request both review)

`docs/interfaces.md`, `tests/contract.js`, `tests/fixtures/inputs/` and `results/`, `tests/browser/harness.js` (every browser test uses it), `tests/run-all.js`, `package.json`, this file, and `docs/integration-checklist.md`.

### Where the two meet

- **Which page scripts run where:** the service worker registers them (`background/content-scripts.js`, Person A), but which scripts and in what order is Person B's call. Person B asks on the checklist; Person A changes the lists there.
- **The service worker's messages for the screens** (`SHOW_WARNING`, `CONTINUE`, `REPORT_FALSE_ALARM`) live in `background/messages.js` (Person A); what they do is Person B's call.
- **New reasons:** Person A adds the code to `interfaces.md` and returns it; Person B decides how it looks (rule 2).
- **New evidence:** Person B adds a field to the input contract by pull request; Person A starts using it.

## The rules

1. **One feature branch per workstream**, for example `feature/detection-engine` and `feature/browser-protection`. Nobody makes overlapping changes directly on the main branch.

2. **Person A never edits Person B's warning interface to add a rule.** To add a rule, Person A returns a new structured reason through the agreed analyzer interface. Person B then decides how that reason appears in the interface.

3. **Person B never writes its own scam-scoring logic** in the content scripts (`content/*.js`, `page.js`) or the warning interface. Person B collects evidence, passes it to the shared analyzer, and displays what comes back. (Before the merge, Person B's branch had a temporary analyzer of its own; it's gone.)

4. **Nobody waits for the other person.**
   - Until Person A's analyzer is ready, Person B develops against **fixed mock results**.
   - Until Person B's webpage scanner is ready, Person A develops against **static JSON fixtures**.

5. **Every completed feature includes its relevant tests, and is merged only when those tests pass.** Today that means:
   ```
   npm test                 # everything (browser tests need Playwright: npm install)
   npm run test:fast        # everything that doesn't need a browser
   ```
   A feature that changes how clicks are stopped or how warnings appear also needs a browser test for that behavior. Changes to rules or wording also re-run `node tests/metrics.js`: detection must not rise by letting false alarms rise.

6. **Keep a short shared checklist of integration issues** in [`integration-checklist.md`](integration-checklist.md). When something in the other person's area needs to change, add it to the checklist instead of editing their code.

7. **Chrome Web Store rules apply during development, not only at publication.** The Web Store requires accurate disclosure of data handling and the narrowest permissions the product needs. So:
   - Any pull request that changes `manifest.json` permissions or website access explains why the extension needs it and why something narrower won't work.
   - Any pull request that sends new data out of the browser (a threat lookup, AI) updates the README's Privacy section in the same pull request.
   - The scanner may record that a password or card field exists. It never reads what someone typed into it.

8. **Manifest V3.** Content scripts inspect pages, the service worker handles extension events, and `declarativeNetRequest` blocks or redirects matching requests. The service worker can stop when idle, so keep persistent state in storage, never only in memory.

9. **Be honest in wording.** `no_warning_signs` is never described as "safe". Do not claim an interception works until it has been tested for that navigation path.


## The analyzer interface

The contract is [`interfaces.md`](interfaces.md): the input (evidence), the output (result), what each verdict means, the reason codes, and the exact message formats. Phase 0 is agreeing on it, together, before either of us builds on a feature branch. Confirm the "Decisions to confirm" list at the bottom of that file first.

After that:
- Person A builds and tests the engine against the fixed inputs in `tests/fixtures/inputs/`.
- Person B builds the interface and the browser behavior against the fixed results in `tests/fixtures/results/`.
- Any change to the contract is a pull request that both of us review, with `interfaces.md`, the fixtures, and `tests/contract.js` updated together.

Both branches were merged into one (`claude/friendly-mayer-hx20bc`) and now follow the contract. What changed for each person is in [`integration-checklist.md`](integration-checklist.md) ("The merge").
