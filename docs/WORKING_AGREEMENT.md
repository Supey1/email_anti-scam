# Working agreement

How the two of us build this together without stepping on each other.

## Who owns what

Neither person blocks the other because both build against the Phase 0 contract ([`interfaces.md`](interfaces.md)) and its fixtures, not against each other's code.

### Person A: detection and security (`feature/detection-engine`)

Owns URL analysis, domain rules, the risk policy, explanations, the automated detection tests, and threat intelligence and network blocking.

| Files | What |
|---|---|
| `extension/core/` | The engine: addresses, domain rules, wording rules, risk policy, explanations, analyzer |
| `extension/rules.js` | The engine's front door (`analyze()`) |
| `extension/data/` | Facts the engine uses, kept apart from the rules: companies and their official websites, email services and ad networks, web-address lists, the known-threat list |
| `extension/service-worker.js`, `extension/background/` | Threat lookups, Chrome's blocking rules, settings storage, and registering page scripts |
| `extension/threat-sync.js` | Hands the service worker's threat list to the engine in each page |
| `tests/rules.test.js`, `tests/regression.test.js` + `tests/fixtures/regression/`, `tests/robustness.test.js`, `tests/service-worker.test.js`, `docs/regression-cases.md`, `docs/threat-intelligence.md` | Detection and security tests, and their documents |

### Person B: browser protection and the interface (`feature/browser-protection`)

Proposed from the earlier split; confirm it when you write Person B's part of the division.

| Files | What |
|---|---|
| `extension/guard.js`, `extension/page.js`, `extension/gmail.js` | Collect evidence (clicks, pages, Gmail) and call `analyze()` |
| `extension/warning.js`, `extension/panel-styles.js`, `extension/blocked.html`, `extension/blocked.js` | How warnings look and behave |
| `extension/settings.html`, `extension/settings.js`, `extension/speech.js`, `extension/settings-sync.js` | Settings and welcome page, reading aloud, text size |
| `extension/manifest.json` | Permissions and the extension's description |
| `tests/speech.test.js`, `tests/fake-gmail.html`, `tests/practice-*.html` | Interface tests and practice pages |

### Shared (changed only by a pull request both review)

`docs/interfaces.md`, `tests/contract.js`, `tests/fixtures/inputs/` and `results/`, `tests/browser/acceptance.test.js` (it tests both halves together), this file, and `docs/integration-checklist.md`.

### Where the two meet

- **Which page scripts run where:** the service worker registers them (`background/content-scripts.js`, Person A), but which scripts and in what order is Person B's call. Person B asks on the checklist; Person A changes `BASE` there.
- **New reasons:** Person A adds the code to `interfaces.md` and returns it; Person B decides how it looks (rule 2).
- **New evidence:** Person B adds a field to the input contract by pull request; Person A starts using it.

## The rules

1. **One feature branch per workstream**, for example `feature/detection-engine` and `feature/browser-protection`. Nobody makes overlapping changes directly on the main branch.

2. **Person A never edits Person B's warning interface to add a rule.** To add a rule, Person A returns a new structured reason through the agreed analyzer interface. Person B then decides how that reason appears in the interface.

3. **Person B never writes its own scam-scoring logic** in the content scripts (`gmail.js`, `page.js`, `guard.js`) or the warning interface. Person B collects evidence, passes it to the shared analyzer, and displays what comes back.

4. **Nobody waits for the other person.**
   - Until Person A's analyzer is ready, Person B develops against **fixed mock results**.
   - Until Person B's webpage scanner is ready, Person A develops against **static JSON fixtures**.

5. **Every completed feature includes its relevant tests, and is merged only when those tests pass.** Today that means:
   ```
   node tests/contract.test.js
   node tests/rules.test.js
   ```
   A feature that changes how clicks are stopped or how warnings appear also needs a browser test for that behavior.

6. **Keep a short shared checklist of integration issues** in [`integration-checklist.md`](integration-checklist.md). When something in the other person's area needs to change, add it to the checklist instead of editing their code.

7. **Chrome Web Store rules apply during development, not only at publication.** The Web Store requires accurate disclosure of data handling and the narrowest permissions the product needs. So:
   - Any pull request that changes `manifest.json` permissions or website access explains why the extension needs it and why something narrower won't work.
   - Any pull request that sends new data out of the browser (a threat lookup, AI) updates the README's Privacy section in the same pull request.
   - The scanner may record that a password or card field exists. It never reads what someone typed into it.

## The analyzer interface

The contract is [`interfaces.md`](interfaces.md): the input (evidence), the output (result), what each verdict means, the reason codes, and the exact message formats. Phase 0 is agreeing on it, together, before either of us builds on a feature branch. Confirm the "Decisions to confirm" list at the bottom of that file first.

After that:
- Person A builds and tests the engine against the fixed inputs in `tests/fixtures/inputs/`.
- Person B builds the interface and the browser behavior against the fixed results in `tests/fixtures/results/`.
- Any change to the contract is a pull request that both of us review, with `interfaces.md`, the fixtures, and `tests/contract.js` updated together.

**The current code doesn't follow the contract yet.** It was written before Phase 0. Moving it over is listed in [`integration-checklist.md`](integration-checklist.md), split between A and B.
