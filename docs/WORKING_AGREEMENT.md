# Working agreement

How the two of us build this together without stepping on each other.

## Who owns what

| | Workstream | Branch | Owns |
|---|---|---|---|
| **Person A** | Detection engine | `feature/detection-engine` | `extension/rules.js`, `extension/core/*.js`, `extension/threat-list.js`, `extension/threat-sync.js`, `tests/rules.test.js`, test fixtures, threat intelligence: `extension/service-worker.js`, `extension/background/*.js`, `tests/service-worker.test.js` (from Phase 5); permissions, storage, settings, and reading aloud: `extension/settings.*`, `extension/speech.js`, `extension/settings-sync.js`, `tests/speech.test.js` (from Phase 6) |
| **Person B** | Browser protection | `feature/browser-protection` | `extension/gmail.js`, `extension/page.js`, `extension/guard.js`, `extension/warning.js`, `extension/panel-styles.js`, `extension/blocked.html`, `extension/blocked.js`, `extension/manifest.json`, `tests/fake-gmail.html`, `tests/practice-*.html` |

The analyzer interface (below) belongs to both of us. Neither person changes it alone.

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
