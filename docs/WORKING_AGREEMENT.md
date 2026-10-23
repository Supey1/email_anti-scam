# Working agreement

How the two of us build this together without stepping on each other.

## Who owns what

| | Workstream | Branch | Owns |
|---|---|---|---|
| **Person A** | Detection engine | `feature/detection-engine` | `extension/rules.js`, `extension/threat-list.js`, `tests/rules.test.js`, test fixtures, threat intelligence |
| **Person B** | Browser protection | `feature/browser-protection` | `extension/gmail.js`, `extension/page.js`, `extension/guard.js`, `extension/warning.js`, `extension/panel-styles.js`, `extension/service-worker.js`, `extension/blocked.html`, `extension/blocked.js`, `extension/manifest.json`, `tests/fake-gmail.html`, `tests/practice-*.html` |

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
   node tests/rules.test.js
   ```
   A feature that changes how clicks are stopped or how warnings appear also needs a browser test for that behavior.

6. **Keep a short shared checklist of integration issues** in [`integration-checklist.md`](integration-checklist.md). When something in the other person's area needs to change, add it to the checklist instead of editing their code.

7. **Chrome Web Store rules apply during development, not only at publication.** The Web Store requires accurate disclosure of data handling and the narrowest permissions the product needs. So:
   - Any pull request that changes `manifest.json` permissions or website access explains why the extension needs it and why something narrower won't work.
   - Any pull request that sends new data out of the browser (a threat lookup, AI) updates the README's Privacy section in the same pull request.
   - The scanner may record that a password or card field exists. It never reads what someone typed into it.

## The analyzer interface (current)

Everything lives in `extension/rules.js`. The full comments are at the top of that file and above each function.

**In: evidence (collected by Person B)**

| Function | Evidence |
|---|---|
| `analyzeEmail(email)` | `{ senderName, senderEmail, subject, bodyText, links: [{ text, href }] }` |
| `analyzeLink(link, context)` | `link = { text, href }`, `context = { pageUrl, nearbyText, surroundingLevel }` |
| `analyzePage(page)` | `{ url, title, headings, text, hasPassword, formActions }` |

**Out: result (returned by Person A)**

```js
{
  level: 'high' | 'medium' | 'low',
  action: 'block' | 'warn' | 'allow',
  confirmed: true | false,        // true only for a known dangerous website
  score: 7,                       // internal; don't show it to users
  reasons: ['plain sentence', ...],
  evidence: [{ points, text, kind }],  // kind: 'known_threat' | 'destination' | 'sender' | 'wording' | 'page' | 'context'
  // plus host / links / flags depending on the function
}
```

Person B decides what to do from `action` and displays `reasons`. Person B never adds up points or matches scam words itself.

**Not yet good enough for rule 2.** Reasons don't have a stable code yet, so Person B can't choose how a specific reason appears without matching on its sentence. Adding one is the first item in the integration checklist.

**Changing the interface** takes a pull request that both of us review. Update this section in the same pull request.
