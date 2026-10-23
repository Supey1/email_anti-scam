# Analyzer interface (schemaVersion 1)

The single contract between the browser integration (Person B) and the detection engine (Person A). The same input and output shapes are used for every webpage and every email. Change it only through a pull request that both people review.

## Input: evidence

The browser integration builds this object and passes it to the analyzer.

```js
{
  source: "webpage",                  // "webpage" | "email"
  pageUrl: "https://example.example/offer",
  pageTitle: "Claim Your Prize",
  visibleText: "Claim your reward now...",
  links: [
    { text: "Claim reward", url: "https://example.example/claim" }
  ],
  forms: [],                          // see below
  context: {}                         // source-specific extras, see below
}
```
(Sample data uses reserved `.example` domains.)

- `forms`: `{ action: string, hasPassword: boolean, hasPayment: boolean, method?: string, fieldCount?: number }`. **Never include values typed into any field.** Only that a sensitive field exists.
- `context` for `source: "email"`: `{ senderName, senderEmail, subject }`. `visibleText` holds the message text.
- `context` for `source: "webpage"`: the scanner sets `scan` (`"initial"` for the whole page, `"dynamic"` for newly added content only) and `truncated` (`{ text: boolean, links: boolean }`, true when a size limit cut something off). A dynamic scan's `visibleText`, `links` and `forms` hold only the new content; the browser side merges them before calling the analyzer, so the analyzer always sees the page so far.
- `context.ads` for `source: "webpage"`: advertisements the scanner recognized, as `{ signals: string[], text: string, link: { text, url } | null, frame: boolean }`. The scanner keeps an ad's text out of `visibleText`, so an ad is judged as an ad and does not make the whole page look suspicious. `context.adFrames` is `{ readable, unreadable }`: ad frames that were and were not readable (cross-origin frames can't be).
- For a single link click inside an ad, the guard passes the analyzer `{ ad: { text, signals } }` as context.
- Unknown extra fields are ignored by the analyzer.

## Output: result

```js
{
  schemaVersion: 1,
  verdict: "warn",
  reasons: [
    {
      code: "UNVERIFIED_PRIZE_CLAIM",
      title: "Unverified prize offer",
      explanation: "The page promises a prize that has not been verified."
    }
  ],
  recommendedAction: "VERIFY_INDEPENDENTLY",
  evidence: []
}
```

### Verdicts

| Verdict | Meaning |
|---|---|
| `block` | Strong, high-confidence threat evidence (for example, a destination on a verified threat list). |
| `warn` | Meaningful warning signs that call for caution. |
| `no_warning_signs` | The checks found no known warning signs. This is **never** presented as proof that a page is safe. |
| `unknown` | The analysis failed, the page is unsupported, or the checks were incomplete. |

### Entry point

`analyze(evidence)` in `extension/analyzer.js` is the one call for every adapter. `source: "webpage"` and `source: "email"` use it the same way. It never throws: a failure returns `verdict: "unknown"`.

For `source: "email"` the analyzer maps the email's rule score to a verdict: a high score (several strong signs together) is `block`, a medium score is `warn`, none is `allow` / `no_warning_signs`. An email can't be blocked, so for email `block` means "high-confidence combined evidence that this is a scam", and the interface shows the same DANGER wording with no continue option.

### Fields

- `reasons`: specific reasons, not just a score. `code` is a stable `UPPER_SNAKE_CASE` identifier; Person B chooses how each code is displayed. `title` is a short label and `explanation` is one plain sentence an older adult can follow. Empty for `no_warning_signs`.
- `recommendedAction`: one of `GO_BACK`, `VERIFY_INDEPENDENTLY`, `DO_NOT_ENTER_INFO`, `NONE`.
- `evidence`: `{ kind: string, detail: string }` entries for the specific things that triggered a reason (a URL, a form action). May be empty.
- A numeric score may be kept internally but is not part of the contract.

### Rules for adding a reason

Person A adds a new `code` to the analyzer and lists it in the table below. Person B maps it to the interface. Unknown codes must still display using `title` and `explanation`, so a new rule never needs a panel change to appear.

| Code | Meaning |
|---|---|
| `KNOWN_THREAT` | Destination is on a threat list. |
| `LOOKALIKE_DOMAIN` | Address imitates a known brand. |
| `HIDDEN_DESTINATION` | Link text names one site but goes to another. |
| `NUMBER_ADDRESS` | Link or page uses a raw IP address. |
| `CREDENTIALS_SENT_ELSEWHERE` | Password or card form submits to a different site. |
| `INSECURE_FORM` | Sensitive form without a secure connection. |
| `UNVERIFIED_PRIZE_CLAIM` | Prize offer whose claim button leads to an unverified site. |
| `SENDER_MISMATCH` | Sender name does not match the sender address. |
| `PRESSURE_OR_PAYMENT_WORDING` | Urgency, secrecy, gift-card or wire-transfer wording. |

## Messages

Extension parts talk with `chrome.runtime.sendMessage`. Every message has a `type` and a `schemaVersion`.

```js
// content script -> analyzer (service worker or shared module)
{ type: "ANALYZE", schemaVersion: 1, input: <evidence> }

// reply
{ type: "ANALYSIS_RESULT", schemaVersion: 1, result: <result> }

// reply on failure: still a valid result
{ type: "ANALYSIS_RESULT", schemaVersion: 1,
  result: { schemaVersion: 1, verdict: "unknown", reasons: [], recommendedAction: "NONE", evidence: [] } }
```

## Fixtures and mocks

- `tests/fixtures/inputs/*.json`: fixed evidence objects (for Person A).
- `tests/fixtures/results/*.json`: fixed result objects, one per verdict (for Person B).
