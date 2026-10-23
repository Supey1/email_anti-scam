# Analyzer interface (schemaVersion 1)

The one contract between the three parts of the extension:

```
webpage scanner / Gmail reader / click guard   (Person B)
        │  input: evidence
        ▼
detection engine                                (Person A)
        │  output: result
        ▼
warning interface                               (Person B)
```

Every website, link, and email uses the same input shape and the same output shape. **Changes to this file go through a pull request that both people review.** A change that would break existing code also bumps `schemaVersion`.

Sample data uses reserved `.example` domains, which can never be real websites.

---

## 1. Input: evidence

Built by the browser integration (Person B) and passed to the detection engine (Person A).

```js
{
  source: "webpage",                        // "webpage" | "email" | "link"
  pageUrl: "https://example.example/offer", // the address of the page the person is on
  pageTitle: "Claim Your Prize",
  visibleText: "Claim your reward now...",   // what the person can see, up to 50,000 characters
  links: [
    { text: "Claim reward", url: "https://example.example/claim" }
  ],
  forms: [],
  context: {}
}
```

### Fields

| Field | Type | Required | Meaning |
|---|---|---|---|
| `source` | `"webpage"` \| `"email"` \| `"link"` | yes | What is being checked (see below). |
| `pageUrl` | string | yes | Full address of the page the person is on. `""` if there isn't one (for example, a practice page opened as a file). |
| `pageTitle` | string | yes | The page's title. `""` if none. |
| `visibleText` | string | yes | Visible words only (no hidden text, no code), up to 50,000 characters. Text that appears later (pop-ups) goes at the END, so never cut it off to make room: on a long page that is exactly where the scam is. For email: the message text. |
| `links` | array of `{ text, url }` | yes | Links on the page or in the email. `text` is the link's words (or a picture's description); `url` is the link's address exactly as the page has it. May be `[]`. |
| `forms` | array of form objects | yes | Forms that ask for something sensitive. May be `[]`. |
| `context` | object | yes | Extras for one `source`. May be `{}`. |

### `forms[]`

```js
{ action: "https://collect.example/p.php", hasPassword: true, hasPaymentField: false }
```

| Field | Meaning |
|---|---|
| `action` | Full address the form sends what you type to. Use `pageUrl` if the form doesn't say. |
| `hasPassword` | The form has a password box. |
| `hasPaymentField` | The form has a box for a card number, card security code, or bank account number. |

**Privacy rule: the scanner never collects anything a person typed or chose in any field.** It records only that a sensitive field *exists*. No form object, and nothing else in the input, may contain a field's value.

### `context` by source

**`source: "webpage"`**: a whole page.

```js
context: {
  mainHeadings: ["PayPal"]   // optional: text of the page's main (h1) headings, up to 3
}
```

**`source: "email"`**: an email open in Gmail. `pageUrl` is the Gmail address, `visibleText` is the message text, and `links` are the links inside the message.

```js
context: {
  senderName: "PayPal Security",
  senderEmail: "alerts@paypa1-secure.example",
  subject: "Your account has been suspended"
}
```

**`source: "link"`**: someone just clicked a link, and the click is on hold until the result comes back. `links` contains **exactly one** item: the clicked link. `pageUrl` and `pageTitle` describe the page the link is on.

```js
context: {
  nearbyText: "Congratulations! You have won a $2,000 gift card...", // words around the link, like the rest of an ad (up to 400 characters)
  insideFrame: true,           // the link is inside an ad or other frame
  surroundingResult: {         // optional: copied from the result for the email the link is in, if there is one
    verdict: "warn",
    recommendedAction: "GO_BACK"
  }
}
```

The analyzer ignores fields it doesn't know about. The scanner must not rely on that to send extra data: only the fields listed here are allowed.

---

## 2. Output: result

Returned by the detection engine (Person A) for every input.

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

### Fields

| Field | Type | Meaning |
|---|---|---|
| `schemaVersion` | `1` | The version of this contract. |
| `verdict` | `"block"` \| `"warn"` \| `"no_warning_signs"` \| `"unknown"` | See the verdict table. |
| `reasons` | array of reason objects | **Specific** reasons, strongest first. Never just a number. `[]` for `no_warning_signs` and `unknown`. |
| `recommendedAction` | action code | What the person should do. See the action table. |
| `evidence` | array of evidence objects | The exact things that triggered each reason. May be `[]`. |

A numerical risk score may be used inside the engine, but it is **not** part of the result, and the interface never shows one.

### Verdicts

| Verdict | Meaning | Interface must never... |
|---|---|---|
| `block` | Strong, high-confidence threat evidence, such as a destination on a list of known dangerous websites. | ...offer a way through. |
| `warn` | Meaningful warning signs that call for caution. | ...hide the reasons. |
| `no_warning_signs` | The checks found no known warning signs. | ...say or suggest the page or email is **safe**. Say "No warning signs found", never "Safe" or "Verified". |
| `unknown` | The analysis failed, the page isn't supported, or the checks couldn't finish. | ...treat it as `no_warning_signs`. |

### Reasons

```js
{ code: "LOOKALIKE_DOMAIN", title: "Fake company address", explanation: "This link pretends to be PayPal, but it goes to paypa1-secure.example." }
```

| Field | Meaning |
|---|---|
| `code` | Stable `UPPER_SNAKE_CASE` identifier from the reason-code table. Never renamed once in use. |
| `title` | A short label, a few words. |
| `explanation` | One plain sentence an older adult can follow, with the specific details (company name, website). |

**How a new rule reaches the screen:** Person A adds a code to the table below and returns it. Person B chooses how each code is shown (icon, wording, order). A code the interface doesn't know yet is still shown using its `title` and `explanation`, so **a new rule never needs an interface change to appear**.

### Recommended actions

| Code | Meaning | Interface behavior |
|---|---|---|
| `GO_BACK` | Don't go there. | Stop the click or cover the page. Big "Go back to safety" button. |
| `DO_NOT_ENTER_INFO` | Don't type passwords, card numbers, or personal details here. | Cover the page. Big "Leave this page" button. |
| `VERIFY_INDEPENDENTLY` | Check the claim another way (the company's real website, the number on your card) before acting. | Show the reasons **without** stopping a click. |
| `NONE` | Nothing to do. | Show nothing on webpages. In Gmail, "No warning signs found". |

Which actions go with which verdicts:

| Verdict | Allowed actions |
|---|---|
| `block` | `GO_BACK` |
| `warn` | `GO_BACK`, `DO_NOT_ENTER_INFO`, `VERIFY_INDEPENDENTLY` |
| `no_warning_signs` | `NONE` |
| `unknown` | `NONE` |

**Who decides whether to interrupt:** the engine, through `recommendedAction`. The interface stops a click or covers a page **only** for `GO_BACK` or `DO_NOT_ENTER_INFO`. It never looks at reason codes, counts reasons, or adds anything up to make that decision itself.

### Evidence

```js
{ kind: "url", value: "https://paypa1-secure.example/login", reasonCode: "LOOKALIKE_DOMAIN" }
```

| Field | Meaning |
|---|---|
| `kind` | `"url"`, `"domain"`, `"sender"`, `"text"`, or `"form"`. |
| `value` | The exact address, sender, phrase, or form address that triggered the reason. Never a typed value. |
| `reasonCode` | The `code` of the reason this evidence supports. |

### Reason codes

| Code | Tier | Used for | Meaning |
|---|---|---|---|
| `KNOWN_THREAT` | confirmed | all | The website, the exact address, or where a form sends what you type is on the list of known dangerous websites. From an untrusted source it is `strong` instead. |
| `LOOKALIKE_DOMAIN` | moderate | all | The address imitates a company: its name with extra words, swapped characters (`paypa1`), letters from another alphabet, a misspelling, or the company's real website written in front (`paypal.com.fake-domain.example`, which is `strong`). |
| `HIDDEN_DESTINATION` | moderate | email, link | The link's words show one website, but it goes to another. `weak` when the link goes through an email service or ad network, because we can't see where it ends up. |
| `BRAND_NAME_MISMATCH` | weak | email, link | The link or offer names a company, but goes somewhere else; or an email says it's from a company but none of its links go to that company's website (`moderate` when the email is an account, payment, or delivery notice). Links through email services and ad networks are not compared. |
| `MISLEADING_URL` | moderate | email, link | The address is written to look like a company's website (`paypal.com@evil.example`, which is `strong`, or a company's website in the path) but goes elsewhere. A sign-in name or password hidden in a link without a website name is `weak`. |
| `NUMBER_ADDRESS` | moderate | all | A raw number address instead of a website name. |
| `SHORTENED_LINK` | weak | email, link | A shortened link hides where it really goes. |
| `RISKY_DOMAIN_ENDING` | weak | all | A website ending often used by scam sites. |
| `FAKE_SIGN_IN_PAGE` | strong | webpage | A company's sign-in page that isn't on the company's website. |
| `SIGN_IN_ON_FREE_HOSTING` | moderate | link, webpage | A sign-in or payment page (or a sign-in link) on a free hosting website anyone can make. |
| `INSECURE_FORM` | weak | webpage | A password or card form sends what you type without encryption (`http:`). |
| `CREDENTIALS_SENT_ELSEWHERE` | moderate | webpage | A password or card form sends what you type to a different website. |
| `SENDER_NAME_MISMATCH` | moderate | email | The sender's name says a company, but the address isn't one of its own (`domainRules.BRANDS`). `moderate` for account, payment, or delivery notices and free personal accounts; `weak` for other messages; not reported for a newsletter sent through a known email service; `strong` when a company's address is written into the sender's NAME. |
| `LOOKALIKE_SENDER` | moderate | email | The sender's address imitates a company. |
| `COMPANY_ON_FREE_EMAIL` | weak | email | Claims to be a company or department, but uses a free personal address. |
| `PRIZE_CLAIM` | moderate | all | Says you won a prize or are owed money. |
| `UNVERIFIED_PRIZE_CLAIM` | weak | link, webpage | Promises a prize, and we can't confirm the destination belongs to the company in the offer. |
| `PRIZE_WITH_PRESSURE` | moderate | all | A prize plus rushing: a classic scam combination. |
| `PAY_TO_CLAIM` | moderate | all | Asks you to pay a fee first (to claim a prize, or a redelivery or customs fee), or pay with gift cards, crypto, or a wire transfer. |
| `PAYMENT_METHOD_REQUEST` | moderate | email | Mentions gift cards, wire transfers, or crypto. |
| `ACCOUNT_PROBLEM_CLAIM` | moderate | all | Says your account, card, or computer has a serious problem. |
| `CALL_THIS_NUMBER` | moderate | link, webpage | Tells you to call a number, or not to close the page. |
| `TECH_SUPPORT_CLAIM` | moderate | email | Talks about viruses or "tech support". |
| `PERSONAL_INFO_REQUEST` | moderate | email | Asks for account numbers, passwords, or similar. |
| `DELIVERY_PROBLEM_CLAIM` | moderate | all | Says your package couldn't be delivered, is on hold, or needs a fee. |
| `SECRECY_REQUEST` | moderate | email | Asks you to keep a secret. |
| `FAMILY_EMERGENCY` | moderate | email | Says a family member is in trouble and needs money fast. |
| `PRESSURE_TACTICS` | weak | all | Tries to rush you. |
| `PAYMENT_DEMAND` | weak | all | Asks you to pay or send money (a normal bill does too). |
| `THREAT_OF_CONSEQUENCES` | moderate | all | Threatens YOU with arrest, legal action, or losing benefits. |
| `URGENT_PAYMENT_REQUEST` | moderate | all | Asks for money AND rushes or threatens you ("urgent financial action"). |
| `AGENCY_DOES_NOT_EMAIL` | moderate | email | Claims to be an organization that says it never emails first to ask for money or personal details (the IRS), and asks for exactly that. |
| `INSIDE_SCAM_EMAIL` | strong | link | The clicked link is inside an email whose result was `warn` with `GO_BACK` (`context.surroundingResult`). |

"Tier" comes from `extension/core/risk-policy.js` and is not sent in the result. It decides the verdict:

| Evidence | Verdict | recommendedAction |
|---|---|---|
| Any `confirmed` sign (known dangerous, trusted source) | `block` | `GO_BACK` |
| Any `strong` sign, or 5+ points including a `moderate` sign | `warn` | `GO_BACK`, or `DO_NOT_ENTER_INFO` on a page with a password or card box |
| Anything else that counts (weak signs alone, however many) | `warn` | `VERIFY_INDEPENDENTLY` |
| Nothing | `no_warning_signs` | `NONE` |

On websites and around links, one scary phrase on its own doesn't count at all: it needs other evidence, or a second part of the scam story.

---

## 3. Messages

### 3a. In the same page: a direct function call

The detection engine is loaded into every page alongside the scanner, and is called directly:

```js
const result = analyze(input);   // input: section 1, result: section 2
```

It must return synchronously. A click has to be held or let through in the same moment it happens. If the guard had to wait for a reply from another part of the extension, it couldn't stop the click without breaking every normal link.

`analyze()` never throws. If something goes wrong inside it, it returns:

```js
{ schemaVersion: 1, verdict: "unknown", reasons: [], recommendedAction: "NONE", evidence: [] }
```

### 3b. Remote lookups (asking a threat service about an address)

The service worker side is built (`LOOKUP_URL`, below); only a development mock provider exists, and remote lookups are off by default. See `docs/threat-intelligence.md`. These rules apply:

1. `analyze()` always runs first, here, instantly. A lookup is a separate, slower step that runs elsewhere (the service worker), never inside `analyze()`.
2. `whenToLookUp(result)` (in `rules.js`) says whether a click must wait:

   | Answer | When | The browser side must |
   |---|---|---|
   | `not_needed` | `block`, or `warn` with `GO_BACK` / `DO_NOT_ENTER_INFO` | act on the result now; a lookup can't make it safer |
   | `before_opening` | `warn` with `VERIFY_INDEPENDENTLY` | **cancel the click first**, show a clear "Checking this link…" state with a "Go back to safety" button, then decide on the lookup's answer |
   | `optional` | `no_warning_signs` | open normally; a lookup may run alongside |

3. The answer goes back through the engine, never straight to the screen:
   ```js
   analyze(input, { lookup: <the LOOKUP_RESULT from 3d> })
   ```
   - `match` adds `KNOWN_THREAT`: `block` from a trusted source, a strong `warn` from an untrusted one.
   - `no_match` changes nothing. "Not on the list" never removes a warning sign found here.
   - `error` (an error, or no answer in time) changes nothing. (`failed` is accepted as an older name.)
4. **A slow or failed lookup never lets a held link open by itself.** If the answer doesn't come, show the local result's warning and let the person choose, exactly as if there were no lookup.

### 3c. Frames: `chrome.runtime` messages

Every message has a `type` and a `schemaVersion`.

**`SHOW_WARNING`**: a click inside an ad or other frame, sent up to the main page so the warning covers the whole screen. Goes from the frame to the service worker, which forwards it to the main page (frame 0) of the same tab.

```js
// frame -> service worker -> main page
{
  type: "SHOW_WARNING",
  schemaVersion: 1,
  result: { /* section 2 */ },
  navigation: { url: "https://claim-reward.example/claim", newTab: true }  // where "open it anyway" goes
}

// reply
{ type: "SHOW_WARNING_RESULT", schemaVersion: 1, shown: true }
```

If `shown` is `false`, or there's no reply, the frame shows the warning itself.

**`ANALYZE`**: for parts of the extension that can't load the engine directly (for example, a future settings page or a threat lookup in the service worker). Never used for click decisions (see 3a).

```js
// request
{ type: "ANALYZE", schemaVersion: 1, requestId: "a1b2c3", input: { /* section 1 */ } }

// reply: always a valid result, "unknown" on failure
{ type: "ANALYSIS_RESULT", schemaVersion: 1, requestId: "a1b2c3", result: { /* section 2 */ } }
```

---

### 3d. Service worker messages

Content scripts and extension pages talk to the service worker with `chrome.runtime.sendMessage`. Every message and answer has `type` and `schemaVersion: 1`. Any failure is answered with `{ type: "ERROR", schemaVersion: 1, error }`, never by throwing.

| Message | Who may send it | Answer |
|---|---|---|
| `LOOKUP_URL` | anyone | `LOOKUP_RESULT` |
| `OPEN_WARNING_PAGE` | a content script (needs a tab) | `WARNING_PAGE_OPENED` |
| `GET_SETTINGS` | anyone | `SETTINGS` |
| `UPDATE_THREAT_RULES` | **only the extension's own pages** | `THREAT_RULES_UPDATED` |
| `SET_SETTINGS` | **only the extension's own pages** | `SETTINGS` |
| `SHOW_WARNING` | a content script in a frame | `SHOW_WARNING_RESULT` |

```js
// Is this address known to be dangerous?
{ type: "LOOKUP_URL", schemaVersion: 1, url: "https://example.example/claim" }
{ type: "LOOKUP_RESULT", schemaVersion: 1,
  status: "match" | "no_match" | "error",   // no_match is NOT "safe"; error is NOT no_match
  url: "https://example.example/claim",
  source: { name: "Practice list", trusted: true } | null,   // set for a match
  checked: ["local list"],                  // what was asked
  reason: "no answer within 1500 ms",       // for an error (and allowlisted no_match)
  fromCache: false }

// Change the known-threat list (entries: docs/threat-intelligence.md)
{ type: "UPDATE_THREAT_RULES", schemaVersion: 1,
  add: [{ type: "domain" | "url", value, source, trusted, expiresAt? }],
  remove: ["value", ...],           // entries added earlier with "add"
  falsePositives: ["value", ...],   // never block these, even from the bundled list
  replaceAll: false }
{ type: "THREAT_RULES_UPDATED", schemaVersion: 1, installedRules: 9, activeEntries: 4,
  rejected: [{ value: "co.uk", reason: "too broad: ..." }] }

// Show the extension's own warning page in this tab
{ type: "OPEN_WARNING_PAGE", schemaVersion: 1, result: <section 2 result>, url: "https://..." }
{ type: "WARNING_PAGE_OPENED", schemaVersion: 1, token: "..." }

// Settings
{ type: "GET_SETTINGS", schemaVersion: 1 }
{ type: "SET_SETTINGS", schemaVersion: 1, settings: { protectionEnabled: false } }
{ type: "SETTINGS", schemaVersion: 1, settings: {
    protectionEnabled: true, remoteLookups: false, provider: "none",
    providerOptions: {}, lookupTimeoutMs: 1500, allowlist: [] } }
```

## 4. Fixtures: building without waiting for each other

| Folder | Who uses it | What's in it |
|---|---|---|
| `tests/fixtures/inputs/` | Person A | Fixed input objects to build and test the engine before the scanner is finished. |
| `tests/fixtures/results/` | Person B | Fixed result objects, at least one per verdict, to build the interface before the engine is finished. |

`node tests/contract.test.js` checks that every fixture follows this contract, including the privacy rule. Run it after adding or changing a fixture. Real engine output and real scanner output must pass the same checks before a branch is merged.

---

## Decisions to confirm (Phase 0)

The original Phase 0 proposal left these open. This file fills them in; both people should confirm them before splitting into feature branches.

1. **`source: "link"`** for a single clicked link, with `nearbyText` in `context`. Without it, the click guard can't describe "the words around this ad" in the contract.
2. **Weak warning signs** are `warn` + `VERIFY_INDEPENDENTLY`: shown, but never interrupting. Only `GO_BACK` and `DO_NOT_ENTER_INFO` interrupt. Too many interruptions and people stop trusting warnings.
3. **`analyze()` is a synchronous function call in the page, not a message.** Clicks can't wait for a reply.
4. **Evidence shape** `{ kind, value, reasonCode }`.
5. **`hasPaymentField`** in forms, so card-number pages can be checked the same way as password pages.
6. **The other branch's scanner uses different names** (see the integration checklist). The engine accepts `hasPayment` as well as `hasPaymentField` until the two of you pick one.
