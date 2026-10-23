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
  visibleText: "Claim your reward now...",   // what the person can see, first 5,000 characters
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
| `visibleText` | string | yes | Visible words only (no hidden text, no code), cut to the first 5,000 characters. For email: the message text. |
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

| Code | Strength | Used for | Meaning |
|---|---|---|---|
| `KNOWN_THREAT` | block | all | The website is on the list of known dangerous websites. |
| `LOOKALIKE_DOMAIN` | strong | all | The address imitates a company: its name with extra words, swapped characters (`paypa1`), letters from another alphabet, a misspelling, or the company's real website written in front (`paypal.com.fake-domain.example`). |
| `HIDDEN_DESTINATION` | strong | email, link | The link's words show one website, but it goes to another. |
| `BRAND_NAME_MISMATCH` | medium | email, link | The link or offer names a company, but goes somewhere else. |
| `MISLEADING_URL` | strong | email, link | The address is written to look like a company's website (`paypal.com@evil.example`, or a company's website in the path) but goes elsewhere. |
| `NUMBER_ADDRESS` | medium | all | A raw number address instead of a website name. |
| `SHORTENED_LINK` | weak | email, link | A shortened link hides where it really goes. |
| `RISKY_DOMAIN_ENDING` | weak | all | A website ending often used by scam sites. |
| `FAKE_SIGN_IN_PAGE` | strong | webpage | A company's sign-in page that isn't on the company's website. |
| `CREDENTIALS_SENT_ELSEWHERE` | medium | webpage | A password or card form sends what you type to a different website. |
| `SENDER_NAME_MISMATCH` | strong | email | The sender's name says a company, but the address isn't from it. |
| `LOOKALIKE_SENDER` | strong | email | The sender's address imitates a company. |
| `COMPANY_ON_FREE_EMAIL` | medium | email | Claims to be a company or department, but uses a free personal address. |
| `PRIZE_CLAIM` | medium | all | Says you won a prize or are owed money. |
| `UNVERIFIED_PRIZE_CLAIM` | info | link, webpage | Promises a prize, and we can't confirm the destination belongs to the company in the offer. |
| `PRIZE_WITH_PRESSURE` | medium | all | A prize plus rushing: a classic scam combination. |
| `PAY_TO_CLAIM` | medium | all | Asks you to pay a fee first, or pay with gift cards, crypto, or a wire transfer. |
| `PAYMENT_METHOD_REQUEST` | medium | email | Mentions gift cards, wire transfers, or crypto. |
| `ACCOUNT_PROBLEM_CLAIM` | medium | all | Says your account, card, or computer has a serious problem. |
| `CALL_THIS_NUMBER` | medium | link, webpage | Tells you to call a number, or not to close the page. |
| `TECH_SUPPORT_CLAIM` | medium | email | Talks about viruses or "tech support". |
| `PERSONAL_INFO_REQUEST` | medium | email | Asks for account numbers, passwords, or similar. |
| `DELIVERY_PROBLEM_CLAIM` | medium | email | Says a package couldn't be delivered. |
| `SECRECY_REQUEST` | medium | email | Asks you to keep a secret. |
| `FAMILY_EMERGENCY` | medium | email | Says a family member is in trouble and needs money fast. |
| `PRESSURE_TACTICS` | weak | all | Tries to rush you. |
| `INSIDE_SCAM_EMAIL` | strong | link | The clicked link is inside an email whose result was `warn` with `GO_BACK` (`context.surroundingResult`). |

"Strength" is guidance for the engine only. It is not sent in the result.

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

### 3b. Between parts of the extension: `chrome.runtime` messages

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
