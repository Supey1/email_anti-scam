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
| `hasPaymentField` | The form has a box for a card number, card security code, or bank account number. (`hasPayment`, the name the page scanner uses, means the same.) |
| `method`, `fieldCount` | Optional, from the page scanner. Not used by the checks. |

**Privacy rule: the scanner never collects anything a person typed or chose in any field.** It records only that a sensitive field *exists*. No form object, and nothing else in the input, may contain a field's value.

### `context` by source

**`source: "webpage"`**: a whole page.

```js
context: {
  mainHeadings: ["PayPal"],  // optional: text of the page's main (h1) headings, up to 3
  // From content/page-scanner.js (Person B):
  scan: "initial",           // "initial" (the whole page) or "dynamic" (new content only; page.js merges it first)
  truncated: { text: false, links: false },  // a size limit cut something off
  ads: [{                    // advertisements the scanner recognized (content/ad-signals.js); their words are
    signals: ["class:ad-slot"],             //   kept OUT of visibleText, so an ad doesn't make the page look suspicious
    text: "Congratulations! You have won...",
    link: { text: "Claim reward", url: "https://claim-gift.example/x" } | null,
    frame: false             // inside a same-origin ad frame
  }],
  adFrames: { readable: 0, unreadable: 1 }  // cross-origin ad frames can't be read, and are never guessed at
}
```

`analyze()` judges the page itself. `checkWebpage()` (section 3a) also judges each ad (up to 20) the way a click on it would be, and adds a scam ad's reasons after the page's own. An ad leading to a known dangerous website makes the page `warn` + `GO_BACK`, not `block`: the ad is dangerous, not the page.

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
  inAd: true,                  // exactly true: the link is in something content/ad-signals.js recognized as an ad.
                               //   Then "you won, claim it" leading to a website we can't tie to the company stops the click.
  insideFrame: true,           // the link is inside an ad or other frame
  surroundingResult: {         // optional: copied from the result for the email the link is in, if there is one
    verdict: "warn",
    recommendedAction: "GO_BACK"
  }
}
```

The analyzer ignores fields it doesn't know about. The scanner must not rely on that to send extra data: only the fields listed here are allowed.

The analyzer doesn't trust its input: it shortens every field to a sensible length, removes invisible characters, and turns look-alike letters into plain ones before any check. Adapters don't need to clean text for the engine. (They still must never collect typed values.)

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
| `INSECURE_FORM` | weak | webpage | A password or card form on a page without a secure connection, or one that sends what you type without encryption (`http:`). Your own computer (`localhost`) counts as secure, as in Chrome. |
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
| `PERSONAL_INFO_REQUEST` | moderate | email | Asks for account numbers, passwords, or similar. ("I have your password" is not asking for it.) |
| `DELIVERY_PROBLEM_CLAIM` | moderate | all | Says your package couldn't be delivered, is on hold, or needs a fee. |
| `SECRECY_REQUEST` | moderate | email | Asks you to keep a secret. |
| `FAMILY_EMERGENCY` | moderate | email | Says a family member is in trouble and needs money fast. |
| `PRESSURE_TACTICS` | weak | all | Tries to rush you. |
| `PAYMENT_DEMAND` | weak | all | Asks you to pay or send money (a normal bill does too). |
| `UNEXPECTED_CHARGE` | moderate | all | A surprise charge plus a phone number to cancel or get a refund (the "refund" scam). |
| `THREAT_OF_CONSEQUENCES` | moderate | all | Threatens YOU with arrest, legal action, or losing benefits. |
| `URGENT_PAYMENT_REQUEST` | moderate | all | Asks for money AND rushes or threatens you ("urgent financial action"). |
| `AGENCY_DOES_NOT_EMAIL` | moderate | email | Claims to be an organization that says it never emails first to ask for money or personal details (the IRS), and asks for exactly that. |
| `CHARGE_WITH_PRESSURE` | moderate | all | A surprise charge (`UNEXPECTED_CHARGE`) AND a deadline or threat: call before you check your statement. |
| `INVESTMENT_PROMISE` | moderate | all | Promises guaranteed, risk-free, or impossible profits ("300% this month", "20% daily returns"), in a message about investing or crypto. Not when it says profits are NOT guaranteed. |
| `CELEBRITY_ENDORSEMENT` | moderate | all | A famous person's name (`data/people.js`) selling an investment or crypto offer ("Elon Musk is giving away bitcoin"). Just naming them, as news does, doesn't count. |
| `DEPOSIT_TO_TRADE` | weak | all | Asks you to deposit money to start trading or investing. 0 points: a real brokerage says this too. It explains `INVESTMENT_PITCH`. |
| `INVESTMENT_PITCH` | moderate | all | Promised profits or a famous name AND putting money in (a deposit, crypto, a fee). |
| `CRYPTO_GIVEAWAY` | strong | all | "Send crypto and get more back." |
| `JOB_FEE` | strong | all | A job offer that asks you to pay first: equipment, training, a fee, or buying from "our approved vendor". Not when the employer pays. |
| `OVERPAYMENT` | strong | all | Deposit a check and send back the difference (the fake-check scam). |
| `JOB_DETAILS_REQUEST` | moderate | all | A job offer that asks you to send your Social Security or bank account number by email or text, not on a secure form or in person. |
| `RECOVERY_FEE` | strong | all | Offers to get back money you lost, for a fee. Not when it says there's no up-front fee. |
| `SEXTORTION_THREAT` | strong | all | Threatens to send videos or photos to YOUR contacts, family, or friends unless you pay. |
| `INSIDE_SCAM_EMAIL` | strong | link | The clicked link is inside an email whose result was `warn` with `GO_BACK` (`context.surroundingResult`). |

"Tier" comes from `extension/core/risk-policy.js` and is not sent in the result. It decides the verdict:

| Evidence | Verdict | recommendedAction |
|---|---|---|
| Any `confirmed` sign (known dangerous, trusted source) | `block` | `GO_BACK` |
| Any `strong` sign, or 5+ points including a `moderate` sign | `warn` | `GO_BACK`, or `DO_NOT_ENTER_INFO` on a page with a password or card box |
| Anything else that counts (weak signs alone, however many) | `warn` | `VERIFY_INDEPENDENTLY` |
| Nothing | `no_warning_signs` | `NONE` |

On websites and around links, one scary phrase on its own doesn't count at all: it needs other evidence, or a second part of the scam story. A few findings are a two-part story by themselves (`CRYPTO_GIVEAWAY`, `JOB_FEE`, `OVERPAYMENT`, `JOB_DETAILS_REQUEST`, `RECOVERY_FEE`, `SEXTORTION_THREAT`: "send crypto" AND "get more back", a job AND a fee) and count on their own. A page that talks ABOUT scams still needs other evidence.

---

## 3. Messages

### 3a. In the same page: a direct function call

The detection engine is loaded into every page alongside the scanner, and is called directly:

```js
const result = analyze(input);   // input: section 1, result: section 2
```

The screens (Person B) use four small helpers in `rules.js` built on `analyze()`, so none of them repeats glue:

| Helper | Used by | Returns |
|---|---|---|
| `checkWebpage(evidence)` | `page.js` | the page's result, with its ads judged too (section 1, `context.ads`) |
| `checkLinkClick({ text, url, pageUrl, inAd, adText, insideFrame, surroundingResult })` | `content/click-guard.js`, `ui/warning.js` | the result, plus `host`: where the link really goes |
| `checkEmail(evidence)` | `content/gmail.js` | the result, plus `links: [{ text, host, flags }]` for the panel's list of links |
| `stopsPerson(result)` | all of them | `true` for `block`, or `warn` with `GO_BACK` / `DO_NOT_ENTER_INFO`: cancel the click, show the page card. `warn` + `VERIFY_INDEPENDENTLY` never interrupts. |

The extra fields (`host`, `links`) are for the screens; the rest is exactly section 2.

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

### 3c. Frames

The click guard runs in every frame, ads included. When it stops a click, it asks the service worker for the extension's warning page (`SHOW_WARNING`, below), which replaces the **whole tab**, so a frame can't hide it. If that fails (for example, the extension was just updated), the click guard shows the in-page card instead (`panel.js`). The page scanner and its card run in the main page only.

---

### 3d. Service worker messages

Content scripts and extension pages talk to the service worker with `chrome.runtime.sendMessage`. Every message and answer has `type` and `schemaVersion: 1`. Any failure is answered with `{ type: "ERROR", schemaVersion: 1, error }`, never by throwing.

| Message | Who may send it | Answer |
|---|---|---|
| `LOOKUP_URL` | anyone | `LOOKUP_RESULT` |
| `SHOW_WARNING` | a content script (needs a tab) | `{ ok }` |
| `CONTINUE` | **only the warning page itself** | `{ ok }` |
| `REPORT_FALSE_ALARM` | anyone | `{ ok }` |
| `GET_SETTINGS` | anyone | `SETTINGS` |
| `UPDATE_THREAT_RULES` | **only the extension's own pages** | `THREAT_RULES_UPDATED` |
| `SET_SETTINGS` | **only the extension's own pages** | `SETTINGS` |
| `GET_STATUS` | anyone | `STATUS` |
| `ACCESS_CHANGED` | anyone (Chrome's permission events also trigger it) | `STATUS` |

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

// The click guard stopped a link: open ui/warning.html in this tab (or a new tab, for a new-tab click).
// The warning page checks the address again itself; it never trusts a verdict passed to it.
{ type: "SHOW_WARNING", url: "https://...", text: "the link's words", newTab: false,
  inAd: false, adText: "the ad's words", fromScamEmail: false }
{ ok: true }   // false: the click guard shows its in-page card instead

// "Continue" on the warning page. Checked again with the service worker's list: never to a known dangerous website.
{ type: "CONTINUE", url: "https://...", text: "the link's words" }
{ ok: true }

// "This is a false alarm": kept on this computer only (last 100; host, verdict, up to 5 reasons, source, time)
{ type: "REPORT_FALSE_ALARM", report: { host, verdict, reasons: ["..."], source: "click-guard" } }
{ ok: true }

// Settings
{ type: "GET_SETTINGS", schemaVersion: 1 }
{ type: "SET_SETTINGS", schemaVersion: 1, settings: { protectionEnabled: false } }
{ type: "SETTINGS", schemaVersion: 1, settings: {
    protectionEnabled: true, remoteLookups: false, provider: "none",
    providerOptions: {}, lookupTimeoutMs: 1500, allowlist: [] } }

// What's active right now (for the settings page)
{ type: "GET_STATUS", schemaVersion: 1 }
{ type: "STATUS", schemaVersion: 1, settings: { ... },
  access: "all" | "gmail" | "none",   // the website access the person has given
  rules: 9, activeEntries: 4 }
```

Settings live in `chrome.storage.local` (they survive restarts), under two keys:
- `settings`: the person's choices (`extension/settings.js`: on/off, Gmail, which websites, text size, reading aloud). The popup and the settings page save these directly; every part reads them through `Settings`. When they change, the service worker applies them (rules and page scripts follow the on/off switch, and the toolbar button says OFF).
- `engineSettings`: threat lookups and false positives, changed only with `SET_SETTINGS` from the extension's own pages.

`protectionEnabled` in `SET_SETTINGS` / `SETTINGS` **is** `settings.enabled`: one switch, stored once.

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
6. **The page scanner's names** (`hasPayment`, `method`, `fieldCount`, `scan`, `truncated`, `ads`, `adFrames`) are part of this contract since the merge. The engine accepts `hasPayment` and `hasPaymentField` as the same thing.
7. **For email, `block` means a known dangerous website only**, as everywhere else. A scam email with strong signs is `warn` + `GO_BACK` ("Stop and check"); B's temporary engine used `block` for those. (Decided at the merge; B, please confirm.)
