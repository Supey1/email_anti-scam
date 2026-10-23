# Email Anti-Scam

A Chrome extension that stands between an older adult and a risky click. It checks emails in Gmail, the websites you visit, and the links and ads on them. When something looks like a scam, it steps in **before** you go there: a big, plain-language warning explains *what* looks wrong and *what to do instead*, and can read itself out loud.

*Built for the 2026 Congressional App Challenge.*

## The problem

Scammers target older adults by email because many are less familiar with newer technology and the tricks scammers use: fake bank alerts, fake delivery notices, "you've won" messages, and emails pretending to be a grandchild in trouble. Warnings in today's email apps are small, technical, or missing, and one wrong click can cost someone their savings.

> TODO: add one or two statistics from a trusted source (for example, the FBI's annual Elder Fraud Report from IC3) and link to it.

## What it does (version 0.2)

It protects at three levels. The stronger the evidence, the stronger the response.

| Level | When | What happens |
|---|---|---|
| 🛑 **Block** | The website is on the list of **known** dangerous websites | It never loads. A "We blocked a dangerous website" page appears instead. No way through. |
| 🛑 **Stop and check** | Strong warning signs, like a link pretending to be your bank, or an ad promising a prize and rushing you | The click is cancelled and a big warning explains why. "Go back to safety" is the big button; "Open it anyway" is small. |
| ⚠️ **Be careful** | Weaker signs, like a shortened link or one rushed word | Shown in the Gmail panel, but **never** interrupts a click. Too many false alarms and people stop trusting the warnings. |

**In Gmail** (from version 0.1):
- Notices when you open an email and checks it automatically
- Shows a big-text panel with high contrast, color **and** icons, and short sentences
- Checks the sender against each company's **own** email addresses. How much a mismatch matters depends on the message: a "PayPal" account alert from someone else's address is a real warning sign, but a newsletter sent through an email service (SendGrid, Mailchimp, GovDelivery...) is normal. A company's address written into the sender's *name* (`service@paypal.com <x@evil.example>`) is always a warning.
- Notices when an email says it's from a company but none of its links go to that company's website
- Checks the wording: gift cards and wire transfers, "your account is locked," rushing, secrecy, prizes, fake delivery notices and redelivery fees, tech-support scams, the "grandparent scam," and **urgent demands for money** ("pay today or you will be arrested")
- Knows that the IRS says it never emails people first to ask for money or personal details
- **New:** clicking *any* link in an email that looks like a scam brings up the "Stop and check" warning first

**On every website** (new in 0.2):
- **Before a click:** checks where the link really goes and what the words around it (like the rest of an ad) promise
  - links that pretend to be a company (`paypa1-secure.xyz`, `paypal.com.fake-domain.example`, `paypal.com@evil.example`), or whose words say one website but really go to another
  - links through well-known pass-through services (Google, Outlook, Facebook, YouTube) are checked where they really end up
  - number addresses, shortened links, and risky website endings
  - ads that say *you* won a prize, ask you to pay a fee or use gift cards first, say *your* package is on hold, say *your* computer is infected, or tell you to call a number
  - ad clicks that go through an ad network (like Google's) are checked where they really go when the link says so; when it doesn't, the ad's wording is still checked, but the engine doesn't pretend to know the destination
  - clicks inside ads that load in their own frame are caught too, and the warning covers the whole screen
- **On the page itself:** warns if the page looks like a company's sign-in page but isn't on that company's website, sends your password to a different website or to a known dangerous one, asks for a password on a free hosting website, sends it without encryption, or is a fake virus or prize pop-up (including pop-ups that appear after the page loads)
- **Known dangerous websites** are blocked by Chrome itself, so typed addresses, redirects, and pop-ups are stopped too. Only a list from a trusted source blocks outright; everything else gets a warning the person can choose to go past.

**Everywhere:**
- **🔊 Read to me** on every warning
- Every warning lists the actual evidence that triggered it
- Runs entirely on your computer; nothing you read or click is sent anywhere

## Try it

### Option A: the practice pages (no extension needed)

1. Download this repo (green **Code** button, then **Download ZIP**) and unzip it.
2. Open any of these files in Chrome:

| Practice page | What to try |
|---|---|
| `tests/fake-gmail.html` | Click the test emails at the top and watch the panel change. Open "Fake PayPal" and click its link. |
| `tests/practice-ads.html` | A pretend news site with ads. Click the scam ads and links (warning), then the normal ones (nothing happens). |
| `tests/practice-fake-login.html` | A fake PayPal sign-in page. The page warning appears right away. |
| `tests/practice-popup.html` | A recipe page. After 3 seconds a fake virus pop-up appears; the warning follows. |

The practice pages load the extension's files themselves, so open them as files, not with the extension also running on them, or you'll see two warnings.

### Option B: the real extension

1. Open Chrome and go to `chrome://extensions`.
2. Turn on **Developer mode** (top right).
3. Click **Load unpacked** and choose the `extension` folder.
4. Chrome will say the extension can "read and change all your data on all websites." That's needed to check links and pages on every website (see [Privacy](#privacy)).
5. Open Gmail and open any email: the panel appears on the right. Browse normally: warnings only appear when something looks wrong.
6. To see blocking, type `known-phish.example` into the address bar. (It's on the practice list in `extension/threat-list.js`.)
7. After changing any code, click the ↻ reload button on the extension's card, then refresh the page.

## How it works

```
1. COLLECT EVIDENCE                 2. CHECK IT (rules.js + core/)      3. ACT
gmail.js  the open email     ──►    analyzeEmail()   ──►  panel (+ tells guard.js)
guard.js  a link being clicked ──►  analyzeLink()    ──►  "Stop and check" warning
page.js   the page you're on   ──►  analyzePage()    ──►  "Be careful" warning

service-worker.js + threat-list.js  ──►  Chrome blocks known dangerous websites before they load
```

Each check adds "risk points" for a warning sign (`core/risk-policy.js` says how many), and the answer comes with the list of signs that caused it:

| Evidence | Level | Action |
|---|---|---|
| On the known-dangerous list (confirmed, not a guess) | high | **block** |
| 5+ points | high | **warn**: stop and explain |
| 1–4 points | medium | allow (Gmail panel says "be careful") |
| 0 points | low | allow |

Some signs only count together. "Lottery" on a news site is normal; "Congratulations, **you** have won... claim before midnight" next to a link to an unknown website is not. Links to another page on the same website, and links to a company's real website, aren't treated as offers.

Every warning comes from a rule a person can read and understand, so the extension can always explain *why* it is warning you. There is no AI in this version: it's a rules-based scam detection engine.

## Project structure

| File | What it does |
|---|---|
| `extension/manifest.json` | Tells Chrome what the extension is, which files run where, and what it's allowed to do |
| `extension/rules.js` | The front door to the scam checks: `analyze()` (see `docs/interfaces.md`) |
| `extension/core/` | The scam checks, in groups: reading addresses, address rules, company-name rules, wording rules, the risk policy, and the plain-language explanations |
| `extension/threat-list.js` | The list of known dangerous websites (practice addresses for now) |
| `extension/gmail.js` | Reads the open email in Gmail and builds the panel |
| `extension/guard.js` | Stops risky link clicks before the browser leaves the page |
| `extension/page.js` | Checks the website you're on, including pop-ups that appear later |
| `extension/warning.js` | The big full-screen warning and read-aloud |
| `extension/panel-styles.js` | How the panel and warning look (big text, colors) |
| `extension/service-worker.js` | Has Chrome block known dangerous websites; passes warnings up from ads |
| `extension/blocked.html`, `blocked.js` | The page shown instead of a blocked website |
| `tests/rules.test.js` | Automatic tests for the scam checks, with a caught / false-alarm count |
| `tests/fake-gmail.html` | Practice page that imitates Gmail |
| `tests/practice-*.html` | Practice pages for ads, a fake sign-in page, and a fake virus pop-up |
| `tests/contract.js`, `contract.test.js` | Checks inputs and results against the interface contract |
| `tests/fixtures/` | Fixed inputs and results, so each workstream can build without waiting for the other |
| `docs/interfaces.md` | The contract between the scanner, the engine, and the warning interface |
| `docs/WORKING_AGREEMENT.md`, `integration-checklist.md` | How the two workstreams work together, and open integration issues |

## Running the tests

If you have [Node.js](https://nodejs.org) installed, run this from the project folder:

```
node tests/contract.test.js
node tests/rules.test.js
node tests/browser/acceptance.test.js
```

The last one loads the real extension into Chromium, opens local fake pages (a normal page, a fake sign-in page, a news page with ads, a pop-up, and a pretend Gmail inbox), and checks that suspicious clicks are stopped before the browser even asks for the address. It needs Playwright (`npm i playwright` and `npx playwright install chromium`); without it, it skips.

`contract.test.js` checks the shared fixtures against the interface contract in [`docs/interfaces.md`](docs/interfaces.md). `rules.test.js` checks the scam rules.

Node is only needed for running tests. The extension itself is plain JavaScript that Chrome runs directly.

The tests end with two numbers:

```
301/301 tests passed
Scams caught:          18/18
False alarms (normal): 0/15
```

Every rule has at least one example that should trigger it and one that should not, and the policy tests check which combinations of signs lead to each verdict (for example, a strange website ending or an urgent phrase on its own never stops a click). The tests also check the trickiest address cases directly: `paypal.com.fake-domain.example` must never count as PayPal, `paypal.com@evil.example` really goes to evil.example, and two `github.io` sites belong to different people.

Be honest about what these mean: we wrote these examples ourselves, alongside the rules, so of course the rules pass them. They show the extension *works*, not that it catches scams *in general*. For the submission, collect a separate set of real-world-style examples (scam **and** normal emails, ads, and sign-in pages) that nobody tuned the rules on, and report those numbers too.

**When you add a new rule, add a test that should trigger it AND a normal example that should not.**

## Testing safely

- **Never use real scam links.** Use made-up addresses ending in `.example`, which can never be real websites.
- Use a separate test Gmail account for sending yourselves practice scam emails.
- Keep track of how many test emails the extension gets right; this accuracy number goes in our submission.

## Known limits

- **The known-dangerous list is a practice list.** It only has made-up `.example` addresses until we connect a real source (Step 4b). Until then, blocking is only a demo; the "Stop and check" warnings are what protect people.
- **Not every way of opening a link is caught.** Normal clicks, middle clicks, Ctrl/Cmd clicks, and Enter are. "Open in new tab" from the right-click menu, and pages that move you somewhere with their own code, are not (except known dangerous websites, which Chrome blocks however you get there). Test each new case before claiming it works.
- **Ads we can't read can't be checked.** Clicks inside ad frames are checked, but an ad that's only a picture with no words or description gives us little to go on.
- **A scam ad placed directly in a real website's page** (not in its own frame) can make the whole page get a "Be careful" warning.
- **A sign-in page with a company's name on it** (in its title or main heading) that isn't on that company's website gets a warning, even if it's a real partner site.
- Gmail sometimes changes its page layout. If the panel stops appearing, check the `SELECTORS` at the top of `gmail.js`.
- Rules can't catch every scam, especially new tricks, and scammers can avoid our exact wording.
- **Shortened and tracking links aren't followed.** We never open a link to see where it goes (that could warn the scammer, and the answer can change depending on who asks). A shortened link stays a weak warning sign. Only well-known pass-through services that write the destination into the link are followed.
- **Single dangerous addresses** (`KNOWN_THREAT_URLS`) stop clicks, but Chrome doesn't block them yet when typed in (integration checklist).
- **The lists of email services and ad networks (`core/domain-rules.js`) are hand-picked.** A real company's newsletter sent through a service that isn't listed may get a mild "check first" note; a scam sent through a listed service is still checked on everything else.
- **Gmail only shows us the sender's name and address.** The hidden email headers that would prove who really sent a message aren't visible to the extension.
- **Telling owners apart uses a partial list of website endings.** `core/url-normalizer.js` knows common two-part endings (`co.uk`, `com.au`...) and free hosting sites (`github.io`, `netlify.app`...), but not the full Public Suffix List. An ending it doesn't know can make two different owners look like one website.
- **The list of companies and their official websites (`core/domain-rules.js`) must be checked against each company's own site.** A missing official website means a real link gets flagged; a wrong one would let a fake through.
- Chrome only. It can't see text messages, phone calls, or other apps on the computer; that would be a different product.

## Roadmap

- [x] Step 1: Repo and project setup
- [x] Step 2: Extension that reads Gmail and shows the big-text panel
- [x] Step 3: First set of rule-based scam checks
- [x] Step 4a: Protection on every website: click guard, page warnings, and browser-level blocking of known dangerous websites (practice list)
- [ ] Step 4b: Fill the known-dangerous list from a maintained source. Check its current API, terms, and privacy first: Google Safe Browsing (use **v5**; v4 is deprecated) is for non-commercial use only, Google Web Risk is the commercial version, and open phishing feeds are another option. A lookup service that receives the addresses you visit changes our privacy promise, so update [Privacy](#privacy) first.
- [ ] Step 5 (only if testing shows rules miss real cases): AI plain-language summary and second opinion on risk
- [ ] Step 6: "Ask someone I trust" button and an options page
- [ ] Step 7: Test with 15–20 practice emails and with older adults
- [ ] Step 8: Demo video and submission write-up

## Privacy

**What it reads:** in Gmail, the email you have open (sender, subject, text, links). On other websites, the page's address, title, main heading, visible words, whether it has a password box and where that box sends what you type, and the link you click plus the words around it.

**What it sends:** nothing. Every check happens inside your own browser. Nothing is saved, and the extension has no server.

**Permissions it asks for, and why:**

| Permission | Why |
|---|---|
| Access to all `http`/`https` websites | To check pages and links on any website, and inside ads. Chrome shows this as "read and change all your data on all websites." |
| `declarativeNetRequest` | To have Chrome block known dangerous websites before they load. Chrome does this matching itself; the extension doesn't see your browsing history. |

If a threat-lookup service or AI is added later, this section must say exactly what is sent, to whom, and when, *before* that version ships. Don't promise that nothing leaves the browser once anything does. The Chrome Web Store also requires this disclosure, even for data that never leaves your computer.

## Working together

Two workstreams (detection engine and browser protection) share one analyzer interface. Read [`docs/WORKING_AGREEMENT.md`](docs/WORKING_AGREEMENT.md) for the rules and who owns which files, [`docs/interfaces.md`](docs/interfaces.md) for the contract between them, and [`docs/integration-checklist.md`](docs/integration-checklist.md) for open integration issues.

## Team

| Name | Role |
|---|---|
| TODO | Project lead, scam rules, AI prompt |
| TODO | Extension and Gmail integration |
| TODO | Panel design, read-aloud, options page |
| TODO | Testing, user feedback, video and write-up |

## AI use disclosure

Parts of this project's code and documentation were drafted with help from Claude (Anthropic) and then reviewed, tested, and edited by our team.

> TODO: keep this section updated with which parts used AI help, as the challenge rules ask.
