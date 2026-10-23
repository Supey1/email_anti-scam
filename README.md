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
- Catches "refund" scams (a surprise charge and a phone number to cancel it; with a deadline to call, it stops you) and "Hi Mom, this is my new number" messages
- **New:** catches investment and crypto scams (guaranteed or impossible profits plus a deposit, "send crypto and get double back", famous names on fake investment offers, including the "sweetheart, I made 300% on this platform" end of romance scams), job scams (paying for equipment or training, "deposit our check and send back the difference", emailing your Social Security or bank number for a job), "we can recover the money you lost" for a fee, and blackmail emails ("pay or the video goes to your contacts"), explained as blackmail, not as a password request
- Doesn't warn about real bank alerts and newsletters sent from the company's own address with links only to the company, about ordinary marketing ("sale ends tonight"), or about newsletters that warn *about* scams
- Hidden characters and look-alike letters ("Pay\u200bPal", "ＰａｙＰａｌ") can't sneak a company name or a scam phrase past the checks
- **New:** clicking *any* link in an email that looks like a scam brings up the "Stop and check" warning first

**On every website** (new in 0.2):
- **Before a click:** checks where the link really goes and what the words around it (like the rest of an ad) promise
  - links that pretend to be a company (`paypa1-secure.xyz`, `paypal.com.fake-domain.example`, `paypal.com@evil.example`), or whose words say one website but really go to another
  - links through well-known pass-through services (Google, Outlook, Facebook, YouTube) are checked where they really end up
  - number addresses, shortened links, and risky website endings
  - ads that say *you* won a prize, ask you to pay a fee or use gift cards first, say *your* package is on hold, say *your* computer is infected, or tell you to call a number
  - ads that promise guaranteed profits for a deposit, use a famous name to sell crypto, ask you to pay to start a job, or charge to "recover" lost money
  - ad clicks that go through an ad network (like Google's) are checked where they really go when the link says so; when it doesn't, the ad's wording is still checked, but the engine doesn't pretend to know the destination
  - clicks inside ads that load in their own frame are caught too, and the warning covers the whole screen
- **On the page itself:** warns if the page looks like a company's sign-in page but isn't on that company's website, sends your password to a different website or to a known dangerous one, asks for a password on a free hosting website, sends it without encryption, or is a fake virus or prize pop-up (including pop-ups that appear after the page loads)
- **Known dangerous websites** are blocked by Chrome itself, so typed addresses, redirects, and pop-ups are stopped too. Only a list from a trusted source blocks outright; everything else gets a warning the person can choose to go past.

**Everywhere:**
- **🔊 Read to me** and **⏹ Stop reading** on every warning, at the speed you choose, optionally reading each warning as soon as it appears. If this computer can't read aloud, the button says so; the warning is always written on screen too.
- A settings page (also the welcome page after installing): turn protection on or off, choose which websites to check, text size, reading aloud, and a plain explanation of every permission
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
4. The welcome page opens. Choose **Check all websites and Gmail**; Chrome then asks you to allow it to "read and change all your data on all websites." That's needed to check links and pages (see [Privacy](#privacy)). Until you allow it, the extension can only block known dangerous websites.
5. Open Gmail and open any email: the panel appears on the right. Browse normally: warnings only appear when something looks wrong.
6. Settings (protection on/off, which websites, text size, reading aloud) are on the extension's **Options** page, or right-click its icon → Options.
7. To see blocking, type `known-phish.example` into the address bar. (It's on the practice list in `extension/data/threat-list.js`.)
8. After changing any code, click the ↻ reload button on the extension's card, then refresh the page.

## How it works

```
1. COLLECT EVIDENCE                 2. CHECK IT (rules.js + core/)      3. ACT
gmail.js  the open email     ──►    analyzeEmail()   ──►  panel (+ tells guard.js)
guard.js  a link being clicked ──►  analyzeLink()    ──►  "Stop and check" warning
page.js   the page you're on   ──►  analyzePage()    ──►  "Be careful" warning

service-worker.js + data/threat-list.js ►  Chrome blocks known dangerous websites before they load
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
| `extension/data/` | Facts the checks use, kept apart from the rules: companies and their official websites (`companies.js`), email services and ad networks (`services.js`), web-address lists (`addresses.js`), famous names used on fake investment ads (`people.js`), and the known-dangerous list (`threat-list.js`, practice addresses for now) |
| `extension/gmail.js` | Reads the open email in Gmail and builds the panel |
| `extension/guard.js` | Stops risky link clicks before the browser leaves the page |
| `extension/page.js` | Checks the website you're on, including pop-ups that appear later |
| `extension/warning.js` | The big full-screen warning and read-aloud |
| `extension/panel-styles.js` | How the panel and warning look (big text, colors) |
| `extension/service-worker.js` | Connects Chrome to `background/`: blocking rules, threat lookups, settings, the warning page |
| `extension/background/` | Turns the known-threat list into Chrome's blocking rules, answers threat lookups, and handles the service worker's messages |
| `extension/threat-sync.js` | Gives the scam checks in each page the same known-threat list Chrome blocks with |
| `extension/settings.html`, `settings.js` | Settings and welcome page: protection, website access, reading and text, privacy |
| `extension/speech.js` | Reading warnings aloud: read, stop, no restarts, a message when it can't |
| `extension/settings-sync.js` | Gives the warnings in each page the reading and text settings |
| `extension/blocked.html`, `blocked.js` | The extension's own warning page: shown instead of a blocked website, or for any warning |
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
node tests/run-all.js                   # every test that doesn't need a browser
node tests/browser/acceptance.test.js   # the real extension in Chromium
```

Or one at a time: `contract`, `rules`, `regression`, `robustness`, `service-worker`, and `speech` (each `node tests/<name>.test.js`).

The last one loads the real extension into Chromium, opens local fake pages (a normal page, a fake sign-in page, a news page with ads, a pop-up, and a pretend Gmail inbox), and checks that suspicious clicks are stopped before the browser even asks for the address. It also checks the settings page, a fresh install without website access, and a browser restart. (Chrome's own "Allow" prompt can't be clicked by a test, so most of it runs on a copy of the extension that already has website access.) It needs Playwright (`npm i playwright` and `npx playwright install chromium`); without it, it skips.

- `contract.test.js` checks the shared fixtures against the interface contract in [`docs/interfaces.md`](docs/interfaces.md).
- `rules.test.js` checks each scam rule: an example that should trigger it and one that should not.
- `regression.test.js` runs 102 realistic scam and legitimate examples in fourteen groups (fake account alerts, prizes, delivery fees, tech support and refund scams, grandparent scams, investment and crypto, jobs, recovery, blackmail, look-alike addresses, link mismatches, real bank alerts, real marketing, and articles about scams), each with the verdict it should get and the exact explanation the person reads. Readable version: [`docs/regression-cases.md`](docs/regression-cases.md).
- `robustness.test.js` checks hostile input: huge or tricky text can't slow the checks down, invisible or look-alike letters can't hide a company name, address tricks can't get past the known-dangerous list, and malformed input never crashes anything.
- `service-worker.test.js` checks threat lookups and the blocking rules Chrome gets (including that normal addresses are never blocked).
- `speech.test.js` checks reading aloud.

Node is only needed for running tests. The extension itself is plain JavaScript that Chrome runs directly.

The tests end with two numbers:

```
302/302 tests passed
Scams caught:          18/18
False alarms (normal): 0/15
```

Every rule has at least one example that should trigger it and one that should not, and the policy tests check which combinations of signs lead to each verdict (for example, a strange website ending or an urgent phrase on its own never stops a click). The tests also check the trickiest address cases directly: `paypal.com.fake-domain.example` must never count as PayPal, `paypal.com@evil.example` really goes to evil.example, and two `github.io` sites belong to different people.

Be honest about what these mean: we wrote these examples ourselves, alongside the rules, so of course the rules pass them. The same goes for the 102 regression examples. They show the extension *works*, not that it catches scams *in general*. For the submission, collect a separate set of real-world-style examples (scam **and** normal emails, ads, and sign-in pages) that nobody tuned the rules on, and report those numbers too.

**When you add a new rule, add a test that should trigger it AND a normal example that should not.**

## Testing safely

- **Never use real scam links.** Use made-up addresses ending in `.example`, which can never be real websites.
- Use a separate test Gmail account for sending yourselves practice scam emails.
- Keep track of how many test emails the extension gets right; this accuracy number goes in our submission.

## Known limits

- **The known-dangerous list is a practice list.** It only has made-up `.example` addresses until we connect a real source (Step 4b). The blocking machinery is real and tested; the list isn't. Until a real source is connected, the "Stop and check" warnings are what protect people.
- **Not every way of opening a link is caught.** Normal clicks, middle clicks, Ctrl/Cmd clicks, and Enter are. "Open in new tab" from the right-click menu, and pages that move you somewhere with their own code, are not (except known dangerous websites, which Chrome blocks however you get there). Test each new case before claiming it works.
- **Ads we can't read can't be checked.** Clicks inside ad frames are checked, but an ad that's only a picture with no words or description gives us little to go on.
- **A scam ad placed directly in a real website's page** (not in its own frame) can make the whole page get a "Be careful" warning.
- **A sign-in page with a company's name on it** (in its title or main heading) that isn't on that company's website gets a warning, even if it's a real partner site.
- Gmail sometimes changes its page layout. If the panel stops appearing, check the `SELECTORS` at the top of `gmail.js`.
- Rules can't catch every scam, especially new tricks, and scammers can avoid our exact wording.
- **Investment, job, recovery, and blackmail checks look for the moment money or details are asked for.** Romance and investment scams build trust for weeks, mostly in chat apps we can't see; the extension only helps once that conversation reaches an email, an ad, or a website. The famous-name list (`data/people.js`) is hand-picked, and a famous name alone never counts: only with an investment offer.
- **Some honest messages are noted:** a real receipt that gives a phone number to cancel ("Be careful", never "Stop") and a CD or annuity ad that says "guaranteed returns" (on a website it needs a second sign). A real employer who asks you to *email* your bank or Social Security number gets "Stop and check" on purpose: an email can't show whether there was an interview, and sending those numbers by email is unsafe even for a real job. Safety advice is recognized when it says "not", "never", "no", or "if someone…" right before the scam words, or mentions scams twice; advice worded any other way can still be flagged.
- **An email from a company's own address, with links only to that company, is trusted like the company's website.** That stops false alarms on real bank alerts, but a forged sender address on a real company's domain would get the same trust. Gmail usually rejects or flags those, but not always.
- **Shortened and tracking links aren't followed.** We never open a link to see where it goes (that could warn the scammer, and the answer can change depending on who asks). A shortened link stays a weak warning sign. Only well-known pass-through services that write the destination into the link are followed.
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
- [x] Step 5a: Service worker: threat lookups (match / no match / error), browser-level blocking built from the list (updates, duplicates, expiry, false positives), settings, and the extension's own warning page. Tested with made-up addresses only.
- [ ] Step 4b: Fill the known-dangerous list from a maintained source. Check its current API, terms, and privacy first: Google Safe Browsing (use **v5**; v4 is deprecated) is for non-commercial use only, Google Web Risk is the commercial version, and open phishing feeds are another option. A lookup service that receives the addresses you visit changes our privacy promise, so update [Privacy](#privacy) first.
- [ ] Step 5 (only if testing shows rules miss real cases): AI plain-language summary and second opinion on risk
- [ ] Step 6: "Ask someone I trust" button and an options page
- [ ] Step 7: Test with 15–20 practice emails and with older adults
- [ ] Step 8: Demo video and submission write-up

## Privacy

**What it reads:** in Gmail, the email you have open (sender, subject, text, links). On other websites, the page's address, title, main heading, visible words, whether it has a password box and where that box sends what you type, and the link you click plus the words around it.

**What it sends:** nothing. Every check happens inside your own browser, and the extension has no server. Looking addresses up with an online threat service is built but **off**, and only a pretend (development) service exists; see [`docs/threat-intelligence.md`](docs/threat-intelligence.md). Turning a real one on would send the addresses you check to that service, and this section must say so first.

**What it saves, on your computer only:** the protection settings, updates to the known-dangerous list, and, until you close the browser, the warnings shown on the warning page (the link's address and the reasons). Nothing you type, and no browsing history.

**Permissions it asks for, and why.** At install, only the three without website access. Website access is asked for on the welcome page, can be all websites or Gmail only, and can be taken back at any time; without it, known dangerous websites are still blocked.

| Permission | When | Why |
|---|---|---|
| Access to `http`/`https` websites (optional) | Only when you choose it on the welcome or settings page | To check pages and links, inside ads, and in Gmail. Chrome shows this as "read and change all your data on all websites." Choose "Gmail only" to allow just `mail.google.com`. |
| `declarativeNetRequest` | At install | To have Chrome block known dangerous websites before they load. Chrome does this matching itself; the extension doesn't see your browsing history. Chrome shows this as "block content on any page." |
| `storage` | At install | To keep the settings and the known-dangerous list (`storage.local`), and to pass a warning to the extension's own warning page (`storage.session`, gone when the browser closes). |
| `scripting` | At install | To start or stop checking pages when you give or take back website access, or turn protection off. |

It never asks for cookies, browsing history, tabs, or anything else.

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
