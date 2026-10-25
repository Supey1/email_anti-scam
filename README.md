# Granblock

A Chrome extension that stands between an older adult and a risky click. It checks emails in Gmail, the websites you visit, and the links and ads on them. When something looks like a scam, it steps in **before** you go there: a big, plain-language warning explains *what* looks wrong and *what to do instead*, and can read itself out loud.

*Built for the 2026 Congressional App Challenge.*

## The problem

Scammers target older adults by email because many are less familiar with newer technology and the tricks scammers use: fake bank alerts, fake delivery notices, "you've won" messages, and emails pretending to be a grandchild in trouble. Warnings in today's email apps are small, technical, or missing, and one wrong click can cost someone their savings.

> TODO: add one or two statistics from a trusted source (for example, the FBI's annual Elder Fraud Report from IC3) and link to it.

## What it does (version 0.6)

It protects at three levels. The stronger the evidence, the stronger the response.

| Level | When | What happens |
|---|---|---|
| 🛑 **Danger** (block) | The website is on the list of **known** dangerous websites | It never loads. The extension's own warning page appears instead. No way through. |
| ⚠️ **Stop and check this first** | Strong warning signs, like a link pretending to be your bank, or an ad promising a prize and rushing you | The click is cancelled and the extension's warning page explains why. "Go back to safety" is the big button; "I understand the risk. Continue anyway" is small. |
| ⚠️ **Be careful** | Weaker signs, like a shortened link or one rushed word | Shown in the Gmail panel, but **never** interrupts a click. Too many false alarms and people stop trusting the warnings. |

**In Gmail:**
- Notices when you open an email and checks it automatically, with a big-text panel: the verdict (icon **and** word, never color alone), the top three reasons, who sent it, where each link really goes, and what to do
- Checks the sender against each company's **own** email addresses. How much a mismatch matters depends on the message: a "PayPal" account alert from someone else's address is a real warning sign, but a newsletter sent through an email service (SendGrid, Mailchimp, GovDelivery...) is normal. A company's address written into the sender's *name* (`service@paypal.com <x@evil.example>`) is always a warning.
- Notices when an email says it's from a company but none of its links go to that company's website
- Checks the wording: gift cards and wire transfers, "your account is locked," rushing, secrecy, prizes, fake delivery notices and redelivery fees, tech-support scams, the "grandparent scam," and **urgent demands for money** ("pay today or you will be arrested")
- Knows that the IRS says it never emails people first to ask for money or personal details
- Catches "refund" scams (a surprise charge and a phone number to cancel it; with a deadline to call, it stops you) and "Hi Mom, this is my new number" messages
- Catches investment and crypto scams (guaranteed or impossible profits plus a deposit, "send crypto and get double back", famous names on fake investment offers, including the "sweetheart, I made 300% on this platform" end of romance scams), job scams (paying for equipment or training, "deposit our check and send back the difference", emailing your Social Security or bank number for a job), "we can recover the money you lost" for a fee, and blackmail emails ("pay or the video goes to your contacts")
- Doesn't warn about real bank alerts and newsletters sent from the company's own address with links only to the company, about ordinary marketing ("sale ends tonight"), or about newsletters that warn *about* scams
- Clicking *any* link in an email that looks like a scam brings up the "Stop and check" warning first

**On every website:**
- **Before a click:** checks where the link really goes and, for ads, what the ad says
  - links that pretend to be a company (`paypal.com.fake-domain.example`, `paypal.com@evil.example`, `paypa1-secure.xyz` when the link names PayPal), or whose words show a company's real website but go somewhere else
  - links through well-known pass-through services (Google, Outlook, Facebook, YouTube) are checked where they really end up
  - ads (recognized by their markers: `docs/ad-support-matrix.md`) that say *you* won a prize and send you to a website nobody can tie to the company, ask you to pay a fee or use gift cards first, promise guaranteed profits for a deposit, use a famous name to sell crypto, ask you to pay to start a job, or charge to "recover" lost money. Ordinary ads are left alone, and no ad is ever hidden.
  - clicks inside ads that load in their own frame are caught too, and the warning replaces the whole tab
  - ordinary clicks, Enter, middle-click, Ctrl/Cmd/Shift-click, new-tab links, links in shadow DOM and SVG (limits: `docs/click-guard-limits.md`)
- **On the page itself** (a card in the corner, only for strong signs): a page that looks like a company's sign-in page but isn't on that company's website, a password or card box that sends what you type to another website or to a known dangerous one, a sign-in page on a free hosting website, a password box on a page without a secure connection, a fake virus or prize pop-up (including content that appears after the page loads), or a scam ad on the page
- **Known dangerous websites** are blocked by Chrome itself, so typed addresses, redirects, and pop-ups are stopped too. Only a list from a trusted source blocks outright.

**Everywhere:**
- **🔊 Read to me** on every warning, at the speed you choose, or reading each warning out loud on its own
- **The toolbar button** answers three questions in plain words: Is protection on? Is this page being checked (and if not, why)? What can I do when I need help? It turns protection, or one website, on or off; the button says OFF when protection is off.
- **The settings page** (also the welcome page after installing): website access, protection on or off, Gmail on or off, which websites are checked (all except ones you turn off, or only ones you choose), reading aloud (with slow, normal, and fast speeds you can test), text size (only the sample line changes size), what is and isn't checked, every permission explained, and your saved "This is a false alarm" reports
- Every warning lists the actual evidence that triggered it, and "No warning signs found" never says "safe"
- Runs entirely on your computer; nothing you read or click is sent anywhere

The "Ask someone I trust" feature is **not built yet** on purpose: sharing a suspicious email or link with another person raises consent and sensitive-data questions that need their own design.

## Try it

### Option A: the Gmail practice page (no extension needed)

1. Download this repo (green **Code** button, then **Download ZIP**) and unzip it.
2. Open `tests/fake-gmail.html` in Chrome. (Its scripts load straight from the repo.)
3. Click the test emails at the top and watch the panel change.

### Option B: the real extension

1. Open Chrome and go to `chrome://extensions`.
2. Turn on **Developer mode** (top right).
3. Click **Load unpacked** and choose the `extension` folder.
4. The welcome page opens. Choose **Check all websites and Gmail**; Chrome then asks you to allow it to "read and change all your data on all websites." That's needed to check links and pages (see [Privacy](#privacy)). Until you allow it, the extension can only block known dangerous websites.
5. Open Gmail and open any email: the panel appears. Browse normally: warnings only appear when something looks wrong.
6. Click the extension's button in the toolbar to see whether a page is being checked, or open Settings from there.
7. To see blocking, type `known-phish.example` into the address bar. (It's on the practice list in `extension/data/threat-list.js`.)
8. After changing any code, click the ↻ reload button on the extension's card, then refresh the page.

### The webpage practice pages

With the extension loaded, run `python3 -m http.server 8000` inside `tests/pages`, then open `http://localhost:8000/`:
- `fake-login.html` (warns), `prize-ad.html` and `ads.html` (the scam ads warn when clicked; the ordinary ones don't, and nothing is hidden), `legit-shop.html` and `fake-legitimate.html` (no warnings)
- `dangerous-link.html` and `click-guard.html`: the suspicious links don't open and show a warning; `known-phish.example` is on the built-in blocklist and has no continue button; ordinary links open normally
- Every page is described in [`docs/testing.md`](docs/testing.md).

## How it works

```
1. COLLECT EVIDENCE (Person B)                 2. CHECK IT (Person A)              3. ACT (Person B)
content/gmail-adapter.js  the open email   ──►  checkEmail()      ──► Gmail panel
content/page-scanner.js   the page + ads   ──►  checkWebpage()    ──► corner card (strong signs only)
content/click-guard.js    a link clicked   ──►  checkLinkClick()  ──► the extension's warning page
                                                 (rules.js: analyze() + core/ + data/)

service-worker.js + background/  ►  Chrome blocks known dangerous websites before they load,
                                    opens the warning page, and applies your settings
```

Each check adds "risk points" for a warning sign (`core/risk-policy.js` says how many), and the answer comes with the list of signs that caused it:

| Evidence | Verdict | What the person sees |
|---|---|---|
| On the known-dangerous list from a trusted source | `block` | Danger, no way through |
| A strong sign, or 5+ points including a real warning sign | `warn` + `GO_BACK` (or `DO_NOT_ENTER_INFO` on a page with a password or card box) | Stop and check this first |
| Anything else that counts (weak signs alone, however many) | `warn` + `VERIFY_INDEPENDENTLY` | Be careful (Gmail only; never interrupts) |
| Nothing | `no_warning_signs` | No warning signs found (never "safe") |

Some signs only count together. "Lottery" on a news site is normal; "Congratulations, **you** have won... claim before midnight" next to a link to an unknown website is not. On websites, one scary phrase alone never counts. Links to another page on the same website, and links to a company's real website, aren't treated as offers.

Every warning comes from a rule a person can read and understand, so the extension can always explain *why* it is warning you. There is no AI in this version: it's a rules-based scam detection engine. The contract between the parts is [`docs/interfaces.md`](docs/interfaces.md).

## Project structure

| File | What it does |
|---|---|
| `extension/manifest.json` | Tells Chrome what the extension is and what it's allowed to do (website access is optional, asked for on the welcome page) |
| **Scam checks (Person A)** | |
| `extension/rules.js` | The front door: `analyze()` (see `docs/interfaces.md`), plus `checkWebpage`, `checkLinkClick`, `checkEmail`, `stopsPerson` for the screens |
| `extension/core/` | The checks, in groups: reading addresses, address rules, company-name rules, wording rules, the risk policy, and the plain-language explanations |
| `extension/data/` | Facts the checks use, kept apart from the rules: companies and their official websites, email services and ad networks, web-address lists, famous names used on fake investment ads, and the known-dangerous list (practice addresses for now) |
| `extension/service-worker.js`, `extension/background/` | Chrome's blocking rules from the known-threat list, threat lookups, starting the page scripts for the website access given, the warning page, settings, false-alarm reports |
| `extension/threat-sync.js` | Gives the checks in each page the same known-threat list Chrome blocks with |
| **Screens (Person B)** | |
| `extension/content/page-scanner.js`, `ad-signals.js` | Collect evidence from webpages (text, links, form metadata, ads), including content added later. Never read typed values |
| `extension/content/click-guard.js` | Stops a risky link click before the browser navigates |
| `extension/content/gmail-adapter.js`, `gmail.js` | Read the open Gmail email (all Gmail selectors live in the adapter) and show the panel |
| `extension/page.js` | Connects the scanner, the checks, and the warning card on ordinary webpages |
| `extension/ui/warning.html`, `warning.js` | The extension's own warning page: a website can't remove or fake it |
| `extension/ui/explain.js`, `warning-view.js`, `extension/panel.js`, `panel-styles.js` | One place for the warning's words and layout: headline, top reasons, safe action, read aloud, false-alarm report |
| `extension/ui/popup.*`, `status.js`, `options.*`, `ui.css` | The toolbar popup and the settings and welcome page |
| `extension/settings.js` | The person's choices, saved on this computer and shared by every part |
| **Tests and documents** | |
| `tests/` | See [Running the tests](#running-the-tests) |
| `tests/pages/`, `tests/fake-gmail.html` | Practice pages for each kind of check |
| `docs/interfaces.md` | The contract between the scanner, the checks, and the warning interface |
| `docs/WORKING_AGREEMENT.md`, `docs/integration-checklist.md` | Who owns which files, and open issues between the two workstreams |
| `docs/testing.md`, `docs/test-results.md`, `docs/findings.md`, `docs/regression-cases.md` | How the testing works, the latest numbers, what testing found, and every regression example with the words the person reads |
| `docs/usability-testing.md`, `docs/usability-findings.md` | The plan and scoring for sessions with older adults (none run yet) |
| `docs/threat-intelligence.md`, `docs/ad-support-matrix.md`, `docs/click-guard-limits.md` | Known-threat blocking, which ads are understood, and what the click guard can't catch |

## Running the tests

If you have [Node.js](https://nodejs.org) installed, run this from the project folder:

```
npm test              # everything (browser tests need Playwright: npm install)
npm run test:fast     # everything that doesn't need a browser
node tests/metrics.js # accuracy on the labelled examples, with every miss and false alarm listed
```

The scam checks:
- `rules.test.js` checks each scam rule: an example that should trigger it and one that should not, which combinations of signs lead to each verdict, and the trickiest address cases (`paypal.com.fake-domain.example` must never count as PayPal, `paypal.com@evil.example` really goes to evil.example, two `github.io` sites belong to different people).
- `regression.test.js` runs 103 realistic scam and legitimate examples in fourteen groups (fake account alerts, prizes, delivery fees, tech support and refund scams, grandparent scams, investment and crypto, jobs, recovery, blackmail, look-alike addresses, link mismatches, real bank alerts, real marketing, and articles about scams), each with the verdict it should get and the exact explanation the person reads. Readable version: [`docs/regression-cases.md`](docs/regression-cases.md).
- `robustness.test.js` checks hostile input: huge or tricky text can't slow the checks down, invisible or look-alike letters can't hide a company name, address tricks can't get past the known-dangerous list, and malformed input never crashes anything.
- `screens.test.js` checks what each screen gets from the checks (pages with ads, clicks, emails, and when a person is stopped).
- `service-worker.test.js` checks threat lookups, the blocking rules Chrome gets (normal addresses are never blocked), the warning page messages, and the on/off switch.
- `contract.test.js` checks the shared fixtures against the contract.

The screens: `explain.test.js` (the warning's words), `settings.test.js` (settings and the popup), `scanner-merge.test.js`, `usability-score.test.js`, and the real-browser tests in `tests/browser/`: blocking (known dangerous websites, a fresh install without website access, a browser restart), the scanner, the click guard, ads, Gmail, settings, every practice page (`systematic`), the click-protection matrix, and performance. The browser tests load the real extension into Chromium; most of them use a copy that already has website access, because Chrome's own "Allow" prompt can't be clicked by a test.

How the tests work, what each measure means, and what they deliberately do not claim: [`docs/testing.md`](docs/testing.md). Latest numbers: [`docs/test-results.md`](docs/test-results.md).

Node is only needed for running tests. The extension itself is plain JavaScript that Chrome runs directly.

Be honest about what these mean: we wrote these examples ourselves, alongside the rules, so of course the rules pass them. They show the extension *works*, not that it catches scams *in general*. For the submission, collect a separate set of real-world-style examples (scam **and** normal emails, ads, and sign-in pages) that nobody tuned the rules on, and report those numbers too.

**When you add a new rule, add a test that should trigger it AND a normal example that should not.**

## Testing safely

- **Never use real scam links.** Use made-up addresses ending in `.example`, which can never be real websites.
- Use a separate test Gmail account for sending yourselves practice scam emails.
- Keep track of how many test emails the extension gets right; this accuracy number goes in our submission.

## Known limits

- **The known-dangerous list is a practice list.** It only has made-up `.example` addresses until we connect a real source. The blocking machinery is real and tested; the list isn't. Until a real source is connected, the "Stop and check" warnings are what protect people.
- **One warning sign alone doesn't stop a click.** A look-alike address (`paypa1-secure.example`), a raw number address, or a link that shows one website and goes to another unknown one is a "Be careful" sign; it stops the click only with a second sign (like the link naming PayPal). This keeps false alarms down, and means some scams get only a note.
- **Not every way of opening a link is caught.** "Open in new tab" from the right-click menu, links dragged to the address bar, and pages that move you somewhere with their own code are not (except known dangerous websites, which Chrome blocks however you get there). See `docs/click-guard-limits.md`.
- **Advertisements:** only ads that carry a recognizable marker are examined, and ads in other websites' frames (the usual ad-network case) can't be read. An ad that's only a picture with no words gives little to go on. See `docs/ad-support-matrix.md`.
- **A sign-in page with a company's name on it** (in its title or main heading) that isn't on that company's website gets a warning, even if it's a real partner site.
- **Gmail:** the adapter is tested against a Gmail-shaped practice page, not live Gmail. If the panel stops appearing, check the `SELECTORS` in `extension/content/gmail-adapter.js` (`GmailAdapter.diagnose()` shows which still match). Gmail only shows us the sender's name and address, not the hidden headers that would prove who sent a message.
- **An email from a company's own address, with links only to that company, is trusted like the company's website.** That stops false alarms on real bank alerts, but a forged sender address on a real company's domain would get the same trust. Gmail usually rejects or flags those, but not always.
- **Investment, job, recovery, and blackmail checks look for the moment money or details are asked for.** Romance and investment scams build trust for weeks, mostly in chat apps we can't see. The famous-name list (`data/people.js`) is hand-picked, and a famous name alone never counts: only with an investment offer.
- **Some honest messages are noted:** a real receipt that gives a phone number to cancel ("Be careful", never "Stop") and a CD or annuity ad that says "guaranteed returns". A real employer who asks you to *email* your bank or Social Security number gets "Stop and check" on purpose: an email can't show whether there was an interview, and sending those numbers by email is unsafe even for a real job. Safety advice is recognized when it says "not", "never", "no", or "if someone…" right before the scam words, or mentions scams twice; advice worded any other way can still be flagged.
- **Shortened and tracking links aren't followed.** We never open a link to see where it goes (that could warn the scammer). A shortened link stays a weak warning sign.
- **Hand-picked lists:** email services and ad networks, companies and their official websites, and website endings (`core/url-normalizer.js` knows common two-part endings and free hosting sites, not the full Public Suffix List). Check each company entry against the company's own website.
- Rules can't catch every scam, especially new tricks, and scammers can avoid our exact wording.
- Chrome only. It can't see text messages, phone calls, or other apps on the computer.

## Roadmap

- [x] Step 1: Repo and project setup
- [x] Step 2: Extension that reads Gmail and shows the big-text panel
- [x] Step 3: Rule-based scam checks, including investment, job, recovery, and blackmail scams
- [x] Step 4a: Protection on every website: page scanner, ads, click guard, the extension's own warning page, and browser-level blocking of known dangerous websites (practice list)
- [x] Step 5a: Service worker: threat lookups (match / no match / error), blocking rules built from the list (updates, duplicates, expiry, false positives). Tested with made-up addresses only.
- [x] Step 6a: Settings page, welcome page, toolbar popup, optional website access
- [x] Step 7a: Systematic testing, metrics, and a record of false positives and misses
- [ ] Step 4b: Fill the known-dangerous list from a maintained source. Check its current API, terms, and privacy first: Google Safe Browsing (use **v5**) is for non-commercial use only, Google Web Risk is the commercial version, and open phishing feeds are another option. A lookup service that receives the addresses you visit changes our privacy promise, so update [Privacy](#privacy) first.
- [ ] Step 5 (only if testing shows rules miss real cases): AI plain-language summary and second opinion on risk
- [ ] Step 6b: "Ask someone I trust" (deferred: needs its own consent and privacy design)
- [ ] Step 7b: Test with 15–20 practice scenarios with older adults (plan and scoring ready: `docs/usability-testing.md`)
- [ ] Step 8: Demo video and submission write-up

## Privacy

**What it reads:** in Gmail, the email you have open (sender, subject, text, links). On other websites, the page's address, title, visible words, links, ads, whether it has a password or card box and where that box sends what you type, and the link you click plus the ad around it. Never anything you type.

**What it sends:** nothing about what you read or visit, by default. Every check happens inside your own browser, and the extension has no server. There are two optional online lists, both **off until you turn them on** in Settings, and you can use either or both:
- **Free list (Phishing.Database):** Granblock downloads a public list of phishing website names (about 10 MB, once a day, from GitHub) and checks it **on your computer**. The websites you visit are never sent. GitHub only sees that your computer downloaded the list.
- **Google Safe Browsing**, with your own free key from Google: for each website you open, and the links in an open Gmail email, Granblock scrambles the address into fingerprints (SHA-256 hashes) and sends Google only the **first 4 bytes** of each, which many unrelated addresses share; Google answers with the listed addresses that start the same way and Granblock compares the rest on your computer. The address itself, page contents, and anything you type are never sent. Google can still see your computer's address and your key. Your key is saved only on this computer and is never in the code.

Details: [`docs/threat-intelligence.md`](docs/threat-intelligence.md).

**What it saves, on your computer only:** your settings, updates to the known-dangerous list, and the "This is a false alarm" reports you choose to send during testing (the website's name, the verdict, up to five reasons shown, where, and the time; the last 100). You can save or delete the reports in Settings. No browsing history.

**Permissions it asks for, and why.** At install, only the four without website access. Website access is asked for on the welcome page, can be all websites or Gmail only, and can be taken back at any time; without it, known dangerous websites are still blocked.

| Permission | When | Why |
|---|---|---|
| Access to `http`/`https` websites (optional) | Only when you choose it on the welcome or settings page | To check pages and links, ads, and Gmail. Chrome shows this as "read and change all your data on all websites." Choose "Gmail only" to allow just `mail.google.com`. |
| Access to `safebrowsing.googleapis.com` (optional) | Only when you turn on Google Safe Browsing | To ask Google whether an address is on its list of dangerous websites. Taken back when you turn it off. |
| Access to `raw.githubusercontent.com` (optional) | Only when you turn on the free list | To download the Phishing.Database list. Taken back when you turn it off. |
| `unlimitedStorage` | At install | The free list has about 400,000 website names, more than Chrome's default storage allowance. Kept on this computer only. |
| `declarativeNetRequest` | At install | To have Chrome block known dangerous websites before they load. Chrome does this matching itself; the extension doesn't see your browsing history. Chrome shows this as "block content on any page." |
| `storage` | At install | To keep your settings, the known-dangerous list, and false-alarm reports on this computer. |
| `scripting` | At install | To start or stop checking pages when you give or take back website access, or turn protection off. |
| `tts` | At install | To read a warning out loud with your computer's own voices, at the speed you choose, including when "Read warnings out loud on their own" is on. Nothing is recorded or sent anywhere. |

It never asks for cookies, browsing history, or anything else.

If a threat-lookup service or AI is added later, this section must say exactly what is sent, to whom, and when, *before* that version ships. Don't promise that nothing leaves the browser once anything does. The Chrome Web Store also requires this disclosure, even for data that never leaves your computer.

**Also in this version.** Weak warning signs on ordinary websites now show a gentle "Be careful" card with the reasons (it never blocks a click); strong ones still stop you. The "Safety check" button in Gmail can be moved: press, hold, and drag it. The settings page marks the chosen website-access option with a check mark.

## Working together

Two workstreams (the scam checks and the browser screens) share one contract. Read [`docs/WORKING_AGREEMENT.md`](docs/WORKING_AGREEMENT.md) for the rules and who owns which files, [`docs/interfaces.md`](docs/interfaces.md) for the contract between them, and [`docs/integration-checklist.md`](docs/integration-checklist.md) for open issues.

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
