# Email Anti-Scam

A Chrome extension that helps older adults spot scam emails, fake websites, and risky links. When an email is opened in Gmail, a large, easy-to-read panel shows a clear verdict (🛑 scam / ⚠️ be careful / ✅ no warning signs), explains *why* in plain words, and tells the reader exactly what to do next. It can also read everything out loud.

*Built for the 2026 Congressional App Challenge.*

## The problem

Scammers target older adults by email because many are less familiar with newer technology and the tricks scammers use: fake bank alerts, fake delivery notices, "you've won" messages, and emails pretending to be a grandchild in trouble. Warnings in today's email apps are small, technical, or missing, and one wrong click can cost someone their savings.

> TODO: add one or two statistics from a trusted source (for example, the FBI's annual Elder Fraud Report from IC3) and link to it.

## What's new in version 0.2

Protection now works across the web, in three levels:

1. **Block** known dangerous websites before the page loads (service worker + Chrome network rules). There is no way past this screen.
2. **Warn** before a risky link is followed: clicks on links with credible warning signs (fake company sites, hidden destinations, number addresses) are stopped, and a big warning explains why. The person can go back to safety or choose "Continue anyway".
3. **Explain** risky pages: a warning card appears on pages with warning signs that work together, such as a password form that sends your password to a different website, or a prize claim whose button leads off-site. A scary word alone never triggers a warning, so a news article about gift card scams is left alone.

Still true: it runs on your computer, and every warning comes from a readable rule.

## What it does (version 0.1, still included)

- Notices when you open an email in Gmail and checks it automatically
- Shows a big-text panel with high contrast, color **and** icons, and short sentences
- Checks every link for warning signs:
  - links that pretend to be a company (`paypa1-secure.xyz`)
  - links whose words say one website but really go to another
  - number addresses, shortened links, and risky website endings
- Checks the sender: a company name with a personal or fake email address
- Checks the wording: gift cards and wire transfers, "your account is locked," rushing, secrecy, prizes, fake delivery notices, tech-support scams, and the "grandparent scam"
- **🔊 Read to me** button that reads the verdict and advice aloud
- Runs entirely on your computer; no email content leaves your browser

## Try it

### Option A: the practice page (no Gmail needed)

1. Download this repo (green **Code** button, then **Download ZIP**) and unzip it.
2. Open `tests/fake-gmail.html` in Chrome. (Scripts load straight from the repo, so no extension install is needed.)
3. Click the test emails at the top and watch the panel change.

### Option A2: the webpage practice pages

(Also `ads.html`: the advertisement matrix. The first group of ads should warn when clicked, the ordinary ones should not, and nothing is hidden.)

1. Load the extension (steps 1–3 of Option B below), then run `python3 -m http.server 8000` inside `tests/pages`.
2. Open `http://localhost:8000/fake-login.html`, `prize-ad.html`, `dangerous-link.html`, and `legit-shop.html`. The first two should warn; the shop should not.
3. On `dangerous-link.html` and `click-guard.html`, click the links. The suspicious ones do not open and show a warning; `known-phish.example` is on the built-in blocklist and has no continue button; the ordinary ones open normally.
4. To see saved false-alarm reports: `chrome://extensions` > Email Anti-Scam > service worker > Console, then `chrome.storage.local.get('falseAlarms')`.

### Option B: in real Gmail

1. Open Chrome and go to `chrome://extensions`.
2. Turn on **Developer mode** (top right).
3. Click **Load unpacked** and choose the `extension` folder.
4. Open Gmail and open any email. The panel appears on the right.
5. After changing any code, click the ↻ reload button on the extension's card, then refresh Gmail.

## How it works

```
Gmail page, or any webpage
  └─ gmail-adapter.js / page-scanner.js   collect evidence (sender, subject, text, links, forms, ads)
       └─ analyzer.js analyze()           applies the readable rules (rules.js) and returns a verdict with reasons
            block / warn / no warning signs
       └─ warning panel, or click-guard.js stops a risky click and opens the warning page
```

Every warning comes from a rule a person can read and understand, so the extension can always explain *why* it is warning you.

## Project structure

| File | What it does |
|---|---|
| `extension/manifest.json` | Tells Chrome what the extension is, where it runs, and its permissions |
| `extension/content/gmail-adapter.js` | Reads the open Gmail email (sender, subject, text, links). All Gmail-specific selectors live here |
| `extension/content/gmail.js` | Connects the Gmail adapter to the analyzer and the warning panel |
| `extension/content/ad-signals.js` | Recognizes advertisements on a page and describes them as evidence (never hides or blocks them). See `docs/ad-support-matrix.md` |
| `extension/content/page-scanner.js` | Collects evidence from webpages (text, links, form metadata), including content added later. Never reads typed values |
| `extension/page.js` | Connects the scanner, the analyzer, and the warning card on ordinary webpages |
| `extension/content/click-guard.js` | Stops a risky link click before the browser navigates (limits: `docs/click-guard-limits.md`) |
| `extension/ui/warning.html`, `warning.js` | The extension-owned warning page (can't be removed by a website) |
| `extension/ui/explain.js`, `warning-view.js` | One place for the warning's words and layout: headline, top reasons, safe action, read aloud, false-alarm report |
| `extension/rules.js` | The email, link, and wording checks and the scoring |
| `extension/analyzer.js` | The common `analyze(evidence)` entry point for webpages, ads, links, and emails; returns block / warn / allow with reasons |
| `extension/threats.js` | Built-in list of known dangerous websites (demo `.example` addresses) |
| `extension/service-worker.js` | Blocks known dangerous websites before they load |
| `extension/panel.js`, `panel-styles.js` | The in-page warning card and its look |
| `tests/rules.test.js` | Automatic tests for the email checks |
| `tests/scanner-merge.test.js`, `tests/browser/scanner.test.js` | Tests for the webpage scanner (the browser test needs Playwright) |
| `tests/ads-analyzer.test.js`, `tests/browser/ads.test.js`, `tests/browser/gmail-adapter.test.js` | Tests for advertisements and for the Gmail adapter (including the fake Gmail page) |
| `tests/explain.test.js`, `tests/browser/click-guard.test.js` | Tests for the warning wording and for stopping clicks in a real browser |
| `tests/analyzer.test.js` | Automatic tests for webpage and link checks; prints caught-vs-false-alarm counts |
| `tests/pages/` | Practice webpages for trying the extension |
| `tests/fake-gmail.html` | Practice page that imitates Gmail |

## Running the tests

If you have [Node.js](https://nodejs.org) installed, run this from the project folder:

```
node tests/rules.test.js
node tests/analyzer.test.js
node tests/scanner-merge.test.js
node tests/explain.test.js
node tests/ads-analyzer.test.js
node tests/browser/scanner.test.js       # browser tests need Playwright: npm i playwright
node tests/browser/click-guard.test.js
node tests/browser/ads.test.js
node tests/browser/gmail-adapter.test.js
```

Node is only needed for running tests. The extension itself is plain JavaScript that Chrome runs directly.

**When you add a new rule, add a test email that should trigger it.**

## Testing safely

- **Never use real scam links.** Use made-up addresses ending in `.example`, which can never be real websites.
- Use a separate test Gmail account for sending yourselves practice scam emails.
- Keep track of how many test emails the extension gets right; this accuracy number goes in our submission.

## Known limits

- Gmail sometimes changes its page layout. If the panel stops appearing, check the `SELECTORS` at the top of `extension/content/gmail-adapter.js` (`GmailAdapter.diagnose()` shows which ones still match). The adapter is tested against a Gmail-shaped practice page, not live Gmail.
- Rules can't catch every scam, especially new tricks. The AI step below is meant to cover what rules miss.
- Chrome only. A Chrome extension cannot see other apps, text messages, or phone calls.
- The link guard covers ordinary clicks and the Enter key. It does not catch a website's own script opening a page, or links opened from the right-click menu.
- Advertisements: only ads that carry a recognizable marker are examined, and ads in other websites' frames (the usual ad-network case) can't be inspected. The extension flags suspicious ads and never hides or blocks ads. The exact list is in `docs/ad-support-matrix.md`.
- The built-in blocklist is a tiny demo list. A real, maintained source (Step 4) is needed before this protects anyone from real threats.
- The tests are a small set of examples. They show the checks work as designed, not that the extension is reliable against scams in general.

## Roadmap

- [x] Step 1: Repo and project setup
- [x] Step 2: Extension that reads Gmail and shows the big-text panel
- [x] Step 3: First set of rule-based scam checks
- [ ] Step 4: Check links against Google Safe Browsing (known dangerous sites)
- [ ] Step 5: AI plain-language summary and second opinion on risk
- [ ] Step 6: "Ask someone I trust" button and an options page
- [ ] Step 7: Test with 15–20 practice emails and with older adults
- [ ] Step 8: Demo video and submission write-up

## Privacy

Version 0.2 sends nothing anywhere: every check happens inside your own browser. To check webpages and links on any site, it asks Chrome for permission to read all websites, a network-rules permission used for blocking, and local storage. Storage holds only false-alarm reports you choose to send during testing (the website's name, the verdict, the reasons shown, and the time; the last 100), and they never leave your browser. It reads page text, links, and forms only to run its checks, and saves nothing. When AI and Safe Browsing are added, only the email's text and links will be sent, only for the email you have open, and nothing will be saved.

## Working together

Two workstreams (detection engine and browser protection) share one analyzer contract. See [`docs/WORKING_AGREEMENT.md`](docs/WORKING_AGREEMENT.md) for the rules, [`docs/interfaces.md`](docs/interfaces.md) for the contract, and [`docs/integration-checklist.md`](docs/integration-checklist.md) for open integration issues.

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
