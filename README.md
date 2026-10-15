# Email Anti-Scam

A Chrome extension that helps older adults spot scam emails in Gmail. When an email is opened, a large, easy-to-read panel shows a clear verdict (🛑 scam / ⚠️ be careful / ✅ no warning signs), explains *why* in plain words, and tells the reader exactly what to do next. It can also read everything out loud.

*Built for the 2026 Congressional App Challenge.*

## The problem

Scammers target older adults by email because many are less familiar with newer technology and the tricks scammers use: fake bank alerts, fake delivery notices, "you've won" messages, and emails pretending to be a grandchild in trouble. Warnings in today's email apps are small, technical, or missing, and one wrong click can cost someone their savings.

> TODO: add one or two statistics from a trusted source (for example, the FBI's annual Elder Fraud Report from IC3) and link to it.

## What it does (version 0.1)

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
2. Open `tests/fake-gmail.html` in Chrome.
3. Click the test emails at the top and watch the panel change.

### Option B: in real Gmail

1. Open Chrome and go to `chrome://extensions`.
2. Turn on **Developer mode** (top right).
3. Click **Load unpacked** and choose the `extension` folder.
4. Open Gmail and open any email. The panel appears on the right.
5. After changing any code, click the ↻ reload button on the extension's card, then refresh Gmail.

## How it works

```
Gmail page
  └─ content.js    finds the open email and reads sender, subject, text, and links
       └─ rules.js analyzeEmail() adds up "risk points" for each warning sign
            0 points   → ✅ No warning signs found
            1–4 points → ⚠️ Be careful
            5+ points  → 🛑 Looks like a scam
       └─ panel shows the verdict, reasons, links, and what to do
```

Every warning comes from a rule a person can read and understand, so the extension can always explain *why* it is warning you.

## Project structure

| File | What it does |
|---|---|
| `extension/manifest.json` | Tells Chrome what the extension is and that it runs on Gmail |
| `extension/content.js` | Reads the open email in Gmail and builds the panel |
| `extension/rules.js` | All the scam checks and the scoring |
| `extension/panel-styles.js` | How the panel looks (big text, colors) |
| `tests/rules.test.js` | Automatic tests for the scam checks |
| `tests/fake-gmail.html` | Practice page that imitates Gmail |

## Running the tests

If you have [Node.js](https://nodejs.org) installed, run this from the project folder:

```
node tests/rules.test.js
```

Node is only needed for running tests. The extension itself is plain JavaScript that Chrome runs directly.

**When you add a new rule, add a test email that should trigger it.**

## Testing safely

- **Never use real scam links.** Use made-up addresses ending in `.example`, which can never be real websites.
- Use a separate test Gmail account for sending yourselves practice scam emails.
- Keep track of how many test emails the extension gets right; this accuracy number goes in our submission.

## Known limits

- Gmail sometimes changes its page layout. If the panel stops appearing, check the `SELECTORS` at the top of `content.js`.
- Rules can't catch every scam, especially new tricks. The AI step below is meant to cover what rules miss.
- Gmail in Chrome only, for now.

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

Version 0.1 sends nothing anywhere: every check happens inside your own browser, and the extension asks for no special permissions. When AI and Safe Browsing are added, only the email's text and links will be sent, only for the email you have open, and nothing will be saved.

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
