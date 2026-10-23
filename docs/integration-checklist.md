# Integration checklist

Short and shared. When something in the other person's area needs to change, add it here instead of editing their code. Tick it off when the fix is merged with its tests.

## The merge (both branches into `claude/friendly-mayer-hx20bc`)

Person B's branch (`claude/new-session-yy3c1k`) had started from the first commit and built its own versions of features Person A's branch also had. Decided by Person A: **Person A's engine, data, and service worker; Person B's screens.** Retired files are still in git history.

What was done:
- [x] **Retired (A):** `guard.js`, `warning.js`, `gmail.js`, `blocked.html` / `blocked.js`, `settings.html` + its `settings.js`, `settings-sync.js`, `speech.js` (+ `tests/speech.test.js`), `tests/practice-*.html`, `tests/browser/acceptance.test.js` (+ its pages). Their unique checks moved to `tests/browser/blocking.test.js` (blocking, fresh install, restart).
- [x] **Retired (B):** the temporary engine `analyzer.js` and `threats.js`, and `tests/analyzer.test.js` / `tests/ads-analyzer.test.js`. All of B's examples now run against the shared engine in `tests/screens.test.js`.
- [x] **Wiring:** B's screens call four helpers in `rules.js` (`checkWebpage`, `checkLinkClick`, `checkEmail`, `stopsPerson`; `docs/interfaces.md` section 3a). The page scripts are registered by the service worker for the website access given (`background/content-scripts.js`): the engine and the click guard in every frame, the page scanner in the main page, the Gmail reader on Gmail.
- [x] **Service worker:** A's, now also answering B's `SHOW_WARNING` (opens `ui/warning.html`), `CONTINUE` (checked again, never to a known dangerous website), and `REPORT_FALSE_ALARM`. Chrome's blocking redirects to B's warning page. The toolbar button says OFF when protection is off.
- [x] **One settings switch:** B's `settings.js` (key `settings`) holds the person's choices; A's lookup and false-positive settings moved to `engineSettings`. `protectionEnabled` is `settings.enabled`, stored once.
- [x] **Website access (A's permission model):** website access is optional and asked for on the welcome page, which is now B's settings page with a "Website access" section and the permissions explained. The popup says when a page isn't checked because access wasn't given.
- [x] **Contract:** `docs/interfaces.md` is A's version plus B's scanner fields (`ads`, `adFrames`, `scan`, `truncated`, `hasPayment`, `method`, `fieldCount`) and `context.inAd`.
- [x] **Tests:** all Node suites and all browser suites from both branches pass on the merged extension. B's browser harness now runs a copy of the extension with website access, answers every test address itself, and serves the practice pages over plain `http://pages.example/` too.

Changes inside the other person's files (please review):
- [ ] **B (please review):** `ui/explain.js`: `warn` + `VERIFY_INDEPENDENTLY` now reads **"Be careful: check this first"** (label BE CAREFUL), because the engine's weaker level never stops anyone; "Stop and check this first" is only for `GO_BACK` / `DO_NOT_ENTER_INFO`. The TEMPORARY old-shape handling is removed. In Gmail the advice is about the email ("Do not click any links in this email…"), not "close this page" (`panel.js` option `where: 'email'`).
- [ ] **B (please review):** `click-guard.js` and `page.js` act only when `stopsPerson(result)`; a "Be careful" result lets the click through and shows no page card. `click-guard.js` passes `inAd`, and the open email's result in Gmail (a link inside a scam email is stopped).
- [ ] **B (please review):** test changes to fit the engine: practice links that showed `www.mybank.example` now show `www.chase.com` (a link that shows a company's real website but goes elsewhere stops; one that shows an unknown website is only "Be careful"); the fake-login link says "Verify your **PayPal** account now"; the redirect-wrapped number address says "Log in to Wells Fargo"; Gmail scam emails expect CAUTION, not DANGER; the ad-tracker "known false alarm" test now checks that the ad is NOT stopped; locators click the button, not text that matches the advice.
- [ ] **B:** `options.html` / `options.js` gained the welcome text, the "Website access" section, the permissions list, and a line about the scam stories the checks know. Reword as you like.
- [ ] **A (please review, done by the merge):** three engine changes that B's tests found:
  - a prize ad (`inAd`) whose claim button goes to a website we can't tie to the company now stops (`UNVERIFIED_PRIZE_CLAIM` is moderate in an ad);
  - on websites, wording right after "not" / "never" in the same clause is advice ("never pay with gift cards"), and "congratulations to Dot, winner" is someone else's prize (both were false alarms on B's library page);
  - `INSECURE_FORM` also covers a password or card box on a page that isn't itself secure (not `localhost`).

Decisions to confirm (both):
- [ ] **Email `block`:** B's engine used `block` (DANGER) for a high-scoring scam email. The contract keeps `block` for known dangerous websites only; a scam email is `warn` + `GO_BACK`.
- [ ] **One moderate sign alone is "Be careful", not a stop:** a look-alike address alone, a raw number address, a link that shows an unknown website but goes elsewhere. B's engine stopped these. On B's labelled examples the merged engine stops 23/37 scams and 0/37 legitimate cases (31/37 scams and 11/37 legitimate are at least noted). If you'd rather stop more, it's one line in `core/risk-policy.js`, and `node tests/metrics.js` shows the cost.

Open items for B:
- [ ] **B:** Remote lookups: when they're turned on, follow "Remote lookups" in `docs/interfaces.md` in `click-guard.js` (hold the click when `whenToLookUp()` says `before_opening`, show "Checking this link…", never let a slow or failed lookup open the link). Lookups are off, so nothing is lost today.
- [ ] **B:** Reading aloud: A's `speech.js` showed a message when the computer couldn't speak (no voices). `warning-view.js` doesn't yet.
- [ ] **B:** The page scanner keeps 20,000 characters of visible text per scan; the engine reads up to 50,000. A pop-up added at the end of a very long page may be cut (`context.truncated` says so).
- [ ] **B:** Map reason codes to custom wording or icons if you want (everything falls back to `title` / `explanation`). New codes since B's branch: everything in the reason-code table, including `INVESTMENT_PROMISE`, `CRYPTO_GIVEAWAY`, `CELEBRITY_ENDORSEMENT`, `DEPOSIT_TO_TRADE`, `INVESTMENT_PITCH`, `JOB_FEE`, `OVERPAYMENT`, `JOB_DETAILS_REQUEST`, `RECOVERY_FEE`, `SEXTORTION_THREAT`, `CHARGE_WITH_PRESSURE`.
- [ ] **B:** Run the usability sessions (`docs/usability-testing.md`; the expected verdicts are updated for the merged engine), record them, score them, and make at least one change from what participants actually did. None done yet.
- [ ] **B:** Manual checks that can't be automated: a real extension reload, real Gmail (selectors and Gmail's link redirects), a real screen reader, 200% zoom, read-aloud on real sites (Chrome may block speech until the page is clicked), incognito (`docs/testing.md`).
- [ ] **B:** The corner warning card can cover the page (concern C1 in `docs/usability-findings.md`).
- [ ] **B:** The scanner doesn't look inside cross-origin frames or shadow DOM; decide whether ads need that, with a privacy review, before the Web Store listing.
- [ ] **B:** `dynamic-ad.html` and some other practice pages are only checked by hand; add them to the browser tests.

Open items for both:
- [ ] **Both:** Measure scams caught and false alarms on a set of examples nobody tuned the rules on (the regression cases and `tests/corpus/` are development sets).
- [ ] **Both:** Choose the threat-intelligence provider and privacy model (`docs/threat-intelligence.md`) before adding one, and update the README Privacy section in the same pull request.
- [ ] **Both (Web Store):** write the justification for optional access to all websites and for `declarativeNetRequest`, and disclose the local false-alarm reports in the listing.
- [ ] **Deferred by decision:** "Ask someone I trust" (sharing an email or link with another person). Design consent, what is shared, and sensitive-data handling first.

## History: what each person built before the merge

Person A (engine, data, service worker), Phases 0–8: the contract and fixtures; the modular engine (`core/`) with address, company-name, wording, and policy rules and plain explanations; known-threat blocking with Chrome's rules, threat lookups (off; a development mock only), expiry, false positives, and restart tolerance; optional website access; the regression fixtures, robustness and security tests; engine data moved to `extension/data/`; investment, job, recovery, and blackmail scams. Details: `git log`, `docs/regression-cases.md`, `docs/threat-intelligence.md`.

Person B (screens), Phases 1–7: the page scanner (`content/page-scanner.js`) with dynamic scans and size limits; ad recognition (`content/ad-signals.js`, `docs/ad-support-matrix.md`); the click guard (`docs/click-guard-limits.md`) and the extension-owned warning page; the shared warning interface (top 3 reasons, Go back to safety, read aloud, false-alarm report, keyboard and screen-reader labels); the Gmail adapter; settings, the toolbar popup, and the settings page; practice pages, systematic browser tests, the click-protection matrix (18/18 supported scenarios stopped), performance budgets, the labelled corpus and metrics, and the usability plan. Details: `git log`, `docs/testing.md`, `docs/findings.md`.
