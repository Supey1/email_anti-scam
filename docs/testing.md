# Testing

How the extension is tested, what each measure means, and what the tests deliberately do **not** claim.

## Run everything

```
npm install            # only needed for the browser tests (Playwright)
npm test               # every test below, one summary  (npm run test:fast skips the browser tests)
npm run metrics        # re-measure accuracy and write docs/test-results.md
```
Without `npm`, run any file directly, for example `node tests/metrics.js`. If Playwright cannot find Chromium, set `CHROMIUM_PATH`. To run one browser test: `TEST_FILTER="part of the name" node tests/browser/systematic.test.js`.

## What is tested

| Layer | Files | What it checks |
|---|---|---|
| Scam checks | `tests/rules.test.js`, `regression.test.js`, `robustness.test.js`, `screens.test.js`, `service-worker.test.js`, `contract.test.js` | Every rule, realistic scam and legitimate examples, hostile input, what each screen gets (pages with ads, clicks, emails), blocking rules and service worker messages |
| Words in the interface | `tests/explain.test.js` | The same result reads the same way for every adapter |
| Settings and usability scoring | `tests/settings.test.js`, `usability-score.test.js` | Settings logic, popup status words, the scoring script |
| Accuracy | `tests/metrics.js` on `tests/corpus/cases.js` | The metrics below, with floors that catch regressions |
| Real browser, one feature each | `tests/browser/blocking`, `scanner`, `click-guard`, `ads`, `gmail-adapter`, `settings` | The real extension loaded into Chromium (`blocking`: known dangerous websites, a fresh install without website access, a browser restart) |
| Real browser, systematic | `tests/browser/systematic.test.js` | One group per practice page, plus frames, new tabs, keyboard, dynamic content, limits |
| Click protection metric | `tests/browser/click-matrix.test.js` | Every risky-click scenario: was navigation really stopped? |
| Performance | `tests/browser/performance.test.js` | Time and main-thread blocking on a huge, constantly changing page |

## Practice pages (`tests/pages/`, and `tests/fake-gmail.html`)

All addresses are made-up `.example` names; the browser tests answer them locally, so nothing touches the internet. Never replace them with real scam links.

| Page | What it tests |
|---|---|
| `fake-gmail.html` | Gmail extraction and the email panel (served as `https://mail.google.com/` in the tests) |
| `fake-webpage.html` | Generic extraction (hidden and typed text skipped), a mismatched link, a password form to another site |
| `fake-ad.html` | Promotional text and suspicious destinations; an ad inserted later; an ordinary ad behind an ad tracker (must not be stopped) |
| `fake-redirect.html` (+ `redirect-meta*.html`) | Redirects and click interception, including everything that is **not** stopped |
| `fake-form.html` | Form destinations, credential and card forms, typed values never collected |
| `fake-legitimate.html` | False positives: scary words, real brand links, ordinary ads, a normal login |
| `fake-iframes.html` | Same-origin and cross-origin frames |
| `ads.html`, `click-guard.html`, `fake-login.html`, … | The advertisement matrix and earlier click-guard scenarios |

The browser tests serve pages over `https://pages.example/` because a plain-`http` page is itself a warning sign for password and card forms. Some tests also open the page over plain `http` to check that.

## The metrics

| Metric | Definition | Where |
|---|---|---|
| **Scam detection rate** | Scam cases whose verdict is `warn` or `block`, out of all scam cases | `docs/test-results.md` |
| **False-positive rate** | Legitimate cases whose verdict is `warn` or `block`, out of all legitimate cases | same |
| **High-confidence block precision** | Of the cases that received `block`, the share that meet the block criteria below | same |
| **Click protection success** | Of the supported risky-click scenarios, the share where the browser never requested the destination, the page was not navigated there, and a warning appeared | `tests/results/click-protection.json` |
| **Explanation accuracy** | Of the flagged scams that have an expected explanation, the share whose top three reasons (what the person sees first) mention the real evidence and make no wrong claim | `docs/test-results.md` |
| **Usability success** | Share of scenario attempts where the person understood the verdict and chose an appropriate next step without help | `docs/usability-testing.md`: measured with people |

**Block criteria** (written down so the precision number means something): a case deserves a hard block when the destination is on the threat list, or a known brand is impersonated and the destination is not that brand's, or two or more independent strong signs appear together (for example a gift-card payment request plus a request for secrecy). Each corpus case is labelled with this before its result is looked at.

**Explanation accuracy is a permissive check.** It looks for the key evidence (for example the brand's name, or "number address") in the top three reasons and for wrong claims (for example naming the wrong company). A high score means the warnings did not misdescribe the evidence in these cases; it does not mean every sentence is easy to understand. That is what the sessions with older adults are for.

**Reading the numbers.** A high detection rate means nothing without the false-positive rate beside it: an extension that flags every page would catch every scam and fail its purpose. The test set was written alongside the code, so it is a development set. The deliberately hard cases are marked, and every miss and false alarm is listed by name in `docs/test-results.md`. The floors in `tests/metrics.js` stop things getting worse; they are not goals.

## Limits the tests assert on purpose

These are tested as *not stopped*, so the project does not claim more than is true (details in `docs/click-guard-limits.md`):

| Not stopped by the click guard | What still helps |
|---|---|
| Typing or pasting a novel malicious address into the address bar | The browser-level blocklist, but only for addresses on it |
| A page that moves you with its own script (`location`, `window.open`, a script clicking a link, a self-rewriting link, a form that submits to another site, a `<meta refresh>`) | A page redirecting to a **known** dangerous address is still blocked by the browser-level rule (tested) |
| An unknown redirect service | Nothing: the destination cannot be seen |
| A link clicked inside any frame | The ad inside a same-origin ad frame is still read and reported |
| A cross-origin frame (the usual ad-network case) | Counted as unreadable, never guessed at |
| An ad with no recognizable marker, in shadow DOM, or drawn as an image | Page-level and link checks only |

## Checks that cannot be automated here

Do these by hand and record the date and result in `docs/integration-checklist.md`:

1. **Extension reload.** A real reload cannot be driven in this headless Chromium (the extension is removed and not loaded again). Reload it at `chrome://extensions` with a page open: the open page should still cancel a risky click and show an in-page warning (the test "lost connection" simulates exactly this by cutting the page's connection), and pages opened afterwards should work normally.
2. **Real Gmail** with a test account (the tests use a Gmail-shaped practice page).
3. **A real screen reader**, Chrome zoom at 200%, and reading aloud on real sites.
4. **Usability sessions** with older adults: `docs/usability-testing.md`.
