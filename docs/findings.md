# Findings from Phase 7 testing

What the systematic testing turned up, including what it got wrong. Numbers come from `docs/test-results.md`.

## Bugs found and fixed

| Bug | How it was found | Fix |
|---|---|---|
| **A prize ad was not stopped when clicked** if the link's own `id` started with `ad-` (for example `ad-prize-link`). The detector took the link itself as "the ad", so the ad's wording was never seen and the click went through | The new `fake-ad.html` page: clicks on both prize ads navigated freely while the earlier `ads.html` tests passed | An ad is now the **outermost** marked element that is still small enough to be one ad unit, not the innermost. Covered by `fake-ad.html` tests and the click matrix |
| A stray number typed into the website list was stored as the address `0.0.0.5` | `tests/settings.test.js` (Phase 6) | Only text is accepted |
| Test pages served over plain `http` made every form look "insecure", hiding real behavior | Reviewing why `fake-webpage.html` and `fake-legitimate.html` warned | Tests now serve pages over `https://pages.example/` and test plain `http` separately |

## Measured behavior worth knowing (not changed)

- **False positives.** About 3 in 10 legitimate cases are flagged (mostly emails). The causes are the wording rules firing on real senders (a real UPS notice, a real Chase fraud alert, a doctor's reminder, a utility bill), shortened links, and links that go through a tracker (a news digest, an ad network). None is hard-blocked. They are all "caution", but they will teach people to ignore warnings if they are common. Candidate fixes for Phase 8: lower the severity, and soften the words, when the sender and every link belong to a verified brand domain; ignore known ad-tracker and email-tracking hosts in the "hidden destination" check; treat a shortened link alone as a hint, not a warning.
- **Misses.** Seven of the eight deliberately hard scams get no warning: polite phishing with no usual words, a voicemail lure, a QR-code lure, a fake tech-support page with no form or link, a "free gift" page whose card form stays on its own site, an ad with no claim wording, a look-alike of a brand we do not know. A fake Microsoft sign-in page on an unrelated address is also missed because its only strong sign is the page's claim. These are limits of rules that look for known patterns. They are the case for a maintained threat list and, later, a second opinion.
- **One password form to another site is not a warning by itself** over https. A real single-sign-on page looks the same. It does warn when combined with other signs, or over plain http.
- **Plain-http pages with a login form warn** (correctly: no secure connection), and the warning grows stronger if the page also talks about gift cards or passwords, even in an anti-scam article. The legitimate-page tests use https for that reason.
- **Ordinary ads that go through an ad tracker** are stopped when clicked ("a link says it goes to shoes.example, but it really goes to ad.doubleclick.net"). The person can continue, and the test checks that continuing works.
- **Performance** is not a problem on a deliberately huge page: the first scan takes tens of milliseconds, and a thousand ad insertions cause two brief slowdowns, not a stream. See the table in `docs/test-results.md`.

## Limits confirmed (see `docs/testing.md`)

A novel malicious address typed into the address bar, a page that moves you with its own script, an unknown redirect service, a link clicked inside a frame, and a cross-origin frame are not stopped or read. These are asserted by tests so no one overstates the protection.

## Not yet done

Participant sessions, a real extension reload, real Gmail, a real screen reader, and Phase 8's false-positive fixes.
