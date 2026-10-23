# Usability findings and interface changes

## Study status

No participant sessions have been run. There are **no user findings yet**. Add them below after sessions, using the scoring script and your notes (`docs/usability-testing.md`).

## Interface changes so far, and where they came from

None of these came from participants. They come from the team's own review while testing, and each one needs to be confirmed or rejected in the sessions.

| # | Change | What prompted it | Evidence it works |
|---|---|---|---|
| H1 | The warning page now shows, side by side, **what the link said** ("You clicked a link that says: “www.mybank.example/statement”") and **where it really goes** ("It really goes to: other-site.example"). Before, it showed only the address. | Cognitive walk-through of the "hidden destination" warning: the reason sentence mentions both sites, but nothing on screen showed the person the link they had just clicked, so the warning is easier to dismiss as unrelated | Automated: the wording is checked in `tests/browser/click-guard.test.js`. **With people: not yet tested.** Watch scenarios U05, U11, U13 |

## Concerns to check in sessions (found during testing, not yet confirmed)

| # | Concern | How it showed up | What to watch |
|---|---|---|---|
| C1 | The page-level warning card sits in the top-right corner and can **cover part of the page**, including the link a person wants. The automated clicks had to remove it first | Test runs: "the warning card intercepts pointer events" | Do people find "Hide"? Do they feel stuck? Candidate fixes: a smaller card, or dock it at the bottom |
| C2 | Warnings about **ordinary senders and ads** (real UPS, doctor's office, ad trackers) use the same alarming headline, "Stop and check this first", as real scams | The false positives in `docs/test-results.md` | U06, U07, U13: do people lose trust in the tool? Candidate fix: a gentler headline and wording for weak, wording-only warnings |
| C3 | "No warning signs found" could be read as "safe" | The hard scam U09 is not detected | Do people stop thinking? Candidate fix: stronger wording, or a reminder under it |
| C4 | The popup and settings page were checked with keyboard and ARIA only | n/a | Real screen reader; Chrome zoom at 200% |

## Session log

| Date | Participants | Scenarios | Usability success | Main problems | Change made |
|---|---|---|---|---|---|
| | | | | | |
