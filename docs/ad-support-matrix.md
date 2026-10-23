# Advertisement support matrix

The goal is to **identify suspicious advertisements, not to block advertisements**. The extension never hides, removes, or changes an ad. Most ads are fine and are never mentioned. Ads go through the same analyzer as everything else; the scanner only adds context saying "this is an ad" (`context.ads`, see `docs/interfaces.md`).

An ad can only be examined if the page reveals it. An element counts as an ad when it carries a recognizable marker. Anything else is treated as ordinary page content (and may still be caught by the page-level checks).

Tests: `tests/browser/ads.test.js` (this matrix, on `tests/pages/ads.html`) and `tests/ads-analyzer.test.js` (the judging).

## What the scanner collects for each ad

| Evidence | Where it comes from |
|---|---|
| Why we think it's an ad (`signals`) | The marker that matched (class, attribute, label, `rel`, ad-network link) |
| Offer or promotional text (`text`, up to 400 characters) | The ad's visible text |
| Advertised destination (`link.url`) | The ad's first link to another website, otherwise its first link |
| Link text (`link.text`) | What the link displays, so the analyzer can compare it with the destination |
| New ads that appear later | The same debounced `MutationObserver` as the rest of the scanner; iframes are re-read when they finish loading |

The scanner does not decide whether the link text and destination mismatch. It supplies both, and the analyzer's link checks decide (the same checks used for any link click).

## Patterns

| Pattern | Identified as an ad? | If suspicious | Test |
|---|---|---|---|
| Container with an ad-style class (`ad`, `ad-slot`, `advert`, `adsbygoogle`, `sponsored`, ...) | Yes | Warned | A1, A6, B1 |
| Container with `data-ad`, `data-ad-slot`, `data-ad-client`, `data-ad-unit` | Yes | Warned | A2, B2 |
| Link with `rel="sponsored"` | Yes | Warned | A3 |
| Container with `aria-label` / `title` mentioning "Advertisement" or "Sponsored" | Yes | Warned | A4 |
| A small "Sponsored" / "Advertisement" / "Ad" label next to a link | Yes (nearest container holding both) | Warned | A5, B3 |
| Link to a known ad network (e.g. doubleclick, googleadservices) | Yes | Warned | unit-tested markers |
| Ad inserted after the page loads | Yes (dynamic scan) | Warned | A8 |
| Same-origin iframe (e.g. `srcdoc`) that looks like an ad frame | Yes: the frame's content is read | Warned | A7 |
| Cross-origin iframe (the usual ad-network case) | **No.** The frame is counted as unreadable (`context.adFrames.unreadable`) and left alone | Not examined | C1 |
| Ad with no recognizable marker (native or in-feed ads) | **No** | Only page-level checks apply | C2 |
| Ad inside shadow DOM | **No** (the scanner does not enter shadow DOM; clicks on its link are still checked) | Link checks on click only | C3 |
| Image-only or canvas ad with no text | Identified if marked, but there is no text to judge | Link checks only | C4 |
| Click on any link inside an ad | Yes, the click guard asks for the ad context | Stopped before navigation | A1–A6, A8 |

## Ordinary ads stay untouched

B1–B4 are ordinary ads (a sale, a book, an image ad, an award notice). They are not mentioned in any warning, they stay on the page, and their links open normally.

## Honest limits

- A page can avoid markers, so "no warning" for an ad means only that it wasn't recognized or had no credible warning signs.
- Ads in cross-origin frames can't be inspected by a content script running in the top page. Covering them would need the extension to run in all frames, which is a bigger permission and privacy decision (see the checklist).
- Ad networks change their markup. The marker list is in `extension/content/ad-signals.js`.
