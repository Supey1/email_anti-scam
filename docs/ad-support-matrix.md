# Advertisement support

The goal is to **identify suspicious advertisements, not to block advertisements**. The extension never hides, removes, or changes an ad. Most ads are fine and are never mentioned.

Ads are not scored separately. An ad's words are part of the page text, and its links are page links, so the engine judges them with everything else. When someone **clicks** a link, the words around it (the rest of the ad, up to 400 characters) go to the engine as `context.nearbyText`; the engine decides whether to interrupt. `extension/content/ad-signals.js` recognizes marked ads only to describe those surrounding words well.

Tests: `tests/browser/ads.test.js` (on `tests/pages/ads.html`), `systematic.test.js` (`fake-ad.html`, `fake-iframes.html`), and the corpus kind `ad` in `tests/metrics.js`.

## Patterns

| Pattern | Recognized as an ad? | What a click gets | Test |
|---|---|---|---|
| Container with an ad-style class (`ad`, `ad-slot`, `advert`, `adsbygoogle`, `sponsored`, ...) | Yes | The engine reads the whole ad | A1, A6, B1 |
| Container with `data-ad`, `data-ad-slot`, `data-ad-client`, `data-ad-unit` | Yes | same | A2, B2 |
| Link with `rel="sponsored"` | Yes | same | A3 |
| Container with `aria-label` / `title` "Advertisement" or "Sponsored" | Yes | same | A4 |
| A small "Sponsored" / "Advertisement" / "Ad" label next to a link | Yes (the nearest container holding both) | same | A5, B3 |
| Link to a known ad network (doubleclick, googleadservices, ...) | Yes | The surrounding words, not just the link | `tests/browser/acceptance.test.js` |
| Ad inserted after the page loads | Yes | same | A8 |
| Ad in a frame (same-origin, `src` or `srcdoc`, or cross-origin) | The click guard runs inside the frame | The words in the frame; the warning covers the whole tab | A7, acceptance |
| Ad with no recognizable marker (native or in-feed ads) | **No** | The generic surrounding words (largest box under 400 characters) still work | C2 |
| Ad inside shadow DOM | **No** (not entered by the ad finder) | Clicks on its link are still checked | C3 |
| Image-only ad with no words | Maybe marked | Nothing to read; only the address is judged | C4 |

## Ordinary ads stay untouched

B1 to B4 (a sale, a book, an image ad, an award notice) are never mentioned, stay on the page, and their links open normally.

## Honest limits

- A page can avoid markers, so "no warning" for an ad means only that the engine found nothing to warn about in the words and address it was given.
- An ad that is only a picture gives the engine little to go on.
- A scam ad that sits directly in a real page can make the page itself warn, because its words are page text.
- An ordinary ad whose link goes through an ad tracker is a weak warning (the link's words show one company, the address goes through a counting service): shown, never interrupting.
- Ad networks change their markup; the marker list is in `extension/content/ad-signals.js`.
