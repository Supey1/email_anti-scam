# What the click guard can and cannot stop

`extension/content/click-guard.js` listens for link clicks (in every frame), builds a `source: "link"` input (the link, where it really goes, and the words around it), and asks the engine, `analyze()`. **Only when the engine recommends `GO_BACK` or `DO_NOT_ENTER_INFO`** does it cancel the click and ask the service worker for the extension's own warning page (`blocked.html`). A content script that intercepts anchor clicks **cannot guarantee** interception of every navigation. Do not claim more than this table.

## Verified by browser tests (`tests/browser/click-matrix.test.js`, `click-guard.test.js`, `systematic.test.js`)

| Navigation | Result |
|---|---|
| Ordinary click on a link the engine says to interrupt | Stopped; the browser never requests the destination |
| Click on an element inside a link, SVG links, links in shadow DOM | Stopped |
| `target="_blank"`, Ctrl/Cmd-click, Shift-click, middle-click | Stopped; the warning opens in a new tab and the original page stays |
| Enter on a focused link | Stopped |
| Links with `rel`, `referrerpolicy`, `ping` | Stopped |
| Links added to the page after it loaded | Stopped |
| Links inside frames (including `srcdoc`) | Stopped; the warning covers the whole tab |
| Links inside an email that looks like a scam (Gmail) | Stopped; the warning opens in a new tab so the mailbox stays |
| Safe links (new tab, same site, `#section`, `mailto:`, the page's own script) | Left alone; behave normally |
| Page's own click handler on a stopped link | Does not run (we cancel in the capture phase) |

## By design, not stopped: weak warnings

The engine says `VERIFY_INDEPENDENTLY` for weak evidence (a link whose words name another site, a raw number address, a shortened link, a look-alike without more). Those are shown (the Gmail panel, the details) but **never interrupt a click**: too many interruptions and people stop trusting them (`docs/interfaces.md`). Tested: "weak" rows in the click matrix.

## Not caught

- **Navigation by the website's own script**: `location.href = ...`, `window.open(...)`, `<meta refresh>`, redirects after load, or a script calling `a.click()`.
- **Links opened without a click**: the right-click menu, dragging a link to the address bar, typing or pasting an address, other extensions.
- **A site that rewrites a link's address in its own click handler** after our check.
- **An unknown redirect service**: the destination cannot be seen.
- **A click the engine does not rate as interrupting**, whatever the reason: see `docs/test-results.md` for what the engine misses.

## Backstop

Websites on the known-dangerous list are blocked when they load (`declarativeNetRequest`), however the person got there, including a page that redirects itself to one. That list is currently a small practice list.

## `warn` vs `block`

- `block` (confirmed evidence): the extension's own warning page, **no continue button**.
- `warn` that interrupts: the same page with a prominent "Go back to safety" and a secondary "I understand the risk. Continue anyway".
- The in-page card (`panel.js`) is used for page-level warnings, the Gmail panel, and as a fallback if the extension cannot be reached (for example just after an update). A website could hide or remove it, so it is not a security boundary.
