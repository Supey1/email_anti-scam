# What the click guard can and cannot stop

`extension/content/click-guard.js` listens for link clicks, checks the destination with the local rules, cancels the click for a `warn` or `block`, and asks the service worker to show the extension-owned warning page (`extension/ui/warning.html`). A content script that intercepts anchor clicks **cannot guarantee** interception of every navigation. Do not claim more than this table.

## Verified by browser tests (`tests/browser/click-guard.test.js`)

| Navigation | Result |
|---|---|
| Ordinary click on a link | Stopped; the browser never requests the destination |
| Click on an element inside a link, SVG links, links in shadow DOM | Stopped |
| `target="_blank"`, Ctrl/Cmd-click, Shift-click, middle-click | Stopped; the warning opens in a new tab and the original page stays |
| Enter on a focused link | Stopped |
| Links with `rel`, `referrerpolicy`, `ping` | Stopped |
| Safe links (new tab, same site, `#section`, `mailto:`, the page's own script) | Left alone; behave normally |
| Page's own click handler on a stopped link | Does not run (we cancel in the capture phase) |

## Not caught

- **Navigation by the website's own script**: `location.href = ...`, `window.open(...)`, `<meta refresh>`, redirects after load, or a script calling `a.click()`. (Test: "KNOWN LIMIT".) A link like `<a href="#" onclick="location.href=...">` looks like a harmless `#` link to us.
- **Links opened without a click**: the right-click menu, dragging a link to the address bar, typing or pasting an address, other extensions.
- **A site that rewrites a link's address in its own click handler** after our check.
- **Content in iframes** the extension doesn't run in, and links in the browser's own pages.
- **Same-site links** are skipped on purpose (a site linking to itself), so a compromised page linking within its own domain is not stopped.

## Backstop

Websites on the known-dangerous list are blocked when they load (`declarativeNetRequest`), however the person got there. That list is currently a small demo list.

## `warn` vs `block`

- `block` (strong evidence): extension-owned warning page, **no continue button**. The service worker also refuses a continue request for a block, even if the warning page is asked to.
- `warn`: the same page with a prominent "Go back to safety" and a secondary "I understand the risk. Continue anyway".
- The in-page card (`panel.js`) is only used for page-level notices and as a fallback if the extension can't open its warning page. A website could hide or remove it, so it is not a security boundary.
