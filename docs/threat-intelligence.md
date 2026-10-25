# Known-threat intelligence

How the extension knows about dangerous websites it hasn't analyzed, how that
becomes browser-level blocking, and what has to be decided before a real
threat service is added.

## The layers

| Layer | What it's for | Where |
|---|---|---|
| Local click guard | Analyze a link's destination before a normal click navigates | `content/click-guard.js` + the engine |
| Extension-owned warning page | A warning the website can't hide or fake, with safe choices | `ui/warning.html` (`SHOW_WARNING`; Chrome's blocking redirects there too) |
| Browser-level network rules | Block known dangerous addresses before they load, however you got there (typed, redirected, pop-up) | `background/threat-rules.js` → Chrome's `declarativeNetRequest` |
| Threat lookup | Ask "is this address known to be dangerous?" for addresses not on the local list | `background/threat-lookup.js` (`LOOKUP_URL`) |

The layers complement each other, and even together they **don't** catch every
way of opening a page or every new scam. Network rules only match addresses:
they can't read what an ad says. That's still the analyzer's job.

## Today: local only

- The **active list** is the bundled `data/threat-list.js` (made-up `.example`
  addresses) plus updates sent with `UPDATE_THREAT_RULES`, minus expired
  entries and false positives someone removed.
- The service worker builds it, installs it as Chrome rules, and saves it for
  the pages (`threat-sync.js`), so **the click guard and Chrome always use the
  same list**.
- Only entries from a **trusted** source become hard blocks in Chrome. Others
  still make the click guard warn.
- Refused entries: whole website endings (`com`, `co.uk`, `github.io`),
  `localhost`, and official company websites from `domainRules.BRANDS` (a feed
  listing `paypal.com` is almost certainly wrong, and blocking it would hurt).
- **Remote lookups are off by default.** Nothing leaves the computer until the person
  turns on "PhishTank list of fake websites" in Settings (see below). The other "remote"
  provider is a development mock (`provider: "mock"`) that answers from
  made-up `.example` addresses, so the slow path (waiting, timeouts, errors)
  can be tested without sending anything anywhere.

## Lookup answers

| `status` | Means | Never means |
|---|---|---|
| `match` | On a list we checked, from a named source (trusted or not) | |
| `no_match` | Not on any list we checked (`checked` says which) | that the address is safe. New scam websites aren't on any list yet. |
| `error` | We couldn't find out: timeout, no connection, unreadable answer | `no_match`, or safe |

Errors are never cached; the next click asks again. A slow or failed lookup
never lets a held link open by itself (see "Remote lookups" in
`docs/interfaces.md`).

## PhishTank (built, opt-in)

`provider: "phishtank-feed"` (`background/phishtank-feed.js` + `threat-lookup.js`), turned on from the settings page.

- **What it is:** PhishTank's downloadable list of verified, online phishing addresses
  (`https://data.phishtank.com/data/online-valid.csv.gz`, updated hourly by PhishTank). The
  extension downloads it, keeps a compact index in `chrome.storage.local`, and checks addresses
  **on this computer**. Looking an address up sends nothing anywhere.
- **Matching:** an entry with no path blocks the whole website and its subdomains (never an
  official company website or a whole website ending); an entry with a path matches that
  address (any `?query` on a path entry without one); an entry with a `?query` matches only
  that query. Matches are **trusted**, so the engine blocks them.
- **Refreshing:** when the saved copy is older than 6 hours, checked at the next lookup, at most
  once an hour. A failed download keeps the old copy and records the error (shown in Settings).
  Lookups with no list yet answer `error`, never `no_match`.
- **Where it runs:** `page.js` asks once per page opened (main page); `content/gmail.js` asks about
  up to 25 different websites linked in the open email. Both go through `LOOKUP_URL`.
  A held-click flow for links on ordinary pages is **not** wired: a linked page is checked when it opens.
- **Why the list and not the per-address "check URL" service:** the first version used the check-URL
  service, which sends each address to PhishTank, and it only ever answered for the one address asked
  about. The list sees every listed site and sends nothing. That version was removed; saved settings
  from it move to the list.
- **Application key:** PhishTank limits unkeyed downloads to a few a day (we try about 4). A key
  would lift that (`https://data.phishtank.com/data/<key>/online-valid.csv.gz`); one can be saved as
  `providerOptions.appKey` by the person (no screen for it yet), and it is never in the code.
- **Not verified from the build environment:** it cannot reach PhishTank (its network policy blocks
  the connection), so downloading has only been tested with a pretend `fetch` and a made-up CSV in the
  documented format (`phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target`).
  Try it once in real Chrome. A browser cannot set PhishTank's requested `User-Agent`.

## Choosing another provider

Add one **only after** choosing the privacy model, because turning it on
changes the README's promise that nothing leaves the computer.

| Option | Notes (check the current terms and quotas before deciding) |
|---|---|
| Google Safe Browsing API (v5) | The current docs describe v5 and say the API is for **non-commercial** use. Its newer designs check hashed address prefixes rather than full addresses, which helps privacy, but read exactly what v5 sends before relying on that. |
| Google Web Risk | Google's **commercial** version, for products that charge or are run by a business. Needs a Google Cloud project and credentials, so it needs our own server (below). |
| Open phishing feeds | Downloadable lists. Check each one's licence, how often it updates, and how it confirms entries (how many false positives). Fits the existing `UPDATE_THREAT_RULES` path. |

### Secrets: never in the extension

Anyone can unpack an installed extension and read its code. **A secret key
written into `extension/` is a published key.** So:

- A service that needs a secret (Web Risk's credentials) needs **our own
  server** in between. That server then sees which addresses people check:
  say so in the README's Privacy section and the Chrome Web Store listing,
  and decide what it keeps (ideally nothing).
- A service with a non-secret, restricted key can be called from the
  extension, but quota abuse is still possible. Restrict the key, and still
  disclose that addresses are sent.

### Adding a provider

1. Write an adapter in `background/threat-lookup.js`:
   `{ name, trusted, lookup(parsedUrl, { signal }) -> Promise<{ matched, threatType? }> }`,
   and add it to `PROVIDERS`. Respect `signal` (lookups are cancelled at the timeout).
2. Decide `trusted`: only a source whose matches you'd accept as a hard block.
3. Update the README's Privacy section in the **same** pull request.
4. Add tests next to the mock's in `tests/service-worker.test.js`, with made-up addresses only.

## Testing rules

Never use real malicious links, not even in tests. Use reserved `.example`
addresses. `tests/service-worker.test.js` and `tests/browser/blocking.test.js`
check: a matching test address is blocked; look-alike normal addresses are
**not** blocked; updates, duplicates, stale entries, and false-positive removal;
untrusted sources; and lookup errors and timeouts.
