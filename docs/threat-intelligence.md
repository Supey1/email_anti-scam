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
  turns on "Online check with PhishTank" in Settings (see below). The other "remote"
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

`provider: "phishtank"` in `background/threat-lookup.js`, turned on from the settings page.

- **What it is:** a community list of reported phishing addresses, verified by people. It
  asks PhishTank's *check URL* service (`https://checkurl.phishtank.com/checkurl/`, POST,
  base64 address, `format=json`) about one address. A match needs `in_database`, `verified`
  and `valid` all true. Matches are treated as **trusted**, so the engine blocks them.
- **Where it runs:** `page.js` asks once per page the person opens (main page, only on
  websites being checked); `content/gmail.js` asks about up to five different websites
  linked in the open email. Both go through `LOOKUP_URL`, which also checks the local
  list first, caches answers (10 min no match, 1 h match), and times out at 4 s.
  A held-click ("Checking this link...") flow for links on ordinary pages is **not**
  wired: a linked page is checked when it opens.
- **Privacy:** only website + path is sent (query and fragment removed); never official
  company websites, IP addresses, or names without a dot. No cookies, no referrer.
  Disclosed in the README Privacy section and the settings page.
- **No secret in the extension.** The check URL works without an app key but with a lower
  rate limit; over it, PhishTank answers HTTP 509, which becomes a lookup `error`
  (never `no_match`). An optional key can only be saved by the person
  (`providerOptions.appKey`); there is no screen for it, and it is never in the code.
- **Why not the downloadable database?** `data.phishtank.com/data/online-valid.json` keeps
  addresses on the computer (best for privacy), but it is very large for an extension,
  updates hourly, and without an application key downloads are limited to a few per day.
  PhishTank's developer page asks for a key, but new registrations have been reported as
  closed (Wikipedia, as of June 2026), so the key may be impossible to get. If one is
  obtained, the database could be filtered and loaded through `UPDATE_THREAT_RULES`.
- **Not verified from the build environment:** it had no access to phishtank.org, so
  the request/response shape follows PhishTank's published docs but has only been tested
  with a pretend `fetch`. Try it once in real Chrome before relying on it.

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
