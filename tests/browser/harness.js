// Shared by the browser tests: serves tests/pages, loads the real extension into Chromium,
// and answers every ".example" address with a tiny page so nothing touches the internet.
// Needs Playwright (npm i playwright). Set CHROMIUM_PATH if Playwright can't find Chromium.

const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

const PAGES = path.join(__dirname, '..', 'pages');
const SOURCE = path.join(__dirname, '..', '..', 'extension');

// The extension asks for website access on its welcome page, and Chrome's "Allow" prompt can't be
// clicked by a test. So most tests run a copy whose manifest already has that access (as if the
// person said yes). Everything else is the real extension, unchanged. withAccess: false loads the
// real extension exactly as installed: no website access yet.
function extensionCopy() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'anti-scam-ext-'));
  fs.cpSync(SOURCE, dir, { recursive: true });
  const manifestPath = path.join(dir, 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  manifest.host_permissions = manifest.optional_host_permissions;
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  return dir;
}

let chromium;
try { ({ chromium } = require('playwright')); } catch (e) { console.log('SKIP  Playwright is not installed (npm i playwright)'); process.exit(0); }

function serve() {
  const server = http.createServer((req, res) => {
    const file = path.join(PAGES, path.normalize(req.url.split('?')[0]).replace(/^\/+/, '') || 'index.html');
    if (!file.startsWith(PAGES) || !fs.existsSync(file)) { res.writeHead(404); res.end('not found'); return; }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(fs.readFileSync(file));
  });
  return new Promise(resolve => server.listen(0, () => resolve({ server, base: `http://localhost:${server.address().port}/` })));
}

//   withAccess  false: the real extension as installed, no website access yet
//   profile, extension, keep   for a restart: reuse a browser profile and extension copy, and keep them on close
async function launch({ withAccess = true, profile = null, extension = null, keep = false } = {}) {
  const { server, base } = await serve();
  profile = profile || fs.mkdtempSync(path.join(os.tmpdir(), 'anti-scam-test-'));
  const EXTENSION = extension || process.env.EXTENSION_PATH || (withAccess ? extensionCopy() : SOURCE);
  const context = await chromium.launchPersistentContext(profile, {
    headless: false,
    executablePath: process.env.CHROMIUM_PATH || undefined,
    args: [`--disable-extensions-except=${EXTENSION}`, `--load-extension=${EXTENSION}`, '--headless=new', '--no-sandbox'],
  });
  const requests = []; // every address the browser asked for
  context.on('request', r => requests.push(r.url()));
  // Every test address is answered here, never fetched. Chrome's own blocking (declarativeNetRequest)
  // acts BEFORE this, so a known dangerous address that reaches `served` was NOT blocked.
  const served = [];
  await context.route(/^https?:\/\/([^/]+\.example|(www\.)?(paypal\.com|amazon\.com|google\.com)|([^/]+\.)?(doubleclick\.net|googleadservices\.com)|bit\.ly)\//, route => {
    served.push(new URL(route.request().url()).hostname);
    return route.fulfill({ contentType: 'text/html', body: '<title>Destination</title><h1>Destination reached</h1>' });
  });
  // The same practice pages as https://pages.example/ (a plain-http page is itself a warning sign for forms),
  // and as http://pages.example/ for the tests about that. (http://localhost counts as secure in Chrome.)
  await context.route(/^https?:\/\/pages\.example\//, route => {
    const file = path.join(PAGES, path.normalize(new URL(route.request().url()).pathname).replace(/^\/+/, ''));
    if (!file.startsWith(PAGES) || !fs.existsSync(file)) return route.fulfill({ status: 404, body: 'not found' });
    return route.fulfill({ contentType: 'text/html', body: fs.readFileSync(file) });
  });
  const reached = host => requests.some(u => new URL(u).hostname === host);
  const close = async () => {
    await context.close();
    server.close();
    if (keep) return;
    fs.rmSync(profile, { recursive: true, force: true });
    if (EXTENSION !== SOURCE && !process.env.EXTENSION_PATH) fs.rmSync(EXTENSION, { recursive: true, force: true });
  };
  // The service worker registers the page scripts once it has seen the access; wait for that.
  const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  if (withAccess) {
    await worker.evaluate(async () => {
      for (let i = 0; i < 100; i++) {
        if ((await chrome.scripting.getRegisteredContentScripts()).length) return;
        await new Promise(r => setTimeout(r, 50));
      }
    });
  }
  // The welcome page opens on install; most tests open their own pages.
  if (withAccess) for (const page of context.pages()) if (page.url().includes('options.html')) await page.close();
  return { context, base, secure: 'https://pages.example/', plain: 'http://pages.example/', requests, reached, served: host => served.includes(host), close, worker, extensionId: new URL(worker.url()).host, extension: EXTENSION, profile };
}

// Runs named async tests, prints PASS/FAIL, exits non-zero on failure.
async function run(tests, env) {
  let failed = 0;
  const only = process.env.TEST_FILTER; // run just the tests whose name contains this text
  for (const t of tests) {
    if (only && !t.name.includes(only)) continue;
    env.requests.length = 0; // each test starts with a clean record of what the browser asked for
    try { await t.fn(env); console.log(`PASS  ${t.name}`); }
    catch (err) { failed++; console.log(`FAIL  ${t.name}: ${err.message.split('\n').slice(0, 4).join(' | ')}`); }
  }
  await env.close();
  console.log(failed ? `\n${failed} test(s) failed` : '\nAll tests passed');
  process.exit(failed ? 1 : 0);
}

module.exports = { launch, run };
