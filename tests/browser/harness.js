// Shared by the browser tests: serves tests/pages, loads the real extension into Chromium,
// and answers every ".example" address with a tiny page so nothing touches the internet.
// Needs Playwright (npm i playwright). Set CHROMIUM_PATH if Playwright can't find Chromium.

const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

const PAGES = path.join(__dirname, '..', 'pages');
const EXTENSION_SOURCE = process.env.EXTENSION_PATH || path.join(__dirname, '..', '..', 'extension');

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

// A copy of the extension whose manifest already holds the website access a person would give on the welcome page
// (Chrome shows a permission prompt that a test cannot click). Everything else is the real extension.
function copyExtension({ access = true } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'anti-scam-extension-'));
  fs.cpSync(EXTENSION_SOURCE, dir, { recursive: true });
  if (access) {
    const manifestPath = path.join(dir, 'manifest.json');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    manifest.host_permissions = ['http://*/*', 'https://*/*'];
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  }
  return dir;
}

async function launch({ access = true } = {}) {
  const EXTENSION = copyExtension({ access });
  const { server, base } = await serve();
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'anti-scam-test-'));
  const context = await chromium.launchPersistentContext(profile, {
    headless: false,
    executablePath: process.env.CHROMIUM_PATH || undefined,
    args: [`--disable-extensions-except=${EXTENSION}`, `--load-extension=${EXTENSION}`, '--headless=new', '--no-sandbox'],
  });
  const requests = []; // every address the browser asked for
  context.on('request', r => requests.push(r.url()));
  await context.route(/^https?:\/\/([^/]+\.example|(www\.)?(paypal\.com|amazon\.com|google\.com)|([^/]+\.)?doubleclick\.net|bit\.ly)\//, route => {
    if (/known-phish|fake-bank-login/.test(route.request().url())) return route.fallback(); // let the extension's own blocking handle these
    return route.fulfill({ contentType: 'text/html', body: '<title>Destination</title><h1>Destination reached</h1>' });
  });
  // The same practice pages over https (as https://pages.example/), because a plain-http page is itself a warning sign for forms.
  // ...and over plain http from a name that is not localhost (the engine treats localhost as safe to use without encryption).
  await context.route(/^https?:\/\/(pages|plain-pages)\.example\//, route => {
    const file = path.join(PAGES, path.normalize(new URL(route.request().url()).pathname).replace(/^\/+/, ''));
    if (!file.startsWith(PAGES) || !fs.existsSync(file)) return route.fulfill({ status: 404, body: 'not found' });
    return route.fulfill({ contentType: 'text/html', body: fs.readFileSync(file) });
  });
  // Wait for the extension's background script to register its page scripts (it does that once it knows the access it has).
  const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  for (let i = 0; i < 80; i++) {
    const scripts = await worker.evaluate(async () => (await chrome.scripting.getRegisteredContentScripts()).length).catch(() => 0);
    if (scripts === 3 || !access) break;
    await new Promise(r => setTimeout(r, 100));
  }
  await new Promise(r => setTimeout(r, 300));
  const reached = host => requests.some(u => new URL(u).hostname === host);
  const close = async () => { await context.close(); server.close(); for (const dir of [profile, EXTENSION]) fs.rmSync(dir, { recursive: true, force: true }); };
  return { context, base, secure: 'https://pages.example/', plain: 'http://plain-pages.example/', requests, reached, close, worker, extensionId: new URL(worker.url()).host };
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
