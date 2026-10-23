// Shared by the browser tests: serves tests/pages, loads the real extension into Chromium,
// and answers every ".example" address with a tiny page so nothing touches the internet.
// Needs Playwright (npm i playwright). Set CHROMIUM_PATH if Playwright can't find Chromium.

const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

const PAGES = path.join(__dirname, '..', 'pages');
const EXTENSION = process.env.EXTENSION_PATH || path.join(__dirname, '..', '..', 'extension');

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

async function launch() {
  const { server, base } = await serve();
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'anti-scam-test-'));
  const context = await chromium.launchPersistentContext(profile, {
    headless: false,
    executablePath: process.env.CHROMIUM_PATH || undefined,
    args: [`--disable-extensions-except=${EXTENSION}`, `--load-extension=${EXTENSION}`, '--headless=new', '--no-sandbox'],
  });
  const requests = []; // every address the browser asked for
  context.on('request', r => requests.push(r.url()));
  await context.route(/^https?:\/\/([^/]+\.example|(www\.)?(paypal\.com|amazon\.com|google\.com)|bit\.ly)\//, route => {
    if (/known-phish|fake-bank-login/.test(route.request().url())) return route.fallback(); // let the extension's own blocking handle these
    return route.fulfill({ contentType: 'text/html', body: '<title>Destination</title><h1>Destination reached</h1>' });
  });
  // The same practice pages over https (as https://pages.example/), because a plain-http page is itself a warning sign for forms.
  await context.route('https://pages.example/**', route => {
    const file = path.join(PAGES, path.normalize(new URL(route.request().url()).pathname).replace(/^\/+/, ''));
    if (!file.startsWith(PAGES) || !fs.existsSync(file)) return route.fulfill({ status: 404, body: 'not found' });
    return route.fulfill({ contentType: 'text/html', body: fs.readFileSync(file) });
  });
  const reached = host => requests.some(u => new URL(u).hostname === host);
  const close = async () => { await context.close(); server.close(); fs.rmSync(profile, { recursive: true, force: true }); };
  return { context, base, secure: 'https://pages.example/', requests, reached, close };
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
