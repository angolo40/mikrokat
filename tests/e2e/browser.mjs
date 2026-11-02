// Drives the Settings page in a real headless Chromium, because reading the HTML does not show what the
// owner sees: a tab can be in the page and still be hidden by the CSS. Run by tests/e2e/run.sh in the
// Playwright image, which installs the playwright package with npm. It is a test tool only and no image
// of the project holds it.
//
//   node browser.mjs request   tabs, then switch on, create a request, sign it, upload the certificate alone
//   node browser.mjs pair      the older upload of certificate and key together, then Stop using my CA
//   node browser.mjs names     the Known devices list of a rendered page with 38 names (NAMES_HTML)
//
// APP, MK_PASSWORD and OUT (where the downloads and the screenshots go) come from the environment.
import { chromium } from 'playwright';
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';

const APP = process.env.APP ?? 'http://127.0.0.1:8088';
const OUT = process.env.OUT ?? '/out';
const PASSWORD = process.env.MK_PASSWORD ?? '';
const CA_NAME = 'Mikrokat E2E requested CA';
const PAIR_NAME = 'Mikrokat E2E pair CA';
const TABS = ['protection', 'notifications', 'router', 'data', 'ai', 'https', 'account'];
const SHORT = 8000;
const LONG = 30000;

mkdirSync(OUT, { recursive: true });
const sh = (cmd, cwd) => execFileSync('sh', ['-c', cmd], { cwd, stdio: ['ignore', 'pipe', 'pipe'] }).toString();
const step = (text) => console.log(`-- ${text}`);

class Failure extends Error {}
const fail = (text) => { throw new Failure(text); };

// Playwright's own visibility check: it needs a box with a size and no visibility:hidden, so a pane that
// display:none hides fails here although its text is in the HTML.
async function shown(locator, what) {
  try {
    await locator.first().waitFor({ state: 'visible', timeout: SHORT });
  } catch {
    fail(`${what} is not visible`);
  }
}
async function hidden(locator, what) {
  try {
    await locator.first().waitFor({ state: 'hidden', timeout: SHORT });
  } catch {
    fail(`${what} is visible`);
  }
}

async function shot(page, name) {
  await page.screenshot({ path: `${OUT}/${name}.png`, fullPage: true });
  console.log(`   screenshot ${name}.png`);
}

async function signIn(page) {
  await page.goto(`${APP}/login`);
  await page.fill('input[name=username]', 'admin');
  await page.fill('input[name=password]', PASSWORD);
  await Promise.all([page.waitForURL(`${APP}/`), page.click('button:has-text("Sign in")')]);
}

// The page after the proxy has had time to write its answer: the tab does not refresh by itself.
async function untilShown(page, locator, what, tries = 20) {
  for (let i = 0; i < tries; i++) {
    if (await locator.first().isVisible()) return;
    await page.waitForTimeout(1500);
    await page.goto(`${APP}/settings?tab=https`);
  }
  fail(`${what} never appeared`);
}

async function tabs(page) {
  step('every Settings tab shows its content');
  for (const tab of TABS) {
    await page.goto(`${APP}/settings?tab=${tab}`);
    await shown(page.locator(`#pane-${tab}`), `the ${tab} pane`);
    await shown(page.locator(`#pane-${tab} h2`), `the first heading of the ${tab} pane`);
    for (const other of TABS.filter((t) => t !== tab)) {
      await hidden(page.locator(`#pane-${other}`), `the ${other} pane on the ${tab} tab`);
    }
    await shot(page, `tab-${tab}`);
  }
}

async function openHttps(page) {
  await page.goto(`${APP}/settings?tab=https`);
  await shown(page.locator('#pane-https'), 'the HTTPS inspection tab');
}

async function switchOn(page) {
  step('switch inspection on with a device');
  await openHttps(page);
  const toggle = page.locator('label.switch:has(input[name=tls_enabled])');
  const input = page.locator('input[name=tls_enabled]');
  if (!(await input.isChecked())) await toggle.click();
  const devices = page.locator('textarea[name=tls_devices]');
  await shown(devices, 'the Devices field after the switch');
  await devices.fill('127.0.0.1');
  await Promise.all([page.waitForURL(/\/settings/), page.click('.savebar button')]);
  await openHttps(page);
  if (!(await page.locator('input[name=tls_enabled]').isChecked())) fail('the switch did not stay on');
  await shown(page.locator('textarea[name=tls_devices]'), 'the Devices field after saving');
  if ((await page.locator('textarea[name=tls_devices]').inputValue()).trim() !== '127.0.0.1') fail('the device was not saved');
  await shot(page, 'https-on');
}

async function download(page, selector, file) {
  const [dl] = await Promise.all([page.waitForEvent('download'), page.click(selector)]);
  await dl.saveAs(`${OUT}/${file}`);
  console.log(`   downloaded ${dl.suggestedFilename()}`);
  return dl.suggestedFilename();
}

async function request(page) {
  await signIn(page);
  await tabs(page);
  await switchOn(page);

  step('the Create a key here card is on the tab');
  await shown(page.locator('h2:has-text("Create a key here")'), 'the Create a key here heading');
  await shown(page.locator('.recommended'), 'the Recommended mark');
  await shown(page.locator('input[name=ca_request_name]'), 'the CA name field');
  await shown(page.locator('button:has-text("Create request")'), 'the Create request button');
  await shown(page.locator('h3:has-text("Or upload a certificate and key you already have")'), 'the heading of the two-file form');
  await shot(page, 'create-card');

  step('the skip list opens prefilled with the defaults, and they survive a save');
  const skip = page.locator('textarea[name=tls_bypass]');
  await shown(skip, 'the Never inspect these names field');
  await untilShown(page, page.locator('textarea[name=tls_bypass]'), 'the skip list');
  const listed = (await skip.inputValue()).split('\n').map((t) => t.trim());
  for (const name of ['paypal.com', 'ubs.com', 'google.com']) if (!listed.includes(name)) fail(`${name} is not in the prefilled list: ${listed.length} names`);
  await shown(page.locator('text=already filled in with the defaults'), 'the hint under the skip list');
  await shot(page, 'skip-list');
  await Promise.all([page.waitForURL(/\/settings/), page.click('.savebar button')]);
  await openHttps(page);
  const after = (await page.locator('textarea[name=tls_bypass]').inputValue()).split('\n').map((t) => t.trim());
  if (after.length !== listed.length) fail(`a save changed the list from ${listed.length} to ${after.length} names`);

  step('create a request');
  await page.fill('input[name=ca_request_name]', CA_NAME);
  await Promise.all([page.waitForURL(/ok=ca-requested/), page.click('button:has-text("Create request")')]);
  await untilShown(page, page.locator('a[href="/tls/own-ca.csr"]'), 'the Download request link');
  await shown(page.locator('a[href="/tls/own-ca.ext"]'), 'the Download extensions link');
  await shown(page.locator('code.command'), 'the signing command');
  await shown(page.locator('button:has-text("Cancel request")'), 'the Cancel request button');
  await shot(page, 'request-pending');

  step('download the request and the extensions through the browser');
  const csrName = await download(page, 'a[href="/tls/own-ca.csr"]', 'mikrokat-ca.csr');
  const extName = await download(page, 'a[href="/tls/own-ca.ext"]', 'mikrokat-ca.ext');
  if (csrName !== 'mikrokat-ca.csr' || extName !== 'mikrokat-ca.ext') fail(`file names ${csrName} ${extName}`);
  const command = (await page.locator('code.command').first().textContent()).trim();
  const subject = sh(`openssl req -in mikrokat-ca.csr -noout -subject`, OUT);
  if (!subject.includes(CA_NAME)) fail(`the request is for ${subject}`);

  step('sign it with a root of our own, outside the page, with the command the page shows');
  sh(`openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=Mikrokat E2E browser root" ` +
     `-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign -keyout root.key -out root.crt`, OUT);
  sh(command, OUT);
  sh('cat mikrokat-ca.pem root.crt > chain.pem', OUT);

  step('upload the certificate through the file input and press the real button');
  const input = page.locator('input[type=file][form=own-ca-signed]');
  await shown(input, 'the signed certificate input');
  await input.setInputFiles(`${OUT}/chain.pem`);
  await Promise.all([page.waitForURL(/ok=ca-uploaded/), page.click('button:has-text("Upload signed certificate")')]);
  await untilShown(page, page.locator(`text=In use: your own CA, CN=${CA_NAME}`), 'the CA in use');
  await hidden(page.locator('a[href="/tls/own-ca.csr"]'), 'the Download request link after the install');
  await shot(page, 'own-ca-installed');
}

async function pair(page) {
  await signIn(page);
  step('the older upload of certificate and key together, through the real form');
  sh(`openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=${PAIR_NAME}" -keyout pair.key -out pair.csr`, OUT);
  sh('openssl x509 -req -in pair.csr -CA root.crt -CAkey root.key -CAcreateserial -days 2 -sha256 -extfile mikrokat-ca.ext -out pair.pem', OUT);
  sh('cat pair.pem root.crt > pair-chain.pem', OUT);
  await openHttps(page);
  await page.locator('input[type=file][name=chain][form=own-ca]').setInputFiles(`${OUT}/pair-chain.pem`);
  await page.locator('input[type=file][name=key][form=own-ca]').setInputFiles(`${OUT}/pair.key`);
  await Promise.all([page.waitForURL(/ok=ca-uploaded/), page.click('button[form=own-ca]:has-text("Upload")')]);
  await untilShown(page, page.locator(`text=In use: your own CA, CN=${PAIR_NAME}`), 'the CA of the pair');
  await shot(page, 'pair-installed');

  step('press Stop using my CA');
  page.once('dialog', (d) => d.accept());
  await Promise.all([page.waitForURL(/ok=ca-removed/), page.click('button:has-text("Stop using my CA")')]);
  await untilShown(page, page.locator('text=In use: the CA Mikrokat generated'), 'the generated CA back in use');
  await shot(page, 'stopped');
}

async function names(page) {
  step('Known devices lists every name and scrolls');
  await page.goto(`file://${process.env.NAMES_HTML}`);
  const details = page.locator('details:has(summary:has-text("Known devices"))');
  await shown(details, 'the Known devices list');
  await details.locator('summary').click();
  const items = details.locator('ul.scroll li');
  await shown(items.first(), 'the first known device');
  const count = await items.count();
  if (count !== 38) fail(`the list has ${count} names, not 38`);
  const texts = await items.allTextContents();
  const sorted = [...texts].sort((a, b) => a.split(' ').slice(1).join(' ').toLowerCase().localeCompare(b.split(' ').slice(1).join(' ').toLowerCase()));
  if (JSON.stringify(sorted) !== JSON.stringify(texts)) fail('the names are not sorted');
  if (!texts.some((t) => t.includes('Alpha-PC'))) fail('the owner PC is missing');
  const box = await details.locator('ul.scroll').evaluate((el) => ({ scroll: el.scrollHeight, client: el.clientHeight, overflow: getComputedStyle(el).overflowY }));
  if (box.overflow !== 'auto' || box.scroll <= box.client) fail(`the list does not scroll: ${JSON.stringify(box)}`);
  const last = items.last();
  await last.scrollIntoViewIfNeeded();
  await shown(last, 'the last known device after scrolling');
  await shot(page, 'known-devices');
}

const phase = process.argv[2];
const phases = { request, pair, names };
if (!phases[phase]) { console.error(`usage: browser.mjs ${Object.keys(phases).join('|')}`); process.exit(2); }
const browser = await chromium.launch();
let code = 0;
try {
  const context = await browser.newContext({ acceptDownloads: true, viewport: { width: 1280, height: 900 } });
  const page = await context.newPage();
  page.setDefaultTimeout(LONG);
  try {
    await phases[phase](page);
    console.log(`browser ${phase}: ok`);
  } catch (error) {
    code = 1;
    console.error(`browser ${phase}: FAIL: ${error.message}`);
    await page.screenshot({ path: `${OUT}/failure-${phase}.png`, fullPage: true }).catch(() => {});
  }
} finally {
  await browser.close();
}
process.exit(code);
