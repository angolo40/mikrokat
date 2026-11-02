// Drives the Settings page in a real headless Chromium, because reading the HTML does not show what the
// owner sees: a tab can be in the page and still be hidden by the CSS. Run by tests/e2e/run.sh in the
// Playwright image, which installs the playwright package with npm. It is a test tool only and no image
// of the project holds it.
//
//   node browser.mjs request   tabs, then switch on, create a request, sign it, upload the certificate alone
//   node browser.mjs pair      the older upload of certificate and key together, then Stop using my CA
//   node browser.mjs connections   the Connections page after real traffic: bars, tiles, tables, filters, dark and light
//   node browser.mjs guide     click every Settings tab: its pane and only its guide block show, with no reload; the AI presets
//   node browser.mjs off      the stack without the https profile: no HTTPS inspection tab or guide block, no Connections item, a note on /connections
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
const rgb = (text) => (text.match(/[\d.]+/g) ?? []).slice(0, 3).join(',');
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

// The HTTPS inspection tab as the owner sees it: cards in order, closed sections that open on a click, a Save bar
// that stays off the field being edited, and no sideways scroll on a phone, in light and dark.
async function layout(page) {
  const pane = page.locator('#pane-https');
  const sectionOf = (title) => page.locator(`details.section:has(> summary:has-text("${title}"))`);
  const noSideways = async (what) => {
    if (await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth)) fail(`${what}: the page scrolls sideways`);
  };

  step('the beta marks: the tab, the line at the top, the Inspection heading');
  await openHttps(page);
  await shown(page.locator('.tabbar label[for=tab-https] .badge:has-text("Beta")'), 'the Beta mark on the tab');
  await shown(pane.locator('h2:has-text("Inspection") .badge:has-text("Beta")'), 'the Beta mark on the Inspection heading');
  await shown(pane.locator('p.note:has-text("in beta. It has been tested on one network")'), 'the beta line');

  step('the cards come in order: status, Inspection, Exceptions, Certificate, Connection log, Advanced');
  const tops = await page.evaluate(() => {
    const top = (el) => el.getBoundingClientRect().top + window.scrollY;
    const heads = [...document.querySelectorAll('#pane-https .card > h2, #pane-https details.advanced > summary')];
    return { beta: top(document.querySelector('#pane-https > p.note')), status: top(document.querySelector('#pane-https .status')),
             cards: heads.map((h) => [h.textContent.replace('Beta', '').trim(), top(h)]) };
  });
  const names = tops.cards.map((c) => c[0]);
  if (JSON.stringify(names) !== JSON.stringify(['Inspection', 'Exceptions', 'Certificate', 'Connection log', 'Advanced'])) fail(`the cards are ${JSON.stringify(names)}`);
  const ys = [tops.beta, tops.status, ...tops.cards.map((c) => c[1])];
  if (ys.some((y, i) => i && y <= ys[i - 1])) fail(`the cards are out of order: ${JSON.stringify(ys)}`);
  await shown(pane.locator('.status:has-text("On")'), 'the status row');
  await shown(pane.locator('.logrow a[href="/connections"]'), 'the Connections link on the log card');
  await shown(pane.locator('.status .fact:has-text("CA")'), 'the CA in the status row');
  await shown(pane.locator('.status .fact:has-text("inspected")'), 'Inspected in the status row');
  await shown(pane.locator('.status .fact:has-text("Refused")'), 'Refused in the status row');
  if ((await pane.locator('h2:has-text("Numbers")').count()) !== 0) fail('the Numbers card is still there');

  step('the fields stand at equal width, the skip list has a fixed height and scrolls');
  const widths = await page.evaluate(() => ['textarea[name=tls_devices]', 'textarea[name=tls_bypass]', 'input[name=tls_socks_port]'].map((s) => document.querySelector(s)).map((e) => e.closest('.field').getBoundingClientRect().width));
  if (Math.abs(widths[0] - widths[1]) > 1) fail(`the two lists differ in width: ${widths}`);
  const list = await page.locator('textarea[name=tls_bypass]').evaluate((el) => ({ h: el.clientHeight, lh: parseFloat(getComputedStyle(el).lineHeight), overflow: getComputedStyle(el).overflowY, resize: getComputedStyle(el).resize }));
  if (list.h < list.lh * 9 || list.h > list.lh * 11.5 || list.resize !== 'none') fail(`the skip list is ${JSON.stringify(list)}`);

  step('the closed sections open on a click, one at a time');
  for (const title of ['Create a key here', 'Upload a certificate and key you already have', 'Regenerate the CA']) await shown(sectionOf(title).locator('> summary'), `the ${title} summary`);
  await hidden(page.locator('input[name=ca_request_name]'), 'the CA name field while its section is closed');
  await hidden(page.locator('input[type=file][name=key][form=own-ca]'), 'the key upload while its section is closed');
  await hidden(page.locator('button:has-text("Regenerate the CA")'), 'Regenerate while its section is closed');
  await sectionOf('Create a key here').locator('> summary').click();
  await shown(page.locator('input[name=ca_request_name]'), 'the CA name field after the click');
  await sectionOf('Upload a certificate and key you already have').locator('> summary').click();
  await shown(page.locator('input[type=file][name=key][form=own-ca]'), 'the key upload after the click');
  await shown(sectionOf('Upload a certificate and key you already have').locator('.note.error:has-text("plain HTTP")'), 'the plain HTTP warning inside its section');
  await hidden(page.locator('input[name=ca_request_name]'), 'the CA name field once another section opened');
  await sectionOf('Regenerate the CA').locator('> summary').click();
  await shown(page.locator('button:has-text("Regenerate the CA")'), 'Regenerate after the click');
  await shown(pane.locator('.ca-line a[href="/tls/ca.pem"]'), 'the Download link in the first line');
  const space = await page.locator('details.section > summary:has-text("Create a key here")').evaluate((el) => el.textContent);
  if (!/Create a key here\s+Recommended/.test(space)) fail(`no space before the badge: ${JSON.stringify(space)}`);

  step('Advanced is closed, and holds the SOCKS switch, port and address');
  await hidden(page.locator('input[name=tls_socks_port]'), 'the SOCKS port while Advanced is closed');
  await page.locator('details.advanced > summary').click();
  await shown(page.locator('input[name=tls_socks_port]'), 'the SOCKS port after the click');
  await shown(page.locator('label.switch:has-text("Offer the SOCKS entry point")'), 'the SOCKS switch');
  await shown(page.locator('details.advanced code:has-text("/tls.pac")'), 'the automatic proxy configuration address');
  await page.locator('details.advanced > summary').click();

  step('the Save bar does not cover the field being edited');
  await page.setViewportSize({ width: 1280, height: 520 });
  const clear = async (selector) => {
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.locator(selector).focus();
    await page.waitForTimeout(200);
    const r = await page.evaluate((s) => {
      const f = document.querySelector(s).getBoundingClientRect(), bar = document.querySelector('.savebar').getBoundingClientRect(), head = document.querySelector('header').getBoundingClientRect();
      return { fieldTop: f.top, fieldBottom: f.bottom, barTop: bar.top, headBottom: head.bottom, vh: window.innerHeight };
    }, selector);
    if (r.fieldBottom > r.barTop + 1 && r.fieldTop < r.vh) fail(`the Save bar covers ${selector}: ${JSON.stringify(r)}`);
    if (r.fieldTop < r.headBottom - 1) fail(`the header covers ${selector}: ${JSON.stringify(r)}`);
  };
  await clear('textarea[name=tls_devices]');
  await clear('textarea[name=tls_bypass]');
  await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
  await clear('textarea[name=tls_bypass]');
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.setViewportSize({ width: 1280, height: 900 });

  step('screenshots: light, dark, sections open, and a phone in both');
  // A full page screenshot puts a sticky bar at the foot of the first screen, so the shots show it in flow.
  const flat = () => page.addStyleTag({ content: '.savebar { position: static !important; }' });
  await page.emulateMedia({ colorScheme: 'light' });
  await openHttps(page);
  await noSideways('light');
  await flat();
  await shot(page, 'https-layout-light');
  await page.emulateMedia({ colorScheme: 'dark' });
  await openHttps(page);
  if (rgb(await page.evaluate(() => getComputedStyle(document.body).backgroundColor)) === '252,252,251') fail('dark mode kept the light page');
  await noSideways('dark');
  await flat();
  await shot(page, 'https-layout-dark');
  await page.emulateMedia({ colorScheme: 'light' });
  await openHttps(page);
  // Opening several at once means dropping the shared name, which only the screenshot needs.
  await page.evaluate(() => document.querySelectorAll('#pane-https details').forEach((d) => { d.removeAttribute('name'); d.open = true; }));
  await noSideways('open sections');
  await flat();
  await shot(page, 'https-layout-open');
  await page.setViewportSize({ width: 390, height: 800 });
  for (const scheme of ['dark', 'light']) {
    await page.emulateMedia({ colorScheme: scheme });
    await openHttps(page);
    await noSideways(`phone ${scheme}`);
    await flat();
    await page.evaluate(() => document.querySelectorAll('#pane-https details').forEach((d) => { d.removeAttribute('name'); d.open = true; }));
    await noSideways(`phone ${scheme} with the sections open`);
    await page.evaluate(() => document.querySelectorAll('#pane-https details').forEach((d) => { d.open = false; }));
    if (scheme === 'light') await shot(page, 'https-layout-phone');
  }
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.emulateMedia({ colorScheme: null });
  await openHttps(page);
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
  await layout(page);

  step('the Create a key here section is on the tab, closed until a click');
  const create = page.locator('details.section:has(> summary:has-text("Create a key here"))');
  await shown(create.locator('> summary'), 'the Create a key here heading');
  await shown(page.locator('.recommended'), 'the Recommended mark');
  if (await create.evaluate((el) => el.open)) fail('the Create a key here section is open with no request pending');
  await create.locator('> summary').click();
  await shown(page.locator('input[name=ca_request_name]'), 'the CA name field');
  await shown(page.locator('button:has-text("Create request")'), 'the Create request button');
  await shown(page.locator('details.section > summary:has-text("Upload a certificate and key you already have")'), 'the heading of the two-file form');
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

  step('the bank list switch is on the tab, with the source and the status');
  const bank = page.locator('label.switch:has-text("Skip the bank list")');
  await shown(bank, 'the Skip the bank list switch');
  if (!(await page.locator('input[name=tls_bank_list]').isChecked())) fail('the bank list switch is not on by default');
  await shown(page.locator('text=Université Toulouse Capitole'), 'the source of the bank list');
  await untilShown(page, page.locator('text=1 101 names, downloaded'), 'the bank list status');
  await shot(page, 'bank-list-switch');

  step('create a request');
  // Each page load starts with the sections closed while nothing is pending.
  if (!(await create.evaluate((el) => el.open))) await create.locator('> summary').click();
  await page.fill('input[name=ca_request_name]', CA_NAME);
  await Promise.all([page.waitForURL(/ok=ca-requested/), page.click('button:has-text("Create request")')]);
  await untilShown(page, page.locator('a[href="/tls/own-ca.csr"]'), 'the Download request link');
  if (!(await create.evaluate((el) => el.open))) fail('a pending request did not open its section');
  if (await page.locator('details.section:has(> summary:has-text("Upload a certificate and key you already have"))').evaluate((el) => el.open)) fail('the upload section opened with the request');
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
  await page.locator('details.section > summary:has-text("Upload a certificate and key you already have")').click();
  await page.locator('input[type=file][name=chain][form=own-ca]').setInputFiles(`${OUT}/pair-chain.pem`);
  await page.locator('input[type=file][name=key][form=own-ca]').setInputFiles(`${OUT}/pair.key`);
  await Promise.all([page.waitForURL(/ok=ca-uploaded/), page.click('button[form=own-ca]:has-text("Upload")')]);
  await untilShown(page, page.locator(`text=In use: your own CA, CN=${PAIR_NAME}`), 'the CA of the pair');
  await shown(page.locator('.ca-line button:has-text("Stop using my CA")'), 'Stop using my CA in the first line');
  await hidden(page.locator('details.section > summary:has-text("Regenerate the CA")'), 'the Regenerate section with an own CA');
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

async function connections(page) {
  await signIn(page);
  step('the Connections item is in the menu, and the Overview tile opens the page');
  await page.goto(`${APP}/`);
  await shown(page.locator('nav a:has-text("Connections")'), 'the Connections menu item');
  const tile = page.locator('a.tile:has-text("Decrypted, 24h")');
  await shown(tile, 'the Decrypted, 24h tile on Overview');
  await shot(page, 'overview-tile');
  await Promise.all([page.waitForURL(`${APP}/connections`), tile.click()]);
  await shown(page.locator('h1:has-text("Connections")'), 'the Connections heading');

  step('the tiles show data');
  for (const label of ['Connections, 24h', 'Inspected share', 'Passed share', 'Data through the proxy']) {
    const t = page.locator(`.tile:has-text("${label}")`);
    await shown(t, `the ${label} tile`);
    const value = (await t.locator('b').textContent()).trim();
    if (!value || /^(0|0%|0 B)$/.test(value)) fail(`the ${label} tile shows ${value}`);
  }

  step('the chart has bars of both series, a legend, and is really drawn');
  const chart = page.locator('section.panel:has(h2:has-text("Connections per hour")) svg').first();
  await shown(chart, 'the chart');
  const box = await chart.boundingBox();
  if (!box || box.width < 200 || box.height < 80) fail(`the chart is ${JSON.stringify(box)}`);
  for (const series of ['bar-1', 'bar-2']) {
    const bars = chart.locator(`path.${series}`);
    if ((await bars.count()) === 0) fail(`the chart has no ${series} bars`);
    await shown(bars, `a ${series} bar`);
    const b = await bars.first().boundingBox();
    if (!b || b.height < 1 || b.width < 3) fail(`a ${series} bar is ${JSON.stringify(b)}`);
  }
  await shown(page.locator('.legend:has-text("Inspected"):has-text("Passed")'), 'the legend');

  step('the tables show the traffic');
  for (const title of ['Why connections passed', 'Top sites by connections', 'Top sites by data', 'Data per device', 'Recent connections']) {
    const panel = page.locator(`section.panel:has(h2:has-text("${title}"))`);
    await shown(panel, title);
    await shown(panel.locator('tr td').first(), `a row of ${title}`);
  }
  const rows = page.locator('section.panel:has(h2:has-text("Recent connections")) tr:has(td)');
  const all = await rows.count();
  if (all < 3) fail(`only ${all} recent connections`);
  const text = await rows.allTextContents();
  for (const expected of ['test.example.net', 'bad.example.net', 'banked.example.net', 'Passed: Name on the downloaded bank list', 'Refused']) if (!text.some((t) => t.includes(expected))) fail(`no recent row with ${expected}`);
  await shot(page, 'connections-light');

  step('the filters narrow the list');
  // The newest 200 are all from 127.0.0.1 after the load tests, so the filter is shown on the refused source. The menu leaves refused sources out, so it is reached by the address.
  const sources = await page.locator('select[name=device] option').evaluateAll((os) => os.map((o) => o.value).filter((v) => v));
  const refusedRow = page.locator('section.panel:has(h2:has-text("Recent connections")) tr:has-text("Refused: Not on the device list")').first();
  const other = (await refusedRow.locator('td').nth(1).innerText()).trim();
  if (!other || other === '127.0.0.1') fail(`the refused source is ${other}`);
  if (!sources.includes('127.0.0.1') || sources.includes(other) || sources.includes('(refused)')) fail(`the device filter offers ${JSON.stringify(sources)}`);
  await page.goto(`${APP}/connections?device=${encodeURIComponent(other)}`);
  const byDevice = await page.locator('section.panel:has(h2:has-text("Recent connections")) tr:has(td)').allTextContents();
  if (!byDevice.length || byDevice.length >= all) fail(`the device filter left ${byDevice.length} of ${all} rows`);
  if (byDevice.some((t) => !t.includes('Refused: Not on the device list'))) fail('the device filter kept a row of another device');
  await page.selectOption('select[name=device]', '127.0.0.1');
  await Promise.all([page.waitForURL(/device=127.0.0.1/), page.click('.filters button')]);
  const local = await page.locator('section.panel:has(h2:has-text("Recent connections")) tr:has(td)').allTextContents();
  if (!local.length || local.some((t) => t.includes('Not on the device list'))) fail('the filter on 127.0.0.1 kept a row of the other device');
  await page.fill('input[name=site]', 'bad.example');
  await Promise.all([page.waitForURL(/site=bad.example/), page.click('.filters button')]);
  const bySite = await page.locator('section.panel:has(h2:has-text("Recent connections")) tr:has(td)').allTextContents();
  if (!bySite.length || bySite.some((t) => !t.includes('bad.example.net'))) fail(`the site filter left ${JSON.stringify(bySite)}`);
  await shot(page, 'connections-filtered');
  await page.fill('input[name=site]', 'no-such-site.invalid');
  await Promise.all([page.waitForURL(/no-such-site/), page.click('.filters button')]);
  await shown(page.locator('text=Nothing matches these filters'), 'the empty filter result');
  await page.goto(`${APP}/connections`);

  step('dark and light: the bars are drawn in a colour that is not the background');
  for (const scheme of ['light', 'dark']) {
    await page.emulateMedia({ colorScheme: scheme });
    const seen = await page.evaluate(() => {
      const fill = (sel) => getComputedStyle(document.querySelector(sel)).fill;
      return { one: fill('section.panel svg path.bar-1'), two: fill('section.panel svg path.bar-2'), page: getComputedStyle(document.body).backgroundColor,
               card: getComputedStyle(document.querySelector('section.panel')).backgroundColor };
    });
    if (rgb(seen.one) === rgb(seen.card) || rgb(seen.two) === rgb(seen.card) || rgb(seen.one) === rgb(seen.two)) fail(`${scheme}: the bars are ${JSON.stringify(seen)}`);
    if (scheme === 'dark' && rgb(seen.page) === '252,252,251') fail('dark mode kept the light page');
    await shot(page, `connections-${scheme}`);
  }
  await page.emulateMedia({ colorScheme: null });

  step('a narrow screen has no sideways scroll on the page');
  await page.setViewportSize({ width: 390, height: 800 });
  await page.goto(`${APP}/connections`);
  const wide = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
  if (wide) fail('the page scrolls sideways on a phone');
  await shot(page, 'connections-phone');
}


// A tab click must change the guide next to the form with no reload, and a preset must fill the two fields and leave the key.
async function guide(page) {
  await signIn(page);
  await page.goto(`${APP}/settings?tab=protection`);
  await page.evaluate(() => { window.__sameDocument = 'yes'; });

  step('clicking a tab shows its pane and only its guide block, with no reload');
  for (const tab of TABS) {
    await page.click(`.tabbar label[for=tab-${tab}]`);
    await shown(page.locator(`#pane-${tab}`), `the ${tab} pane`);
    await shown(page.locator(`.guide-block.guide-${tab}`), `the ${tab} guide block`);
    await shown(page.locator(`.guide-block.guide-${tab} h2`), `the first heading of the ${tab} guide`);
    for (const other of TABS.filter((t) => t !== tab)) {
      await hidden(page.locator(`#pane-${other}`), `the ${other} pane on the ${tab} tab`);
      await hidden(page.locator(`.guide-block.guide-${other}`), `the ${other} guide block on the ${tab} tab`);
    }
    const box = await page.locator(`.guide-block.guide-${tab}`).boundingBox();
    if (!box || box.width < 200 || box.height < 60) fail(`the ${tab} guide is ${JSON.stringify(box)}`);
    const side = await page.evaluate((t) => document.querySelector(`.guide-block.guide-${t}`).getBoundingClientRect().left > document.querySelector(`#pane-${t}`).getBoundingClientRect().right - 1, tab);
    if (!side) fail(`the ${tab} guide is not in the right column`);
    if ((await page.evaluate(() => window.__sameDocument)) !== 'yes') fail(`clicking ${tab} reloaded the page`);
    await shot(page, `guide-${tab}`);
  }

  step('the guide follows the form on a phone');
  await page.setViewportSize({ width: 390, height: 800 });
  for (const tab of ['router', 'ai']) {
    await page.click(`.tabbar label[for=tab-${tab}]`);
    await shown(page.locator(`.guide-block.guide-${tab}`), `the ${tab} guide block on a phone`);
    const order = await page.evaluate((t) => document.querySelector(`.guide-block.guide-${t}`).getBoundingClientRect().top >= document.querySelector(`#pane-${t}`).getBoundingClientRect().bottom - 1, tab);
    if (!order) fail(`on a phone the ${tab} guide is not below the form`);
    if (await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth)) fail('the page scrolls sideways on a phone');
  }
  await shot(page, 'guide-phone');
  await page.setViewportSize({ width: 1280, height: 900 });

  step('a preset fills the address and the model and never touches the key');
  await page.goto(`${APP}/settings?tab=ai`);
  await shown(page.locator('#pane-ai'), 'the AI tab');
  const toggle = page.locator('label.switch:has(input[name=ai_enabled])');
  if (!(await page.locator('input[name=ai_enabled]').isChecked())) await toggle.click();
  const select = page.locator('#ai-preset');
  await shown(select, 'the Preset menu');
  const options = await select.locator('option').allTextContents();
  const wanted = ['Ollama', 'LM Studio', 'OpenAI', 'Google Gemini', 'Anthropic', 'OpenRouter', 'Custom'];
  if (JSON.stringify(options) !== JSON.stringify(wanted)) fail(`the presets are ${JSON.stringify(options)}`);
  const key = page.locator('input[name=ai_key]');
  await key.fill('typed-key-not-saved');
  const url = page.locator('input[name=ai_url]'), model = page.locator('input[name=ai_model]');
  const expected = {
    ollama: ['http://host:11434/v1', 'llama3.2'], lmstudio: ['http://host:1234/v1', ''], openai: ['https://api.openai.com/v1', 'gpt-5.6-luna'],
    gemini: ['https://generativelanguage.googleapis.com/v1beta/openai', 'gemini-3.1-flash-lite'], anthropic: ['https://api.anthropic.com/v1', 'claude-haiku-5-5'],
    openrouter: ['https://openrouter.ai/api/v1', ''],
  };
  for (const [name, [address, suggested]] of Object.entries(expected)) {
    await select.selectOption(name);
    if ((await url.inputValue()) !== address) fail(`${name}: the address is ${await url.inputValue()}`);
    if ((await model.inputValue()) !== suggested) fail(`${name}: the model is ${await model.inputValue()}`);
    if ((await key.inputValue()) !== 'typed-key-not-saved') fail(`${name}: the key field changed`);
    await shown(page.locator(`.preset-hint[data-preset=${name}]`), `the ${name} hint`);
    if ((await page.locator('.preset-hint:visible').count()) !== 1) fail(`${name}: more than one hint is visible`);
  }
  await url.fill('http://192.0.2.50:8000/v1');
  await model.fill('mine');
  await select.selectOption('custom');
  if ((await url.inputValue()) !== 'http://192.0.2.50:8000/v1' || (await model.inputValue()) !== 'mine') fail('Custom changed the fields');
  await select.selectOption('anthropic');
  await shot(page, 'ai-presets');
  await shown(page.locator('button:has-text("Test the model")'), 'the Test button');
}

async function off(page) {
  await signIn(page);
  step('no Connections item and no tile on Overview');
  await page.goto(`${APP}/`);
  if ((await page.locator('nav a:has-text("Connections")').count()) !== 0) fail('the menu has a Connections item');
  if ((await page.locator('a.tile:has-text("Decrypted")').count()) !== 0) fail('Overview has the Decrypted tile');
  step('no HTTPS inspection tab, pane or guide block');
  await page.goto(`${APP}/settings`);
  await shown(page.locator('.tabbar label[for=tab-protection]'), 'the Protection tab');
  const labels = await page.locator('.tabbar label').allTextContents();
  if (labels.some((t) => t.includes('HTTPS'))) fail(`the tabs are ${JSON.stringify(labels)}`);
  for (const selector of ['#pane-https', '.guide-block.guide-https', 'input[name=tls_enabled]']) {
    if ((await page.locator(selector).count()) !== 0) fail(`${selector} is on the page`);
  }
  await page.goto(`${APP}/settings?tab=https`);
  await shown(page.locator('#pane-protection'), 'the first tab, when the HTTPS one is asked for');
  await shot(page, 'off-settings');
  step('/connections says how to turn it on');
  await page.goto(`${APP}/connections`);
  await shown(page.locator('text=COMPOSE_PROFILES=https'), 'the note on /connections');
  await shot(page, 'off-connections');
}

const phase = process.argv[2];
const phases = { request, pair, names, connections, guide, off };
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
