/*
 * Inputs page of TA-stocks, driven in a browser on a real Splunk: create,
 * disable, enable, edit and delete one input of every service in
 * globalConfig.json, each step read back from splunkd's raw
 * configs/conf-inputs endpoint, which the page and the add-on's REST handler
 * never read.
 *
 * Keys are dummies. The Tiingo inputs reach the compose mock
 * (local/tiingo_api_base). Alpha Vantage and Vanguard have no mock: the CI
 * step before this suite points their hosts at 127.0.0.1 inside the Splunk
 * container, so an enabled input fails to connect instead of calling them.
 */
const path = require('path');
const { test, expect } = require('@playwright/test');
const ucc = require('./ucc/ucc-helpers');

const GC = ucc.loadGlobalConfig(path.join(__dirname, '..'));
const APP = GC.meta.name;
const ROOT = GC.meta.restRoot.toLowerCase();
const PAGE_TITLE = GC.pages.inputs.title;
const ACCOUNT_NAME = `e2e_inputs_acct_${Date.now().toString(36)}`;

// Visible label -> inputs.conf key per service, written out here.
const BASE = { name: 'Name', interval: 'Interval', index: 'Index' };
const WITH_ACCOUNT = { ...BASE, account: 'Account to use' };
const FIELDS = {
    alphavantage_daily: { ...WITH_ACCOUNT, ticker: 'Ticker' },
    vanguard_graphql: { ...BASE, portids: 'portIds', function: 'Function' },
    tiingo_iex_current: { ...WITH_ACCOUNT, tickers: 'Ticker(s)' },
    tiingo_stock_endofday: { ...WITH_ACCOUNT, tickers: 'Ticker(s)' },
    tiingo_crypto_endofday: { ...WITH_ACCOUNT, tickers: 'Ticker(s)' },
    tiingo_fx_current: { ...WITH_ACCOUNT, tickers: 'Tickers' },
};
const t = (tickers, edit) => ({ create: { interval: '3600', index: 'main', tickers }, edit: { interval: '7200', tickers: edit } });
const VALUES = {
    alphavantage_daily: { create: { interval: '3600', index: 'main', ticker: 'IBM' }, edit: { interval: '7200', ticker: 'MSFT' } },
    vanguard_graphql: { create: { interval: '3600', index: 'main', portids: '9999' }, edit: { interval: '7200', portids: '8888' },
        select: { function: ['End of Day value', 'endofday'] } },
    tiingo_iex_current: t('aapl', 'msft'),
    tiingo_stock_endofday: t('aapl', 'msft'),
    tiingo_crypto_endofday: t('btcusd', 'ethusd'),
    tiingo_fx_current: t('gbpusd', 'eurusd'),
};

let rest;
test.beforeAll(async () => {
    rest = await ucc.restClient();
    const r = await rest.post(`/servicesNS/nobody/${APP}/${ROOT}_account`, { name: ACCOUNT_NAME, api_key: 'e2e-dummy-key' });
    expect([200, 201], `create account: ${r.status}`).toContain(r.status);
});
test.afterAll(async () => {
    await rest.del(`/servicesNS/nobody/${APP}/${ROOT}_account/${ACCOUNT_NAME}`);
    await rest.dispose();
});
test.beforeEach(async ({ page }) => ucc.login(page));

test('every input service has test values and labels', () => {
    const services = GC.pages.inputs.services.map((s) => s.name).sort();
    expect(services).toEqual(Object.keys(VALUES).sort());
    expect(services).toEqual(Object.keys(FIELDS).sort());
});

async function fillTexts(d, label, values) {
    for (const [f, v] of Object.entries(values)) {
        await ucc.fillText(d, label(f), v);
        await ucc.control(d, label(f)).press('Tab');
    }
}

for (const service of GC.pages.inputs.services) {
    const label = (key) => FIELDS[service.name][key];
    const stanza = (name) => rest.inputStanza(APP, service.name, name);
    const vals = VALUES[service.name];
    const hasAccount = !!FIELDS[service.name].account;
    const selects = vals.select || {};

    async function fillCreate(page, d, name) {
        await fillTexts(d, label, { name, ...vals.create });
        if (hasAccount) await ucc.selectOption(page, d, label('account'), ACCOUNT_NAME);
        for (const [f, [optLabel]] of Object.entries(selects)) await ucc.selectOption(page, d, label(f), optLabel);
    }

    test(`${service.name}: create, disable, enable, edit and delete through the page`, async ({ page }) => {
        const errs = ucc.watchAppErrors(page, APP);
        const name = `e2e_${service.name}_${Date.now().toString(36)}`;
        try {
            await ucc.gotoUccPage(page, APP, 'inputs', PAGE_TITLE);

            const d = await ucc.openCreateInput(page, service.title);
            await fillCreate(page, d, name);
            await ucc.submitDialog(page, 'Add');
            await expect(ucc.inputRow(page, name)).toBeVisible();
            const made = await ucc.expectConf(() => stanza(name), (c) => c !== null, `[${service.name}://${name}] created`);
            const want = { ...vals.create, ...(hasAccount ? { account: ACCOUNT_NAME } : {}),
                ...Object.fromEntries(Object.entries(selects).map(([f, [, v]]) => [f, v])) };
            for (const [f, v] of Object.entries(want)) expect(made[f], `created ${f}`).toBe(v);
            expect(ucc.isTrue(made.disabled), 'a new input starts enabled').toBe(false);

            await ucc.toggleRow(page, name);
            await ucc.expectConf(() => stanza(name), (c) => c && ucc.isTrue(c.disabled), 'disabled after the switch');
            await ucc.toggleRow(page, name);
            await ucc.expectConf(() => stanza(name), (c) => c && !ucc.isTrue(c.disabled), 'enabled after the switch');

            await ucc.rowAction(page, name, 'Edit');
            const e = ucc.dialog(page);
            await expect(e).toBeVisible();
            for (const [f, v] of Object.entries(vals.create)) expect(await ucc.readText(e, label(f)), `edit shows ${f}`).toBe(v);
            if (hasAccount) await expect(ucc.controlGroup(e, label('account'))).toContainText(ACCOUNT_NAME);
            for (const [f, [optLabel]] of Object.entries(selects)) await expect(ucc.controlGroup(e, label(f))).toContainText(optLabel);
            await fillTexts(e, label, vals.edit);
            await ucc.submitDialog(page, 'Update');
            const after = await ucc.expectConf(() => stanza(name),
                (c) => c && Object.entries(vals.edit).every(([f, v]) => c[f] === v), 'edited values saved');
            for (const [f, v] of Object.entries({ ...want, ...vals.edit })) expect(after[f], `after edit ${f}`).toBe(v);

            await ucc.rowAction(page, name, 'Delete');
            await ucc.submitDialog(page, 'Delete');
            await expect(ucc.inputRow(page, name)).toHaveCount(0);
            await ucc.expectConf(() => stanza(name), (c) => c === null, `[${service.name}://${name}] removed`);
            errs.assertNone();
        } finally {
            await rest.deleteInput(APP, service.name, name);
        }
    });

    test(`${service.name}: an invalid name or interval is refused and nothing is written`, async ({ page }) => {
        const bad = '9_starts_with_a_digit';
        await ucc.gotoUccPage(page, APP, 'inputs', PAGE_TITLE);
        const d = await ucc.openCreateInput(page, service.title);
        await fillCreate(page, d, bad);
        await d.getByRole('button', { name: 'Add', exact: true }).click();
        const nameMsg = service.entity.find((x) => x.field === 'name').validators[0].errorMsg;
        await expect(d.getByText(nameMsg).first()).toBeVisible();
        const good = `e2e_badinterval_${Date.now().toString(36)}`;
        await fillTexts(d, label, { name: good, interval: '5' });
        await d.getByRole('button', { name: 'Add', exact: true }).click();
        const rangeMsg = service.entity.find((x) => x.field === 'interval').validators.find((v) => v.type === 'number').errorMsg;
        await expect(d.getByText(rangeMsg).first()).toBeVisible();
        await page.waitForTimeout(3000);
        expect(await stanza(bad)).toBeNull();
        expect(await stanza(good)).toBeNull();
        await d.getByRole('button', { name: 'Cancel', exact: true }).click();
    });
}
