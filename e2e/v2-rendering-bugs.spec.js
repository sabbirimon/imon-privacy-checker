// e2e/v2-rendering-bugs.spec.js
//
// Regression tests for the v2 rendering bugs found in the Phase 19.5
// pass. Each test would have caught one of the issues listed in the
// "Part 1 — Bugs to fix" brief:
//
//   1. The User Agent row was rendering the literal "[object Object]"
//      because the whole user_agent payload object was assigned to a
//      text node.
//   2. The Security Findings "Browser" row was rendering "undefined
//      NNN" because the JS read sp.browser.name which is undefined —
//      the REST payload uses sp.browser.browser.
//   3. The main Privacy Score gauge rendered "—" because the JS read
//      report.privacy_score which doesn't exist; the canonical field
//      is privacy_report.overall.
//   4. The Overview card used to render sub-scores with naive
//      capitalize() — "Ip", "Dns", "Webrtc" — instead of the proper
//      "IP", "DNS", "WebRTC" labels.
//   5. The DNS Resolver card used to be stuck on "Provider: Not
//      configured" / "Status: Not available" because the JS never
//      fired the parallel DNS-over-HTTPS probe.
//   6. The Overview card used to be a flat key-value list — the user
//      asked for a real chart.
//
// These tests assert each fix is still in place. If any of them
// starts failing, that's a regression on a real user-visible bug.

const { test, expect } = require('@playwright/test');

async function gotoV2(page) {
    await page.context().clearCookies();
    await page.goto('/?v=2');
    await page.waitForSelector('[data-pcv2-region="report"]:not([hidden])', { timeout: 15_000 });
    // Wait for all six cards to be populated (title + body) before
    // asserting against them.
    await page.waitForFunction(
        () => document.querySelectorAll('.pcv2__card').length === 6
           && Array.from(document.querySelectorAll('.pcv2__card [data-pcv2-region="card-title"]'))
                   .every(el => (el.textContent || '').trim().length > 0)
           && Array.from(document.querySelectorAll('.pcv2__card [data-pcv2-region="card-body"]'))
                   .every(el => el.children.length > 0),
        null,
        { timeout: 15_000 }
    );
}

test.describe('v2 rendering-bug regressions', () => {

    test('User Agent row never contains "[object Object]"', async ({ page }) => {
        await gotoV2(page);
        const html = await page.evaluate(() => document.body.innerHTML);
        expect(html).not.toContain('[object Object]');
        // And the Browser card must have a non-empty User Agent row
        // whose first row is a real string, not a bare dash.
        const uaRow = await page.evaluate(() => {
            const card = document.querySelector('[data-pcv2-card="browser"]');
            if (!card) return null;
            const rows = card.querySelectorAll('dt');
            for (const dt of rows) {
                if ((dt.textContent || '').trim().toLowerCase() === 'user agent') {
                    const dd = dt.nextElementSibling;
                    return (dd ? dd.textContent : '').trim();
                }
            }
            return null;
        });
        expect(uaRow).not.toBeNull();
        expect(uaRow.length).toBeGreaterThan(0);
        expect(uaRow).not.toBe('[object Object]');
    });

    test('Security Browser row never contains "undefined NNN"', async ({ page }) => {
        await gotoV2(page);
        const browserRow = await page.evaluate(() => {
            const card = document.querySelector('[data-pcv2-card="security"]');
            if (!card) return null;
            const rows = card.querySelectorAll('dt');
            for (const dt of rows) {
                if ((dt.textContent || '').trim().toLowerCase() === 'browser') {
                    const dd = dt.nextElementSibling;
                    return dd ? (dd.textContent || '').trim() : null;
                }
            }
            return null;
        });
        // The literal "undefined" substring must never appear, neither
        // as a value nor as a prefix. Empty / dash is acceptable for
        // genuinely-missing browser data.
        if (browserRow) {
            expect(browserRow).not.toMatch(/\bundefined\b/i);
        }
        // And the body itself must never contain the literal pattern.
        const html = await page.evaluate(() => document.body.innerHTML);
        expect(html).not.toMatch(/undefined\s+\d/);
    });

    test('main Privacy Score shows a numeric 0..100', async ({ page }) => {
        await gotoV2(page);
        const value = await page.evaluate(() => {
            const el = document.querySelector('.pcv2__score-ring-value');
            if (!el) return null;
            // The first text node is the numeric value, /100 in a child.
            return (el.childNodes[0] && el.childNodes[0].textContent || el.textContent || '').trim();
        });
        expect(value).not.toBe('—');
        expect(value).toMatch(/^\d+$/);
        const n = parseInt(value, 10);
        expect(n).toBeGreaterThanOrEqual(0);
        expect(n).toBeLessThanOrEqual(100);
    });

    test('category labels use proper acronyms (IP / DNS / WebRTC)', async ({ page }) => {
        await gotoV2(page);
        // The bar chart on the Overview card carries the per-category
        // labels. None of them should be the broken "Ip", "Dns", or
        // "Webrtc".
        const labels = await page.evaluate(() => {
            return Array.from(document.querySelectorAll('.pcv2__bar-chart-label'))
                .map(el => (el.textContent || '').trim());
        });
        expect(labels.length).toBeGreaterThan(0);
        expect(labels).not.toContain('Ip');
        expect(labels).not.toContain('Dns');
        expect(labels).not.toContain('Webrtc');
        // And the proper acronyms are present somewhere in the labels.
        const all = labels.join('|');
        expect(all).toMatch(/IP/);
        expect(all).toMatch(/DNS/);
        expect(all).toMatch(/WebRTC/);
    });

    test('DNS Resolver card shows real resolver detail from the probe', async ({ page }) => {
        await gotoV2(page);
        // The DNS probe is fired in parallel; allow up to 15 s for it
        // to land.
        const ok = await page.waitForFunction(
            () => document.querySelectorAll('.pcv2__dns-resolver-row').length > 0,
            null,
            { timeout: 15_000 }
        ).then(() => true).catch(() => false);
        expect(ok).toBe(true);

        const rows = await page.evaluate(() => {
            return Array.from(document.querySelectorAll('.pcv2__dns-resolver-row')).map(r => ({
                name:    (r.querySelector('.pcv2__dns-resolver-name')    || {}).textContent || '',
                answer:  (r.querySelector('.pcv2__dns-resolver-answer')  || {}).textContent || '',
                latency: (r.querySelector('.pcv2__dns-resolver-latency') || {}).textContent || '',
                tone:    r.getAttribute('data-pcv2-tone') || ''
            }));
        });
        expect(rows.length).toBeGreaterThanOrEqual(1);
        // The Cloudflare resolver is the first one in the probe result
        // and should appear with a tone of "safe" and an answer IP.
        const cf = rows.find(r => /cloudflare/i.test(r.name));
        if (cf) {
            expect(cf.tone).toBe('safe');
            // Answer IP must look like an IPv4 literal — never "Not
            // available" or an error string.
            expect(cf.answer).toMatch(/^\d+\.\d+\.\d+\.\d+$/);
        }
    });

    test('Overview card renders a real bar chart', async ({ page }) => {
        await gotoV2(page);
        const chart = await page.evaluate(() => {
            const ul = document.querySelector('[data-pcv2-card="overview"] .pcv2__bar-chart');
            if (!ul) return null;
            return Array.from(ul.querySelectorAll('.pcv2__bar-chart-row')).map(r => ({
                label: (r.querySelector('.pcv2__bar-chart-label') || {}).textContent || '',
                value: (r.querySelector('.pcv2__bar-chart-value') || {}).textContent || '',
                tone:  r.getAttribute('data-pcv2-tone') || '',
                width: (r.querySelector('.pcv2__bar-chart-fill') || {}).style && r.querySelector('.pcv2__bar-chart-fill').style.width
            }));
        });
        expect(chart).not.toBeNull();
        expect(chart.length).toBeGreaterThanOrEqual(3);
        // Every row must have a numeric value (or em-dash if missing),
        // a label, and a tone — not the old flat key-value list.
        for (const r of chart) {
            expect(r.label.length).toBeGreaterThan(0);
            expect(['safe', 'warning', 'danger', 'neutral']).toContain(r.tone);
            expect(r.value).toMatch(/^\d+%$|^—$/);
        }
    });
});
