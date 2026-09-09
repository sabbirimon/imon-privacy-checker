// e2e/scan-deep-debug.spec.js
// Captures every API response and console error during a real scan
// to surface the actual failure cause.

const { test } = require('@playwright/test');

test('scan deep debug', async ({ page }) => {
    const apiCalls = [];
    const consoleErrors = [];

    page.on('request', (req) => {
        if (req.url().includes('/wp-json/privacy-checker/')) {
            apiCalls.push({ phase: 'req', method: req.method(), url: req.url() });
        }
    });
    page.on('response', async (resp) => {
        if (resp.url().includes('/wp-json/privacy-checker/')) {
            let body = '';
            try { body = (await resp.text()).slice(0, 400); } catch (e) {}
            apiCalls.push({ phase: 'resp', status: resp.status(), url: resp.url(), body });
        }
    });
    page.on('console', (msg) => {
        const t = msg.type();
        if (t === 'error' || t === 'warning') {
            consoleErrors.push(`[${t}] ${msg.text().slice(0, 400)}`);
        }
    });
    // Log the actual page origin & PC_SCAN config so we see the mismatch.
    await page.goto('/');
    const ctx = await page.evaluate(() => ({
        origin: window.location.origin,
        restUrl: window.PC_SCAN && window.PC_SCAN.restUrl,
        assetUrl: window.PC_SCAN && window.PC_SCAN.assetUrl,
    }));
    console.log(`PAGE ORIGIN: ${ctx.origin}`);
    console.log(`PC_SCAN.restUrl: ${ctx.restUrl}`);
    console.log(`PC_SCAN.assetUrl: ${ctx.assetUrl}`);
    console.log(`CROSS-ORIGIN: ${ctx.origin !== new URL(ctx.restUrl).origin}`);
    page.on('pageerror', (err) => {
        consoleErrors.push('pageerror: ' + err.message.slice(0, 300));
    });

    await page.click('a[data-pc-action="start-scan"]', { timeout: 5000 });
    await page.waitForTimeout(10000);

    console.log('\n=== API CALLS ===');
    for (const c of apiCalls) {
        if (c.phase === 'req') {
            console.log(`> ${c.method} ${c.url}`);
        } else {
            console.log(`< ${c.status} ${c.url}`);
            if (c.status >= 400) {
                console.log(`   body: ${c.body.replace(/\s+/g, ' ')}`);
            }
        }
    }
    console.log('\n=== CONSOLE ERRORS ===');
    if (consoleErrors.length === 0) console.log('(none)');
    for (const e of consoleErrors) console.log(`! ${e}`);

    await page.screenshot({ path: 'test-results/scan-deep-debug.png', fullPage: true });
});
