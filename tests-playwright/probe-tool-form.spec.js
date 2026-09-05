const { test, expect } = require('@playwright/test');

test('debug: probe IP Lookup form submission', async ({ page }) => {
    const consoleMsgs = [];
    const pageErrors = [];
    const apiCalls = [];
    page.on('console', (m) => consoleMsgs.push(`[${m.type()}] ${m.text()}`));
    page.on('pageerror', (e) => pageErrors.push(String(e)));
    page.on('request', (r) => {
        if (r.url().includes('/wp-json/privacy-checker/') || r.url().includes('rest_route=')) {
            apiCalls.push(`${r.method()} ${r.url()}`);
        }
    });

    await page.goto('http://127.0.0.1:8080/ip-lookup/', { waitUntil: 'load' });
    await page.waitForTimeout(2500);

    const hasScript = await page.evaluate(() => {
        const scripts = Array.from(document.scripts).map((s) => s.src).filter(Boolean);
        const form = document.querySelector('[data-pc-component="ip-lookup"] form[data-pc-action="ip-lookup"]');
        const input = form ? form.querySelector('input[name="ip"]') : null;
        return {
            scannerJsLoaded: scripts.some((u) => u.includes('scanner.js')),
            formExists: !!form,
            inputExists: !!input,
            inputName: input ? input.name : null,
        };
    });

    console.log('=== Page state ===');
    console.log(JSON.stringify(hasScript, null, 2));

    if (hasScript.formExists && hasScript.inputExists) {
        // Try to submit
        await page.fill('[data-pc-component="ip-lookup"] input[name="ip"]', '8.8.8.8');
        await Promise.all([
            page.waitForResponse((r) => r.url().includes('lookup/ip') && r.status() === 200, { timeout: 5000 }).catch(() => null),
            page.locator('[data-pc-component="ip-lookup"] form[data-pc-action="ip-lookup"] button[type="submit"]').first().click({ force: true }).catch(() => null),
        ]);
        await page.waitForTimeout(2000);
    }

    console.log('=== API calls ===');
    apiCalls.forEach((u) => console.log(u));
    console.log('=== Page errors ===');
    pageErrors.forEach((m) => console.log(m));
    console.log('=== Console msgs (last 10) ===');
    consoleMsgs.slice(-10).forEach((m) => console.log(m));
});
