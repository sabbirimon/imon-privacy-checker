const { test, expect } = require('@playwright/test');

test('debug: probe Run Privacy Check button click + console errors', async ({ page }) => {
    const consoleMsgs = [];
    const pageErrors = [];
    page.on('console', (msg) => consoleMsgs.push(`[${msg.type()}] ${msg.text()}`));
    page.on('pageerror', (e) => pageErrors.push(String(e)));

    // Capture every network request to REST endpoints
    const apiCalls = [];
    page.on('request', (req) => {
        if (req.url().includes('/wp-json/privacy-checker/') || req.url().includes('rest_route=')) {
            apiCalls.push(req.url());
        }
    });

    await page.goto('http://127.0.0.1:8080/', { waitUntil: 'domcontentloaded' });

    // Wait for the auto-scan to fire on its own (dashboard auto-runs).
    await page.waitForTimeout(3000);

    const apiCallsBefore = [...apiCalls];

    // Click the "Run Privacy Check" hero button explicitly.
    const startBtn = await page.locator('[data-pc-action="start-scan"]').first();
    const btnExists = await startBtn.count();

    if (btnExists > 0) {
        await startBtn.click({ force: true });
    }
    await page.waitForTimeout(2500);

    const apiCallsAfter = [...apiCalls];

    const stepStates = await page.evaluate(() => {
        const dashboard = document.querySelector('[data-pc-component="dashboard"]');
        if (!dashboard) return { error: 'no-dashboard' };
        const steps = Array.from(dashboard.querySelectorAll('[data-pc-step]')).map((el) => ({
            name: el.getAttribute('data-pc-step'),
            state: el.getAttribute('data-pc-state') || el.className,
        }));
        const scoreEl = dashboard.querySelector('[data-pc-score]');
        const html = dashboard.querySelector('[data-pc-region="report"]');
        return {
            steps,
            score: scoreEl ? scoreEl.textContent.trim() : null,
            reportHtmlLen: html ? html.innerHTML.length : 0,
            reportHidden: html ? html.hidden : null,
        };
    });

    console.log('=== Console msgs ===');
    consoleMsgs.slice(-20).forEach((m) => console.log(m));
    console.log('=== Page errors ===');
    pageErrors.forEach((m) => console.log(m));
    console.log('=== API calls before click ===');
    apiCallsBefore.forEach((u) => console.log(u));
    console.log('=== API calls after click ===');
    apiCallsAfter.slice(apiCallsBefore.length).forEach((u) => console.log('  + ' + u));
    console.log('=== Step states + score ===');
    console.log(JSON.stringify(stepStates, null, 2));

    // Save full report region HTML so we can inspect it.
    const reportHtml = await page.evaluate(() => {
        const r = document.querySelector('[data-pc-region="report"]');
        return r ? r.innerHTML.substring(0, 1500) : null;
    });
    console.log('=== Report HTML head (1500 chars) ===');
    console.log(reportHtml);
});
