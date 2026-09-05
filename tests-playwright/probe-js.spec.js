const { test, expect } = require('@playwright/test');

test('debug: verify scanner.js loads + DOMContentLoaded fires', async ({ page }) => {
    const network404 = [];
    const consoleMsgs = [];
    const pageErrors = [];
    page.on('response', (r) => { if (r.status() >= 400) network404.push(`${r.status()} ${r.url()}`); });
    page.on('console', (msg) => consoleMsgs.push(`[${msg.type()}] ${msg.text()}`));
    page.on('pageerror', (e) => pageErrors.push(String(e)));

    await page.goto('http://127.0.0.1:8080/', { waitUntil: 'load' });
    await page.waitForTimeout(2000);

    const scriptInfo = await page.evaluate(() => {
        const scripts = Array.from(document.scripts).map((s) => ({
            src: s.src,
            type: s.type,
            hasContent: !!s.textContent && s.textContent.length > 0,
            contentLen: s.textContent ? s.textContent.length : 0,
        }));
        const pcScanGlobal = !!window.PC_SCAN;
        const dashboard = document.querySelector('[data-pc-component="dashboard"]');
        const dashboardExists = !!dashboard;
        const dashboardReady = dashboard ? dashboard.dataset.pcScanned : null;
        return { scripts, pcScanGlobal, dashboardExists, dashboardReady };
    });

    console.log('=== 404 responses ===');
    network404.forEach((u) => console.log(u));
    console.log('=== Scripts on page ===');
    scriptInfo.scripts.forEach((s) => console.log(JSON.stringify(s)));
    console.log('=== Globals ===');
    console.log('PC_SCAN:', scriptInfo.pcScanGlobal);
    console.log('Dashboard exists:', scriptInfo.dashboardExists);
    console.log('Dashboard pcScanned:', scriptInfo.dashboardReady);
    console.log('=== Page errors ===');
    pageErrors.forEach((m) => console.log(m));
    console.log('=== Console msgs ===');
    consoleMsgs.slice(0, 30).forEach((m) => console.log(m));
});
