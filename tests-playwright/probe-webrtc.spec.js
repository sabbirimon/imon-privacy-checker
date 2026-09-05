const { test } = require('@playwright/test');

test('debug: probe WebRTC page button', async ({ page }) => {
    const apiCalls = [];
    const errors = [];
    page.on('pageerror', (e) => errors.push(String(e)));
    page.on('request', (r) => {
        if (r.url().includes('/wp-json/privacy-checker/') || r.url().includes('rest_route=')) {
            apiCalls.push(`${r.method()} ${r.url().replace('http://127.0.0.1:8080', '')}`);
        }
    });

    await page.goto('http://127.0.0.1:8080/webrtc-test/', { waitUntil: 'load' });
    await page.waitForTimeout(1500);

    const state = await page.evaluate(() => {
        const sec = document.querySelector('[data-pc-component="webrtc"]');
        const btn = sec ? sec.querySelector('[data-pc-action="webrtc"]') : null;
        return {
            sectionExists: !!sec,
            buttonExists: !!btn,
            buttonText: btn ? btn.textContent.trim() : null,
        };
    });
    console.log('=== State ===');
    console.log(JSON.stringify(state, null, 2));

    if (state.buttonExists) {
        await page.locator('[data-pc-component="webrtc"] [data-pc-action="webrtc"]').first().click({ force: true });
        await page.waitForTimeout(3000);
    }

    console.log('=== API calls ===');
    apiCalls.forEach((u) => console.log(u));
    console.log('=== Errors ===');
    errors.forEach((m) => console.log(m));

    const result = await page.evaluate(() => {
        const sec = document.querySelector('[data-pc-component="webrtc"]');
        const r = sec ? sec.querySelector('[data-pc-region="result"]') : null;
        return {
            resultExists: !!r,
            resultHidden: r ? r.hidden : null,
            resultText: r ? r.textContent.substring(0, 300) : null,
        };
    });
    console.log('=== Result region ===');
    console.log(JSON.stringify(result, null, 2));
});
