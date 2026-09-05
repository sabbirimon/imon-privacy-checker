const { test, expect } = require('@playwright/test');

const tools = [
    { url: '/ip-lookup/', component: 'ip-lookup', action: 'ip-lookup', input: '8.8.8.8', submitText: 'Lookup' },
    { url: '/whois/', component: 'whois', action: 'whois', input: 'example.com', submitText: 'Lookup' },
    { url: '/user-agent/', component: 'user-agent', action: 'user-agent', input: 'Mozilla/5.0 (compatible; Test)', submitText: 'Parse' },
    { url: '/fingerprint/', component: 'fingerprint', action: 'fingerprint', input: null, submitText: 'Check Browser' },
    { url: '/dns-leak-test/', component: 'dns-test', action: 'dns-test', input: null, submitText: 'Run Test' },
    { url: '/webrtc-test/', component: 'webrtc', action: 'webrtc', input: null, submitText: 'Run WebRTC Test' },
];

for (const tool of tools) {
    test(`debug: probe ${tool.url} form submission`, async ({ page }) => {
        const apiCalls = [];
        const pageErrors = [];
        page.on('pageerror', (e) => pageErrors.push(String(e)));
        page.on('request', (r) => {
            if (r.url().includes('/wp-json/privacy-checker/') || r.url().includes('rest_route=')) {
                apiCalls.push(`${r.method()} ${r.url().replace('http://127.0.0.1:8080', '')}`);
            }
        });

        await page.goto(`http://127.0.0.1:8080${tool.url}`, { waitUntil: 'load' });
        await page.waitForTimeout(1500);

        const state = await page.evaluate((sel) => {
            const form = document.querySelector(sel);
            const btn  = form ? form.querySelector('button[type="submit"]') : null;
            return {
                formExists: !!form,
                buttonText: btn ? btn.textContent.trim() : null,
                hasInput: !!(form && form.querySelector('input, textarea')),
            };
        }, `[data-pc-component="${tool.component}"] form[data-pc-action="${tool.action}"]`);

        console.log(`=== ${tool.url} state ===`);
        console.log(JSON.stringify(state, null, 2));

        if (!state.formExists) {
            console.log('Form NOT found, skipping submission');
            return;
        }

        if (tool.input) {
            const inputSelector = `[data-pc-component="${tool.component}"] form[data-pc-action="${tool.action}"] input, [data-pc-component="${tool.component}"] form[data-pc-action="${tool.action}"] textarea`;
            const inp = await page.locator(inputSelector).first();
            await inp.fill(tool.input);
        }

        // Click submit
        const submitSelector = `[data-pc-component="${tool.component}"] form[data-pc-action="${tool.action}"] button[type="submit"]`;
        await page.locator(submitSelector).first().click({ force: true }).catch((e) => console.log('Click err:', String(e)));
        await page.waitForTimeout(2500);

        console.log(`=== ${tool.url} API calls ===`);
        apiCalls.forEach((u) => console.log(u));
        console.log(`=== ${tool.url} errors ===`);
        pageErrors.forEach((m) => console.log(m));
    });
}
