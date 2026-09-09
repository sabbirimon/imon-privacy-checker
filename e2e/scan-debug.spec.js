// e2e/scan-debug.spec.js
//
// Diagnose why the scanner shows "Something went wrong" locally.
// Captures network responses for the scan API calls and prints
// any non-2xx status with body.

const { test } = require('@playwright/test');

test('scan debug: capture failed API calls', async ({ page }) => {
    const failures = [];

    page.on('response', async (resp) => {
        const url = resp.url();
        const status = resp.status();
        if (url.includes('localhost:8080') && url.includes('/wp-json/')) {
            if (status >= 400) {
                let body = '';
                try {
                    body = (await resp.text()).slice(0, 300);
                } catch (e) {
                    body = '<unreadable>';
                }
                failures.push({ url, status, body });
            }
        }
    });

    page.on('console', (msg) => {
        if (msg.type() === 'error') {
            console.log('[browser console error]', msg.text().slice(0, 200));
        }
    });

    page.on('pageerror', (err) => {
        console.log('[browser pageerror]', err.message.slice(0, 200));
    });

    await page.goto('/');
    await page.click('button[data-pc-action="start-scan"]', { timeout: 5000 }).catch(() => {});
    await page.waitForTimeout(8000);

    if (failures.length === 0) {
        console.log('NO failed API calls detected');
    } else {
        console.log('\n=== FAILED API CALLS ===');
        for (const f of failures) {
            console.log(`[${f.status}] ${f.url}`);
            console.log(`     ${f.body.replace(/\s+/g, ' ').slice(0, 250)}\n`);
        }
    }

    await page.screenshot({ path: 'test-results/scan-debug.png', fullPage: true });
});
