// e2e/scan-cors.spec.js
// Captures the EXACT request/response pair for the POST /scan that
// fails CORS — to see whether preflight or actual response is missing
// the header.

const { test } = require('@playwright/test');

test('scan CORS detail', async ({ page }) => {
    page.on('request', (req) => {
        const u = req.url();
        if (u.includes('/privacy-checker/v1/scan')) {
            console.log(`>>> ${req.method()} ${req.url()}`);
            const acrh = req.headers()['access-control-request-headers'];
            const acrm = req.headers()['access-control-request-method'];
            if (acrh || acrm) {
                console.log(`     preflight: request-method=${acrm}, request-headers=${acrh}`);
            }
        }
    });
    // ALL requests, not just scan.
    page.on('request', (req) => {
        if (req.method() === 'OPTIONS') {
            console.log(`OOO OPTIONS ${req.url()}`);
        }
    });
    page.on('response', async (resp) => {
        const u = resp.url();
        if (u.includes('/privacy-checker/v1/scan')) {
            console.log(`<<< ${resp.status()} ${resp.request().method()} ${resp.url()}`);
            const corsHeaders = {};
            for (const [k, v] of Object.entries(resp.headers())) {
                if (k.toLowerCase().includes('access-control') || k.toLowerCase() === 'vary') {
                    corsHeaders[k] = v;
                }
            }
            console.log(`     CORS headers: ${JSON.stringify(corsHeaders)}`);
        }
    });
    page.on('requestfailed', (req) => {
        const u = req.url();
        if (u.includes('/privacy-checker/v1/scan')) {
            console.log(`!!! ${req.method()} ${u} ${req.failure()?.errorText || ''}`);
        }
    });
    page.on('requestfinished', async (req) => {
        if (req.url().endsWith('/scan') && !req.url().includes('/scan/')) {
            const resp = await req.response();
            if (resp) {
                console.log(`< ${resp.status()} ${resp.url()}`);
                console.log(`  response headers: ${JSON.stringify(resp.headers(), null, 0).slice(0, 800)}`);
                try {
                    const body = await resp.text();
                    console.log(`  body: ${body.slice(0, 400)}`);
                } catch (e) {}
            }
        }
    });
    page.on('requestfailed', (req) => {
        if (req.url().endsWith('/scan') && !req.url().includes('/scan/')) {
            console.log(`!! FAILED: ${req.method()} ${req.url()}`);
            console.log(`  failure: ${JSON.stringify(req.failure())}`);
        }
    });

    await page.context().clearCookies();
    // Also capture all responses for /scan so we see the OPTIONS preflight.
    page.on('response', async (resp) => {
        const u = resp.url();
        if (u.includes('/privacy-checker/v1/scan')) {
            console.log(`<<< ${resp.status()} ${resp.request().method()} ${resp.url()}`);
        }
    });
    await page.goto('/');
    await page.click('a[data-pc-action="start-scan"]');
    await page.waitForTimeout(8000);
});
