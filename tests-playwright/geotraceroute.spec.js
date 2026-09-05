const { test } = require('@playwright/test');

test.describe('geotraceroute page', () => {
    test('loads and renders hop list', async ({ page }) => {
        await page.setViewportSize({ width: 1440, height: 900 });
        await page.goto('http://127.0.0.1:8080/geotraceroute/', { waitUntil: 'networkidle' });
        // Wait for the map + at least one hop card.
        await page.waitForSelector('.pc-geo__hop', { timeout: 15000 });
        await page.waitForTimeout(2500); // let starfield + packet animation render
        await page.screenshot({ path: 'screenshots/geotraceroute.png', fullPage: true });
    });

    test('reset clears route', async ({ page }) => {
        await page.setViewportSize({ width: 1440, height: 900 });
        await page.goto('http://127.0.0.1:8080/geotraceroute/', { waitUntil: 'networkidle' });
        await page.waitForSelector('.pc-geo__hop', { timeout: 15000 });
        await page.waitForTimeout(1500);
        await page.click('[data-pc-action="geo-reset"]');
        await page.waitForTimeout(500);
        await page.screenshot({ path: 'screenshots/geotraceroute-reset.png', fullPage: true });
    });

    test('animate toggle works', async ({ page }) => {
        await page.setViewportSize({ width: 1440, height: 900 });
        await page.goto('http://127.0.0.1:8080/geotraceroute/', { waitUntil: 'networkidle' });
        await page.waitForSelector('.pc-geo__hop', { timeout: 15000 });
        await page.waitForTimeout(1500);
        await page.click('[data-pc-action="geo-toggle"]');
        await page.waitForTimeout(500);
        await page.screenshot({ path: 'screenshots/geotraceroute-paused.png', fullPage: true });
    });

    test('paste traceroute parser visualizes hops', async ({ page }) => {
        await page.setViewportSize({ width: 1440, height: 900 });
        await page.goto('http://127.0.0.1:8080/geotraceroute/', { waitUntil: 'networkidle' });
        await page.waitForSelector('.pc-geo__hop', { timeout: 15000 });
        await page.click('[data-pc-action="geo-paste-toggle"]');
        await page.waitForTimeout(300);
        const sample = [
            'traceroute to 1.1.1.1 (1.1.1.1), 30 hops max',
            ' 1  10.0.0.1 (10.0.0.1)  0.412 ms  0.512 ms  0.612 ms',
            ' 2  192.0.2.1 (192.0.2.1)  1.123 ms  1.245 ms  1.301 ms',
            ' 3  198.51.100.1 (198.51.100.1)  8.231 ms  8.512 ms  8.901 ms',
            ' 4  1.1.1.1 (1.1.1.1)  12.4 ms  12.5 ms  12.6 ms'
        ].join('\n');
        await page.fill('#pc-geo-paste', sample);
        await page.click('button.pc-btn--primary:has-text("Visualize")');
        await page.waitForTimeout(1500);
        await page.screenshot({ path: 'screenshots/geotraceroute-paste.png', fullPage: true });
    });

    test('preferences modal opens and saves', async ({ page }) => {
        await page.setViewportSize({ width: 1440, height: 900 });
        await page.goto('http://127.0.0.1:8080/geotraceroute/', { waitUntil: 'networkidle' });
        await page.waitForSelector('.pc-geo__hop', { timeout: 15000 });
        await page.click('[data-pc-action="open-prefs"]');
        await page.waitForTimeout(300);
        await page.screenshot({ path: 'screenshots/geotraceroute-prefs.png', fullPage: true });
    });

    test('methodology modal opens', async ({ page }) => {
        await page.setViewportSize({ width: 1440, height: 900 });
        await page.goto('http://127.0.0.1:8080/geotraceroute/', { waitUntil: 'networkidle' });
        await page.waitForSelector('.pc-geo__hop', { timeout: 15000 });
        await page.click('[data-pc-action="open-methodology"]');
        await page.waitForTimeout(300);
        await page.screenshot({ path: 'screenshots/geotraceroute-methodology.png', fullPage: true });
    });

    test('probe network panel renders probes', async ({ page }) => {
        await page.setViewportSize({ width: 1440, height: 900 });
        await page.goto('http://127.0.0.1:8080/geotraceroute/', { waitUntil: 'networkidle' });
        await page.waitForSelector('.pc-geo__hop', { timeout: 15000 });
        await page.click('[data-pc-action="geo-probes-toggle"]');
        await page.waitForTimeout(300);
        await page.waitForSelector('.pc-geo__probes li');
        await page.screenshot({ path: 'screenshots/geotraceroute-probes.png', fullPage: true });
    });
});
