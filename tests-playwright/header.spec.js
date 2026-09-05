const { test } = require('@playwright/test');

test.describe('header', () => {
    test('horizontal menu + glassmorphism (light)', async ({ page }) => {
        await page.setViewportSize({ width: 1440, height: 900 });
        await page.goto('http://127.0.0.1:8080/fingerprint/', { waitUntil: 'networkidle' });
        await page.waitForTimeout(800);
        await page.screenshot({ path: 'screenshots/header-light.png', fullPage: false, clip: { x: 0, y: 0, width: 1440, height: 220 } });
    });

    test('horizontal menu + glassmorphism (dark)', async ({ page }) => {
        await page.setViewportSize({ width: 1440, height: 900 });
        await page.goto('http://127.0.0.1:8080/fingerprint/', { waitUntil: 'networkidle' });
        await page.evaluate(() => localStorage.setItem('pc-theme', 'dark'));
        await page.reload({ waitUntil: 'networkidle' });
        await page.waitForTimeout(800);
        await page.screenshot({ path: 'screenshots/header-dark.png', fullPage: false, clip: { x: 0, y: 0, width: 1440, height: 220 } });
    });

    test('mobile 3-dot menu opens', async ({ page }) => {
        await page.setViewportSize({ width: 390, height: 800 });
        await page.goto('http://127.0.0.1:8080/fingerprint/', { waitUntil: 'networkidle' });
        await page.waitForTimeout(500);
        await page.screenshot({ path: 'screenshots/header-mobile-closed.png', fullPage: false, clip: { x: 0, y: 0, width: 390, height: 220 } });
        await page.click('.pc-nav-toggle');
        await page.waitForTimeout(300);
        await page.screenshot({ path: 'screenshots/header-mobile-open.png', fullPage: false, clip: { x: 0, y: 0, width: 390, height: 480 } });
    });
});
