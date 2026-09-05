const { test } = require('@playwright/test');

test('force dark', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    // Set localStorage BEFORE the page loads.
    await page.addInitScript(() => {
        localStorage.setItem('pc-theme', 'dark');
    });
    await page.goto('http://127.0.0.1:8080/', { waitUntil: 'networkidle' });
    await page.waitForTimeout(800);
    const cs = await page.evaluate(() => {
        const html = document.documentElement;
        const cs = window.getComputedStyle(html);
        return {
            theme: html.getAttribute('data-pc-theme'),
            pcBg: cs.getPropertyValue('--pc-bg').trim(),
            pcAccent: cs.getPropertyValue('--pc-accent').trim(),
        };
    });
    console.log('After addInitScript:', JSON.stringify(cs));
});
