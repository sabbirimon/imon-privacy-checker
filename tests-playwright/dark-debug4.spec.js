const { test } = require('@playwright/test');

test('inspect html style', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto('http://127.0.0.1:8080/', { waitUntil: 'networkidle' });
    await page.evaluate(() => {
        document.documentElement.setAttribute('data-pc-theme', 'dark');
    });
    await page.waitForTimeout(300);
    const cs = await page.evaluate(() => {
        const html = document.documentElement;
        const cs = window.getComputedStyle(html);
        return {
            theme: html.getAttribute('data-pc-theme'),
            pcBg: cs.getPropertyValue('--pc-bg').trim(),
            pcText: cs.getPropertyValue('--pc-text').trim(),
            pcAccent: cs.getPropertyValue('--pc-accent').trim(),
            pcSurface: cs.getPropertyValue('--pc-surface').trim(),
        };
    });
    console.log(JSON.stringify(cs, null, 2));
});
