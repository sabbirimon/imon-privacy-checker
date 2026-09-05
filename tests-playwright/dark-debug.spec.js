const { test } = require('@playwright/test');

test('take dark screenshot', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto('http://127.0.0.1:8080/', { waitUntil: 'load' });
    await page.evaluate(() => {
        localStorage.setItem('pc-theme', 'dark');
        document.documentElement.setAttribute('data-pc-theme', 'dark');
    });
    await page.waitForTimeout(500);
    const themeAttr = await page.evaluate(() => document.documentElement.getAttribute('data-pc-theme'));
    const bgColor = await page.evaluate(() => window.getComputedStyle(document.body).backgroundColor);
    const html = await page.content();
    console.log('Theme attr:', themeAttr);
    console.log('Body bg:', bgColor);
    console.log('Has data-pc-theme=dark in HTML:', html.includes('data-pc-theme="dark"'));
    await page.screenshot({ path: 'screenshots/home-dark-fixed.png', fullPage: false });
});
