const { test } = require('@playwright/test');

test('inspect dark', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto('http://127.0.0.1:8080/', { waitUntil: 'networkidle' });
    await page.evaluate(() => {
        localStorage.setItem('pc-theme', 'dark');
        document.documentElement.setAttribute('data-pc-theme', 'dark');
    });
    await page.waitForTimeout(800);
    const cs = await page.evaluate(() => {
        const bodyStyle = window.getComputedStyle(document.body);
        const htmlStyle = window.getComputedStyle(document.documentElement);
        return {
            htmlTheme: htmlStyle.getPropertyValue('--pc-bg'),
            htmlBg: htmlStyle.backgroundColor,
            bodyBg: bodyStyle.backgroundColor,
            bodyBgImage: bodyStyle.backgroundImage,
        };
    });
    console.log(JSON.stringify(cs, null, 2));
});
