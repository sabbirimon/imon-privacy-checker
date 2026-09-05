const { test } = require('@playwright/test');

test('screenshot homepage hero with new branding', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 600 });
    await page.goto('http://127.0.0.1:8080/', { waitUntil: 'load' });
    await page.waitForTimeout(1500);
    await page.screenshot({ path: '/tmp/hero-light.png', fullPage: false });
});
