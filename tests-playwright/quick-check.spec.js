const { test } = require('@playwright/test');

test('debug dark theme', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.evaluate(() => {}).catch(()=>{});
    await page.goto('http://127.0.0.1:8080/', { waitUntil: 'networkidle' });
    await page.evaluate(() => localStorage.setItem('pc-theme', 'dark'));
    const beforeReload = await page.evaluate(() => document.documentElement.getAttribute('data-pc-theme'));
    console.log('Before reload, theme attr:', beforeReload);
    await page.reload({ waitUntil: 'networkidle' });
    await page.waitForTimeout(1000);
    const afterReload = await page.evaluate(() => document.documentElement.getAttribute('data-pc-theme'));
    console.log('After reload, theme attr:', afterReload);
    const html = await page.content();
    if (html.includes('pc-theme-toggle')) {
        console.log('TOGGLE BUTTON IS IN DOM');
    }
    if (html.includes('data-pc-action="theme-toggle"')) {
        console.log('TOGGLE BUTTON HAS ACTION ATTR');
    }
});
