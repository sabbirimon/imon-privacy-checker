const { test } = require('@playwright/test');

test.describe('visual smoke', () => {
  test('homepage — light theme', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto('http://127.0.0.1:8080/', { waitUntil: 'networkidle' });
    await page.waitForTimeout(2500); // let scan + animations finish
    await page.screenshot({ path: 'screenshots/home-light.png', fullPage: true });
  });

  test('homepage — dark theme', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto('http://127.0.0.1:8080/', { waitUntil: 'networkidle' });
    // Force dark mode via localStorage and reload.
    await page.evaluate(() => localStorage.setItem('pc-theme', 'dark'));
    await page.reload({ waitUntil: 'networkidle' });
    await page.waitForTimeout(2500);
    await page.screenshot({ path: 'screenshots/home-dark.png', fullPage: true });
  });

  test('anonymity tips page', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto('http://127.0.0.1:8080/anonymity-tips/', { waitUntil: 'networkidle' });
    await page.waitForTimeout(500);
    await page.screenshot({ path: 'screenshots/anonymity-tips.png', fullPage: true });
  });
});
