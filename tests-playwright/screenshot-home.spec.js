const { test } = require('@playwright/test');

test('screenshot homepage network path', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto('http://127.0.0.1:8080/', { waitUntil: 'load' });
    await page.waitForTimeout(5000); // wait for scan to finish

    // Screenshot the network path card region
    const networkCard = await page.locator('.pc-network').first();
    await networkCard.scrollIntoViewIfNeeded();
    await page.waitForTimeout(500);
    await networkCard.screenshot({ path: '/tmp/network-card.png' });

    // Also screenshot the full page
    await page.screenshot({ path: '/tmp/homepage-full.png', fullPage: true });

    console.log('Screenshots saved to /tmp/network-card.png and /tmp/homepage-full.png');
});
