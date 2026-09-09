// e2e/cards-closeup.spec.js
// Crop just the top of the dashboard after a scan so the IP ADDRESS /
// CONNECTION DETAILS cards are visible at readable size.

const { test } = require('@playwright/test');

test('cards closeup — IP ADDRESS + CONNECTION DETAILS', async ({ page }) => {
    await page.goto('/');
    await page.click('a[data-pc-action="start-scan"]', { timeout: 5000 });
    await page.waitForSelector('.pc-dash-cols', { timeout: 12_000 });
    // Wait for the cards to actually finish rendering (the .pc-info-table
    // rows appear after renderCards runs).
    await page.waitForSelector('.pc-info-table tr', { timeout: 12_000 });
    await page.waitForTimeout(500);

    // Top viewport (above the fold) — captures the hero + privacy score
    // card + the top of the two-column grid (IP ADDRESS / CONNECTION DETAILS).
    await page.screenshot({
        path: 'test-results/cards-top.png',
        clip: { x: 0, y: 0, width: 1280, height: 1600 },
    });

    // Just the cards area
    const cols = await page.$('.pc-dash-cols');
    if (cols) {
        await cols.screenshot({ path: 'test-results/cards-closeup.png' });
    }
});
