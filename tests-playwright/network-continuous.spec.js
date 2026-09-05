const { test, expect } = require('@playwright/test');

test.describe('network path — device tags + continuous mode', () => {
    test('device tags show ms/jitter/ip overlay; continuous toggle flips state', async ({ page }) => {
        await page.setViewportSize({ width: 1440, height: 1000 });
        await page.goto('http://127.0.0.1:8080/fingerprint/', { waitUntil: 'networkidle' });
        // Wait for the initial scan to render the network card.
        await page.waitForSelector('.pc-network', { timeout: 15000 });
        await page.waitForTimeout(800);

        // Per-device tag overlay should be present on every node.
        const nodeTags = await page.locator('.pc-network__node-tag').count();
        expect(nodeTags).toBeGreaterThanOrEqual(4);

        // Edge tag pills (ms · j) between hops.
        const edgeTags = await page.locator('.pc-network__edge-tag').count();
        expect(edgeTags).toBeGreaterThanOrEqual(3);

        // Side panel: jitter + ms tags
        const sideJitter = await page.locator('.pc-network__meta-tag:has-text("jitter")').count();
        expect(sideJitter).toBeGreaterThanOrEqual(3);

        // Continuous button visible and currently OFF
        const contBtn = page.locator('[data-pc-action="continuous-toggle"]');
        await expect(contBtn).toBeVisible();
        await expect(contBtn).not.toHaveClass(/is-on/);

        await page.screenshot({ path: 'screenshots/network-with-tags.png', fullPage: false, clip: { x: 0, y: 800, width: 1440, height: 700 } });

        // Click → LIVE state
        await contBtn.click();
        await page.waitForTimeout(300);
        await expect(contBtn).toHaveClass(/is-on/);
        await expect(contBtn).toHaveText(/LIVE/);

        // The dot should pulse — just verify the class is applied.
        const dotHasAnim = await page.evaluate(() => {
            const dot = document.querySelector('.pc-network__continuous.is-on .pc-network__continuous-dot');
            if (!dot) return false;
            const s = getComputedStyle(dot);
            return s.animationName && s.animationName !== 'none';
        });
        expect(dotHasAnim).toBe(true);

        await page.screenshot({ path: 'screenshots/network-continuous-live.png', fullPage: false, clip: { x: 0, y: 800, width: 1440, height: 700 } });

        // Wait for at least one auto-refresh tick (4s interval)
        await page.waitForTimeout(4500);
        const nodeTagsAfter = await page.locator('.pc-network__node-tag').count();
        expect(nodeTagsAfter).toBeGreaterThanOrEqual(4);

        // Toggle back off
        await contBtn.click();
        await page.waitForTimeout(200);
        await expect(contBtn).not.toHaveClass(/is-on/);
        await expect(contBtn).toHaveText(/CONTINUOUS/);
    });
});
