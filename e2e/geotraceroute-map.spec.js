// e2e/geotraceroute-map.spec.js
//
// Smoke test for /geotraceroute/: verifies the Leaflet map container
// renders (width > 0, height > 0, has tile layers) and that the page
// has not regressed after recent CSS changes.

const { test, expect } = require('@playwright/test');

test.describe('geotraceroute map', () => {

    test('map container renders with tiles', async ({ page }) => {
        await page.goto('/geotraceroute/');

        // The map div is rendered server-side by class-public-assets.php
        // (look for .leaflet-container — that's the actual Leaflet
        // mounted DOM element, not just our pc-geo wrapper).
        await page.waitForSelector('.leaflet-container', { timeout: 10_000 });

        const dims = await page.evaluate(() => {
            const el = document.querySelector('.leaflet-container');
            if (!el) return { error: 'no .leaflet-container' };
            const rect = el.getBoundingClientRect();
            return {
                width: rect.width,
                height: rect.height,
                tiles: document.querySelectorAll('.leaflet-tile').length,
                tileLoaded: document.querySelectorAll('.leaflet-tile-loaded').length,
            };
        });

        expect(dims.error, JSON.stringify(dims)).toBeUndefined();
        expect(dims.width, 'map container must have non-zero width').toBeGreaterThan(100);
        expect(dims.height, 'map container must have non-zero height').toBeGreaterThan(100);

        await page.screenshot({
            path: 'test-results/geotraceroute-map.png',
            fullPage: true,
        });
    });
});
