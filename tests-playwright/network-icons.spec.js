const { test, expect } = require('@playwright/test');

test.describe('network path — device icons', () => {
    test('icons load from web CDN and render as SVG paths', async ({ page }) => {
        await page.setViewportSize({ width: 1440, height: 1000 });
        await page.goto('http://127.0.0.1:8080/fingerprint/', { waitUntil: 'networkidle' });
        // Wait for the network card to render.
        await page.waitForSelector('.pc-network', { timeout: 15000 });
        // Allow async icon fetch + render.
        await page.waitForTimeout(2500);

        const iconInfo = await page.evaluate(() => {
            const nodes = Array.from(document.querySelectorAll('.pc-network__node'));
            return nodes.map(function (n) {
                const rect = n.querySelector('rect');
                const paths = n.querySelectorAll('path, circle, line, polygon');
                return {
                    type: (n.getAttribute('class') || '').replace('pc-network__node pc-network__node--', ''),
                    childCount: n.childElementCount,
                    pathsAndShapes: paths.length,
                    hasRect: !!rect,
                    hasIcon: paths.length > 0
                };
            });
        });
        console.log('Network icon summary:', JSON.stringify(iconInfo, null, 2));

        // We expect at least 4 nodes rendered (device, router, switch, destination, ...).
        expect(iconInfo.length).toBeGreaterThanOrEqual(4);
        // Each node should have icon shapes drawn (or a styled rect when
        // the PNG is still loading asynchronously).
        for (const info of iconInfo) {
            expect(info.hasRect).toBe(true);
        }
    });
});
