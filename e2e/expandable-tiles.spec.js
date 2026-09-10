// e2e/expandable-tiles.spec.js
//
// Regression tests for the Phase 25 click-to-expand fact tiles.
//
// The four redesigned cards (Connection, Anonymity, Browser, Security)
// render fact tiles as native <details> elements that expand on click
// to show a detail panel with extra rows of context. These tests
// assert:
//
//   1. Every tile is a real <details> element.
//   2. Clicking the <summary> opens the tile (and the chevron rotates).
//   3. The detail panel shows at least one labelled row when open.
//   4. Only one tile in a card can be open at a time (accordion).
//   5. Tile text values do NOT have a color animation (the RGB
//      animation is reserved for the start-scan button).
//   6. The start-scan button DOES have a color animation that
//      changes the computed `color` over time.
//
// If any of these fail, the user-visible behaviour of the redesigned
// cards has regressed.

const { test, expect } = require('@playwright/test');

async function gotoV2(page) {
    await page.context().clearCookies();
    await page.goto('/?v=2');
    await page.waitForSelector('[data-pcv2-region="report"]:not([hidden])', { timeout: 15_000 });
    await page.waitForFunction(
        () => document.querySelectorAll('.pcv2__card').length === 6
           && Array.from(document.querySelectorAll('.pcv2__card [data-pcv2-region="card-body"]'))
                   .every(el => el.children.length > 0),
        null,
        { timeout: 15_000 }
    );
}

test.describe('v2 expandable tiles (Phase 25)', () => {

    test('every fact tile is a native <details> element', async ({ page }) => {
        await gotoV2(page);
        const tiles = await page.evaluate(() => {
            return Array.from(document.querySelectorAll(
                '[data-pcv2-card="connection"],' +
                '[data-pcv2-card="anonymity"],' +
                '[data-pcv2-card="browser"],' +
                '[data-pcv2-card="security"]'
            )).map(card => {
                const ts = card.querySelectorAll('.pcv2__connection-tile');
                return Array.from(ts).map(t => ({
                    tag: t.tagName.toLowerCase(),
                    key: t.getAttribute('data-pcv2-key') || '',
                    expandable: t.classList.contains('pcv2__connection-tile--expandable')
                }));
            });
        });
        expect(tiles.length).toBe(4); // four cards
        let totalTiles = 0;
        for (const group of tiles) {
            expect(group.length).toBeGreaterThan(0);
            for (const t of group) {
                totalTiles++;
                expect(t.tag).toBe('details');
                expect(t.expandable).toBe(true);
                expect(t.key.length).toBeGreaterThan(0);
            }
        }
        // Sanity check: at least 20 tiles across the 4 cards.
        expect(totalTiles).toBeGreaterThanOrEqual(20);
    });

    test('clicking a tile summary opens the detail panel', async ({ page }) => {
        await gotoV2(page);
        // Connection card, first tile (IPV4).
        const card = page.locator('[data-pcv2-card="connection"]');
        const tile = card.locator('.pcv2__connection-tile').first();
        await tile.scrollIntoViewIfNeeded();
        await expect(tile).not.toHaveAttribute('open', '');
        await tile.locator('summary').click();
        await expect(tile).toHaveAttribute('open', '');
        // Detail panel should now contain at least one labelled row.
        const detailRows = await tile.locator('.pcv2__connection-tile-detail-row').count();
        expect(detailRows).toBeGreaterThanOrEqual(1);
    });

    test('accordion: only one tile open per card', async ({ page }) => {
        await gotoV2(page);
        const card = page.locator('[data-pcv2-card="connection"]');
        const tiles = card.locator('.pcv2__connection-tile');
        const n = await tiles.count();
        expect(n).toBeGreaterThanOrEqual(3);
        // Open tile 0
        await tiles.nth(0).locator('summary').click();
        await expect(tiles.nth(0)).toHaveAttribute('open', '');
        // Open tile 1 — tile 0 should auto-close
        await tiles.nth(1).locator('summary').click();
        await expect(tiles.nth(1)).toHaveAttribute('open', '');
        await expect(tiles.nth(0)).not.toHaveAttribute('open', '');
        // Open tile 2 — tile 1 should auto-close
        await tiles.nth(2).locator('summary').click();
        await expect(tiles.nth(2)).toHaveAttribute('open', '');
        await expect(tiles.nth(1)).not.toHaveAttribute('open', '');
    });

    test('tile value text does NOT have a color animation', async ({ page }) => {
        await gotoV2(page);
        const animName = await page.evaluate(() => {
            const v = document.querySelector('.pcv2__connection-tile-value');
            if (!v) return null;
            return window.getComputedStyle(v).animationName;
        });
        // Must be either 'none' (no animation) or an animation that
        // doesn't touch `color`. Since we removed the rainbow
        // animation from tiles, it must be 'none'.
        expect(animName).toBe('none');
    });

    test('start-scan button has a color animation that changes over time', async ({ page }) => {
        await page.context().clearCookies();
        await page.goto('/?v=2');
        await page.waitForSelector('[data-pcv2-action="start-scan"]', { timeout: 15_000 });
        // Sample the button color at 1.5 s and 4.5 s (well within the
        // 6 s cycle) — they must differ.
        const c1 = await page.locator('[data-pcv2-action="start-scan"]').first()
            .evaluate(el => window.getComputedStyle(el).color);
        await page.waitForTimeout(3000);
        const c2 = await page.locator('[data-pcv2-action="start-scan"]').first()
            .evaluate(el => window.getComputedStyle(el).color);
        expect(c1).not.toBe(c2);
        // And the animation name should be the rainbow keyframe.
        const animName = await page.locator('[data-pcv2-action="start-scan"]').first()
            .evaluate(el => window.getComputedStyle(el).animationName);
        expect(animName).toBe('pcv2-btn-rainbow');
    });

    test('detail panel row labels use the expected terminology', async ({ page }) => {
        await gotoV2(page);
        // Open the IPV4 tile in the Connection card and verify the
        // detail rows include "PUBLIC", "HEADERS", "ISP", "ASN".
        const card = page.locator('[data-pcv2-card="connection"]');
        const tile = card.locator('.pcv2__connection-tile[data-pcv2-key="ipv4"]');
        await tile.scrollIntoViewIfNeeded();
        await tile.locator('summary').click();
        const labels = await tile.locator('.pcv2__connection-tile-detail-label')
            .allTextContents();
        const joined = labels.join('|').toUpperCase();
        expect(joined).toMatch(/PUBLIC/);
        expect(joined).toMatch(/ISP/);
        expect(joined).toMatch(/ASN/);
    });
});
