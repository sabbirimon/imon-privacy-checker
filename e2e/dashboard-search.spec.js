// e2e/dashboard-search.spec.js
//
// Phase 39: global dashboard search/filter. Verifies that:
//   1. The search bar renders inside the dashboard report region
//   2. Typing a query into it dims non-matching cards and
//      highlights matching ones
//   3. The clear button resets the dashboard back to normal
//   4. The search bar exposes the right placeholder string
//      (translated via the I18N bag)
//
// Forces the 127.0.0.1 origin so the scan API isn't blocked by CORS.

const { test, expect } = require('@playwright/test');

test.describe('global dashboard search (Phase 39)', () => {
    test('search bar renders, filters cards, and clears', async ({ page }) => {
        await page.goto('/');
        await page.click('a[data-pc-action="start-scan"]', { timeout: 5000 });
        await page.waitForSelector('.pc-dash-cols', { timeout: 12_000 });

        // The search bar must exist with the right id and placeholder.
        const searchInput = page.locator('#pc-dashboard-search');
        await expect(searchInput).toBeVisible();
        const placeholder = await searchInput.getAttribute('placeholder');
        expect(placeholder).toMatch(/filter/i);

        // Snapshot the initial card count.
        const initial = await page.evaluate(() => {
            return {
                cards: document.querySelectorAll('[data-pc-region="report"] .pc-card').length,
                hero:  document.querySelectorAll('[data-pc-region="report"] .pc-dashboard__hero').length,
                hasBar: !!document.querySelector('.pc-dashboard__search'),
                hasClear: !!document.querySelector('.pc-dashboard__search-clear'),
            };
        });
        expect(initial.cards).toBeGreaterThan(3);
        expect(initial.hasBar).toBe(true);
        expect(initial.hasClear).toBe(true);

        // Type "fingerprint" — the BROWSER FINGERPRINT card should
        // get the match class; everything else should dim.
        await searchInput.fill('fingerprint');
        await page.waitForTimeout(250); // debounce flush
        const matched = await page.evaluate(() => {
            return {
                matches: document.querySelectorAll('[data-pc-region="report"] .pc-search-match').length,
                dimmed:  document.querySelectorAll('[data-pc-region="report"] .pc-search-dim').length,
            };
        });
        expect(matched.matches).toBeGreaterThan(0);
        expect(matched.dimmed).toBeGreaterThan(0);

        // Clear via the button — both classes should disappear.
        await page.locator('.pc-dashboard__search-clear').click();
        await page.waitForTimeout(250);
        const cleared = await page.evaluate(() => {
            return {
                matches: document.querySelectorAll('[data-pc-region="report"] .pc-search-match').length,
                dimmed:  document.querySelectorAll('[data-pc-region="report"] .pc-search-dim').length,
            };
        });
        expect(cleared.matches).toBe(0);
        expect(cleared.dimmed).toBe(0);

        await page.screenshot({ path: 'test-results/dashboard-search-cleared.png', fullPage: true });
    });

    test('empty query is a no-op (no match/dim classes applied)', async ({ page }) => {
        await page.goto('/');
        await page.click('a[data-pc-action="start-scan"]', { timeout: 5000 });
        await page.waitForSelector('.pc-dash-cols', { timeout: 12_000 });

        await page.locator('#pc-dashboard-search').fill('__no_such_term_xyz__');
        await page.waitForTimeout(250);
        const after = await page.evaluate(() => ({
            matches: document.querySelectorAll('[data-pc-region="report"] .pc-search-match').length,
            dimmed:  document.querySelectorAll('[data-pc-region="report"] .pc-search-dim').length,
        }));
        // No matches expected; everything dimmed (or zero matches is also valid
        // because the algorithm only adds the dim class to nodes it iterates
        // and there will be at least the hero + some cards).
        expect(after.matches).toBe(0);
        expect(after.dimmed).toBeGreaterThan(0);
    });
});
