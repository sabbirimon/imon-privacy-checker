// e2e/scanner-v2.spec.js
//
// Verifies the experimental v2 UI works end-to-end:
//   1. Toggle pill appears on the v1 home page and opts the visitor in.
//   2. The v2 dashboard renders after the scan, with Overview /
//      Connection / Anonymity / DNS / Browser / Security cards.
//   3. Theme toggle cycles Light → Dark → System and persists via
//      localStorage.
//   4. The Post-Scan action bar exposes Copy JSON / Copy summary /
//      Download JSON / Copy share link buttons.
//
// Each test uses the existing siteurl origin (127.0.0.1) so CORS
// doesn't block the scan API.

const { test, expect } = require('@playwright/test');

test.describe('v2 experimental UI', () => {

    test('toggle pill on home page opts the visitor into v2', async ({ page }) => {
        await page.context().clearCookies();
        await page.goto('/');
        // Pill should appear (v1 default).
        const pill = page.locator('.pcv2__toggle');
        await expect(pill).toBeVisible({ timeout: 5_000 });
        const href = await pill.getAttribute('href');
        expect(href).toMatch(/[?&]v=2\b/);

        // Click → reloads with v=2 cookie set.
        await Promise.all([
            page.waitForURL(/[?&]v=2\b/, { timeout: 5_000 }),
            pill.click()
        ]);

        // After reload, v2 dashboard component must be present.
        await expect(page.locator('[data-pcv2-component="dashboard"]')).toBeVisible({ timeout: 5_000 });
    });

    test('v2 dashboard renders all six cards after scan', async ({ page }) => {
        await page.context().clearCookies();
        await page.goto('/?v=2');
        await expect(page.locator('[data-pcv2-component="dashboard"]')).toBeVisible();

        // Trigger the scan.
        await page.click('[data-pcv2-action="start-scan"]');

        // Wait for the report region to appear (hidden attribute removed).
        await page.waitForSelector('[data-pcv2-region="report"]:not([hidden])', { timeout: 15_000 });

        // All six cards must be present and titled.
        const cardTitles = await page.evaluate(() => {
            const cards = Array.from(document.querySelectorAll('.pcv2__card'));
            return cards.map(c => {
                const h = c.querySelector('[data-pcv2-region="card-title"]');
                return { key: c.getAttribute('data-pcv2-card'), title: h ? h.textContent.trim() : '' };
            });
        });

        const expected = ['overview', 'connection', 'anonymity', 'dns', 'browser', 'security'];
        for (const key of expected) {
            const found = cardTitles.find(c => c.key === key);
            expect(found, 'card ' + key + ' must exist').toBeTruthy();
            expect(found.title.length, 'card ' + key + ' must have a title').toBeGreaterThan(0);
        }

        // Score gauge must show a numeric value 0..100.
        const score = await page.evaluate(() => {
            const v = document.querySelector('.pcv2__score-value');
            return v ? parseInt(v.textContent, 10) : null;
        });
        expect(score).not.toBeNull();
        expect(score).toBeGreaterThanOrEqual(0);
        expect(score).toBeLessThanOrEqual(100);
    });

    test('post-scan action bar shows Copy / Download / Share buttons', async ({ page }) => {
        await page.context().clearCookies();
        await page.goto('/?v=2');
        await page.click('[data-pcv2-action="start-scan"]');
        await page.waitForSelector('[data-pcv2-region="report"]:not([hidden])', { timeout: 15_000 });

        // All four buttons must be visible.
        await expect(page.locator('[data-pcv2-action="copy-json"]')).toBeVisible();
        await expect(page.locator('[data-pcv2-action="copy-summary"]')).toBeVisible();
        await expect(page.locator('[data-pcv2-action="download-json"]')).toBeVisible();
        await expect(page.locator('[data-pcv2-action="share-link"]')).toBeVisible();
    });

    test('theme toggle cycles Light → Dark → System and persists', async ({ page }) => {
        await page.context().clearCookies();
        await page.goto('/?v=2');
        await expect(page.locator('[data-pcv2-component="dashboard"]')).toBeVisible();

        const toggle = page.locator('.pcv2 [data-pcv2-action="theme-cycle"]').first();
        await expect(toggle).toBeVisible();

        // Default = system.
        let stored = await page.evaluate(() => localStorage.getItem('pcv2_theme'));
        // First cycle from default "system" → "light".
        await toggle.click();
        stored = await page.evaluate(() => localStorage.getItem('pcv2_theme'));
        expect(stored).toBe('light');
        await expect(page.locator('.pcv2')).toHaveAttribute('data-pcv2-theme', 'light');

        // Second cycle → dark.
        await toggle.click();
        stored = await page.evaluate(() => localStorage.getItem('pcv2_theme'));
        expect(stored).toBe('dark');
        await expect(page.locator('.pcv2')).toHaveAttribute('data-pcv2-theme', 'dark');

        // Third cycle → system.
        await toggle.click();
        stored = await page.evaluate(() => localStorage.getItem('pcv2_theme'));
        expect(stored).toBe('system');

        // Reload — persistence must survive.
        await page.reload();
        stored = await page.evaluate(() => localStorage.getItem('pcv2_theme'));
        expect(stored).toBe('system');
    });

    test('v2 honours prefers-reduced-motion when set', async ({ browser }) => {
        const context = await browser.newContext({ reducedMotion: 'reduce' });
        const page = await context.newPage();
        await page.context().clearCookies();
        await page.goto('/?v=2');
        await expect(page.locator('[data-pcv2-component="dashboard"]')).toBeVisible();
        // The reduced-motion CSS rule zeros transitions. We just assert
        // the page loaded without console errors.
        const errors = [];
        page.on('pageerror', e => errors.push(e.message));
        page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
        await page.click('[data-pcv2-action="start-scan"]');
        await page.waitForSelector('[data-pcv2-region="report"]:not([hidden])', { timeout: 15_000 });
        expect(errors.filter(e => !/favicon|404/.test(e))).toEqual([]);
        await context.close();
    });

    test('mobile viewport (375×812) renders dashboard without horizontal scroll', async ({ browser }) => {
        const context = await browser.newContext({ viewport: { width: 375, height: 812 } });
        const page = await context.newPage();
        await page.context().clearCookies();
        await page.goto('/?v=2');
        await expect(page.locator('[data-pcv2-component="dashboard"]')).toBeVisible();
        await page.click('[data-pcv2-action="start-scan"]');
        await page.waitForSelector('[data-pcv2-region="report"]:not([hidden])', { timeout: 15_000 });

        const overflows = await page.evaluate(() => {
            const docW = document.documentElement.clientWidth;
            const offenders = [];
            document.querySelectorAll('.pcv2 *').forEach(el => {
                const r = el.getBoundingClientRect();
                if (r.right > docW + 1) offenders.push({ tag: el.tagName, cls: el.className });
            });
            return { docW, offenders: offenders.slice(0, 5) };
        });
        expect(overflows.offenders).toEqual([]);
        await page.screenshot({ path: 'test-results/scanner-v2-mobile.png', fullPage: true });
        await context.close();
    });
});