// e2e/eli5-toggle.spec.js
//
// Regression tests for the "Explain Like I'm Five" toggle in the v2
// UI. When flipped on, the per-category labels on the Overview bar
// chart and the Privacy Findings list should switch from the
// technical dictionary ("IP", "DNS", "WebRTC") to the plain-language
// ELI5 dictionary ("Your Internet Address", "Who looks up websites
// for you", "Video-call leak risk").
//
// If this test starts failing, the toggle plumbing — prettySubLabel()
// reading PCV2.eli5Enabled, the data-pcv2-key stash on bar rows /
// findings / mini-cards, the localStorage persistence, or the
// reapplyEli5Labels() walker — has regressed.

const { test, expect } = require('@playwright/test');

const ELI5_LABELS = [
    'Your Internet Address',
    'Video-call leak risk',
    'How others see your address',
    'How unique your browser looks',
    'How visible your address is'
];

const TECHNICAL_LABELS = [
    'IP',
    'DNS',
    'WebRTC',
    'Reputation',
    'Fingerprint',
    'IP Exposure',
    'DNS Leak'
];

async function gotoV2(page) {
    await page.context().clearCookies();
    await page.goto('/?v=2');
    await page.waitForSelector('[data-pcv2-region="report"]:not([hidden])', { timeout: 15_000 });
    await page.waitForFunction(
        () => document.querySelectorAll('.pcv2__card').length === 6
           && Array.from(document.querySelectorAll('.pcv2__card [data-pcv2-region="card-title"]'))
                   .every(el => (el.textContent || '').trim().length > 0)
           && Array.from(document.querySelectorAll('.pcv2__card [data-pcv2-region="card-body"]'))
                   .every(el => el.children.length > 0),
        null,
        { timeout: 15_000 }
    );
}

async function getAllVisibleLabels(page) {
    return await page.evaluate(() => {
        const labels = [];
        document.querySelectorAll('.pcv2__bar-chart-label').forEach(el => {
            labels.push((el.textContent || '').trim());
        });
        document.querySelectorAll('.pcv2__finding-title').forEach(el => {
            // Title is "Label — NN / 100"; we only want the label half.
            const t = (el.textContent || '').trim();
            const cut = t.split(' — ');
            if (cut.length) labels.push(cut[0].trim());
        });
        document.querySelectorAll('.pcv2__mini-card-label').forEach(el => {
            labels.push((el.textContent || '').trim());
        });
        return labels;
    });
}

test.describe('ELI5 toggle (Phase 20)', () => {

    test('toggle button is present and starts in the technical (off) state', async ({ page }) => {
        await gotoV2(page);
        const btn = page.locator('.pcv2__eli5-toggle');
        await expect(btn).toBeVisible();
        await expect(btn).toHaveAttribute('aria-pressed', 'false');
        await expect(btn).toHaveText(/ELI5/);
        // Some technical label should be visible by default.
        const labels = await getAllVisibleLabels(page);
        const all = labels.join('|');
        const hasTechnical = TECHNICAL_LABELS.some(l => all.includes(l));
        expect(hasTechnical).toBe(true);
    });

    test('clicking the toggle switches labels to plain language and back', async ({ page }) => {
        await gotoV2(page);

        // Capture the technical baseline.
        const before = await getAllVisibleLabels(page);
        const technicalBefore = before.join('|');

        // Click the toggle.
        const btn = page.locator('.pcv2__eli5-toggle');
        await btn.click();
        await expect(btn).toHaveAttribute('aria-pressed', 'true');
        await expect(btn).toHaveText(/ELI5/);

        // Labels should now include the ELI5 plain-language entries
        // (and may or may not include the technical ones — depends on
        // overlap, but we require at least one ELI5 label).
        const after = await getAllVisibleLabels(page);
        const eli5After = after.join('|');
        const hasEli5 = ELI5_LABELS.some(l => eli5After.includes(l));
        expect(hasEli5).toBe(true);

        // At least one of the technical labels should have been
        // replaced — if not, the re-label walker is doing nothing.
        const technicalAfter = TECHNICAL_LABELS.filter(l => eli5After.includes(l));
        expect(technicalAfter.length).toBeLessThan(
            TECHNICAL_LABELS.filter(l => technicalBefore.includes(l)).length || 1
        );

        // Click again to restore.
        await btn.click();
        await expect(btn).toHaveAttribute('aria-pressed', 'false');
        const restored = await getAllVisibleLabels(page);
        // We don't require bitwise equality (scores may shift between
        // renders), but the technical labels should be back in place.
        const restoredText = restored.join('|');
        const hasTechnicalAgain = TECHNICAL_LABELS.some(l => restoredText.includes(l));
        expect(hasTechnicalAgain).toBe(true);
    });

    test('ELI5 preference persists across reloads via localStorage', async ({ page }) => {
        await gotoV2(page);

        // Flip the toggle on.
        const btn = page.locator('.pcv2__eli5-toggle');
        await btn.click();
        await expect(btn).toHaveAttribute('aria-pressed', 'true');

        // Confirm the storage key was written.
        const stored = await page.evaluate(() => window.localStorage.getItem('pcv2_eli5'));
        expect(stored).toBe('1');

        // Reload — autostart will run, the dashboard will re-render,
        // and the toggle should still be on.
        await page.reload();
        await page.waitForSelector('[data-pcv2-region="report"]:not([hidden])', { timeout: 15_000 });
        await page.waitForFunction(
            () => document.querySelectorAll('.pcv2__bar-chart-row').length > 0,
            null,
            { timeout: 15_000 }
        );
        const btnAfter = page.locator('.pcv2__eli5-toggle');
        await expect(btnAfter).toHaveAttribute('aria-pressed', 'true');
    });
});
