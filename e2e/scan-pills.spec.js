// e2e/scan-pills.spec.js — capture scan pill status after running a scan.

const { test } = require('@playwright/test');

test('scan pill status', async ({ page }) => {
    await page.goto('/');
    await page.click('a[data-pc-action="start-scan"]');
    await page.waitForSelector('.pc-dash-cols', { timeout: 12_000 });
    await page.waitForTimeout(800);

    const pills = await page.evaluate(() => {
        return Array.from(document.querySelectorAll('.pc-steps .pc-step')).map((step) => {
            return {
                label: (step.textContent || '').trim(),
                classes: step.className,
                isDone:   step.classList.contains('is-done'),
                isError:  step.classList.contains('is-error'),
                isActive: step.classList.contains('is-active'),
            };
        });
    });
    console.log('SCAN PILL STATUS:');
    for (const p of pills) {
        const status = p.isDone ? 'DONE' : p.isError ? 'ERROR' : p.isActive ? 'ACTIVE' : 'PENDING';
        console.log(`  [${status}] ${p.label}`);
    }

    // Crop just the pill strip area
    const steps = await page.$('.pc-steps');
    if (steps) {
        await steps.screenshot({ path: 'test-results/scan-pills.png' });
    }
});
