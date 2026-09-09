// e2e/scan-exact-trace.spec.js
// Captures the EXACT response body of every /scan* endpoint that the
// browser sees during a real scan run, so we can identify what causes
// "Something went wrong".

const { test } = require('@playwright/test');

test('scan exact trace', async ({ page }) => {
    const calls = [];

    page.on('request', async (req) => {
        if (req.url().includes('/wp-json/privacy-checker/v1/scan')) {
            calls.push({
                phase: 'req',
                method: req.method(),
                url: req.url(),
                postData: req.postData() ? req.postData().slice(0, 200) : null,
            });
        }
    });

    page.on('response', async (resp) => {
        if (resp.url().includes('/wp-json/privacy-checker/v1/scan')) {
            let body = '';
            try { body = (await resp.text()).slice(0, 600); } catch (e) {}
            calls.push({
                phase: 'resp',
                method: resp.request().method(),
                status: resp.status(),
                url: resp.url(),
                ok: resp.ok(),
                body,
            });
        }
    });

    page.on('pageerror', (err) => {
        console.log('!!! PAGE ERROR:', err.message.slice(0, 300));
    });

    page.on('console', (msg) => {
        if (msg.type() === 'error') {
            console.log('[console error]', msg.text().slice(0, 300));
        }
    });

    await page.goto('/');
    await page.click('a[data-pc-action="start-scan"]');
    await page.waitForTimeout(8000);

    console.log('\n=== SCAN API CALLS (request → response) ===\n');
    for (const c of calls) {
        if (c.phase === 'req') {
            const data = c.postData ? ` body=${c.postData}` : '';
            console.log(`> ${c.method} ${c.url}${data}`);
        } else {
            const tag = c.ok ? '✓' : '✗';
            console.log(`< ${tag} ${c.status} ${c.url}`);
            console.log(`     ${c.body.replace(/\s+/g, ' ').slice(0, 300)}`);
        }
    }

    // Final state: error banner or cards?
    const state = await page.evaluate(() => {
        const errCard = Array.from(document.querySelectorAll('.pc-card__title'))
            .find(t => (t.textContent || '').trim() === 'Something went wrong');
        const cols = document.querySelector('.pc-dash-cols');
        return {
            hasErrorCard: !!errCard,
            hasTwoColumnGrid: !!cols,
            cardTitles: Array.from(document.querySelectorAll('.pc-card__title'))
                .map(t => (t.textContent || '').trim()),
        };
    });
    console.log('\n=== FINAL PAGE STATE ===');
    console.log('  hasErrorCard:', state.hasErrorCard);
    console.log('  hasTwoColumnGrid:', state.hasTwoColumnGrid);
    console.log('  cardTitles:', state.cardTitles);
});
