// e2e/scanner-cards.spec.js
//
// Verifies the IP ADDRESS / CONNECTION DETAILS / BROWSER FINGERPRINT
// cards render after a scan. Forces the correct siteurl origin
// (127.0.0.1, matching the WP DB siteurl) so CORS doesn't block the
// scan API.

const { test, expect } = require('@playwright/test');

test.describe('scanner cards render', () => {
    test('after scan, dashboard shows IP ADDRESS + CONNECTION DETAILS cards', async ({ page }) => {
        await page.goto('/');
        // The Run Privacy Check element is an <a> tag in the marketing hero.
        await page.click('a[data-pc-action="start-scan"]', { timeout: 5000 });
        // Wait up to 12s for the cards to render. Allow warning banner.
        await page.waitForSelector('.pc-dash-cols', { timeout: 12_000 });

        const cards = await page.evaluate(() => {
            const titles = Array.from(document.querySelectorAll('.pc-card__title'))
                .map(t => (t.textContent || '').trim());
            const hasIpCard     = titles.includes('IP ADDRESS');
            const hasConnCard   = titles.includes('CONNECTION DETAILS');
            const hasProxyCard  = titles.includes('PROXY / VPN / TOR') || titles.includes('Proxy / VPN / Tor / Hosting');
            const hasFPCard     = titles.some(t => t.toLowerCase().includes('fingerprint'));
            const hasCols       = !!document.querySelector('.pc-dash-cols');
            return { hasCols, hasIpCard, hasConnCard, hasProxyCard, hasFPCard, titles };
        });

        console.log('rendered card titles:', cards.titles);
        expect(cards.hasCols,    'two-column grid must be present').toBe(true);
        expect(cards.hasIpCard,  'IP ADDRESS card must render').toBe(true);
        expect(cards.hasConnCard,'CONNECTION DETAILS card must render').toBe(true);
        expect(cards.hasFPCard,  'BROWSER FINGERPRINT card must render').toBe(true);

        await page.screenshot({ path: 'test-results/scanner-cards-light.png', fullPage: true });
    });
});
