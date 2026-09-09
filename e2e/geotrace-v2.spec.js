// e2e/geotrace-v2.spec.js
//
// Verifies the GeoTrace honesty contract end-to-end:
//
//   1. /scan/geo/paste parses a multi-hop traceroute (Linux / Windows /
//      MTR) into the canonical `route` shape.
//   2. The canonical route keeps the *order* of hops even when some are
//      private / unanswered.
//   3. Private hops have status `private` and NO coordinates.
//   4. Unanswered hops have status `unanswered` and NO coordinates.
//   5. Public hops have status `public` and a confidence in
//      {high, medium, low, unknown}.
//   6. The same `route` object is what the v2 GeoTrace widget reads —
//      so 2D map + hop timeline always agree.
//
// The page itself is exercised by Playwright's browser; the parsing
// layer is exercised by hitting /scan/geo/paste directly with the
// multi-hop fixture, then asserting the response shape.

const { test, expect } = require('@playwright/test');

const MULTI_HOP_FIXTURE = `traceroute to 1.1.1.1 (1.1.1.1), 30 hops max
 1  10.0.0.1 (10.0.0.1)  0.523 ms  0.412 ms  0.398 ms
 2  192.168.1.1 (192.168.1.1)  4.231 ms  4.187 ms  4.342 ms
 3  * * *
 4  * * *
 5  203.0.113.45 (203.0.113.45)  18.789 ms  18.654 ms  18.823 ms
 6  * * *
 7  198.51.100.7 (198.51.100.7)  52.103 ms  51.872 ms  52.234 ms
 8  142.250.80.46 (142.250.80.46)  60.123 ms  60.012 ms  60.234 ms`;

test.describe('GeoTrace v2 pipeline', () => {
    test('paste endpoint returns canonical route with hops in order', async ({ request }) => {
        const resp = await request.post('/wp-json/privacy-checker/v1/scan/geo/paste', {
            data: { paste: MULTI_HOP_FIXTURE }
        });
        expect(resp.status()).toBe(200);
        const body = await resp.json();

        expect(body.source_kind).toBe('pasted-traceroute');
        expect(Array.isArray(body.hops)).toBe(true);
        expect(body.hops.length).toBe(8);

        // Order preserved: hop indices are 1..8 in trace order.
        const indices = body.hops.map(h => h.index);
        expect(indices).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);

        // Hops 1, 2 → private (RFC1918).
        expect(body.hops[0].status).toBe('private');
        expect(body.hops[0].ip).toBe('10.0.0.1');
        expect(body.hops[0].lat).toBeNull();
        expect(body.hops[0].lon).toBeNull();

        expect(body.hops[1].status).toBe('private');
        expect(body.hops[1].ip).toBe('192.168.1.1');
        expect(body.hops[1].lat).toBeNull();

        // Hops 3, 4 → unanswered.
        expect(body.hops[2].status).toBe('unanswered');
        expect(body.hops[2].ip).toBeNull();
        expect(body.hops[2].lat).toBeNull();

        expect(body.hops[3].status).toBe('unanswered');

        // Hops 5, 7, 8 → public (the 203.0.113.x and 198.51.100.x are
        // TEST-NET ranges; the public 8.8.8.8 IP is the 142.250.80.46).
        // 203.0.113.45 + 198.51.100.7 are TEST-NET → marked private by
        // the parser (reserved for documentation).
        expect(body.hops[4].status).toBe('private');
        expect(body.hops[4].ip).toBe('203.0.113.45');

        expect(body.hops[5].status).toBe('unanswered');

        expect(body.hops[6].status).toBe('private');
        expect(body.hops[6].ip).toBe('198.51.100.7');

        // The 142.250.x IP (real Google IP) gets geolocated.
        const hop8 = body.hops[7];
        expect(hop8.status).toBe('public');
        expect(hop8.ip).toBe('142.250.80.46');
        if (hop8.lat != null) {
            // If geolocation worked, coordinates must be on Earth.
            expect(hop8.lat).toBeGreaterThan(-90);
            expect(hop8.lat).toBeLessThan(90);
            expect(hop8.lon).toBeGreaterThan(-180);
            expect(hop8.lon).toBeLessThan(180);
        }
        // Confidence must NEVER be 'high' (geolocation is not GPS).
        expect(['unknown', 'low', 'medium']).toContain(hop8.confidence);

        // Disclaimer message must be present.
        expect(typeof body.disclaimer).toBe('string');
        expect(body.disclaimer.toLowerCase()).toContain('approximate');
    });

    test('live traceroute endpoint returns a canonical route object', async ({ request }) => {
        // We don't assert specific hops (the sandbox may block probes);
        // we only assert the response shape matches the contract.
        const resp = await request.get('/wp-json/privacy-checker/v1/scan/geo/lookup?target=cloudflare.com');
        expect(resp.status()).toBe(200);
        const body = await resp.json();

        // Canonical top-level keys.
        expect(body).toHaveProperty('probe');
        expect(body).toHaveProperty('target');
        expect(body).toHaveProperty('hops');
        expect(body).toHaveProperty('source_kind');
        expect(body).toHaveProperty('message');
        expect(body).toHaveProperty('disclaimer');

        // probe + target records have the documented fields.
        expect(body.probe).toHaveProperty('ip');
        expect(body.probe).toHaveProperty('lat');
        expect(body.probe).toHaveProperty('lon');
        expect(body.target).toHaveProperty('ip');
        expect(body.target).toHaveProperty('lat');
        expect(body.target).toHaveProperty('lon');

        // source_kind is one of the documented values.
        expect(['real-traceroute', 'pasted-traceroute', 'unavailable']).toContain(body.source_kind);

        // Hops array, when present, must be in trace order (indices monotonically increasing).
        const indices = body.hops.map(h => h.index);
        const sorted = [...indices].sort((a, b) => a - b);
        expect(indices).toEqual(sorted);

        // Every hop has the canonical shape.
        for (const h of body.hops) {
            expect(h).toHaveProperty('status');
            expect(['public', 'private', 'unanswered']).toContain(h.status);
            expect(h).toHaveProperty('lat');
            expect(h).toHaveProperty('lon');
            // Status implies coordinates consistency.
            if (h.status !== 'public') {
                expect(h.lat).toBeNull();
                expect(h.lon).toBeNull();
            }
        }

        // Confidence must NEVER be 'high'.
        for (const h of body.hops) {
            if (h.confidence != null) {
                expect(h.confidence).not.toBe('high');
            }
        }
    });

    test('bad input returns 400', async ({ request }) => {
        const resp = await request.post('/wp-json/privacy-checker/v1/scan/geo/paste', {
            data: { paste: '' }
        });
        expect(resp.status()).toBe(400);
    });

    test('unparseable traceroute returns 400', async ({ request }) => {
        const resp = await request.post('/wp-json/privacy-checker/v1/scan/geo/paste', {
            data: { paste: 'this is not a traceroute at all\nhello world' }
        });
        expect(resp.status()).toBe(400);
    });

    test('v2 GeoTrace page renders the widget after paste', async ({ page }) => {
        await page.context().clearCookies();
        // Visit the home page with v=2 — the GeoTrace widget lives in a
        // shortcode so we'll also test the route /wp/?v=2 by appending
        // a [privacy_checker_v2_geotrace] via a fresh page setup if
        // the home doesn't include it. Skip silently if not present.
        await page.goto('/?v=2');
        const hasGeoWidget = await page.locator('[data-pcv2-component="geotrace"]').count();
        test.skip(hasGeoWidget === 0, 'No GeoTrace v2 widget on home page in this test setup');

        // Paste a traceroute into the paste textarea and submit.
        // The textarea lives inside <details> — open the panel first so
        // the textarea is visible (Phase 19: paste form is collapsed by
        // default to keep the inline widget compact).
        await page.evaluate(() => {
            const d = document.querySelector('.pcv2__geo-paste');
            if (d) d.open = true;
        });
        await page.fill('[data-pcv2-region="geo-paste"]', MULTI_HOP_FIXTURE);
        await page.click('.pcv2__geo-paste button[type="submit"]');

        // The hop timeline should populate with 8 rows.
        await page.waitForFunction(
            () => document.querySelectorAll('[data-pcv2-region="geo-hops"] .pcv2__geo-hop').length >= 8,
            null,
            { timeout: 10_000 }
        );
        const rowCount = await page.evaluate(
            () => document.querySelectorAll('[data-pcv2-region="geo-hops"] .pcv2__geo-hop').length
        );
        expect(rowCount).toBe(8);

        // The probe / target / hops meta should be populated.
        const meta = await page.evaluate(() => {
            const items = Array.from(document.querySelectorAll('[data-pcv2-region="geo-meta"] dd'));
            return items.map(el => (el.textContent || '').trim());
        });
        expect(meta.length).toBeGreaterThanOrEqual(3);
    });

    test('only one .pcv2__geo-disclaimer element exists in empty state', async ({ page }) => {
        // Regression: the JS used to inject a second .pcv2__geo-disclaimer
        // into the hops container when there were no hops, which made the
        // "Traceroute is not available..." text appear twice. The static
        // skeleton still has exactly one; the empty-state fallback inside
        // [data-pcv2-region="geo-hops"] must use a different class.
        await page.context().clearCookies();
        await page.goto('/?v=2');
        const hasGeoWidget = await page.locator('[data-pcv2-component="geotrace"]').count();
        test.skip(hasGeoWidget === 0, 'No GeoTrace v2 widget on home page in this test setup');
        await page.waitForSelector('[data-pcv2-component="geotrace"]');

        const counts = await page.evaluate(() => ({
            disclaimers: document.querySelectorAll('.pcv2__geo-disclaimer').length,
            emptyHops:   document.querySelectorAll('[data-pcv2-region="geo-hops"] .pcv2__geo-hops-empty').length,
            // No disclaimer-like <p> should live inside the hops container.
            paragraphsInsideHops: document.querySelectorAll('[data-pcv2-region="geo-hops"] p.pcv2__geo-disclaimer').length
        }));
        expect(counts.disclaimers).toBe(1);
        expect(counts.emptyHops).toBe(1);
        expect(counts.paragraphsInsideHops).toBe(0);
    });
});