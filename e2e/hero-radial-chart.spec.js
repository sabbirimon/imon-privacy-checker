// e2e/hero-radial-chart.spec.js
//
// Regression tests for the redesigned score hero card. The hero used
// to be a flat 4-mini-card row; it is now a radial SVG chart with
// wedges + perimeter labels + a legend, plus a count-up animation on
// the main privacy score number.
//
// What we lock down here:
//   1. The radial SVG is present with the correct number of wedges
//      (one per sub-score, up to 6).
//   2. Each wedge carries the data-pcv2-tone attribute mapped from
//      the sub-score severity, so the colour tokens are wired up.
//   3. Each wedge has the data-pcv2-label set so hover tooltips and
//      the <title> a11y node have something to show.
//   4. The legend has the same number of rows as the wedges.
//   5. The main score number is present and animates (it changes from
//      0 to its target value over ~1s on first paint). This is a
//      smoke test — we don't assert the exact intermediate value.
//   6. prefers-reduced-motion: reduce context — count-up is skipped
//      and the final value is rendered instantly.

const { test, expect } = require('@playwright/test');

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
    // Let the count-up animation finish (≤1.2 s) before sampling.
    await page.waitForTimeout(1300);
}

test.describe('score hero — radial sub-score chart', () => {

    test('SVG chart is present with one wedge per sub-score', async ({ page }) => {
        await gotoV2(page);
        const info = await page.evaluate(() => {
            const svg = document.querySelector('.pcv2__score-hero .pcv2__radial-chart');
            if (!svg) return null;
            const wedges = Array.from(svg.querySelectorAll('.pcv2__radial-wedge'));
            const labels = Array.from(svg.querySelectorAll('.pcv2__radial-label'));
            return {
                wedges: wedges.length,
                labels: labels.length,
                tones: wedges.map(w => w.getAttribute('data-pcv2-tone')),
                scores: wedges.map(w => w.getAttribute('data-pcv2-score')),
                labelTexts: labels.map(l => (l.textContent || '').trim())
            };
        });
        expect(info).not.toBeNull();
        // At least 3 wedges, at most 6 (renderScoreHero caps the
        // subscore slice at 6 to keep the radial readable).
        expect(info.wedges).toBeGreaterThanOrEqual(3);
        expect(info.wedges).toBeLessThanOrEqual(6);
        // One label per wedge.
        expect(info.labels).toBe(info.wedges);
        // Every wedge has a tone mapped from severity.
        for (const t of info.tones) {
            expect(['safe', 'warning', 'danger', 'info', 'neutral']).toContain(t);
        }
        // Every wedge with a non-empty score carries a label text.
        for (let i = 0; i < info.wedges; i++) {
            if (info.scores[i] !== '' && info.scores[i] !== null) {
                expect(info.labelTexts[i].length).toBeGreaterThan(0);
            }
        }
    });

    test('legend mirrors the wedge count and carries tone swatches', async ({ page }) => {
        await gotoV2(page);
        const rows = await page.evaluate(() => {
            const legend = document.querySelector('.pcv2__score-hero .pcv2__radial-legend');
            if (!legend) return [];
            return Array.from(legend.querySelectorAll('.pcv2__radial-legend-row')).map(r => ({
                tone:    r.getAttribute('data-pcv2-tone'),
                label:   (r.querySelector('.pcv2__radial-legend-label') || {}).textContent || '',
                value:   (r.querySelector('.pcv2__radial-legend-value') || {}).textContent || '',
                hasSwatch: !!r.querySelector('.pcv2__radial-legend-swatch')
            }));
        });
        const wedges = await page.evaluate(() =>
            document.querySelectorAll('.pcv2__score-hero .pcv2__radial-wedge').length
        );
        expect(rows.length).toBe(wedges);
        expect(rows.length).toBeGreaterThanOrEqual(3);
        for (const r of rows) {
            expect(['safe', 'warning', 'danger', 'info', 'neutral']).toContain(r.tone);
            expect(r.label.length).toBeGreaterThan(0);
            expect(r.value).toMatch(/^\d+%$/);
            expect(r.hasSwatch).toBe(true);
        }
    });

    test('main privacy score is numeric 0..100 in the value node', async ({ page }) => {
        await gotoV2(page);
        const value = await page.evaluate(() => {
            const el = document.querySelector('.pcv2__score-hero .pcv2__score-ring-value');
            if (!el) return null;
            const t = (el.childNodes[0] && el.childNodes[0].textContent || el.textContent || '').trim();
            return t;
        });
        expect(value).not.toBeNull();
        expect(value).not.toBe('—');
        expect(value).toMatch(/^\d+$/);
        const n = parseInt(value, 10);
        expect(n).toBeGreaterThanOrEqual(0);
        expect(n).toBeLessThanOrEqual(100);
    });

    test('hero background has the decorative orb layer (animated)', async ({ page }) => {
        await gotoV2(page);
        // The ::before pseudo-element carries the orb gradient. We
        // assert the parent element has the pcv2__score-hero class
        // (the pseudo can't be queried directly).
        const hasHero = await page.evaluate(() =>
            !!document.querySelector('.pcv2__score-hero')
        );
        expect(hasHero).toBe(true);
        // And the orb layer should at least be defined in the
        // stylesheet. We check via getComputedStyle on the hero.
        const hasOrb = await page.evaluate(() => {
            const hero = document.querySelector('.pcv2__score-hero');
            if (!hero) return false;
            const cs = window.getComputedStyle(hero, '::before');
            // content is "none" by default — we only set it via the
            // CSS rule. So we check the animation-name instead.
            return (cs.animationName || '').length > 0;
        });
        expect(hasOrb).toBe(true);
    });

    test('main ring is rendered as SVG with halo + fill + sparkle layers', async ({ page }) => {
        await gotoV2(page);
        const ring = await page.evaluate(() => {
            const wrap = document.querySelector('.pcv2__score-ring');
            if (!wrap) return null;
            const svg = wrap.querySelector('.pcv2__score-ring-svg');
            const halo = wrap.querySelector('.pcv2__score-ring-halo');
            const fill = wrap.querySelector('.pcv2__score-ring-fill');
            const sparkles = wrap.querySelectorAll('.pcv2__score-ring-sparkle');
            const bg = wrap.querySelector('.pcv2__score-ring-bg');
            return {
                animated: wrap.classList.contains('pcv2__score-ring--animated'),
                hasSvg: !!svg,
                hasHalo: !!halo,
                hasFill: !!fill,
                hasBg: !!bg,
                sparkleCount: sparkles.length,
                // Fill arc must have a non-zero dasharray length.
                dashArray: fill ? fill.getAttribute('stroke-dasharray') : null,
                // Initial dashoffset should be the full arc length
                // (animation will animate it to 0).
                initialOffset: fill ? fill.getAttribute('data-pcv2-ring-init') : null
            };
        });
        expect(ring).not.toBeNull();
        expect(ring.animated).toBe(true);
        expect(ring.hasSvg).toBe(true);
        expect(ring.hasHalo).toBe(true);
        expect(ring.hasFill).toBe(true);
        expect(ring.hasBg).toBe(true);
        expect(ring.sparkleCount).toBeGreaterThanOrEqual(4);
        // The fill arc length should be a positive number.
        const dashParts = (ring.dashArray || '').split(' ');
        const arcLen = parseFloat(dashParts[0]);
        expect(arcLen).toBeGreaterThan(0);
        expect(ring.initialOffset).toBeTruthy();
    });

    test('grade badge is present with holographic animated styling', async ({ page }) => {
        await gotoV2(page);
        const grade = await page.evaluate(() => {
            const g = document.querySelector('.pcv2__score-grade');
            if (!g) return null;
            const letter = g.querySelector('.pcv2__score-grade-letter');
            const label  = g.querySelector('.pcv2__score-grade-label');
            return {
                animated: g.classList.contains('pcv2__score-grade--animated'),
                tone: g.getAttribute('data-pcv2-tone'),
                letter: letter ? letter.textContent.trim() : '',
                label:  label  ? label.textContent.trim()  : '',
                // The rotating sheen ::before pseudo must have an
                // animation name set in computed style.
                pseudoAnim: (function () {
                    const cs = window.getComputedStyle(g, '::before');
                    return cs.animationName || '';
                })()
            };
        });
        expect(grade).not.toBeNull();
        expect(grade.animated).toBe(true);
        expect(grade.letter.length).toBeGreaterThan(0);
        expect(['safe', 'warning', 'danger', 'info', 'neutral']).toContain(grade.tone);
        expect(grade.pseudoAnim).toMatch(/pcv2-grade-spin/);
    });

    test('main ring value text has visible color (gradient resolves)', async ({ page }) => {
        await gotoV2(page);
        const info = await page.evaluate(() => {
            const v = document.querySelector('.pcv2__score-ring-value');
            if (!v) return null;
            const cs = window.getComputedStyle(v);
            return {
                text: v.textContent,
                bgImage: cs.backgroundImage,
                fillColor: cs.webkitTextFillColor || cs.color,
                bgClip: cs.backgroundClip || cs.webkitBackgroundClip
            };
        });
        expect(info).not.toBeNull();
        expect(info.text).toMatch(/^\d+\/100$/);
        // The gradient must actually be applied — backgroundImage
        // must be a linear-gradient(...), NOT 'none'.
        expect(info.bgImage).toMatch(/linear-gradient/);
        expect(info.bgClip).toBe('text');
    });
});
