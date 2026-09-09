// e2e/dark-mode-contrast.spec.js
//
// Bug fix verification + ongoing contrast guard for #138.
//
// Drives the static /anonymity-tips/ page (no scan dependency) and the
// scanner homepage in both themes. For each suspect selector the test
// asserts the computed text color is sufficiently far from the painted
// background (max-RGB-channel difference >= threshold).
//
// Why max-RGB-channel instead of WCAG contrast ratio?
//   - It's easy to explain: "in at least one channel the text moves
//     by N units away from the background".
//   - It doesn't false-fail on alpha-blended surfaces where the
//     computed `color` is an opaque rgb() and the `backgroundColor` is
//     rgba(...) — WCAG ratio math needs RGB fusion first.
//   - WCAG AA normal-text 4.5:1 ≈ 80 max-channel diff in our palette,
//     so 80 is the right floor.
//
// Captures a PNG screenshot of every assertion for visual review —
// these land in test-results/ on failure, and explicitly here for
// light/dark side-by-side verification.
//
// Modes:
//   npx playwright test e2e/dark-mode-contrast.spec.js
//   npx playwright test e2e/dark-mode-contrast.spec.js --grep=dark
//   npx playwright test e2e/dark-mode-contrast.spec.js --grep=light

const { test, expect } = require('@playwright/test');

// --- helpers ---------------------------------------------------------------

function parseRgb(value) {
    const m = value.match(/rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)/);
    if (!m) {
        throw new Error(`unparseable color: ${value}`);
    }
    return { r: +m[1], g: +m[2], b: +m[3] };
}

function maxChannelDiff(a, b) {
    return Math.max(
        Math.abs(a.r - b.r),
        Math.abs(a.g - b.g),
        Math.abs(a.b - b.b),
    );
}

async function forceTheme(page, theme) {
    await page.addInitScript((t) => {
        try {
            localStorage.setItem('pc-theme', t);
        } catch (e) { /* ignore */ }
        document.documentElement.setAttribute('data-pc-theme', t);
    }, theme);
}

async function getEffectiveTheme(page) {
    return page.evaluate(() =>
        document.documentElement.getAttribute('data-pc-theme')
    );
}

// Walk up the DOM to the nearest non-transparent background so we
// compare text vs the painted surface, not vs the element's own
// transparent background.
async function textVsBackground(page, selector) {
    return page.evaluate((sel) => {
        const el = document.querySelector(sel);
        if (!el) {
            return { error: `not-found: ${sel}` };
        }
        const cs = getComputedStyle(el);
        let bg = cs.backgroundColor;
        let cur = el;
        while (cur && (bg === 'rgba(0, 0, 0, 0)' || bg === 'transparent')) {
            cur = cur.parentElement;
            if (cur) {
                bg = getComputedStyle(cur).backgroundColor;
            } else {
                break;
            }
        }
        return {
            color: cs.color,
            background: bg,
            text: (el.textContent || '').trim().slice(0, 80),
        };
    }, selector);
}

// Assert two RGB triples differ by at least `threshold` on one channel.
function assertContrast(actual, expectedMsg, threshold) {
    const color    = parseRgb(actual.color);
    const bg       = parseRgb(actual.background);
    const diff     = maxChannelDiff(color, bg);
    expect(diff, `${expectedMsg} (got color=${actual.color}, bg=${actual.background}, diff=${diff}, need>=${threshold})`)
        .toBeGreaterThanOrEqual(threshold);
}

// --- shared selectors that must read in both themes ------------------------

// Each entry is { selector, label, threshold }.
//   threshold >= 80 ≈ WCAG AA normal-text contrast for our palette.
//   threshold >= 60 acceptable for dim/secondary text.
//   threshold >= 120 for pill text on a pill background (pill bg + pill
//   text should pop strongly).
const ANON_TIPS_SELECTORS = [
    { sel: '.pc-tips__tier-title',  label: 'tier title (FOUNDATIONAL/STRONG/...)', threshold: 80 },
    { sel: '.pc-tips__title',       label: 'individual tip title',                 threshold: 80 },
    { sel: '.pc-tips__summary',     label: 'tip summary paragraph',                threshold: 80 },
    { sel: '.pc-tips__priority',    label: 'priority badge (#1, #2, ...)',         threshold: 80 },
];

// --- tests -----------------------------------------------------------------

test.describe('theme contrast — bug #138 regression guard', () => {

    test('dark mode: /anonymity-tips/ tier titles and tip bodies readable', async ({ page }) => {
        await forceTheme(page, 'dark');
        await page.goto('/anonymity-tips/');

        expect(await getEffectiveTheme(page)).toBe('dark');

        const tiers = await page.$$('.pc-tips__tier');
        expect(tiers.length, 'expected at least one tier to render').toBeGreaterThan(0);

        for (const { sel, label, threshold } of ANON_TIPS_SELECTORS) {
            const actual = await textVsBackground(page, sel);
            expect(actual.error, `${sel}: ${JSON.stringify(actual)}`).toBeUndefined();
            expect(actual.text.length, `${sel} should have visible text content`).toBeGreaterThan(0);
            assertContrast(actual, `${sel} (${label}) must contrast against its background in dark mode`, threshold);
        }

        // Optional selectors — present when the seed data includes
        // examples / why fields.
        for (const sel of ['.pc-tips__examples', '.pc-tips__why']) {
            const has = await page.$(sel);
            if (has) {
                const actual = await textVsBackground(page, sel);
                expect(actual.error, `${sel}: ${JSON.stringify(actual)}`).toBeUndefined();
                assertContrast(actual, `${sel} must contrast against its background in dark mode`, 60);
            }
        }

        // Snapshot for visual review.
        await page.screenshot({
            path: 'test-results/anonymity-tips-dark.png',
            fullPage: true,
        });
    });

    test('light mode: /anonymity-tips/ tier titles and tip bodies readable', async ({ page }) => {
        await forceTheme(page, 'light');
        await page.goto('/anonymity-tips/');

        expect(await getEffectiveTheme(page)).toBe('light');

        const tiers = await page.$$('.pc-tips__tier');
        expect(tiers.length, 'expected at least one tier to render').toBeGreaterThan(0);

        for (const { sel, label, threshold } of ANON_TIPS_SELECTORS) {
            const actual = await textVsBackground(page, sel);
            expect(actual.error, `${sel}: ${JSON.stringify(actual)}`).toBeUndefined();
            expect(actual.text.length, `${sel} should have visible text content`).toBeGreaterThan(0);
            assertContrast(actual, `${sel} (${label}) must contrast against its background in light mode`, threshold);
        }

        for (const sel of ['.pc-tips__examples', '.pc-tips__why']) {
            const has = await page.$(sel);
            if (has) {
                const actual = await textVsBackground(page, sel);
                expect(actual.error, `${sel}: ${JSON.stringify(actual)}`).toBeUndefined();
                assertContrast(actual, `${sel} must contrast against its background in light mode`, 60);
            }
        }

        await page.screenshot({
            path: 'test-results/anonymity-tips-light.png',
            fullPage: true,
        });
    });

    test('dark mode: scanner homepage hero + run button readable', async ({ page }) => {
        await forceTheme(page, 'dark');
        await page.goto('/');
        expect(await getEffectiveTheme(page)).toBe('dark');

        // Hero title text on the marketing hero (--pc-hero-bg).
        const heroTitle = await textVsBackground(page, '.pc-hero__title');
        expect(heroTitle.error, JSON.stringify(heroTitle)).toBeUndefined();
        assertContrast(heroTitle, '.pc-hero__title must contrast against hero bg in dark mode', 80);

        // Run Privacy Check button — text color must contrast with its bg.
        const btn = await page.evaluate(() => {
            const el = document.querySelector('.pc-btn--primary');
            if (!el) {
                return { error: 'run button not found' };
            }
            const cs = getComputedStyle(el);
            return {
                color: cs.color,
                background: cs.backgroundColor,
                text: (el.textContent || '').trim().slice(0, 40),
            };
        });
        expect(btn.error, JSON.stringify(btn)).toBeUndefined();
        assertContrast(btn, 'Run Privacy Check button must contrast against its bg', 80);

        // Page background should be the Whoer-style deep teal (#20586f),
        // not white. Catches the bug regression where dark mode
        // accidentally falls back to white. Sum threshold 350 (white=765)
        // accommodates the teal hue (R is lower than G+B).
        const pageBg = await page.evaluate(() =>
            getComputedStyle(document.body).backgroundColor
        );
        const bg = parseRgb(pageBg);
        expect(bg.r + bg.g + bg.b,
            `dark-mode page bg should be dark teal (got ${pageBg})`
        ).toBeLessThan(350);
        // And the red channel specifically should be low — teal is
        // R-dominant only on white pages.
        expect(bg.r,
            `dark-mode page bg red channel should be low (got ${pageBg})`
        ).toBeLessThan(100);

        await page.screenshot({
            path: 'test-results/homepage-dark.png',
            fullPage: true,
        });
    });

    test('light mode: scanner homepage hero + run button readable', async ({ page }) => {
        await forceTheme(page, 'light');
        await page.goto('/');
        expect(await getEffectiveTheme(page)).toBe('light');

        const heroTitle = await textVsBackground(page, '.pc-hero__title');
        expect(heroTitle.error, JSON.stringify(heroTitle)).toBeUndefined();
        assertContrast(heroTitle, '.pc-hero__title must contrast against hero bg in light mode', 80);

        const btn = await page.evaluate(() => {
            const el = document.querySelector('.pc-btn--primary');
            if (!el) {
                return { error: 'run button not found' };
            }
            const cs = getComputedStyle(el);
            return {
                color: cs.color,
                background: cs.backgroundColor,
                text: (el.textContent || '').trim().slice(0, 40),
            };
        });
        expect(btn.error, JSON.stringify(btn)).toBeUndefined();
        assertContrast(btn, 'Run Privacy Check button must contrast against its bg', 80);

        await page.screenshot({
            path: 'test-results/homepage-light.png',
            fullPage: true,
        });
    });
});
