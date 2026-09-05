const { test } = require('@playwright/test');

test('inspect dark via matchMedia', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto('http://127.0.0.1:8080/', { waitUntil: 'networkidle' });
    // Set attribute BEFORE stylesheet (won't work either way).
    await page.evaluate(() => {
        document.documentElement.setAttribute('data-pc-theme', 'dark');
    });
    // Force re-evaluation by listing stylesheets
    const matches = await page.evaluate(() => {
        // Check whether the selector exists in any stylesheet.
        const sheets = Array.from(document.styleSheets);
        const found = [];
        for (const s of sheets) {
            try {
                const rules = s.cssRules || [];
                for (const r of rules) {
                    if (r.cssText && r.cssText.includes('pc-theme')) {
                        found.push(r.cssText.slice(0, 200));
                    }
                }
            } catch (e) { found.push('cors:' + e.message); }
        }
        const matchesDark = document.documentElement.matches(':root[data-pc-theme="dark"]');
        return { found: found.slice(0, 6), matchesDark };
    });
    console.log(JSON.stringify(matches, null, 2));
});
