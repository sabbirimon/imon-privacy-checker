const { test, expect } = require('@playwright/test');

test('debug: probe dark mode contrast on homepage', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });

    // Set dark theme via cookie/storage if available, or click the toggle.
    await page.goto('http://127.0.0.1:8080/', { waitUntil: 'load' });

    // Set dark theme via JS evaluation rather than click — the click handler
    // is on `document` and waits for a properly-rendered header.
    await page.evaluate(() => {
        document.documentElement.setAttribute('data-pc-theme', 'dark');
    });

    // Wait for the scan to render in dark mode.
    await page.waitForTimeout(4000);

    // Probe hero text contrast.
    const heroInfo = await page.evaluate(() => {
        function rgb(s) { return s; }
        function get(sel) {
            const el = document.querySelector(sel);
            if (!el) return { exists: false };
            const cs = window.getComputedStyle(el);
            return {
                exists: true,
                text: el.textContent.trim().substring(0, 100),
                color: cs.color,
                background: cs.backgroundColor,
                backgroundImage: cs.backgroundImage,
                fontSize: cs.fontSize,
            };
        }
        return {
            htmlTheme: document.documentElement.getAttribute('data-pc-theme'),
            hero: get('.pc-hero'),
            heroIp: get('.pc-hero__ip'),
            heroScoreNum: get('.pc-hero__score-num'),
            heroScoreSub: get('.pc-hero__score-sub'),
            disguiseMark: get('.pc-disguise__mark'),
            disguiseMarkSmall: get('.pc-disguise__mark small'),
        };
    });

    console.log('HTML theme attr:', heroInfo.htmlTheme);
    console.log('Hero:', JSON.stringify(heroInfo.hero, null, 2));
    console.log('Hero IP:', JSON.stringify(heroInfo.heroIp, null, 2));
    console.log('Hero ScoreNum:', JSON.stringify(heroInfo.heroScoreNum, null, 2));
    console.log('Hero ScoreSub:', JSON.stringify(heroInfo.heroScoreSub, null, 2));
    console.log('Disguise Mark:', JSON.stringify(heroInfo.disguiseMark, null, 2));
    console.log('Disguise Mark small:', JSON.stringify(heroInfo.disguiseMarkSmall, null, 2));

    await page.screenshot({ path: '/tmp/homepage-dark.png', fullPage: false });
});
