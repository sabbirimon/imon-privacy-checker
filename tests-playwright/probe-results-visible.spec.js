const { test, expect } = require('@playwright/test');

test('debug: verify result region populates and is visible on IP Lookup', async ({ page }) => {
    await page.goto('http://127.0.0.1:8080/ip-lookup/', { waitUntil: 'load' });
    await page.waitForTimeout(1000);

    await page.fill('[data-pc-component="ip-lookup"] input[name="ip"]', '8.8.8.8');
    await page.locator('[data-pc-component="ip-lookup"] form[data-pc-action="ip-lookup"] button[type="submit"]').first().click({ force: true });
    await page.waitForTimeout(3000);

    const result = await page.evaluate(() => {
        const sec = document.querySelector('[data-pc-component="ip-lookup"]');
        const r = sec ? sec.querySelector('[data-pc-region="result"]') : null;
        const styles = r ? window.getComputedStyle(r) : null;
        return {
            resultExists: !!r,
            resultHidden: r ? r.hidden : null,
            display: styles ? styles.display : null,
            visibility: styles ? styles.visibility : null,
            innerHtmlLen: r ? r.innerHTML.length : 0,
            innerTextSnippet: r ? r.innerText.substring(0, 400) : null,
        };
    });
    console.log('Result region:', JSON.stringify(result, null, 2));
});

test('debug: verify result region populates and is visible on WHOIS', async ({ page }) => {
    await page.goto('http://127.0.0.1:8080/whois/', { waitUntil: 'load' });
    await page.waitForTimeout(1000);

    await page.fill('[data-pc-component="whois"] input[name="query"]', 'example.com');
    await page.locator('[data-pc-component="whois"] form[data-pc-action="whois"] button[type="submit"]').first().click({ force: true });
    await page.waitForTimeout(3000);

    const result = await page.evaluate(() => {
        const sec = document.querySelector('[data-pc-component="whois"]');
        const r = sec ? sec.querySelector('[data-pc-region="result"]') : null;
        return {
            resultExists: !!r,
            resultHidden: r ? r.hidden : null,
            innerHtmlLen: r ? r.innerHTML.length : 0,
            innerTextSnippet: r ? r.innerText.substring(0, 400) : null,
        };
    });
    console.log('Result region:', JSON.stringify(result, null, 2));
});
