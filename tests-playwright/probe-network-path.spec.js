const { test } = require('@playwright/test');

test('debug: probe homepage network path card', async ({ page }) => {
    await page.goto('http://127.0.0.1:8080/', { waitUntil: 'load' });
    await page.waitForTimeout(4000); // wait for scan to finish

    const info = await page.evaluate(() => {
        const region = document.querySelector('[data-pc-component="dashboard"] [data-pc-region="report"]');
        const networkCard = document.querySelector('.pc-network');
        const mapCard = document.querySelector('.pc-map-card');
        const hopListItems = document.querySelectorAll('.pc-map__hop');
        const networkHops = document.querySelectorAll('.pc-network__hop');
        return {
            networkCardExists: !!networkCard,
            networkCardClass: networkCard ? networkCard.className : null,
            networkCardInnerLen: networkCard ? networkCard.innerHTML.length : 0,
            networkCardSnip: networkCard ? networkCard.innerHTML.substring(0, 800) : null,
            mapCardExists: !!mapCard,
            mapCardInnerLen: mapCard ? mapCard.innerHTML.length : 0,
            hopListCount: hopListItems.length,
            hopFirstRowInner: hopListItems[0] ? hopListItems[0].innerHTML.substring(0, 500) : null,
            networkHopCount: networkHops.length,
            regionChildren: region ? region.children.length : 0,
        };
    });
    console.log(JSON.stringify(info, null, 2));
});
