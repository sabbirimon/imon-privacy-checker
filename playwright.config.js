// Playwright config — local dark-mode contrast test.
// Single-project (chromium), single-worker, single-baseURL against the
// local WP install at http://localhost:8080.

const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
    testDir: './e2e',
    timeout: 60_000,
    expect: { timeout: 5_000 },
    fullyParallel: false,
    workers: 1,
    reporter: [['list']],
    use: {
        baseURL: 'http://localhost:8080',
        headless: true,
        viewport: { width: 1280, height: 800 },
        // No screenshots / videos on success — we only capture on failure.
        screenshot: 'only-on-failure',
        video: 'retain-on-failure',
        trace: 'retain-on-failure',
    },
});
