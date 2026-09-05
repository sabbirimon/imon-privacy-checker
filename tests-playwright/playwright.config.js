// Playwright config — Privacy Checker e2e tests.

const { defineConfig, devices } = require( '@playwright/test' );

const BASE_URL = process.env.BASE_URL || 'http://localhost:8080';
const ADMIN_USER = process.env.PC_ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.PC_ADMIN_PASS || 'admin';

module.exports = defineConfig( {
	testDir: __dirname,
	timeout: 30_000,
	expect: { timeout: 8_000 },
	fullyParallel: false,
	retries: 0,
	reporter: [ [ 'list' ] ],
	use: {
		baseURL: BASE_URL,
		trace: 'retain-on-failure',
		screenshot: 'only-on-failure',
		video: 'retain-on-failure',
		actionTimeout: 8_000,
	},
	projects: [
		{
			name: 'chromium',
			use: {
				...devices[ 'Desktop Chrome' ],
				viewport: { width: 1440, height: 900 },
			},
		},
		{
			name: 'chromium-tablet',
			use: {
				...devices[ 'Desktop Chrome' ],
				viewport: { width: 768, height: 1024 },
			},
		},
		{
			name: 'chromium-mobile',
			use: {
				...devices[ 'Desktop Chrome' ],
				viewport: { width: 390, height: 844 },
			},
		},
	],
} );

// Make credentials accessible to specs that need to log in.
module.exports.ADMIN = { user: ADMIN_USER, pass: ADMIN_PASS };
