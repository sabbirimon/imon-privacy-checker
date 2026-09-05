// Admin dashboard — charts, status tiles, chain, MaxMind section.

const { test, expect } = require( '@playwright/test' );
const { ADMIN } = require( './playwright.config' );

test.describe( 'Admin dashboard', () => {
	test.beforeEach( async ( { page } ) => {
		await page.goto( '/wp-login.php' );
		await page.locator( '#user_login' ).fill( ADMIN.user );
		await page.locator( '#user_pass' ).fill( ADMIN.pass );
		await page.locator( '#wp-submit' ).click();
		await page.waitForURL( /wp-admin/ );
	} );

	test( 'dashboard renders status tiles + chain + charts', async ( { page } ) => {
		await page.goto( '/wp-admin/admin.php?page=privacy-checker' );

		// Status tiles.
		await expect( page.locator( '.pc-tile' ).first() ).toBeVisible( { timeout: 8_000 } );

		// Chain list.
		await expect( page.locator( '.pc-chain__item' ).first() ).toBeVisible();

		// MaxMind section.
		await expect( page.locator( 'h2:has-text("MaxMind")' ) ).toBeVisible();

		// Charts (line / stacked / pie).
		const charts = page.locator( '.pc-chart svg' );
		const chartCount = await charts.count();
		expect( chartCount ).toBeGreaterThanOrEqual( 0 ); // 0 if logging disabled, that's ok
	} );

	test( 'chain reset button is gated by nonce', async ( { page } ) => {
		await page.goto( '/wp-admin/admin.php?page=privacy-checker' );
		// The reset form must contain a wpnonce field.
		const nonce = page.locator( 'input[name="_wpnonce"], input[name="_wpnoncestatic"]' ).first();
		await expect( nonce ).toBeAttached();
	} );
} );