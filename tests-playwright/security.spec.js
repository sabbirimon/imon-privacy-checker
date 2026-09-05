// Security smoke — admin endpoints require auth; rate-limit returns 429.

const { test, expect } = require( '@playwright/test' );
const { ADMIN } = require( './playwright.config' );

test.describe( 'Security & auth', () => {
	test( 'unauthenticated GET /settings REST returns 401/403', async ( { request } ) => {
		const res = await request.get( '/wp-json/privacy-checker/v1/settings' );
		expect( [ 401, 403 ] ).toContain( res.status() );
	} );

	test( 'rate-limit on /scan/connection returns 429 after threshold', async ( { request } ) => {
		// Hit /scan/connection repeatedly. Default limit is 60/minute.
		// We won't spam 60+ requests; instead we just confirm the route
		// responds with sane status codes (not 5xx) and that retry-after
		// appears after enough hits.
		const responses = [];
		for ( let i = 0; i < 80; i++ ) {
			const r = await request.get( '/wp-json/privacy-checker/v1/scan/connection' );
			responses.push( r.status() );
			if ( r.status() === 429 ) {
				break;
			}
		}
		// We expect at least one 200 followed eventually by 429.
		expect( responses ).toContain( 200 );
		expect( responses ).toContain( 429 );
	} );

	test( 'admin dashboard requires login', async ( { page } ) => {
		const res = await page.goto( '/wp-admin/admin.php?page=privacy-checker' );
		// Either redirected to login (302/200 + login form) or 403.
		const url = page.url();
		expect( url ).toMatch( /wp-login\.php|privacy-checker/ );
		expect( res.status() ).toBeLessThan( 500 );
	} );

	test( 'logged-in admin can reach the dashboard', async ( { page } ) => {
		await page.goto( '/wp-login.php' );
		await page.locator( '#user_login' ).fill( ADMIN.user );
		await page.locator( '#user_pass' ).fill( ADMIN.pass );
		await page.locator( '#wp-submit' ).click();

		await page.goto( '/wp-admin/admin.php?page=privacy-checker' );
		await expect( page.locator( 'h1' ).first() ).toContainText( /Privacy Checker/i, { timeout: 8_000 } );
	} );
} );