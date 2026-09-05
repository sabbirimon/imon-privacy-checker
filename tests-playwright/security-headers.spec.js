// Security-headers probe — happy path + SSRF rejection.

const { test, expect } = require( '@playwright/test' );

test.describe( 'Security-headers probe', () => {
	test( 'public URL returns ok', async ( { page } ) => {
		await page.goto( '/security-headers/' );

		const input = page.locator( 'input[name="url"]' ).first();
		await input.fill( 'https://example.com' );

		const submit = page.locator( 'button[type="submit"], button:has-text("Scan")' ).first();
		await submit.click();

		const result = page.locator( '.pc-result, [data-pc-result]' ).first();
		await expect( result ).toBeVisible( { timeout: 12_000 } );
	} );

	test( 'localhost is rejected (SSRF guard)', async ( { page } ) => {
		await page.goto( '/security-headers/' );

		const input = page.locator( 'input[name="url"]' ).first();
		await input.fill( 'http://localhost/' );

		const submit = page.locator( 'button[type="submit"], button:has-text("Scan")' ).first();
		await submit.click();

		const error = page.locator( '.pc-error, .pc-notice--error, [data-pc-error]' ).first();
		await expect( error ).toBeVisible( { timeout: 5_000 } );
	} );

	test( 'private IP 10.0.0.1 is rejected', async ( { page } ) => {
		await page.goto( '/security-headers/' );

		const input = page.locator( 'input[name="url"]' ).first();
		await input.fill( 'http://10.0.0.1/' );

		const submit = page.locator( 'button[type="submit"], button:has-text("Scan")' ).first();
		await submit.click();

		const error = page.locator( '.pc-error, .pc-notice--error, [data-pc-error]' ).first();
		await expect( error ).toBeVisible( { timeout: 5_000 } );
	} );
} );