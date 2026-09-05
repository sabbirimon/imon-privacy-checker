// IP lookup page — submits a known public IP and expects a populated result.

const { test, expect } = require( '@playwright/test' );

test.describe( 'IP lookup', () => {
	test( 'submitting 1.1.1.1 returns a country', async ( { page } ) => {
		await page.goto( '/ip-lookup/' );

		const input = page.locator( 'input[name="ip"], input[type="text"]' ).first();
		await input.fill( '1.1.1.1' );

		const submit = page.locator( 'button[type="submit"], button:has-text("Lookup")' ).first();
		await submit.click();

		// The result area should render within 8s.
		const result = page.locator( '.pc-result, [data-pc-result], #pc-result' ).first();
		await expect( result ).toBeVisible( { timeout: 8_000 } );
		const text = await result.innerText();
		expect( text.toLowerCase() ).toMatch( /country|united states|australia|cloudflare/ );
	} );

	test( 'private IP is rejected', async ( { page } ) => {
		await page.goto( '/ip-lookup/' );

		const input = page.locator( 'input[name="ip"], input[type="text"]' ).first();
		await input.fill( '10.0.0.5' );

		const submit = page.locator( 'button[type="submit"], button:has-text("Lookup")' ).first();
		await submit.click();

		const error = page.locator( '.pc-error, [data-pc-error], .pc-notice--error' ).first();
		await expect( error ).toBeVisible( { timeout: 5_000 } );
	} );
} );
