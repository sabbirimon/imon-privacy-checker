// WHOIS lookup page — submits a known domain and expects a registrar result.

const { test, expect } = require( '@playwright/test' );

test.describe( 'WHOIS lookup', () => {
	test( 'submitting example.com returns registrar info', async ( { page } ) => {
		await page.goto( '/whois/' );

		const input = page.locator( 'input[name="domain"], input[name="q"], input[type="text"]' ).first();
		await input.fill( 'example.com' );

		const submit = page.locator( 'button[type="submit"], button:has-text("Lookup")' ).first();
		await submit.click();

		const result = page.locator( '.pc-result, [data-pc-result]' ).first();
		await expect( result ).toBeVisible( { timeout: 8_000 } );
		const text = ( await result.innerText() ).toLowerCase();
		expect( text ).toMatch( /registrar|registry|created|status|domain/ );
	} );
} );