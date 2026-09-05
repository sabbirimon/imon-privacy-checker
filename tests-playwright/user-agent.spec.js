// User-Agent parser page — submits a UA and expects a populated browser row.

const { test, expect } = require( '@playwright/test' );

test.describe( 'User-Agent parser', () => {
	test( 'Chrome UA yields browser=Chrome', async ( { page } ) => {
		await page.goto( '/user-agent/' );

		const input = page.locator( 'input[name="ua"], input[name="q"], textarea[name="ua"]' ).first();
		await input.fill( 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36' );

		const submit = page.locator( 'button[type="submit"], button:has-text("Parse")' ).first();
		await submit.click();

		const browserRow = page.locator( ':text("Browser"), [data-pc-field="browser"]' ).first();
		await expect( browserRow ).toBeVisible( { timeout: 5_000 } );
		// Either the page displays "Chrome" or the row contains a browser
		// label whose value (sibling cell) is Chrome.
		const text = await page.locator( 'body' ).innerText();
		expect( text ).toContain( 'Chrome' );
	} );
} );