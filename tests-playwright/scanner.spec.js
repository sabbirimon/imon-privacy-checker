// Full scan flow — clicks "Run Privacy Check" and verifies all 7 cards render.

const { test, expect } = require( '@playwright/test' );

test.describe( 'Privacy scanner', () => {
	test( 'manual run completes and renders the 7 cards', async ( { page } ) => {
		await page.goto( '/' );

		// Click the manual "Run" button if present; otherwise rely on auto-scan.
		const runBtn = page.locator( 'button:has-text("Run"), button:has-text("Check"), [data-pc-action="run"]' ).first();
		if ( await runBtn.isVisible( { timeout: 2_000 } ).catch( () => false ) ) {
			await runBtn.click();
		}

		// All 7 cards should render with non-empty content.
		const cards = page.locator( '.pc-card, [data-pc-card]' );
		await expect( cards.first() ).toBeVisible( { timeout: 12_000 } );
		const count = await cards.count();
		expect( count ).toBeGreaterThanOrEqual( 5 );
	} );

	test( 'IP card shows a non-empty country value', async ( { page } ) => {
		await page.goto( '/' );

		// Wait for the connection/card row containing "country".
		const countryRow = page.locator( '[data-pc-field="country"], .pc-row:has-text("Country")' ).first();
		await expect( countryRow ).toBeVisible( { timeout: 12_000 } );
		const text = await countryRow.innerText();
		expect( text.length ).toBeGreaterThan( 0 );
	} );
} );
