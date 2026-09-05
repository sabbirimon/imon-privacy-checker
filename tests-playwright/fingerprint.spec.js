// Fingerprint page — confirms the scanner UI + visibility score.

const { test, expect } = require( '@playwright/test' );

test.describe( 'Fingerprint page', () => {
	test( 'page loads and shows the scanner', async ( { page } ) => {
		await page.goto( '/fingerprint/' );

		// Either the auto-scan starts and the score ring renders, or the
		// page shows the "Run" button. Both are acceptable.
		const ring = page.locator( '[data-pc-score], .pc-score' ).first();
		const runBtn = page.locator( 'button:has-text("Run")' ).first();

		const ringVisible = await ring.isVisible( { timeout: 8_000 } ).catch( () => false );
		const btnVisible = await runBtn.isVisible( { timeout: 2_000 } ).catch( () => false );
		expect( ringVisible || btnVisible ).toBe( true );
	} );
} );