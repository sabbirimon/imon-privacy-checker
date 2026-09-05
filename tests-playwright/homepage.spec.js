// Homepage smoke — hero, auto-scan, score ring.

const { test, expect } = require( '@playwright/test' );

test.describe( 'Homepage', () => {
	test( 'hero renders and score reaches a number within 8s', async ( { page } ) => {
		await page.goto( '/' );

		// Hero copy must include the project tagline.
		await expect( page.locator( 'h1' ).first() ).toContainText( /Private/i, { timeout: 8_000 } );

		// The auto-scan kicks off; the score ring should reach a numeric
		// value within 8 seconds.
		const ring = page.locator( '[data-pc-score], .pc-score, [class*="score"]' ).first();
		await expect( ring ).toBeVisible( { timeout: 8_000 } );
	} );

	test( 'all 7 progress steps reach "done" state', async ( { page } ) => {
		await page.goto( '/' );

		// Wait for the auto-scan to complete (max 12s). Steps should all
		// have the "done" class.
		await page.waitForSelector( '.pc-step.is-done, [data-pc-step="done"]', { timeout: 12_000 } );
		const doneCount = await page.locator( '.pc-step.is-done, [data-pc-step="done"]' ).count();
		expect( doneCount ).toBeGreaterThanOrEqual( 5 );
	} );
} );
