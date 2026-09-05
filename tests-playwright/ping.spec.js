// Ping / Latency page — smoke test for the ping component.

const { test, expect } = require( '@playwright/test' );

test.describe( 'Ping / Latency', () => {
	test.beforeEach( async ( { page } ) => {
		await page.goto( '/ping/' );
	} );

	test( 'clicking run populates a result or denial message', async ( { page } ) => {
		const runBtn = page.locator( 'button:has-text("Run Ping"), button:has-text("Run"), button[type="submit"]' ).first();
		await expect( runBtn ).toBeVisible( { timeout: 8_000 } );
		await runBtn.click();

		// Wait for either a latency row or a danger/denied status to appear.
		const dangerStatus = page.locator( '.pc-status--danger' ).first();
		const latencyRow = page.locator( '.pc-row:has-text("Latency")' ).first();

		const dangerVisible = await dangerStatus.isVisible( { timeout: 8_000 } ).catch( () => false );
		const latencyVisible = await latencyRow.isVisible( { timeout: 2_000 } ).catch( () => false );

		if ( dangerVisible ) {
			const dangerText = ( await dangerStatus.innerText() ).toLowerCase();
			expect( dangerText ).toMatch( /not allowed|denied|disabled|forbidden/ );
			return;
		}

		// Otherwise expect a latency value rendered as <number> ms.
		await expect( latencyRow ).toBeVisible( { timeout: 10_000 } );
		const text = await latencyRow.innerText();
		expect( text ).toMatch( /latency/i );
		expect( text ).toMatch( /\d+\s*ms/ );
	} );
} );
