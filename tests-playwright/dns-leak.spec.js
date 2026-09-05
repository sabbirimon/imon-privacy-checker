// DNS leak test page — smoke test for the DNS leak component.

const { test, expect } = require( '@playwright/test' );

test.describe( 'DNS leak test', () => {
	test.beforeEach( async ( { page } ) => {
		await page.goto( '/dns-leak-test/' );
	} );

	test( 'clicking the run button populates a result', async ( { page } ) => {
		const component = page.locator( '[data-pc-component="dns-test"]' );
		await expect( component ).toBeVisible( { timeout: 8_000 } );

		const runBtn = component.locator( 'button.pc-btn--primary' );
		await expect( runBtn ).toBeVisible();
		await runBtn.click();

		// Wait for the result region to populate.
		const result = component.locator( '[data-pc-region="result"]' );
		await expect( result ).toBeVisible( { timeout: 12_000 } );
		const text = await result.innerText();
		expect( text.trim().length ).toBeGreaterThan( 0 );

		// Either a warning/danger status is shown (unconfigured / unreachable),
		// or a results table with at least one row is rendered.
		const warningOrDanger = component.locator( '.pc-status--warning, .pc-status--danger' ).first();
		const table = component.locator( '.pc-table' ).first();

		const warnVisible = await warningOrDanger.isVisible( { timeout: 2_000 } ).catch( () => false );
		if ( warnVisible ) {
			const warnText = await warningOrDanger.innerText();
			expect( warnText.length ).toBeGreaterThan( 0 );
			return;
		}

		await expect( table ).toBeVisible( { timeout: 4_000 } );
		const rows = component.locator( '.pc-table tr' );
		const rowCount = await rows.count();
		expect( rowCount ).toBeGreaterThan( 0 );
	} );
} );
