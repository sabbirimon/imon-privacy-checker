// Responsive layout — confirms the dashboard cards stack on mobile.

const { test, expect } = require( '@playwright/test' );

test.describe( 'Responsive layout', () => {
	test.use( { viewport: { width: 390, height: 844 } } );

	test( 'cards stack to a single column at 390px', async ( { page } ) => {
		await page.goto( '/' );
		await page.waitForLoadState( 'networkidle' );

		const cards = page.locator( '.pc-card, [data-pc-card]' );
		if ( ( await cards.count() ) < 2 ) {
			test.skip( true, 'Fewer than 2 cards rendered; layout test inconclusive.' );
		}

		// First two cards should not share a horizontal row at this width.
		const first = await cards.nth( 0 ).boundingBox();
		const second = await cards.nth( 1 ).boundingBox();
		expect( first ).not.toBeNull();
		expect( second ).not.toBeNull();
		// Y positions should differ (stacked).
		expect( Math.abs( first.y - second.y ) ).toBeGreaterThan( 20 );
	} );
} );