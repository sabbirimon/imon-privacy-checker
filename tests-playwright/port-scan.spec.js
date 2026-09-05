// Port Scan page — smoke test for allowed host and SSH denylist rejection.

const { test, expect } = require( '@playwright/test' );

test.describe( 'Port Scan', () => {
	test.beforeEach( async ( { page } ) => {
		await page.goto( '/port-scan/' );
	} );

	async function submitScan( page, host, port ) {
		const hostInput = page.locator( 'input[name="host"], input[name="ip"], input[name="target"], input[type="text"]' ).first();
		await hostInput.fill( host );

		const portInput = page.locator( 'input[name="port"]' ).first();
		if ( await portInput.isVisible( { timeout: 2_000 } ).catch( () => false ) ) {
			await portInput.fill( String( port ) );
		}

		const submit = page.locator( 'button[type="submit"], button:has-text("Scan"), button:has-text("Run")' ).first();
		await submit.click();
	}

	test( 'self host (127.0.0.1:8080) returns a status or denial', async ( { page } ) => {
		await submitScan( page, '127.0.0.1', 8080 );

		// Either a port status (Open / Closed / Filtered) or a denial message.
		const status = page.locator( '.pc-status, [data-pc-status], .pc-result, [data-pc-result]' ).first();
		await expect( status ).toBeVisible( { timeout: 12_000 } );

		const text = ( await status.innerText() ).toLowerCase();
		expect( text ).toMatch( /open|closed|filtered|denied|allowed|reachable|unreachable|not allowed/ );
	} );

	test( 'localhost port 22 is denied (SSH denylist)', async ( { page } ) => {
		await submitScan( page, '127.0.0.1', 22 );

		const danger = page.locator( '.pc-status--danger, .pc-error, .pc-notice--error, [data-pc-error]' ).first();
		await expect( danger ).toBeVisible( { timeout: 8_000 } );

		const text = ( await danger.innerText() ).toLowerCase();
		expect( text ).toMatch( /denied|not allowed|forbidden|blocked/ );
	} );
} );
