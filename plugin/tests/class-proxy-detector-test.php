<?php
/**
 * Tests for PrivacyChecker\ProxyDetector::classify().
 *
 * Covers the curated ASN catalog and the organization/ISP substring token
 * table, including the residential / datacenter / hosting / vpn / proxy /
 * tor fallthroughs and the empty-input safety net.
 *
 * @package PrivacyChecker\Tests
 */

declare( strict_types=1 );

namespace PrivacyChecker\Tests;

use PrivacyChecker\ProxyDetector;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

final class ProxyDetectorTest extends TestCase {

	protected function set_up(): void {
		parent::set_up();
		\WpState::reset();
	}

	public function test_classify_mullvad_asn(): void {
		$out = ProxyDetector::classify( array(
			'asn' => 'AS212238',
			'org' => 'Mullvad VPN',
		) );
		$this->assertSame( 'vpn', $out['category'] );
		$this->assertSame( 'Mullvad VPN', $out['vendor'] );
		$this->assertSame( 'high', $out['confidence'] );
		$this->assertStringContainsString( 'VPN', $out['label'] );
		$this->assertGreaterThanOrEqual( 85, (int) $out['score'] );
	}

	public function test_classify_protonvpn_asn(): void {
		$out = ProxyDetector::classify( array(
			'asn' => 'AS57630',
			'org' => 'Proton AG',
		) );
		$this->assertSame( 'vpn', $out['category'] );
		$this->assertSame( 'ProtonVPN', $out['vendor'] );
		$this->assertSame( 'high', $out['confidence'] );
		$this->assertGreaterThanOrEqual( 85, (int) $out['score'] );
	}

	public function test_classify_aws_asn(): void {
		$out = ProxyDetector::classify( array(
			'asn' => 'AS16509',
			'org' => 'Amazon.com',
		) );
		$this->assertSame( 'datacenter', $out['category'] );
		$this->assertSame( 'Amazon AWS', $out['vendor'] );
		$this->assertSame( 'high', $out['confidence'] );
		$this->assertGreaterThanOrEqual( 55, (int) $out['score'] );
	}

	public function test_classify_google_cloud_asn(): void {
		$out = ProxyDetector::classify( array(
			'asn' => 'AS15169',
			'org' => 'Google LLC',
		) );
		$this->assertSame( 'datacenter', $out['category'] );
		$this->assertSame( 'Google Cloud', $out['vendor'] );
		$this->assertSame( 'high', $out['confidence'] );
	}

	public function test_classify_hetzner_asn(): void {
		$out = ProxyDetector::classify( array(
			'asn' => 'AS24940',
			'org' => 'Hetzner Online GmbH',
		) );
		$this->assertSame( 'hosting', $out['category'] );
		$this->assertSame( 'Hetzner', $out['vendor'] );
		$this->assertSame( 'high', $out['confidence'] );
	}

	public function test_classify_org_only_hosting_token_is_hosting(): void {
		// "hosting" is in the generic-datacenter-signals list, so the
		// detector matches it as `hosting` with low confidence. Specific
		// vendors (Hetzner, OVH, ...) get medium confidence via ORG_TOKENS.
		$out = ProxyDetector::classify( array(
			'asn' => '',
			'org' => 'Foo Bar Hosting LLC',
		) );
		$this->assertSame( 'hosting', $out['category'] );
		$this->assertSame( 'low', $out['confidence'] );
		$this->assertSame( 'Generic hosting', $out['vendor'] );
	}

	public function test_classify_random_isp_is_residential_low(): void {
		$out = ProxyDetector::classify( array(
			'asn' => 'AS99999',
			'org' => 'Some random ISP',
		) );
		$this->assertSame( 'residential', $out['category'] );
		$this->assertSame( 'low', $out['confidence'] );
		$this->assertSame( 0, (int) $out['score'] );
	}

	public function test_classify_tor_exit_relay(): void {
		$out = ProxyDetector::classify( array(
			'asn' => '',
			'org' => 'Tor exit relay something',
		) );
		$this->assertSame( 'tor', $out['category'] );
		$this->assertSame( 'Tor exit relay', $out['label'] );
		$this->assertSame( 100, (int) $out['score'] );
	}

	public function test_classify_empty_input_does_not_throw(): void {
		$out = ProxyDetector::classify( array() );
		$this->assertIsArray( $out );
		// Empty intel falls back to residential + low confidence.
		$this->assertSame( 'residential', $out['category'] );
		$this->assertSame( 'low', $out['confidence'] );
		// Shape contract.
		$this->assertArrayHasKey( 'vendor', $out );
		$this->assertArrayHasKey( 'label', $out );
		$this->assertArrayHasKey( 'reasons', $out );
		$this->assertArrayHasKey( 'score', $out );
		$this->assertIsArray( $out['reasons'] );
	}

	public function test_classify_proxy_vendor_high_score(): void {
		$out = ProxyDetector::classify( array(
			'asn' => '',
			'org' => 'Bright Data Ltd',
		) );
		$this->assertSame( 'proxy', $out['category'] );
		$this->assertGreaterThanOrEqual( 90, (int) $out['score'] );
	}
}
