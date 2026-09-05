<?php
/**
 * Mock reputation provider.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker\Providers;

use PrivacyChecker\Provider\ReputationProviderInterface;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

final class MockReputationProvider implements ReputationProviderInterface {

    public function key(): string {
        return 'mock';
    }

    public function label(): string {
        return 'Mock (Development)';
    }

    public function check( string $ip ): array {
        return array(
            'status'   => 'unknown',
            'ip'       => $ip,
            'provider' => $this->key(),
            'is_mock'  => true,
            'sources'  => array(
                array(
                    'source' => 'mock-dnsbl',
                    'listed' => false,
                    'detail' => null,
                ),
            ),
            'note'     => 'DEVELOPMENT DATA — configure a real reputation provider for production.',
        );
    }
}