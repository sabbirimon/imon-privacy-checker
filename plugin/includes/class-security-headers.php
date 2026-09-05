<?php
/**
 * Security-headers checker.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Inspect the security-relevant HTTP response headers of a remote site.
 *
 * Hardened against SSRF by Security::validate_remote_url() and an internal
 * redirect-revalidation pass.
 */
final class SecurityHeaders {

    /**
     * Headers we evaluate, with their recommended baseline value.
     *
     * @var array<string,string>
     */
    private const EXPECTED = array(
        'content-security-policy'   => 'Recommended. Restrict sources of executable content.',
        'strict-transport-security' => 'Recommended. Force HTTPS for returning visitors.',
        'x-content-type-options'    => 'Recommended. Disables MIME-type sniffing.',
        'referrer-policy'           => 'Recommended. Controls how much Referer is shared.',
        'permissions-policy'        => 'Optional. Restrict browser feature use.',
        'x-frame-options'           => 'Optional. Anti-clickjacking fallback.',
    );

    /**
     * @param string $url User-supplied URL.
     * @return array<string,mixed>
     */
    public static function check( string $url ): array {
        $validation = Security::validate_remote_url( $url );
        if ( ! $validation['valid'] ) {
            return array(
                'status' => 'error',
                'url'    => $url,
                'error'  => $validation['error'] ?: 'Invalid URL.',
            );
        }

        $target = $validation['normalized'];

        $response = wp_remote_get(
            $target,
            array(
                'timeout'    => 8,
                'redirection'=> 3,
                'user-agent' => 'PrivacyChecker/' . PRIVACY_CHECKER_VERSION . ' (Security Headers Check)',
                'sslverify'  => true,
            )
        );

        if ( is_wp_error( $response ) ) {
            return array(
                'status' => 'error',
                'url'    => $target,
                'error'  => $response->get_error_message(),
            );
        }

        $redirected_to = (string) wp_remote_retrieve_header( $response, 'Location' );
        if ( '' !== $redirected_to && ! Security::is_safe_redirect_target( $redirected_to ) ) {
            return array(
                'status' => 'error',
                'url'    => $target,
                'error'  => 'Redirect target rejected by SSRF guard.',
            );
        }

        $headers = wp_remote_retrieve_headers( $response );
        $header_array = array();
        if ( is_object( $headers ) && method_exists( $headers, 'getAll' ) ) {
            $header_array = $headers->getAll();
        } elseif ( is_array( $headers ) ) {
            $header_array = $headers;
        }

        $normalized = array();
        foreach ( $header_array as $name => $value ) {
            $normalized[ strtolower( (string) $name ) ] = is_array( $value ) ? implode( ', ', $value ) : (string) $value;
        }

        $report = array();
        foreach ( self::EXPECTED as $name => $description ) {
            $value = $normalized[ $name ] ?? null;
            $verdict = self::verdict( $name, $value );
            $report[] = array(
                'header'     => $name,
                'value'      => $value,
                'verdict'    => $verdict,
                'description'=> $description,
            );
        }

        return array(
            'status'      => 'ok',
            'url'         => $target,
            'http_status' => (int) wp_remote_retrieve_response_code( $response ),
            'headers'     => $report,
        );
    }

    /**
     * Score a single header value.
     */
    private static function verdict( string $name, ?string $value ): string {
        if ( null === $value || '' === $value ) {
            return 'missing';
        }
        $lower = strtolower( $value );
        switch ( $name ) {
            case 'strict-transport-security':
                return strpos( $lower, 'max-age' ) !== false ? 'good' : 'weak';
            case 'x-content-type-options':
                return strpos( $lower, 'nosniff' ) !== false ? 'good' : 'weak';
            case 'x-frame-options':
                if ( in_array( $lower, array( 'deny', 'sameorigin' ), true ) ) {
                    return 'good';
                }
                return 'weak';
            case 'content-security-policy':
                return strpos( $lower, 'default-src' ) !== false || strpos( $lower, 'script-src' ) !== false ? 'good' : 'weak';
            case 'referrer-policy':
                return in_array( $lower, array( 'no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin' ), true ) ? 'good' : 'weak';
            case 'permissions-policy':
                return strpos( $lower, '=' ) !== false ? 'good' : 'weak';
            default:
                return 'unknown';
        }
    }
}