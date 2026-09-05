<?php
/**
 * TlsInfo — reports the TLS protocol version and cipher suite negotiated
 * for the CURRENT incoming request.
 *
 * Different web servers expose this under different $_SERVER keys. This
 * class checks them in a well-known order and returns an explicit
 * "unknown" status when none are present — never guesses.
 *
 * Common server-specific keys (in the order we check):
 *   - Apache / mod_ssl:                SSL_PROTOCOL, SSL_CIPHER
 *   - nginx (via fastcgi_param) — admin typically adds:
 *         fastcgi_param HTTPS_TLS_VERSION $ssl_protocol;
 *         fastcgi_param HTTPS_TLS_CIPHER   $ssl_cipher;
 *     which surfaces here as HTTPS_TLS_VERSION / HTTPS_TLS_CIPHER. We
 *     also accept HTTPS_TLS_CIPHERS (plural, nginx 1.23+ sometimes uses
 *     this for the negotiated suite).
 *   - LiteSpeed: SSL_PROTOCOL / SSL_CIPHER (same as Apache).
 *   - Some reverse proxies: SSL_PROTOCOL / SSL_CIPHER forwarded from
 *     the proxy via X-Forwarded-* headers — we DO NOT trust those here
 *     because they're trivially spoofable; this class reports only what
 *     the web server saw on the local socket.
 *
 * If the visitor's request did not arrive over TLS at all (plain HTTP,
 * or behind a TLS-terminating proxy that didn't forward the
 * handshake info), every key is empty → status 'unknown', and the UI
 * shows a "TLS info not available — server may be behind a proxy"
 * message rather than a misleading "no TLS".
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

final class TlsInfo {

    /**
     * Ordered list of $_SERVER keys we consult for the TLS protocol.
     * First non-empty match wins.
     *
     * @var array<int,string>
     */
    private const PROTOCOL_KEYS = array(
        'SSL_PROTOCOL',         // Apache mod_ssl, LiteSpeed.
        'HTTPS_TLS_VERSION',    // nginx via fastcgi_param.
        'TLS_VERSION',          // some proxies.
    );

    /**
     * Ordered list of $_SERVER keys we consult for the negotiated cipher.
     *
     * @var array<int,string>
     */
    private const CIPHER_KEYS = array(
        'SSL_CIPHER',           // Apache mod_ssl, LiteSpeed.
        'HTTPS_TLS_CIPHER',     // nginx via fastcgi_param.
        'HTTPS_TLS_CIPHERS',    // nginx 1.23+ sometimes plural.
        'TLS_CIPHER',           // some proxies.
    );

    /**
     * Set of protocol strings we recognise as "current" TLS.
     * TLS 1.2 is "acceptable" (still widely supported, not in
     * immediate danger); anything older is "outdated".
     *
     * @var array<int,string>
     */
    private const CURRENT_PROTOCOLS = array( 'TLSv1.3' );

    /**
     * Report TLS info for the current request. Returns a structured
     * array — never throws, never reads from outside $_SERVER.
     *
     * @return array{status:string, protocol:string, cipher:string, note:string}
     *   - status:   'modern' | 'acceptable' | 'outdated' | 'unknown'
     *   - protocol: the raw protocol string (e.g. "TLSv1.3") or '' if unknown
     *   - cipher:   the raw cipher string (e.g. "TLS_AES_128_GCM_SHA256") or ''
     *   - note:     human-readable one-liner about why status is what it is
     */
    public static function current_request_info(): array {
        $protocol = self::first_nonempty( self::PROTOCOL_KEYS );
        $cipher   = self::first_nonempty( self::CIPHER_KEYS );

        if ( '' === $protocol ) {
            return array(
                'status'   => 'unknown',
                'protocol' => '',
                'cipher'   => $cipher,
                'note'     => __( 'TLS info not available — server may be behind a reverse proxy that did not forward the handshake data.', 'privacy-checker' ),
            );
        }

        $status = self::classify_protocol( $protocol );

        // Build a contextual note. We don't claim "secure" if the protocol
        // is older than TLS 1.2; we don't claim "insecure" for TLS 1.0
        // without mentioning it can still be acceptable for legacy clients.
        switch ( $status ) {
            case 'modern':
                $note = sprintf(
                    /* translators: %s: TLS protocol version, e.g. "TLSv1.3" */
                    __( '%s is current and recommended.', 'privacy-checker' ),
                    $protocol
                );
                break;
            case 'acceptable':
                $note = sprintf(
                    /* translators: %s: TLS protocol version, e.g. "TLSv1.2" */
                    __( '%s is acceptable but older than the latest version.', 'privacy-checker' ),
                    $protocol
                );
                break;
            case 'outdated':
                $note = sprintf(
                    /* translators: %s: TLS protocol version, e.g. "TLSv1.0" */
                    __( '%s is outdated and known to be vulnerable — upgrade your server.', 'privacy-checker' ),
                    $protocol
                );
                break;
            default:
                $note = '';
        }

        return array(
            'status'   => $status,
            'protocol' => $protocol,
            'cipher'   => $cipher,
            'note'     => $note,
        );
    }

    /**
     * Classify a protocol string against the modern set.
     *
     * @param string $protocol
     * @return string 'modern' | 'acceptable' | 'outdated'
     */
    public static function classify_protocol( string $protocol ): string {
        // Trim whitespace and case-normalise the common "TLSv" prefix.
        $p = trim( $protocol );
        if ( '' === $p ) {
            return 'unknown';
        }
        if ( in_array( $p, self::CURRENT_PROTOCOLS, true ) ) {
            return 'modern';
        }
        if ( 'TLSv1.2' === $p ) {
            return 'acceptable';
        }
        // Anything we recognise as a TLS-family protocol but not in the
        // current/acceptable sets is "outdated" — TLS 1.0, TLS 1.1,
        // SSLv2, SSLv3. Unrecognised strings also land here — better to
        // surface a server config note than silently treat garbage as
        // fine.
        if ( 0 === strpos( $p, 'TLSv' ) || 0 === strpos( $p, 'SSLv' ) ) {
            return 'outdated';
        }
        // Unknown protocol string — treat as "unknown" not "outdated" so
        // we don't false-alarm on a server that reports something new
        // we haven't classified yet.
        return 'unknown';
    }

    /**
     * Walk a list of $_SERVER keys, return the first non-empty value.
     */
    private static function first_nonempty( array $keys ): string {
        foreach ( $keys as $k ) {
            if ( ! empty( $_SERVER[ $k ] ) && is_string( $_SERVER[ $k ] ) ) {
                return trim( (string) $_SERVER[ $k ] );
            }
        }
        return '';
    }
}
