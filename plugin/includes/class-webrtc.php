<?php
/**
 * WebRTC support endpoints.
 *
 * The actual WebRTC test runs entirely client-side via RTCPeerConnection.
 * This class provides the server endpoints the client calls during the test,
 * and shapes the result before returning it for display.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * WebRTC result helpers.
 */
final class Webrtc {

    /**
     * Normalise client-collected WebRTC data into a UI-ready report.
     *
     * @param array<string,mixed> $client_data Raw data posted from the browser.
     * @return array<string,mixed>
     */
    public static function summarize( array $client_data ): array {
        $supported    = ! empty( $client_data['supported'] );
        $candidates   = is_array( $client_data['candidates'] ?? null ) ? $client_data['candidates'] : array();
        $public_addrs = array();
        $local_addrs  = array();

        foreach ( $candidates as $candidate ) {
            if ( ! is_array( $candidate ) ) {
                continue;
            }
            $ip   = (string) ( $candidate['ip'] ?? '' );
            $type = (string) ( $candidate['type'] ?? '' );
            if ( '' === $ip ) {
                continue;
            }
            if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
                continue;
            }
            if ( 'srflx' === $type || 'relay' === $type || 'host' === $type ) {
                if ( Security::is_public_ip_literal( $ip ) ) {
                    $public_addrs[] = $ip;
                } else {
                    $local_addrs[] = $ip;
                }
            }
        }

        $public_addrs = array_values( array_unique( $public_addrs ) );
        $local_addrs  = array_values( array_unique( $local_addrs ) );

        if ( ! $supported ) {
            $verdict = 'not_supported';
            $message = 'WebRTC is not supported by this browser.';
        } elseif ( ! empty( $public_addrs ) ) {
            $verdict = 'potential_exposure';
            $message = 'WebRTC exposed a public IP address during this test. This may differ from your normal connection IP.';
        } else {
            $verdict = 'protected';
            $message = 'WebRTC did not reveal an additional public IP address during this test.';
        }

        return array(
            'supported'      => $supported,
            'verdict'        => $verdict,
            'message'        => $message,
            'public_addrs'   => $public_addrs,
            'local_addrs'    => $local_addrs,
            'candidate_count'=> count( $candidates ),
        );
    }
}