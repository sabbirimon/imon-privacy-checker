<?php
/**
 * Fingerprint helpers.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Provides a UA parser and a fingerprint-uniqueness estimator.
 *
 * The uniqueness estimator uses a coarse, conservative heuristic so it never
 * over-claims. It is server-side only and never persisted.
 */
final class Fingerprint {

    /**
     * Parse a User-Agent string into a small, UI-friendly structure.
     *
     * @param string $ua
     * @return array<string,mixed>
     */
    public static function parse_user_agent( string $ua ): array {
        $ua = (string) $ua;

        $result = array(
            'raw'     => $ua,
            'browser' => null,
            'version' => null,
            'os'      => null,
            'device'  => null,
            'engine'  => null,
            'is_bot'  => false,
        );

        if ( '' === $ua ) {
            return $result;
        }

        // Bot detection (cheap checks first).
        if ( preg_match( '/bot|crawler|spider|crawling|slurp|mediapartners|facebookexternalhit|preview/i', $ua ) ) {
            $result['is_bot'] = true;
            $result['device'] = 'Bot';
            return $result;
        }

        // Browser family.
        $browsers = array(
            'Edge'    => '/Edg\/([\d.]+)/',
            'Opera'   => '/OPR\/([\d.]+)/',
            'Chrome'  => '/Chrome\/([\d.]+)/',
            'Firefox' => '/Firefox\/([\d.]+)/',
            'Safari'  => '/Version\/([\d.]+).*Safari/',
            'Samsung' => '/SamsungBrowser\/([\d.]+)/',
            'IE'      => '/MSIE ([\d.]+)/',
        );
        foreach ( $browsers as $name => $pattern ) {
            if ( preg_match( $pattern, $ua, $matches ) ) {
                $result['browser'] = $name;
                $result['version'] = $matches[1];
                break;
            }
        }

        // Engine.
        if ( strpos( $ua, 'Gecko/' ) !== false && strpos( $ua, 'like Gecko' ) === false ) {
            $result['engine'] = 'Gecko';
        } elseif ( strpos( $ua, 'AppleWebKit' ) !== false || strpos( $ua, 'Blink' ) !== false ) {
            $result['engine'] = 'WebKit';
        } elseif ( strpos( $ua, 'Trident/' ) !== false ) {
            $result['engine'] = 'Trident';
        }

        // OS.
        $os_patterns = array(
            'Windows'  => '/Windows NT ([\d.]+)/',
            'macOS'    => '/Mac OS X ([\d_.]+)/',
            'iOS'      => '/iPhone OS ([\d_]+)/',
            'Android'  => '/Android ([\d.]+)/',
            'Linux'    => '/Linux/',
            'Chrome OS'=> '/CrOS/',
        );
        foreach ( $os_patterns as $name => $pattern ) {
            if ( preg_match( $pattern, $ua, $matches ) ) {
                $result['os'] = $name;
                if ( isset( $matches[1] ) && ( 'macOS' === $name || 'iOS' === $name ) ) {
                    $result['os_version'] = str_replace( '_', '.', $matches[1] );
                } elseif ( isset( $matches[1] ) ) {
                    $result['os_version'] = $matches[1];
                }
                break;
            }
        }

        // Device.
        if ( preg_match( '/iPhone/', $ua ) ) {
            $result['device'] = 'Mobile';
        } elseif ( preg_match( '/iPad/', $ua ) ) {
            $result['device'] = 'Tablet';
        } elseif ( preg_match( '/Android/', $ua ) && ! preg_match( '/Mobile/', $ua ) ) {
            $result['device'] = 'Tablet';
        } elseif ( preg_match( '/Android|Mobile|iPhone/', $ua ) ) {
            $result['device'] = 'Mobile';
        } else {
            $result['device'] = 'Desktop';
        }

        return $result;
    }

    /**
     * Estimate fingerprint visibility from a set of browser signals.
     *
     * @param array<string,mixed> $signals
     * @return array{level:string, signals:array<string,bool>, exposure_score:int}
     */
    public static function estimate_visibility( array $signals ): array {
        $weights = array(
            'user_agent'        => 15,
            'screen_resolution' => 12,
            'color_depth'       => 6,
            'pixel_ratio'       => 6,
            'timezone'          => 10,
            'language'          => 8,
            'languages'         => 6,
            'platform'          => 9,
            'hardware_concurrency' => 7,
            'device_memory'     => 7,
            'touch_support'     => 4,
            'cookies'           => 4,
            'do_not_track'      => 3,
            'webgl'             => 12,
            'canvas'            => 10,
            'audio'             => 6,
            'fonts'             => 6,
        );

        $total  = 0;
        $actual = array();
        foreach ( $weights as $name => $weight ) {
            $present = ! empty( $signals[ $name ] );
            $actual[ $name ] = $present;
            if ( $present ) {
                $total += $weight;
            }
        }

        // Normalise to a 0–100 visibility score.
        $max = array_sum( $weights );
        $score = (int) round( ( $total / max( 1, $max ) ) * 100 );

        if ( $score >= 60 ) {
            $level = 'high';
        } elseif ( $score >= 30 ) {
            $level = 'moderate';
        } else {
            $level = 'low';
        }

        return array(
            'level'          => $level,
            'exposure_score' => $score,
            'signals'        => $actual,
        );
    }
}