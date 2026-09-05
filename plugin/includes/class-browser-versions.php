<?php
/**
 * BrowserVersions — small static lookup table that classifies a browser
 * family + major version into "current" / "outdated" / "very outdated".
 *
 * IMPORTANT: This table is HARDCODED and NEEDS PERIODIC MANUAL UPDATES.
 * It's intentionally not auto-fetched — a privacy plugin should not
 * phone home on every scan request. The "current" thresholds below were
 * chosen as of 2026-Q1 and will drift; treat them as "good enough" not
 * "always right". When in doubt, the UI copy invites the visitor to
 * check their own browser vendor for the latest version.
 *
 * Coverage is limited to the four major families: Chrome, Firefox,
 * Safari, Edge. Other UA strings (Opera, Samsung Internet, etc.) are
 * reported as "unknown family" rather than guessed.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

final class BrowserVersions {

    /**
     * Per-family (current, outdated_cutoff) major-version thresholds.
     * - >= current → 'current'
     * - >= outdated_cutoff (but < current) → 'outdated'
     * - < outdated_cutoff → 'very_outdated'
     *
     * These are intentionally conservative — the "outdated" band is
     * generous so we don't false-alarm visitors who are on a slightly
     * older release.
     *
     * @var array<string,array{current:int, outdated_cutoff:int}>
     */
    private const THRESHOLDS = array(
        'Chrome'  => array(
            'current'        => 130,
            'outdated_cutoff'=> 100,  // Chrome 100+ ~ 2022
        ),
        'Firefox' => array(
            'current'        => 125,
            'outdated_cutoff'=> 100,  // Firefox 100+ ~ 2022
        ),
        'Safari'  => array(
            'current'        => 17,
            'outdated_cutoff'=> 14,   // Safari 14 ~ 2020; < 14 is "very outdated"
        ),
        'Edge'    => array(
            'current'        => 130,  // Edge follows Chrome's cycle.
            'outdated_cutoff'=> 100,
        ),
    );

    /**
     * Classify a browser family + major version.
     *
     * @param string      $browser_name  Output of Fingerprint::parse_user_agent()['browser'].
     * @param int|null    $major_version Output of Fingerprint::parse_user_agent()['version']
     *                                   split on the first '.'. Null/0 = unknown.
     * @return array{status:string, browser:string, version:int|null, message:string}
     *   - status:  'current' | 'outdated' | 'very_outdated' | 'unknown_family' | 'unknown_version'
     *   - browser: the input browser name (echoed back for the UI)
     *   - version: the input major version (int) or null if not parseable
     *   - message: human-readable one-liner
     */
    public static function check( string $browser_name, ?int $major_version ): array {
        if ( ! isset( self::THRESHOLDS[ $browser_name ] ) ) {
            return array(
                'status'  => 'unknown_family',
                'browser' => $browser_name,
                'version' => $major_version,
                'message' => sprintf(
                    /* translators: %s: browser family name, e.g. "Opera" */
                    __( 'No version guidance for %s — check your vendor for updates.', 'privacy-checker' ),
                    '' !== $browser_name ? $browser_name : __( 'this browser', 'privacy-checker' )
                ),
            );
        }

        if ( null === $major_version || $major_version <= 0 ) {
            return array(
                'status'  => 'unknown_version',
                'browser' => $browser_name,
                'version' => $major_version,
                'message' => sprintf(
                    /* translators: %s: browser family name */
                    __( '%s version could not be determined — visit your browser vendor to check.', 'privacy-checker' ),
                    $browser_name
                ),
            );
        }

        $t           = self::THRESHOLDS[ $browser_name ];
        $current_max = $t['current'];
        $outdated    = $t['outdated_cutoff'];

        if ( $major_version >= $current_max ) {
            $status = 'current';
            $message = sprintf(
                /* translators: 1: browser name, 2: major version */
                __( '%1$s %2$d is current — no update recommended.', 'privacy-checker' ),
                $browser_name,
                $major_version
            );
        } elseif ( $major_version >= $outdated ) {
            $status = 'outdated';
            $message = sprintf(
                /* translators: 1: browser name, 2: current major version, 3: visitor's major version */
                __( '%1$s %3$d is a few versions behind the latest (%2$d) — update when convenient.', 'privacy-checker' ),
                $browser_name,
                $current_max,
                $major_version
            );
        } else {
            $status = 'very_outdated';
            $message = sprintf(
                /* translators: 1: browser name, 2: visitor's major version */
                __( '%1$s %2$d is significantly out of date and likely has known security issues — update as soon as possible.', 'privacy-checker' ),
                $browser_name,
                $major_version
            );
        }

        return array(
            'status'  => $status,
            'browser' => $browser_name,
            'version' => $major_version,
            'message' => $message,
        );
    }

    /**
     * Public getter for the threshold table — exposed for the Phase 8
     * admin "Scoring Parameters" reference card so the values shown
     * there come from this single source of truth rather than being
     * duplicated in admin-only HTML.
     *
     * Shape: `[ browser_name => [ 'current' => int, 'outdated_cutoff' => int ], ... ]`
     *
     * @return array<string,array{current:int, outdated_cutoff:int}>
     */
    public static function thresholds(): array {
        return self::THRESHOLDS;
    }
}
