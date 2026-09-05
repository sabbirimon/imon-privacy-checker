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
     * Bit-assignments for fingerprint entropy estimation.
     *
     * Per IMON-BUILD-GUIDE.md Phase 3: these are ROUGH PROXIES based
     * on Panopticlick / EFF Cover-Your-Tracks family cardinality
     * estimates. They will over- or under-count against any real
     * population, but they give an intuitive "more signals = more
     * unique" readout. Replace with measured -log2(p) values when
     * population stats exist; entropy_estimate() is the only call
     * site that needs to change.
     *
     * Exposed via entropy_bit_assignments() so the Phase 8 admin
     * "Scoring Parameters" reference card can render these without
     * duplicating the constants in admin-only HTML.
     *
     * Shape: `signal_name => bits`. Special values:
     *   - `font_per_extra` is a per-font delta applied beyond the
     *     baseline count (not a one-shot add).
     *   - `font_baseline` is the baseline font count that contributes
     *     zero bits.
     *   - `webgl_renderer_masked` is a NEGATIVE bonus (reward) when
     *     the browser explicitly masks the WebGL renderer.
     *
     * @var array<string,int>
     */
    private const ENTROPY_BIT_ASSIGNMENTS = array(
        'canvas_hash'          => 15,
        'audio_hash'           => 15,
        'webgl_renderer'       => 6,
        'webgl_renderer_masked'=> -5,
        'font_per_extra'       => 1,
        'font_baseline'        => 8,
        'timezone'             => 4,
        'language'             => 4,
        'languages'            => 2,
        'cap_bits'             => 100,
    );

    /**
     * Public getter for the entropy bit-assignment table.
     *
     * @return array<string,int>
     */
    public static function entropy_bit_assignments(): array {
        return self::ENTROPY_BIT_ASSIGNMENTS;
    }

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
     * As of Phase 3 this now folds in the entropy_estimate() result rather
     * than the old boolean-only scoring. The top-level shape is preserved
     * (`level`, `exposure_score`, `signals`) so existing UI consumers don't
     * break, but the entropy breakdown is also returned under
     * `entropy` for the new rows in the report card.
     *
     * @param array<string,mixed> $signals
     * @return array{level:string, signals:array<string,bool>, exposure_score:int, entropy:array<string,mixed>, masked_signals:array<int,string>}
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

        // Normalise to a 0–100 visibility score from the boolean flags.
        $max = array_sum( $weights );
        $boolean_score = (int) round( ( $total / max( 1, $max ) ) * 100 );

        // New entropy-based estimate — weighted higher because it reflects
        // actual rendered-pipeline uniqueness rather than capability flags.
        // Average the two so a single signal family doesn't dominate.
        $entropy       = self::entropy_estimate( $signals );
        $entropy_score = isset( $entropy['score'] ) ? (int) $entropy['score'] : 0;
        $score         = (int) round( ( $boolean_score + $entropy_score ) / 2 );

        if ( $score >= 60 ) {
            $level = 'high';
        } elseif ( $score >= 30 ) {
            $level = 'moderate';
        } else {
            $level = 'low';
        }

        // Signals that the browser is intentionally masking (anti-fp).
        // Surfaced separately so the UI can show them as GOOD signs, not
        // as missing data.
        $masked_signals = array();
        if ( isset( $signals['webgl_renderer'] ) && 'masked-by-browser' === $signals['webgl_renderer'] ) {
            $masked_signals[] = 'webgl_renderer';
        }
        if ( isset( $signals['webgl_vendor'] ) && 'masked-by-browser' === $signals['webgl_vendor'] ) {
            $masked_signals[] = 'webgl_vendor';
        }

        return array(
            'level'          => $level,
            'exposure_score' => $score,
            'signals'        => $actual,
            'entropy'        => $entropy,
            'masked_signals' => $masked_signals,
        );
    }

    /**
     * Estimate fingerprint entropy in bits from the new Phase 3 signals.
     *
     * IMPORTANT: This is a ROUGH PROXY, not measured against real traffic.
     * The bit-assignments below are cardinality estimates from public
     * fingerprinting research (Panopticlick / EFF Cover-Your-Tracks
     * family). They will over-count or under-count depending on the
     * visitor's actual population — the goal here is to give the
     * visitor an intuitive "more signals = more unique" readout, not
     * to produce a scientifically defensible number.
     *
     * TODO: when population stats exist (e.g. a Cache-backed rolling
     * histogram per signal), replace these constants with measured
     * -log2(p) values. The seam is here — entropy_estimate() is the only
     * place that needs to change.
     *
     * Bit assignments:
     *   - canvas_hash present (non-empty):        +15 bits
     *   - audio_hash  present (non-empty):        +15 bits
     *   - webgl_renderer present and not masked:  +6  bits
     *   - webgl_renderer == "masked-by-browser":  -5  bits (REWARD anti-fp)
     *   - font_list:                              +1  bit per font beyond
     *                                               a baseline of 8 common
     *                                               fonts (so 9 fonts = +1,
     *                                               12 fonts = +4)
     *   - timezone present:                       +4  bits
     *   - language  present:                      +4  bits
     *   - languages  non-empty:                   +2  bits
     *
     * Total is capped at 100 bits; the score is min(100, total_bits).
     * "1 in N visitors" estimate is 2^bits, capped at a sane upper bound.
     *
     * @param array<string,mixed> $signals
     * @return array{bits:int, score:int, uniqueness_estimate:string, breakdown:array<string,mixed>, masked_signals:array<int,string>}
     */
    public static function entropy_estimate( array $signals ): array {
        $bits = 0;
        $breakdown = array();

        // canvas_hash
        if ( ! empty( $signals['canvas_hash'] ) && is_string( $signals['canvas_hash'] ) ) {
            $bits += 15;
            $breakdown['canvas_hash'] = 15;
        } else {
            $breakdown['canvas_hash'] = 0;
        }

        // audio_hash
        if ( ! empty( $signals['audio_hash'] ) && is_string( $signals['audio_hash'] ) ) {
            $bits += 15;
            $breakdown['audio_hash'] = 15;
        } else {
            $breakdown['audio_hash'] = 0;
        }

        // webgl_renderer
        $masked_signals = array();
        if ( isset( $signals['webgl_renderer'] ) && 'masked-by-browser' === $signals['webgl_renderer'] ) {
            $bits -= 5;
            $breakdown['webgl_renderer'] = -5;
            $masked_signals[] = 'webgl_renderer';
        } elseif ( ! empty( $signals['webgl_renderer'] ) ) {
            $bits += 6;
            $breakdown['webgl_renderer'] = 6;
        } else {
            $breakdown['webgl_renderer'] = 0;
        }
        if ( isset( $signals['webgl_vendor'] ) && 'masked-by-browser' === $signals['webgl_vendor'] ) {
            $masked_signals[] = 'webgl_vendor';
        }

        // font_list — baseline of 8 common fonts don't add anything;
        // each font beyond baseline contributes 1 bit.
        $baseline_fonts = 8;
        $font_list = ( isset( $signals['font_list'] ) && is_array( $signals['font_list'] ) )
            ? count( $signals['font_list'] )
            : 0;
        $font_bits = max( 0, $font_list - $baseline_fonts );
        $bits += $font_bits;
        $breakdown['font_list'] = array(
            'installed' => $font_list,
            'baseline'  => $baseline_fonts,
            'bits'      => $font_bits,
        );

        // timezone
        if ( ! empty( $signals['timezone'] ) ) {
            $bits += 4;
            $breakdown['timezone'] = 4;
        } else {
            $breakdown['timezone'] = 0;
        }

        // language
        if ( ! empty( $signals['language'] ) ) {
            $bits += 4;
            $breakdown['language'] = 4;
        } else {
            $breakdown['language'] = 0;
        }

        // languages (array)
        if ( ! empty( $signals['languages'] ) && is_array( $signals['languages'] ) ) {
            $bits += 2;
            $breakdown['languages'] = 2;
        } else {
            $breakdown['languages'] = 0;
        }

        // Clamp to 0..100 bits.
        $bits    = max( 0, min( 100, $bits ) );
        $score   = (int) $bits; // already 0..100

        // "1 in N visitors" — cap at a reasonable upper bound so the
        // string doesn't say "1 in 2.5e12 visitors" when bits are 41.
        // 2**bits overflows to float when bits > ~63, so compute via
        // left-shift when within int range, else use the upper cap.
        if ( $bits >= 64 ) {
            $one_in = 10000000;
        } else {
            $one_in = (int) min( 10000000, max( 1, 1 << $bits ) );
        }

        if ( $bits <= 5 ) {
            $human = sprintf(
                /* translators: 1: bits of entropy */
                _x( 'Roughly 1 in %1$s visitors share this fingerprint — low uniqueness.', 'fingerprint entropy', 'privacy-checker' ),
                number_format_i18n( $one_in )
            );
        } elseif ( $bits <= 15 ) {
            $human = sprintf(
                /* translators: 1: bits of entropy */
                _x( 'Roughly 1 in %1$s visitors share this fingerprint.', 'fingerprint entropy', 'privacy-checker' ),
                number_format_i18n( $one_in )
            );
        } elseif ( $bits <= 30 ) {
            $human = sprintf(
                /* translators: 1: bits of entropy */
                _x( 'Roughly 1 in %1$s visitors share this fingerprint — likely unique in the wild.', 'fingerprint entropy', 'privacy-checker' ),
                number_format_i18n( $one_in )
            );
        } else {
            $human = sprintf(
                /* translators: 1: bits of entropy */
                _x( 'Roughly 1 in %1$s visitors share this fingerprint — almost certainly unique.', 'fingerprint entropy', 'privacy-checker' ),
                number_format_i18n( $one_in )
            );
        }

        return array(
            'bits'                 => $bits,
            'score'                => $score,
            'uniqueness_estimate'  => $human,
            'breakdown'            => $breakdown,
            'masked_signals'       => $masked_signals,
        );
    }
}