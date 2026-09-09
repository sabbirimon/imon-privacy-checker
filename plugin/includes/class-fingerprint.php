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
     * Pluggable seam: return a histogram of signal values seen across the
     * visitor population, or [] to fall back to the constants in
     * `entropy_bit_assignments()`.
     *
     * Backed by the site-wide Cache (transients). Key convention:
     *   pc_fp_hist_{$signal}
     * TTL: DAY_IN_SECONDS. Future work can swap the empty collector
     * (the inner `fn() => []`) for a real rolling-histogram store
     * without needing to touch `entropy_estimate()`.
     *
     * Phase 3 guide explicitly defers the actual collector. This seam
     * lands the lookup path so the eventual collector has a stable
     * integration point.
     *
     * @param string $signal  e.g. 'canvas_hash', 'audio_hash', 'webgl_renderer'.
     * @return array<string,int> histogram buckets, or [] when no data exists.
     */
    public static function population_histogram( string $signal ): array {
        return Cache::remember(
            'pc_fp_hist_' . $signal,
            static function (): array {
                return array();
            },
            DAY_IN_SECONDS
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
     * place that needs to change. The plumbing for that seam is now in
     * place via `Fingerprint::population_histogram()` below; the actual
     * histogram collector is intentionally not implemented yet (Phase 3
     * guide defers it until real per-signal population data exists).
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
        // Phase 9 / Item C: population-stats seam. Consult the histogram
        // for each signal we care about. While the histograms are empty
        // (the default — no collector wired in yet), the existing
        // constant-based computation below runs unchanged.
        //
        // TODO: weight by histogram when non-empty. Future work swaps
        // the empty collector for a real rolling-histogram store without
        // needing to touch this method's structure.
        $histograms = array(
            'canvas_hash'    => self::population_histogram( 'canvas_hash' ),
            'audio_hash'     => self::population_histogram( 'audio_hash' ),
            'webgl_renderer' => self::population_histogram( 'webgl_renderer' ),
            'timezone'       => self::population_histogram( 'timezone' ),
            'language'       => self::population_histogram( 'language' ),
            'languages'      => self::population_histogram( 'languages' ),
        );
        $use_histograms = ! empty( array_filter( $histograms ) );

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

        // Phase 9 / Item C: when population histograms are non-empty,
        // blend the histogram-weighted estimate into the result. While
        // the collector returns [], `$use_histograms` is false and this
        // block is a no-op (preserves existing behaviour exactly). When
        // a future contributor wires in a real histogram store, this
        // block re-routes the scoring without needing to restructure
        // the method.
        if ( $use_histograms ) {
            $measured_bits = self::histogram_weighted_bits( $signals, $histograms );
            // Blend 50/50 — once histograms exist, both signals matter.
            // The constant branch covers capabilities; the histogram
            // branch covers observed frequency. Together they're more
            // honest than either alone.
            $bits = (int) round( ( $bits + $measured_bits ) / 2 );
        }

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

    /**
     * Histogram-weighted entropy estimator — Phase 9 / Item C seam.
     *
     * Given a set of `$histograms` keyed by signal name (each histogram
     * is `value => observed_count` across the visitor population), and
     * the current visitor's `$signals`, sum the per-signal
     * `-log2(max(p, epsilon))` bits where `p = observed_count / total`.
     *
     * Returns 0 when called with empty histograms — the caller is
     * expected to gate this behind `! empty( array_filter( $histograms ) )`,
     * so the constant-based branch in `entropy_estimate()` keeps
     * driving the score until a real collector lands.
     *
     * @param array<string,mixed> $signals    Current visitor's signals.
     * @param array<string,array<string,int>> $histograms Signal histograms.
     * @return int Estimated bits (already clamped to [0, 100]).
     */
    private static function histogram_weighted_bits( array $signals, array $histograms ): int {
        $bits = 0;
        $eps  = 1e-9;

        // For each signal we know, look up its observation count in
        // the histogram and compute the entropy contribution.
        $lookup = static function ( string $signal_key, string $hist_key, $current_value ) use ( $histograms, $eps ) {
            $hist = $histograms[ $hist_key ] ?? array();
            if ( empty( $hist ) || empty( $current_value ) ) {
                return 0.0;
            }
            $total = array_sum( $hist );
            if ( $total <= 0 ) {
                return 0.0;
            }
            // For string-valued signals (canvas_hash, etc.) the visitor's
            // exact value is the bucket key. For array-valued signals
            // (languages), the per-element buckets are summed.
            if ( is_array( $current_value ) ) {
                $count = 0;
                foreach ( $current_value as $v ) {
                    $count += (int) ( $hist[ (string) $v ] ?? 0 );
                }
            } else {
                $count = (int) ( $hist[ (string) $current_value ] ?? 0 );
            }
            if ( $count <= 0 ) {
                // Bucket unobserved in our population — treat as
                // maximally unique (capped at 20 bits to avoid
                // runaway totals).
                return 20.0;
            }
            $p        = max( $eps, $count / $total );
            $bits     = -log( $p, 2 );
            // Cap per-signal contribution so one outlier can't blow up
            // the whole estimate.
            return min( 20.0, $bits );
        };

        // Canvas hash.
        $bits += $lookup( 'canvas_hash', 'canvas_hash', $signals['canvas_hash'] ?? '' );
        // Audio hash.
        $bits += $lookup( 'audio_hash', 'audio_hash', $signals['audio_hash'] ?? '' );
        // WebGL renderer (no negative reward here — anti-fp behaviour
        // is its own category handled in the constant branch).
        if ( ! empty( $signals['webgl_renderer'] ) && 'masked-by-browser' !== $signals['webgl_renderer'] ) {
            $bits += $lookup( 'webgl_renderer', 'webgl_renderer', $signals['webgl_renderer'] );
        }
        // Timezone, language, languages.
        $bits += $lookup( 'timezone', 'timezone', $signals['timezone'] ?? '' );
        $bits += $lookup( 'language', 'language', $signals['language'] ?? '' );
        $bits += $lookup( 'languages', 'languages', $signals['languages'] ?? array() );

        // Font list: sum per-font entropy bits up to a sensible cap.
        if ( ! empty( $signals['font_list'] ) && is_array( $signals['font_list'] ) && ! empty( $histograms['fonts'] ) ) {
            $fonts_bits = 0.0;
            foreach ( (array) $signals['font_list'] as $font ) {
                $fonts_bits += $lookup( 'fonts', 'fonts', (string) $font );
            }
            $bits += min( 15.0, $fonts_bits );
        }

        return (int) max( 0, min( 100, (int) round( $bits ) ) );
    }
}