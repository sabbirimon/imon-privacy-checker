<?php
/**
 * Pure-PHP SVG chart helpers for the admin dashboard.
 *
 * No JS, no external libraries — the goal is "easy to host" and zero
 * third-party dependencies. All charts return inline SVG strings.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AdminCharts {

	/**
	 * Line chart of counts per day.
	 *
	 * @param array<string,int> $series Day => count.
	 * @param string            $title
	 * @param string            $color
	 */
	public static function line( array $series, string $title, string $color = '#3dd2d2' ): string {
		if ( empty( $series ) ) {
			return self::empty_chart( $title );
		}
		$w   = 520;
		$h   = 160;
		$pad = 30;
		$max = max( max( $series ), 1 );
		$n   = count( $series );
		$dx  = ( $w - 2 * $pad ) / max( 1, $n - 1 );

		$points = array();
		$labels = array();
		$i = 0;
		foreach ( $series as $day => $count ) {
			$x = $pad + $dx * $i;
			$y = $h - $pad - ( ( $count / $max ) * ( $h - 2 * $pad ) );
			$points[] = sprintf( '%.1f,%.1f', $x, $y );
			$labels[ $day ] = array( 'x' => $x, 'y' => $y, 'count' => $count );
			$i++;
		}
		$path = 'M ' . implode( ' L ', $points );

		$x_axis = '';
		$idx = 0;
		foreach ( $series as $day => $count ) {
			$x = $pad + $dx * $idx;
			$short = substr( $day, 5 ); // MM-DD
			$x_axis .= sprintf( '<text x="%.1f" y="%d" font-size="10" text-anchor="middle" fill="#8a98b3">%s</text>', $x, $h - 8, esc_html( $short ) );
			$idx++;
		}

		$dots = '';
		foreach ( $labels as $lbl ) {
			$dots .= sprintf(
				'<circle cx="%.1f" cy="%.1f" r="3" fill="%s" />',
				$lbl['x'],
				$lbl['y'],
				esc_attr( $color )
			);
		}

		return sprintf(
			'<figure class="pc-chart"><figcaption>%s</figcaption><svg viewBox="0 0 %d %d" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="%s"><rect x="0" y="0" width="%d" height="%d" fill="transparent" /><line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#1f2c45" stroke-width="1" /><path d="%s" stroke="%s" stroke-width="2" fill="none" />%s%s</svg></figure>',
			esc_html( $title ),
			$w,
			$h,
			esc_attr( $title ),
			$w,
			$h,
			$pad,
			$h - $pad,
			$w - $pad,
			$h - $pad,
			esc_attr( $path ),
			esc_attr( $color ),
			$dots,
			$x_axis
		);
	}

	/**
	 * Stacked bar chart for two series (e.g. cache hit vs miss).
	 *
	 * @param array<string,int> $top    Top series label => value.
	 * @param array<string,int> $bottom Bottom series label => value.
	 * @param string            $title
	 * @param string            $top_color
	 * @param string            $bottom_color
	 */
	public static function stacked_bar( array $top, array $bottom, string $title, string $top_color = '#3dd2d2', string $bottom_color = '#5db5ff' ): string {
		$labels = array_unique( array_merge( array_keys( $top ), array_keys( $bottom ) ) );
		if ( empty( $labels ) ) {
			return self::empty_chart( $title );
		}
		$w   = 520;
		$h   = 160;
		$pad = 30;
		$max = 0;
		foreach ( $labels as $l ) {
			$max = max( $max, ( $top[ $l ] ?? 0 ) + ( $bottom[ $l ] ?? 0 ) );
		}
		$max = max( $max, 1 );
		$n   = count( $labels );
		$bar = ( $w - 2 * $pad ) / max( 1, $n );

		$bars = '';
		$x_axis = '';
		$idx = 0;
		foreach ( $labels as $lbl ) {
			$x = $pad + $bar * $idx + 4;
			$w_bar = max( 4, $bar - 8 );
			$t   = $top[ $lbl ] ?? 0;
			$b   = $bottom[ $lbl ] ?? 0;
			$h_top = ( $t / $max ) * ( $h - 2 * $pad );
			$h_bot = ( $b / $max ) * ( $h - 2 * $pad );
			$y_top = $h - $pad - $h_top - $h_bot;
			$y_bot = $h - $pad - $h_bot;
			$bars .= sprintf(
				'<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="%s" />',
				$x, $y_top, $w_bar, $h_top, esc_attr( $top_color )
			);
			$bars .= sprintf(
				'<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="%s" />',
				$x, $y_bot, $w_bar, $h_bot, esc_attr( $bottom_color )
			);
			$x_axis .= sprintf(
				'<text x="%.1f" y="%d" font-size="10" text-anchor="middle" fill="#8a98b3">%s</text>',
				$x + $w_bar / 2, $h - 8, esc_html( (string) $lbl )
			);
			$idx++;
		}

		return sprintf(
			'<figure class="pc-chart"><figcaption>%s</figcaption><svg viewBox="0 0 %d %d" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="%s">%s%s</svg></figure>',
			esc_html( $title ),
			$w,
			$h,
			esc_attr( $title ),
			$bars,
			$x_axis
		);
	}

	/**
	 * Pie chart of label => count.
	 *
	 * @param array<string,int> $series
	 * @param string            $title
	 */
	public static function pie( array $series, string $title ): string {
		$total = array_sum( $series );
		if ( $total <= 0 || empty( $series ) ) {
			return self::empty_chart( $title );
		}
		$colors = array( '#3dd2d2', '#5db5ff', '#36c98c', '#f6b54a', '#ef5b5b', '#a78bfa' );
		$cx = 110;
		$cy = 110;
		$r  = 90;
		$angle = -90.0;
		$paths = '';
		$legend = '';
		$i = 0;
		foreach ( $series as $label => $count ) {
			$frac = $count / $total;
			$end  = $angle + $frac * 360;
			$rad_a = deg2rad( $angle );
			$rad_b = deg2rad( $end );
			$large = $frac > 0.5 ? 1 : 0;
			$x1 = $cx + $r * cos( $rad_a );
			$y1 = $cy + $r * sin( $rad_a );
			$x2 = $cx + $r * cos( $rad_b );
			$y2 = $cy + $r * sin( $rad_b );
			$d  = sprintf( 'M %f %f L %f %f A %d %d 0 %d 1 %f %f Z', $cx, $cy, $x1, $y1, $r, $r, $large, $x2, $y2 );
			$color = $colors[ $i % count( $colors ) ];
			$paths .= sprintf( '<path d="%s" fill="%s" />', esc_attr( $d ), esc_attr( $color ) );
			$legend .= sprintf(
				'<li><span class="pc-pie-swatch" style="background:%s"></span>%s — %d (%d%%)</li>',
				esc_attr( $color ),
				esc_html( (string) $label ),
				(int) $count,
				(int) round( $frac * 100 )
			);
			$angle = $end;
			$i++;
		}
		return sprintf(
			'<figure class="pc-chart pc-chart--pie"><figcaption>%s</figcaption><div class="pc-pie-row"><svg viewBox="0 0 220 220" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="%s">%s</svg><ul class="pc-pie-legend">%s</ul></div></figure>',
			esc_html( $title ),
			esc_attr( $title ),
			$paths,
			$legend
		);
	}

	private static function empty_chart( string $title ): string {
		return sprintf(
			'<figure class="pc-chart pc-chart--empty"><figcaption>%s</figcaption><p class="description">%s</p></figure>',
			esc_html( $title ),
			esc_html__( 'No data yet. Enable event logging in Settings to start collecting this chart.', 'privacy-checker' )
		);
	}
}