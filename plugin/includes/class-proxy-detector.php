<?php
/**
 * Proxy / VPN / Tor / Hosting / Datacenter detection by vendor.
 *
 * Heuristic-only. We classify an IP using ASN, organization, ISP, and
 * a curated list of well-known hosting, VPN, and Tor exit providers.
 *
 * Categories:
 *   - residential  : ordinary consumer ISP.
 *   - datacenter   : hosting/cloud provider (AWS, GCP, Azure, Hetzner, OVH,
 *                    Cloudflare, etc.).
 *   - vpn          : commercial VPN provider (Mullvad, PIA, ProtonVPN, etc.).
 *   - proxy        : open proxy / commercial proxy (Smartproxy, Bright Data).
 *   - tor          : known Tor exit relay.
 *   - relay        : I2P / anonymous relay.
 *   - hosting      : generic VPS / dedicated hosting (ColoCrossing, Psychz).
 *
 * Confidence levels:
 *   - high   : exact ASN match in a curated list.
 *   - medium : organization string contains a known vendor token.
 *   - low    : only ISP-class signals matched (e.g. generic "Datacamp").
 *
 * Important caveats:
 *   - Detection is probabilistic. False positives on small ISPs that share
 *     ASNs with hosting providers are possible.
 *   - We never write to the log or persist results; the result is a JSON
 *     blob that survives in the scan response only.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Static proxy detector.
 */
final class ProxyDetector {

    /**
     * Curated ASN -> category map (case-insensitive on the ASN string).
     *
     * Sources: published ASN ownership pages of major providers, plus
     * community-maintained lists like bgp.tools / ipinfo.io / Tor's
     * published relay ASN list. We are deliberately conservative — only
     * highly stable ASNs appear here.
     *
     * @var array<string, array{label:string, vendors:array<int,string>}>
     */
    private const ASN_CATALOG = array(
        // Cloud / hyperscaler.
        'AS16509' => array( 'category' => 'datacenter', 'vendor' => 'Amazon AWS' ),
        'AS14618' => array( 'category' => 'datacenter', 'vendor' => 'Amazon AWS' ),
        'AS15169' => array( 'category' => 'datacenter', 'vendor' => 'Google Cloud' ),
        'AS8075'  => array( 'category' => 'datacenter', 'vendor' => 'Microsoft Azure' ),
        'AS13335' => array( 'category' => 'datacenter', 'vendor' => 'Cloudflare' ),
        'AS20940' => array( 'category' => 'datacenter', 'vendor' => 'Akamai' ),
        'AS16625' => array( 'category' => 'datacenter', 'vendor' => 'Akamai' ),

        // Large hosting.
        'AS16276' => array( 'category' => 'hosting',    'vendor' => 'OVH' ),
        'AS24940' => array( 'category' => 'hosting',    'vendor' => 'Hetzner' ),
        'AS51167' => array( 'category' => 'hosting',    'vendor' => 'Hetzner' ),
        'AS200000' => array( 'category' => 'hosting',   'vendor' => 'Hetzner' ),
        'AS14061' => array( 'category' => 'datacenter', 'vendor' => 'DigitalOcean' ),
        'AS31898' => array( 'category' => 'datacenter', 'vendor' => 'DigitalOcean' ),
        'AS62567' => array( 'category' => 'datacenter', 'vendor' => 'DigitalOcean' ),
        'AS204957' => array( 'category' => 'hosting',   'vendor' => 'Vultr' ),
        'AS6453'  => array( 'category' => 'datacenter', 'vendor' => 'Tata Communications' ),
        'AS1299'  => array( 'category' => 'datacenter', 'vendor' => 'Arelion (Telia)' ),
        'AS3356'  => array( 'category' => 'datacenter', 'vendor' => 'Lumen (CenturyLink)' ),
        'AS174'   => array( 'category' => 'datacenter', 'vendor' => 'Cogent' ),
        'AS6939'  => array( 'category' => 'datacenter', 'vendor' => 'Hurricane Electric' ),
        'AS9009'  => array( 'category' => 'datacenter', 'vendor' => 'M247' ),
        'AS60729' => array( 'category' => 'hosting',    'vendor' => 'Stark Industries (M247 family)' ),
        'AS14576' => array( 'category' => 'hosting',    'vendor' => 'Hosting Solutions International' ),
        'AS36352' => array( 'category' => 'datacenter', 'vendor' => 'ColoCrossing' ),
        'AS46844' => array( 'category' => 'datacenter', 'vendor' => 'ColoCrossing' ),
        'AS204957' => array( 'category' => 'hosting',   'vendor' => 'Vultr' ),
        'AS39572' => array( 'category' => 'hosting',    'vendor' => 'DataCamp' ),
        'AS60068' => array( 'category' => 'datacenter', 'vendor' => 'DataCamp / Psychz' ),
        'AS204428' => array( 'category' => 'hosting',   'vendor' => 'Psychz Networks' ),
        'AS40676' => array( 'category' => 'hosting',    'vendor' => 'Psychz Networks' ),
        'AS60068' => array( 'category' => 'hosting',    'vendor' => 'Datacamp Limited' ),
        'AS8100'  => array( 'category' => 'datacenter', 'vendor' => 'QuadraNet' ),
        'AS394711' => array( 'category' => 'datacenter','vendor' => 'Limenet' ),
        'AS393559' => array( 'category' => 'datacenter','vendor' => 'WebNX' ),

        // VPN providers (selected well-known ASNs).
        'AS212238' => array( 'category' => 'vpn',       'vendor' => 'Mullvad VPN' ),
        'AS57630'  => array( 'category' => 'vpn',       'vendor' => 'ProtonVPN' ),
        'AS208091' => array( 'category' => 'vpn',       'vendor' => 'ProtonVPN' ),
        'AS50321'  => array( 'category' => 'vpn',       'vendor' => 'Windscribe' ),
        'AS59930'  => array( 'category' => 'vpn',       'vendor' => 'IVPN' ),
        'AS206092' => array( 'category' => 'vpn',       'vendor' => 'IVPN' ),
        'AS9009'   => array( 'category' => 'vpn',       'vendor' => 'Generic VPN (M247 range)' ), // overlap; see vendor list.

        // Tor.
        'AS208294' => array( 'category' => 'tor',       'vendor' => 'Tor Exit Relay' ),
        'AS208091' => array( 'category' => 'tor',       'vendor' => 'Tor (possible)' ),
    );

    /**
     * Substring match table. Lower-case needle on the org/isp field.
     * Order matters: longer / more specific tokens come first so they
     * match before a generic "hosting" substring wins.
     *
     * @var array<string, array{category:string, vendor:string}>
     */
    private const ORG_TOKENS = array(
        'mullvad vpn'                     => array( 'category' => 'vpn',       'vendor' => 'Mullvad' ),
        'protonvpn'                       => array( 'category' => 'vpn',       'vendor' => 'ProtonVPN' ),
        'proton ag'                       => array( 'category' => 'vpn',       'vendor' => 'ProtonVPN' ),
        'windscribe'                      => array( 'category' => 'vpn',       'vendor' => 'Windscribe' ),
        'private internet access'         => array( 'category' => 'vpn',       'vendor' => 'PIA' ),
        'pia llc'                         => array( 'category' => 'vpn',       'vendor' => 'PIA' ),
        'expressvpn'                      => array( 'category' => 'vpn',       'vendor' => 'ExpressVPN' ),
        'nordvpn'                         => array( 'category' => 'vpn',       'vendor' => 'NordVPN' ),
        'surfshark'                       => array( 'category' => 'vpn',       'vendor' => 'Surfshark' ),
        'cyberghost'                      => array( 'category' => 'vpn',       'vendor' => 'CyberGhost' ),
        'tunnelbear'                      => array( 'category' => 'vpn',       'vendor' => 'TunnelBear' ),
        'ivpn'                            => array( 'category' => 'vpn',       'vendor' => 'IVPN' ),

        // Datacenter / hyperscaler.
        'amazon'                          => array( 'category' => 'datacenter', 'vendor' => 'Amazon AWS' ),
        'aws'                             => array( 'category' => 'datacenter', 'vendor' => 'Amazon AWS' ),
        'google cloud'                    => array( 'category' => 'datacenter', 'vendor' => 'Google Cloud' ),
        'google llc'                      => array( 'category' => 'datacenter', 'vendor' => 'Google' ),
        'microsoft corp'                  => array( 'category' => 'datacenter', 'vendor' => 'Microsoft Azure' ),
        'microsoft azure'                 => array( 'category' => 'datacenter', 'vendor' => 'Microsoft Azure' ),
        'azure'                           => array( 'category' => 'datacenter', 'vendor' => 'Microsoft Azure' ),
        'cloudflare'                      => array( 'category' => 'datacenter', 'vendor' => 'Cloudflare' ),
        'akamai'                          => array( 'category' => 'datacenter', 'vendor' => 'Akamai' ),

        // Hosting.
        'ovh'                             => array( 'category' => 'hosting',    'vendor' => 'OVH' ),
        'hetzner'                         => array( 'category' => 'hosting',    'vendor' => 'Hetzner' ),
        'digitalocean'                    => array( 'category' => 'datacenter', 'vendor' => 'DigitalOcean' ),
        'vultr'                           => array( 'category' => 'hosting',    'vendor' => 'Vultr' ),
        'linode'                          => array( 'category' => 'hosting',    'vendor' => 'Linode/Akamai' ),
        'colocrossing'                    => array( 'category' => 'datacenter', 'vendor' => 'ColoCrossing' ),
        'psychz'                          => array( 'category' => 'hosting',    'vendor' => 'Psychz' ),
        'datacamp limited'                => array( 'category' => 'hosting',    'vendor' => 'DataCamp' ),
        'quadranet'                       => array( 'category' => 'datacenter', 'vendor' => 'QuadraNet' ),
        'buyvm'                           => array( 'category' => 'hosting',    'vendor' => 'FranTech Solutions' ),
        'frantech'                        => array( 'category' => 'hosting',    'vendor' => 'FranTech Solutions' ),
        'cogent'                          => array( 'category' => 'datacenter', 'vendor' => 'Cogent' ),
        'hurricane electric'              => array( 'category' => 'datacenter', 'vendor' => 'Hurricane Electric' ),

        // Proxy / web-scraping.
        'bright data'                     => array( 'category' => 'proxy',      'vendor' => 'Bright Data' ),
        'smartproxy'                      => array( 'category' => 'proxy',      'vendor' => 'Smartproxy' ),
        'oxylabs'                         => array( 'category' => 'proxy',      'vendor' => 'Oxylabs' ),
        'geosurf'                         => array( 'category' => 'proxy',      'vendor' => 'GeoSurf' ),
        'netnut'                          => array( 'category' => 'proxy',      'vendor' => 'NetNut' ),

        // Tor / relay.
        'tor exit'                       => array( 'category' => 'tor',        'vendor' => 'Tor' ),
        'tor network'                    => array( 'category' => 'tor',        'vendor' => 'Tor' ),
        'tor-relay'                      => array( 'category' => 'tor',        'vendor' => 'Tor' ),
    );

    /**
     * Classify an IP using the supplied intel output (from IpFallback::lookup).
     *
     * @param array<string,mixed> $intel Output shape of IpFallback::lookup().
     * @return array<string,mixed>       { category, vendor, label, confidence, reasons[], score }
     */
    public static function classify( array $intel ): array {
        $asn      = strtoupper( trim( (string) ( $intel['asn'] ?? '' ) ) );
        $org      = strtolower( trim( (string) ( $intel['org'] ?? $intel['asn_org'] ?? '' ) ) );
        $isp      = strtolower( trim( (string) ( $intel['isp'] ?? '' ) ) );
        $country  = strtolower( trim( (string) ( $intel['country'] ?? '' ) ) );

        $reasons  = array();
        $category = 'residential';
        $vendor   = '';
        $conf     = 'low';

        // 1) ASN catalog (high confidence).
        if ( '' !== $asn && isset( self::ASN_CATALOG[ $asn ] ) ) {
            $entry     = self::ASN_CATALOG[ $asn ];
            $category  = $entry['category'];
            $vendor    = $entry['vendor'];
            $conf      = 'high';
            $reasons[] = sprintf( 'ASN %s matches %s catalog.', $asn, $vendor );
        }

        // 2) Org/ISP substring (medium confidence).
        $haystack = trim( $org . ' ' . $isp );
        if ( '' !== $haystack ) {
            foreach ( self::ORG_TOKENS as $needle => $entry ) {
                if ( false !== strpos( $haystack, $needle ) ) {
                    // ASN match wins on conflict (high > medium).
                    if ( 'high' !== $conf ) {
                        $category = $entry['category'];
                        $vendor   = $entry['vendor'];
                        $conf     = 'medium';
                    }
                    $reasons[] = sprintf( 'Organization string contains "%s" (vendor: %s).', $needle, $entry['vendor'] );
                    break;
                }
            }
        }

        // 3) Generic datacenter signals (lowest priority).
        if ( 'residential' === $category ) {
            $generic_tokens = array(
                'hosting', 'datacenter', 'data center', 'cloud', 'server', 'vps',
                'colocation', 'colo ', 'leaseweb', 'choopa', 'psychz', 'vultr',
            );
            foreach ( $generic_tokens as $tok ) {
                if ( false !== strpos( $haystack, $tok ) ) {
                    $category = 'hosting';
                    $vendor   = 'Generic hosting';
                    $conf     = 'low';
                    $reasons[] = sprintf( 'Organization string mentions "%s".', $tok );
                    break;
                }
            }
        }

        // 4) Country sanity — known privacy-friendly jurisdictions get a
        // small "label only" hint but no confidence change.
        $privacy_jurisdictions = array( 'is', 'ch', 'pa', 'ky', 'bs', 'vg', 'sc' );
        if ( in_array( $country, $privacy_jurisdictions, true ) && 'residential' === $category ) {
            $reasons[] = sprintf( 'Country "%s" is commonly associated with privacy-friendly hosting.', strtoupper( $country ) );
        }

        $label = self::label_for( $category, $vendor );
        $score = self::score_for( $category, $conf );

        return array(
            'category'   => $category,
            'vendor'     => $vendor,
            'label'      => $label,
            'confidence' => $conf,
            'reasons'    => array_values( array_unique( $reasons ) ),
            'score'      => $score,
        );
    }

    /**
     * Classify an IP and additionally consult any uploaded Tor / VPN / proxy /
     * datacenter exit lists. The intel array's 'ip' field is used to look up
     * the lists; pass the visitor's IPv4 string. The list-based verdict
     * upgrades confidence to "high" and overrides the heuristic when present.
     *
     * @param array<string,mixed> $intel Same shape as classify() takes.
     * @return array<string,mixed>
     */
    public static function classify_with_lists( array $intel ): array {
        $base = self::classify( $intel );
        $ip   = (string) ( $intel['ip'] ?? '' );
        if ( '' === $ip ) {
            return $base;
        }
        $lists = TorExitScanner::lookup( $ip );

        // Tor wins outright.
        if ( ! empty( $lists['tor']['matched'] ) ) {
            $base['category']   = 'tor';
            $base['vendor']     = 'Tor exit relay';
            $base['label']      = self::label_for( 'tor', 'Tor exit relay' );
            $base['confidence'] = 'high';
            $base['reasons'][]  = sprintf(
                'IP appears in uploaded Tor exit list (%s).',
                (string) ( $lists['tor']['source'] ?? 'unknown source' )
            );
            $base['score']      = self::score_for( 'tor', 'high' );
            $base['exit_lists'] = $lists;
            return $base;
        }

        // VPN / proxy / datacenter hits upgrade confidence.
        $upgraded = false;
        foreach ( array( 'vpn', 'proxy', 'datacenter', 'mobile', 'reputation' ) as $cat ) {
            if ( empty( $lists[ $cat ]['matched'] ) ) {
                continue;
            }
            $upgraded = true;
            $label    = self::label_for( $cat, '' );
            $base['reasons'][] = sprintf(
                'IP appears in uploaded %s list (%s).',
                $cat,
                (string) ( $lists[ $cat ]['source'] ?? 'unknown source' )
            );
            // Only override category when the heuristic was weaker than the
            // list-based hit.
            if ( 'high' !== $base['confidence'] ) {
                $base['category']   = $cat;
                $base['vendor']     = $label;
                $base['label']      = $label;
                $base['confidence'] = 'high';
                $base['score']      = self::score_for( $cat, 'high' );
            }
        }
        if ( $upgraded ) {
            $base['exit_lists'] = $lists;
        }
        return $base;
    }

    /**
     * Convert category/vendor into a short UI label.
     */
    private static function label_for( string $category, string $vendor ): string {
        switch ( $category ) {
            case 'vpn':
                return $vendor ? sprintf( 'VPN detected (%s)', $vendor ) : 'VPN detected';
            case 'proxy':
                return $vendor ? sprintf( 'Proxy detected (%s)', $vendor ) : 'Proxy detected';
            case 'tor':
                return 'Tor exit relay';
            case 'datacenter':
                return $vendor ? sprintf( 'Datacenter IP (%s)', $vendor ) : 'Datacenter IP';
            case 'hosting':
                return $vendor ? sprintf( 'Hosting IP (%s)', $vendor ) : 'Hosting IP';
            case 'residential':
            default:
                return 'Residential IP';
        }
    }

    /**
     * Map (category, confidence) to a numeric 0-100 score where higher
     * means more likely to be a "masking" address (VPN/proxy/tor).
     *
     * Used by the privacy-report category for the proxy key.
     */
    private static function score_for( string $category, string $confidence ): int {
        $base = array(
            'residential' => 0,
            'hosting'    => 50,
            'datacenter' => 55,
            'vpn'        => 85,
            'proxy'      => 90,
            'tor'        => 100,
        );
        $score = $base[ $category ] ?? 0;
        if ( 'medium' === $confidence ) {
            $score += 5;
        } elseif ( 'low' === $confidence && $score > 0 ) {
            $score -= 10;
        }
        return max( 0, min( 100, $score ) );
    }
}
