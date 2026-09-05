<?php
/**
 * Anonymity tips — practical, prioritized guidance for end users.
 *
 * NOT legal advice. NOT a guarantee. The goal is to give ordinary users a
 * short, honest menu of techniques rather than the marketing claims of any
 * single product. Each tip includes the *category* of tool expected, the
 * *user effort* required (low / medium / high), and a *why* line.
 *
 * Content lives in code (not the database) on purpose: it ships with the
 * plugin and survives in environments where the site admin can't write
 * anything beyond the bundled options.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Static content provider.
 */
final class AnonymityTips {

    /**
     * @return array<int, array<string,mixed>>
     */
    public static function all(): array {
        return array(
            // --- 1. Foundational ---
            array(
                'tier'     => 'foundational',
                'priority' => 1,
                'category' => 'network',
                'title'    => __( 'Use a reputable no-logs VPN', 'privacy-checker' ),
                'effort'   => 'low',
                'summary'  => __( 'A VPN shifts the IP the rest of the internet sees from your ISP to the VPN provider. Choose one with a published no-logs policy, RAM-only servers, and a jurisdiction outside the 5/9/14 Eyes alliances.', 'privacy-checker' ),
                'examples' => array( 'Mullvad', 'ProtonVPN', 'IVPN' ),
                'why'      => __( 'Hides your IP, your ISP, and your approximate physical location from every site you visit.', 'privacy-checker' ),
            ),
            array(
                'tier'     => 'foundational',
                'priority' => 2,
                'category' => 'browser',
                'title'    => __( 'Use a privacy-respecting browser', 'privacy-checker' ),
                'effort'   => 'low',
                'summary'  => __( 'Default browsers (Chrome, Edge, Safari) phone home and let sites fingerprint you. Firefox with privacy.resistFingerprinting, Brave, or Tor Browser are stronger defaults.', 'privacy-checker' ),
                'examples' => array( 'Firefox + resistFingerprinting', 'Brave', 'Tor Browser' ),
                'why'      => __( 'Default browsers leak canvas / WebGL / font data that uniquely identifies you across sites.', 'privacy-checker' ),
            ),
            array(
                'tier'     => 'foundational',
                'priority' => 3,
                'category' => 'dns',
                'title'    => __( 'Fix DNS leaks', 'privacy-checker' ),
                'effort'   => 'low',
                'summary'  => __( 'Even with a VPN, the operating system may still send DNS queries to your ISP. Configure your VPN client to push DNS through the tunnel, or set a system-level DNS-over-HTTPS resolver (Cloudflare 1.1.1.1, Quad9 9.9.9.9).', 'privacy-checker' ),
                'examples' => array( 'Cloudflare DoH', 'Quad9', 'Mullvad DNS' ),
                'why'      => __( 'A DNS leak reveals every site you visit to your ISP even when a VPN is active.', 'privacy-checker' ),
            ),

            // --- 2. Strong ---
            array(
                'tier'     => 'strong',
                'priority' => 4,
                'category' => 'network',
                'title'    => __( 'Use Tor for sensitive browsing', 'privacy-checker' ),
                'effort'   => 'medium',
                'summary'  => __( 'Tor routes traffic through three random relays, so no single party knows both your IP and the destination. Use it for journalism, activism, whistleblowing — not for daily high-bandwidth use.', 'privacy-checker' ),
                'examples' => array( 'Tor Browser' ),
                'why'      => __( 'Strongest IP-layer anonymity currently available to ordinary users. Slower than a VPN.', 'privacy-checker' ),
            ),
            array(
                'tier'     => 'strong',
                'priority' => 5,
                'category' => 'identity',
                'title'    => __( 'Use an anti-detect browser for multi-account work', 'privacy-checker' ),
                'effort'   => 'high',
                'summary'  => __( 'Tools like AdsPower, GoLogin, and Multilogin let you run multiple isolated browser profiles, each with its own fingerprint (canvas, fonts, WebGL, timezone, language) and its own proxy. Useful for managing distinct online identities without cross-contamination.', 'privacy-checker' ),
                'examples' => array( 'AdsPower', 'GoLogin', 'Multilogin', 'Dolphin Anty' ),
                'why'      => __( 'Websites correlate profiles by fingerprint; an anti-detect browser gives each profile a distinct, stable fingerprint and pairs it with a matching proxy.', 'privacy-checker' ),
            ),
            array(
                'tier'     => 'strong',
                'priority' => 6,
                'category' => 'proxy',
                'title'    => __( 'Pair a proxy with each identity', 'privacy-checker' ),
                'effort'   => 'medium',
                'summary'  => __( 'Each anti-detect profile should be paired with its own residential proxy. Residential proxies come from real consumer ISP addresses and are far less likely to be flagged than datacenter IPs.', 'privacy-checker' ),
                'examples' => array( 'Bright Data', 'Smartproxy', 'IPRoyal', 'Oxylabs' ),
                'why'      => __( 'Datacenter IPs are already reputation-flagged on most platforms. Residential proxies blend in with ordinary consumer traffic.', 'privacy-checker' ),
            ),

            // --- 3. Identity & accounts ---
            array(
                'tier'     => 'identity',
                'priority' => 7,
                'category' => 'email',
                'title'    => __( 'Use email aliases, not your real address', 'privacy-checker' ),
                'effort'   => 'low',
                'summary'  => __( 'Forwarding alias services give you a unique address per signup so you can revoke any single alias later.', 'privacy-checker' ),
                'examples' => array( 'SimpleLogin', 'anonaddy', 'Apple Hide My Email' ),
                'why'      => __( 'Limits which sites share your real email and stops cross-site correlation by address.', 'privacy-checker' ),
            ),
            array(
                'tier'     => 'identity',
                'priority' => 8,
                'category' => 'phone',
                'title'    => __( 'Use a virtual phone number', 'privacy-checker' ),
                'effort'   => 'medium',
                'summary'  => __( 'Most account-creation flows require a phone for SMS verification. A virtual number separates your real SIM from your online accounts.', 'privacy-checker' ),
                'examples' => array( 'JMP.chat', 'MySudo', 'Silent.Link', 'efani' ),
                'why'      => __( 'Phone numbers are a strong cross-account identifier. A virtual number stops sites from linking accounts via SIM.', 'privacy-checker' ),
            ),
            array(
                'tier'     => 'identity',
                'priority' => 9,
                'category' => 'payment',
                'title'    => __( 'Pay with cash or privacy-preserving crypto', 'privacy-checker' ),
                'effort'   => 'medium',
                'summary'  => __( 'Credit cards link purchases to your name. Cash, gift cards, or privacy coins (Monero, Zcash) cut the financial link.', 'privacy-checker' ),
                'examples' => array( 'Cash / gift cards', 'Monero (XMR)', 'Zcash (ZEC)' ),
                'why'      => __( 'Payment metadata is the most durable identifier — it survives password resets and email changes.', 'privacy-checker' ),
            ),

            // --- 4. Hardening ---
            array(
                'tier'     => 'hardening',
                'priority' => 10,
                'category' => 'browser',
                'title'    => __( 'Disable WebRTC', 'privacy-checker' ),
                'effort'   => 'low',
                'summary'  => __( 'WebRTC can expose your real local and public IP even behind a VPN. Firefox has a media.peerconnection.enabled flag; Chrome users should use an extension like uBlock Origin or WebRTC Leak Prevent.', 'privacy-checker' ),
                'examples' => array( 'about:config media.peerconnection.enabled=false', 'uBlock Origin', 'WebRTC Leak Prevent' ),
                'why'      => __( 'WebRTC bypasses the VPN tunnel for STUN traffic, leaking your real IP to any site that asks.', 'privacy-checker' ),
            ),
            array(
                'tier'     => 'hardening',
                'priority' => 11,
                'category' => 'browser',
                'title'    => __( 'Use container tabs for compartmentalization', 'privacy-checker' ),
                'effort'   => 'low',
                'summary'  => __( 'Firefox Multi-Account Containers and Chrome profiles isolate cookies, storage, and history per task (work / personal / shopping).', 'privacy-checker' ),
                'examples' => array( 'Firefox Multi-Account Containers', 'Chrome profiles' ),
                'why'      => __( 'Prevents cross-site tracking by keeping storage scoped to a task rather than a global identity.', 'privacy-checker' ),
            ),
            array(
                'tier'     => 'hardening',
                'priority' => 12,
                'category' => 'os',
                'title'    => __( 'Use a dedicated OS for sensitive work', 'privacy-checker' ),
                'effort'   => 'high',
                'summary'  => __( 'Tails is a live-boot amnesic OS that routes everything through Tor. Whonix is a VM that forces all traffic through Tor. Both are stronger than a single VPN.', 'privacy-checker' ),
                'examples' => array( 'Tails', 'Whonix', 'Qubes OS' ),
                'why'      => __( 'Removes OS-level identifiers (machine ID, hostname) and forces all network traffic through an anonymity network.', 'privacy-checker' ),
            ),
            array(
                'tier'     => 'hardening',
                'priority' => 13,
                'category' => 'network',
                'title'    => __( 'Run your own DNS resolver + VPN server', 'privacy-checker' ),
                'effort'   => 'high',
                'summary'  => __( 'A self-hosted WireGuard or OpenVPN endpoint plus a recursive DNS resolver (Unbound, Pi-hole) eliminates third-party dependencies entirely.', 'privacy-checker' ),
                'examples' => array( 'WireGuard', 'OpenVPN', 'Unbound', 'Pi-hole' ),
                'why'      => __( 'You become your own trust anchor. No VPN provider, no upstream DNS operator.', 'privacy-checker' ),
            ),

            // --- 5. Habits ---
            array(
                'tier'     => 'habits',
                'priority' => 14,
                'category' => 'behavior',
                'title'    => __( 'Don\'t log into anonymous + real identities from the same device', 'privacy-checker' ),
                'effort'   => 'high',
                'summary'  => __( 'Hardware identifiers (machine ID, MAC, GPU) tie all browser profiles on a device together. Use separate devices or VMs for separate identities.', 'privacy-checker' ),
                'examples' => array( 'Tails USB stick', 'Whonix VM', 'Separate cheap laptop' ),
                'why'      => __( 'Hardware IDs are invisible to the browser but visible to advanced anti-fraud systems.', 'privacy-checker' ),
            ),
            array(
                'tier'     => 'habits',
                'priority' => 15,
                'category' => 'behavior',
                'title'    => __( 'Don\'t share writing style across identities', 'privacy-checker' ),
                'effort'   => 'high',
                'summary'  => __( 'Stylometric analysis can identify authors from a few hundred words. Switch writing style, language, or have a friend write for an anonymous identity.', 'privacy-checker' ),
                'examples' => array( 'Different vocabulary', 'Different punctuation habits', 'Translation round-trip' ),
                'why'      => __( 'A unique writing style is a fingerprint you carry with every post, even on a fresh account.', 'privacy-checker' ),
            ),
        );
    }

    /**
     * Group tips by tier for the UI.
     *
     * @return array<string, array<int, array<string,mixed>>>
     */
    public static function by_tier(): array {
        $out = array(
            'foundational' => array(),
            'strong'       => array(),
            'identity'     => array(),
            'hardening'    => array(),
            'habits'       => array(),
        );
        foreach ( self::all() as $tip ) {
            $tier = (string) ( $tip['tier'] ?? 'foundational' );
            if ( ! isset( $out[ $tier ] ) ) {
                $out[ $tier ] = array();
            }
            $out[ $tier ][] = $tip;
        }
        return $out;
    }

    /**
     * Tier label map for UI rendering.
     *
     * @return array<string,string>
     */
    public static function tier_labels(): array {
        return array(
            'foundational' => __( 'Foundational', 'privacy-checker' ),
            'strong'       => __( 'Strong', 'privacy-checker' ),
            'identity'     => __( 'Identity & Accounts', 'privacy-checker' ),
            'hardening'    => __( 'Hardening', 'privacy-checker' ),
            'habits'       => __( 'Habits', 'privacy-checker' ),
        );
    }

    /**
     * Effort label map for UI rendering.
     *
     * @return array<string,string>
     */
    public static function effort_labels(): array {
        return array(
            'low'    => __( 'Low effort', 'privacy-checker' ),
            'medium' => __( 'Medium effort', 'privacy-checker' ),
            'high'   => __( 'High effort', 'privacy-checker' ),
        );
    }
}
