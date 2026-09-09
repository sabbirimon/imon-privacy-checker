# GeoTrace Page — Page Override

> Extends `../MASTER.md`. Document only what's specific to this page.

## Truthfulness contract

The GeoTrace page must obey these rules **at all times**:

1. **A real traceroute, when available, drives the visualisation.** If
   the server can execute `/usr/sbin/traceroute` and `shell_exec` is
   enabled, the backend runs it against the target (public host only)
   and parses the output into ordered hops. Each hop IP is geolocated
   via the existing `IpFallback` provider. **No fabricated hops.**
2. **Unanswered hops (`*`) are kept in order with NO coordinates.** They
   appear in the hop timeline as `Hop 3 — no response`. The polyline
   skips them with a dashed gap segment.
3. **Private / loopback / link-local IPs are marked `Private` and never
   geolocated.** They appear in the timeline with a neutral chip; the
   polyline skips them with a dashed gap segment.
4. **Probe location is the WP server's own geo** (from its public IP),
   not the visitor's. The page must clearly label this as the probe:
   `Probe: <city>, <country>`.
5. **2D map and 3D globe read from the same `route` object.** No parallel
   route generators.
6. **Geolocation confidence is shown per hop** (High / Medium / Low /
   Unknown) because IP geolocation is not GPS.
7. **Hop labels never claim "the packet physically travelled along this
   line."** The page labels the visualisation as
   "Approximate geographic visualization of traceroute hops."
8. **When no traceroute can be obtained**, the page does **not** draw a
   fake route. It shows an honest empty state with:
   - The probe location and IP.
   - The reason traceroute could not run (e.g. "shell_exec disabled" or
     "binary missing" or "target unreachable").
   - A "Paste your own traceroute" form that accepts Linux `traceroute`,
     Windows `tracert`, or MTR output.
   - The same parser/geolocation pipeline runs on the pasted output.

## Canonical route object

```js
const route = {
    probe:    { ip, hostname, city, country, country_code, lat, lon, asn, isp, confidence },
    target:   { hostname, ip, city, country, country_code, lat, lon, asn, isp, confidence },
    hops: [
        {
            index: 1,
            ip: '203.0.113.7',          // may be null for unanswered hops
            hostname: 'router.isp.net', // may be null
            rtt_ms: 4.2,                // may be null
            city: 'Singapore',          // null if not geolocatable
            country: 'Singapore',
            country_code: 'SG',
            lat: 1.3521,                // null if private / unanswered / unknown
            lon: 103.8198,
            asn: 'AS12345',
            isp: 'Example ISP',
            confidence: 'medium',       // high | medium | low | unknown
            status: 'public',           // public | private | unanswered
        },
        // ...
    ],
    source_kind: 'real-traceroute' | 'pasted-traceroute' | 'unavailable',
    generated_at: '2026-09-09T10:00:00Z',
};
```

## Single-render pipeline

```js
function renderRoute(route) {
    const coords = routeCoordinates(route);   // builds the ordered lat/lon array
    renderSummary(route);                     // probe, target, hop count, distance, AS path
    renderHopTimeline(route);                 // right rail
    render2DMap(coords, route);               // Leaflet
    render3DGlobe(coords, route);             // three.js — same coords array
    renderLegend();
    renderEmptyStateIfNeeded(route);
}
```

`routeCoordinates(route)` returns `null` for a hop with no coordinates
(unanswered / private) and `render2DMap` / `render3DGlobe` MUST treat
`null` as a gap (no segment drawn).

## Map visual rules

- Origin marker: small ring, color `--pc-text`.
- Destination marker: filled, color `--pc-action`.
- Each intermediate hop marker: numbered circle, color band by RTT
  (green < 30 ms, amber 30–80 ms, red > 80 ms).
- Route polyline: solid for adjacent hops that both have coordinates;
  dashed gap when one is missing; the next solid segment starts at the
  next geolocatable hop.
- Hovering a marker highlights the matching timeline row; clicking a
  marker scrolls/focuses the timeline row.
- Clicking a timeline row flies the map to that hop and pulses the
  marker.

## 3D globe

- Same markers, same polyline rules as 2D.
- The packet animation walks `routeCoordinates(route)` step-by-step at
  1.2 s per hop. It MUST step (no interpolation) under
  `prefers-reduced-motion: reduce`.
- The "current hop" label updates on each step. The animation does not
  play when the route has fewer than 2 geolocatable hops — the globe
  shows the static route instead.

## Hop timeline

Each row:

```text
01  router.isp.net
    Singapore, SG
    AS12345 · Example ISP
    4.2 ms
```

Latency jump: if `rtt_ms[i] > 1.5 * rtt_ms[i-1]` and both values exist,
add a `data-pc-latency-jump="true"` flag, render a `LATENCY JUMP`
chip, and color the RTT in `--pc-status-medium` (text label included).
Do NOT attribute the cause to a specific router — IP geolocation is not
physical.

## Paste-traceroute form

Accepts Linux `traceroute`, Windows `tracert`, and MTR-style output.
Parser is best-effort; on failure, show a clear error and do not draw
a route.

The parsed output produces the same `route` object the live traceroute
path produces, so the rest of the render pipeline is unchanged.

## What this page does NOT do

- Does not invent hops when traceroute fails.
- Does not draw lines through coordinates that don't exist.
- Does not claim the route is the user's physical network path when
  it's actually the WP server's outbound route.
- Does not label any hop's coordinates as "GPS" — confidence chip is
  always present.
- Does not pre-render markers for hops that the backend never returned.
