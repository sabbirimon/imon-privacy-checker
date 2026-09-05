# Globe textures (vendored)

These three texture images are fetched at runtime by the optional 3D globe
view in the Geo Traceroute page. They are vendored here so the plugin has
no third-party CDN dependency at page-load time — important on networks
that block unpkg.com (corporate proxies, airgapped networks, GDPR-strict
EU hosting with strict CSPs).

## Files

| File | Source | Size | License |
| --- | --- | --- | --- |
| `earth-blue-marble.jpg` | NASA Blue Marble | ~1.4 MB | Public domain (NASA imagery) |
| `earth-topology.png`    | three-globe example assets | ~380 KB | MIT (three-globe) |
| `night-sky.png`         | three-globe example assets | ~900 KB | MIT (three-globe) |

## Provenance

All three files were downloaded from the official `three-globe` npm package
(v2.33.0) at <https://unpkg.com/three-globe@2.33.0/example/img/>. The
`three-globe` package itself is MIT-licensed by Vasco Asturiano.

If you upgrade `three-globe`, re-download these from the matching version
on npm so the file format stays compatible:

```bash
cd plugin/public/assets/img/
BASE="https://unpkg.com/three-globe@<version>/example/img"
curl -sS -o earth-blue-marble.jpg "$BASE/earth-blue-marble.jpg"
curl -sS -o earth-topology.png    "$BASE/earth-topology.png"
curl -sS -o night-sky.png         "$BASE/night-sky.png"
```

## Attribution

The 3D globe view in `class-public-assets.php` references these files via
`PRIVACY_CHECKER_URL . 'public/assets/img/'`. The Geo Traceroute
page footer already credits NASA + Maxmind + IPinfo + IP2Location +
Three.js — the textures themselves are NASA-imagery (public domain) and
three-globe example assets (MIT).
