# Leaflet (vendored)

These two files are vendored copies of Leaflet 1.9.4, an open-source
JavaScript library for interactive maps. They are bundled with this
plugin so the public frontend has no `unpkg.com` page-load
dependency for Leaflet (matching the existing self-host pattern for
three.js / three-globe / globe-textures).

## Files

| File | Source | Size | License |
| --- | --- | --- | --- |
| `plugin/public/assets/css/leaflet.css` | unpkg.com/leaflet@1.9.4 | ~14 KB | BSD-2-Clause |
| `plugin/public/assets/js/leaflet.js`   | unpkg.com/leaflet@1.9.4 | ~148 KB | BSD-2-Clause |

## Provenance

Both files were downloaded from the official Leaflet 1.9.4 distribution
at <https://unpkg.com/leaflet@1.9.4/dist/>. The `leaflet.js` package
itself is BSD-2-Clause licensed by Vladimir Agafonkin (with copyright
shared with CloudMade for early work).

If you upgrade Leaflet, re-download these from the matching version
on npm so the file format stays compatible:

```bash
cd plugin/public/assets/
BASE="https://unpkg.com/leaflet@<version>/dist"
curl -sS -o css/leaflet.css "$BASE/leaflet.css"
curl -sS -o js/leaflet.js   "$BASE/leaflet.js"
```

## BSD-2-Clause license text

```
Copyright (c) 2010-2023, Vladimir Agafonkin
Copyright (c) 2010-2011, CloudMade
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
```

## Attribution

The Leaflet CSS/JS files are loaded by `class-public-assets.php` via
`PRIVACY_CHECKER_URL . 'public/assets/{css,js}/leaflet.{css,js}'`.
Leaflet is also credited alongside other open-source dependencies in
the Geo Traceroute page footer.
