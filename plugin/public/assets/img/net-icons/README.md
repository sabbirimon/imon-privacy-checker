# Network-path device icons (vendored)

Five SVG icons used by the Network Path card on the Geo Traceroute
page. Each icon is rendered as a data URI inside an SVG `<image>`
element with a per-device coloured badge behind it.

## Files

| File | Source | License |
| --- | --- | --- |
| `iServer.svg`      | Clean-room original | MIT (this plugin) |
| `iRouter.svg`      | Clean-room original | MIT (this plugin) |
| `iSwitch.svg`      | Clean-room original | MIT (this plugin) |
| `iWorkstation.svg` | Clean-room original | MIT (this plugin) |
| `iHub.svg`         | Clean-room original | MIT (this plugin) |

## Why originals, not a vendored library

Earlier versions of this plugin fetched these icons as PNGs from
`raw.githubusercontent.com/tmusabaika/minimalistic-networking-icons`.
That repo ships a useful icon set, but it has **no LICENSE file** —
vendoring the PNGs into a public plugin would have been a license
violation. Phase 9 / Item B replaced those PNGs with five clean-room
SVG originals (hand-drawn, MIT-licensed to match the plugin), so the
Network Path card now has no third-party icon CDN dependency.

## Mapping

The Network Path card maps device roles to icons via `PC_ICON_MAP`
in `plugin/public/assets/js/scanner.js`. The keys are unchanged
from the previous PNG-based version, so the icon-to-role mapping
stays identical:

| Role         | Icon |
| ---          | --- |
| device       | `iWorkstation.svg` |
| mobile       | `iWorkstation.svg` |
| tablet       | `iWorkstation.svg` |
| pc           | `iWorkstation.svg` |
| home-router  | `iRouter.svg` |
| router       | `iRouter.svg` |
| server       | `iServer.svg` |
| switch       | `iSwitch.svg` |
| firewall     | `iSwitch.svg` (with red overlay) |
| vpn          | `iRouter.svg` (with lock overlay) |
| tor          | `iServer.svg` (with onion overlay) |
| destination  | `iServer.svg` |
| hub          | `iHub.svg` |
| cell-tower   | `iHub.svg` (with tower overlay) |
| satellite    | `iHub.svg` (with dish overlay) |

## MIT license text (this plugin)

```
MIT License

Copyright (c) 2024-present IMON Privacy Checker contributors

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject
to the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
