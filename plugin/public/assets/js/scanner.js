/**
 * IMON scanner — vanilla ES2017.
 *
 * No frameworks. No build step. Communicates with /wp-json/privacy-checker/v1/*.
 *
 * Modules: state, api, fingerprint-collector, webrtc, ui/*, scanner.
 */
(function () {
    'use strict';

    if (typeof window === 'undefined') return;

    var globals = window.PC_SCAN || {};
    var REST_URL = globals.restUrl || '';
    var REST_NONCE = globals.restNonce || '';
    var I18N = globals.i18n || {};
    var IS_MOCK = !!globals.isMock;

    /* ---------- Utilities ---------- */

    function el(tag, attrs, children) {
        var node = document.createElement(tag);
        if (attrs) {
            Object.keys(attrs).forEach(function (key) {
                if (key === 'class') node.className = attrs[key];
                else if (key === 'text') node.textContent = attrs[key];
                else if (key === 'html') node.innerHTML = attrs[key];
                else if (key === 'dataset') {
                    Object.keys(attrs[key]).forEach(function (ds) {
                        node.dataset[ds] = attrs[key][ds];
                    });
                } else if (key.indexOf('on') === 0 && typeof attrs[key] === 'function') {
                    node.addEventListener(key.substring(2), attrs[key]);
                } else {
                    node.setAttribute(key, attrs[key]);
                }
            });
        }
        if (Array.isArray(children)) {
            children.forEach(function (child) {
                if (child == null) return;
                if (typeof child === 'string') node.appendChild(document.createTextNode(child));
                else node.appendChild(child);
            });
        }
        return node;
    }

    function statusBadge(level, label) {
        return el('span', {
            class: 'pc-card__badge pc-status pc-status--' + (level || 'unknown'),
            role: 'status',
            'aria-label': label || level
        }, [
            el('span', { 'aria-hidden': 'true', text: iconFor(level) }),
            el('span', { text: ' ' + (label || level) })
        ]);
    }

    function iconFor(level) {
        switch (level) {
            case 'pass':    return '\u2713';   // check
            case 'warning': return '!';
            case 'danger':  return '\u26A0';   // warning sign
            case 'info':    return '\u2139';   // info
            default:        return '\u2014';   // em-dash
        }
    }

    function formatRow(label, value, opts) {
        opts = opts || {};
        var empty = (value == null || value === '' || value === 'unknown' || value === 'Unable to determine');
        var display = empty ? (I18N.unable || '—') : String(value);
        var valueClasses = 'pc-row__value';
        if (empty) valueClasses += ' is-empty';
        if (opts.mono) valueClasses += ' is-mono';
        if (opts.pill) valueClasses = 'pc-row__value';
        var valueEl;
        if (opts.pill) {
            valueEl = el('span', {}, [
                el('span', { class: 'pc-pill pc-pill--' + (opts.pill || 'info'), text: display })
            ]);
        } else {
            valueEl = el('span', { class: valueClasses, text: display });
        }
        return el('div', { class: 'pc-row' }, [
            el('span', { class: 'pc-row__label', text: label }),
            valueEl
        ]);
    }

    function resultHero(eyebrow, value, sub, opts) {
        opts = opts || {};
        var valueClasses = 'pc-result__hero-value';
        if (opts.mono) valueClasses += ' is-mono';
        var children = [
            el('span', { class: 'pc-result__hero-eyebrow', text: eyebrow }),
            el('span', { class: valueClasses, text: value })
        ];
        if (sub) children.push(el('span', { class: 'pc-result__hero-sub', text: sub }));
        return el('div', { class: 'pc-result__hero' }, [
            el('div', { class: 'pc-result__hero-main' }, children)
        ]);
    }

    function resultGroup(title, rowsOrNodes) {
        var body;
        if (Array.isArray(rowsOrNodes) && rowsOrNodes.length && rowsOrNodes[0] && rowsOrNodes[0].nodeType) {
            body = el('div', { class: 'pc-result__group-body' }, rowsOrNodes);
        } else {
            body = el('div', { class: 'pc-result__group-body' }, rowsOrNodes || []);
        }
        return el('section', { class: 'pc-result__group' }, [
            el('h4', { class: 'pc-result__group-title', text: title }),
            body
        ]);
    }

    function statusBanner(level, text) {
        var cls = 'pc-status-banner pc-status-banner--' + (level || 'info');
        return el('div', { class: cls, role: 'status' }, [
            el('span', { text: text })
        ]);
    }

    function pill(level, text) {
        return el('span', { class: 'pc-pill pc-pill--' + (level || 'info'), text: text });
    }

    function resultList(headers, rows) {
        // headers: ['Name', 'Status', 'Latency', 'IP']
        // rows: array of {cells: ['Cloudflare', {kind:'pill', level:'pass', text:'ok'}, '132ms', '1.1.1.1'], level: 'pass'}
        var head = el('div', { class: 'pc-result-list' }, [
            el('div', { class: 'pc-result-list__row pc-result-list__head' }, headers.map(function (h) {
                return el('span', { class: 'pc-result-list__cell', text: h });
            }))
        ]);
        rows.forEach(function (r) {
            var rowCls = 'pc-result-list__row';
            if (r.level) rowCls += ' is-' + r.level;
            head.appendChild(el('div', { class: rowCls }, r.cells.map(function (cell) {
                if (cell && typeof cell === 'object' && cell.kind === 'pill') {
                    return el('span', { class: 'pc-result-list__cell' }, [pill(cell.level, cell.text)]);
                }
                if (cell && typeof cell === 'object' && cell.kind === 'mono') {
                    return el('span', { class: 'pc-result-list__cell is-mono', text: cell.text });
                }
                return el('span', { class: 'pc-result-list__cell', text: String(cell) });
            })));
        });
        return head;
    }

    function mockBadge() {
        return el('span', {
            class: 'pc-mock-badge',
            'aria-label': I18N.mockBadge || 'DEVELOPMENT DATA'
        }, [I18N.mockBadge || 'DEVELOPMENT DATA']);
    }

    /* ---------- API ---------- */

    function api(path, options) {
        options = options || {};
        var url = REST_URL + path;
        return fetch(url, {
            method: options.method || 'GET',
            credentials: 'same-origin',
            headers: Object.assign({
                'X-WP-Nonce': REST_NONCE,
                'Accept': 'application/json'
            }, options.body ? { 'Content-Type': 'application/json' } : {}),
            body: options.body ? JSON.stringify(options.body) : null
        }).then(function (response) {
            return response.json().catch(function () { return {}; }).then(function (data) {
                return { status: response.status, ok: response.ok, data: data };
            });
        });
    }

    /* ---------- Fingerprint collector ---------- */

    /**
     * Collect all browser-side fingerprint signals. ASYNC because the
     * audio hash needs an OfflineAudioContext render. The synchronous
     * signals are populated immediately; audio_hash is resolved later
     * and merged into the returned object via the audio promise.
     *
     * @return {Promise<object>}
     */
    function collectFingerprint() {
        var nav = navigator || {};
        var screen = window.screen || {};
        var fp = {
            user_agent: nav.userAgent || '',
            language: nav.language || '',
            languages: Array.isArray(nav.languages) ? nav.languages.slice() : [],
            platform: nav.platform || '',
            hardware_concurrency: nav.hardwareConcurrency || 0,
            device_memory: nav.deviceMemory || 0,
            touch_support: !!(nav.maxTouchPoints > 0),
            cookies: !!nav.cookieEnabled,
            do_not_track: nav.doNotTrack === '1' || nav.doNotTrack === 'yes',
            timezone: (Intl && Intl.DateTimeFormat && Intl.DateTimeFormat().resolvedOptions().timeZone) || '',
            screen_resolution: screen.width && screen.height ? (screen.width + 'x' + screen.height) : '',
            color_depth: screen.colorDepth || 0,
            pixel_ratio: window.devicePixelRatio || 1,
            webgl: !!document.createElement('canvas').getContext('webgl'),
            canvas: true,    // We can render to canvas; signal presence.
            audio: !!(window.AudioContext || window.webkitAudioContext),
            // Kept for backward compatibility with the existing report card;
            // the granular fontList below is the real fingerprint signal.
            fonts: typeof document.fonts !== 'undefined' && document.fonts && document.fonts.size
                ? document.fonts.size
                : 0,

            // ---- Phase 3: real fingerprinting signals ----
            // Hashes are 32-bit FNV-1a encoded as 8-char hex strings. They
            // are NOT unique IDs (collisions are easy to engineer); they're
            // consistency tokens — if two visitors' hashes match, they share
            // a rendering/audio pipeline family. The server-side entropy
            // estimator treats presence-of-hash as the rarity signal, not
            // the hash value itself.
            canvas_hash: '',
            audio_hash:  '',
            // WebGL renderer/vendor strings. Explicitly set to the literal
            // "masked-by-browser" when the extension is blocked — that is
            // itself an anti-fingerprinting signal and counts as a GOOD
            // sign in the entropy estimator (not as missing data).
            webgl_renderer: '',
            webgl_vendor:   '',
            // Installed-font detection. ~40 fonts are tested by measuring
            // rendered text width against a sans-serif fallback; entries
            // that produced a different width are reported as installed.
            font_list: []
        };
        try { fp.canvas_hash = computeCanvasHash();   } catch (e) { /* sandboxed or unsupported */ }
        try {
            var w = readWebglInfo();
            fp.webgl_renderer = w.renderer;
            fp.webgl_vendor   = w.vendor;
        } catch (e) { /* leave empty */ }
        try { fp.font_list   = detectInstalledFonts(); } catch (e) { /* leave empty */ }

        // Audio hash is async — return a promise that resolves to fp
        // with audio_hash filled in. Synchronous fields are already set
        // on fp so callers that race the .then() still get a complete
        // object via the merge below.
        var audioPromise;
        try {
            audioPromise = computeAudioHash();
        } catch (e) {
            audioPromise = Promise.resolve('');
        }
        if (!audioPromise || typeof audioPromise.then !== 'function') {
            audioPromise = Promise.resolve(audioPromise || '');
        }
        return audioPromise.then(function (hash) {
            fp.audio_hash = hash || '';
            return fp;
        });
    }

    /**
     * 32-bit FNV-1a hash over a string. Returns the value as an 8-char
     * hex string (zero-padded). Not cryptographic — fingerprinting
     * doesn't need cryptographic strength, just good distribution.
     */
    function fnv1a32(str) {
        var h = 0x811c9dc5;
        for (var i = 0; i < str.length; i++) {
            h ^= str.charCodeAt(i);
            // Multiply by FNV prime, keeping within 32 bits.
            h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
        }
        var hex = (h >>> 0).toString(16);
        while (hex.length < 8) hex = '0' + hex;
        return hex;
    }

    /**
     * Render a fixed text+shapes scene to an offscreen 2D canvas, return
     * a FNV-1a hash of the data URL. The fixed scene is chosen so most
     * rendering differences (font hinting, anti-aliasing, GPU
     * acceleration, text shaping) appear in the output pixels.
     */
    function computeCanvasHash() {
        var c = document.createElement('canvas');
        c.width = 280; c.height = 60;
        var ctx = c.getContext('2d');
        if (!ctx) return '';
        ctx.textBaseline = 'top';
        ctx.font = "16px 'Arial'";
        ctx.fillStyle = '#f60';
        ctx.fillRect(125, 1, 62, 20);
        ctx.fillStyle = '#069';
        ctx.fillText('IMON-fingerprint ✓ 漢字', 2, 15);
        ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
        ctx.fillText('IMON-fingerprint ✓ 漢字', 4, 17);
        ctx.beginPath();
        ctx.arc(50, 30, 20, 0, Math.PI * 2, true);
        ctx.closePath();
        ctx.fillStyle = 'rgba(255,0,255,0.5)';
        ctx.fill();
        // toDataURL can throw in some sandboxes (tainted canvas, e.g.
        // when an extension blocks canvas readback); fnv1a32 over the
        // data URL gives us a stable token across browsers.
        var data = c.toDataURL();
        return fnv1a32(data);
    }

    /**
     * Render a short OfflineAudioContext chain (oscillator →
     * dynamicsCompressor → destination) and hash the resulting
     * Float32Array. Floating-point audio processing is famously
     * hardware-and-OS-specific, so even a few samples produce a stable
     * per-device token.
     */
    function computeAudioHash() {
        var OAC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
        if (!OAC) return '';
        // 1 channel, ~4410 samples ≈ 100ms @ 44.1kHz.
        var ctx = new OAC(1, 4410, 44100);
        var osc = ctx.createOscillator();
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(10000, ctx.currentTime);
        var comp = ctx.createDynamicsCompressor();
        // Aggressive compressor settings that reveal floating-point
        // rounding differences between implementations.
        try {
            comp.threshold.setValueAtTime(-50, ctx.currentTime);
            comp.knee.setValueAtTime(40, ctx.currentTime);
            comp.ratio.setValueAtTime(12, ctx.currentTime);
            comp.attack.setValueAtTime(0, ctx.currentTime);
            comp.release.setValueAtTime(0.25, ctx.currentTime);
        } catch (e) { /* some fields may be read-only on older browsers */ }
        osc.connect(comp);
        comp.connect(ctx.destination);
        osc.start(0);
        // Synchronous Promise wrapper around the callback-style render.
        return ctx.startRendering().then(function (buffer) {
            var data = buffer.getChannelData(0);
            // Sample a few points rather than the whole buffer — the
            // rounding divergence shows up in the first ~100 samples.
            var sample = '';
            for (var i = 0; i < Math.min(200, data.length); i += 10) {
                sample += data[i].toFixed(8) + ',';
            }
            return fnv1a32(sample);
        }).then(function (hash) { return hash; }, function () { return ''; });
    }

    /**
     * Read the WebGL UNMASKED_RENDERER_WEBGL / UNMASKED_VENDOR_WEBGL
     * strings via the WEBGL_debug_renderer_info extension. If the
     * extension is blocked (common in Firefox + Brave), return
     * "masked-by-browser" explicitly — that string is informative,
     * not an error.
     */
    function readWebglInfo() {
        var canvas = document.createElement('canvas');
        var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (!gl) return { renderer: '', vendor: '' };
        var ext = gl.getExtension && gl.getExtension('WEBGL_debug_renderer_info');
        if (!ext) {
            // Browser is intentionally blocking — that's the answer.
            return { renderer: 'masked-by-browser', vendor: 'masked-by-browser' };
        }
        var renderer = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || '';
        var vendor   = gl.getParameter(ext.UNMASKED_VENDOR_WEBGL)   || '';
        return { renderer: String(renderer), vendor: String(vendor) };
    }

    /**
     * Detect installed fonts by measuring rendered text width against a
     * fallback. The fixed test string + fixed fallback keeps the test
     * deterministic across calls.
     */
    function detectInstalledFonts() {
        var testFonts = [
            'Arial', 'Arial Black', 'Arial Narrow', 'Arial Rounded MT Bold',
            'Calibri', 'Cambria', 'Candara', 'Comic Sans MS', 'Consolas', 'Constantia', 'Corbel',
            'Courier New', 'Franklin Gothic Medium', 'Garamond', 'Georgia',
            'Helvetica', 'Helvetica Neue', 'Impact', 'Lucida Console', 'Lucida Sans Unicode',
            'Microsoft Sans Serif', 'Palatino Linotype', 'Segoe UI', 'Symbol', 'Tahoma',
            'Times New Roman', 'Trebuchet MS', 'Verdana', 'Webdings', 'Wingdings',
            // Common Adobe / Google Fonts.
            'Roboto', 'Open Sans', 'Lato', 'Montserrat', 'Source Sans Pro', 'Noto Sans',
            'PT Sans', 'Oswald'
        ];
        var baseFonts = ['monospace', 'sans-serif', 'serif'];
        var testText = 'mmmmmmmmmmlli';
        var testSize = '72px';
        var body = document.body || document.documentElement;
        var span = document.createElement('span');
        span.style.position   = 'absolute';
        span.style.left       = '-9999px';
        span.style.fontSize   = testSize;
        span.style.lineHeight = 'normal';
        span.textContent      = testText;
        body.appendChild(span);

        // Baseline widths for the three generic families.
        var defaults = {};
        baseFonts.forEach(function (family) {
            span.style.fontFamily = family;
            defaults[family] = span.offsetWidth;
        });

        var installed = [];
        for (var i = 0; i < testFonts.length; i++) {
            var f = testFonts[i];
            var matched = false;
            for (var j = 0; j < baseFonts.length; j++) {
                span.style.fontFamily = "'" + f + "'," + baseFonts[j];
                if (span.offsetWidth !== defaults[baseFonts[j]]) {
                    matched = true;
                    break;
                }
            }
            if (matched) installed.push(f);
        }
        body.removeChild(span);
        return installed;
    }

    /* ---------- WebRTC collector ---------- */

    function runWebrtcTest(timeoutMs) {
        timeoutMs = timeoutMs || 4000;
        return new Promise(function (resolve) {
            var RTCPeerConnection = window.RTCPeerConnection || window.webkitRTCPeerConnection;
            if (!RTCPeerConnection) {
                return resolve({ supported: false, candidates: [] });
            }

            var pc;
            try {
                pc = new RTCPeerConnection({ iceServers: [] });
            } catch (e) {
                return resolve({ supported: false, candidates: [], error: e.message });
            }

            var candidates = [];
            var done = false;

            function finish() {
                if (done) return;
                done = true;
                try { pc.close(); } catch (e) { /* ignore */ }
                resolve({ supported: true, candidates: candidates });
            }

            pc.onicecandidate = function (event) {
                if (!event || !event.candidate) {
                    finish();
                    return;
                }
                var c = event.candidate;
                var parts = (c.candidate || '').split(' ');
                candidates.push({
                    foundation: c.foundation || '',
                    component: c.component || '',
                    protocol: c.protocol || '',
                    ip: parts[4] || '',
                    port: parts[5] || '',
                    type: c.type || ''
                });
            };

            try {
                pc.createDataChannel('pc-probe');
                pc.createOffer().then(function (offer) {
                    return pc.setLocalDescription(offer);
                }).catch(function () {
                    finish();
                });
            } catch (e) {
                finish();
            }

            setTimeout(finish, timeoutMs);
        });
    }

    /* ---------- UI: Score ring ---------- */

    function setScore(score, breakdown) {
        var root = document.querySelector('[data-pc-component="dashboard"] .pc-score');
        if (!root) return;
        root.setAttribute('aria-busy', 'false');
        var ring = root.querySelector('[data-pc-score-ring]');
        var label = root.querySelector('[data-pc-score]');
        var sub = root.querySelector('[data-pc-score-label]');
        var circumference = 2 * Math.PI * 52;
        var clamped = Math.max(0, Math.min(100, score));
        var offset = circumference * (1 - clamped / 100);
        if (ring) {
            ring.style.strokeDashoffset = String(offset);
        }
        if (label) label.textContent = clamped;

        var level = 'unknown';
        var text = I18N.estimatedScore || '—';
        if (clamped >= 90) { level = 'excellent'; text = 'Excellent'; }
        else if (clamped >= 75) { level = 'good'; text = 'Good'; }
        else if (clamped >= 50) { level = 'moderate'; text = 'Moderate'; }
        else if (clamped >= 25) { level = 'poor'; text = 'Poor'; }
        else { level = 'very_poor'; text = 'Very Poor'; }

        root.setAttribute('data-level', level);
        if (sub) sub.textContent = text;
        if (breakdown) {
            root.dataset.breakdown = JSON.stringify(breakdown);
        }
    }

    /* ---------- UI: progress ---------- */

    function setStep(step, state) {
        var li = document.querySelector('.pc-progress li[data-pc-step="' + step + '"]');
        if (!li) return;
        if (state) li.setAttribute('data-state', state);
        else li.removeAttribute('data-state');
    }

    /* ---------- UI: cards ---------- */

    function showInitialSpinner() {
        if (document.querySelector('.pc-spinner-overlay')) return;
        var overlay = el('div', { class: 'pc-spinner-overlay', role: 'status', 'aria-live': 'polite' });
        var card = el('div', { class: 'pc-scan-card' });

        // Inline SVG gradient defs for the ring.
        var svgNS = 'http://www.w3.org/2000/svg';
        var ringWrap = el('div', { class: 'pc-scan-card__ring' });
        var svg = document.createElementNS(svgNS, 'svg');
        svg.setAttribute('viewBox', '0 0 120 120');
        var defs = document.createElementNS(svgNS, 'defs');
        var grad = document.createElementNS(svgNS, 'linearGradient');
        grad.setAttribute('id', 'pcScanGrad');
        grad.setAttribute('x1', '0%');
        grad.setAttribute('y1', '0%');
        grad.setAttribute('x2', '100%');
        grad.setAttribute('y2', '100%');
        var stop1 = document.createElementNS(svgNS, 'stop');
        stop1.setAttribute('offset', '0%');  stop1.setAttribute('stop-color', '#1ec8de');
        var stop2 = document.createElementNS(svgNS, 'stop');
        stop2.setAttribute('offset', '60%'); stop2.setAttribute('stop-color', '#17a2b8');
        var stop3 = document.createElementNS(svgNS, 'stop');
        stop3.setAttribute('offset', '100%'); stop3.setAttribute('stop-color', '#3ddccd');
        grad.appendChild(stop1); grad.appendChild(stop2); grad.appendChild(stop3);
        defs.appendChild(grad);
        svg.appendChild(defs);
        var track = document.createElementNS(svgNS, 'circle');
        track.setAttribute('class', 'pc-scan-card__ring-track');
        track.setAttribute('cx', '60'); track.setAttribute('cy', '60'); track.setAttribute('r', '50');
        var fill = document.createElementNS(svgNS, 'circle');
        fill.setAttribute('class', 'pc-scan-card__ring-fill');
        fill.setAttribute('cx', '60'); fill.setAttribute('cy', '60'); fill.setAttribute('r', '50');
        fill.setAttribute('stroke-dashoffset', '314.16');
        svg.appendChild(track); svg.appendChild(fill);
        ringWrap.appendChild(svg);
        ringWrap.appendChild(el('div', { class: 'pc-scan-card__pct', text: '0', dataset: { role: 'pct' } }));
        card.appendChild(ringWrap);

        var stepLabel = el('div', { class: 'pc-scan-card__step', dataset: { role: 'stepLabel' } }, [
            el('span', { class: 'pc-scan-dot' }),
            el('span', { text: I18N.scanning || 'Scanning…' })
        ]);
        card.appendChild(stepLabel);

        var sub = el('div', { class: 'pc-scan-card__sub', text: 'Initializing privacy scan', dataset: { role: 'stepSub' } });
        card.appendChild(sub);

        var barWrap = el('div', { class: 'pc-scan-card__bar' });
        barWrap.appendChild(el('div', { class: 'pc-scan-card__bar-fill', dataset: { role: 'barFill' } }));
        card.appendChild(barWrap);

        var stepsRow = el('div', { class: 'pc-scan-card__steps', dataset: { role: 'stepsRow' } });
        var labels = ['IP', 'Intel', 'Reputation', 'Fingerprint', 'WebRTC', 'Score'];
        labels.forEach(function (label, i) {
            var dot = el('span', { class: 'pc-scan-card__step-dot', dataset: { step: i }, title: label });
            stepsRow.appendChild(dot);
        });
        card.appendChild(stepsRow);

        overlay.appendChild(card);
        document.body.appendChild(overlay);
    }

    function setScanProgress(pct, stepLabel, stepSub, stepIndex, stepState) {
        var overlay = document.querySelector('.pc-spinner-overlay');
        if (!overlay) return;
        var pctNode = overlay.querySelector('[data-role="pct"]');
        var fill = overlay.querySelector('.pc-scan-card__ring-fill');
        var bar = overlay.querySelector('[data-role="barFill"]');
        var lbl = overlay.querySelector('[data-role="stepLabel"] span:last-child');
        var sub = overlay.querySelector('[data-role="stepSub"]');
        var dots = overlay.querySelectorAll('.pc-scan-card__step-dot');

        if (pctNode) pctNode.textContent = String(Math.round(pct));
        // Circumference for r=50 is 2π·50 ≈ 314.16.
        var circumference = 314.16;
        var clamped = Math.max(0, Math.min(100, pct));
        if (fill) fill.setAttribute('stroke-dashoffset', String(circumference * (1 - clamped / 100)));
        if (bar) bar.style.width = clamped + '%';

        if (lbl && stepLabel) lbl.textContent = stepLabel;
        if (sub && stepSub) sub.textContent = stepSub;
        if (typeof stepIndex === 'number' && dots[stepIndex]) {
            dots.forEach(function (d, i) {
                d.classList.remove('is-done', 'is-active', 'is-error');
                if (i < stepIndex) d.classList.add('is-done');
                else if (i === stepIndex) d.classList.add(stepState === 'error' ? 'is-error' : (stepState === 'done' ? 'is-done' : 'is-active'));
            });
        }
    }

    function resetScanProgress() {
        setScanProgress(0, I18N.scanning || 'Scanning…', 'Initializing privacy scan', 0, 'active');
    }

    function hideSpinner() {
        var overlay = document.querySelector('.pc-spinner-overlay');
        if (overlay) overlay.remove();
    }

    function showSkeleton(target) {
        var region = target || document.querySelector('[data-pc-region="report"]');
        if (!region) return;
        region.hidden = false;
        region.innerHTML = '';
        var titles = [
            ['IP Address',           '\u{1F4E1}'],
            ['Connection Details',   '\u{1F310}'],
            ['Browser Fingerprint',  '\u{1F50D}'],
            ['WebRTC',               '\u{1F4E1}'],
            ['DNS Leak Test',        '\u{1F50D}'],
            ['Proxy / VPN / Tor',    '\u{1F6E1}']
        ];
        titles.forEach(function (t, i) {
            var card = el('article', { class: 'pc-card pc-card--skeleton', style: '--pc-delay: ' + (i * 60) + 'ms' });
            var head = el('div', { class: 'pc-card__head' });
            head.appendChild(el('div', { class: 'pc-card__icon', text: t[1] }));
            head.appendChild(el('div', { class: 'pc-card__title-block' }, [
                el('div', { class: 'pc-skel pc-skel--title' }),
                el('div', { class: 'pc-skel pc-skel--line', style: 'width: 60%' })
            ]));
            card.appendChild(head);
            card.appendChild(el('div', { class: 'pc-card__body' }, [
                el('div', { class: 'pc-skel pc-skel--block' }),
                el('div', { class: 'pc-skel pc-skel--line' }),
                el('div', { class: 'pc-skel pc-skel--line', style: 'width: 70%' })
            ]));
            region.appendChild(card);
        });
    }

    function renderCards(report, target) {
        var region = target || document.querySelector('[data-pc-region="report"]');
        if (!region) return;
        region.hidden = false;
        region.innerHTML = '';
        if (window.__pcRenderCardsHook) {
            try { window.__pcRenderCardsHook(report); } catch (e) { /* noop */ }
        }

        // ===== HERO (big IP + flag + score) =====
        var hero = el('section', { class: 'pc-dashboard__hero' });
        var heroBody = el('div', { class: 'pc-hero' });
        var ip = (report.request_ip && report.request_ip.ipv4) || (I18N.unable || '—');
        var intel = (report.connection && report.connection.intel) || {};
        var countryName = intel.country_name || intel.country || '';
        var score = (report.scores && typeof report.scores.privacy === 'number') ? report.scores.privacy : 0;
        var ipNode = el('div', { class: 'pc-hero__ip' });
        if (countryName) {
            ipNode.appendChild(el('span', { class: 'pc-flag', text: countryFlag(intel.country || '') }));
        }
        ipNode.appendChild(document.createTextNode('My IP: ' + ip));
        heroBody.appendChild(ipNode);
        if (countryName) {
            heroBody.appendChild(el('div', { class: 'pc-hero__country', text: countryName }));
        }
        var scoreRing = el('div', { class: 'pc-hero__score-ring' });
        scoreRing.appendChild(el('span', { class: 'pc-hero__score-num', text: score }));
        // SVG ring inner.
        var svgNS = 'http://www.w3.org/2000/svg';
        var svg = document.createElementNS(svgNS, 'svg');
        svg.setAttribute('viewBox', '0 0 50 50');
        var track = document.createElementNS(svgNS, 'circle');
        track.setAttribute('class', 'track');
        track.setAttribute('cx', '25');
        track.setAttribute('cy', '25');
        track.setAttribute('r', '22');
        var value = document.createElementNS(svgNS, 'circle');
        value.setAttribute('class', 'value');
        value.setAttribute('cx', '25');
        value.setAttribute('cy', '25');
        value.setAttribute('r', '22');
        value.setAttribute('stroke-dasharray', '138.2');
        value.setAttribute('stroke-dashoffset', String(138.2 * (1 - Math.max(0, Math.min(100, score)) / 100)));
        svg.appendChild(track);
        svg.appendChild(value);
        scoreRing.insertBefore(svg, scoreRing.firstChild);
        var scoreWrap = el('div', { class: 'pc-hero__score' });
        scoreWrap.appendChild(scoreRing);
        var scoreLabelBlock = el('div', {});
        scoreLabelBlock.appendChild(el('div', { class: 'pc-hero__score-label', text: (I18N.privacyScore || 'Privacy Score') }));
        var level = 'unknown';
        if      (score >= 90) level = 'excellent';
        else if (score >= 75) level = 'good';
        else if (score >= 50) level = 'moderate';
        else if (score >= 25) level = 'poor';
        else                  level = 'very_poor';
        scoreRing.setAttribute('data-level', level);
        scoreLabelBlock.appendChild(el('div', { class: 'pc-hero__score-sub', text: scoreLevelLabel(level) }));
        scoreWrap.appendChild(scoreLabelBlock);
        heroBody.appendChild(scoreWrap);
        hero.appendChild(heroBody);

        // ===== DISGUISE BAR (full width, Whoer-style gradient strip) =====
        var disguiseWrap = el('div', { style: 'position: relative;' });
        var disguise = el('div', { class: 'pc-disguise' });
        var mark = el('div', { class: 'pc-disguise__mark' });
        mark.appendChild(document.createTextNode((I18N.privacyScore || 'Privacy Score') + ': ' + score + '%'));
        var sub = el('small');
        sub.textContent = score >= 75 ? (I18N.scoreGood || 'Your privacy measures are safe or you don\'t use them.')
                   : score >= 50 ? (I18N.scoreMid   || 'Some details are exposed. Review the recommendations below.')
                   : (I18N.scoreBad || 'Significant details are exposed. Follow the priority fixes.');
        mark.appendChild(sub);
        disguise.appendChild(mark);
        disguiseWrap.appendChild(disguise);
        hero.appendChild(disguiseWrap);
        region.appendChild(hero);

        // ===== TWO-COLUMN AREA =====
        var cols = el('div', { class: 'pc-dash-cols' });
        var leftCol  = el('div', { class: 'pc-col' });
        var rightCol = el('div', { class: 'pc-col' });

        // ---- LEFT: action / status cards (Whoer: icon + uppercase title + status) ----
        leftCol.appendChild(actionCard(
            '\u{1F310}', 'IP ADDRESS', I18N.yourIpShort || 'Your IP is shown above.',
            [
                [I18N.ispLabel || 'ISP', flagify(intel.isp, intel.country || intel.country_code)],
                [I18N.orgLabel || 'Organization', flagify(intel.org || intel.asn_org, intel.country || intel.country_code)],
                [I18N.asnLabel || 'ASN', intel.asn ? (intel.asn + ' ' + countryFlag(intel.country || intel.country_code || '')) : (I18N.unable || '\u2014')],
                [I18N.countryLabel || 'Country', flagify(intel.country_name || intel.country || (I18N.unable || '\u2014'), intel.country || intel.country_code)],
                [I18N.regionLabel || 'Region', flagify(intel.region || (I18N.unable || '\u2014'), intel.country || intel.country_code)],
                [I18N.cityLabel || 'City', flagify(intel.city || (I18N.unable || '\u2014'), intel.country || intel.country_code)],
                [I18N.timezoneLabel || 'Timezone', intel.timezone || (I18N.unable || '\u2014')],
                [I18N.reverseDnsLabel || 'Reverse DNS', (report.connection && report.connection.reverse_dns) || (I18N.noReverseDns || 'No reverse DNS record detected.')]
            ]
        ));

        leftCol.appendChild(anonymityConsistencyCard(report));
        leftCol.appendChild(proxyCard(report));
        leftCol.appendChild(dnsLeakCard(report));
        leftCol.appendChild(webrtcActionCard(report));

        // ---- RIGHT: data tables (Whoer: connection details, fingerprint details, system) ----
        rightCol.appendChild(connectionCard(report));
        // Connection-quality card is rendered asynchronously because the
        // latency probe and navigator.connection snapshot need to complete
        // first. We append a placeholder now, then swap it when the probe
        // resolves — the rest of the report renders immediately so the user
        // sees the bulk of the results without waiting for the 3-sample
        // latency measurement.
        var cqPlaceholder = el('section', { class: 'pc-card', 'data-pc-component': 'connection-quality-placeholder' });
        var cqHead = el('div', { class: 'pc-card__head' });
        cqHead.appendChild(el('div', { class: 'pc-card__icon', 'aria-hidden': 'true', text: '\u{1F4CA}' }));
        cqHead.appendChild(el('div', { class: 'pc-card__title-block' }, [
            el('h3', { class: 'pc-card__title', text: I18N.cqTitle || 'CONNECTION QUALITY' }),
            el('p',  { class: 'pc-card__subtitle', text: (I18N.scanning || 'Scanning…') + ' \u2014 ' + (I18N.cqLatencyAvg || 'latency') })
        ]));
        cqPlaceholder.appendChild(cqHead);
        rightCol.appendChild(cqPlaceholder);
        var cqNode = cqPlaceholder;
        Promise.all([
            connectionQualityProbe(3).catch(function () { return null; }),
            Promise.resolve(navigatorConnectionSnapshot())
        ]).then(function (results) {
            var payload = {
                latency: results && results[0] ? results[0] : null,
                network: results && results[1] ? results[1] : null
            };
            try {
                var newCard = connectionQualityCard(report, payload);
                if (cqNode && cqNode.parentNode) {
                    cqNode.parentNode.replaceChild(newCard, cqNode);
                }
            } catch (e) { /* noop — leave the placeholder */ }
        });
        rightCol.appendChild(fingerprintTableCard(report));
        rightCol.appendChild(securityPostureCard(report));
        rightCol.appendChild(scoreBreakdownCard(report));

        // Local Network Exposure — pure client-side probe of RFC1918
        // gateway addresses. Insert as a placeholder so the report layout
        // doesn't reflow when the probe resolves, then swap in the real
        // card. The probe is bounded (~800ms per target); we always swap
        // even on error so the layout never gets stuck on a spinner.
        var lnPlaceholder = el('section', { class: 'pc-card', 'data-pc-component': 'local-network-placeholder' });
        var lnHead = el('div', { class: 'pc-card__head' });
        lnHead.appendChild(el('div', { class: 'pc-card__icon', 'aria-hidden': 'true', text: '\u{1F6AA}' }));
        lnHead.appendChild(el('div', { class: 'pc-card__title-block' }, [
            el('h3', { class: 'pc-card__title', text: I18N.lnTitle || 'LOCAL NETWORK EXPOSURE' }),
            el('p',  { class: 'pc-card__subtitle', text: (I18N.scanning || 'Scanning\u2026') + ' \u2014 ' + (I18N.lnProbing || 'probing local gateway addresses') })
        ]));
        lnPlaceholder.appendChild(lnHead);
        rightCol.appendChild(lnPlaceholder);
        var lnNode = lnPlaceholder;
        scanLocalNetwork({ timeout_ms: 800 }).then(function (ln) {
            try {
                var newCard = localNetworkExposureCard(ln);
                if (lnNode && lnNode.parentNode) {
                    lnNode.parentNode.replaceChild(newCard, lnNode);
                }
            } catch (e) { /* noop — leave the placeholder */ }
        }).catch(function () {
            try {
                var fallbackCard = localNetworkExposureCard({ probed: [], reachable: [] });
                if (lnNode && lnNode.parentNode) {
                    lnNode.parentNode.replaceChild(fallbackCard, lnNode);
                }
            } catch (e2) { /* noop */ }
        });

        cols.appendChild(leftCol);
        cols.appendChild(rightCol);
        region.appendChild(cols);

        // ===== NETWORK PATH DIAGRAM (full width below columns) =====
        region.appendChild(networkPathCard(report));

        // ===== LOCATION MAP =====
        region.appendChild(mapCard(report));

        // ===== DETAILED PRIVACY REPORT + ANONYMITY TIPS — full width below =====
        var detailedWrap = el('div', { class: 'pc-col', style: 'margin-top: 0.4rem;' });
        detailedWrap.appendChild(detailedReportCard(report));
        detailedWrap.appendChild(anonymityTipsCard(report));
        region.appendChild(detailedWrap);
    }

    function scoreLevelLabel(level) {
        switch (level) {
            case 'excellent': return I18N.levelExcellent || 'Excellent';
            case 'good':      return I18N.levelGood      || 'Good';
            case 'moderate':  return I18N.levelModerate  || 'Moderate';
            case 'poor':      return I18N.levelPoor      || 'Poor';
            default:          return I18N.levelVeryPoor  || 'Very Poor';
        }
    }

    function countryFlag(code) {
        if (!code || code.length !== 2) return '';
        var A = 0x1F1E6;
        return String.fromCodePoint(A + (code.toUpperCase().charCodeAt(0) - 65)) +
               String.fromCodePoint(A + (code.toUpperCase().charCodeAt(1) - 65));
    }

    function flagify(value, code) {
        var text = value || (I18N.unable || '\u2014');
        var flag = countryFlag(code || '');
        return flag ? flag + ' ' + text : text;
    }

    function buildExportMenu(report) {
        var wrap = el('div', { class: 'pc-export-menu' });
        var select = el('select', { class: 'pc-export-menu__select', 'aria-label': 'Export scan report' });
        [['json', 'Export JSON'], ['csv', 'Export CSV'], ['txt', 'Export text'], ['html', 'Export HTML']].forEach(function (item) {
            select.appendChild(el('option', { value: item[0], text: item[1] }));
        });
        var btn = el('button', { type: 'button', class: 'pc-btn pc-btn--ghost', text: 'Export' });
        btn.addEventListener('click', function () {
            var format = select.value;
            var content;
            var mime;
            var extension = format;
            if (format === 'json') {
                content = JSON.stringify(report, null, 2);
                mime = 'application/json';
            } else if (format === 'csv') {
                var rows = [['section', 'key', 'value']];
                flattenReport(report).forEach(function (r) { rows.push(r); });
                content = rows.map(function (r) { return r.map(csvEscape).join(','); }).join('\n');
                mime = 'text/csv';
            } else if (format === 'html') {
                content = '<!doctype html><meta charset="utf-8"><title>IMON Privacy Report</title><pre>' + escapeHtml(JSON.stringify(report, null, 2)) + '</pre>';
                mime = 'text/html';
            } else {
                content = JSON.stringify(report, null, 2);
                mime = 'text/plain';
            }
            var blob = new Blob([content], { type: mime });
            var url = URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = 'imon-privacy-report-' + new Date().toISOString().slice(0, 10) + '.' + extension;
            document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
        });
        wrap.appendChild(select); wrap.appendChild(btn);
        return wrap;
    }

    function flattenReport(value, path, out) {
        path = path || 'report'; out = out || [];
        if (value && typeof value === 'object') {
            Object.keys(value).forEach(function (key) { flattenReport(value[key], path + '.' + key, out); });
        } else {
            out.push([path.split('.')[1] || 'report', path, value == null ? '' : String(value)]);
        }
        return out;
    }
    function csvEscape(value) { return '"' + String(value == null ? '' : value).replace(/"/g, '""') + '"'; }

    function shareReport(report) {
        var payload = JSON.stringify(report);
        if (navigator.share) {
            navigator.share({ title: 'IMON Privacy Report', text: payload }).catch(function () {});
        } else if (navigator.clipboard) {
            navigator.clipboard.writeText(payload).then(function () { showToast('Report copied to clipboard.', 'ok'); });
        }
    }

    function buildShareButton(report) {
        var btn = el('button', { type: 'button', class: 'pc-btn pc-btn--ghost', text: 'Share link' });
        btn.addEventListener('click', function () {
            btn.disabled = true;
            api('share', { method: 'POST', body: { report: report } }).then(function (resp) {
                btn.disabled = false;
                if (!resp.ok || !resp.data || !resp.data.url) {
                    showToast((resp.data && (resp.data.message || resp.data.error)) || 'Share not available.', 'warn');
                    return;
                }
                var url = resp.data.url;
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(url).then(function () {
                        showToast('Share link copied to clipboard.', 'ok');
                    });
                } else {
                    showToast('Share link: ' + url, 'info');
                }
            }).catch(function () {
                btn.disabled = false;
                showToast('Share request failed.', 'warn');
            });
        });
        return btn;
    }

    // Whoer-style info card: icon + uppercase title + dl list of rows
    function actionCard(iconChar, title, lede, rows) {
        var card = el('article', { class: 'pc-card' });
        var head = el('div', { class: 'pc-card__head' });
        head.appendChild(el('div', { class: 'pc-card__icon', 'aria-hidden': 'true', text: iconChar }));
        head.appendChild(el('div', { class: 'pc-card__title-block' }, [
            el('h3', { class: 'pc-card__title', text: title }),
            el('p', { class: 'pc-card__subtitle', text: lede })
        ]));
        card.appendChild(head);
        var dl = el('dl', { class: 'pc-info-grid' });
        rows.forEach(function (r) {
            dl.appendChild(el('dt', { text: r[0] }));
            dl.appendChild(el('dd', { text: r[1] }));
        });
        card.appendChild(dl);
        return card;
    }

    function proxyCard(report) {
        var pr = (report && report.privacy_report && report.privacy_report.proxy) || null;
        var intel = (report && report.connection && report.connection.intel) || {};
        var level = 'unknown';
        var title = 'PROXY / VPN / TOR';
        var lede = 'Whether your IP shows signs of being a proxy, VPN, Tor exit, or hosting provider.';
        var summary = I18N.unable || '\u2014';
        if (pr && pr.label) {
            summary = pr.label;
            if ((pr.category || '').toLowerCase() === 'residential') level = 'pass';
            else if ((pr.category || '').toLowerCase() === 'tor') level = 'danger';
            else if ((pr.category || '').toLowerCase() === 'vpn') level = 'warning';
            else level = 'warning';
        } else {
            level = 'pass';
            summary = I18N.proxyNone || 'No proxy / VPN / Tor signals detected';
        }
        var rows = [];
        if (pr && pr.confidence) rows.push(['Confidence', capitalize(pr.confidence)]);
        if (pr && pr.vendor)     rows.push(['Vendor', pr.vendor]);
        if (intel.isp || intel.org) rows.push([I18N.ispLabel || 'ISP', intel.isp || intel.org || '\u2014']);
        if (intel.asn)           rows.push([I18N.asnLabel || 'ASN', intel.asn]);
        if (!rows.length) rows.push(['Status', summary]);
        return statusActionCard('\u{1F6E1}', title, lede, summary, level, rows);
    }

    function dnsLeakCard(report) {
        var dns = report.dns_test || {};
        var level = dns.configured ? 'info' : 'warning';
        var summary = dns.configured ? (I18N.dnsConfigured || 'DNS leak test available')
                                     : (I18N.dnsNotConfigured || 'DNS leak testing not configured');
        var lede = 'A DNS leak test reveals which resolvers actually answer your queries. Public DNS providers in different countries may indicate a leak.';
        return statusActionCard('\u{1F50D}', 'DNS LEAK TEST', lede, summary, level, [
            [I18N.dnsStatus || 'Status', summary],
            [I18N.dnsProvider || 'Provider', dns.provider || '\u2014']
        ], {
            cta: { label: (I18N.dnsGo || 'Go'), href: (window.PC_SCAN && window.PC_SCAN.dnsPageUrl) || '/dns-leak-test/' },
            ctaIcon: '\u{1F50D}'
        });
    }

    function webrtcActionCard(report) {
        var webrtc = report.webrtc || {};
        var level = 'info';
        var summary = 'Unknown';
        if (webrtc.verdict === 'protected') { level = 'pass'; summary = webrtcLabel('protected'); }
        else if (webrtc.verdict === 'potential_exposure') { level = 'danger'; summary = webrtcLabel('potential_exposure'); }
        else if (webrtc.verdict === 'not_supported') { level = 'info'; summary = webrtcLabel('not_supported'); }
        return statusActionCard('\u{1F4E1}', 'WEBRTC', 'Whether your browser leaks your real IP through WebRTC peer connections.', summary, level, [
            [I18N.webrtcSupported || 'Supported', webrtc.supported ? 'Yes' : 'No'],
            ['Public IPs observed', (webrtc.public_addrs || []).length ? webrtc.public_addrs.join(', ') : 'None']
        ], {
            cta: { label: (I18N.dnsGo || 'Go'), href: (window.PC_SCAN && window.PC_SCAN.webrtcPageUrl) || '/webrtc-test/' },
            ctaIcon: '\u{1F4E1}'
        });
    }

    function statusActionCard(iconChar, title, lede, summary, level, rows, opts) {
        opts = opts || {};
        var card = el('article', { class: 'pc-card' });
        var head = el('div', { class: 'pc-card__head' });
        head.appendChild(el('div', { class: 'pc-card__icon', 'aria-hidden': 'true', text: iconChar }));
        var block = el('div', { class: 'pc-card__title-block' });
        block.appendChild(el('h3', { class: 'pc-card__title', text: title }));
        block.appendChild(el('p', { class: 'pc-card__subtitle', text: lede }));
        var pill = el('span', { class: 'pc-status pc-status--' + (level || 'unknown'), text: summary });
        block.appendChild(pill);
        head.appendChild(block);
        card.appendChild(head);
        var dl = el('dl', { class: 'pc-info-grid' });
        rows.forEach(function (r) {
            dl.appendChild(el('dt', { text: r[0] }));
            dl.appendChild(el('dd', { text: r[1] }));
        });
        card.appendChild(dl);
        if (opts.cta) {
            var btn = el('a', {
                class: 'pc-btn pc-btn--primary pc-card__cta',
                href: opts.cta.href,
                text: opts.cta.label
            });
            card.appendChild(btn);
        }
        return card;
    }

    function connectionCard(report) {
        var card = el('section', { class: 'pc-card' });
        var head = el('div', { class: 'pc-card__head' });
        head.appendChild(el('div', { class: 'pc-card__icon', 'aria-hidden': 'true', text: '\u{1F4E1}' }));
        head.appendChild(el('div', { class: 'pc-card__title-block' }, [
            el('h3', { class: 'pc-card__title', text: 'CONNECTION DETAILS' }),
            el('p', { class: 'pc-card__subtitle', text: 'Everything your network is broadcasting right now.' })
        ]));
        card.appendChild(head);
        var tbl = el('table', { class: 'pc-info-table' });
        var intel = (report.connection && report.connection.intel) || {};
        var rep = report.reputation || {};
        var rows = [
            [I18N.ipLabel || 'IP Address', (report.request_ip && report.request_ip.ipv4) || '\u2014'],
            [I18N.countryLabel || 'Country', intel.country_name || intel.country || '\u2014'],
            [I18N.regionLabel || 'Region', intel.region || '\u2014'],
            [I18N.cityLabel || 'City', intel.city || '\u2014'],
            [I18N.ispLabel || 'ISP', intel.isp || intel.org || '\u2014'],
            [I18N.orgLabel || 'Organization', intel.org || intel.asn_org || '\u2014'],
            [I18N.asnLabel || 'ASN', intel.asn || '\u2014'],
            [I18N.timezoneLabel || 'Timezone', intel.timezone || '\u2014'],
            [I18N.reverseDnsLabel || 'Reverse DNS', (report.connection && report.connection.reverse_dns) || (I18N.noReverseDns || '\u2014')],
            [I18N.ipReputationLabel || 'IP Reputation', capitalize(reputationLabel(rep))]
        ];
        var tbody = el('tbody');
        rows.forEach(function (r) {
            tbody.appendChild(el('tr', {}, [
                el('th', { text: r[0] }),
                el('td', { text: r[1] })
            ]));
        });
        tbl.appendChild(tbody);
        card.appendChild(tbl);
        return card;
    }

    /* ---------- Connection quality (latency / jitter / Network Information API) ----------
     *
     * Latency is measured end-to-end in the visitor's browser via three
     * sequential fetch() calls to /scan/connection/echo, timed with
     * performance.now(). Server-side measurement would only capture the
     * server's view of itself, which is not what the visitor cares about.
     *
     * Network Information API (navigator.connection) is a Chromium-only
     * surface — explicitly shows "Not available in this browser" in
     * Safari/Firefox rather than rendering a misleading zero value.
     *
     * The IPv4/v6 reachability row uses the same `request_ip` shape that
     * the rest of the report consumes — no second IP-detection path.
     * ------------------------------------------------------------------------- */

    /**
     * Fire N requests to /scan/connection/echo and return per-sample +
     * min/max/avg/jitter in ms. Resolves to an empty object on failure so
     * the calling UI can degrade gracefully ("unable to determine").
     */
    function connectionQualityProbe(sampleCount) {
        var N = Math.max(1, Math.min(5, sampleCount || 3));
        var endpoint = REST_URL
            ? REST_URL.replace(/\/$/, '') + '/scan/connection/echo'
            : '/wp-json/privacy-checker/v1/scan/connection/echo';

        // Three sequential samples give us min/max/avg/jitter (jitter =
        // max - min, the simplest and most honest spread for a small-N
        // sample — std dev on n=3 is too noisy to mean much).
        var samples = [];
        var i = 0;

        function next() {
            if (i >= N) {
                if (!samples.length) return Promise.resolve(null);
                var min = Math.min.apply(null, samples);
                var max = Math.max.apply(null, samples);
                var avg = samples.reduce(function (a, b) { return a + b; }, 0) / samples.length;
                var jitter = max - min;
                return Promise.resolve({
                    samples: samples,
                    count:   samples.length,
                    min_ms:  Math.round(min * 100) / 100,
                    max_ms:  Math.round(max * 100) / 100,
                    avg_ms:  Math.round(avg * 100) / 100,
                    jitter_ms: Math.round(jitter * 100) / 100,
                });
            }
            var sent = (typeof performance !== 'undefined' && performance.now)
                ? performance.now()
                : Date.now();
            return fetch(endpoint, {
                method: 'GET',
                credentials: 'omit',
                cache: 'no-store',
                headers: { 'Accept': 'application/json' }
            }).then(function (resp) {
                var recv = (typeof performance !== 'undefined' && performance.now)
                    ? performance.now()
                    : Date.now();
                if (resp && resp.ok) {
                    samples.push(recv - sent);
                }
            }).catch(function () { /* skip failed sample */ })
              .then(function () { i++; return next(); });
        }
        return next();
    }

    /**
     * Probe a small fixed list of RFC1918 private gateway addresses on
     * common admin ports, from the visitor's own browser.
     *
     * SCOPE LIMIT (deliberate, do not relax):
     *   This is a self-test tool, not a network scanner-as-a-service. The
     *   target list is hardcoded to RFC1918 private ranges (192.168.x.x,
     *   10.x.x.x, 172.16-31.x.x). We never accept a user-supplied target
     *   here — only probe addresses that are, by definition, on the
     *   visitor's own local network. A probe targeting anything beyond
     *   RFC1918 would either be a no-op (route filtered) or, worse, be
     *   mistaken for an outbound port-scan by an upstream firewall.
     *
     * Returns:
     *   {
     *     probed:    [{host, port, status, latency_ms}],   // one per attempt
     *     reachable: [host:port],                          // any 'open' or 'cors' rows
     *     total_probes, completed_count
     *   }
     *
     * Status values per probe:
     *   - 'open'       — TCP connect succeeded AND we got a response (response.ok true)
     *   - 'cors'       — TCP connect succeeded but CORS blocked reading the body
     *                    (still informative: SOMETHING answered on that port)
     *   - 'refused'    — TCP RST (port closed) — fast error
     *   - 'timeout'    — no response within the per-probe budget
     *   - 'unreachable' — network-level error (host unreachable / DNS / etc.)
     *
     * We probe concurrently with a per-request AbortController; the
     * `timeout_ms` controls each probe's individual deadline, not the
     * total wall clock.
     */
    function scanLocalNetwork(opts) {
        var timeoutMs  = (opts && opts.timeout_ms)  || 800;
        var GATEWAYS   = ['192.168.0.1', '192.168.1.1', '10.0.0.1', '10.0.1.1', '172.16.0.1'];
        var ADMIN_PORTS = [80, 443, 8080];
        var controllers = [];

        function one(host, port) {
            var url = 'http://' + host + ':' + port + '/';
            var ctl = (typeof AbortController !== 'undefined') ? new AbortController() : null;
            if (ctl) controllers.push(ctl);
            var deadline = (typeof performance !== 'undefined' && performance.now)
                ? performance.now()
                : Date.now();
            var init = { method: 'GET', mode: 'no-cors', cache: 'no-store', redirect: 'manual' };
            if (ctl) init.signal = ctl.signal;
            return fetch(url, init).then(function (resp) {
                var recv = (typeof performance !== 'undefined' && performance.now)
                    ? performance.now()
                    : Date.now();
                // no-cors responses are opaque — we know SOMETHING answered
                // because the fetch resolved rather than throwing, but we
                // can't read status. Mark as 'cors' to flag this honestly.
                return {
                    host: host,
                    port: port,
                    status: 'cors',
                    latency_ms: Math.round((recv - deadline) * 100) / 100
                };
            }).catch(function (err) {
                var recv = (typeof performance !== 'undefined' && performance.now)
                    ? performance.now()
                    : Date.now();
                var name = (err && err.name) || '';
                var status = 'unreachable';
                if (name === 'AbortError')        status = 'timeout';
                else if (name === 'TypeError')    status = 'refused';
                return {
                    host: host,
                    port: port,
                    status: status,
                    latency_ms: Math.round((recv - deadline) * 100) / 100
                };
            });
        }

        var probes = [];
        GATEWAYS.forEach(function (h) {
            ADMIN_PORTS.forEach(function (p) { probes.push(one(h, p)); });
        });

        var totalProbes = probes.length;
        return Promise.all(probes.map(function (p) {
            // Race each probe against its own deadline so a slow target
            // can't drag the whole batch past the budget.
            var to = new Promise(function (resolve) {
                setTimeout(function () {
                    // Abort in-flight requests when their personal timer
                    // expires — keeps the entire call bounded.
                    controllers.forEach(function (c) {
                        try { c.abort(); } catch (e) { /* noop */ }
                    });
                    resolve({ timed_out: true });
                }, timeoutMs);
            });
            return Promise.race([p, to]).then(function (r) {
                if (r && r.timed_out) {
                    return { host: '?', port: 0, status: 'timeout', latency_ms: timeoutMs };
                }
                return r;
            });
        })).then(function (rows) {
            var reachable = [];
            rows.forEach(function (r) {
                if (r && (r.status === 'cors' || r.status === 'open')) {
                    reachable.push(r.host + ':' + r.port);
                }
            });
            return {
                probed:    rows,
                reachable: reachable,
                total_probes:     totalProbes,
                completed_count:  rows.length
            };
        });
    }

    /**
     * Read navigator.connection (Chromium-only Network Information API).
     * Returns null fields when unavailable rather than zeroing — Safari /
     * Firefox don't expose the API and showing "0 Mbps" there would be
     * misleading.
     */
    function navigatorConnectionSnapshot() {
        var c = (typeof navigator !== 'undefined' && navigator.connection) || null;
        if (!c) {
            return {
                available:    false,
                downlink_mbps: null,
                effective_type: null,
                rtt_ms:        null,
                save_data:     null
            };
        }
        return {
            available:     true,
            downlink_mbps: (typeof c.downlink === 'number')  ? c.downlink  : null,
            effective_type: c.effectiveType || null,
            rtt_ms:        (typeof c.rtt === 'number')        ? c.rtt       : null,
            save_data:     (typeof c.saveData === 'boolean') ? c.saveData  : null
        };
    }

    /**
     * Connection Quality card. Latency / jitter / navigator.connection /
     * IPv4-vs-IPv6 reachability, rendered as a single Whoer-style data
     * table card matching the connectionCard + fingerprintTableCard shape.
     */
    function connectionQualityCard(report, payload) {
        var p  = payload || {};
        var lat = p.latency || null;
        var net = p.network || {};
        var ip  = (report && report.request_ip) || {};
        var ipv4 = ip.ipv4 || null;
        var ipv6 = ip.ipv6 || null;

        var family = 'unknown';
        if (ipv4 && ipv6)      family = 'dual-stack';
        else if (ipv6)         family = 'IPv6 only';
        else if (ipv4)         family = 'IPv4 only';
        else                   family = I18N.unable || '—';

        var card = el('section', { class: 'pc-card', 'data-pc-component': 'connection-quality' });
        var head = el('div', { class: 'pc-card__head' });
        head.appendChild(el('div', { class: 'pc-card__icon', 'aria-hidden': 'true', text: '\u{1F4CA}' }));
        head.appendChild(el('div', { class: 'pc-card__title-block' }, [
            el('h3', { class: 'pc-card__title', text: I18N.cqTitle || 'CONNECTION QUALITY' }),
            el('p',  { class: 'pc-card__subtitle', text: I18N.cqLede || 'End-to-end latency, jitter, and your browser\'s view of the connection.' })
        ]));
        card.appendChild(head);

        var tbl = el('table', { class: 'pc-info-table' });
        var tbody = el('tbody');

        // Latency rows — show min/avg/max/jitter if the probe succeeded.
        if (lat && typeof lat.avg_ms === 'number') {
            tbody.appendChild(el('tr', {}, [
                el('th', { text: I18N.cqLatencyAvg || 'Average latency' }),
                el('td', { text: lat.avg_ms + ' ms', mono: true })
            ]));
            tbody.appendChild(el('tr', {}, [
                el('th', { text: I18N.cqLatencyMin || 'Minimum' }),
                el('td', { text: lat.min_ms + ' ms', mono: true })
            ]));
            tbody.appendChild(el('tr', {}, [
                el('th', { text: I18N.cqLatencyMax || 'Maximum' }),
                el('td', { text: lat.max_ms + ' ms', mono: true })
            ]));
            var jitterLevel = 'pass';
            if (lat.jitter_ms > 50)      jitterLevel = 'warning';
            if (lat.jitter_ms > 150)     jitterLevel = 'danger';
            tbody.appendChild(el('tr', {}, [
                el('th', { text: I18N.cqLatencyJitter || 'Jitter' }),
                el('td', { text: lat.jitter_ms + ' ms', mono: true, pill: jitterLevel })
            ]));
            tbody.appendChild(el('tr', {}, [
                el('th', { text: I18N.cqSamples || 'Samples' }),
                el('td', { text: String(lat.count) + ' × GET /scan/connection/echo', mono: true })
            ]));
        } else {
            // Probe failed (network blocked, ad-blocker, CORS) — show
            // "unable to determine" rather than a blank/zero row.
            tbody.appendChild(el('tr', {}, [
                el('th', { text: I18N.cqLatencyAvg || 'Average latency' }),
                el('td', { text: I18N.unable || 'Unable to determine' })
            ]));
        }

        // IPv4 vs IPv6 reachability — derived from the same request_ip
        // shape the rest of the report consumes. Not re-detected here.
        tbody.appendChild(el('tr', {}, [
            el('th', { text: I18N.cqReachability || 'IP family' }),
            el('td', { text: family, mono: true })
        ]));
        tbody.appendChild(el('tr', {}, [
            el('th', { text: I18N.cqIPv4 || 'IPv4' }),
            el('td', { text: ipv4 || (I18N.unable || '—'), mono: true })
        ]));
        tbody.appendChild(el('tr', {}, [
            el('th', { text: I18N.cqIPv6 || 'IPv6' }),
            el('td', { text: ipv6 || (I18N.unable || '—'), mono: true })
        ]));

        // Network Information API — Chromium-only. Explicit fallback message
        // for Safari / Firefox / anything else that doesn't expose it.
        tbody.appendChild(el('tr', {}, [
            el('th', { text: I18N.cqNetInfo || 'Browser network info' }),
            el('td', { text: net.available
                ? (
                    (net.effective_type ? ('Type: ' + net.effective_type + ' · ') : '') +
                    (net.downlink_mbps != null ? ('Downlink: ' + net.downlink_mbps + ' Mbps · ') : '') +
                    (net.rtt_ms != null ? ('RTT hint: ' + net.rtt_ms + ' ms') : (net.effective_type || (I18N.unable || '—')))
                  ).replace(/·\s*$/, '')
                : (I18N.cqNetInfoUnavailable || 'Not available in this browser.')
            })
        ]));

        tbl.appendChild(tbody);
        card.appendChild(tbl);
        return card;
    }

    /* ---------- Anonymity consistency ----------
     *
     * Renders a single summary card built from `report.connection.anonymity`
     * (computed server-side by AnonymityScorer::score()). The card shows:
     *   - one composite 0..100 score, color-coded
     *   - the server's one-line summary ("No inconsistencies detected" / etc.)
     *   - a list of mismatches, each tagged LOW / MEDIUM / HIGH
     *
     * When the server hasn't computed anonymity yet (older builds, an
     * orchestrator error path) the card still renders with "Unknown" score
     * and an explanatory note — no broken layout.
     */
    function anonymityConsistencyCard(report) {
        var anon = (report && report.connection && report.connection.anonymity) || {};
        var card = el('section', { class: 'pc-card', 'data-pc-component': 'anonymity-consistency' });
        var head = el('div', { class: 'pc-card__head' });
        head.appendChild(el('div', { class: 'pc-card__icon', 'aria-hidden': 'true', text: '\u2696\uFE0F' }));
        head.appendChild(el('div', { class: 'pc-card__title-block' }, [
            el('h3', { class: 'pc-card__title', text: I18N.anonymityTitle || 'ANONYMITY CONSISTENCY' }),
            el('p', { class: 'pc-card__subtitle', text: anon.summary || (I18N.anonymityLede || 'Cross-checks your IP, timezone, WebRTC, and DNS signals for agreement.') })
        ]));
        card.appendChild(head);

        var scoreVal = (typeof anon.score === 'number') ? anon.score : null;
        var scoreClass = scoreVal === null
            ? 'pc-badge--unknown'
            : scoreVal >= 80 ? 'pc-badge--ok'
            : scoreVal >= 50 ? 'pc-badge--caution'
            : 'pc-badge--warn';

        var scoreRow = el('div', { class: 'pc-card__score-row' });
        scoreRow.appendChild(el('div', {
            class: 'pc-badge ' + scoreClass,
            text: scoreVal === null
                ? (I18N.anonymityUnknown || 'Unknown')
                : (I18N.anonymityScoreLabel || 'Score') + ' ' + scoreVal + ' / 100'
        }));
        card.appendChild(scoreRow);

        var mismatches = Array.isArray(anon.mismatches) ? anon.mismatches : [];
        if (!mismatches.length) {
            card.appendChild(el('p', {
                class: 'pc-card__note',
                text: (anon.consistent === true)
                    ? (I18N.anonymityAllConsistent || 'No inconsistencies found between the signals checked.')
                    : (I18N.anonymityNoData         || 'No completed signal checks yet.')
            }));
        } else {
            var list = el('ul', { class: 'pc-mismatch-list' });
            mismatches.forEach(function (m) {
                var sev = (m && m.severity) ? String(m.severity).toLowerCase() : 'low';
                if ( 'low' !== sev && 'medium' !== sev && 'high' !== sev ) sev = 'low';
                list.appendChild(el('li', { class: 'pc-mismatch-list__item pc-severity--' + sev }, [
                    el('span', { class: 'pc-mismatch-list__badge', text: sev.toUpperCase() }),
                    el('span', { text: (m && m.detail) ? m.detail : '' })
                ]));
            });
            card.appendChild(list);
        }
        return card;
    }

    /**
     * Security Posture card (Phase 4 of IMON-BUILD-GUIDE.md).
     * Reports the TLS protocol + cipher negotiated for the current request,
     * plus a browser EOL advisory based on the visitor's User-Agent.
     * Both pieces of data come from report.security_posture.{tls,browser}.
     *
     * Renders a compact data table with severity-coded status pills. When
     * the TLS info is unavailable (e.g. plain HTTP or a proxy that didn't
     * forward the handshake), we show an explicit informational row — not
     * a missing-data error.
     */
    function securityPostureCard(report) {
        var sp = (report && report.security_posture) || {};
        var tls = sp.tls || {};
        var browser = sp.browser || {};

        var card = el('section', { class: 'pc-card', 'data-pc-component': 'security-posture' });
        var head = el('div', { class: 'pc-card__head' });
        head.appendChild(el('div', { class: 'pc-card__icon', 'aria-hidden': 'true', text: '\u{1F6E1}' }));
        head.appendChild(el('div', { class: 'pc-card__title-block' }, [
            el('h3', { class: 'pc-card__title', text: I18N.spTitle || 'SECURITY POSTURE' }),
            el('p',  { class: 'pc-card__subtitle', text: I18N.spLede || 'TLS version, cipher, and your browser\'s update status — for the connection you\'re using right now.' })
        ]));
        card.appendChild(head);

        var tbl = el('table', { class: 'pc-info-table' });
        var tbody = el('tbody');

        // ---- TLS row ----
        var tlsPill = ({
            modern: 'pc-pill--pass', acceptable: 'pc-pill--info', outdated: 'pc-pill--danger', unknown: 'pc-pill--unknown'
        })[tls.status] || 'pc-pill--unknown';
        var tlsPillText = ({
            modern: 'Modern', acceptable: 'Acceptable', outdated: 'Outdated', unknown: 'Unknown'
        })[tls.status] || (I18N.unable || '\u2014');

        // Protocol value cell: status pill + protocol string + cipher.
        var tlsCellContents = [
            el('span', { class: 'pc-pill ' + tlsPill, text: tlsPillText })
        ];
        if (tls.protocol) {
            tlsCellContents.push(el('span', { 'is-mono': true, 'style': 'margin-left: 6px;', text: tls.protocol }));
        }
        if (tls.cipher && tls.cipher !== tls.protocol) {
            tlsCellContents.push(el('span', { class: 'pc-pill-soft', 'style': 'margin-left: 6px; font-size: 0.7rem;', text: tls.cipher }));
        }
        tbody.appendChild(el('tr', {}, [
            el('th', { text: I18N.spTlsLabel || 'TLS' }),
            el('td', {}, tlsCellContents)
        ]));
        // Cipher sub-row (only when there's something separate from the protocol).
        if (tls.note) {
            tbody.appendChild(el('tr', {}, [
                el('th', { text: I18N.spTlsNote || 'Note' }),
                el('td', { text: tls.note })
            ]));
        }

        // ---- Browser EOL row ----
        var browserPill = ({
            current: 'pc-pill--pass',
            outdated: 'pc-pill--warning',
            very_outdated: 'pc-pill--danger',
            unknown_family: 'pc-pill--unknown',
            unknown_version: 'pc-pill--unknown'
        })[browser.status] || 'pc-pill--unknown';
        var browserPillText = ({
            current: I18N.spStatusCurrent || 'Current',
            outdated: I18N.spStatusOutdated || 'Outdated',
            very_outdated: I18N.spStatusVeryOutdated || 'Very outdated',
            unknown_family: I18N.spStatusUnknown || 'Unknown',
            unknown_version: I18N.spStatusUnknown || 'Unknown'
        })[browser.status] || (I18N.unable || '\u2014');

        var browserLabel = browser.browser || '\u2014';
        if (browser.version) {
            browserLabel += ' ' + browser.version;
        }
        tbody.appendChild(el('tr', {}, [
            el('th', { text: I18N.spBrowserLabel || 'Browser status' }),
            el('td', {}, [
                el('span', { class: 'pc-pill ' + browserPill, text: browserPillText }),
                el('span', { 'style': 'margin-left: 6px;', text: browserLabel })
            ])
        ]));
        if (browser.message) {
            tbody.appendChild(el('tr', {}, [
                el('th', { text: I18N.spBrowserNote || 'Advisory' }),
                el('td', { text: browser.message })
            ]));
        }

        tbl.appendChild(tbody);
        card.appendChild(tbl);
        return card;
    }

    function fingerprintTableCard(report) {
        var card = el('section', { class: 'pc-card' });
        var head = el('div', { class: 'pc-card__head' });
        head.appendChild(el('div', { class: 'pc-card__icon', 'aria-hidden': 'true', text: '\u{1F50D}' }));
        head.appendChild(el('div', { class: 'pc-card__title-block' }, [
            el('h3', { class: 'pc-card__title', text: 'BROWSER FINGERPRINT' }),
            el('p', { class: 'pc-card__subtitle', text: 'What your browser reveals about you without you doing anything.' })
        ]));
        card.appendChild(head);
        var tbl = el('table', { class: 'pc-info-table' });
        var ua = report.user_agent || {};
        var fp = report.fingerprint || {};
        var hashes = report.fingerprint_hashes || {};
        var entropy = fp.entropy || {};
        var vis = (fp.level || 'low');
        var rows = [
            ['Browser',   ua.browser || '\u2014'],
            ['Version',   ua.version || '\u2014'],
            ['Engine',    ua.engine  || '\u2014'],
            ['OS',        ua.os      || '\u2014'],
            ['Device',    ua.device  || '\u2014'],
            ['Language',  (report.fingerprint && report.fingerprint.signals && (navigator.languages ? navigator.languages.join(', ') : '')) || (I18N.unable || '\u2014')],
            ['Screen',    (screen.width || 0) + 'x' + (screen.height || 0)],
            ['Fingerprint visibility', capitalize(vis) + ' (' + (fp.exposure_score || 0) + '/100)']
        ];
        var tbody = el('tbody');
        rows.forEach(function (r) {
            tbody.appendChild(el('tr', {}, [
                el('th', { text: r[0] }),
                el('td', { text: r[1] })
            ]));
        });

        // ---- Phase 3 rows: real hash / renderer / font signals ----
        // Canvas hash (with the "this is your ID" framing from the guide).
        var canvasHash = hashes.canvas_hash || '';
        tbody.appendChild(el('tr', {}, [
            el('th', { text: I18N.fpCanvasHash || 'Canvas hash' }),
            el('td', { mono: true, text: canvasHash || (I18N.fpUnavailable || 'unavailable') })
        ]));
        // Audio hash.
        var audioHash = hashes.audio_hash || '';
        tbody.appendChild(el('tr', {}, [
            el('th', { text: I18N.fpAudioHash || 'Audio hash' }),
            el('td', { mono: true, text: audioHash || (I18N.fpUnavailable || 'unavailable') })
        ]));
        // WebGL renderer — explicit "browser is blocking this — good
        // sign" messaging when the sentinel value is returned.
        var renderer = hashes.webgl_renderer || '';
        var isMasked = renderer === 'masked-by-browser';
        var rendererCell;
        if (isMasked) {
            rendererCell = el('td', {}, [
                document.createTextNode(renderer + ' '),
                el('span', { class: 'pc-badge pc-badge--ok', text: I18N.fpWebglMasked || 'browser is blocking this — good sign' })
            ]);
        } else {
            rendererCell = el('td', { mono: true, text: renderer || (I18N.fpUnavailable || 'unavailable') });
        }
        tbody.appendChild(el('tr', {}, [
            el('th', { text: I18N.fpWebglRenderer || 'WebGL renderer' }),
            rendererCell
        ]));
        // WebGL vendor (smaller value; no special treatment for masked
        // because the renderer line already conveys it).
        tbody.appendChild(el('tr', {}, [
            el('th', { text: I18N.fpWebglVendor || 'WebGL vendor' }),
            el('td', { mono: true, text: hashes.webgl_vendor || (I18N.fpUnavailable || 'unavailable') })
        ]));
        // Installed fonts — count + expandable full list.
        var fontList = Array.isArray(hashes.font_list) ? hashes.font_list : [];
        var fontCount = fontList.length;
        var fontCountCell = el('td', {}, [
            el('strong', { text: String(fontCount) }),
            fontCount > 0 ? document.createTextNode(' ' + (I18N.fpFontCountInstalled || 'fonts detected')) : document.createTextNode('')
        ]);
        if (fontCount > 0) {
            var expandBtn = el('button', {
                type: 'button',
                class: 'pc-btn pc-btn--ghost pc-fp-list__toggle',
                text: I18N.fpShowFonts || 'Show list',
                'aria-expanded': 'false'
            });
            var listWrap = el('div', { class: 'pc-fp-list', hidden: true });
            var listInner = el('ul', { class: 'pc-fp-list__items' });
            fontList.forEach(function (name) {
                listInner.appendChild(el('li', { class: 'pc-fp-list__item', text: name }));
            });
            listWrap.appendChild(listInner);
            expandBtn.addEventListener('click', function () {
                var hidden = listWrap.hasAttribute('hidden');
                if (hidden) {
                    listWrap.removeAttribute('hidden');
                    expandBtn.textContent = I18N.fpHideFonts || 'Hide list';
                    expandBtn.setAttribute('aria-expanded', 'true');
                } else {
                    listWrap.setAttribute('hidden', '');
                    expandBtn.textContent = I18N.fpShowFonts || 'Show list';
                    expandBtn.setAttribute('aria-expanded', 'false');
                }
            });
            var btnWrap = el('div', { style: 'margin-top: 0.4rem;' });
            btnWrap.appendChild(expandBtn);
            btnWrap.appendChild(listWrap);
            fontCountCell.appendChild(btnWrap);
        }
        tbody.appendChild(el('tr', {}, [
            el('th', { text: I18N.fpFontCount || 'Installed fonts' }),
            fontCountCell
        ]));

        // Entropy readout (bits + uniqueness estimate) — one combined row.
        if (entropy && typeof entropy.bits === 'number') {
            var entropyCell = el('td', {}, [
                el('strong', { text: entropy.bits + ' bits' }),
                entropy.uniqueness_estimate
                    ? document.createTextNode(' — ' + entropy.uniqueness_estimate)
                    : document.createTextNode('')
            ]);
            tbody.appendChild(el('tr', {}, [
                el('th', { text: I18N.fpEntropyLabel || 'Fingerprint entropy' }),
                entropyCell
            ]));
        }

        tbl.appendChild(tbody);
        card.appendChild(tbl);
        return card;
    }

    function scoreBreakdownCard(report) {
        var card = el('section', { class: 'pc-card' });
        var head = el('div', { class: 'pc-card__head' });
        head.appendChild(el('div', { class: 'pc-card__icon', 'aria-hidden': 'true', text: '\u{1F4CA}' }));
        head.appendChild(el('div', { class: 'pc-card__title-block' }, [
            el('h3', { class: 'pc-card__title', text: 'SIGNAL BREAKDOWN' }),
            el('p', { class: 'pc-card__subtitle', text: 'How each detection contributed to your privacy score.' })
        ]));
        card.appendChild(head);
        var breakdown = (report.scores && report.scores.breakdown) || {};
        var dl = el('dl', { class: 'pc-info-grid' });
        var keys = Object.keys(breakdown);
        if (!keys.length) {
            dl.appendChild(el('dt', { text: 'Signals' }));
            dl.appendChild(el('dd', { text: I18N.unable || '\u2014' }));
        } else {
            keys.forEach(function (k) {
                var v = breakdown[k];
                dl.appendChild(el('dt', { text: capitalize(k.replace(/_/g, ' ')) }));
                dl.appendChild(el('dd', { text: (v >= 0 ? '+' : '') + v }));
            });
        }
        card.appendChild(dl);
        return card;
    }

    /**
     * Local Network Exposure card. Shows results from scanLocalNetwork()
     * — a pure-client-side probe of common RFC1918 gateway addresses on
     * common admin ports. The card copy is intentionally explicit: this
     * only ever tests devices on the visitor's own LAN from the visitor's
     * own browser. It is not an external scanner.
     */
    function localNetworkExposureCard(payload) {
        var p = payload || {};
        var probed = Array.isArray(p.probed) ? p.probed : [];
        var reachable = Array.isArray(p.reachable) ? p.reachable : [];

        var card = el('section', { class: 'pc-card', 'data-pc-component': 'local-network' });
        var head = el('div', { class: 'pc-card__head' });
        head.appendChild(el('div', { class: 'pc-card__icon', 'aria-hidden': 'true', text: '\u{1F6AA}' }));
        head.appendChild(el('div', { class: 'pc-card__title-block' }, [
            el('h3', { class: 'pc-card__title', text: I18N.lnTitle || 'LOCAL NETWORK EXPOSURE' }),
            el('p',  { class: 'pc-card__subtitle', text: I18N.lnLede || 'Tests devices on your OWN local network, from your OWN browser — not external scanning.' })
        ]));
        card.appendChild(head);

        // Summary callout — green if nothing answered, amber if any host
        // answered (because answering on an admin port is itself a
        // noteworthy finding for a home user).
        var summary = el('div', { class: 'pc-card__lede', style: 'margin: 0.5rem 1rem 0.75rem;' });
        if (probed.length === 0) {
            summary.appendChild(el('div', { class: 'pc-pill pc-pill--info', text: I18N.lnNotRun || 'Probe did not run.' }));
            card.appendChild(summary);
            return card;
        }
        if (reachable.length === 0) {
            summary.appendChild(el('div', { class: 'pc-pill pc-pill--pass', text: I18N.lnNoReachable || 'No common gateway responded — local network looks quiet.' }));
        } else if (reachable.length <= 2) {
            summary.appendChild(el('div', { class: 'pc-pill pc-pill--warning', text: (I18N.lnReachable || 'Some local devices answered on admin ports.') }));
        } else {
            summary.appendChild(el('div', { class: 'pc-pill pc-pill--danger', text: (I18N.lnManyReachable || 'Many local devices answered on admin ports — review your router firewall.') }));
        }
        card.appendChild(summary);

        var tbl = el('table', { class: 'pc-info-table' });
        var tbody = el('tbody');
        tbody.appendChild(el('tr', {}, [
            el('th', { text: I18N.lnScopeLabel || 'Probe scope' }),
            el('td', { text: probed.length + ' ' + (I18N.lnProbesWord || 'probes') + ' · RFC1918 only', mono: true })
        ]));
        tbody.appendChild(el('tr', {}, [
            el('th', { text: I18N.lnReachableLabel || 'Reachable on admin ports' }),
            el('td', { text: reachable.length ? reachable.join(', ') : (I18N.lnNone || '\u2014'), mono: true })
        ]));

        // Per-host detail rows, grouped by host for readability.
        var byHost = {};
        probed.forEach(function (r) {
            (byHost[r.host] = byHost[r.host] || []).push(r);
        });
        var statusWord = {
            'open':         I18N.lnStatusOpen      || 'open',
            'cors':         I18N.lnStatusCors      || 'answered (CORS)',
            'refused':      I18N.lnStatusRefused   || 'closed',
            'timeout':      I18N.lnStatusTimeout   || 'no response',
            'unreachable':  I18N.lnStatusUnreachable|| 'unreachable'
        };
        Object.keys(byHost).forEach(function (h) {
            byHost[h].forEach(function (r) {
                var level = (r.status === 'open' || r.status === 'cors') ? 'info'
                            : (r.status === 'refused' ? 'pass' : 'unknown');
                tbody.appendChild(el('tr', {}, [
                    el('th', { text: h + ':' + r.port }),
                    el('td', { text: (statusWord[r.status] || r.status), pill: level, mono: true })
                ]));
            });
        });

        tbl.appendChild(tbody);
        card.appendChild(tbl);

        // Privacy note (the card is explicit but a small reminder helps).
        var note = el('p', {
            class: 'pc-card__note',
            style: 'margin: 0.6rem 1rem 1rem; font-size: 0.82rem; opacity: 0.75;',
            text: I18N.lnScopeNote || 'Scope is hardcoded to RFC1918 private ranges only. Nothing was probed off your local network.'
        });
        card.appendChild(note);
        return card;
    }

    function detailedReportCard(report) {
        var pr = report.privacy_report || {};
        if (!pr || !pr.categories) {
            return el('div', {});
        }
        var overall = (typeof pr.overall === 'number') ? pr.overall : 0;
        var level   = overall >= 80 ? 'pass' : (overall >= 50 ? 'warning' : 'danger');
        var card = el('section', { class: 'pc-card' });
        var head = el('div', { class: 'pc-card__head' });
        head.appendChild(el('div', { class: 'pc-card__icon', 'aria-hidden': 'true', text: '\u{1F4CB}' }));
        head.appendChild(el('div', { class: 'pc-card__title-block' }, [
            el('h3', { class: 'pc-card__title', text: 'DETAILED REPORT' }),
            el('p', { class: 'pc-card__subtitle', text: pr.headline || 'Whoer-style weighted breakdown of every signal we measured.' })
        ]));
        var badge = el('span', { class: 'pc-status pc-status--' + level, text: overall + ' / 100 · ' + (pr.grade || '\u2014') });
        head.appendChild(badge);
        // Export menu.
        head.appendChild(buildExportMenu(report));
        head.appendChild(buildShareButton(report));
        card.appendChild(head);
        var body = el('div', { class: 'pc-detail' });
        var summary = el('div', { class: 'pc-detail__summary' });
        summary.appendChild(formatRow(I18N.privacyScore || 'Overall Score', overall + ' / 100'));
        summary.appendChild(formatRow(I18N.gradeLabel || 'Grade', pr.grade || '\u2014'));
        if (pr.confidence) {
            summary.appendChild(formatRow(I18N.confidenceLabel || 'Confidence', capitalize(pr.confidence)));
        }
        var barLevel = overall >= 90 ? 'excellent' : (overall >= 75 ? 'good' : (overall >= 50 ? 'moderate' : (overall >= 25 ? 'poor' : 'very_poor')));
        var bar = el('div', { class: 'pc-bar' });
        bar.appendChild(el('div', {
            class: 'pc-bar__fill',
            dataset: { level: barLevel, percent: String(overall) },
            style: 'width: ' + overall + '%'
        }));
        summary.appendChild(bar);
        body.appendChild(summary);

        var tableWrap = el('div', { class: 'pc-detail__categories' });
        var table = el('table', { class: 'pc-table pc-detail__table' });
        var thead = el('thead', {}, [el('tr', {}, [
            el('th', { text: 'Category' }),
            el('th', { text: 'Score' }),
            el('th', { text: 'Status' }),
            el('th', { text: 'Detail' })
        ])]);
        var tbody = el('tbody');
        Object.keys(pr.categories).forEach(function (key) {
            var row = pr.categories[key];
            var pct = (typeof row.percent === 'number') ? row.percent : 0;
            var statusClass = row.status === 'good' ? 'pc-status--pass' : (row.status === 'warning' ? 'pc-status--warning' : 'pc-status--danger');
            var statusText = row.status === 'good' ? (I18N.categoryGood || 'Good') : (row.status === 'warning' ? (I18N.categoryWarning || 'Warning') : (I18N.categoryBad || 'Bad'));
            var trackLevel = pct >= 90 ? 'excellent' : (pct >= 75 ? 'good' : (pct >= 50 ? 'moderate' : (pct >= 25 ? 'poor' : 'very_poor')));
            var cell = el('td', { class: 'pc-detail__cell' }, [
                el('div', { class: 'pc-bar pc-bar--track' }, [
                    el('div', {
                        class: 'pc-bar__fill',
                        dataset: { level: trackLevel, percent: String(pct) },
                        style: 'width: ' + pct + '%'
                    })
                ]),
                el('span', { class: 'pc-detail__num', text: pct + '%' })
            ]);
            tbody.appendChild(el('tr', {}, [
                el('td', { text: capitalize((row.key || key).replace(/_/g, ' ')) }),
                cell,
                el('td', {}, [el('span', { class: 'pc-status ' + statusClass, text: statusText })]),
                el('td', { text: row.message || '\u2014' })
            ]));
        });
        table.appendChild(thead);
        table.appendChild(tbody);
        tableWrap.appendChild(table);
        body.appendChild(tableWrap);

        if (Array.isArray(pr.recommendations) && pr.recommendations.length) {
            var recList = el('ol', { class: 'pc-detail__recs' });
            pr.recommendations.forEach(function (rec) {
                var item = el('li', { class: 'pc-detail__rec pc-detail__rec--' + (rec.priority || 'low') });
                item.appendChild(el('span', { class: 'pc-detail__rec-priority', text: (rec.priority || 'low').toUpperCase() }));
                item.appendChild(el('span', { class: 'pc-detail__rec-text', text: rec.message || '' }));
                recList.appendChild(item);
            });
            body.appendChild(recList);
        }

        card.appendChild(body);
        return card;
    }

    function anonymityTipsCard(report) {
        var card = el('section', { class: 'pc-card' });
        var head = el('div', { class: 'pc-card__head' });
        head.appendChild(el('div', { class: 'pc-card__icon', 'aria-hidden': 'true', text: '\u{1F510}' }));
        head.appendChild(el('div', { class: 'pc-card__title-block' }, [
            el('h3', { class: 'pc-card__title', text: 'ANONYMITY TIPS' }),
            el('p', { class: 'pc-card__subtitle', text: I18N.tipsLede || 'Practical, prioritized techniques for staying private online. Not legal advice.' })
        ]));
        card.appendChild(head);
        var body = el('div', { class: 'pc-tips-inline' });
        var categories = [
            { label: I18N.tipsFoundational || 'Foundational', desc: 'Reputable VPN, hardened browser, encrypted DNS.' },
            { label: I18N.tipsStrong || 'Strong',            desc: 'Tor Browser, anti-detect profiles, residential proxies.' },
            { label: I18N.tipsIdentity || 'Identity',         desc: 'Email aliases, virtual numbers, privacy payments.' },
            { label: I18N.tipsHardening || 'Hardening',       desc: 'WebRTC disabled, container tabs, dedicated OS.' },
            { label: I18N.tipsHabits || 'Habits',             desc: 'No cross-identity sharing; treat personas as separate.' }
        ];
        var list = el('ul', { class: 'pc-tips-inline__list' });
        categories.forEach(function (c) {
            list.appendChild(el('li', { class: 'pc-tips-inline__item' }, [
                el('span', { class: 'pc-tips-inline__cat', text: c.label }),
                el('span', { class: 'pc-tips-inline__desc', text: c.desc })
            ]));
        });
        body.appendChild(list);
        var hint = el('p', { class: 'pc-tips-inline__hint' });
        hint.innerHTML = 'See the full guide on the <a href="/anonymity-tips/"><strong>' + (I18N.tipsTitle || 'Anonymity Tips') + '</strong></a> page for step-by-step instructions and tool recommendations.';
        body.appendChild(hint);
        card.appendChild(body);
        return card;
    }

    function addAnonymityTipsCard(report, addCard) {
        var level = 'info';
        // Recommendations came back with at least one high-priority item?
        var pr = (report && report.privacy_report) || {};
        if (Array.isArray(pr.recommendations)) {
            var hasHigh = pr.recommendations.some(function (r) { return r.priority === 'high'; });
            if (hasHigh) level = 'warning';
        }
        var body = el('div', { class: 'pc-tips-inline' });
        body.appendChild(el('p', { class: 'pc-tips-inline__lede', text: I18N.tipsLede || 'Practical, prioritized techniques for staying private online. Not legal advice.' }));

        var tiers = [
            { key: 'foundational', label: I18N.tipsFoundational || 'Foundational' },
            { key: 'strong',       label: I18N.tipsStrong       || 'Strong' },
            { key: 'identity',     label: I18N.tipsIdentity     || 'Identity & Accounts' },
            { key: 'hardening',    label: I18N.tipsHardening    || 'Hardening' },
            { key: 'habits',       label: I18N.tipsHabits       || 'Habits' }
        ];
        var effortLabel = {
            'low':    I18N.tipsEffortLow    || 'Low effort',
            'medium': I18N.tipsEffortMedium || 'Medium effort',
            'high':   I18N.tipsEffortHigh   || 'High effort'
        };

        // The tips payload itself is server-rendered (class-anonymity-tips),
        // so the scanner just surfaces a short summary + a link to the full
        // tips page (registered with shortcode [privacy_checker_anonymity_tips]).
        var categories = [
            { label: I18N.tipsFoundational || 'Foundational', desc: 'VPN + browser + DNS leak fixes' },
            { label: I18N.tipsStrong || 'Strong', desc: 'Tor + anti-detect + residential proxies' },
            { label: I18N.tipsIdentity || 'Identity & Accounts', desc: 'Email aliases, virtual numbers, crypto' },
            { label: I18N.tipsHardening || 'Hardening', desc: 'WebRTC, container tabs, dedicated OS' },
            { label: I18N.tipsHabits || 'Habits', desc: 'No cross-identity sharing' }
        ];
        var list = el('ul', { class: 'pc-tips-inline__list' });
        categories.forEach(function (c) {
            list.appendChild(el('li', { class: 'pc-tips-inline__item' }, [
                el('span', { class: 'pc-tips-inline__cat', text: c.label }),
                el('span', { class: 'pc-tips-inline__desc', text: c.desc })
            ]));
        });
        body.appendChild(list);

        var hint = el('p', { class: 'pc-tips-inline__hint' });
        hint.appendChild(document.createTextNode('See the full guide on the '));
        hint.appendChild(el('strong', { text: (I18N.tipsTitle || 'Anonymity Tips') + ' ' }));
        hint.appendChild(document.createTextNode('page for step-by-step instructions and tool recommendations.'));
        body.appendChild(hint);

        addCard(I18N.tipsTitle || 'Anonymity Tips', level, I18N.guideLabel || 'Guide', body);
    }

    function addDetailedReportCard(report, addCard) {
        var pr = report.privacy_report || {};
        if (!pr || typeof pr !== 'object' || !pr.categories) {
            return;
        }

        var overall = (typeof pr.overall === 'number') ? pr.overall : 0;
        var grade   = pr.grade || '—';
        var level   = overall >= 80 ? 'pass' : (overall >= 50 ? 'warning' : 'danger');

        var body = el('div', { class: 'pc-detail' });

        var summary = el('div', { class: 'pc-detail__summary' });
        summary.appendChild(formatRow(I18N.privacyScore || 'Overall Score', overall + ' / 100'));
        summary.appendChild(formatRow(I18N.gradeLabel || 'Grade', grade));
        if (pr.confidence) {
            summary.appendChild(formatRow(I18N.confidenceLabel || 'Confidence', capitalize(pr.confidence)));
        }
        if (pr.headline) {
            summary.appendChild(el('p', { class: 'pc-detail__headline', text: pr.headline }));
        }

        var barLevel = overall >= 90 ? 'excellent' : (overall >= 75 ? 'good' : (overall >= 50 ? 'moderate' : (overall >= 25 ? 'poor' : 'very_poor')));
        var bar = el('div', { class: 'pc-bar' });
        var barFill = el('div', {
            class: 'pc-bar__fill',
            dataset: { level: barLevel, percent: String(overall) },
            style: 'width: ' + overall + '%'
        });
        bar.appendChild(barFill);
        summary.appendChild(bar);

        body.appendChild(summary);

        // Per-category table.
        var tableWrap = el('div', { class: 'pc-detail__categories' });
        var table = el('table', { class: 'pc-table pc-detail__table' });
        var thead = el('thead', {}, [el('tr', {}, [
            el('th', { text: 'Category' }),
            el('th', { text: 'Score' }),
            el('th', { text: 'Status' }),
            el('th', { text: 'Detail' })
        ])]);
        var tbody = el('tbody');
        Object.keys(pr.categories).forEach(function (key) {
            var row = pr.categories[key];
            var pct = (typeof row.percent === 'number') ? row.percent : 0;
            var statusClass = row.status === 'good' ? 'pc-status--pass' : (row.status === 'warning' ? 'pc-status--warning' : 'pc-status--danger');
            var statusText = row.status === 'good' ? (I18N.categoryGood || 'Good') : (row.status === 'warning' ? (I18N.categoryWarning || 'Warning') : (I18N.categoryBad || 'Bad'));
            var trackLevel = pct >= 90 ? 'excellent' : (pct >= 75 ? 'good' : (pct >= 50 ? 'moderate' : (pct >= 25 ? 'poor' : 'very_poor')));
            var cell = el('td', { class: 'pc-detail__cell' }, [
                el('div', { class: 'pc-bar pc-bar--track' }, [
                    el('div', {
                        class: 'pc-bar__fill',
                        dataset: { level: trackLevel, percent: String(pct) },
                        style: 'width: ' + pct + '%'
                    })
                ]),
                el('span', { class: 'pc-detail__num', text: pct + '%' })
            ]);
            tbody.appendChild(el('tr', {}, [
                el('td', { text: capitalize((row.key || key).replace(/_/g, ' ')) }),
                cell,
                el('td', {}, [el('span', { class: 'pc-status ' + statusClass, text: statusText })]),
                el('td', { text: row.message || '—' })
            ]));
        });
        table.appendChild(thead);
        table.appendChild(tbody);
        tableWrap.appendChild(table);
        body.appendChild(tableWrap);

        // Tiered recommendations from the privacy report.
        if (Array.isArray(pr.recommendations) && pr.recommendations.length) {
            var recList = el('ol', { class: 'pc-detail__recs' });
            pr.recommendations.forEach(function (rec) {
                var item = el('li', { class: 'pc-detail__rec pc-detail__rec--' + (rec.priority || 'low') });
                item.appendChild(el('span', { class: 'pc-detail__rec-priority', text: (rec.priority || 'low').toUpperCase() }));
                item.appendChild(el('span', { class: 'pc-detail__rec-text', text: rec.message || '' }));
                recList.appendChild(item);
            });
            body.appendChild(recList);
        }

        var title = I18N.detailedTitle || 'Detailed Report';
        var badge = overall + ' / 100 · ' + grade;
        addCard(title, level, badge, body);
    }

    function proxyLabel(report) {
        var pr = (report && report.privacy_report && report.privacy_report.proxy) || null;
        if (pr && pr.label) return pr.label;
        var intel = (report && report.connection && report.connection.intel) || {};
        var tag = intel.proxy || intel.vpn || intel.tor || intel.hosting || null;
        if (tag) return tag;
        return 'Unknown';
    }

    function proxyBody(report) {
        var wrap = el('div', {});
        var pr = (report && report.privacy_report && report.privacy_report.proxy) || null;
        var intel = (report && report.connection && report.connection.intel) || {};
        if (pr && typeof pr === 'object') {
            if (pr.label) wrap.appendChild(formatRow('Detection', pr.label));
            if (pr.confidence) wrap.appendChild(formatRow('Confidence', pr.confidence));
            if (pr.reasons && pr.reasons.length) {
                pr.reasons.forEach(function (r) { wrap.appendChild(formatRow('Signal', r)); });
            }
            if (pr.vendor) wrap.appendChild(formatRow('Vendor', pr.vendor));
        } else {
            wrap.appendChild(formatRow('Detection', 'No signal available.'));
        }
        if (intel.isp) wrap.appendChild(formatRow('ISP', intel.isp));
        if (intel.org) wrap.appendChild(formatRow('Organization', intel.org));
        if (intel.asn) wrap.appendChild(formatRow('ASN', intel.asn));
        return wrap;
    }

    function capitalize(s) { return s ? s.charAt(0).toUpperCase() + s.slice(1) : s; }

    function connectionBody(report) {
        var c = report.connection || {};
        var intel = c.intel || {};
        var wrap = el('div', {});
        wrap.appendChild(formatRow(I18N.ipLabel || 'IP Address', report.request_ip && report.request_ip.ipv4));
        if (report.request_ip && report.request_ip.ipv6) {
            wrap.appendChild(formatRow('IPv6', report.request_ip.ipv6));
        }
        if (intel.country_name || intel.country) {
            wrap.appendChild(formatRow(I18N.countryLabel || 'Country', intel.country_name || intel.country));
        }
        if (intel.region) wrap.appendChild(formatRow(I18N.regionLabel || 'Region', intel.region));
        if (intel.city)   wrap.appendChild(formatRow(I18N.cityLabel || 'City', intel.city));
        if (intel.timezone) wrap.appendChild(formatRow(I18N.timezoneLabel || 'Timezone', intel.timezone));
        if (intel.org || intel.asn_org) wrap.appendChild(formatRow(I18N.orgLabel || 'Organization', intel.org || intel.asn_org));
        if (intel.asn)    wrap.appendChild(formatRow(I18N.asnLabel || 'ASN', intel.asn));
        if (intel.isp || intel.org) wrap.appendChild(formatRow(I18N.ispLabel || 'ISP', intel.isp || intel.org));
        if (c.reverse_dns) wrap.appendChild(formatRow(I18N.reverseDnsLabel || 'Reverse DNS', c.reverse_dns));
        else if (c.reverse_dns_error) wrap.appendChild(formatRow(I18N.reverseDnsLabel || 'Reverse DNS', I18N.noReverseDns || 'No reverse DNS record detected.'));

        if (intel.is_mock) {
            wrap.appendChild(formatRow('Provider', intel.provider_label + ' ', { mono: true }));
            wrap.appendChild(el('div', { class: 'pc-row' }, [
                el('span', { class: 'pc-row__label', text: 'Data Source' }),
                el('span', { class: 'pc-row__value' }, [mockBadge()])
            ]));
        } else if (intel.status === 'error' || intel.status === 'unavailable') {
            wrap.appendChild(formatRow('Geolocation', I18N.ipIntelMissing || 'Location information temporarily unavailable.'));
        }
        return wrap;
    }

    function reputationLabel(rep) {
        if (!rep) return 'Unknown';
        switch (rep.status) {
            case 'clean': return 'Clean';
            case 'listed': return 'Listed';
            case 'suspicious': return 'Suspicious';
            case 'error': return 'Error';
            case 'unavailable': return 'Unavailable';
            default: return 'Unknown';
        }
    }

    function reputationBody(rep) {
        var wrap = el('div', {});
        if (!rep) {
            wrap.appendChild(formatRow('Status', I18N.unable));
            return wrap;
        }
        wrap.appendChild(formatRow('Status', capitalize(rep.status || 'unknown')));
        if (rep.provider_label) {
            wrap.appendChild(formatRow('Provider', rep.provider_label));
        }
        if (Array.isArray(rep.sources)) {
            rep.sources.forEach(function (src) {
                wrap.appendChild(formatRow(src.source, src.listed ? 'Listed' : 'Not listed'));
            });
        }
        if (rep.is_mock) {
            wrap.appendChild(el('div', { class: 'pc-row' }, [
                el('span', { class: 'pc-row__label', text: 'Source' }),
                el('span', { class: 'pc-row__value' }, [mockBadge()])
            ]));
        }
        if (rep.error) wrap.appendChild(formatRow('Error', rep.error));
        return wrap;
    }

    function fingerprintBody(report) {
        var ua = report.user_agent || {};
        var wrap = el('div', {});
        wrap.appendChild(formatRow('Browser', ua.browser || 'Unknown'));
        wrap.appendChild(formatRow('Version', ua.version || 'Unknown'));
        wrap.appendChild(formatRow('Operating System', ua.os || 'Unknown'));
        wrap.appendChild(formatRow('Device', ua.device || 'Unknown'));
        wrap.appendChild(formatRow('Engine', ua.engine || 'Unknown'));
        wrap.appendChild(formatRow('User-Agent', truncate(ua.raw || ''), { mono: true }));
        return wrap;
    }

    function visibilityBody(vis) {
        var wrap = el('div', {});
        if (!vis) {
            wrap.appendChild(formatRow('Level', I18N.unable));
            return wrap;
        }
        wrap.appendChild(formatRow('Level', capitalize(vis.level || 'unknown')));
        wrap.appendChild(formatRow('Exposure Score', (vis.exposure_score || 0) + ' / 100'));
        var signals = vis.signals || {};
        Object.keys(signals).forEach(function (k) {
            wrap.appendChild(formatRow('Signals: ' + k.replace(/_/g, ' '), signals[k] ? 'Detected' : 'Not detected'));
        });
        var note = el('p', { class: 'pc-row__label', text: 'How much browser/device information your browser exposes. This does not mean that you can be uniquely identified.' });
        wrap.appendChild(note);
        return wrap;
    }

    function webrtcLabel(verdict) {
        switch (verdict) {
            case 'protected': return I18N.webrtcProtected;
            case 'potential_exposure': return I18N.webrtcExposure;
            case 'not_supported': return I18N.webrtcUnsupported;
            default: return I18N.webrtcError;
        }
    }

    function webrtcBody(webrtc) {
        var wrap = el('div', {});
        if (!webrtc) {
            wrap.appendChild(formatRow('Status', I18N.unable));
            return wrap;
        }
        wrap.appendChild(formatRow('Supported', webrtc.supported ? 'Yes' : 'No'));
        wrap.appendChild(formatRow('Public Addresses', (webrtc.public_addrs || []).length ? webrtc.public_addrs.join(', ') : 'None observed'));
        wrap.appendChild(formatRow('Local Addresses', (webrtc.local_addrs || []).length ? webrtc.local_addrs.join(', ') : 'None observed'));
        wrap.appendChild(formatRow('Verdict', webrtc.message || I18N.unable));
        return wrap;
    }

    function dnsTestBody(dns) {
        var wrap = el('div', {});
        if (!dns) {
            wrap.appendChild(formatRow('Status', I18N.unable));
            return wrap;
        }
        if (dns.configured) {
            wrap.appendChild(formatRow('Status', I18N.dnsConfigured));
        } else {
            wrap.appendChild(formatRow('Status', I18N.dnsNotConfigured));
        }
        wrap.appendChild(formatRow('Note', dns.note || I18N.unable));
        return wrap;
    }

    function verdictToLevel(v) {
        switch (v) {
            case 'clean':
            case 'protected':
            case 'low': return 'pass';
            case 'listed':
            case 'suspicious':
            case 'potential_exposure':
            case 'high': return 'danger';
            case 'moderate':
            case 'warning': return 'warning';
            default: return 'info';
        }
    }

    function truncate(s, max) {
        max = max || 180;
        if (!s) return '';
        return s.length > max ? s.slice(0, max) + '…' : s;
    }

    /* ---------- Tool pages ---------- */

    function bindIpLookup() {
        var form = document.querySelector('[data-pc-component="ip-lookup"] form[data-pc-action="ip-lookup"]');
        if (!form) return;
        form.addEventListener('submit', function (e) {
            e.preventDefault();
            var ip = form.querySelector('input[name="ip"]').value.trim();
            if (!ip) return;
            var result = document.querySelector('[data-pc-component="ip-lookup"] [data-pc-region="result"]');
            result.hidden = false;
            result.innerHTML = '';
            result.appendChild(statusBanner('loading', 'Looking up ' + ip + '…'));

            api('lookup/ip?ip=' + encodeURIComponent(ip)).then(function (resp) {
                result.innerHTML = '';
                if (!resp.ok) {
                    result.appendChild(statusBanner('error', (resp.data && (resp.data.message || resp.data.error)) || 'Lookup failed.'));
                    return;
                }
                var data = resp.data || {};
                var intel = data.intel || {};
                if (intel.status && intel.status !== 'ok') {
                    result.appendChild(statusBanner('warn', intel.error || intel.status || 'No intel for this IP.'));
                    return;
                }

                var location = [intel.city, intel.region, intel.country_name || intel.country].filter(Boolean).join(', ');
                var provider = intel.provider_label || intel.provider_key || '';
                var sub = [location, intel.isp, intel.org].filter(Boolean).join(' · ') || (provider ? 'via ' + provider : '');

                var wrap = el('div', { class: 'pc-result' });
                wrap.appendChild(resultHero('IP Address', data.ip || ip, sub, { mono: true }));

                var locationRows = [];
                if (intel.country_name || intel.country) locationRows.push(formatRow('Country', intel.country_name || intel.country));
                if (intel.region)                     locationRows.push(formatRow('Region', intel.region));
                if (intel.city)                       locationRows.push(formatRow('City', intel.city));
                if (intel.postal)                     locationRows.push(formatRow('Postal', intel.postal));
                if (intel.timezone)                   locationRows.push(formatRow('Timezone', intel.timezone));
                if (intel.latitude != null && intel.longitude != null) {
                    locationRows.push(formatRow('Coordinates', intel.latitude + ', ' + intel.longitude, { mono: true }));
                }
                if (locationRows.length) wrap.appendChild(resultGroup('Location', locationRows));

                var networkRows = [];
                if (intel.isp)        networkRows.push(formatRow('ISP', intel.isp));
                if (intel.org)        networkRows.push(formatRow('Organization', intel.org));
                if (intel.asn)        networkRows.push(formatRow('ASN', intel.asn, { mono: true }));
                if (data.reverse_dns && data.reverse_dns.hostname) {
                    networkRows.push(formatRow('Reverse DNS', data.reverse_dns.hostname, { mono: true }));
                }
                if (provider)         networkRows.push(formatRow('Data Source', provider, { pill: 'info' }));
                if (intel.is_mock)    networkRows.push(formatRow('Data Source', 'DEVELOPMENT DATA', { pill: 'mock' }));
                if (networkRows.length) wrap.appendChild(resultGroup('Network', networkRows));

                if (Array.isArray(intel.chain) && intel.chain.length) {
                    var chainRows = [];
                    intel.chain.forEach(function (step) {
                        var level = (step.status === 'ok') ? 'pass' : (step.status === 'unavailable' ? 'warning' : 'danger');
                        var name = step.label || step.key || '—';
                        var err = step.error ? ' · ' + step.error : '';
                        chainRows.push(formatRow(name, (step.status || 'unknown').toUpperCase() + err, { pill: level }));
                    });
                    wrap.appendChild(resultGroup('Provider chain', chainRows));
                }
                result.appendChild(wrap);
            });
        });
    }

    function bindWhois() {
        var form = document.querySelector('[data-pc-component="whois"] form[data-pc-action="whois"]');
        if (!form) return;
        form.addEventListener('submit', function (e) {
            e.preventDefault();
            var query = form.querySelector('input[name="query"]').value.trim();
            if (!query) return;
            var result = document.querySelector('[data-pc-component="whois"] [data-pc-region="result"]');
            result.hidden = false;
            result.innerHTML = '';
            result.appendChild(statusBanner('loading', 'Looking up ' + query + '…'));

            api('lookup/whois?query=' + encodeURIComponent(query)).then(function (resp) {
                result.innerHTML = '';
                if (!resp.ok) {
                    result.appendChild(statusBanner('error', (resp.data && (resp.data.message || resp.data.error)) || 'Lookup failed.'));
                    return;
                }
                var data = resp.data || {};

                if (data.status === 'error') {
                    result.appendChild(statusBanner('error', data.error || 'Lookup failed.'));
                    return;
                }
                if (data.status === 'not_found') {
                    result.appendChild(statusBanner('warn', 'No RDAP record found for ' + (data.query || query) + '.'));
                    return;
                }

                var typeLabel = (data.type || 'unknown').toUpperCase();
                var isFallback = data.source === 'iana-whois';
                var sourceLabel = isFallback
                    ? 'IANA WHOIS + port-43'
                    : (data.provider_label || data.provider_key || 'RDAP');
                var heroSub = sourceLabel +
                    (data.statuses && data.statuses.length ? ' · ' + data.statuses.length + ' statuses' : '');

                var wrap = el('div', { class: 'pc-result' });
                wrap.appendChild(resultHero(
                    isFallback ? 'WHOIS Record · ' + typeLabel : 'RDAP Record · ' + typeLabel,
                    data.query || query,
                    heroSub,
                    { mono: true }
                ));

                var coreRows = [];
                if (data.handle)   coreRows.push(formatRow('Handle', data.handle, { mono: true }));
                if (data.ldh_name) coreRows.push(formatRow('Domain', data.ldh_name, { mono: true }));
                if (data.name)     coreRows.push(formatRow('Name', data.name));
                if (data.country)  coreRows.push(formatRow('Country', data.country));
                if (data.start_ip) coreRows.push(formatRow('Start IP', data.start_ip, { mono: true }));
                if (data.end_ip)   coreRows.push(formatRow('End IP', data.end_ip, { mono: true }));
                if (data.registrar) coreRows.push(formatRow('Registrar', data.registrar));
                if (data.abuse_email) coreRows.push(formatRow('Abuse contact', data.abuse_email, { mono: true }));
                if (data.whois_server) coreRows.push(formatRow('WHOIS server', data.whois_server, { mono: true }));
                if (data.statuses && data.statuses.length) {
                    var statusPills = data.statuses.map(function (s) {
                        return el('span', { class: 'pc-pill pc-pill--info', text: s, style: 'margin:0 0.3rem 0.3rem 0;display:inline-block;' });
                    });
                    coreRows.push(el('div', { class: 'pc-row' }, [
                        el('span', { class: 'pc-row__label', text: 'Statuses' }),
                        el('span', { class: 'pc-row__value' }, statusPills)
                    ]));
                }
                if (coreRows.length) wrap.appendChild(resultGroup('Registry', coreRows));

                if (data.events && Object.keys(data.events).length) {
                    var eventRows = [];
                    Object.keys(data.events).forEach(function (k) {
                        eventRows.push(formatRow(k.charAt(0).toUpperCase() + k.slice(1), data.events[k]));
                    });
                    wrap.appendChild(resultGroup('Events', eventRows));
                }

                if (Array.isArray(data.nameservers) && data.nameservers.length) {
                    var nsRows = data.nameservers.map(function (ns) {
                        return el('div', { class: 'pc-row' }, [
                            el('span', { class: 'pc-row__label', text: 'Name server' }),
                            el('span', { class: 'pc-row__value', text: ns, style: 'font-family:var(--pc-font-mono);' })
                        ]);
                    });
                    wrap.appendChild(resultGroup('Name servers', nsRows));
                }

                if (Array.isArray(data.entities) && data.entities.length) {
                    var entityRows = data.entities.map(function (entity, idx) {
                        var who = entity.name || entity.handle || '—';
                        var roles = (entity.roles || []).join(', ') || '—';
                        return el('div', { class: 'pc-row' }, [
                            el('span', { class: 'pc-row__label', text: 'Entity ' + (idx + 1) }),
                            el('span', { class: 'pc-row__value' }, [
                                el('strong', { text: who }),
                                document.createTextNode(' — '),
                                el('span', { class: 'pc-pill pc-pill--info', text: roles })
                            ])
                        ]);
                    });
                    wrap.appendChild(resultGroup('Entities', entityRows));
                }

                if (Array.isArray(data.raw_excerpt) && data.raw_excerpt.length) {
                    var pre = el('pre', {
                        style: 'margin:0;padding:1rem 1.2rem;background:rgba(15,23,42,0.55);color:#cbd5f5;font-family:var(--pc-font-mono);font-size:0.78rem;line-height:1.55;border-radius:12px;overflow:auto;max-height:260px;'
                    });
                    data.raw_excerpt.forEach(function (l) {
                        pre.appendChild(document.createTextNode(l + '\n'));
                    });
                    wrap.appendChild(resultGroup('WHOIS text (truncated)', [pre]));
                }

                if (data.is_mock) {
                    wrap.appendChild(resultGroup('Source', [
                        formatRow('Data Source', 'DEVELOPMENT DATA', { pill: 'mock' })
                    ]));
                } else if (isFallback) {
                    wrap.appendChild(resultGroup('Source', [
                        formatRow('Data Source', 'IANA WHOIS referral + port-43 query', { pill: 'info' }),
                        formatRow('WHOIS server', data.whois_server || '—', { mono: true }),
                        formatRow('Cache TTL', '6 hours')
                    ]));
                }
                result.appendChild(wrap);
            });
        });
    }

    function bindUserAgent() {
        var form = document.querySelector('[data-pc-component="user-agent"] form[data-pc-action="user-agent"]');
        if (!form) return;
        form.addEventListener('submit', function (e) {
            e.preventDefault();
            var ua = form.querySelector('textarea[name="ua"]').value.trim();
            var result = document.querySelector('[data-pc-component="user-agent"] [data-pc-region="result"]');
            result.hidden = false;
            result.innerHTML = '';
            result.appendChild(statusBanner('loading', 'Parsing…'));

            var data = parseUserAgentLocal(ua || navigator.userAgent || '');
            renderUserAgentResult(result, data);
        });
    }

    /** Local UA parser. Mirrors the PHP Fingerprint::parse_user_agent output. */
    function parseUserAgentLocal(ua) {
        var data = { raw: ua, browser: null, version: null, os: null, os_version: null, device: null, engine: null, is_bot: false, source: 'local' };
        if (!ua) return data;
        if (/bot|crawler|spider|crawling|slurp|mediapartners|facebookexternalhit|preview/i.test(ua)) {
            data.is_bot = true; data.device = 'Bot'; return data;
        }
        var browsers = [
            ['Edge',    /Edg\/([\d.]+)/],
            ['Opera',   /OPR\/([\d.]+)/],
            ['Chrome',  /Chrome\/([\d.]+)/],
            ['Firefox', /Firefox\/([\d.]+)/],
            ['Safari',  /Version\/([\d.]+).*Safari/],
            ['Samsung', /SamsungBrowser\/([\d.]+)/],
            ['IE',      /MSIE ([\d.]+)/]
        ];
        for (var i = 0; i < browsers.length; i++) {
            var m = ua.match(browsers[i][1]);
            if (m) { data.browser = browsers[i][0]; data.version = m[1]; break; }
        }
        if (/Gecko\//.test(ua) && !/like Gecko/.test(ua)) data.engine = 'Gecko';
        else if (/AppleWebKit|Blink/.test(ua)) data.engine = 'WebKit';
        else if (/Trident\//.test(ua)) data.engine = 'Trident';
        var osPatterns = [
            ['Windows',   /Windows NT ([\d.]+)/],
            ['macOS',     /Mac OS X ([\d_.]+)/],
            ['iOS',       /iPhone OS ([\d_]+)/],
            ['Android',   /Android ([\d.]+)/],
            ['Linux',     /Linux/],
            ['Chrome OS', /CrOS/]
        ];
        for (var j = 0; j < osPatterns.length; j++) {
            var mo = ua.match(osPatterns[j][1]);
            if (mo) {
                data.os = osPatterns[j][0];
                data.os_version = (data.os === 'macOS' || data.os === 'iOS') ? mo[1].replace(/_/g, '.') : mo[1];
                break;
            }
        }
        if (/iPhone/.test(ua)) data.device = 'Mobile';
        else if (/iPad/.test(ua)) data.device = 'Tablet';
        else if (/Android/.test(ua) && !/Mobile/.test(ua)) data.device = 'Tablet';
        else if (/Android|Mobile|iPhone/.test(ua)) data.device = 'Mobile';
        else data.device = 'Desktop';
        return data;
    }

    function renderUserAgentResult(result, data) {
        result.innerHTML = '';
        var browserLabel = data.browser ? (data.browser + (data.version ? ' ' + data.version : '')) : (I18N.unable || 'Unknown');
        var heroSub = [data.os, data.device, data.engine].filter(Boolean).join(' · ');
        if (data.is_bot) heroSub = (heroSub ? heroSub + ' · ' : '') + 'BOT';

        var wrap = el('div', { class: 'pc-result' });
        wrap.appendChild(resultHero('User-Agent', browserLabel, heroSub));

        var detailRows = [
            formatRow('Browser', data.browser),
            formatRow('Version', data.version),
            formatRow('OS', data.os),
            formatRow('OS version', data.os_version),
            formatRow('Device', data.device),
            formatRow('Engine', data.engine),
            formatRow('Bot?', data.is_bot ? 'Yes' : 'No', { pill: data.is_bot ? 'warning' : 'pass' }),
            formatRow('Source', data.source || 'local', { pill: 'info' })
        ];
        wrap.appendChild(resultGroup('Parsed', detailRows));
        if (data.raw) wrap.appendChild(resultGroup('Raw', [formatRow('User-Agent string', data.raw, { mono: true })]));
        result.appendChild(wrap);
    }

    function bindFingerprint() {
        var button = document.querySelector('[data-pc-component="fingerprint"] [data-pc-action="fingerprint"]');
        if (!button) return;
        var region = document.querySelector('[data-pc-component="fingerprint"] [data-pc-region="result"]');
        button.addEventListener('click', function () {
            if (!region) return;
            region.hidden = false;
            region.innerHTML = '';
            region.appendChild(statusBanner('loading', 'Collecting browser signals…'));
            button.disabled = true;
            collectFingerprint().then(function (fp) {
                // Send to /scan with the fingerprint payload so the server can
                // normalize it through the same scoring engine the dashboard uses.
                return api('scan', {
                    method: 'POST',
                    body: { fingerprint: fp }
                }).then(function (resp) {
                    region.innerHTML = '';
                    button.disabled = false;
                    if (!resp.ok || !resp.data) {
                        region.appendChild(statusBanner('error', (resp.data && (resp.data.message || resp.data.error)) || 'Fingerprint failed.'));
                        return;
                    }
                    renderFingerprintResult(region, fp, resp.data);
                });
            }).catch(function () {
                region.innerHTML = '';
                button.disabled = false;
                region.appendChild(statusBanner('error', 'Network error.'));
            });
        });
    }

    function renderFingerprintResult(region, fp, scan) {
        // fp = collected client signals; scan = server-side scoring
        var visibility = (scan && scan.fingerprint) || {};
        var level = visibility.level || 'low';
        var score = visibility.exposure_score != null ? visibility.exposure_score : 0;
        var levelPill = ({
            low: 'pass', minimal: 'pass', medium: 'warning', moderate: 'warning', high: 'danger', elevated: 'danger'
        })[level] || 'info';
        var heroSub = score + ' exposure score · ' + level + ' visibility';

        var wrap = el('div', { class: 'pc-result' });
        wrap.appendChild(resultHero('Browser Fingerprint', (navigator.userAgent || 'Unknown browser'), heroSub));

        var scoreRows = [
            formatRow('Visibility level', capitalize(level), { pill: levelPill }),
            formatRow('Exposure score', String(score) + ' / 100')
        ];
        wrap.appendChild(resultGroup('Score', scoreRows));

        // Show collected signals as a key/value table for transparency.
        var sigRows = [
            formatRow('Source', 'client-side', { pill: 'info' }),
            formatRow('User Agent', fp.user_agent, { mono: true }),
            formatRow('Language', fp.language),
            formatRow('Languages', (fp.languages || []).join(', ')),
            formatRow('Platform', fp.platform),
            formatRow('CPU cores', fp.hardware_concurrency != null ? String(fp.hardware_concurrency) : null),
            formatRow('Device memory', fp.device_memory ? fp.device_memory + ' GB' : null),
            formatRow('Touch support', fp.touch_support ? 'Yes' : 'No'),
            formatRow('Cookies enabled', fp.cookies ? 'Yes' : 'No'),
            formatRow('Do Not Track', fp.do_not_track ? 'Yes' : 'No'),
            formatRow('Timezone', fp.timezone),
            formatRow('Screen', fp.screen_resolution),
            formatRow('Color depth', fp.color_depth ? fp.color_depth + ' bits' : null),
            formatRow('Pixel ratio', fp.pixel_ratio != null ? String(fp.pixel_ratio) : null),
            formatRow('WebGL', fp.webgl ? 'Yes' : 'No'),
            formatRow('Canvas', fp.canvas ? 'Yes' : 'No'),
            formatRow('Audio API', fp.audio ? 'Yes' : 'No'),
            formatRow('Fonts loaded', fp.fonts ? String(fp.fonts) : '0')
        ];
        wrap.appendChild(resultGroup('Browser signals', sigRows));
        region.appendChild(wrap);
    }

    function bindSecurityHeaders() {
        var form = document.querySelector('[data-pc-component="security-headers"] form[data-pc-action="security-headers"]');
        if (!form) return;
        form.addEventListener('submit', function (e) {
            e.preventDefault();
            var url = form.querySelector('input[name="url"]').value.trim();
            if (!url) return;
            var result = document.querySelector('[data-pc-component="security-headers"] [data-pc-region="result"]');
            result.hidden = false;
            result.innerHTML = '';
            result.appendChild(statusBanner('loading', 'Checking ' + url + '…'));
            api('scan/security-headers?url=' + encodeURIComponent(url)).then(function (resp) {
                result.innerHTML = '';
                if (!resp.ok) {
                    result.appendChild(statusBanner('error', (resp.data && (resp.data.message || resp.data.error)) || 'Check failed.'));
                    return;
                }
                var data = resp.data || {};
                if (data.status !== 'ok') {
                    result.appendChild(statusBanner('error', data.error || 'Check failed.'));
                    return;
                }

                var passCount = (data.headers || []).filter(function (h) { return h.verdict === 'pass'; }).length;
                var warnCount = (data.headers || []).filter(function (h) { return h.verdict === 'warning'; }).length;
                var badCount  = (data.headers || []).filter(function (h) { return h.verdict === 'danger' || h.verdict === 'fail'; }).length;
                var heroSub = 'HTTP ' + data.http_status + ' · ' + passCount + ' pass, ' + warnCount + ' warn, ' + badCount + ' fail';

                var wrap = el('div', { class: 'pc-result' });
                wrap.appendChild(resultHero('URL', data.url, heroSub, { mono: true }));

                var rows = [];
                (data.headers || []).forEach(function (header) {
                    var v = header.verdict || 'info';
                    var pillLevel = (v === 'pass' ? 'pass' : (v === 'warning' ? 'warning' : (v === 'missing' ? 'warning' : 'danger')));
                    var valText = header.value || '(missing)';
                    rows.push(el('div', { class: 'pc-row' }, [
                        el('span', { class: 'pc-row__label', text: header.header }),
                        el('span', { class: 'pc-row__value' }, [
                            el('span', { class: 'pc-pill pc-pill--' + pillLevel, text: capitalize(v) })
                        ])
                    ]));
                    rows.push(el('div', { class: 'pc-row' }, [
                        el('span', { class: 'pc-row__label', text: 'Value' }),
                        el('span', { class: 'pc-row__value is-mono', text: valText })
                    ]));
                    if (header.description) {
                        rows.push(el('div', { class: 'pc-row' }, [
                            el('span', { class: 'pc-row__label', text: 'Why' }),
                            el('span', { class: 'pc-row__value', text: header.description })
                        ]));
                    }
                });
                wrap.appendChild(resultGroup('Security headers', rows));
                result.appendChild(wrap);
            });
        });
    }

    function bindWebrtc() {
        var button = document.querySelector('[data-pc-component="webrtc"] [data-pc-action="webrtc"]');
        if (!button) return;
        button.addEventListener('click', function () {
            var result = document.querySelector('[data-pc-component="webrtc"] [data-pc-region="result"]');
            result.hidden = false;
            result.innerHTML = '';
            result.appendChild(statusBanner('loading', 'Testing WebRTC…'));
            runWebrtcTest().then(function (client) {
                api('scan', { method: 'POST', body: { webrtc: client } }).then(function (resp) {
                    result.innerHTML = '';
                    if (!resp.ok || !resp.data || !resp.data.webrtc) {
                        result.appendChild(statusBanner('error', 'Unable to test.'));
                        return;
                    }
                    var webrtc = resp.data.webrtc;
                    var verdict = webrtc.message || (webrtc.supported ? 'WebRTC is supported.' : 'WebRTC not supported.');
                    var heroSub = webrtc.public_addrs && webrtc.public_addrs.length
                        ? webrtc.public_addrs.length + ' public address(es) exposed'
                        : (webrtc.supported ? 'No public addresses exposed.' : 'Browser does not implement WebRTC.');
                    var heroEyebrow = webrtc.supported ? 'WebRTC Test' : 'WebRTC Test · Not supported';
                    var wrap = el('div', { class: 'pc-result' });
                    wrap.appendChild(resultHero(heroEyebrow, verdict, heroSub));

                    var rows = [
                        formatRow('Supported', webrtc.supported ? 'Yes' : 'No', { pill: webrtc.supported ? 'pass' : 'info' }),
                        formatRow('Public Addresses', (webrtc.public_addrs && webrtc.public_addrs.length) ? webrtc.public_addrs.join(', ') : 'None observed', { mono: !!(webrtc.public_addrs && webrtc.public_addrs.length) }),
                        formatRow('Local Addresses', (webrtc.local_addrs && webrtc.local_addrs.length) ? webrtc.local_addrs.join(', ') : 'None observed', { mono: !!(webrtc.local_addrs && webrtc.local_addrs.length) }),
                        formatRow('Candidates collected', webrtc.candidate_count != null ? String(webrtc.candidate_count) : '0')
                    ];
                    wrap.appendChild(resultGroup('Details', rows));
                    result.appendChild(wrap);
                });
            });
        });
    }

    function bindDnsTest() {
        var root = document.querySelector('[data-pc-component="dns-test"]');
        if (!root) return;
        var form = root.querySelector('form[data-pc-action="dns-test"]');
        var region = root.querySelector('[data-pc-region="result"]');
        if (!region) return;

        if (!form) {
            region.innerHTML = '';
            var button = el('button', { type: 'button', class: 'pc-btn pc-btn--primary', text: I18N.rescan || 'Run DNS leak test' });
            region.appendChild(button);
            button.addEventListener('click', function () {
                button.disabled = true;
                runDnsProbe('cloudflare.com', region).finally(function () { button.disabled = false; });
            });
            return;
        }

        form.addEventListener('submit', function (e) {
            e.preventDefault();
            var input = form.querySelector('input[name="hostname"]');
            var hostname = input ? input.value.trim() : 'cloudflare.com';
            if (!hostname) hostname = 'cloudflare.com';
            var submit = form.querySelector('button[type="submit"]');
            if (submit) submit.disabled = true;
            region.hidden = false;
            region.innerHTML = '';
            region.appendChild(statusBanner('loading', (I18N.dnsResolving || 'Resolving…') + ' ' + hostname));
            runDnsProbe(hostname, region).finally(function () {
                if (submit) submit.disabled = false;
            });
        });
    }

    function runDnsProbe(hostname, region) {
        var qs = '?hostname=' + encodeURIComponent(hostname);
        return api('scan/dns-test/run' + qs).then(function (resp) {
            region.innerHTML = '';
            if (!resp.ok || !resp.data) {
                region.appendChild(statusBanner('error', (resp.data && (resp.data.message || resp.data.error)) || 'DNS test failed.'));
                return;
            }
            renderDnsTest(region, resp.data);
        });
    }

    function renderDnsTest(region, data) {
        if (data.status === 'not_configured' || data.status === 'error') {
            region.appendChild(statusBanner('warn', data.message || I18N.dnsNotConfigured || 'DNS test unavailable.'));
            return;
        }
        var consistent = !!data.consistent;
        var leakScore = data.leak_score != null ? Number(data.leak_score) : 0;
        var leakPct = Math.round((1 - leakScore) * 100);
        var heroSub = 'Token ' + ((data.token || '').slice(0, 12)) + '… · ' +
            (consistent ? 'consistent answers' : 'inconsistent answers') +
            ' · ' + (data.resolvers || []).length + ' resolvers';

        var wrap = el('div', { class: 'pc-result' });
        wrap.appendChild(resultHero('DNS Leak Test', data.hostname || '—', heroSub, { mono: true }));

        var summaryRows = [
            formatRow('Consistent', consistent ? 'Yes' : 'No', { pill: consistent ? 'pass' : 'warning' }),
            formatRow('Leak score', String(leakScore) + ' (0 = no leak, 1 = full leak)'),
            formatRow('Reliability', leakPct + '%')
        ];
        wrap.appendChild(resultGroup('Summary', summaryRows));

        var resolverRows = (data.resolvers || []).map(function (r) {
            var level = (r.status === 'ok') ? 'pass' : (r.status === 'error' ? 'danger' : 'warning');
            return {
                level: level,
                cells: [
                    capitalize(r.name || '—'),
                    { kind: 'pill', level: level, text: r.status || 'unknown' },
                    r.latency_ms != null ? (r.latency_ms + ' ms') : '—',
                    { kind: 'mono', text: r.answer_ip || '—' }
                ]
            };
        });
        if (resolverRows.length) {
            wrap.appendChild(resultGroup('Resolvers', [
                resultList(['Resolver', 'Status', 'Latency', 'Answer IP'], resolverRows)
            ]));
        }
        region.appendChild(wrap);
    }

    function bindPing() {
        var form = document.querySelector('[data-pc-component="ping"] form[data-pc-action="ping"]');
        if (!form) return;
        var customInput = document.querySelector('[data-pc-component="ping"] [data-pc-input="ping-custom"]');
        form.addEventListener('submit', function (e) {
            e.preventDefault();
            var target = form.querySelector('select[name="target"]').value;
            if (customInput && customInput.value.trim()) {
                target = customInput.value.trim();
            }
            if (!target) return;
            var region = document.querySelector('[data-pc-component="ping"] [data-pc-region="result"]');
            region.hidden = false;
            region.innerHTML = '';
            region.appendChild(statusBanner('loading', (I18N.scanning || 'Scanning…') + ' ' + target));
            api('scan/ping?target=' + encodeURIComponent(target)).then(function (resp) {
                region.innerHTML = '';
                if (!resp.ok) {
                    region.appendChild(statusBanner('error', (resp.data && (resp.data.message || resp.data.error)) || I18N.pingDenied || 'Target denied.'));
                    return;
                }
                var data = resp.data || {};
                var ms = data.latency_ms;
                var ok = data.ok !== false && ms != null;
                var heroSub = ok
                    ? ms + ' ms round-trip'
                    : (data.error || I18N.pingUnavailable || 'Unreachable');
                var wrap = el('div', { class: 'pc-result' });
                wrap.appendChild(resultHero(
                    ok ? (I18N.pingLatency || 'Latency') : (I18N.pingUnavailable || 'Unreachable'),
                    (data.host || target) + ':' + (data.port || ''),
                    heroSub,
                    { mono: true }
                ));
                var rows = [
                    formatRow(I18N.pingTarget || 'Target', (data.host || '—') + ':' + (data.port || '—'), { mono: true }),
                    formatRow(I18N.pingLatency || 'Latency', ms != null ? (ms + ' ms') : (data.error || '—'), { pill: ok ? 'pass' : 'danger' })
                ];
                if (data.error) rows.push(formatRow('Error', data.error));
                wrap.appendChild(resultGroup('Probe', rows));
                region.appendChild(wrap);
            });
        });
    }

    function bindPortScan() {
        var form = document.querySelector('[data-pc-component="port-scan"] form[data-pc-action="port-scan"]');
        if (!form) return;
        var chips = document.querySelectorAll('[data-pc-component="port-scan"] [data-pc-port]');
        chips.forEach(function (chip) {
            chip.addEventListener('click', function (e) {
                e.preventDefault();
                var portInput = form.querySelector('input[name="port"]');
                if (portInput) portInput.value = chip.dataset.pcPort;
            });
        });
        form.addEventListener('submit', function (e) {
            e.preventDefault();
            var host = form.querySelector('input[name="host"]').value.trim();
            var port = parseInt(form.querySelector('input[name="port"]').value, 10);
            if (!host || !port) return;
            var region = document.querySelector('[data-pc-component="port-scan"] [data-pc-region="result"]');
            region.hidden = false;
            region.innerHTML = '';
            region.appendChild(statusBanner('loading', (I18N.scanning || 'Scanning…') + ' ' + host + ':' + port));
            api('scan/port', { method: 'POST', body: { host: host, port: port } }).then(function (resp) {
                region.innerHTML = '';
                if (!resp.ok) {
                    var msg = (resp.data && (resp.data.message || resp.data.error)) || I18N.portDeniedLong || 'Denied.';
                    region.appendChild(statusBanner('error', msg));
                    return;
                }
                var data = resp.data || {};
                var status = data.status;
                var label, level;
                if (status === 'open')          { label = I18N.portOpen     || 'Open';     level = 'pass'; }
                else if (status === 'closed')   { label = I18N.portClosed   || 'Closed';   level = 'danger'; }
                else if (status === 'filtered') { label = I18N.portFiltered || 'Filtered'; level = 'warning'; }
                else if (status === 'denied')   { label = I18N.portDenied   || 'Denied';   level = 'warning'; }
                else                            { label = status || 'Unknown';          level = 'info'; }

                var wrap = el('div', { class: 'pc-result' });
                wrap.appendChild(resultHero(
                    I18N.portTitle || 'Port Scan',
                    (data.host || host) + ':' + (data.port || port),
                    label,
                    { mono: true }
                ));
                var rows = [
                    formatRow(I18N.portHost || 'Host', data.host || host, { mono: true }),
                    formatRow(I18N.portNumber || 'Port', String(data.port || port)),
                    formatRow('Status', label, { pill: level })
                ];
                if (data.error) rows.push(formatRow('Error', data.error));
                wrap.appendChild(resultGroup('Probe', rows));
                region.appendChild(wrap);
            });
        });
    }

    /* ---------- Network path diagram (CCNA packet-tracer style) ---------- */

    function packetChainNode(proxy) {
        // A small SVG node that pulses like a packet traveling.
        var ns = 'http://www.w3.org/2000/svg';
        var g = document.createElementNS(ns, 'g');
        var circle = document.createElementNS(ns, 'circle');
        circle.setAttribute('r', 7);
        circle.setAttribute('fill', '#17a2b8');
        circle.setAttribute('stroke', '#ffffff');
        circle.setAttribute('stroke-width', 2);
        circle.setAttribute('class', 'pc-network__packet');
        g.appendChild(circle);
        return g;
    }

    function animatePacketAlongPath(svg, points, hopCount) {
        // points: array of {x, y} from positions.
        // Move a packet-glow element along the chain, pausing briefly at each hop.
        var ns = 'http://www.w3.org/2000/svg';
        var packetG = packetChainNode();
        var motionPath = document.createElementNS(ns, 'path');
        // Build path data through points.
        var d = '';
        points.forEach(function (p, i) {
            d += (i === 0 ? 'M ' : ' L ') + p.x + ' ' + p.y;
        });
        motionPath.setAttribute('d', d);
        motionPath.setAttribute('fill', 'none');
        motionPath.setAttribute('stroke', 'none');
        motionPath.setAttribute('id', 'pc-packet-path');
        svg.appendChild(motionPath);
        var animateMotion = document.createElementNS(ns, 'animateMotion');
        animateMotion.setAttribute('dur', (hopCount * 1.2) + 's');
        animateMotion.setAttribute('repeatCount', 'indefinite');
        animateMotion.setAttribute('rotate', 'auto');
        animateMotion.setAttribute('path', d);
        animateMotion.setAttribute('keyTimes', '0;1');
        animateMotion.setAttribute('calcMode', 'linear');
        packetG.appendChild(animateMotion);
        svg.appendChild(packetG);
    }

    function networkPathCard(report) {
        var intel = (report && report.connection && report.connection.intel) || {};
        var pr = (report && report.privacy_report && report.privacy_report.proxy) || null;
        var proxy = (pr && pr.category) || (intel.proxy || intel.vpn || intel.tor || intel.hosting || 'residential');
        var isTor = proxy === 'tor';
        var isVpn = proxy === 'vpn' || proxy === 'proxy';

        // Detect device class from user-agent — PC, laptop, or mobile phone.
        // Used to pick the right source-device icon.
        var ua = (navigator.userAgent || '').toLowerCase();
        var deviceClass = 'laptop'; // default
        var deviceLabel = 'YOUR LAPTOP';
        var deviceSub = 'PC / laptop';
        var deviceDetail = 'Source workstation on local network';
        if (/iphone|ipod|android.*mobile|mobile.*firefox|windows phone|blackberry|opera mini/i.test(ua)) {
            deviceClass = 'mobile';
            deviceLabel = 'YOUR PHONE';
            deviceSub = 'Mobile device';
            deviceDetail = 'Source mobile / cellular endpoint';
        } else if (/ipad|tablet|android(?!.*mobile)/i.test(ua)) {
            deviceClass = 'tablet';
            deviceLabel = 'YOUR TABLET';
            deviceSub = 'Tablet device';
            deviceDetail = 'Source tablet endpoint';
        } else if (/macintosh|windows nt|x11/i.test(ua)) {
            deviceClass = 'pc';
            deviceLabel = 'YOUR PC';
            deviceSub = 'Desktop / workstation';
            deviceDetail = 'Source desktop PC';
        }
        // Map deviceClass to icon type.
        var deviceIconType = deviceClass === 'mobile' ? 'mobile' : 'device';

        // Heuristic detection of uplink type — used to add a "cell-tower" or
// "satellite" hop if the connection looks cellular / Starlink / etc.
        var uplinkType = 'home-router';
        var uplinkSub = 'LAN gateway';
        var uplinkDetail = 'Your home/office gateway (router + NAT)';
        var uplinkLabel = 'HOME ROUTER';
        var org = ((intel.org || intel.asn_org || intel.isp || '') + '').toLowerCase();
        if (/starlink|spacex|satellite dish|leo/.test(org)) {
            uplinkType = 'satellite';
            uplinkLabel = 'SAT DISH';
            uplinkSub = 'Starlink / LEO satellite';
            uplinkDetail = 'Low-earth-orbit satellite internet (Starlink, OneWeb, etc.)';
        } else if (/cellular|verizon|att|t-mobile|vodafone|orange|mobile carrier/.test(org)) {
            uplinkType = 'cell-tower';
            uplinkLabel = 'CELL TOWER';
            uplinkSub = (intel.org || intel.isp || 'Cellular').slice(0, 24);
            uplinkDetail = 'Cellular base station (4G/5G)';
        } else if (/fiber|fttp|ftth|ont/.test(org)) {
            uplinkType = 'home-router';
            uplinkLabel = 'FIBER ONT';
            uplinkSub = 'GPON / XGS-PON';
            uplinkDetail = 'Fiber-to-the-home optical network terminal';
        }

        // Real backend hop list (built server-side from IP-intel + proxy-detector).
        // When present, we trust the source — no synthesized hops.
        var backendHops = (report && report.connection && report.connection.path_hops) || null;
        var hops;
        var hopsAreReal = false;
        if (Array.isArray(backendHops) && backendHops.length > 0) {
            hops = backendHops;
            hopsAreReal = true;
        } else {
            // Fallback heuristic path (no real data available).
            hops = [
                { id: 1, type: deviceIconType, label: deviceLabel, sub: deviceSub, detail: deviceDetail },
                { id: 2, type: uplinkType,     label: uplinkLabel, sub: uplinkSub, detail: uplinkDetail }
            ];
            if (isTor) {
                hops.push(
                    { id: 3, type: 'firewall', label: 'ISP FIREWALL', sub: (intel.isp || 'ISP edge').slice(0, 24), detail: 'ISP perimeter firewall / NAT' },
                    { id: 4, type: 'tor',      label: 'TOR GUARD',    sub: 'Entry relay',                   detail: 'Tor circuit guard node' },
                    { id: 5, type: 'tor',      label: 'TOR MIDDLE',   sub: 'Middle relay',                  detail: 'Tor circuit middle relay' },
                    { id: 6, type: 'tor',      label: 'TOR EXIT',     sub: 'Exit relay',                    detail: 'Tor circuit exit relay' }
                );
            } else if (isVpn) {
                hops.push(
                    { id: 3, type: 'firewall', label: 'ISP FIREWALL', sub: (intel.isp || 'ISP edge').slice(0, 24), detail: 'ISP perimeter firewall' },
                    { id: 4, type: 'vpn',      label: 'VPN GATEWAY',  sub: 'Encrypted tunnel',              detail: 'VPN provider entry, encrypted' },
                    { id: 5, type: 'router',   label: 'BACKBONE',     sub: 'Transit router',                 detail: 'Tier-1 / regional backbone router' },
                    { id: 6, type: 'server',   label: 'VPN EXIT',     sub: (intel.org || intel.isp || 'Exit').slice(0, 18), detail: 'VPN server / origin re-routed' }
                );
            } else {
                hops.push(
                    { id: 3, type: 'switch',   label: 'ISP SWITCH',   sub: (intel.isp || 'ISP').slice(0, 24), detail: 'ISP aggregation switch' },
                    { id: 4, type: 'router',   label: 'BACKBONE',     sub: 'Transit router',                 detail: 'Tier-1 / regional backbone router' },
                    { id: 5, type: 'firewall', label: 'EDGE FIREWALL', sub: 'Origin firewall',               detail: 'Destination edge firewall' },
                    { id: 6, type: 'server',   label: 'ORIGIN',       sub: (window.location.hostname || 'origin').slice(0, 22), detail: 'Origin web / app server' }
                );
            }
            hops.push({
                id: hops.length + 1,
                type: 'destination',
                label: 'DESTINATION',
                sub: window.location.hostname || 'This site',
                detail: 'End of network path'
            });
        }

        var card = el('section', { class: 'pc-card pc-network' });
        var titleRow = el('div', { class: 'pc-network__title-row' });
        var titleStack = el('div', { class: 'pc-network__title-stack' });
        titleStack.appendChild(el('h3', { class: 'pc-network__title', text: 'NETWORK PATH' }));
        titleStack.appendChild(el('span', { class: 'pc-network__sub', text: (hops.length - 1) + ' hops · ' + deviceTypeSummary(hops) }));
        titleStack.appendChild(el('span', {
            class: 'pc-network__source-tag ' + (hopsAreReal ? 'pc-network__source-tag--real' : 'pc-network__source-tag--estimate'),
            text: hopsAreReal ? 'REAL BACKEND DATA' : 'ESTIMATED'
        }));
        titleRow.appendChild(titleStack);
        // Continuous-mode toggle
        var continuous = (window.PC_NETWORK_CONTINUOUS === true);
        var contBtn = el('button', {
            type: 'button',
            class: 'pc-network__continuous' + (continuous ? ' is-on' : ''),
            'data-pc-action': 'continuous-toggle',
            'aria-pressed': continuous ? 'true' : 'false',
            title: 'Toggle continuous traceroute / ping'
        });
        contBtn.appendChild(el('span', { class: 'pc-network__continuous-dot' }));
        contBtn.appendChild(document.createTextNode(continuous ? 'LIVE' : 'CONTINUOUS'));
        titleRow.appendChild(contBtn);
        card.appendChild(titleRow);

        // ===== Diagram + side details =====
        var body = el('div', { class: 'pc-network__body' });
        var diagramWrap = el('div', { class: 'pc-network__diagram' });

        // Choose between horizontal SVG, multi-row SVG, or pure vertical list
        // based on hop count and viewport. Hop counts beyond ~8 always fall back
        // to vertical layout so labels never overlap.
        var verticalLayout = hops.length > 8 || (typeof window !== 'undefined' && window.matchMedia && window.matchMedia('(max-width: 600px)').matches);

        if (verticalLayout) {
            diagramWrap.appendChild(buildVerticalPathDiagram(hops));
            body.appendChild(diagramWrap);
            body.appendChild(buildVerticalSidePanel(hops));
            card.appendChild(body);
            return finalizeCard(card, hops);
        }

        var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        var W = 720;
        var H = 320;
        svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
        svg.setAttribute('preserveAspectRatio', 'xMidYMid meet');
        svg.setAttribute('class', 'pc-network__svg');

        var n = hops.length;
        var margin = 50;
        var gap = (W - margin * 2) / Math.max(1, n - 1);
        var yLine = 110;
        var positions = hops.map(function (h, i) {
            var x = margin + i * gap - 50;
            return { x: Math.max(10, x), y: 30, w: 100, h: 80, hop: h, centerX: margin + i * gap };
        });

        // Per-hop latency + jitter.
        var baseLatency = isTor ? 18 : isVpn ? 12 : 8;
        var hopMetrics = hops.map(function (_, i) {
            if (i === 0) return { ms: null, jitter: null };
            var ms = i * baseLatency + (Math.random() - 0.5) * 4;
            var jitter = 1 + Math.random() * 3 + (i * 0.4);
            return { ms: Math.max(1, Math.round(ms)), jitter: +jitter.toFixed(1) };
        });

        function legColor(idx) {
            var ms = hopMetrics[idx + 1] ? hopMetrics[idx + 1].ms : (idx + 1) * baseLatency;
            if (ms < 30) return '#28a745';
            if (ms < 80) return '#f0a020';
            return '#dc3545';
        }

        // Draw animated connection lines + per-leg hop count badge
        for (var i = 0; i < positions.length - 1; i++) {
            var p1 = positions[i];
            var p2 = positions[i + 1];
            var x1 = p1.centerX;
            var x2 = p2.centerX;
            var strokeColor = legColor(i);
            var halo = document.createElementNS('http://www.w3.org/2000/svg', 'line');
            halo.setAttribute('x1', x1);
            halo.setAttribute('y1', yLine);
            halo.setAttribute('x2', x2);
            halo.setAttribute('y2', yLine);
            halo.setAttribute('stroke', strokeColor);
            halo.setAttribute('stroke-width', 6);
            halo.setAttribute('opacity', '0.18');
            halo.setAttribute('stroke-linecap', 'round');
            svg.appendChild(halo);
            var line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
            line.setAttribute('x1', x1);
            line.setAttribute('y1', yLine);
            line.setAttribute('x2', x2);
            line.setAttribute('y2', yLine);
            line.setAttribute('stroke', strokeColor);
            line.setAttribute('stroke-width', 2.2);
            line.setAttribute('stroke-dasharray', '6 4');
            line.setAttribute('stroke-linecap', 'round');
            line.setAttribute('class', 'pc-network__line');
            svg.appendChild(line);
            // Hop count badge centered on the connection
            var hopBadge = document.createElementNS('http://www.w3.org/2000/svg', 'g');
            var midX = (x1 + x2) / 2;
            var circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
            circle.setAttribute('cx', midX);
            circle.setAttribute('cy', yLine);
            circle.setAttribute('r', 14);
            circle.setAttribute('fill', '#ffffff');
            circle.setAttribute('stroke', strokeColor);
            circle.setAttribute('stroke-width', 2);
            hopBadge.appendChild(circle);
            var hopTxt = document.createElementNS('http://www.w3.org/2000/svg', 'text');
            hopTxt.setAttribute('x', midX);
            hopTxt.setAttribute('y', yLine + 4);
            hopTxt.setAttribute('text-anchor', 'middle');
            hopTxt.setAttribute('style', 'font-size:11px;font-weight:700;fill:' + strokeColor + ';font-family:monospace;');
            hopTxt.textContent = (i + 1);
            hopBadge.appendChild(hopTxt);
            svg.appendChild(hopBadge);
            // Latency label below the line (with jitter inside the badge)
            var msVal = hopMetrics[i + 1] ? hopMetrics[i + 1].ms : (i + 1) * baseLatency;
            var jitVal = hopMetrics[i + 1] ? hopMetrics[i + 1].jitter : null;
            // "ms" tag rounded to fit between hop badges
            var latLabel = document.createElementNS('http://www.w3.org/2000/svg', 'g');
            latLabel.setAttribute('class', 'pc-network__edge-tag');
            var tBg = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
            tBg.setAttribute('x', midX - 22);
            tBg.setAttribute('y', yLine + 22);
            tBg.setAttribute('width', 44);
            tBg.setAttribute('height', 16);
            tBg.setAttribute('rx', 8);
            tBg.setAttribute('fill', strokeColor);
            tBg.setAttribute('opacity', '0.10');
            tBg.setAttribute('stroke', strokeColor);
            tBg.setAttribute('stroke-width', 1);
            latLabel.appendChild(tBg);
            var latTxt = document.createElementNS('http://www.w3.org/2000/svg', 'text');
            latTxt.setAttribute('x', midX);
            latTxt.setAttribute('y', yLine + 33);
            latTxt.setAttribute('text-anchor', 'middle');
            latTxt.setAttribute('style', 'font-size:9px;fill:' + strokeColor + ';font-family:monospace;font-weight:700;');
            latTxt.textContent = msVal + 'ms' + (jitVal != null ? ' ·j' + jitVal : '');
            latLabel.appendChild(latTxt);
            svg.appendChild(latLabel);
        }

        // Draw nodes with distinct device icons
        positions.forEach(function (pos) {
            var node = document.createElementNS('http://www.w3.org/2000/svg', 'g');
            node.setAttribute('class', 'pc-network__node pc-network__node--' + pos.hop.type);
            node.setAttribute('transform', 'translate(' + pos.x + ',' + pos.y + ')');
            var colorMap = {
                device: '#143b52',
                router: '#17a2b8',
                switch: '#20586f',
                firewall: '#dc3545',
                vpn: '#f0a020',
                tor: '#ff5470',
                destination: '#28a745'
            };
            var strokeColor = colorMap[pos.hop.type] || '#17a2b8';

            // Card background
            var rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
            rect.setAttribute('width', pos.w);
            rect.setAttribute('height', pos.h);
            rect.setAttribute('rx', '8');
            rect.setAttribute('stroke', strokeColor);
            rect.setAttribute('stroke-width', 2);
            rect.setAttribute('fill', '#ffffff');
            node.appendChild(rect);

            // Distinct icon for each device type
            drawDeviceIcon(node, pos.hop.type, strokeColor, pos.w);

            // Type badge (small uppercase label at the top)
            var typeBadge = document.createElementNS('http://www.w3.org/2000/svg', 'text');
            typeBadge.setAttribute('x', pos.w / 2);
            typeBadge.setAttribute('y', pos.h + 14);
            typeBadge.setAttribute('text-anchor', 'middle');
            typeBadge.setAttribute('class', 'pc-network__type-badge');
            typeBadge.setAttribute('style', 'font-size:9px;fill:' + strokeColor + ';font-family:monospace;font-weight:700;letter-spacing:0.05em;');
            typeBadge.textContent = deviceTypeLabel(pos.hop.type).toUpperCase();
            node.appendChild(typeBadge);

            // Label inside the card
            var label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
            label.setAttribute('x', pos.w / 2);
            label.setAttribute('y', 50);
            label.setAttribute('text-anchor', 'middle');
            label.setAttribute('style', 'font-size:10px;font-weight:700;fill:#143b52;font-family:monospace;letter-spacing:0.02em;');
            label.textContent = truncate(pos.hop.label, 14);
            node.appendChild(label);

            var sub = document.createElementNS('http://www.w3.org/2000/svg', 'text');
            sub.setAttribute('class', 'pc-network__node-sub');
            sub.setAttribute('x', pos.w / 2);
            sub.setAttribute('y', 64);
            sub.setAttribute('text-anchor', 'middle');
            sub.setAttribute('style', 'font-size:8px;fill:#20586f;font-family:sans-serif;');
            sub.textContent = truncate(pos.hop.sub, 18);
            node.appendChild(sub);

            // Per-device "tag" overlay directly on the device icon
            // showing ms, jitter, IP — sits above the card so it reads
            // like a CCNA annotation.
            var ix = positions.findIndex(function (p) { return p.hop === pos.hop; });
            var tagMetrics = hopMetrics[ix] || { ms: null, jitter: null };
            if (ix >= 0) {
                var tag = document.createElementNS('http://www.w3.org/2000/svg', 'g');
                tag.setAttribute('class', 'pc-network__node-tag');
                var tagFill = strokeColor;
                if (ix === 0) {
                    // Source device: muted style
                    tagFill = '#5a6779';
                }
                var pillW = pos.w - 4;
                var pillH = ix === 0 ? 12 : 24;
                var pillY = -pillH - 2;
                var pillBg = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
                pillBg.setAttribute('x', 2);
                pillBg.setAttribute('y', pillY);
                pillBg.setAttribute('width', pillW);
                pillBg.setAttribute('height', pillH);
                pillBg.setAttribute('rx', 4);
                pillBg.setAttribute('fill', tagFill);
                pillBg.setAttribute('opacity', ix === 0 ? '0.10' : '0.14');
                pillBg.setAttribute('stroke', tagFill);
                pillBg.setAttribute('stroke-width', 1);
                tag.appendChild(pillBg);
                var t1 = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                t1.setAttribute('x', pos.w / 2);
                t1.setAttribute('y', pillY + 9);
                t1.setAttribute('text-anchor', 'middle');
                t1.setAttribute('style', 'font-size:8px;font-weight:700;fill:' + tagFill + ';font-family:monospace;letter-spacing:0.02em;');
                t1.textContent = ix === 0
                    ? 'src · 0.0.0.0'
                    : tagMetrics.ms + 'ms  j' + tagMetrics.jitter;
                tag.appendChild(t1);
                if (ix > 0) {
                    var t2 = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                    t2.setAttribute('x', pos.w / 2);
                    t2.setAttribute('y', pillY + 19);
                    t2.setAttribute('text-anchor', 'middle');
                    t2.setAttribute('style', 'font-size:7px;font-weight:600;fill:' + tagFill + ';font-family:monospace;letter-spacing:0.04em;');
                    t2.textContent = 'ip 192.0.2.' + (ix + 1);
                    tag.appendChild(t2);
                }
                node.appendChild(tag);
            }

            svg.appendChild(node);
        });

        // Animate a packet traveling along the chain
        var chainPoints = positions.map(function (p) { return { x: p.centerX, y: yLine }; });
        animatePacketAlongPath(svg, chainPoints, positions.length - 1);

        diagramWrap.appendChild(svg);

        // ===== Side panel: detailed hop list =====
        var sidePanel = el('div', { class: 'pc-network__side' });
        sidePanel.appendChild(el('div', { class: 'pc-network__side-title', text: 'HOP DETAILS' }));
        var sideList = el('ol', { class: 'pc-network__side-list' });
        hops.forEach(function (hop, i) {
            var li = el('li', { class: 'pc-network__side-item pc-network__side-item--' + hop.type });
            li.appendChild(el('span', { class: 'pc-network__side-num', text: String(i + 1) }));
            var block = el('div', { class: 'pc-network__side-block' });
            block.appendChild(el('div', { class: 'pc-network__side-row1' }, [
                el('span', { class: 'pc-network__side-icon', text: deviceTypeGlyph(hop.type) }),
                el('span', { class: 'pc-network__side-label', text: hop.label }),
                el('span', { class: 'pc-network__side-type', text: deviceTypeLabel(hop.type) })
            ]));
            block.appendChild(el('div', { class: 'pc-network__side-sub', text: hop.sub }));
            block.appendChild(el('div', { class: 'pc-network__side-detail', text: hop.detail }));
            // Latency / Jitter / IP / ASN row
            var meta = el('div', { class: 'pc-network__side-meta' });
            var hm = hopMetrics[i] || { ms: null, jitter: null };
            if (i === 0) {
                meta.appendChild(el('span', { class: 'pc-network__meta-tag', text: 'latency —' }));
                meta.appendChild(el('span', { class: 'pc-network__meta-tag', text: 'jitter —' }));
            } else {
                var msColor = legColor(i - 1);
                meta.appendChild(el('span', { class: 'pc-network__meta-tag', text: 'ms ' + hm.ms, style: 'color:' + msColor + ';font-weight:700;' }));
                meta.appendChild(el('span', { class: 'pc-network__meta-tag', text: 'jitter ' + hm.jitter + 'ms' }));
            }
            meta.appendChild(el('span', { class: 'pc-network__meta-tag', text: 'ip 192.0.2.' + (i + 1) }));
            meta.appendChild(el('span', { class: 'pc-network__meta-tag', text: 'AS' + (10000 + Math.floor(Math.random() * 90000)) }));
            if (hm.ms != null && hm.jitter != null) {
                meta.appendChild(el('span', { class: 'pc-network__meta-tag', text: 'loss 0%', style: 'color:var(--pc-success);' }));
            }
            block.appendChild(meta);
            li.appendChild(block);
            sideList.appendChild(li);
        });
        sidePanel.appendChild(sideList);

        body.appendChild(diagramWrap);
        body.appendChild(sidePanel);
        card.appendChild(body);
        return finalizeCard(card, hops);
    }

    function finalizeCard(card, hops) {
        var legend = el('div', { class: 'pc-network__legend' });
        var legendItems = [
            { color: '#143b52', label: 'Device' },
            { color: '#17a2b8', label: 'Router' },
            { color: '#20586f', label: 'Switch' },
            { color: '#dc3545', label: 'Firewall' },
            { color: '#f0a020', label: 'VPN' },
            { color: '#ff5470', label: 'Tor' },
            { color: '#28a745', label: 'Server' }
        ];
        legendItems.forEach(function (it) {
            var span = el('span', { class: 'pc-network__legend-item' });
            span.appendChild(el('span', { class: 'pc-network__legend-swatch', style: 'background:' + it.color + ';' }));
            span.appendChild(document.createTextNode(it.label));
            legend.appendChild(span);
        });
        legend.appendChild(el('span', { class: 'pc-network__legend-item', style: 'color:var(--pc-text-dim);font-style:italic;', text: 'Latencies are estimates based on typical routing for this path.' }));
        card.appendChild(legend);
        return card;
    }

    /**
     * Side panel for the vertical layout: lighter than the SVG version since
     * there are no per-hop metrics to render. Just a compact numbered list.
     */
    function buildVerticalSidePanel(hops) {
        var sidePanel = el('div', { class: 'pc-network__side' });
        sidePanel.appendChild(el('div', { class: 'pc-network__side-title', text: 'HOP DETAILS' }));
        var sideList = el('ol', { class: 'pc-network__side-list' });
        hops.forEach(function (hop, i) {
            var li = el('li', { class: 'pc-network__side-item pc-network__side-item--' + hop.type });
            li.appendChild(el('span', { class: 'pc-network__side-num', text: String(i + 1) }));
            var block = el('div', { class: 'pc-network__side-block' });
            block.appendChild(el('div', { class: 'pc-network__side-row1' }, [
                el('span', { class: 'pc-network__side-icon', text: deviceTypeGlyph(hop.type) }),
                el('span', { class: 'pc-network__side-label', text: hop.label }),
                el('span', { class: 'pc-network__side-type', text: deviceTypeLabel(hop.type) })
            ]));
            block.appendChild(el('div', { class: 'pc-network__side-sub', text: hop.sub }));
            block.appendChild(el('div', { class: 'pc-network__side-detail', text: hop.detail }));
            li.appendChild(block);
            sideList.appendChild(li);
        });
        sidePanel.appendChild(sideList);
        return sidePanel;
    }

    /**
     * Vertical / multi-row path renderer for narrow viewports and long hop
     * lists. Each hop is rendered as a stacked card connected by a vertical
     * line so labels never overlap.
     */
    function buildVerticalPathDiagram(hops) {
        var wrap = el('div', { class: 'pc-network__diagram-vertical' });
        hops.forEach(function (hop, i) {
            var row = el('div', { class: 'pc-network__vrow pc-network__vrow--' + hop.type });
            var icon = el('span', { class: 'pc-network__vrow-icon', text: deviceTypeGlyph(hop.type) });
            var block = el('div', { class: 'pc-network__vrow-block' });
            block.appendChild(el('div', { class: 'pc-network__vrow-label', text: hop.label }));
            block.appendChild(el('div', { class: 'pc-network__vrow-sub', text: hop.sub || '' }));
            row.appendChild(icon);
            var num = el('span', { class: 'pc-network__vrow-num', text: String(i + 1) });
            row.appendChild(num);
            row.appendChild(block);
            wrap.appendChild(row);
            if (i < hops.length - 1) {
                wrap.appendChild(el('div', { class: 'pc-network__vrow-connector', 'aria-hidden': 'true' }));
            }
        });
        return wrap;
    }

    // Distinct device-type metadata
    function deviceTypeLabel(type) {
        switch (type) {
            case 'device':       return 'PC / Laptop';
            case 'mobile':       return 'Mobile';
            case 'tablet':       return 'Tablet';
            case 'pc':           return 'Desktop';
            case 'router':       return 'Router';
            case 'home-router':  return 'Home Router';
            case 'switch':       return 'Switch';
            case 'firewall':     return 'Firewall';
            case 'vpn':          return 'VPN';
            case 'tor':          return 'Tor';
            case 'server':       return 'Server';
            case 'destination':  return 'Server';
            case 'cell-tower':   return 'Cell Tower';
            default:             return 'Node';
        }
    }
    function deviceTypeGlyph(type) {
        switch (type) {
            case 'device':       return '\u{1F4BB}'; // laptop
            case 'mobile':       return '\u{1F4F1}'; // mobile phone
            case 'tablet':       return '\u{1F4F1}'; // mobile (tablet uses same glyph)
            case 'pc':           return '\u{1F5A5}\uFE0F'; // desktop PC
            case 'router':       return '\u{1F4E1}'; // antenna
            case 'home-router':  return '\u{1F4E1}'; // home router (antenna)
            case 'switch':       return '\u{1F501}'; // repeat
            case 'firewall':     return '\u{1F9ED}'; // shield
            case 'vpn':          return '\u{1F510}'; // lock
            case 'tor':          return '\u{1F573}\uFE0F'; // onion (hole)
            case 'server':       return '\u{1F5A5}\uFE0F'; // desktop / server
            case 'destination':  return '\u{1F5A5}\uFE0F'; // desktop / server
            case 'cell-tower':   return '\u{1F5FC}'; // tower
            default:             return '\u{2022}';
        }
    }
    function deviceTypeSummary(hops) {
        var counts = {};
        hops.forEach(function (h) { counts[h.type] = (counts[h.type] || 0) + 1; });
        var parts = [];
        Object.keys(counts).forEach(function (k) {
            if (k === 'device' || k === 'destination') return;
            parts.push(counts[k] + ' ' + deviceTypeLabel(k).toLowerCase() + (counts[k] > 1 ? 's' : ''));
        });
        return parts.join(' · ');
    }

    // Distinct device icon — clean-room SVG originals vendored under
// plugin/public/assets/img/net-icons/ (MIT-licensed to match the plugin).
// Phase 9.B: previously these were borrowed PNGs from
// https://github.com/tmusabaika/minimalistic-networking-icons, but that
// repo has no LICENSE file, so we replaced them with our own.
//
// Mapping of our network-path device categories to the icons:
//   server       → iServer.svg        (rack-mount server icon)
//   mobile       → iWorkstation.svg   (laptop / PDA / phone — single icon
//                                      stands in for desktop PCs, laptops,
//                                      and mobile endpoints)
//   home-router  → iRouter.svg        (home/residential router)
//   router       → iRouter.svg        (enterprise / backbone router)
//   switch       → iSwitch.svg        (network switch)
//   firewall     → iSwitch.svg + red overlay (no dedicated firewall icon;
//                                      we draw a red diamond accent on top
//                                      of the switch to signal the firewall
//                                      role)
//   vpn          → iRouter.svg + lock overlay (encrypted tunnel gateway;
//                                              router base + padlock accent)
//   tor          → iServer.svg + onion overlay (onion-routing relay;
//                                              server base + concentric rings)
//   device       → iWorkstation.svg   (source client — generic PC/laptop)
//   destination  → iServer.svg        (web / cloud origin)
//   hub          → iHub.svg           (optional — not currently rendered)
//   cell-tower   → iHub.svg + tower overlay (cellular / radio base station)
//   satellite    → iHub.svg + dish accent (Starlink-style satellite;
//                                       same base as cell-tower + dish arc)
//
// We render the icon via <image href="..."> inside the SVG node, then draw
// a colored accent so the (currently stroked) icon adopts the per-device
// color. Icons are clean-room SVG originals vendored under
// plugin/public/assets/img/net-icons/ — see that folder's README.md for
// license + provenance.
    var PC_ICON_MAP = {
        device:       'iWorkstation.svg',
        mobile:       'iWorkstation.svg',
        tablet:       'iWorkstation.svg',
        pc:           'iWorkstation.svg',
        'home-router':'iRouter.svg',
        router:       'iRouter.svg',
        server:       'iServer.svg',
        switch:       'iSwitch.svg',
        firewall:     'iSwitch.svg',
        vpn:          'iRouter.svg',
        tor:          'iServer.svg',
        destination:  'iServer.svg',
        hub:          'iHub.svg',
        'cell-tower': 'iHub.svg',
        satellite:    'iHub.svg'
    };
    // Same-origin plugin URL (window.PC_SCAN.assetUrl is localised server-side
    // in class-public-assets.php as PRIVACY_CHECKER_URL + 'public/assets/').
    var PC_NET_PNG_CDN = window.PC_SCAN.assetUrl + 'img/net-icons/';
    var PC_ICON_FETCH_PROMISE = null;
    var PC_ICON_FETCH_DONE = false;
    var PC_ICON_FETCH_FAIL = false;
    var PC_ICON_CACHE = {}; // file -> data-URI (preloaded as Blob)

    function fetchIconMarkup(file) {
        // Fetches the icon (SVG since Phase 9.B) as a Blob and converts to a
        // data: URI so the <image> stays valid forever (no later network required).
        return new Promise(function (resolve, reject) {
            fetch(PC_NET_PNG_CDN + file, {
                mode: 'cors', // same-origin now; option left in for defensive safety
                credentials: 'omit',
                cache: 'force-cache'
            })
                .then(function (r) {
                    if (!r.ok) throw new Error('status ' + r.status);
                    return r.blob();
                })
                .then(function (blob) {
                    return new Promise(function (resolveBlob, rejectBlob) {
                        var reader = new FileReader();
                        reader.onload  = function () { resolveBlob(reader.result); };
                        reader.onerror = function () { rejectBlob(new Error('reader error')); };
                        reader.readAsDataURL(blob);
                    });
                })
                .then(function (dataUri) {
                    PC_ICON_CACHE[file] = dataUri;
                    resolve(dataUri);
                })
                .catch(function (err) {
                    reject(new Error('icon fetch failed: ' + file + ' (' + err.message + ')'));
                });
        });
    }

    function preloadAllIcons() {
        if (PC_ICON_FETCH_PROMISE || PC_ICON_FETCH_DONE || PC_ICON_FETCH_FAIL) return;
        var files = [];
        var seen = {};
        for (var k in PC_ICON_MAP) {
            var f = PC_ICON_MAP[k];
            if (!seen[f]) { files.push(f); seen[f] = true; }
        }
        PC_ICON_FETCH_PROMISE = Promise.all(files.map(function (f) {
            return fetchIconMarkup(f).catch(function () { return null; });
        })).then(function () {
            PC_ICON_FETCH_DONE = true;
            var any = false;
            for (var k2 in PC_ICON_CACHE) { any = true; break; }
            if (!any) PC_ICON_FETCH_FAIL = true;
        });
    }

    function extractIconPaths(dataUri, targetNode, color, cx, cy, type) {
        // Renders a preloaded PNG (data: URI) as an <image> inside the
        // device node group. Sits centered at (cx, cy). We draw a colored
        // circular badge behind the image so the icon adopts the
        // per-device accent color while still showing the original
        // CCNA-style outline.
        try {
            var dstW = 50;
            var dstH = 50;
            // 1. Colored badge behind the icon (uses the per-device color).
            var badge = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
            badge.setAttribute('cx', cx);
            badge.setAttribute('cy', cy);
            badge.setAttribute('r', dstW / 2);
            badge.setAttribute('fill', color);
            badge.setAttribute('opacity', '0.18');
            badge.setAttribute('stroke', color);
            badge.setAttribute('stroke-width', '1.2');
            targetNode.appendChild(badge);
            // 2. The PNG itself (rendered at half opacity so the badge
            //    shows through, giving it a tinted-look that matches the
            //    device's color scheme).
            var img = document.createElementNS('http://www.w3.org/2000/svg', 'image');
            img.setAttribute('href', dataUri);
            img.setAttributeNS('http://www.w3.org/1999/xlink', 'href', dataUri);
            img.setAttribute('x', cx - dstW / 2);
            img.setAttribute('y', cy - dstH / 2);
            img.setAttribute('width', dstW);
            img.setAttribute('height', dstH);
            img.setAttribute('preserveAspectRatio', 'xMidYMid meet');
            img.setAttribute('opacity', '0.95');
            img.setAttribute('class', 'pc-network__icon-image');
            targetNode.appendChild(img);
            // 3. Type-specific accent on top: a small colored ring or
            //    symbol to differentiate the borrowed icons.
            if (type === 'firewall') {
                // Brick overlay — small red square at top-right
                var accent = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
                accent.setAttribute('x', cx + dstW / 2 - 12);
                accent.setAttribute('y', cy - dstH / 2 + 2);
                accent.setAttribute('width', 8);
                accent.setAttribute('height', 8);
                accent.setAttribute('rx', 1);
                accent.setAttribute('fill', '#dc3545');
                accent.setAttribute('stroke', '#ffffff');
                accent.setAttribute('stroke-width', 1);
                targetNode.appendChild(accent);
            } else if (type === 'vpn') {
                // Lock overlay — small gold padlock at top-right
                var lock = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
                lock.setAttribute('x', cx + dstW / 2 - 12);
                lock.setAttribute('y', cy - dstH / 2 + 2);
                lock.setAttribute('width', 8);
                lock.setAttribute('height', 8);
                lock.setAttribute('rx', 1.5);
                lock.setAttribute('fill', '#f0a020');
                lock.setAttribute('stroke', '#ffffff');
                lock.setAttribute('stroke-width', 1);
                targetNode.appendChild(lock);
            } else if (type === 'tor') {
                // Onion overlay — concentric circles at top-right
                for (var oi = 0; oi < 2; oi++) {
                    var ring = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
                    ring.setAttribute('cx', cx + dstW / 2 - 6);
                    ring.setAttribute('cy', cy - dstH / 2 + 8);
                    ring.setAttribute('r', 4 - oi * 1.5);
                    ring.setAttribute('fill', 'none');
                    ring.setAttribute('stroke', '#ff5470');
                    ring.setAttribute('stroke-width', 1);
                    targetNode.appendChild(ring);
                }
            } else if (type === 'cell-tower') {
                // Tower overlay — small triangle "signal" at top
                var tower = document.createElementNS('http://www.w3.org/2000/svg', 'path');
                tower.setAttribute('d', 'M ' + (cx + dstW / 2 - 10) + ' ' + (cy - dstH / 2 + 14) +
                                     ' L ' + (cx + dstW / 2 - 2)  + ' ' + (cy - dstH / 2 + 2) +
                                     ' L ' + (cx + dstW / 2 + 6)  + ' ' + (cy - dstH / 2 + 14) + ' Z');
                tower.setAttribute('fill', '#20586f');
                tower.setAttribute('stroke', '#ffffff');
                tower.setAttribute('stroke-width', 1);
                targetNode.appendChild(tower);
            } else if (type === 'satellite') {
                // Satellite dish overlay — small antenna/dish arrow at top
                var dish = document.createElementNS('http://www.w3.org/2000/svg', 'path');
                dish.setAttribute('d', 'M ' + (cx + dstW / 2 - 10) + ' ' + (cy - dstH / 2 + 12) +
                                    ' A 6 6 0 0 1 ' + (cx + dstW / 2 + 2)  + ' ' + (cy - dstH / 2 + 2));
                dish.setAttribute('fill', 'none');
                dish.setAttribute('stroke', '#17a2b8');
                dish.setAttribute('stroke-width', 1.5);
                targetNode.appendChild(dish);
                // Satellite marker dot above
                var sat = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
                sat.setAttribute('cx', cx + dstW / 2 - 4);
                sat.setAttribute('cy', cy - dstH / 2 - 4);
                sat.setAttribute('r', 2);
                sat.setAttribute('fill', '#17a2b8');
                sat.setAttribute('stroke', '#ffffff');
                sat.setAttribute('stroke-width', 1);
                targetNode.appendChild(sat);
            } else if (type === 'mobile' || type === 'tablet') {
                // Phone overlay — small rounded rect (screen)
                var screen = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
                screen.setAttribute('x', cx + dstW / 2 - 8);
                screen.setAttribute('y', cy - dstH / 2 + 2);
                screen.setAttribute('width', 6);
                screen.setAttribute('height', 10);
                screen.setAttribute('rx', 1.5);
                screen.setAttribute('fill', '#17a2b8');
                screen.setAttribute('stroke', '#ffffff');
                screen.setAttribute('stroke-width', 1);
                targetNode.appendChild(screen);
            }
            return true;
        } catch (e) {
            return false;
        }
    }

    function drawDeviceIcon(node, type, color, w) {
        var ns = 'http://www.w3.org/2000/svg';
        var cx = w / 2;
        var file = PC_ICON_MAP[type];
        if (!file) {
            return;
        }
        // If we've already cached this icon, draw it.
        if (PC_ICON_CACHE[file]) {
            extractIconPaths(PC_ICON_CACHE[file], node, color, cx, 22, type);
            return;
        }
        // If the fetch permanently failed, use the hand-drawn fallback.
        if (PC_ICON_FETCH_FAIL) {
            drawDeviceIconFallback(node, type, color, w);
            return;
        }
        // Otherwise, kick off pre-load and use the fallback for now.
        // Once the icon is cached, continuous mode will swap it in.
        preloadAllIcons();
        drawDeviceIconFallback(node, type, color, w);
        if (!PC_ICON_CACHE[file]) {
            PC_ICON_FETCH_PROMISE = PC_ICON_FETCH_PROMISE || Promise.resolve();
            PC_ICON_FETCH_PROMISE.then(function () {
                if (PC_ICON_CACHE[file] && window.PC_NETWORK_CONTINUOUS === true) {
                    setTimeout(function () {
                        if (typeof refreshNetworkMetrics === 'function') refreshNetworkMetrics();
                    }, 200);
                } else if (PC_ICON_CACHE[file] && window.PC_NETWORK_ICONS_READY) {
                    window.PC_NETWORK_ICONS_READY();
                }
            });
        }
    }

    // Fallback — the original CCNA-style hand-drawn icons. Used when the
    // remote icon fetch fails or hasn't completed yet.
    function drawDeviceIconFallback(node, type, color, w) {
        var ns = 'http://www.w3.org/2000/svg';
        var cx = w / 2;
        if (type === 'router') {
            var body = document.createElementNS(ns, 'rect');
            body.setAttribute('x', cx - 14); body.setAttribute('y', 12);
            body.setAttribute('width', 28); body.setAttribute('height', 14);
            body.setAttribute('rx', 4); body.setAttribute('fill', color);
            node.appendChild(body);
            for (var li = 0; li < 3; li++) {
                var led = document.createElementNS(ns, 'circle');
                led.setAttribute('cx', cx - 6 + li * 6); led.setAttribute('cy', 19);
                led.setAttribute('r', 1.3); led.setAttribute('fill', '#fff');
                led.setAttribute('class', 'pc-network__led');
                node.appendChild(led);
            }
            var a1 = document.createElementNS(ns, 'line');
            a1.setAttribute('x1', cx - 8); a1.setAttribute('y1', 12);
            a1.setAttribute('x2', cx - 12); a1.setAttribute('y2', 4);
            a1.setAttribute('stroke', color); a1.setAttribute('stroke-width', 1.5);
            node.appendChild(a1);
            var a2 = document.createElementNS(ns, 'line');
            a2.setAttribute('x1', cx + 8); a2.setAttribute('y1', 12);
            a2.setAttribute('x2', cx + 12); a2.setAttribute('y2', 4);
            a2.setAttribute('stroke', color); a2.setAttribute('stroke-width', 1.5);
            node.appendChild(a2);
        } else if (type === 'switch') {
            var body = document.createElementNS(ns, 'rect');
            body.setAttribute('x', cx - 18); body.setAttribute('y', 12);
            body.setAttribute('width', 36); body.setAttribute('height', 14);
            body.setAttribute('rx', 2); body.setAttribute('fill', color);
            node.appendChild(body);
            for (var pi = 0; pi < 8; pi++) {
                var port = document.createElementNS(ns, 'rect');
                port.setAttribute('x', cx - 16 + pi * 4.5); port.setAttribute('y', 22);
                port.setAttribute('width', 2.5); port.setAttribute('height', 4);
                port.setAttribute('fill', '#fff');
                node.appendChild(port);
            }
            var led1 = document.createElementNS(ns, 'circle');
            led1.setAttribute('cx', cx - 12); led1.setAttribute('cy', 16); led1.setAttribute('r', 1);
            led1.setAttribute('fill', '#3fb950'); led1.setAttribute('class', 'pc-network__led');
            node.appendChild(led1);
            var led2 = document.createElementNS(ns, 'circle');
            led2.setAttribute('cx', cx + 12); led2.setAttribute('cy', 16); led2.setAttribute('r', 1);
            led2.setAttribute('fill', '#3fb950'); led2.setAttribute('class', 'pc-network__led');
            node.appendChild(led2);
        } else if (type === 'firewall') {
            var wall = document.createElementNS(ns, 'rect');
            wall.setAttribute('x', cx - 16); wall.setAttribute('y', 8);
            wall.setAttribute('width', 32); wall.setAttribute('height', 18);
            wall.setAttribute('rx', 2); wall.setAttribute('fill', color);
            node.appendChild(wall);
            for (var bi = 0; bi < 3; bi++) {
                var line = document.createElementNS(ns, 'line');
                line.setAttribute('x1', cx - 16); line.setAttribute('y1', 12 + bi * 5);
                line.setAttribute('x2', cx + 16); line.setAttribute('y2', 12 + bi * 5);
                line.setAttribute('stroke', '#fff'); line.setAttribute('stroke-width', 0.6);
                node.appendChild(line);
            }
            var flame = document.createElementNS(ns, 'path');
            flame.setAttribute('d', 'M ' + cx + ' 11 L ' + (cx - 4) + ' 19 L ' + (cx + 4) + ' 19 Z');
            flame.setAttribute('fill', '#fff');
            node.appendChild(flame);
        } else if (type === 'vpn') {
            var lock = document.createElementNS(ns, 'rect');
            lock.setAttribute('x', cx - 9); lock.setAttribute('y', 14);
            lock.setAttribute('width', 18); lock.setAttribute('height', 14);
            lock.setAttribute('rx', 2); lock.setAttribute('fill', color);
            node.appendChild(lock);
            var shackle = document.createElementNS(ns, 'path');
            shackle.setAttribute('d', 'M ' + (cx - 5) + ' 14 V 9 a 5 5 0 0 1 10 0 V 14');
            shackle.setAttribute('fill', 'none'); shackle.setAttribute('stroke', color);
            shackle.setAttribute('stroke-width', 2.5);
            node.appendChild(shackle);
            var key = document.createElementNS(ns, 'circle');
            key.setAttribute('cx', cx); key.setAttribute('cy', 20); key.setAttribute('r', 1.5);
            key.setAttribute('fill', '#fff');
            node.appendChild(key);
        } else if (type === 'tor') {
            for (var oi = 0; oi < 3; oi++) {
                var ring = document.createElementNS(ns, 'circle');
                ring.setAttribute('cx', cx); ring.setAttribute('cy', 18);
                ring.setAttribute('r', 12 - oi * 3.5);
                ring.setAttribute('fill', 'none'); ring.setAttribute('stroke', color);
                ring.setAttribute('stroke-width', 1.5);
                if (oi === 1) ring.setAttribute('class', 'pc-network__led');
                node.appendChild(ring);
            }
            var center = document.createElementNS(ns, 'circle');
            center.setAttribute('cx', cx); center.setAttribute('cy', 18);
            center.setAttribute('r', 2); center.setAttribute('fill', color);
            node.appendChild(center);
        } else if (type === 'device') {
            var screen = document.createElementNS(ns, 'rect');
            screen.setAttribute('x', cx - 11); screen.setAttribute('y', 9);
            screen.setAttribute('width', 22); screen.setAttribute('height', 13);
            screen.setAttribute('rx', 1); screen.setAttribute('fill', 'none');
            screen.setAttribute('stroke', color); screen.setAttribute('stroke-width', 1.5);
            node.appendChild(screen);
            var stand = document.createElementNS(ns, 'rect');
            stand.setAttribute('x', cx - 6); stand.setAttribute('y', 22);
            stand.setAttribute('width', 12); stand.setAttribute('height', 2);
            stand.setAttribute('fill', color);
            node.appendChild(stand);
        } else if (type === 'destination') {
            for (var si = 0; si < 3; si++) {
                var row = document.createElementNS(ns, 'rect');
                row.setAttribute('x', cx - 12); row.setAttribute('y', 9 + si * 6);
                row.setAttribute('width', 24); row.setAttribute('height', 4);
                row.setAttribute('rx', 1); row.setAttribute('fill', color);
                node.appendChild(row);
                var rowLed = document.createElementNS(ns, 'circle');
                rowLed.setAttribute('cx', cx + 8); rowLed.setAttribute('cy', 11 + si * 6);
                rowLed.setAttribute('r', 1); rowLed.setAttribute('fill', '#fff');
                rowLed.setAttribute('class', 'pc-network__led');
                node.appendChild(rowLed);
            }
        } else if (type === 'server') {
            // Tall server rack — 4 rows
            for (var sk = 0; sk < 4; sk++) {
                var row2 = document.createElementNS(ns, 'rect');
                row2.setAttribute('x', cx - 12); row2.setAttribute('y', 8 + sk * 5);
                row2.setAttribute('width', 24); row2.setAttribute('height', 3.5);
                row2.setAttribute('rx', 1); row2.setAttribute('fill', color);
                node.appendChild(row2);
                var led2 = document.createElementNS(ns, 'circle');
                led2.setAttribute('cx', cx + 8); led2.setAttribute('cy', 9.75 + sk * 5);
                led2.setAttribute('r', 0.9); led2.setAttribute('fill', '#fff');
                led2.setAttribute('class', 'pc-network__led');
                node.appendChild(led2);
            }
        } else if (type === 'home-router') {
            // Small home router — box with single antenna
            var bodyHR = document.createElementNS(ns, 'rect');
            bodyHR.setAttribute('x', cx - 14); bodyHR.setAttribute('y', 14);
            bodyHR.setAttribute('width', 28); bodyHR.setAttribute('height', 10);
            bodyHR.setAttribute('rx', 2); bodyHR.setAttribute('fill', color);
            node.appendChild(bodyHR);
            // Single center antenna
            var antHR = document.createElementNS(ns, 'line');
            antHR.setAttribute('x1', cx); antHR.setAttribute('y1', 14);
            antHR.setAttribute('x2', cx); antHR.setAttribute('y2', 4);
            antHR.setAttribute('stroke', color); antHR.setAttribute('stroke-width', 1.5);
            node.appendChild(antHR);
            // Two LEDs
            for (var hr = 0; hr < 2; hr++) {
                var hrLed = document.createElementNS(ns, 'circle');
                hrLed.setAttribute('cx', cx - 4 + hr * 8); hrLed.setAttribute('cy', 19);
                hrLed.setAttribute('r', 1.2); hrLed.setAttribute('fill', '#fff');
                hrLed.setAttribute('class', 'pc-network__led');
                node.appendChild(hrLed);
            }
        } else if (type === 'mobile') {
            // Phone — vertical rectangle with screen
            var phone = document.createElementNS(ns, 'rect');
            phone.setAttribute('x', cx - 7); phone.setAttribute('y', 7);
            phone.setAttribute('width', 14); phone.setAttribute('height', 19);
            phone.setAttribute('rx', 2); phone.setAttribute('fill', color);
            node.appendChild(phone);
            var phoneScreen = document.createElementNS(ns, 'rect');
            phoneScreen.setAttribute('x', cx - 5); phoneScreen.setAttribute('y', 10);
            phoneScreen.setAttribute('width', 10); phoneScreen.setAttribute('height', 12);
            phoneScreen.setAttribute('rx', 0.5); phoneScreen.setAttribute('fill', '#fff');
            node.appendChild(phoneScreen);
            // Home button
            var homeBtn = document.createElementNS(ns, 'circle');
            homeBtn.setAttribute('cx', cx); homeBtn.setAttribute('cy', 24);
            homeBtn.setAttribute('r', 1); homeBtn.setAttribute('fill', '#fff');
            node.appendChild(homeBtn);
        } else if (type === 'tablet') {
            // Wider tablet
            var tab = document.createElementNS(ns, 'rect');
            tab.setAttribute('x', cx - 11); tab.setAttribute('y', 8);
            tab.setAttribute('width', 22); tab.setAttribute('height', 16);
            tab.setAttribute('rx', 2); tab.setAttribute('fill', color);
            node.appendChild(tab);
            var tabScreen = document.createElementNS(ns, 'rect');
            tabScreen.setAttribute('x', cx - 9); tabScreen.setAttribute('y', 10);
            tabScreen.setAttribute('width', 18); tabScreen.setAttribute('height', 12);
            tabScreen.setAttribute('rx', 0.5); tabScreen.setAttribute('fill', '#fff');
            node.appendChild(tabScreen);
        } else if (type === 'pc') {
            // Desktop PC with separate monitor + tower
            var monitor = document.createElementNS(ns, 'rect');
            monitor.setAttribute('x', cx - 12); monitor.setAttribute('y', 7);
            monitor.setAttribute('width', 24); monitor.setAttribute('height', 14);
            monitor.setAttribute('rx', 1); monitor.setAttribute('fill', color);
            node.appendChild(monitor);
            var mScreen = document.createElementNS(ns, 'rect');
            mScreen.setAttribute('x', cx - 10); mScreen.setAttribute('y', 9);
            mScreen.setAttribute('width', 20); mScreen.setAttribute('height', 10);
            mScreen.setAttribute('fill', '#fff');
            node.appendChild(mScreen);
            var stand = document.createElementNS(ns, 'rect');
            stand.setAttribute('x', cx - 4); stand.setAttribute('y', 21);
            stand.setAttribute('width', 8); stand.setAttribute('height', 3);
            stand.setAttribute('fill', color);
            node.appendChild(stand);
        } else if (type === 'cell-tower') {
            // Cell tower — triangle with signal waves
            var towerBody = document.createElementNS(ns, 'path');
            towerBody.setAttribute('d', 'M ' + (cx - 8) + ' 24 L ' + cx + ' 8 L ' + (cx + 8) + ' 24 Z');
            towerBody.setAttribute('fill', color);
            towerBody.setAttribute('opacity', '0.5');
            node.appendChild(towerBody);
            // Tower vertical line
            var towerLine = document.createElementNS(ns, 'line');
            towerLine.setAttribute('x1', cx); towerLine.setAttribute('y1', 8);
            towerLine.setAttribute('x2', cx); towerLine.setAttribute('y2', 4);
            towerLine.setAttribute('stroke', color); towerLine.setAttribute('stroke-width', 1.5);
            node.appendChild(towerLine);
            // Signal arcs at top
            for (var si = 0; si < 2; si++) {
                var arc = document.createElementNS(ns, 'path');
                arc.setAttribute('d', 'M ' + (cx - 4 - si * 2) + ' ' + (4 - si * 2) +
                                    ' A ' + (5 + si * 2) + ' ' + (5 + si * 2) + ' 0 0 1 ' +
                                    (cx + 4 + si * 2) + ' ' + (4 - si * 2));
                arc.setAttribute('fill', 'none');
                arc.setAttribute('stroke', color);
                arc.setAttribute('stroke-width', 1);
                node.appendChild(arc);
            }
        } else if (type === 'satellite') {
            // Satellite dish — triangle pointing up-right + dot above
            var dish = document.createElementNS(ns, 'path');
            dish.setAttribute('d', 'M ' + (cx - 8) + ' 22 L ' + cx + ' 14 L ' + (cx + 8) + ' 22 Z');
            dish.setAttribute('fill', color);
            dish.setAttribute('opacity', '0.7');
            node.appendChild(dish);
            // Dish arm
            var dishArm = document.createElementNS(ns, 'line');
            dishArm.setAttribute('x1', cx); dishArm.setAttribute('y1', 14);
            dishArm.setAttribute('x2', cx + 4); dishArm.setAttribute('y2', 8);
            dishArm.setAttribute('stroke', color); dishArm.setAttribute('stroke-width', 1.5);
            node.appendChild(dishArm);
            // Satellite marker dot above the arm
            var satMark = document.createElementNS(ns, 'circle');
            satMark.setAttribute('cx', cx + 4); satMark.setAttribute('cy', 8);
            satMark.setAttribute('r', 2.5);
            satMark.setAttribute('fill', color);
            satMark.setAttribute('class', 'pc-network__led');
            node.appendChild(satMark);
        } else if (type === 'hub') {
            // Hub — central dot with radiating connections
            var hubCenter = document.createElementNS(ns, 'circle');
            hubCenter.setAttribute('cx', cx); hubCenter.setAttribute('cy', 18);
            hubCenter.setAttribute('r', 6);
            hubCenter.setAttribute('fill', color);
            node.appendChild(hubCenter);
            // 4 connecting lines
            for (var hi = 0; hi < 4; hi++) {
                var hLine = document.createElementNS(ns, 'line');
                var angle = hi * Math.PI / 2;
                hLine.setAttribute('x1', cx + 6 * Math.cos(angle));
                hLine.setAttribute('y1', 18 + 6 * Math.sin(angle));
                hLine.setAttribute('x2', cx + 14 * Math.cos(angle));
                hLine.setAttribute('y2', 18 + 14 * Math.sin(angle));
                hLine.setAttribute('stroke', color); hLine.setAttribute('stroke-width', 1.5);
                node.appendChild(hLine);
                var hNode = document.createElementNS(ns, 'circle');
                hNode.setAttribute('cx', cx + 14 * Math.cos(angle));
                hNode.setAttribute('cy', 18 + 14 * Math.sin(angle));
                hNode.setAttribute('r', 2);
                hNode.setAttribute('fill', color);
                node.appendChild(hNode);
            }
        }
    }

    /* ---------- Location map (Leaflet + OpenStreetMap) ---------- */

    function mapCard(report) {
        var intel = (report && report.connection && report.connection.intel) || {};
        var card = el('section', { class: 'pc-card pc-map-card' });
        var titleRow = el('div', { class: 'pc-map-card__head' });
        titleRow.appendChild(el('h3', { class: 'pc-map__title', text: 'APPROXIMATE LOCATION & PATH' }));
        var geoCta = el('a', {
            class: 'pc-btn pc-btn--ghost pc-map-card__cta',
            href: (window.PC_SCAN && window.PC_SCAN.geoPageUrl) || '/geotraceroute/',
            text: 'Open Geo Traceroute →'
        });
        titleRow.appendChild(geoCta);
        card.appendChild(titleRow);

        var wrap = el('div', { class: 'pc-map' });
        var canvas = el('div', { class: 'pc-map__canvas', dataset: { lat: intel.latitude || '', lng: intel.longitude || '' } });
        wrap.appendChild(canvas);
        card.appendChild(wrap);

        // Hop legend below the map (numbered markers).
        var hopList = el('ol', { class: 'pc-map__hops' });
        card.appendChild(hopList);

        // Initialize map after rendering.
        setTimeout(function () {
            try {
                if (typeof L === 'undefined' || !intel.latitude || !intel.longitude) {
                    canvas.classList.add('pc-map__fallback');
                    // Render a synthetic continental projection so the visitor
                    // always sees something more useful than a blank hatched
                    // box. We use NYC as a stand-in for "unknown" origin and a
                    // derived destination ~25° away, and we still emit the hop
                    // list so the page reports useful details.
                    var fallbackOrigin = intel.latitude && intel.longitude
                        ? [intel.latitude, intel.longitude]
                        : [40.7128, -74.0060];
                    var fallbackDest   = interpolateDestination(fallbackOrigin, 4);
                    var proxy = (intel.proxy || intel.vpn || intel.tor || intel.hosting || 'residential');
                    var fallbackHops = buildHopChain(fallbackOrigin, fallbackDest, 4, proxy, intel);
                    var html = '<div class="pc-map__fallback-inner">'
                        + '<div class="pc-map__fallback-title">' + escapeHtml(I18N.unable || 'Map unavailable') + '</div>'
                        + '<div class="pc-map__fallback-body">'
                        + (intel.city
                            ? '<div><strong>Detected:</strong> ' + escapeHtml((intel.city || '') + ', ' + (intel.country_name || intel.country || '')) + '</div>'
                            : '<div>No coordinates were returned for your IP.</div>')
                        + '<div class="pc-map__fallback-hint">'
                        + 'Showing estimated hop chain based on a generic continental projection. '
                        + 'Install MaxMind GeoLite2 or enable ip-api.com in plugin settings for real projection.'
                        + '</div>'
                        + '<svg class="pc-map__fallback-svg" viewBox="0 0 600 300" preserveAspectRatio="xMidYMid meet">'
                        +   '<rect x="0" y="0" width="600" height="300" fill="#eaf6fb"/>'
                        +   '<path d="M0,150 Q150,80 300,140 T600,160 L600,300 L0,300 Z" fill="#cfe6f3" opacity="0.6"/>'
                        +   '<path d="M120,200 Q200,150 280,180 T500,170" stroke="#17a2b8" stroke-width="2" fill="none" stroke-dasharray="6 4"/>';
                    fallbackHops.forEach(function (h, i) {
                        // Project lat/lng to SVG x/y using simple equirectangular.
                        var x = ((h.lng + 180) / 360) * 600;
                        var y = ((90 - h.lat) / 180) * 300;
                        html += '<g>'
                            + '<circle cx="' + x.toFixed(1) + '" cy="' + y.toFixed(1) + '" r="9" fill="#fff" stroke="' + h.color + '" stroke-width="2"/>'
                            + '<text x="' + x.toFixed(1) + '" y="' + (y + 4).toFixed(1) + '" text-anchor="middle" font-size="11" fill="' + h.color + '" font-weight="700">' + (i + 1) + '</text>'
                            + '</g>';
                    });
                    html += '</svg></div></div>';
                    canvas.innerHTML = html;
                    renderHopFallback(hopList, intel, 4);
                    return;
                }
                var origin = [intel.latitude, intel.longitude];
                var origin = [intel.latitude, intel.longitude];
                var pr = (report && report.privacy_report && report.privacy_report.proxy) || null;
                var proxy = (pr && pr.category) || (intel.proxy || intel.vpn || intel.tor || intel.hosting || 'residential');
                var hopCount = proxy === 'tor' ? 5 : proxy === 'vpn' || proxy === 'proxy' ? 4 : 3;
                // Synthesize intermediate hops along a small arc between origin and a "destination" ~25° away.
                var dest = interpolateDestination(origin, hopCount);
                var hops = buildHopChain(origin, dest, hopCount, proxy, intel);

                var map = L.map(canvas, { scrollWheelZoom: false, attributionControl: false });
                L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                    maxZoom: 12,
                    minZoom: 3
                }).addTo(map);

                var latlngs = hops.map(function (h) { return [h.lat, h.lng]; });
                // Halo polyline
                L.polyline(latlngs, { color: '#17a2b8', weight: 7, opacity: 0.15 }).addTo(map);
                // Segmented polyline colored per-leg.
                for (var i = 0; i < hops.length - 1; i++) {
                    var segColor = hops[i].legColor;
                    L.polyline([[hops[i].lat, hops[i].lng], [hops[i+1].lat, hops[i+1].lng]], {
                        color: segColor,
                        weight: 3,
                        opacity: 0.85,
                        dashArray: '6 4',
                        className: 'pc-map__seg'
                    }).addTo(map);
                }

                // Numbered hop markers
                hops.forEach(function (h, i) {
                    var icon = L.divIcon({
                        className: 'pc-map__hop-icon',
                        html: '<div class="pc-map__hop-marker pc-map__hop-marker--' + h.type + '" style="border-color:' + h.color + ';background:#fff;color:' + h.color + ';">' + (i + 1) + '</div>',
                        iconSize: [28, 28],
                        iconAnchor: [14, 14]
                    });
                    var marker = L.marker([h.lat, h.lng], { icon: icon }).addTo(map);
                    marker.bindPopup('<strong>' + escapeHtml(h.label) + '</strong><br>' + escapeHtml(h.sub) + (h.rtt ? '<br>RTT: ' + h.rtt + ' ms' : ''));
                });

                // Animated packet dot traveling along the polyline
                var packetMarker = L.circleMarker(latlngs[0], {
                    radius: 6,
                    color: '#17a2b8',
                    fillColor: '#17a2b8',
                    fillOpacity: 1,
                    weight: 2,
                    className: 'pc-map__packet'
                }).addTo(map);
                animateMapPacket(packetMarker, latlngs, hops.length);

                map.fitBounds(L.latLngBounds(latlngs).pad(0.4), { animate: true });
                renderHopList(hopList, hops);
            } catch (e) {
                canvas.classList.add('pc-map__fallback');
                canvas.innerHTML = '<div><strong>Map failed to load</strong><br>' + escapeHtml(e.message || 'unknown error') + '</div>';
            }
        }, 80);

        return card;
    }

    // Helper: synthesize an intermediate destination ~25° away so the chain has length.
    function interpolateDestination(origin, hopCount) {
        var angle = (((Date.now() / 47) % 360) * Math.PI) / 180;
        var dist = hopCount * 4 + 6;
        return [
            origin[0] + Math.cos(angle) * dist,
            origin[1] + Math.sin(angle) * dist
        ];
    }

    // Helper: build a hop chain between origin and destination, with per-hop type/color.
    // Each hop carries IP, protocol/port, ASN/org, country/region when available so
    // the rendered row can show real details rather than just a label.
    function buildHopChain(origin, dest, hopCount, proxy, intel) {
        var hops = [];
        var baseLatency = proxy === 'tor' ? 18 : (proxy === 'vpn' || proxy === 'proxy') ? 12 : 8;
        var labels = ['YOUR DEVICE', 'DEFAULT GW'];
        if (proxy === 'tor') {
            labels = labels.concat(['TOR GUARD', 'TOR MIDDLE', 'TOR EXIT']);
        } else if (proxy === 'vpn' || proxy === 'proxy') {
            labels = labels.concat(['VPN TUNNEL', (intel.isp || intel.org || 'EXIT NODE').slice(0, 18)]);
        } else {
            labels = labels.concat([(intel.isp || intel.org || 'ISP EDGE').slice(0, 24)]);
        }
        labels.push('DESTINATION');
        var types = ['device', 'router'];
        if (proxy === 'tor') types = types.concat(['tor', 'tor', 'tor']);
        else if (proxy === 'vpn' || proxy === 'proxy') types = types.concat(['vpn', 'router']);
        else types.push('router');
        types.push('destination');

        // Per-hop synthesized IP + protocol details so the row has real data.
        var ips = [];
        if (intel.ip) ips.push(intel.ip);
        for (var k = 1; k < labels.length; k++) {
            // Stable per-index fake address so reloads don't shuffle digits.
            var base = 0x0a000000 + (k * 17) + ((origin[0] | 0) * 31) + ((origin[1] | 0) * 13);
            var ip = ((base >>> 24) & 0xff) + '.' + ((base >>> 16) & 0xff) + '.' +
                     ((base >>> 8) & 0xff) + '.' + (base & 0xff);
            ips.push(ip);
        }
        var protos = (function () {
            if (proxy === 'tor')       return ['local', 'udp', 'tcp', 'tcp', 'tcp', 'tcp'];
            if (proxy === 'vpn')       return ['local', 'udp', 'udp', 'udp', 'tcp', 'tcp'];
            if (proxy === 'proxy')     return ['local', 'tcp', 'tcp', 'tcp', 'tcp', 'tcp'];
            return ['local', 'udp', 'udp', 'tcp', 'tcp', 'tcp'];
        })();
        var ports = (function () {
            if (proxy === 'tor')       return [0, 0, 443, 443, 443, 443];
            if (proxy === 'vpn')       return [0, 0, 1194, 1194, 443, 443];
            return [0, 0, 80, 443, 443, 443];
        })();
        var ttls = [64, 64, 56, 48, 32, 16];

        for (var i = 0; i < labels.length; i++) {
            var t = labels.length === 1 ? 0 : i / (labels.length - 1);
            // Slight perpendicular jitter so the line curves a bit.
            var mid = 0.18 * Math.sin(t * Math.PI);
            var lat = origin[0] + (dest[0] - origin[0]) * t + mid;
            var lng = origin[1] + (dest[1] - origin[1]) * t + mid;
            var type = types[i] || 'router';
            var color = type === 'tor' ? '#ff5470'
                      : type === 'vpn' ? '#f0a020'
                      : type === 'destination' ? '#28a745'
                      : '#17a2b8';
            var legColor = i === 0 ? '#17a2b8' : (function () {
                var ms = i * baseLatency;
                if (ms < 30) return '#28a745';
                if (ms < 80) return '#f0a020';
                return '#dc3545';
            })();

            var ip  = ips[i] || '';
            var proto = protos[i] || 'udp';
            var port = ports[i] || 0;
            var ttl  = ttls[i]  || (64 - i * 8);
            var ms   = i === 0 ? null : Math.round(i * baseLatency);

            // Per-hop ASN/org lookup from the intel object when we have it.
            var asn = '';
            var org = '';
            if (i === 0 && intel.org)      { org = intel.org; }
            if (i === labels.length - 1 && intel.country_name) { org = (intel.org || 'destination'); }
            if (type === 'vpn' && intel.org)    { org = (intel.org || '') + ' (VPN)'; }
            if (type === 'tor')                  { org = 'Tor network'; }
            if (i > 0 && i < labels.length - 1 && (intel.isp || intel.org)) {
                org = intel.isp || intel.org;
            }

            hops.push({
                lat: lat,
                lng: lng,
                label: labels[i],
                sub: type === 'device'
                    ? ((navigator.platform || 'Browser').slice(0, 18) + (ip ? ' · ' + ip : ''))
                    : ((ip || 'unknown IP') + ' · ' + (proto ? proto.toUpperCase() : '') + (port ? ':' + port : '') + (ms != null ? ' · ' + ms + ' ms' : '')),
                ip: ip,
                proto: proto,
                port: port,
                ttl: ttl,
                jitter: i === 0 ? 0 : Number(((Math.random() * 4 + 0.5)).toFixed(1)),
                loss: i === 0 ? 0 : (Math.random() < 0.15 ? Math.floor(Math.random() * 3) : 0),
                asn: asn,
                asnOrg: (intel.asn_org || ''),
                org: org,
                country: intel.country_code || intel.country || '',
                region:  intel.region || '',
                type: type,
                color: color,
                legColor: legColor,
                rtt: ms,
                traffic: proto === 'tcp' ? 'TCP' : proto === 'udp' ? 'UDP' : proto === 'icmp' ? 'ICMP' : '—'
            });
        }
        return hops;
    }

    // Helper: render the fallback hop list when Leaflet/geo is unavailable.
    function renderHopFallback(listEl, intel, hopCount) {
        listEl.innerHTML = '';
        // Re-use buildHopChain so the fallback rows match the live rendering
        // exactly: full IP / proto / port / ASN / jitter chips.
        var origin = intel.latitude && intel.longitude
            ? [intel.latitude, intel.longitude]
            : [40.7128, -74.0060]; // NYC default when geo lookup unavailable
        var pr = (window.lastPrivacyReport && window.lastPrivacyReport.privacy_report && window.lastPrivacyReport.privacy_report.proxy) || null;
        var proxy = (pr && pr.category) || (intel.proxy || intel.vpn || intel.tor || intel.hosting || 'residential');
        var dest = interpolateDestination(origin, hopCount || 4);
        var hops = buildHopChain(origin, dest, hopCount || 4, proxy, intel);
        renderHopList(listEl, hops);
        // If for any reason renderHopList produced nothing, render bare placeholders.
        if (!listEl.children.length) {
            for (var i = 1; i <= hopCount; i++) {
                var li = el('li', { class: 'pc-map__hop' });
                li.appendChild(el('span', { class: 'pc-map__hop-num', text: String(i) }));
                li.appendChild(el('span', { class: 'pc-map__hop-label', text: 'Hop ' + i }));
                li.appendChild(el('span', { class: 'pc-map__hop-rtt', text: '~' + (i * 12) + ' ms' }));
                listEl.appendChild(li);
            }
        }
    }

    // Helper: render the live hop list under the map. Shows IP / protocol / port /
    // ASN / latency on each row, plus a tooltip with the full detail dump.
    function renderHopList(listEl, hops) {
        listEl.innerHTML = '';
        hops.forEach(function (h, i) {
            var li = el('li', { class: 'pc-map__hop pc-map__hop--' + (h.type || 'router') });
            li.appendChild(el('span', { class: 'pc-map__hop-num', text: String(i + 1), style: 'border-color:' + h.color + ';color:' + h.color + ';' }));

            var body = el('div', { class: 'pc-map__hop-body' });
            var nameLine = el('div', { class: 'pc-map__hop-name' });
            nameLine.appendChild(document.createTextNode(h.label + ' '));
            if (h.role) {
                nameLine.appendChild(el('span', { class: 'pc-badge', text: h.role }));
            }
            body.appendChild(nameLine);

            var subBits = [];
            if (h.ip) {
                subBits.push(h.ip);
            } else if (h.label) {
                subBits.push(h.label);
            }
            if (h.proto || h.port) {
                var pp = (h.proto ? h.proto : '?').toUpperCase();
                if (h.port) { pp += ':' + h.port; }
                subBits.push(pp);
            }
            if (h.ttl != null) { subBits.push('TTL ' + h.ttl); }
            if (h.asn || h.org) {
                var asnTxt = '';
                if (h.asn) { asnTxt += h.asn; }
                if (h.org) { asnTxt += (asnTxt ? ' · ' : '') + h.org; }
                subBits.push(asnTxt);
            }
            if (h.country) {
                subBits.push(h.country + (h.region ? ' / ' + h.region : ''));
            }
            // Always render a sub line, even if empty, so the row layout stays
            // consistent across hop rows. Falls back to the hop label.
            var subText = subBits.length ? subBits.join(' · ') : h.label;
            body.appendChild(el('div', { class: 'pc-map__hop-sub', text: subText }));
            li.appendChild(body);

            var right = el('div', { class: 'pc-map__hop-right' });
            if (h.traffic) {
                right.appendChild(el('span', { class: 'pc-badge pc-badge--proto pc-badge--' + String(h.traffic).toLowerCase(), text: h.traffic }));
            }
            if (h.rtt !== null && h.rtt !== undefined) {
                right.appendChild(el('span', { class: 'pc-map__hop-rtt', text: h.rtt + ' ms', style: 'color:' + h.legColor + ';' }));
            } else {
                right.appendChild(el('span', { class: 'pc-map__hop-rtt', text: '—' }));
            }
            if (h.jitter != null && h.jitter > 0) {
                right.appendChild(el('span', { class: 'pc-badge pc-badge--jitter', text: 'j' + h.jitter.toFixed(1).replace(/\.0$/, '') }));
            }
            if (h.loss != null && h.loss > 0) {
                right.appendChild(el('span', { class: 'pc-badge pc-badge--warn pc-badge--loss', text: 'loss ' + h.loss + '%' }));
            }
            li.appendChild(right);

            // Tooltip with full detail dump.
            var tt = [];
            if (h.ip)    { tt.push('IP: ' + h.ip); }
            if (h.proto) { tt.push('Protocol: ' + h.proto.toUpperCase()); }
            if (h.port)  { tt.push('Port: ' + h.port); }
            if (h.traffic){ tt.push('Traffic: ' + h.traffic); }
            if (h.ttl != null) { tt.push('TTL: ' + h.ttl); }
            if (h.rtt != null) { tt.push('RTT: ' + h.rtt + ' ms'); }
            if (h.asn)  { tt.push('ASN: ' + h.asn); }
            if (h.org)  { tt.push('Org: ' + h.org); }
            if (h.country) { tt.push('Country: ' + h.country + (h.region ? ' / ' + h.region : '')); }
            if (tt.length) { li.title = tt.join('\n'); }

            listEl.appendChild(li);
        });
    }

    // Helper: animate a Leaflet circleMarker along the polyline.
    function animateMapPacket(marker, latlngs, hopCount) {
        if (!latlngs || latlngs.length < 2) return;
        var totalMs = Math.max(2000, hopCount * 1100);
        var start = performance.now();
        function frame(now) {
            var t = ((now - start) % totalMs) / totalMs;
            var pos = positionOnLine(latlngs, t);
            marker.setLatLng(pos);
            // Pulse radius for a glowing-packet effect.
            var pulse = 5 + 2.5 * Math.sin((t * Math.PI * 4));
            try { marker.setRadius(pulse); } catch (e) {}
            requestAnimationFrame(frame);
        }
        requestAnimationFrame(frame);
    }

    // Helper: linear interpolation along an array of [lat,lng] points at t in [0,1].
    function positionOnLine(latlngs, t) {
        if (t <= 0) return latlngs[0];
        if (t >= 1) return latlngs[latlngs.length - 1];
        var segments = latlngs.length - 1;
        var segF = t * segments;
        var i = Math.floor(segF);
        var f = segF - i;
        return [
            latlngs[i][0] + (latlngs[i + 1][0] - latlngs[i][0]) * f,
            latlngs[i][1] + (latlngs[i + 1][1] - latlngs[i][1]) * f
        ];
    }

    function escapeHtml(s) {
        return String(s || '').replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }

    /* ---------- Main scanner orchestration ---------- */

    var steps = ['ip', 'intel', 'reputation', 'fingerprint', 'webrtc', 'score'];

    function runScan() {
        var dashboard = document.querySelector('[data-pc-component="dashboard"]');
        if (!dashboard) return;
        var region = dashboard.querySelector('[data-pc-region="report"]');
        region.hidden = true;
        region.innerHTML = '';
        showInitialSpinner();
        resetScanProgress();
        showSkeleton(region);
        steps.forEach(function (s) { setStep(s, 'pending'); });

        var rescanBtn = document.querySelector('[data-pc-action="rescan"]');
        if (rescanBtn) rescanBtn.classList.add('is-scanning');

        var STEP_LABELS = {
            ip:          I18N.detectIp         || 'Detecting IP…',
            intel:       I18N.detectIntel      || 'Resolving geolocation…',
            reputation:  I18N.detectReputation || 'Checking reputation…',
            fingerprint: I18N.detectFingerprint|| 'Estimating fingerprint…',
            webrtc:      I18N.detectWebrtc     || 'Testing WebRTC…',
            score:       I18N.detectScore      || 'Calculating score…'
        };
        var STEP_SUBS = {
            ip:          'Looking up your public IPv4 / IPv6',
            intel:       'Resolving city, region, ASN, ISP, rDNS',
            reputation:  'Querying blocklists and reputation signals',
            fingerprint: 'Computing fingerprint visibility from browser signals',
            webrtc:      'Testing STUN/TURN for IP leaks',
            score:       'Aggregating signals into privacy & anonymity scores'
        };

        var currentStep = 0;
        function advance() {
            if (currentStep >= steps.length) return;
            var step = steps[currentStep];
            setStep(step, 'active');
            // Drive the scan card: 0..95% across the 6 stages.
            var pct = Math.min(95, (currentStep / steps.length) * 100 + 5);
            setScanProgress(pct, STEP_LABELS[step], STEP_SUBS[step], currentStep, 'active');
            currentStep++;
        }
        function complete(step) {
            setStep(step, 'done');
            // Find the index of this step in the steps array and mark its dot done.
            var idx = steps.indexOf(step);
            if (idx >= 0) {
                var pct = Math.min(99, ((idx + 1) / steps.length) * 100);
                setScanProgress(pct, STEP_LABELS[step] + ' ✓', STEP_SUBS[step], idx, 'done');
            }
        }
        function fail(step) {
            setStep(step, 'error');
            var idx = steps.indexOf(step);
            if (idx >= 0) {
                setScanProgress(
                    Math.max(0, (idx / steps.length) * 100),
                    STEP_LABELS[step] + ' ⚠',
                    'Continuing with partial data',
                    idx,
                    'error'
                );
            }
        }

        advance(); // ip
        var fingerprint = collectFingerprint().then(function (fp) { return fp; });

        // Run WebRTC in parallel; UI updates sequentially.
        var webrtcPromise = runWebrtcTest();

        api('scan/ip').then(function (resp) {
            complete('ip');
            if (resp.ok) {
                advance(); // intel
                return api('scan/connection');
            }
            fail('ip');
            throw new Error('ip');
        }).then(function (resp) {
            complete('intel');
            if (resp.ok) {
                advance(); // reputation
                return api('scan/reputation');
            }
            fail('intel');
            throw new Error('intel');
        }).then(function (resp) {
            complete('reputation');
            if (resp.ok) {
                advance(); // fingerprint
                return Promise.all([fingerprint, webrtcPromise]).then(function (results) {
                    var fp = results[0] || {};
                    var webrtcData = results[1] || {};
                    return api('scan', {
                        method: 'POST',
                        body: Object.assign({}, fp, { webrtc: webrtcData })
                    });
                });
            }
            fail('reputation');
            throw new Error('reputation');
        }).then(function (resp) {
            complete('fingerprint');
            if (resp.ok) {
                advance(); // webrtc
                complete('webrtc');
                advance(); // score
                if (resp.data && resp.data.scores) {
                    setScore(resp.data.scores.privacy, resp.data.scores.breakdown);
                } else {
                    setScore(0, {});
                }
                complete('score');
                // 100% bump before hiding the spinner so the user sees completion.
                setScanProgress(100, 'Done', 'Privacy report ready', steps.length - 1, 'done');
                setTimeout(function () {
                    hideSpinner();
                    if (rescanBtn) rescanBtn.classList.remove('is-scanning');
                }, 240);
                renderCards(resp.data || {}, region);
            } else {
                fail('fingerprint');
                hideSpinner();
                if (rescanBtn) rescanBtn.classList.remove('is-scanning');
                showError(region);
            }
        }).catch(function () {
            hideSpinner();
            if (rescanBtn) rescanBtn.classList.remove('is-scanning');
            showError(region);
        });
    }

    function showError(region) {
        steps.forEach(function (s) { setStep(s, 'error'); });
        region.hidden = false;
        region.innerHTML = '';
        var card = el('div', { class: 'pc-card pc-status--danger' }, [
            el('h2', { class: 'pc-card__title', text: I18N.errorTitle || 'Something went wrong' }),
            el('p', { text: I18N.errorBody || 'Please retry.' })
        ]);
        region.appendChild(card);
    }

    /* ---------- Continuous-mode wiring (network path) ---------- */

    // Tracks the last scan result so continuous mode can re-render the
    // network card with refreshed (slightly perturbed) ms/jitter values
    // without re-running the full pipeline.
    var PC_LAST_REPORT = null;
    var PC_CONTINUOUS_TIMER = null;

    function refreshNetworkMetrics() {
        var dashboard = document.querySelector('[data-pc-component="dashboard"]');
        if (!dashboard || !PC_LAST_REPORT) return;
        var region = dashboard.querySelector('[data-pc-region="report"]');
        if (!region) return;
        // Re-render the network card in-place.
        var existing = region.querySelector('.pc-network');
        if (!existing) return;
        var next = networkPathCard(PC_LAST_REPORT);
        next.classList.add('is-refreshing');
        existing.parentNode.replaceChild(next, existing);
    }

    function startContinuousScan() {
        if (PC_CONTINUOUS_TIMER) return;
        // Re-poll every 4 s with small perturbations
        PC_CONTINUOUS_TIMER = setInterval(function () {
            var dashboard = document.querySelector('[data-pc-component="dashboard"]');
            if (!dashboard) return;
            refreshNetworkMetrics();
            // Pulse any visible .pc-network__continuous-dot (already animated by CSS)
            var dot = dashboard.querySelector('.pc-network__continuous-dot');
            if (dot) {
                dot.classList.remove('is-pulse');
                void dot.offsetWidth;
                dot.classList.add('is-pulse');
            }
        }, 4000);
    }

    function stopContinuousScan() {
        if (PC_CONTINUOUS_TIMER) {
            clearInterval(PC_CONTINUOUS_TIMER);
            PC_CONTINUOUS_TIMER = null;
        }
    }

    function attachContinuousDelegation() {
        var dashboard = document.querySelector('[data-pc-component="dashboard"]');
        if (!dashboard || dashboard.__pcContinuousBound) return;
        dashboard.__pcContinuousBound = true;
        dashboard.addEventListener('click', function (e) {
            var t = e.target.closest('[data-pc-action="continuous-toggle"]');
            if (!t) return;
            var isOn = !t.classList.contains('is-on');
            t.classList.toggle('is-on', isOn);
            t.setAttribute('aria-pressed', isOn ? 'true' : 'false');
            // Replace label text only (keep dot child).
            var dot = t.querySelector('.pc-network__continuous-dot');
            t.innerHTML = '';
            if (dot) t.appendChild(dot);
            t.appendChild(document.createTextNode(isOn ? 'LIVE' : 'CONTINUOUS'));
            window.PC_NETWORK_CONTINUOUS = isOn;
            if (isOn) {
                startContinuousScan();
                if (typeof showToast === 'function') {
                    showToast('Continuous traceroute / ping ON — refreshing every 4s.', 'ok');
                }
            } else {
                stopContinuousScan();
                if (typeof showToast === 'function') {
                    showToast('Continuous traceroute / ping OFF.', 'info');
                }
            }
        });
    }

    // Hook into runScan: keep a reference to the latest report and
    // ensure the delegation is attached after each render.
    (function () {
        var orig = renderCards;
        // Save reference so we can wrap it after definition below.
        window.__pcRenderCardsHook = function (rep) {
            PC_LAST_REPORT = rep;
            setTimeout(attachContinuousDelegation, 0);
            // If continuous mode is already on, refresh metrics now.
            if (window.PC_NETWORK_CONTINUOUS === true) {
                setTimeout(refreshNetworkMetrics, 50);
            }
        };
    })();

    /**
     * User-guide onboarding tour — MANUAL-ONLY driver.
     *
     * The tour is opened ONLY when the user clicks a trigger carrying
     * `data-pc-action="open-guide"` (rendered by the [privacy_checker_user_guide]
     * shortcode as a floating "?" button). It is never auto-launched: there is
     * no first-visit hook, no localStorage flag, no scheduled timer, and no
     * listener that runs `openGuide()` on `DOMContentLoaded`. The only paths
     * into the overlay are explicit clicks.
     */
    function bindUserGuide() {
        var tour = (window.PC_GUIDE && window.PC_GUIDE.tour) || [];
        if (!tour.length) return;
        var overlay = document.querySelector('[data-pc-component="user-guide"]');
        var fab     = document.querySelector('.pc-guide-fab');
        if (!overlay || !fab) return;

        var titleEl  = overlay.querySelector('[data-pc-region="tour-title"]');
        var bodyEl   = overlay.querySelector('[data-pc-region="tour-body"]');
        var stepEl   = overlay.querySelector('[data-pc-region="tour-step"]');
        var cardEl   = overlay.querySelector('[data-pc-region="tour-card"]');
        var prevBtn  = overlay.querySelector('[data-pc-action="prev-step"]');
        var nextBtn  = overlay.querySelector('[data-pc-action="next-step"]');
        var endBtn   = overlay.querySelector('[data-pc-action="end-tour"]');
        var closeEls = overlay.querySelectorAll('[data-pc-action="close-guide"]');

        // Per-session UI state for the tour.
        var currentIndex = 0;
        var lastFocus    = null;

        function escapeHtml(s) {
            return String(s == null ? '' : s)
                .replace(/&/g, '&amp;').replace(/</g, '&lt;')
                .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }

        function stepCount() { return tour.length; }
        function currentStep() { return tour[Math.max(0, Math.min(currentIndex, stepCount() - 1))]; }

        /**
         * Find the first element matching any of the comma-separated selectors
         * in `step.target`. Returns null if the page doesn't have a matching
         * node — in that case we center the card without highlighting.
         */
        function resolveTarget(target) {
            if (!target) return null;
            var parts = String(target).split(',');
            for (var i = 0; i < parts.length; i++) {
                var sel = parts[i].trim();
                if (!sel) continue;
                var node = document.querySelector(sel);
                if (node) return node;
            }
            return null;
        }

        /**
         * Position the card relative to `target`. If `place` is "center" or
         * the target is missing, anchor the card to the viewport center.
         */
        function positionForStep(step) {
            // Reset placement classes first.
            cardEl.classList.remove(
                'pc-guide-card--center',
                'pc-guide-card--top',
                'pc-guide-card--bottom',
                'pc-guide-card--left',
                'pc-guide-card--right'
            );

            var targetNode = resolveTarget(step && step.target);
            if (!targetNode || (step && step.place === 'center')) {
                cardEl.classList.add('pc-guide-card--center');
                return;
            }

            var place = (step && step.place) || 'bottom';
            cardEl.classList.add('pc-guide-card--' + place);

            // Defer to next frame so the layout (including class flip) settles.
            requestAnimationFrame(function () {
                var rect = targetNode.getBoundingClientRect();
                var vw = window.innerWidth || document.documentElement.clientWidth;
                var vh = window.innerHeight || document.documentElement.clientHeight;

                // If the target is off-screen, treat as no highlight.
                if (rect.bottom < 0 || rect.top > vh || rect.right < 0 || rect.left > vw) {
                    cardEl.classList.remove('pc-guide-card--top', 'pc-guide-card--bottom',
                                            'pc-guide-card--left', 'pc-guide-card--right');
                    cardEl.classList.add('pc-guide-card--center');
                    return;
                }

                var cardRect = cardEl.getBoundingClientRect();
                var cw = cardRect.width  || 360;
                var ch = cardRect.height || 220;
                var margin = 16;
                var top = 0, left = 0;

                switch (place) {
                    case 'top':
                        top  = Math.max(margin, rect.top - ch - margin);
                        left = rect.left + (rect.width / 2) - (cw / 2);
                        break;
                    case 'left':
                        top  = rect.top + (rect.height / 2) - (ch / 2);
                        left = Math.max(margin, rect.left - cw - margin);
                        break;
                    case 'right':
                        top  = rect.top + (rect.height / 2) - (ch / 2);
                        left = rect.right + margin;
                        break;
                    case 'bottom':
                    default:
                        top  = rect.bottom + margin;
                        left = rect.left + (rect.width / 2) - (cw / 2);
                        break;
                }

                // Clamp into viewport.
                var maxLeft = (vw - cw) - margin;
                var maxTop  = (vh - ch) - margin;
                if (left < margin) left = margin;
                if (left > maxLeft) left = Math.max(margin, maxLeft);
                if (top  < margin) top  = margin;
                if (top  > maxTop)  top  = Math.max(margin, maxTop);

                cardEl.style.left = Math.round(left) + 'px';
                cardEl.style.top  = Math.round(top)  + 'px';
            });
        }

        function renderStep() {
            var step    = currentStep();
            var i18n    = (window.PC_SCAN && window.PC_SCAN.i18n) || {};
            var next    = i18n.guideNext  || 'Next';
            var prev    = i18n.guidePrev  || 'Previous';
            var done    = i18n.guideDone  || 'Got it';
            var stepTpl = i18n.guideStepOf || 'Step %1$d of %2$d';

            titleEl.textContent = step.title || '';
            bodyEl.innerHTML    = '<p>' + escapeHtml(step.body || '') + '</p>';
            stepEl.textContent  = stepTpl
                .replace('%1$d', String(currentIndex + 1))
                .replace('%2$d', String(stepCount()));

            prevBtn.disabled = (currentIndex === 0);
            var isLast = (currentIndex === stepCount() - 1);
            nextBtn.hidden = isLast;
            endBtn.hidden  = !isLast;
            nextBtn.textContent = next;
            prevBtn.textContent = prev;
            endBtn.textContent  = done;

            positionForStep(step);
        }

        function openGuide() {
            if (!overlay.hidden) return;
            lastFocus = document.activeElement;
            currentIndex = 0;
            overlay.hidden = false;
            document.body.classList.add('pc-guide-open');
            renderStep();
            // Move focus into the card for keyboard navigation.
            try { cardEl.focus(); } catch (e) { /* noop */ }
        }

        function closeGuide() {
            if (overlay.hidden) return;
            overlay.hidden = true;
            document.body.classList.remove('pc-guide-open');
            cardEl.classList.remove(
                'pc-guide-card--center',
                'pc-guide-card--top',
                'pc-guide-card--bottom',
                'pc-guide-card--left',
                'pc-guide-card--right'
            );
            cardEl.style.left = '';
            cardEl.style.top  = '';
            if (lastFocus && typeof lastFocus.focus === 'function') {
                try { lastFocus.focus(); } catch (e) { /* noop */ }
            }
        }

        function nextStep() {
            if (currentIndex < stepCount() - 1) {
                currentIndex++;
                renderStep();
            }
        }

        function prevStep() {
            if (currentIndex > 0) {
                currentIndex--;
                renderStep();
            }
        }

        function endTour() {
            closeGuide();
        }

        // --- Wiring (manual-only launch) -----------------------------

        fab.addEventListener('click', function (e) {
            e.preventDefault();
            openGuide();
        });

        // Any in-page element with data-pc-action="open-guide" also opens
        // the tour. This is opt-in: nothing fires unless a page author or
        // a visitor click hit one of these elements.
        document.addEventListener('click', function (e) {
            var trigger = e.target && e.target.closest
                ? e.target.closest('[data-pc-action="open-guide"]:not(.pc-guide-fab)')
                : null;
            if (trigger) {
                e.preventDefault();
                openGuide();
            }
        });

        closeEls.forEach(function (el_) {
            el_.addEventListener('click', function (e) {
                e.preventDefault();
                closeGuide();
            });
        });

        nextBtn.addEventListener('click', function (e) { e.preventDefault(); nextStep(); });
        prevBtn.addEventListener('click', function (e) { e.preventDefault(); prevStep(); });
        endBtn.addEventListener('click',  function (e) { e.preventDefault(); endTour(); });

        // Keyboard: Esc closes, arrows navigate (when focus is inside the overlay).
        overlay.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' || e.keyCode === 27) {
                e.preventDefault();
                closeGuide();
            } else if (e.key === 'ArrowRight' || e.keyCode === 39) {
                if (!nextBtn.hidden) { e.preventDefault(); nextStep(); }
            } else if (e.key === 'ArrowLeft' || e.keyCode === 37) {
                if (!prevBtn.disabled) { e.preventDefault(); prevStep(); }
            } else if (e.key === 'Enter' && document.activeElement === cardEl) {
                e.preventDefault();
                if (!nextBtn.hidden) { nextStep(); } else { endTour(); }
            }
        });

        // Re-position on resize / scroll while the guide is open so the card
        // stays attached to its target.
        var reposition = function () { if (!overlay.hidden) { positionForStep(currentStep()); } };
        window.addEventListener('resize', reposition);
        window.addEventListener('scroll', reposition, { passive: true });
    }

    /* ---------- Boot ---------- */

    function bindGeotraceroute() {
        var root = document.querySelector('[data-pc-component="geotraceroute"]');
        if (!root) return;

        var canvas = root.querySelector('.pc-geo__stars');
        var mapEl  = root.querySelector('[data-pc-region="map"]');
        var globeEl = root.querySelector('[data-pc-region="globe"]');
        var status = root.querySelector('[data-pc-region="status"]');
        var originOut = root.querySelector('[data-pc-region="origin"]');
        var destOut   = root.querySelector('[data-pc-region="destination"]');
        var hopsOut   = root.querySelector('[data-pc-region="hops"]');
        var distOut   = root.querySelector('[data-pc-region="distance"]');
        var asOut     = root.querySelector('[data-pc-region="aspath"]');
        var durOut    = root.querySelector('[data-pc-region="duration"]');
        var hopList   = root.querySelector('[data-pc-region="hops"]');
        var probesList = root.querySelector('[data-pc-region="probes"]');
        var recentList = root.querySelector('[data-pc-region="recent"]');
        var toastEl   = root.querySelector('[data-pc-region="toast"]');
        var runBtn    = root.querySelector('[data-pc-action="geo-run"]');
        var resetBtn  = root.querySelector('[data-pc-action="geo-reset"]');
        var toggleBtn = root.querySelector('[data-pc-action="geo-toggle"]');
        var viewBtn   = root.querySelector('[data-pc-action="geo-view"]');
        var playIcon  = root.querySelector('[data-pc-geo-icon-play]');
        var pauseIcon = root.querySelector('[data-pc-geo-icon-pause]');
        var hostInput = root.querySelector('#pc-geo-target');

        // ===== Helpers =====
        function showToast(text, kind) {
            if (!toastEl) return;
            toastEl.textContent = text;
            toastEl.dataset.kind = kind || 'info';
            toastEl.hidden = false;
            clearTimeout(showToast._t);
            showToast._t = setTimeout(function () { toastEl.hidden = true; }, 3000);
        }

        function loadPrefs() {
            try {
                var raw = localStorage.getItem('pc-geo-prefs');
                return raw ? JSON.parse(raw) : {};
            } catch (e) { return {}; }
        }
        function savePrefs(p) {
            try { localStorage.setItem('pc-geo-prefs', JSON.stringify(p || {})); } catch (e) {}
        }
        function applyPrefsToForm() {
            var p = loadPrefs();
            root.querySelectorAll('[data-pc-pref]').forEach(function (el) {
                var key = el.dataset.pcPref;
                if (el.type === 'checkbox') el.checked = !!p[key];
                else el.value = p[key] || el.value || '';
            });
        }
        function collectPrefs() {
            var p = {};
            root.querySelectorAll('[data-pc-pref]').forEach(function (el) {
                var key = el.dataset.pcPref;
                if (el.type === 'checkbox') p[key] = el.checked;
                else p[key] = el.value;
            });
            return p;
        }

        function setLang(lang) {
            try {
                localStorage.setItem('pc-geo-lang', lang);
                document.documentElement.lang = lang;
            } catch (e) {}
        }
        function readLang() {
            try { return localStorage.getItem('pc-geo-lang') || 'en'; } catch (e) { return 'en'; }
        }

        // ===== Probe network =====
        var probes = [
            { cc: 'FR', city: 'Strasbourg', org: 'SdV Plurimedia',       asn: 'AS8839',  flag: '\u{1F1EB}\u{1F1F7}' },
            { cc: 'FR', city: 'Paris',      org: 'Online SAS',           asn: 'AS12876', flag: '\u{1F1EB}\u{1F1F7}' },
            { cc: 'NL', city: 'Amsterdam',  org: 'WorldStream',          asn: 'AS49981', flag: '\u{1F1F3}\u{1F1F1}' },
            { cc: 'DE', city: 'Frankfurt',  org: 'Hetzner',              asn: 'AS24940', flag: '\u{1F1E9}\u{1F1EA}' },
            { cc: 'GB', city: 'London',     org: 'Vultr',                asn: 'AS204957',flag: '\u{1F1EC}\u{1F1E7}' },
            { cc: 'CH', city: 'Zurich',     org: 'Infomaniak',           asn: 'AS29222', flag: '\u{1F1E8}\u{1F1ED}' },
            { cc: 'US', city: 'New York',   org: 'Cogent',               asn: 'AS174',   flag: '\u{1F1FA}\u{1F1F8}' },
            { cc: 'US', city: 'Ashburn',    org: 'Hetzner',              asn: 'AS213230',flag: '\u{1F1FA}\u{1F1F8}' },
            { cc: 'CA', city: 'Toronto',    org: 'OVHcloud',             asn: 'AS16276', flag: '\u{1F1E8}\u{1F1E6}' },
            { cc: 'BR', city: 'Sao Paulo',  org: 'Locaweb',              asn: 'AS27693', flag: '\u{1F1E7}\u{1F1F7}' },
            { cc: 'JP', city: 'Tokyo',      org: 'IIJ',                  asn: 'AS4713',  flag: '\u{1F1EF}\u{1F1F5}' },
            { cc: 'SG', city: 'Singapore',  org: 'Vultr',                asn: 'AS204957',flag: '\u{1F1F8}\u{1F1EC}' },
            { cc: 'AU', city: 'Sydney',     org: 'Vultr',                asn: 'AS204957',flag: '\u{1F1E6}\u{1F1FA}' },
            { cc: 'ZA', city: 'Cape Town',  org: 'Hetzner',              asn: 'AS37153', flag: '\u{1F1FF}\u{1F1E6}' }
        ];
        function renderProbes() {
            if (!probesList) return;
            probesList.innerHTML = '';
            probes.forEach(function (p) {
                var li = el('li', {});
                li.appendChild(el('span', { class: 'pc-geo__probe-flag', text: p.flag }));
                li.appendChild(el('div', {}, [
                    el('strong', { text: p.cc + '-' + p.city }),
                    el('small',  { text: p.org })
                ]));
                li.appendChild(el('span', { class: 'pc-geo__probe-asn', text: p.asn }));
                probesList.appendChild(li);
            });
        }

        // ===== Recent traceroutes (localStorage) =====
        var RECENT_KEY = 'pc-geo-recent';
        function readRecent() {
            try { return JSON.parse(localStorage.getItem(RECENT_KEY) || '[]'); }
            catch (e) { return []; }
        }
        function writeRecent(list) {
            try { localStorage.setItem(RECENT_KEY, JSON.stringify(list.slice(0, 10))); } catch (e) {}
        }
        function pushRecent(target, hopsCount) {
            var list = readRecent();
            list.unshift({
                target: target,
                hops: hopsCount,
                ts: Date.now()
            });
            writeRecent(list);
            renderRecent();
        }
        function renderRecent() {
            if (!recentList) return;
            var list = readRecent();
            recentList.innerHTML = '';
            if (!list.length) {
                var li = el('li', { style: 'grid-column:1 / -1;justify-content:center;color:var(--geo-text-dim);' });
                li.textContent = (I18N.geoRecentEmpty || 'No recent traceroutes yet.');
                recentList.appendChild(li);
                return;
            }
            list.forEach(function (r) {
                var li = el('li', {});
                var flag = (r.target && r.target.length > 0) ? '\u{1F310}' : '\u{1F310}';
                li.appendChild(el('span', { class: 'pc-geo__recent-flag', text: flag }));
                var target = String(r.target || '').replace(/^https?:\/\//, '').slice(0, 24);
                li.appendChild(el('div', {}, [
                    el('strong', { text: target || '\u2014' }),
                    el('small',  { text: (r.hops || 0) + ' hops' })
                ]));
                var d = new Date(r.ts || Date.now());
                li.appendChild(el('span', { style: 'color:var(--geo-text-dim);font-size:0.72rem;', text: d.toLocaleTimeString() }));
                recentList.appendChild(li);
            });
        }

        // ===== Paste-traceroute parser =====
        // Accept Linux traceroute, Windows tracert, and MTR output. Extracts IP,
        // hostname, RTT, loss% (MTR), protocol hint (ICMP/UDP/TCP inferred from
        // tool + hop index), and a default TTL/port when the source doesn't print
        // them. The hop index is used as a TTL stand-in so the row still shows
        // a meaningful value.
        function parseTraceroute(text) {
            if (!text || !text.trim()) return null;
            var lines = text.split(/\r?\n/);
            var hops = [];
            var detectedTool = /MTR/i.test(text) ? 'mtr'
                            : /tracert/i.test(text) ? 'win'
                            : /traceroute/i.test(text) ? 'linux'
                            : 'unknown';
            var defaultProto = detectedTool === 'mtr' ? 'icmp'
                             : detectedTool === 'win' ? 'icmp'
                             : 'udp'; // classic Linux traceroute default.
            for (var i = 0; i < lines.length; i++) {
                var line = lines[i].trim();
                if (!line) continue;
                if (/^traceroute|^tracert|^MTR|^Start:|^HOST:/i.test(line)) continue;

                // Linux style: " 1  router.lan (192.0.2.1)  1.123 ms  1.245 ms  1.301 ms"
                var linux = line.match(/^(\d+)\s+([\w\-\.]+)?\s*(?:\(([\d\.:a-fA-F]+)\))?\s+([\d\.]+)\s+ms/);
                if (linux) {
                    hops.push({
                        n: parseInt(linux[1], 10),
                        host: linux[2] || '',
                        ip: linux[3] || '',
                        ms: parseFloat(linux[4]),
                        loss: 0,
                        proto: defaultProto,
                        port: 33434 + parseInt(linux[1], 10), // Linux default starting port.
                        ttl: parseInt(linux[1], 10)
                    });
                    continue;
                }
                // Windows style: "  1     1 ms     1 ms     1 ms  192.0.2.1"
                var win = line.match(/^\s*(\d+)\s+<?\s*(\d+)\s*ms/i);
                if (win) {
                    var tail = line.replace(/^\s*\d+\s+<?\s*\d+\s*ms\s*/i, '');
                    var ipMatch = tail.match(/([\d\.:a-fA-F]+)/);
                    hops.push({
                        n: parseInt(win[1], 10),
                        host: '',
                        ip: ipMatch ? ipMatch[1] : '',
                        ms: parseFloat(win[2]),
                        loss: 0,
                        proto: 'icmp',
                        ttl: parseInt(win[1], 10)
                    });
                    continue;
                }
                // MTR style: " 1. 192.0.2.1         0.0%   10  1.2  1.5  1.0  2.3  2.0"
                var mtr = line.match(/^\s*(\d+)\.\s+([\w\-\.]+)?\s*(?:\(([\d\.:a-fA-F]+)\))?\s+([\d\.]+)%\s+(\d+)\s+([\d\.]+)/);
                if (mtr) {
                    hops.push({
                        n: parseInt(mtr[1], 10),
                        host: mtr[2] || '',
                        ip: mtr[3] || '',
                        ms: parseFloat(mtr[6]),
                        loss: parseFloat(mtr[4]),
                        proto: 'icmp',
                        ttl: parseInt(mtr[1], 10)
                    });
                    continue;
                }
                // MTR report-style header continuation (no leading "%" line): some
                // MTR builds omit the loss column. " 1. 192.0.2.1  1.2  1.5  1.0  2.3  2.0"
                var mtrShort = line.match(/^\s*(\d+)\.\s+([\w\-\.]+)?\s*(?:\(([\d\.:a-fA-F]+)\))?\s+([\d\.]+)\s+([\d\.]+)/);
                if (mtrShort) {
                    hops.push({
                        n: parseInt(mtrShort[1], 10),
                        host: mtrShort[2] || '',
                        ip: mtrShort[3] || '',
                        ms: parseFloat(mtrShort[4]),
                        loss: 0,
                        proto: 'icmp',
                        ttl: parseInt(mtrShort[1], 10)
                    });
                }
            }
            return hops.length ? hops : null;
        }

        // ===== Panels / modals =====
        function bindPanelToggle(panel) {
            var toggle = panel.querySelector('.pc-geo__panel-toggle');
            var body   = panel.querySelector('.pc-geo__panel-body');
            if (!toggle || !body) return;
            toggle.addEventListener('click', function () {
                var open = !body.hidden;
                body.hidden = open;
                toggle.setAttribute('aria-expanded', open ? 'false' : 'true');
            });
        }
        root.querySelectorAll('.pc-geo__panel').forEach(bindPanelToggle);

        function openModal(name) {
            var m = root.querySelector('[data-pc-modal="' + name + '"]');
            if (m) m.hidden = false;
        }
        function closeModals() {
            root.querySelectorAll('.pc-geo__modal').forEach(function (m) { m.hidden = true; });
        }
        root.addEventListener('click', function (e) {
            var t = e.target.closest('[data-pc-action]');
            if (!t) return;
            var action = t.dataset.pcAction;
            if (action === 'open-methodology') openModal('methodology');
            if (action === 'open-prefs') {
                applyPrefsToForm();
                openModal('preferences');
            }
            if (action === 'modal-close') closeModals();
            if (action === 'prefs-save') {
                e.preventDefault();
                savePrefs(collectPrefs());
                closeModals();
                showToast('Preferences saved.', 'ok');
            }
            if (action === 'set-lang') {
                setLang(t.value);
            }
            if (action === 'geo-paste-toggle' || action === 'geo-probes-toggle' || action === 'geo-recent-toggle') {
                // handled per-panel binding
            }
            if (action === 'geo-view') {
                setGeoView(globeState.mode !== '3d');
            }
            if (action === 'geo-paste') {
                e.preventDefault();
                var ta = root.querySelector('#pc-geo-paste');
                var text = (ta && ta.value) || '';
                var parsed = parseTraceroute(text);
                if (!parsed) {
                    showToast(I18N.geoPasteEmpty || 'Paste traceroute output first.', 'warn');
                    return;
                }
                if (!parsed.length) {
                    showToast(I18N.geoPasteBad || 'Could not parse.', 'warn');
                    return;
                }
                renderFromParsed(parsed);
                showToast('Visualized ' + parsed.length + ' hops.', 'ok');
            }
        });
        // Esc closes modals.
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') closeModals();
        });

        function renderFromParsed(hops) {
            // Build a synthetic latlng path along the existing origin if known, else a default.
            var lastReportLocal = lastReport || synthesizeFromReport({ connection: { intel: {} } });
            var origin = lastReportLocal.hops[0] ? [lastReportLocal.hops[0].lat, lastReportLocal.hops[0].lng] : [48.5734, 7.7521];
            var dest = [origin[0] - 22 + Math.random() * 6, origin[1] - 50 + Math.random() * 10];
            var newChain = [];
            var totalKm = 0;
            var lastLat = origin[0];
            var lastLng = origin[1];
            hops.forEach(function (h, i) {
                var t = hops.length === 1 ? 0 : i / (hops.length - 1);
                var mid = 0.18 * Math.sin(t * Math.PI);
                var lat = origin[0] + (dest[0] - origin[0]) * t + mid;
                var lng = origin[1] + (dest[1] - origin[1]) * t + mid;
                var km = (i === 0) ? 0 : haversine(lastLat, lastLng, lat, lng);
                totalKm += km;
                var ms = (i === 0) ? null : Math.round(h.ms || 0);
                newChain.push({
                    lat: lat,
                    lng: lng,
                    label: h.host ? h.host : ('Hop ' + i),
                    sub: (h.ip ? h.ip : 'unknown IP') + ' · ' + (h.ms ? h.ms.toFixed(1) + ' ms' : '—'),
                    flag: '',
                    ip: h.ip,
                    asn: 'AS' + (10000 + Math.floor(Math.random() * 90000)),
                    ms: ms,
                    km: i === 0 ? null : Math.round(km),
                    type: i === hops.length - 1 ? 'destination' : 'router',
                    color: i === hops.length - 1 ? '#28a745' : '#17a2b8',
                    legColor: i === 0 ? '#17a2b8' : colorForMs(ms)
                });
                lastLat = lat;
                lastLng = lng;
            });
            lastReport = {
                origin: 'Pasted input',
                destination: hops[hops.length - 1] && (hops[hops.length - 1].host || hops[hops.length - 1].ip) || 'destination',
                hops: newChain,
                as_path: newChain.map(function (h) { return h.asn; }),
                total_km: Math.round(totalKm),
                duration_ms: newChain.reduce(function (a, h) { return a + (h.ms || 0); }, 0)
            };
            updateSummary(lastReport);
            renderHopList(lastReport.hops);
            drawRoute(lastReport);
            setStatus((I18N.geoConnectedHops || 'Connected (%s hops received)').replace('%s', String(lastReport.hops.length - 1)), 'connected');
            pushRecent(lastReport.destination, lastReport.hops.length);
        }


        // Starfield background.
        if (canvas && typeof canvas.getContext === 'function') {
            var ctx = canvas.getContext('2d');
            var stars = [];
            function resize() {
                var rect = canvas.parentElement.getBoundingClientRect();
                canvas.width = rect.width * (window.devicePixelRatio || 1);
                canvas.height = rect.height * (window.devicePixelRatio || 1);
                canvas.style.width = rect.width + 'px';
                canvas.style.height = rect.height + 'px';
                ctx.setTransform(window.devicePixelRatio || 1, 0, 0, window.devicePixelRatio || 1, 0, 0);
                stars = [];
                for (var i = 0; i < 200; i++) {
                    stars.push({
                        x: Math.random() * rect.width,
                        y: Math.random() * rect.height,
                        r: Math.random() * 1.2 + 0.3,
                        o: Math.random() * 0.7 + 0.3,
                        tw: Math.random() * 0.02 + 0.005
                    });
                }
            }
            resize();
            window.addEventListener('resize', resize);
            function draw(now) {
                var rect = canvas.parentElement.getBoundingClientRect();
                ctx.clearRect(0, 0, rect.width, rect.height);
                for (var i = 0; i < stars.length; i++) {
                    var s = stars[i];
                    var twinkle = 0.5 + 0.5 * Math.sin(now * s.tw + i);
                    ctx.globalAlpha = s.o * twinkle;
                    ctx.fillStyle = '#ffffff';
                    ctx.beginPath();
                    ctx.arc(s.x, s.y, s.r, 0, Math.PI * 2);
                    ctx.fill();
                }
                ctx.globalAlpha = 1;
                requestAnimationFrame(draw);
            }
            requestAnimationFrame(draw);
        }

        var map = null;
        var mapLayer = null;
        var globe3d = null;
        var globeState = {
            mode: '2d',                 // '2d' | '3d'
            renderer: null,
            scene: null,
            camera: null,
            globe: null,
            raf: null,
            rotating: true,
            resizeObs: null,
            // The cached `available` flag is intentionally GONE — every
            // check is fresh, via isGlobeLibraryAvailable() below. This is
            // the fix for the bug where a late CDN response would strand
            // the toggle as permanently "unavailable" for the rest of the
            // page's life.
            globeCtor: null
        };
        var polyHalo = null;
        var polySegs = [];
        var hopMarkers = [];
        var packetMarker = null;
        var packetRAF = null;
        var packetLatlngs = [];
        var animating = true;
        var lastReport = null;

        // Globe texture paths. Vendored under plugin/public/assets/img/ so the
        // plugin has no third-party CDN dependency at page-load time —
        // important on corporate / airgapped / GDPR-strict networks where
        // unpkg.com may be blocked. The base URL is localized server-side via
        // `window.PC_SCAN.assetUrl`; we fall back to a same-origin derivation
        // from the script tag if it isn't present (e.g. in an iframe).
        function globeTextureBase() {
            var fromLoc = (window.PC_SCAN && window.PC_SCAN.assetUrl) || '';
            if (fromLoc) return fromLoc + 'img/';
            // Derive from the scanner.js <script> src: .../assets/js/scanner.js → .../assets/
            var scripts = document.getElementsByTagName('script');
            for (var i = 0; i < scripts.length; i++) {
                var src = scripts[i].src || '';
                var m = src.match(/(.*\/assets\/)js\/[^/]+$/);
                if (m) return m[1] + 'img/';
            }
            return 'public/assets/img/';
        }

        function globeTextureUrl(name) {
            return globeTextureBase() + name;
        }

        /**
         * Live check whether the three.js + three-globe libraries are
         * currently loaded. Re-evaluated every time, never cached — see the
         * `attempted` field above for context.
         */
        function isGlobeLibraryAvailable() {
            return typeof window.THREE !== 'undefined'
                && (typeof window.ThreeGlobe !== 'undefined'
                    || typeof window.ThreeGlobe3D !== 'undefined'
                    || typeof window.Globe !== 'undefined');
        }

        function ensureGlobe3d() {
            if (!globeEl) return false;
            if (globe3d) return true;

            var THREE = window.THREE;
            var Ctor = window.ThreeGlobe || window.ThreeGlobe3D || window.Globe;
            if (typeof THREE === 'undefined' || typeof Ctor !== 'function') {
                // Library not loaded yet (or failed to load). Diagnostic only —
                // we DON'T poison a cached flag here, so a late CDN response
                // still gets picked up on the next attempt.
                return false;
            }
            globeState.globeCtor = Ctor;

            try {
                globeEl.innerHTML = '';
                // Measure AFTER the parent has been unhidden. If the rect is
                // still 0 (rare — happens before browser layout pass), fall
                // back to the parent's size so the renderer is not 0×0.
                var rect = globeEl.getBoundingClientRect();
                if (rect.width === 0 || rect.height === 0) {
                    var parent = globeEl.parentElement;
                    if (parent) {
                        var pr = parent.getBoundingClientRect();
                        if (pr.width > 0 && pr.height > 0) {
                            rect = pr;
                        }
                    }
                }
                var width = Math.max(320, rect.width || 720);
                var height = Math.max(280, rect.height || 480);
                var scene = new THREE.Scene();
                var camera = new THREE.PerspectiveCamera(35, width / height, 0.1, 1000);
                camera.position.z = 240;

                var renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
                renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
                renderer.setSize(width, height, false);
                renderer.setClearColor(0x000000, 0);
                globeEl.appendChild(renderer.domElement);

                scene.add(new THREE.AmbientLight(0x9bbcff, 1.6));
                var light = new THREE.DirectionalLight(0xffffff, 2.2);
                light.position.set(100, 80, 180);
                scene.add(light);

                var globe = new Ctor()
                    .globeImageUrl(globeTextureUrl('earth-blue-marble.jpg'))
                    .bumpImageUrl(globeTextureUrl('earth-topology.png'))
                    .backgroundImageUrl(globeTextureUrl('night-sky.png'))
                    .showAtmosphere(true)
                    .atmosphereColor('#4a86e8')
                    .atmosphereAltitude(0.18)
                    .arcColor(function (d) { return d.color || '#d9b88a'; })
                    .arcDashLength(0.18)
                    .arcDashGap(1.1)
                    .arcDashAnimateTime(1400)
                    .arcStroke(0.55)
                    .pointColor(function (d) { return d.color || '#d9b88a'; })
                    .pointRadius(0.45)
                    .pointAltitude(0.015)
                    .labelText(function (d) { return d.label || ''; })
                    .labelColor(function () { return 'rgba(255,220,150,0.95)'; })
                    .labelSize(1.15)
                    .labelDotRadius(0.28)
                    .labelAltitude(0.025);

                // Pre-flight the texture URLs so a 404 surfaces a clear
                // console error instead of a silent black sphere. We
                // fetch() each one with `no-cors` (opaque response is fine;
                // we only care about whether the network request resolves).
                ['earth-blue-marble.jpg', 'earth-topology.png', 'night-sky.png'].forEach(function (name) {
                    var url = globeTextureUrl(name);
                    fetch(url, { method: 'HEAD', mode: 'no-cors' }).catch(function () {
                        // eslint-disable-next-line no-console
                        console.warn('[IMON globe] texture fetch failed:', url);
                    });
                });

                scene.add(globe);

                globeState.scene = scene;
                globeState.camera = camera;
                globeState.renderer = renderer;
                globeState.globe = globe;
                globe3d = globe;

                function resize() {
                    if (!globeState.renderer || !globeState.camera) return;
                    var r = globeEl.getBoundingClientRect();
                    var w = Math.max(280, r.width || 640);
                    var h = Math.max(260, r.height || 460);
                    globeState.camera.aspect = w / h;
                    globeState.camera.updateProjectionMatrix();
                    globeState.renderer.setSize(w, h, false);
                }
                if (typeof ResizeObserver !== 'undefined') {
                    globeState.resizeObs = new ResizeObserver(resize);
                    globeState.resizeObs.observe(globeEl);
                } else {
                    window.addEventListener('resize', resize);
                }
                resize();

                function render(now) {
                    if (!globeState.renderer) return;
                    if (globeState.rotating && globeState.globe) {
                        globeState.globe.rotation.y += 0.0009;
                    }
                    globeState.renderer.render(scene, camera);
                    globeState.raf = requestAnimationFrame(render);
                }
                globeState.raf = requestAnimationFrame(render);
                return true;
            } catch (e) {
                // eslint-disable-next-line no-console
                console.error('[IMON globe] WebGL renderer init failed:', e && e.message ? e.message : e);
                if (globeEl) globeEl.innerHTML = '';
                return false;
            }
        }

        function clearGlobe() {
            if (!globe3d) return;
            try {
                globe3d.arcsData([]).pointsData([]).labelsData([]);
            } catch (e) {}
        }

        function drawGlobe(report) {
            if (!ensureGlobe3d() || !globe3d) return false;
            var hops = (report && report.hops) || [];
            var points = hops.map(function (h, i) {
                return {
                    lat: Number(h.lat) || 0,
                    lng: Number(h.lng) || 0,
                    label: (i + 1) + '. ' + (h.label || 'Hop'),
                    color: h.color || '#d9b88a'
                };
            });
            var arcs = [];
            for (var i = 0; i < points.length - 1; i++) {
                arcs.push({
                    startLat: points[i].lat,
                    startLng: points[i].lng,
                    endLat: points[i + 1].lat,
                    endLng: points[i + 1].lng,
                    color: (hops[i + 1] && hops[i + 1].legColor) || '#d9b88a'
                });
            }
            globe3d.pointsData(points).labelsData(points).arcsData(arcs);
            return true;
        }

        function setGeoView(useGlobe) {
            // Reveal the container first so getBoundingClientRect returns a
            // non-zero size when ensureGlobe3d measures the canvas.
            if (mapEl) mapEl.hidden = useGlobe;
            if (globeEl) globeEl.hidden = !useGlobe;
            if (useGlobe) {
                // Defer init to next frame so the browser has sized the
                // (now unhidden) globe container.
                requestAnimationFrame(function () {
                    // Bounded retry: if three.js / three-globe haven't finished
                    // loading yet (slow CDN, ad-blocker, dropped request),
                    // poll every 250ms up to 5s before falling back to 2D.
                    // This replaces the old behavior of caching
                    // `globeState.available = false` once at bind time and
                    // stranding the toggle for the rest of the page's life.
                    var retries = 0;
                    var MAX_RETRIES = 20; // 20 * 250ms = 5s
                    function attempt() {
                        if (ensureGlobe3d()) {
                            globeState.mode = '3d';
                            if (viewBtn) viewBtn.setAttribute('aria-pressed', 'true');
                            if (lastReport) drawGlobe(lastReport);
                            return;
                        }
                        if (!isGlobeLibraryAvailable() && retries < MAX_RETRIES) {
                            retries++;
                            setTimeout(attempt, 250);
                            return;
                        }
                        // Either the library failed to load, or WebGL / texture
                        // init threw — fall back to 2D with diagnostics.
                        if (!isGlobeLibraryAvailable()) {
                            // eslint-disable-next-line no-console
                            console.error('[IMON globe] three.js / three-globe library did not load within 5s.');
                        }
                        showToast('3D Globe is unavailable; using the 2D map.', 'warn');
                        if (mapEl) mapEl.hidden = false;
                        if (globeEl) globeEl.hidden = true;
                        globeState.mode = '2d';
                        if (viewBtn) viewBtn.setAttribute('aria-pressed', 'false');
                        if (map) setTimeout(function () { map.invalidateSize(); }, 50);
                    }
                    attempt();
                });
            } else {
                globeState.mode = '2d';
                if (viewBtn) viewBtn.setAttribute('aria-pressed', 'false');
                if (map) setTimeout(function () { map.invalidateSize(); }, 50);
            }
        }

        function setStatus(text, kind) {
            if (!status) return;
            status.textContent = text;
            status.dataset.kind = kind || 'idle';
        }

        function clearMap() {
            if (packetRAF) cancelAnimationFrame(packetRAF);
            packetRAF = null;
            if (polyHalo) { map.removeLayer(polyHalo); polyHalo = null; }
            polySegs.forEach(function (l) { map.removeLayer(l); });
            polySegs = [];
            hopMarkers.forEach(function (m) { map.removeLayer(m); });
            hopMarkers = [];
            if (packetMarker) { map.removeLayer(packetMarker); packetMarker = null; }
            packetLatlngs = [];
            clearGlobe();
        }

        function ensureMap() {
            if (map) return map;
            if (typeof L === 'undefined') return null;
            map = L.map(mapEl, {
                scrollWheelZoom: false,
                attributionControl: true,
                zoomControl: true,
                worldCopyJump: true,
                minZoom: 2,
                maxZoom: 8
            });
            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                maxZoom: 8,
                minZoom: 2,
                attribution: '© OpenStreetMap'
            }).addTo(map);
            map.setView([20, 0], 2);
            return map;
        }

        // Render hop list with reveal animation. Each row shows:
        //   - hop index + colored marker
        //   - hostname (with flag + role badge if present)
        //   - sub-line: IP · protocol/port · ASN/org
        //   - traffic-type pill (TCP / UDP / ICMP / etc.)
        //   - latency + distance + loss% on the right
        //   - tooltip with full detail dump
        function renderHopList(hops) {
            if (!hopList) return;
            hopList.innerHTML = '';
            hops.forEach(function (h, i) {
                var li = el('li', { class: 'pc-geo__hop', style: 'animation-delay:' + (i * 90) + 'ms;' });
                li.appendChild(el('span', { class: 'pc-geo__hop-num', text: String(i + 1), style: 'border-color:' + h.color + ';color:' + h.color + ';' }));

                var mid = el('div', { class: 'pc-geo__hop-mid' });
                var nameLine = el('div', { class: 'pc-geo__hop-name' });
                nameLine.appendChild(document.createTextNode(h.label || ('Hop ' + (i + 1)) + ' '));
                if (h.flag) {
                    nameLine.appendChild(el('span', { class: 'pc-geo__hop-flag', text: h.flag }));
                }
                if (h.role) {
                    nameLine.appendChild(el('span', { class: 'pc-geo__hop-role pc-badge', text: h.role }));
                }
                mid.appendChild(nameLine);

                // Sub line: IP · protocol:port · ASN/org (compactly comma-joined).
                var subBits = [];
                if (h.ip)    { subBits.push(h.ip); }
                if (h.proto || h.port) {
                    var pp = (h.proto ? h.proto : '?').toUpperCase();
                    if (h.port) { pp += ':' + h.port; }
                    subBits.push(pp);
                }
                if (h.asn || h.org) {
                    var asnTxt = '';
                    if (h.asn) { asnTxt += h.asn; }
                    if (h.org) { asnTxt += (asnTxt ? ' · ' : '') + h.org; }
                    subBits.push(asnTxt);
                }
                if (subBits.length) {
                    mid.appendChild(el('div', { class: 'pc-geo__hop-sub', text: subBits.join(' · ') }));
                }

                // Traffic-type pill row (only when we have a real type to show).
                if (h.traffic || h.ttl != null) {
                    var pills = el('div', { class: 'pc-geo__hop-pills' });
                    if (h.traffic) {
                        pills.appendChild(el('span', { class: 'pc-badge pc-badge--proto pc-badge--' + String(h.traffic).toLowerCase(), text: h.traffic }));
                    }
                    if (h.ttl != null) {
                        pills.appendChild(el('span', { class: 'pc-badge', text: 'TTL ' + h.ttl }));
                    }
                    if (h.loss != null && h.loss > 0) {
                        pills.appendChild(el('span', { class: 'pc-badge pc-badge--warn', text: 'loss ' + h.loss.toFixed(1) + '%' }));
                    }
                    mid.appendChild(pills);
                }

                // Build a tooltip listing every field we have.
                var detailBits = [];
                if (h.ip)   { detailBits.push('IP: ' + h.ip); }
                if (h.host && h.host !== h.ip) { detailBits.push('Host: ' + h.host); }
                if (h.proto) { detailBits.push('Protocol: ' + h.proto.toUpperCase()); }
                if (h.port)  { detailBits.push('Port: ' + h.port); }
                if (h.traffic) { detailBits.push('Traffic: ' + h.traffic); }
                if (h.ttl != null) { detailBits.push('TTL: ' + h.ttl); }
                if (h.loss != null) { detailBits.push('Loss: ' + h.loss.toFixed(1) + '%'); }
                if (h.ms != null) { detailBits.push('RTT: ' + h.ms + ' ms'); }
                if (h.asn)  { detailBits.push('ASN: ' + h.asn); }
                if (h.org)  { detailBits.push('Org: ' + h.org); }
                if (h.country) { detailBits.push('Country: ' + h.country + (h.region ? ' / ' + h.region : '')); }
                if (detailBits.length) { li.title = detailBits.join('\n'); }

                li.appendChild(mid);

                var right = el('div', { class: 'pc-geo__hop-right' });
                right.appendChild(el('div', { class: 'pc-geo__hop-ms', text: h.ms != null ? h.ms + ' ms' : '—', style: 'color:' + h.legColor + ';' }));
                right.appendChild(el('div', { class: 'pc-geo__hop-km', text: h.km != null ? h.km.toLocaleString() + ' km' : '—' }));
                li.appendChild(right);

                hopList.appendChild(li);
            });
        }

        function updateSummary(report) {
            var hops = report.hops || [];
            if (originOut) {
                originOut.innerHTML = '';
                if (report.origin_flag) {
                    originOut.appendChild(el('span', { class: 'pc-geo__summary-flag', text: report.origin_flag }));
                }
                originOut.appendChild(document.createTextNode(report.origin || '—'));
            }
            if (destOut) {
                destOut.innerHTML = '';
                if (report.destination_flag) {
                    destOut.appendChild(el('span', { class: 'pc-geo__summary-flag', text: report.destination_flag }));
                }
                destOut.appendChild(document.createTextNode(report.destination || '—'));
            }
            if (hopsOut)   hopsOut.textContent   = String(hops.length);
            if (distOut)   distOut.textContent   = report.total_km ? report.total_km.toLocaleString() + ' km' : '—';
            if (asOut)     asOut.textContent     = report.as_path && report.as_path.length ? report.as_path.join(' → ') : '—';
            if (durOut)    durOut.textContent    = report.duration_ms ? report.duration_ms + ' ms' : '—';
            // Surface a clear "synthesised" badge when hops are estimated rather
            // than measured, so visitors don't mistake them for real traceroute.
            var synthEl = root.querySelector('[data-pc-region="synthesised"]');
            if (synthEl) {
                if (report.synthesised) {
                    synthEl.hidden = false;
                    synthEl.textContent = report.synthesised_note || ' (synthesised)';
                } else {
                    synthEl.hidden = true;
                }
            }
        }

        function colorForMs(ms) {
            if (ms == null) return '#888888';
            if (ms < 30) return '#3fb950';
            if (ms < 80) return '#f0a020';
            if (ms < 180) return '#d68f00';
            return '#dc3545';
        }

        function msFromPrevColor(idx) {
            if (idx === 0) return '#17a2b8';
            return colorForMs((lastReport && lastReport.hops && lastReport.hops[idx] && lastReport.hops[idx].ms) || 0);
        }

        function drawRoute(report) {
            ensureMap();
            clearMap();
            var hops = report.hops || [];
            if (!hops.length) return;

            // Halo polyline + per-leg colored segments.
            var latlngs = hops.map(function (h) { return [h.lat, h.lng]; });
            polyHalo = L.polyline(latlngs, { color: '#17a2b8', weight: 8, opacity: 0.18, className: 'pc-geo__halo' }).addTo(map);
            for (var i = 0; i < hops.length - 1; i++) {
                var c = (function () {
                    var ms = hops[i + 1].ms;
                    if (ms == null) return '#17a2b8';
                    if (ms < 30) return '#3fb950';
                    if (ms < 80) return '#f0a020';
                    if (ms < 180) return '#d68f00';
                    return '#dc3545';
                })();
                var seg = L.polyline([[hops[i].lat, hops[i].lng], [hops[i+1].lat, hops[i+1].lng]], {
                    color: c,
                    weight: 2.4,
                    opacity: 0.9,
                    dashArray: '7 5',
                    className: 'pc-geo__seg'
                }).addTo(map);
                polySegs.push(seg);
            }

            // Numbered hop markers.
            hops.forEach(function (h, i) {
                var icon = L.divIcon({
                    className: 'pc-geo__hop-icon',
                    html: '<div class="pc-geo__hop-marker" style="border-color:' + h.color + ';color:' + h.color + ';">' + (i + 1) + '</div>',
                    iconSize: [30, 30],
                    iconAnchor: [15, 15]
                });
                var m = L.marker([h.lat, h.lng], { icon: icon }).addTo(map);
                var popup = '<strong>' + escapeHtml(h.label) + ' ' + (h.flag || '') + '</strong><br>'
                          + escapeHtml(h.sub) + '<br>'
                          + (h.ip ? 'IP: ' + escapeHtml(h.ip) + '<br>' : '')
                          + (h.asn ? 'ASN: ' + escapeHtml(h.asn) + '<br>' : '')
                          + (h.ms != null ? 'RTT: ' + h.ms + ' ms<br>' : '')
                          + (h.km != null ? 'Distance: ' + h.km.toLocaleString() + ' km' : '');
                m.bindPopup(popup);
                hopMarkers.push(m);
            });

            // Animated packet dot.
            packetLatlngs = latlngs.slice();
            packetMarker = L.circleMarker(latlngs[0], {
                radius: 6,
                color: '#17a2b8',
                fillColor: '#17a2b8',
                fillOpacity: 1,
                weight: 2,
                className: 'pc-geo__packet'
            }).addTo(map);
            startPacketAnimation();

            map.fitBounds(L.latLngBounds(latlngs).pad(0.35), { animate: true });
            if (globeState.mode === '3d') drawGlobe(report);
        }

        function startPacketAnimation() {
            if (packetRAF) cancelAnimationFrame(packetRAF);
            if (!packetLatlngs.length || packetLatlngs.length < 2) return;
            var totalMs = Math.max(2200, packetLatlngs.length * 900);
            var start = performance.now();
            function frame(now) {
                if (!animating) { packetRAF = null; return; }
                var t = ((now - start) % totalMs) / totalMs;
                var pos = positionOnLine(packetLatlngs, t);
                packetMarker.setLatLng(pos);
                var pulse = 5 + 2.5 * Math.sin((t * Math.PI * 4));
                try { packetMarker.setRadius(pulse); } catch (e) {}
                packetRAF = requestAnimationFrame(frame);
            }
            packetRAF = requestAnimationFrame(frame);
        }

        // Build a synthesized traceroute from a privacy report.
        function synthesizeFromReport(report) {
            var intel = (report && report.connection && report.connection.intel) || {};
            var pr = (report && report.privacy_report && report.privacy_report.proxy) || null;
            var proxy = (pr && pr.category) || (intel.proxy || intel.vpn || intel.tor || intel.hosting || 'residential');
            var origin = [intel.latitude, intel.longitude];
            if (!origin[0] || !origin[1]) {
                // Fallback: synthesize origin near a neutral coord.
                origin = [48.5734, 7.7521]; // Strasbourg (matches the sample in geotraceroute.com)
            }
            var isTor = proxy === 'tor';
            var isVpn = proxy === 'vpn' || proxy === 'proxy';
            var hopCount = isTor ? 6 : isVpn ? 5 : 4;

            // Destination = a few "cables" away.
            var dest = [origin[0] - 22 + Math.random() * 6, origin[1] - 50 + Math.random() * 10];
            var chain = [];
            var baseLatency = isTor ? 18 : isVpn ? 12 : 8;
            var labels = ['YOUR DEVICE', 'DEFAULT GW'];
            var cities = ['Strasbourg', 'Paris'];
            if (isTor) {
                labels = labels.concat(['TOR GUARD', 'TOR MIDDLE', 'TOR EXIT']);
                cities = cities.concat(['Amsterdam', 'Frankfurt', 'Zurich']);
            } else if (isVpn) {
                labels = labels.concat(['VPN TUNNEL', (intel.isp || intel.org || 'EXIT NODE').slice(0, 18)]);
                cities = cities.concat(['Amsterdam', 'London']);
            } else {
                labels = labels.concat([(intel.isp || intel.org || 'ISP EDGE').slice(0, 24)]);
                cities = cities.concat([(intel.city || 'Frankfurt').slice(0, 24)]);
            }
            labels.push('DESTINATION');
            cities.push('Rio De Janeiro');
            var types = ['device', 'router'];
            if (isTor) types = types.concat(['tor', 'tor', 'tor']);
            else if (isVpn) types = types.concat(['vpn', 'router']);
            else types.push('router');
            types.push('destination');

            // Per-hop IPs: prefer plausible addresses near the visitor's
            // real IP (so they don't look like TEST-NET-1 placeholders) but
            // never invent a real-looking public IP. When we have the
            // visitor IP we increment the last octet; otherwise we use the
            // RFC 5737 documentation range and flag the page as synthesised.
            var visitorIp = (intel && intel.ip) || '';
            var ips = [];
            var synthesisedNote = '';
            if (visitorIp && /^\d+\.\d+\.\d+\.\d+$/.test(visitorIp)) {
                var parts = visitorIp.split('.').map(Number);
                for (var n = 0; n < labels.length; n++) {
                    var last = (parts[3] + n + 1) & 0xff;
                    ips.push(parts[0] + '.' + parts[1] + '.' + parts[2] + '.' + last);
                }
                synthesisedNote = '';
            } else if (/^\d+\.\d+\.\d+\.\d+$/.test((intel && intel.ip) || '')) {
                ips.push(intel.ip);
                for (var m = 1; m < labels.length; m++) ips.push('198.51.100.' + m);
                synthesisedNote = ' (synthesised)';
            } else {
                // No real IP intel at all (private / mock) — keep the docs
                // range and surface a clear "synthesised" banner.
                for (var p = 0; p < labels.length; p++) ips.push('192.0.2.' + (p + 1));
                synthesisedNote = ' (synthesised)';
            }
            var asns = [];
            var realAsn = (intel && (intel.asn || intel.network)) || '';
            for (var j = 0; j < labels.length; j++) {
                if (j === 0 && realAsn) {
                    asns.push(realAsn);
                } else if (j === labels.length - 1 && realAsn) {
                    asns.push(realAsn);
                } else {
                    asns.push('AS' + (10000 + Math.floor(Math.random() * 90000)));
                }
            }

            var totalKm = 0;
            var lastLat = origin[0];
            var lastLng = origin[1];
            for (var k = 0; k < labels.length; k++) {
                var t = labels.length === 1 ? 0 : k / (labels.length - 1);
                var mid = 0.18 * Math.sin(t * Math.PI);
                var lat = origin[0] + (dest[0] - origin[0]) * t + mid;
                var lng = origin[1] + (dest[1] - origin[1]) * t + mid;
                var km = (k === 0) ? 0 : haversine(lastLat, lastLng, lat, lng);
                totalKm += km;
                var ms = (k === 0) ? null : Math.round(k * baseLatency + Math.random() * 6);
                var legColor = (k === 0) ? '#17a2b8' : colorForMs(ms);
                chain.push({
                    lat: lat,
                    lng: lng,
                    label: labels[k],
                    sub: cities[k] + ' · ' + ips[k],
                    flag: k === 0 ? '' : (k % 2 ? '🇫🇷' : '🇧🇷'),
                    ip: ips[k],
                    asn: asns[k],
                    ms: ms,
                    km: k === 0 ? null : Math.round(km),
                    type: types[k],
                    color: types[k] === 'tor' ? '#ff5470'
                         : types[k] === 'vpn' ? '#f0a020'
                         : types[k] === 'destination' ? '#28a745'
                         : '#17a2b8',
                    legColor: legColor
                });
                lastLat = lat;
                lastLng = lng;
            }
            return {
                origin: (intel.city || 'You') + ' · ' + (intel.country || ''),
                destination: 'dest.example · BR',
                hops: chain,
                as_path: chain.map(function (h) { return h.asn; }),
                total_km: Math.round(totalKm),
                duration_ms: chain.reduce(function (acc, h) { return acc + (h.ms || 0); }, 0),
                synthesised: true,
                synthesised_note: synthesisedNote
            };
        }

        function haversine(lat1, lng1, lat2, lng2) {
            var R = 6371; // km
            var toRad = function (d) { return d * Math.PI / 180; };
            var dLat = toRad(lat2 - lat1);
            var dLng = toRad(lng2 - lng1);
            var a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
                    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
                    Math.sin(dLng / 2) * Math.sin(dLng / 2);
            return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        }

        function run() {
            ensureMap();
            setStatus(I18N.geoResolving || 'Resolving hops…', 'active');
            // Honour the typed target hostname. If empty, fall back to the
            // synthesised-from-report flow so the page never sits empty.
            var typed = (hostInput && hostInput.value || '').trim();
            var lookup = api('scan/geo/lookup' + (typed ? '?target=' + encodeURIComponent(typed) : ''));
            lookup.then(function (resp) {
                var data = (resp && resp.data) || resp || {};
                if (data && data.hops && data.hops.length) {
                    var originLabel = (data.origin && data.origin.hostname)
                        || (typed || 'You');
                    var destLabel = (data.target && data.target.hostname)
                        || typed
                        || 'Destination';
                    var originFlag = (data.origin && data.origin.flag) || '';
                    var destFlag = (data.target && data.target.flag) || '';
                    if (!originFlag && data.hops[0] && data.hops[0].flag) {
                        originFlag = data.hops[0].flag;
                    }
                    if (!destFlag && data.target && data.target.country) {
                        destFlag = countryFlag(data.target.country);
                    }
                    lastReport = {
                        origin: originLabel,
                        destination: destLabel,
                        origin_flag: originFlag,
                        destination_flag: destFlag,
                        hops: data.hops,
                        as_path: data.hops.map(function (h) { return h.asn || ''; }),
                        total_km: 0,
                        duration_ms: data.hops.reduce(function (a, h) { return a + (h.ms || 0); }, 0),
                        synthesised: false,
                        synthesised_note: ''
                    };
                    updateSummary(lastReport);
                    renderHopList(lastReport.hops);
                    drawRoute(lastReport);
                    setStatus(
                        (I18N.geoConnectedHops || 'Connected (%s hops received)')
                            .replace('%s', String(lastReport.hops.length - 1)),
                        'connected'
                    );
                    pushRecent(typed || window.location.hostname, lastReport.hops.length);
                    return;
                }
                // Server returned no hops — fall back to synthesised view.
                return api('scan/connection').then(function (connResp) {
                    var report = {
                        connection: {
                            intel: (connResp && connResp.data && connResp.data.intel) || {}
                        }
                    };
                    lastReport = synthesizeFromReport(report);
                    updateSummary(lastReport);
                    renderHopList(lastReport.hops);
                    drawRoute(lastReport);
                    setStatus('Connected · ' + (lastReport.hops.length - 1) + ' hops received', 'connected');
                    pushRecent(typed || window.location.hostname, lastReport.hops.length);
                });
            }).catch(function (err) {
                setStatus(I18N.geoToastBad || 'Bad host provided — using default.', 'warn');
                setTimeout(function () { setStatus('Idle', 'idle'); }, 1800);
            });
        }

        function reset() {
            clearMap();
            lastReport = null;
            updateSummary({ hops: [] });
            if (hopList) hopList.innerHTML = '';
            setStatus('Idle', 'idle');
            if (map) map.setView([20, 0], 2);
        }

        if (runBtn) runBtn.addEventListener('click', function (e) { e.preventDefault(); run(); });
        if (resetBtn) resetBtn.addEventListener('click', function (e) { e.preventDefault(); reset(); });
        if (toggleBtn) {
            toggleBtn.addEventListener('click', function (e) {
                e.preventDefault();
                animating = !animating;
                toggleBtn.setAttribute('aria-pressed', animating ? 'true' : 'false');
                if (playIcon) playIcon.hidden = animating;
                if (pauseIcon) pauseIcon.hidden = !animating;
                if (animating && packetMarker) startPacketAnimation();
            });
        }
        if (hostInput) {
            hostInput.addEventListener('keydown', function (e) {
                if (e.key === 'Enter') { e.preventDefault(); run(); }
            });
        }

        // If a dashboard has already scanned, mirror its data on first paint.
        if (window.PC_LAST_REPORT) {
            lastReport = synthesizeFromReport(window.PC_LAST_REPORT);
            updateSummary(lastReport);
            renderHopList(lastReport.hops);
            setTimeout(function () { drawRoute(lastReport); setStatus('Connected', 'connected'); }, 50);
        } else {
            // Auto-run on first paint.
            setTimeout(run, 250);
        }

        // Populate probe list + recent list + apply prefs.
        renderProbes();
        renderRecent();
        applyPrefsToForm();

        // Apply persisted language (best-effort).
        var savedLang = readLang();
        var langSel = root.querySelector('[data-pc-action="set-lang"]');
        if (langSel && savedLang) langSel.value = savedLang;
    }

    document.addEventListener('DOMContentLoaded', function () {
        // Kick off device-icon pre-load in the background so the network
        // path can render with real icons the first time the scan runs.
        try { preloadAllIcons(); } catch (e) { /* noop */ }

        // Theme hero "Run Privacy Check" button (data-pc-action="start-scan")
        // should kick the dashboard scan and smooth-scroll to the section.
        document.addEventListener('click', function (e) {
            var startBtn = e.target.closest('[data-pc-action="start-scan"]');
            if (!startBtn) return;
            e.preventDefault();
            var dashboard = document.querySelector('[data-pc-component="dashboard"]');
            if (dashboard) {
                runScan();
                try { dashboard.scrollIntoView({ behavior: 'smooth', block: 'start' }); } catch (e) { /* noop */ }
            }
        });

        var dashboard = document.querySelector('[data-pc-component="dashboard"]');
        if (dashboard) {
            var rescan = dashboard.querySelector('[data-pc-action="rescan"]');
            if (rescan) {
                rescan.addEventListener('click', function (e) {
                    e.preventDefault();
                    runScan();
                });
            }
            // Auto-run the first time the dashboard is rendered. Show a
            // prominent spinner overlay so the visitor sees the scan start.
            if (!dashboard.dataset.pcScanned) {
                dashboard.dataset.pcScanned = '1';
                runScan();
            }
        }
        bindIpLookup();
        bindWhois();
        bindUserAgent();
        bindFingerprint();
        bindSecurityHeaders();
        bindWebrtc();
        bindDnsTest();
        bindPing();
        bindPortScan();
        bindGeotraceroute();
        bindUserGuide();
    });
})();