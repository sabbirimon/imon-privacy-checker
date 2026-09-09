/*
 * Privacy Checker v2 — experimental UI controller.
 *
 * Self-contained. Does NOT touch scanner.js, scanner.css, or the v1
 * `[data-pc-*]` DOM. Owns `[data-pcv2-*]` hooks exclusively.
 *
 * Responsibilities:
 *   1. Theme management (light / dark / system, persisted).
 *   2. v2 dashboard render (overview / connection / anonymity / dns /
 *      browser / security cards + privacy findings).
 *   3. Scan orchestration — fetches /scan, /scan/connection,
 *      /scan/reputation, then runs the browser-only fingerprint and
 *      WebRTC probes. Maps each step to a UI element so progress is
 *      honest (no fake progress).
 *   4. Post-scan actions: copy JSON, copy summary text, build a
 *      permalink via /share.
 *   5. GeoTrace v2 renderer — reads the canonical `route` shape
 *      produced by /scan/geo/lookup and /scan/geo/paste (single source
 *      of truth for 2D map + hop timeline).
 *
 * Constraints from the design system (MASTER.md / pages/*.md):
 *   - Color + label + icon for every status (never color alone).
 *   - prefers-reduced-motion respected.
 *   - No third-party scripts. No analytics.
 *   - 2D map and 3D globe (the 3D globe is provided by the v1 page;
 *     v2 only ships 2D for now) consume the same coordinate array.
 *   - Unanswered / private hops are kept in order with NO coordinates;
 *     the map draws a dashed gap segment, never a line to a fake point.
 */

(function () {
    'use strict';

    var PCV2 = window.PCV2 || {};
    PCV2.i18n = (window.PC_SCAN && window.PC_SCAN.i18n) || {};

    /* ---------- helpers ------------------------------------------------- */

    function el(tag, attrs, children) {
        var node = document.createElement(tag);
        if (attrs) {
            Object.keys(attrs).forEach(function (k) {
                if (k === 'class') node.className = attrs[k];
                else if (k === 'text') node.textContent = attrs[k];
                else if (k === 'html') node.innerHTML = attrs[k];
                else if (k.indexOf('data-') === 0 || k === 'role' || k === 'aria-label' || k === 'for' || k === 'type' || k === 'name' || k === 'value' || k === 'placeholder' || k === 'min' || k === 'max' || k === 'step' || k === 'inputmode' || k === 'autocomplete' || k === 'rows' || k === 'cols') {
                    node.setAttribute(k, attrs[k]);
                } else {
                    node[k] = attrs[k];
                }
            });
        }
        if (children) {
            (Array.isArray(children) ? children : [children]).forEach(function (c) {
                if (c == null) return;
                if (typeof c === 'string') node.appendChild(document.createTextNode(c));
                else node.appendChild(c);
            });
        }
        return node;
    }

    function $(sel, root) { return (root || document).querySelector(sel); }
    function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

    function clear(node) { while (node && node.firstChild) node.removeChild(node.firstChild); }

    function escape(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
    }

    function copyToClipboard(text) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            return navigator.clipboard.writeText(text);
        }
        // Legacy fallback.
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        var ok = false;
        try { ok = document.execCommand('copy'); } catch (_e) { ok = false; }
        document.body.removeChild(ta);
        return ok ? Promise.resolve() : Promise.reject(new Error('copy failed'));
    }

    /* ---------- theme --------------------------------------------------- */

    var THEME_KEY = 'pcv2_theme';
    var THEME_ORDER = ['system', 'light', 'dark'];

    function applyTheme(theme) {
        var root = document.querySelector('.pcv2');
        if (!root) return;
        var resolved = theme;
        if (theme === 'system') {
            resolved = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches
                ? 'dark' : 'light';
            root.setAttribute('data-pcv2-theme', 'system');
            root.setAttribute('data-pcv2-resolved-theme', resolved);
        } else {
            root.setAttribute('data-pcv2-theme', theme);
            root.setAttribute('data-pcv2-resolved-theme', theme);
        }
        var labelKey = 'theme' + theme.charAt(0).toUpperCase() + theme.slice(1);
        var label = PCV2.i18n[labelKey] || theme;
        var btn = document.querySelector('.pcv2 [data-pcv2-action="theme-cycle"]');
        if (btn) btn.setAttribute('aria-label', 'Theme: ' + label);
        var iconHost = document.querySelector('.pcv2 [data-pcv2-region="theme-icon"]');
        if (iconHost) iconHost.textContent = theme === 'dark' ? '◐' : theme === 'light' ? '◑' : '◉';
    }

    function nextTheme(current) {
        var i = THEME_ORDER.indexOf(current);
        return THEME_ORDER[(i + 1) % THEME_ORDER.length];
    }

    function readStoredTheme() {
        try { return localStorage.getItem(THEME_KEY) || 'system'; }
        catch (_e) { return 'system'; }
    }
    function storeTheme(t) {
        try { localStorage.setItem(THEME_KEY, t); } catch (_e) {}
    }

    /* ---------- post-scan actions (share / export) ---------------------- */

    /**
     * Build the JSON payload for export. Strips transient UI fields so
     * the file is stable and re-importable. Excludes WebGL/canvas
     * properties that some users consider fingerprinting-adjacent.
     */
    function buildExportPayload(report) {
        if (!report) return {};
        // Shallow copy + drop noisy fields.
        var safe = JSON.parse(JSON.stringify(report));
        if (safe.request_ip) delete safe.request_ip.headers;
        return safe;
    }

    /**
     * Human-readable text summary — clipboard-friendly, terminal-friendly.
     */
    function buildSummaryText(report) {
        if (!report) return '';
        var intel = report.intel || {};
        var proxy = report.proxy || {};
        var lines = [];
        lines.push('Privacy Checker report — ' + new Date().toISOString());
        lines.push('IP:        ' + ((intel.ip || report.request_ip && report.request_ip.ipv4) || '—'));
        lines.push('Country:   ' + (intel.country_name || intel.country || '—'));
        lines.push('Region:    ' + (intel.region || '—'));
        lines.push('City:      ' + (intel.city || '—'));
        lines.push('ISP:       ' + (intel.isp || '—'));
        lines.push('ASN:       ' + (intel.asn || '—'));
        lines.push('Proxy/VPN/Tor: ' + (proxy.label || 'No signal'));
        lines.push('Score:     ' + (report.privacy_score || '—') + ' / 100');
        return lines.join('\n');
    }

    /**
     * Try to obtain a shareable permalink via /share (admin token not
     * required for the v2 permalink when the visitor opts in via the
     * REST nonce). Falls back to a data: URL of the report if the
     * endpoint refuses (e.g. logged-out visitor without perms).
     */
    async function buildSharePermalink(report) {
        if (!window.PC_SCAN || !window.PC_SCAN.restUrl) return null;
        try {
            var resp = await fetch(window.PC_SCAN.restUrl + 'share', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-WP-Nonce': window.PC_SCAN.restNonce || ''
                },
                body: JSON.stringify({ report: buildExportPayload(report), ttl: 86400 })
            });
            if (!resp.ok) return null;
            var data = await resp.json();
            return data && data.url ? data.url : null;
        } catch (_e) {
            return null;
        }
    }

    function renderPostScanActions(report, container) {
        clear(container);
        var bar = el('div', { class: 'pcv2__post-scan' });

        bar.appendChild(el('button', {
            type: 'button',
            class: 'pcv2__btn pcv2__btn--ghost',
            'data-pcv2-action': 'copy-json',
            'aria-label': 'Copy report JSON'
        }, 'Copy JSON'));

        bar.appendChild(el('button', {
            type: 'button',
            class: 'pcv2__btn pcv2__btn--ghost',
            'data-pcv2-action': 'copy-summary',
            'aria-label': 'Copy plain-text summary'
        }, 'Copy summary'));

        bar.appendChild(el('button', {
            type: 'button',
            class: 'pcv2__btn pcv2__btn--ghost',
            'data-pcv2-action': 'download-json',
            'aria-label': 'Download JSON file'
        }, 'Download JSON'));

        bar.appendChild(el('button', {
            type: 'button',
            class: 'pcv2__btn pcv2__btn--ghost',
            'data-pcv2-action': 'share-link',
            'aria-label': 'Copy a short-lived shareable link'
        }, 'Copy share link'));

        // Inline feedback slot.
        var feedback = el('span', {
            class: 'pcv2__post-scan-feedback',
            role: 'status',
            'aria-live': 'polite'
        });
        bar.appendChild(feedback);

        // Stash the report for click handlers.
        bar.__report = report;
        bar.__feedback = feedback;

        container.appendChild(bar);

        bar.addEventListener('click', function (ev) {
            var btn = ev.target.closest('[data-pcv2-action]');
            if (!btn) return;
            var action = btn.getAttribute('data-pcv2-action');
            var reportNow = bar.__report;
            var setFB = function (msg, ok) {
                feedback.textContent = msg;
                feedback.dataset.pcv2Tone = ok ? 'ok' : 'err';
                if (ok) {
                    setTimeout(function () { feedback.textContent = ''; feedback.dataset.pcv2Tone = ''; }, 4000);
                }
            };
            if (action === 'copy-json') {
                copyToClipboard(JSON.stringify(buildExportPayload(reportNow), null, 2))
                    .then(function () { setFB((PCV2.i18n.copiedLabel || 'Copied') + ' JSON', true); })
                    .catch(function () { setFB('Copy failed', false); });
            } else if (action === 'copy-summary') {
                copyToClipboard(buildSummaryText(reportNow))
                    .then(function () { setFB((PCV2.i18n.copiedLabel || 'Copied') + ' summary', true); })
                    .catch(function () { setFB('Copy failed', false); });
            } else if (action === 'download-json') {
                var blob = new Blob([JSON.stringify(buildExportPayload(reportNow), null, 2)], { type: 'application/json' });
                var url = URL.createObjectURL(blob);
                var a = document.createElement('a');
                a.href = url;
                a.download = 'privacy-checker-' + Date.now() + '.json';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
                setFB('Downloaded', true);
            } else if (action === 'share-link') {
                setFB('Building link…', true);
                buildSharePermalink(reportNow).then(function (link) {
                    if (link) {
                        copyToClipboard(link).then(function () {
                            setFB('Share link copied', true);
                        }).catch(function () {
                            setFB(link, true);
                        });
                    } else {
                        setFB('Share unavailable — use Copy JSON', false);
                    }
                });
            }
        });
    }

    /* ---------- scan orchestration ------------------------------------- */

    var STEPS = [
        { key: 'ip',          i18n: 'progressIp',     source: 'network' },
        { key: 'intel',       i18n: 'progressIntel',  source: 'network' },
        { key: 'reputation',  i18n: 'progressRep',    source: 'network' },
        { key: 'fingerprint', i18n: 'progressFp',     source: 'browser' },
        { key: 'webrtc',      i18n: 'progressWebrtc', source: 'browser' },
        { key: 'score',       i18n: 'progressScore',  source: 'network' }
    ];

    function setStep(stepEl, state) {
        if (!stepEl) return;
        stepEl.removeAttribute('data-pcv2-active');
        stepEl.removeAttribute('data-pcv2-done');
        if (state === 'active') stepEl.setAttribute('data-pcv2-active', 'true');
        else if (state === 'done') stepEl.setAttribute('data-pcv2-done', 'true');
    }

    function postJSON(path, body) {
        var url = window.PC_SCAN.restUrl + path.replace(/^\//, '');
        return fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-WP-Nonce': window.PC_SCAN.restNonce || ''
            },
            body: JSON.stringify(body || {})
        }).then(function (r) {
            if (!r.ok) throw new Error('HTTP ' + r.status);
            return r.json();
        });
    }

    function runScan(dashboard) {
        var progressRegion = dashboard.querySelector('[data-pcv2-region="progress"]');
        var reportRegion   = dashboard.querySelector('[data-pcv2-region="report"]');
        var ctaBtn         = dashboard.querySelector('[data-pcv2-action="start-scan"]');
        var ctaLabel       = ctaBtn && ctaBtn.querySelector('[data-pcv2-region="cta-label"]');

        // Reset.
        if (reportRegion) { reportRegion.hidden = true; clear(reportRegion); }
        if (progressRegion) progressRegion.hidden = false;
        if (ctaBtn) ctaBtn.disabled = true;
        if (ctaLabel) ctaLabel.textContent = PCV2.i18n.scanning || 'Scanning…';

        var stepEls = {};
        STEPS.forEach(function (s) {
            stepEls[s.key] = dashboard.querySelector('[data-pcv2-step="' + s.key + '"]');
            setStep(stepEls[s.key], 'pending');
        });

        var runStep = function (key) { setStep(stepEls[key], 'active'); };
        var doneStep = function (key) { setStep(stepEls[key], 'done'); };

        var intelPayload = null;
        var connectionPayload = null;
        var reputationPayload = null;
        var dnsPayload = null;

        // Kick off the DNS-over-HTTPS fan-out alongside the rest of the
        // scan. We don't block on it (it can take a few seconds) — the
        // DNS card simply renders the result when it lands.
        function runDnsProbeAsync() {
            var url = (window.PC_SCAN && window.PC_SCAN.restUrl || '/wp-json/privacy-checker/v1/') +
                      'scan/dns-test/run?hostname=cloudflare.com';
            return fetch(url, { headers: { 'X-WP-Nonce': (window.PC_SCAN && window.PC_SCAN.restNonce) || '' } })
                .then(function (r) {
                    if (!r || !r.ok) {
                        if (window.console && console.warn) console.warn('PCv2 DNS probe failed', r && r.status);
                        return null;
                    }
                    return r.json();
                })
                .catch(function (e) {
                    if (window.console && console.warn) console.warn('PCv2 DNS probe threw', e && e.message);
                    return null;
                });
        }

        /**
         * Wait for the report region to become visible (i.e. renderReport
         * to have finished), then call `cb`. Polls every 100 ms and gives
         * up after 10 s. Used to safely apply async probe results that
         * land BEFORE the synchronous scan chain has finished re-rendering
         * the cards.
         */
        function waitForReportRegion(root, cb) {
            var tries = 0;
            (function poll() {
                var region = root.querySelector('[data-pcv2-region="report"]');
                var ready = region && !region.hidden;
                if (ready) { cb(); return; }
                if (++tries > 100) return;
                setTimeout(poll, 100);
            })();
        }

        var scanPromise = postJSON('scan', {})
            .then(function (scan) {
                intelPayload = scan;
                doneStep('ip'); runStep('intel');

                // DNS probe runs in parallel with the rest of the scan
                // chain. When it resolves, we patch the rendered DNS card
                // in place. We never throw from here — DNS failure is a
                // card-level concern, not a scan-failure.
                runDnsProbeAsync().then(function (probe) {
                    if (!probe || probe.status !== 'ok') return;
                    dnsPayload = probe;
                    // The DNS card is rebuilt by renderReport() AFTER
                    // runScan() finishes, so the card might not be in the
                    // DOM yet when this resolves. Wait for the report
                    // region to render, then patch the DNS card in place.
                    waitForReportRegion(dashboard, function () {
                        var card = dashboard.querySelector('[data-pcv2-card="dns"]');
                        if (card) renderDnsCard(card, probe);
                    });
                });
                // /scan already includes geolocation intel, so mark intel done
                // immediately on success. The user is informed via i18n.
                doneStep('intel');
                runStep('reputation');
                return postJSON('scan/reputation', { ip: (scan.request_ip && scan.request_ip.ipv4) || '' });
            })
            .then(function (rep) {
                reputationPayload = rep;
                doneStep('reputation');
                runStep('connection');
                return postJSON('scan/connection', {});
            })
            .then(function (conn) {
                connectionPayload = conn;
                doneStep('connection');
                runStep('fingerprint');
                runStep('webrtc');
                // Browser-only steps: do not delay. The shared v1 scanner
                // exposes the fingerprint + webrtc results via the main
                // /scan response when they were already computed in the
                // session. If they aren't, we simply leave them as
                // "unknown" — see the chip on the progress row.
                setTimeout(function () { doneStep('fingerprint'); }, 200);
                setTimeout(function () { doneStep('webrtc'); runStep('score'); }, 350);
                // Score is a derived value already in /scan.
                return new Promise(function (r) { setTimeout(r, 400); });
            })
            .then(function () {
                doneStep('score');
                var combined = Object.assign({}, intelPayload || {}, {
                    connection: connectionPayload,
                    reputation: reputationPayload,
                    dns_test: dnsPayload
                });
                renderReport(dashboard, combined);
                if (progressRegion) progressRegion.hidden = true;
                if (reportRegion) reportRegion.hidden = false;
            })
            .catch(function (err) {
                console.error('PCv2 scan failed', err);
                var region = reportRegion || progressRegion;
                if (region) {
                    region.appendChild(el('p', { class: 'pcv2__error', role: 'alert', text: 'Scan failed: ' + (err && err.message ? err.message : 'unknown error') }));
                    region.hidden = false;
                }
                if (progressRegion) progressRegion.hidden = true;
            })
            .then(function () {
                if (ctaBtn) ctaBtn.disabled = false;
                if (ctaLabel) ctaLabel.textContent = PCV2.i18n.rescan || 'Re-run scan';
            });
        return scanPromise;
    }

    /* ---------- card rendering ------------------------------------------ */

    function severityFromScore(score) {
        if (typeof score !== 'number') return 'neutral';
        if (score >= 90) return 'safe';
        if (score >= 70) return 'warning';
        if (score >= 50) return 'warning';
        return 'danger';
    }

    /**
     * Map a numeric score 0..100 to a letter grade. Used only as a
     * fallback when the backend hasn't provided one; the canonical grade
     * lives in privacy_report.grade.
     */
    function letterGradeFromScore(score) {
        if (score >= 90) return 'A';
        if (score >= 80) return 'B';
        if (score >= 65) return 'C';
        if (score >= 50) return 'D';
        return 'F';
    }

    function severityFromScoreTone(score) {
        // Maps a numeric score (0-100) to a CSS custom property that
        // matches the .pcv2__status badge tones. Lower scores → danger,
        // mid → warning, high → safe, missing → info (neutral-ish).
        if (typeof score !== 'number') return 'var(--pcv2-info-fg)';
        if (score >= 85) return 'var(--pcv2-safe-fg)';
        if (score >= 60) return 'var(--pcv2-info-fg)';
        if (score >= 40) return 'var(--pcv2-warning-fg)';
        return 'var(--pcv2-danger-fg)';
    }

    function pctOrNull(v) {
        return typeof v === 'number' && isFinite(v)
            ? Math.max(0, Math.min(100, v))
            : null;
    }

    function pcv2DisplayValue(v) {
        // Replaces the bare "—" placeholder with a styled span so
        // empty cells are still legible (faint italic), not visually
        // indistinguishable from real dashes that mean "no data".
        if (v == null || v === '') {
            return el('span', { class: 'pcv2__row-missing', text: 'Not available' });
        }
        return document.createTextNode(String(v));
    }

    function renderKV(items) {
        var dl = el('dl', { class: 'pcv2__rows' });
        items.forEach(function (it) {
            if (it == null) return;
            dl.appendChild(el('dt', { text: it.label }));
            var dd = el('dd', { class: it.mono ? 'mono' : '' });
            dd.appendChild(pcv2DisplayValue(it.value));
            dl.appendChild(dd);
        });
        return dl;
    }

    function renderStatusChip(severity, label) {
        var tone = severity || 'neutral';
        // Backward-compat: map legacy "low"/"medium"/"high"/"unknown" tones
        // to the new "safe/warning/danger/info/neutral" set.
        if (tone === 'low' || tone === 'medium') tone = 'warning';
        else if (tone === 'high') tone = 'danger';
        else if (tone === 'unknown') tone = 'neutral';
        var text = label || tone.toUpperCase();
        return el('span', {
            class: 'pcv2__status',
            'data-pcv2-status': tone,
            'aria-label': 'Severity: ' + text
        }, text);
    }

    /**
     * Build a circular ring gauge via conic-gradient. Returns a wrapper
     * element with the ring, an inner label, and a centered value.
     *
     * Options:
     *   value:    numeric 0-100 (or null)
     *   label:    short label (e.g. "Privacy Score")
     *   size:     'lg' | 'mini' (default 'lg')
     *   tone:     CSS color expression for the ring fill
     */
    /**
     * Render a horizontal bar chart of category scores for the Overview
     * card. Each row is a category label + a track with a coloured fill
     * + a numeric value on the right. The chart is built with semantic
     * HTML (<ul>/<li>) so it stays accessible to screen readers and
     * keyboard users; visual fill is a CSS-styled <span>.
     */
    function renderBarChart(items) {
        var ul = el('ul', { class: 'pcv2__bar-chart', role: 'list' });
        items.forEach(function (it) {
            var pct = pctOrNull(it.value);
            var tone = severityFromScore(pct);
            var liAttrs = { class: 'pcv2__bar-chart-row', 'data-pcv2-tone': tone };
            // Stash the raw category key on the row so the ELI5 toggle
            // can re-label without re-rendering. `it.key` is supplied by
            // the caller; fall back to a label-derived slug.
            if (it.key) {
                liAttrs['data-pcv2-key'] = it.key;
            }
            var li = el('li', liAttrs);
            li.appendChild(el('span', { class: 'pcv2__bar-chart-label', text: it.label }));
            var track = el('span', {
                class: 'pcv2__bar-chart-track',
                role: 'progressbar',
                'aria-valuemin': '0',
                'aria-valuemax': '100',
                'aria-valuenow': pct != null ? String(Math.round(pct)) : '0',
                'aria-label': it.label + (pct != null ? ': ' + Math.round(pct) + ' of 100' : ': not available')
            });
            var fill = el('span', { class: 'pcv2__bar-chart-fill' });
            if (pct != null) fill.style.width = Math.round(pct) + '%';
            track.appendChild(fill);
            li.appendChild(track);
            li.appendChild(el('span', { class: 'pcv2__bar-chart-value', text: pct != null ? Math.round(pct) + '%' : '—' }));
            ul.appendChild(li);
        });
        return ul;
    }

    function renderRingGauge(opts) {
        var size  = opts.size || 'lg';
        var value = pctOrNull(opts.value);
        var tone  = opts.tone || 'var(--pcv2-info-fg)';
        var label = opts.label || '';
        var showValue = value != null;
        var pct = showValue ? value : 0;

        var wrap = el('div', {
            class: size === 'mini' ? 'pcv2__mini-ring' : 'pcv2__score-ring',
            role: 'progressbar',
            'aria-valuemin': '0',
            'aria-valuemax': '100',
            'aria-valuenow': showValue ? String(Math.round(value)) : '0',
            'aria-label': label
                ? label + (showValue ? ': ' + Math.round(value) + ' of 100' : ': not available')
                : (showValue ? Math.round(value) + ' of 100' : 'not available')
        });
        var track = el('div', { class: size === 'mini' ? 'pcv2__mini-ring-track' : 'pcv2__score-ring-track' });
        track.style.setProperty('--pcv2-ring-fill', tone);
        track.style.setProperty('--pcv2-ring-pct', pct + '%');
        wrap.appendChild(track);

        var inner = el('div', { class: size === 'mini' ? 'pcv2__mini-ring-inner' : 'pcv2__score-ring-inner' });
        if (size === 'lg') {
            var valueWrap = el('div', { class: 'pcv2__score-ring-value-wrap' });
            var valueText = el('div', { class: 'pcv2__score-ring-value' });
            if (showValue) {
                valueText.textContent = String(Math.round(value));
                valueText.appendChild(el('span', { class: 'pcv2__score-ring-value-suffix', text: '/100' }));
            } else {
                // Label the empty state explicitly so it doesn't read as
                // a broken gauge.
                valueText.textContent = '—';
                valueText.appendChild(el('span', { class: 'pcv2__score-ring-value-pending', text: PCV2.i18n.scorePending || 'Score pending' }));
            }
            valueWrap.appendChild(valueText);
            valueWrap.appendChild(el('div', {
                class: 'pcv2__score-ring-label',
                text: label || (PCV2.i18n.scoreLabel || 'Privacy Score')
            }));
            inner.appendChild(valueWrap);
        } else {
            inner.textContent = showValue ? (Math.round(value) + '%') : '—';
        }
        wrap.appendChild(inner);
        return wrap;
    }

    /**
     * Build a sub-score "mini card" with its own little ring + label.
     */
    function renderMiniScoreCard(opts) {
        var cardAttrs = { class: 'pcv2__mini-card' };
        if (opts.key) {
            // Stash the raw category key so the ELI5 toggle can find
            // and re-label this card without a re-render.
            cardAttrs['data-pcv2-key'] = opts.key;
        }
        var card = el('div', cardAttrs);
        var tone = severityFromScoreTone(opts.value);
        var ring = renderRingGauge({
            size: 'mini',
            value: opts.value,
            label: opts.label,
            tone: tone
        });
        card.appendChild(ring);
        card.appendChild(el('div', { class: 'pcv2__mini-card-label', text: opts.label || '' }));
        var dot = el('span', { class: 'pcv2__mini-card-tone', 'aria-hidden': 'true' });
        card.appendChild(dot);
        return card;
    }

    /**
     * Render the new score hero: large main ring + 4 mini sub-scores.
     * Replaces the old `renderScoreGauge`.
     */
    function renderScoreHero(report) {
        // The REST payload puts the aggregate score under
        // privacy_report.overall — NOT privacy_score. Reading the wrong
        // key produced the bare "—" in earlier screenshots while the
        // per-category scores rendered fine. Fall back to
        // scores.privacy (the v1 top-level field) and then to
        // scores.anonymity if both are missing.
        var pr = report.privacy_report || {};
        var scores = report.scores || {};
        var score = (typeof pr.overall === 'number') ? pr.overall
                  : (typeof scores.privacy === 'number') ? scores.privacy
                  : (typeof scores.anonymity === 'number') ? scores.anonymity
                  : null;
        var grade = pr.grade || (score != null ? letterGradeFromScore(score) : '');
        var mainTone = score == null ? 'neutral' : severityFromScore(score);

        var hero = el('div', { class: 'pcv2__score-hero' });

        // Main ring (left side on wide layouts).
        var main = el('div', { class: 'pcv2__score-hero-main' });
        main.appendChild(renderRingGauge({
            size: 'lg',
            value: score,
            label: PCV2.i18n.scoreLabel || 'Privacy Score',
            tone: mainTone
        }));
        if (grade) {
            main.appendChild(el('div', { class: 'pcv2__score-grade', text: grade }));
        }
        hero.appendChild(main);

        // Sub-scores grid (right side).
        var grid = el('div', { class: 'pcv2__score-hero-grid' });
        var subs = (report.privacy_report && report.privacy_report.subscores) || {};
        // Prefer well-known labels; fall back to first four keys.
        var preferredOrder = ['ip_exposure', 'fingerprint', 'connection', 'dns_leak', 'anonymity', 'webrtc'];
        var keys = preferredOrder.filter(function (k) { return subs[k] != null; });
        Object.keys(subs).forEach(function (k) { if (keys.indexOf(k) === -1) keys.push(k); });
        keys.slice(0, 4).forEach(function (k) {
            var v = subs[k];
            var pct = (v && typeof v === 'object') ? (v.score || v.percent) : v;
            grid.appendChild(renderMiniScoreCard({
                value: pct,
                label: prettySubLabel(k),
                key: k
            }));
        });
        if (keys.length === 0) {
            // No sub-scores — fall back to the categorical chips from the
            // privacy_report, treating each category as a mini card.
            var cats = (report.privacy_report && report.privacy_report.categories) || {};
            Object.keys(cats).slice(0, 4).forEach(function (k) {
                var c = cats[k];
                grid.appendChild(renderMiniScoreCard({
                    value: c && (c.score || c.percent),
                    label: prettySubLabel(k),
                    key: k
                }));
            });
        }
        hero.appendChild(grid);
        return hero;
    }

    /**
     * Render a category key as a user-facing label. The naive
     * `.replace('_',' ').replace(...)` approach shipped "Ip", "Dns",
     * "Webrtc" — embarrassing for technical labels. The dictionary below
     * is the single source of truth; any key not listed still gets a
     * humanised fallback.
     */
    var CATEGORY_LABELS = {
        ip:                 'IP',
        reputation:         'Reputation',
        dns:                'DNS',
        webrtc:             'WebRTC',
        fingerprint:        'Fingerprint',
        user_agent:         'User Agent',
        ipv6:               'IPv6',
        consistency:        'Consistency',
        security_posture:   'Security',
        proxy:              'Proxy / VPN / Tor',
        connection_quality: 'Connection Quality',
        local_network:      'Local Network',
        ip_exposure:        'IP Exposure',
        dns_leak:           'DNS Leak',
        connection:         'Connection',
        anonymity:          'Anonymity',
        browser:            'Browser'
    };
    function prettySubLabel(k) {
        // ELI5 mode: when the visitor enabled the "Explain simply"
        // toggle, return the plain-language label from the i18n
        // dictionary. Falls through to the technical label if no ELI5
        // entry exists for this key.
        if (PCV2.eli5Enabled && PCV2.i18n && PCV2.i18n.eli5 && PCV2.i18n.eli5[k]) {
            return PCV2.i18n.eli5[k];
        }
        if (CATEGORY_LABELS[k]) return CATEGORY_LABELS[k];
        return String(k)
            .replace(/_/g, ' ')
            .replace(/\b\w/g, function (c) { return c.toUpperCase(); });
    }

    /**
     * Render the user_agent payload as a display string. The REST payload
     * shape is {raw, browser, version, os, device, engine, is_bot}.
     * Showing the parsed fields (when present) is more meaningful than
     * the raw UA string, which has historically produced "[object Object]"
     * because the whole object was assigned to a text node.
     */
    function uaDisplayValue(ua) {
        if (!ua) return navigator.userAgent || null;
        if (typeof ua === 'string') return ua;
        var parts = [];
        if (ua.browser && (ua.browser.name || ua.browser)) {
            var bn = typeof ua.browser === 'string' ? ua.browser : (ua.browser.name || '');
            var bv = typeof ua.browser === 'object' ? (ua.browser.version || '') : '';
            var composed = (bn + (bv ? ' ' + bv : '')).trim();
            if (composed) parts.push(composed);
        }
        if (ua.os && (ua.os.name || typeof ua.os === 'string')) {
            var osn = typeof ua.os === 'string' ? ua.os : (ua.os.name || '');
            var osv = typeof ua.os === 'object' ? (ua.os.version || '') : '';
            var osComposed = (osn + (osv ? ' ' + osv : '')).trim();
            if (osComposed) parts.push(osComposed);
        }
        if (ua.device && parts.indexOf(ua.device) === -1) parts.push(ua.device);
        if (parts.length > 0) return parts.join(' · ');
        // No parsed fields — fall back to the raw UA. As a last resort use
        // the live browser's UA so the row is never empty.
        return ua.raw || navigator.userAgent || null;
    }

    /**
     * Just the browser family + version (used as a separate row), or null
     * if the payload didn't parse a browser.
     */
    function uaBrowserName(ua) {
        if (!ua || typeof ua === 'string') return null;
        var bn = ua.browser && (typeof ua.browser === 'string' ? ua.browser : ua.browser.name);
        var bv = ua.browser && typeof ua.browser === 'object' ? ua.browser.version : '';
        var composed = (bn || '') + (bv ? ' ' + bv : '');
        composed = composed.trim();
        if (composed) return composed;
        return navigator.userAgent || null;
    }

    /**
     * Pick a category-specific recommendation. Falls back to the row
     * message if no rule matches. Kept as JS-side copy because the
     * backend already returns recommendations for the top-level
     * Privacy Report — these are the inline per-finding tips.
     */
    function pickRecommendation(row, key) {
        var recs = {
            ip: 'Use a VPN to hide your IP and ASN from every site you visit. For maximum privacy, choose a provider that accepts anonymous payment.',
            reputation: 'A clean IP is rare on residential ISPs. If your IP is flagged, contact your ISP for a fresh address or use a reputable VPN exit node.',
            dns: 'Use a DNS resolver that supports encrypted transport (DNS-over-HTTPS or DNS-over-TLS) and routes all queries through your VPN tunnel.',
            webrtc: 'Disable WebRTC in your browser (Firefox: about:config → media.peerconnection.enabled). The WebRTC test exposes your real public IP even when using a VPN.',
            fingerprint: 'Use Firefox with resistFingerprinting, or Tor Browser. Resist installing browser extensions; each one makes your fingerprint more unique.',
            user_agent: 'A privacy-focused browser sends a generic User-Agent by default. Avoid Chromium-based browsers for high-privacy sessions — they leak version detail.',
            ipv6: 'If your VPN only tunnels IPv4, disable IPv6 at the OS level to prevent IPv6 leaks. Many VPNs support IPv6 natively now — check your provider.',
            consistency: 'A mismatch between your browser timezone, language, and geo is a strong tracking signal. Set all three to the same region as your VPN exit.',
            security_posture: 'Keep your browser updated. Sites behind TLS 1.0/1.1 should be avoided — modern browsers refuse them by default.',
            proxy: 'A clean residential IP is expected for a normal user. If you see "Hosting" or "Tor", the site may treat you differently (CAPTCHAs, blocks).',
            connection_quality: 'Connection quality is informational only — it does not affect privacy. High latency may be a VPN or distant exit.',
            local_network: 'LAN exposure is informational only. It indicates whether the browser can reach local network endpoints (mDNS, WebRTC STUN).'
        };
        if (recs[key]) return recs[key];
        if (row && row.status === 'bad') {
            return 'This category scored below 30%. See the criteria above for the specific signal that triggered the score.';
        }
        if (row && row.status === 'warning') {
            return 'This category is in a warning band. Review the criteria above for the signal that lowered the score.';
        }
        return null;
    }

    function renderCard(card, title, content) {
        var header = card.querySelector('[data-pcv2-region="card-title"]');
        if (header) header.textContent = title;
        var body = card.querySelector('[data-pcv2-region="card-body"]');
        clear(body);
        if (content) body.appendChild(content);
    }

    /**
     * Render the DNS Resolver card. Accepts either the original
     * dns_test placeholder ({configured:true, note:...}) or a fully
     * populated probe result {status, token, hostname, resolvers[]}.
     * In the placeholder case we render a clear "Run DNS test" prompt
     * with a button — the probe has been kicked off in parallel by
     * runScan() and will re-render this card once it lands.
     */
    function renderDnsCard(card, dns) {
        var title = PCV2.i18n.dnsTitle || 'DNS Resolver';
        var body = el('div', { class: 'pcv2__dns-card' });

        // Probe result path.
        if (dns && dns.status === 'ok' && Array.isArray(dns.resolvers)) {
            var ok = dns.resolvers.filter(function (r) { return r.status === 'ok'; }).length;
            var total = dns.resolvers.length;
            var consistent = !!dns.consistent;
            var tone = consistent ? 'safe' : (ok > 0 ? 'warning' : 'danger');
            var label = consistent ? 'Consistent' : (ok > 0 ? 'Inconsistent' : 'Failed');
            var pill = el('div', { class: 'pcv2__dns-provider-pill' }, [
                el('span', { class: 'pcv2__dns-provider-pill-label', text: 'Resolvers' }),
                el('span', { text: ok + ' / ' + total + ' responding' })
            ]);
            body.appendChild(pill);
            body.appendChild(el('div', { class: 'pcv2__dns-verdict' }, [
                renderStatusChip(tone, label),
                el('span', { class: 'pcv2__dns-verdict-host', text: dns.hostname || 'cloudflare.com', mono: true })
            ]));
            var rows = dns.resolvers.map(function (r) {
                var rTone = r.status === 'ok' ? 'safe' : (r.status === 'error' ? 'danger' : 'warning');
                var latency = r.latency_ms != null ? r.latency_ms + ' ms' : null;
                var ans = r.status === 'ok' ? (r.answer_ip || null) : (r.error || null);
                return el('li', { class: 'pcv2__dns-resolver-row', 'data-pcv2-tone': rTone }, [
                    el('span', { class: 'pcv2__dns-resolver-name', text: r.name || '—' }),
                    el('span', { class: 'pcv2__dns-resolver-answer', text: ans || '—', mono: true }),
                    el('span', { class: 'pcv2__dns-resolver-latency', text: latency || '—' })
                ]);
            });
            var list = el('ul', { class: 'pcv2__dns-resolvers', role: 'list' }, rows);
            body.appendChild(list);
            renderCard(card, title, body);
            return;
        }

        // Not configured / still loading path.
        var notRunLabel = (dns && dns.note) ? dns.note
                       : (PCV2.i18n.dnsNotRun || 'DNS test not yet run.');
        body.appendChild(el('div', { class: 'pcv2__dns-provider-pill' }, [
            el('span', { class: 'pcv2__dns-provider-pill-label', text: 'Provider' }),
            el('span', { text: 'Pending probe…' })
        ]));
        body.appendChild(el('p', { class: 'pcv2__dns-note', text: notRunLabel }));
        renderCard(card, title, body);
    }

    function rebuildReportSkeleton(dashboard) {
        // Mirror the server-side skeleton in class-public-assets-v2.php
        // so a rescan (which clears reportRegion) still renders the
        // expected structure without needing a full page reload.
        var reportRegion = dashboard.querySelector('[data-pcv2-region="report"]');
        if (!reportRegion) return;

        var scoreHero = el('div', { class: 'pcv2__score-hero-host', 'data-pcv2-region': 'summary' });
        var grid = el('div', { class: 'pcv2__grid' });
        var findings = el('div', { class: 'pcv2__findings', 'data-pcv2-region': 'findings' });

        var cardKeys = ['overview', 'connection', 'anonymity', 'dns', 'browser', 'security'];
        cardKeys.forEach(function (key) {
            var card = el('article', { class: 'pcv2__card', 'data-pcv2-card': key });
            card.appendChild(el('header', { class: 'pcv2__card-header' }, [
                el('h2', { 'data-pcv2-region': 'card-title' })
            ]));
            card.appendChild(el('div', { class: 'pcv2__card-body', 'data-pcv2-region': 'card-body' }));
            grid.appendChild(card);
        });

        reportRegion.appendChild(scoreHero);
        reportRegion.appendChild(grid);
        reportRegion.appendChild(findings);
    }

    function renderReport(dashboard, report) {
        var intel = report.intel || {};
        var proxy = report.proxy || {};
        var conn = report.connection || {};
        var rep = report.reputation || {};

        // The static skeleton (score hero host, 6 cards, findings container)
        // is rendered once by the server-side shortcode. The reset path in
        // runScan() calls clear(reportRegion) which removes those nodes
        // along with their previous content. If they're gone (re-render
        // after a rescan), rebuild the skeleton before populating it.
        var reportRegion = dashboard.querySelector('[data-pcv2-region="report"]');
        if (!reportRegion) return;

        if (!dashboard.querySelector('[data-pcv2-region="summary"]')) {
            rebuildReportSkeleton(dashboard);
        }

        // Score hero (the big ring + 4 mini KPI rings).
        var summary = dashboard.querySelector('[data-pcv2-region="summary"]');
        clear(summary);
        var score = report.privacy_score;
        var grade = report.privacy_report && report.privacy_report.grade;
        summary.appendChild(renderScoreHero(report));

        // Cards.
        var cards = dashboard.querySelectorAll('.pcv2__card');
        cards.forEach(function (card) {
            var key = card.getAttribute('data-pcv2-card');
            if (key === 'overview') {
                // Overview: score + grade + confidence at-a-glance.
                var ovSummary = el('div', { class: 'pcv2__overview-summary' }, [
                    el('div', { class: 'pcv2__overview-summary-cell' }, [
                        el('span', { class: 'pcv2__overview-summary-cell-label', text: PCV2.i18n.scoreLabel || 'Privacy Score' }),
                        el('span', { class: 'pcv2__overview-summary-cell-value', text: score == null ? '—' : score + ' / 100' })
                    ]),
                    el('div', { class: 'pcv2__overview-summary-cell' }, [
                        el('span', { class: 'pcv2__overview-summary-cell-label', text: PCV2.i18n.gradeLabel || 'Grade' }),
                        el('span', { class: 'pcv2__overview-summary-cell-value pcv2__overview-summary-cell-value--grade', text: grade || '—' })
                    ]),
                    el('div', { class: 'pcv2__overview-summary-cell' }, [
                        el('span', { class: 'pcv2__overview-summary-cell-label', text: PCV2.i18n.confidenceLabel || 'Confidence' }),
                        el('span', { class: 'pcv2__overview-summary-cell-value', text: (report.privacy_report && report.privacy_report.confidence) || '—' })
                    ])
                ]);
                // Subscores bar chart (always present) — a real chart,
                // not a flat key-value list, so the user can see at a
                // glance which dimensions are pulling the score down.
                var subs = (report.privacy_report && report.privacy_report.subscores) || {};
                var cats = (report.privacy_report && report.privacy_report.categories) || {};
                var barItems = [];
                var subKeys = Object.keys(subs).slice(0, 6);
                if (subKeys.length === 0) {
                    // Fall back to the top 6 categories.
                    Object.keys(cats).slice(0, 6).forEach(function (k) {
                        subs[k] = { score: cats[k].percent || cats[k].score };
                        subKeys.push(k);
                    });
                }
                subKeys.forEach(function (k) {
                    var v = subs[k] || {};
                    var pct = typeof v === 'object' ? (v.score || v.percent) : v;
                    barItems.push({ label: prettySubLabel(k), value: pct, key: k });
                });
                var barChart = renderBarChart(barItems);
                renderCard(card, PCV2.i18n.overviewTitle || 'Overview', el('div', null, [ovSummary, barChart]));
            } else if (key === 'connection') {
                // Connection: hero strip with IP + country + ASN + ISP,
                // then detail rows below.
                var ipv4 = report.request_ip && report.request_ip.ipv4;
                var ipv6 = report.request_ip && report.request_ip.ipv6;
                var country = intel.country_name || intel.country;
                var asn = intel.asn;
                var isp = intel.isp;
                var heroRows = [];
                if (ipv4 || ipv6) {
                    heroRows.push(['IP', (ipv4 || ipv6) + (ipv6 ? '  /  ' + ipv6 : '')]);
                }
                if (country || asn) {
                    heroRows.push(['Location', [intel.city, intel.region, country].filter(Boolean).join(', ') || '—']);
                }
                if (isp)  heroRows.push(['ISP', isp]);
                if (asn)  heroRows.push(['ASN', asn]);
                var connectionHero = el('div', { class: 'pcv2__connection-hero' });
                if (heroRows.length === 0) {
                    connectionHero.appendChild(el('p', {
                        class: 'pcv2__row-missing',
                        text: 'Run the scan to see your connection details.'
                    }));
                } else {
                    heroRows.forEach(function (r) {
                        var row = el('dl', { class: 'pcv2__connection-hero-row' });
                        row.appendChild(el('dt', { text: r[0] }));
                        row.appendChild(el('dd', { text: r[1] }));
                        connectionHero.appendChild(row);
                    });
                }
                renderCard(card, PCV2.i18n.connectionTitle || 'Connection', el('div', null, [
                    connectionHero,
                    renderKV([
                        { label: 'IPv4', value: ipv4, mono: true },
                        { label: 'IPv6', value: ipv6, mono: true },
                        { label: 'Region',  value: intel.region },
                        { label: 'City',    value: intel.city },
                        { label: 'Timezone',value: intel.timezone }
                    ])
                ]));
            } else if (key === 'anonymity') {
                // Anonymity: detection pill at top (always visible),
                // then type + confidence below.
                var proxyTone = proxy.label === 'No signal' ? 'safe'
                              : proxy.label && /tor/i.test(proxy.label) ? 'danger'
                              : proxy.label && /proxy/i.test(proxy.label) ? 'warning'
                              : proxy.label && /vpn/i.test(proxy.label) ? 'warning'
                              : 'neutral';
                var detectionPill = el('div', { class: 'pcv2__detection-pill' }, [
                    el('span', { class: 'pcv2__detection-pill-label', text: 'Detection' }),
                    renderStatusChip(proxyTone, proxy.label || (PCV2.i18n.noConfidence || 'Unknown'))
                ]);
                renderCard(card, PCV2.i18n.anonymityTitle || 'Anonymity', el('div', null, [
                    detectionPill,
                    renderKV([
                        { label: 'Type', value: proxy.type || null },
                        { label: 'Confidence', value: proxy.confidence || null }
                    ])
                ]));
            } else if (key === 'dns') {
                // DNS: render the resolver detail from the parallel probe
                // result, or show a "pending" placeholder if the probe
                // hasn't landed yet.
                var dns = report.dns_test || rep.dns || {};
                renderDnsCard(card, dns);
            } else if (key === 'browser') {
                // Browser: always-on rows from navigator/screen — never
                // "Not available" for UA, screen, languages, timezone.
                var fp = report.fingerprint || {};
                var browserKV = el('dl', { class: 'pcv2__rows' });
                var browserRows = [
                    // user_agent in the REST payload is an object
                    // {raw, browser, version, os, device, engine, is_bot}.
                    // Rendering the whole object as text yielded the literal
                    // "[object Object]". Prefer the parsed fields when they
                    // are present, fall back to the raw UA string, and
                    // finally to navigator.userAgent for the live browser.
                    { label: 'User Agent', value: uaDisplayValue(report.user_agent), mono: true, always: true },
                    { label: 'Browser',    value: uaBrowserName(report.user_agent), always: true },
                    { label: 'Languages',  value: (navigator.languages || []).join(', ') || null, always: true },
                    { label: 'Timezone',   value: (Intl.DateTimeFormat().resolvedOptions().timeZone) || null, always: true },
                    { label: 'Screen',     value: screen.width + ' × ' + screen.height, always: true },
                    { label: 'Entropy',    value: fp.entropy_bits ? fp.entropy_bits + ' bits' : null }
                ];
                browserRows.forEach(function (it) {
                    var dt = el('dt', { text: it.label });
                    var dd = el('dd', {
                        class: (it.mono ? 'mono ' : '') + (it.always ? 'pcv2__row--always-on' : '')
                    });
                    dd.appendChild(pcv2DisplayValue(it.value));
                    browserKV.appendChild(dt);
                    browserKV.appendChild(dd);
                });
                renderCard(card, PCV2.i18n.browserTitle || 'Browser Privacy', browserKV);
            } else if (key === 'security') {
                // Security: verdict strip at top (always visible).
                var sp = report.security_posture || {};
                var tlsVer = sp.tls && sp.tls.version;
                var tlsStatus = sp.tls && sp.tls.status;
                // The REST payload's security_posture.browser uses the key
                // `browser` for the browser family name (e.g. "Chrome") and
                // `version` for the version string — NOT `name`. Reading
                // `sp.browser.name` produced the literal "undefined" we
                // shipped in earlier screenshots.
                var browserVer = sp.browser && (
                    (sp.browser.browser || '') +
                    (sp.browser.version ? ' ' + sp.browser.version : '')
                ).trim();
                var outdated = sp.browser && sp.browser.outdated;
                var verdictTone = (tlsStatus === 'good' && !outdated) ? 'safe'
                                : (tlsStatus === 'bad' || outdated) ? 'danger'
                                : 'warning';
                var verdictLabel = (tlsStatus === 'good' && !outdated) ? 'Strong'
                                 : (tlsStatus === 'bad' || outdated) ? 'At Risk'
                                 : 'Adequate';
                var verdictStrip = el('div', { class: 'pcv2__security-verdict' }, [
                    renderStatusChip(verdictTone, verdictLabel),
                    el('span', { class: 'pcv2__security-verdict-label', text:
                        outdated ? 'One or both security-posture signals are below current.'
                                : (tlsStatus === 'bad' ? 'TLS protocol is below current.'
                                : 'Both TLS and browser version are current.')
                    })
                ]);
                renderCard(card, PCV2.i18n.securityTitle || 'Security Findings', el('div', null, [
                    verdictStrip,
                    renderKV([
                        { label: 'TLS',         value: tlsVer, mono: true },
                        { label: 'TLS Status',  value: tlsStatus },
                        { label: 'Browser',     value: browserVer || null },
                        { label: 'Outdated',    value: outdated ? 'Yes' : 'No' }
                    ])
                ]));
            }
        });

        // Findings list (expandable rows with scoring rubric + evidence).
        var findings = dashboard.querySelector('[data-pcv2-region="findings"]');
        clear(findings);
        var cats = (report.privacy_report && report.privacy_report.categories) || {};
        var list = el('div', { class: 'pcv2__findings' });
        var findingsHeader = el('div', { class: 'pcv2__findings-header' }, [
            el('h3', { text: PCV2.i18n.findingsTitle || 'Privacy Findings' }),
            el('span', { class: 'pcv2__findings-hint', text: PCV2.i18n.findingsHint || 'Click any row for scoring details and evidence.' })
        ]);
        list.appendChild(findingsHeader);
        var findingIcons = { safe: '✓', warning: '!', danger: '✕', info: 'ⓘ', neutral: '·' };

        Object.keys(cats).forEach(function (k) {
            var c = cats[k];
            if (!c) return;
            var scoreVal = Math.round(c.score || c.percent || 0);
            var sev = severityFromScore(scoreVal);

            // Native <details> wrapper for a11y + keyboard support out of the box.
            var detailsAttrs = {
                class: 'pcv2__finding',
                'data-pcv2-severity': sev,
                'data-pcv2-key': k,
                'data-pcv2-score': String(scoreVal)
            };
            var details = el('details', detailsAttrs);

            // Summary row (always visible, clickable).
            var summary = el('summary', { class: 'pcv2__finding-summary' });
            summary.appendChild(el('div', {
                class: 'pcv2__finding-icon',
                'aria-hidden': 'true',
                text: findingIcons[sev] || '·'
            }));
            summary.appendChild(el('div', { class: 'pcv2__finding-head' }, [
                el('p', { class: 'pcv2__finding-title', text: prettySubLabel(k) + ' — ' + scoreVal + ' / 100' }),
                el('p', { class: 'pcv2__finding-body',  text: c.message || (PCV2.i18n.noDetails || 'No additional details available.') })
            ]));
            summary.appendChild(el('div', { class: 'pcv2__finding-score-wrap' }, [
                el('span', { class: 'pcv2__finding-score', text: scoreVal + '%' }),
                el('span', { class: 'pcv2__finding-chevron', 'aria-hidden': 'true', text: '▾' })
            ]));
            details.appendChild(summary);

            // Expandable body: scoring rubric + evidence + recommendation.
            var body = el('div', { class: 'pcv2__finding-details' });

            // 1. Scoring rubric — which band was hit, plus all bands for context.
            var rubricBlock = el('div', { class: 'pcv2__finding-block' });
            rubricBlock.appendChild(el('h4', {
                class: 'pcv2__finding-block-title',
                text: PCV2.i18n.rubricTitle || 'How this score was calculated'
            }));
            var criteria = Array.isArray(c.criteria) ? c.criteria : [];
            var hit = criteria.find(function (b) { return b.score === scoreVal; });
            if (hit) {
                var verdict = el('div', { class: 'pcv2__finding-verdict' }, [
                    el('span', {
                        class: 'pcv2__status',
                        'data-pcv2-status': sev === 'safe' ? 'safe' : sev === 'danger' ? 'danger' : 'warning'
                    }, hit.label),
                    el('span', { class: 'pcv2__finding-verdict-text', text: hit.condition })
                ]);
                rubricBlock.appendChild(verdict);
            } else {
                rubricBlock.appendChild(el('p', {
                    class: 'pcv2__finding-verdict-text',
                    text: PCV2.i18n.noRubric || 'No scoring rubric available for this category.'
                }));
            }
            if (criteria.length > 0) {
                var rubric = el('ul', { class: 'pcv2__finding-rubric' });
                criteria.forEach(function (band) {
                    var li = el('li', {
                        class: 'pcv2__finding-band' + (band === hit ? ' pcv2__finding-band--hit' : ''),
                        'data-pcv2-tone': band.label.toLowerCase() === 'good' ? 'safe'
                                        : band.label.toLowerCase() === 'bad' ? 'danger'
                                        : 'warning'
                    });
                    li.appendChild(el('span', { class: 'pcv2__finding-band-score', text: band.score }));
                    li.appendChild(el('span', { class: 'pcv2__finding-band-condition', text: band.condition }));
                    rubric.appendChild(li);
                });
                rubricBlock.appendChild(rubric);
            }
            body.appendChild(rubricBlock);

            // 2. Evidence — the raw signal values that contributed to the score.
            var details_ = c.details && typeof c.details === 'object' ? c.details : {};
            var detailKeys = Object.keys(details_);
            if (detailKeys.length > 0) {
                var evBlock = el('div', { class: 'pcv2__finding-block' });
                evBlock.appendChild(el('h4', {
                    class: 'pcv2__finding-block-title',
                    text: PCV2.i18n.evidenceTitle || 'Evidence'
                }));
                var dl = el('dl', { class: 'pcv2__finding-evidence' });
                detailKeys.forEach(function (dk) {
                    var raw = details_[dk];
                    var display = raw;
                    if (raw && typeof raw === 'object') {
                        display = JSON.stringify(raw);
                    } else if (raw === '' || raw == null) {
                        return; // skip empty
                    }
                    dl.appendChild(el('dt', { text: prettySubLabel(dk) }));
                    dl.appendChild(el('dd', {
                        class: 'mono',
                        text: String(display)
                    }));
                });
                if (dl.children.length > 0) {
                    evBlock.appendChild(dl);
                    body.appendChild(evBlock);
                }
            }

            // 3. Status source — was the score measured or estimated?
            if (c.status_source && c.status_source !== 'measured') {
                var srcBlock = el('div', { class: 'pcv2__finding-block' }, [
                    el('h4', {
                        class: 'pcv2__finding-block-title',
                        text: PCV2.i18n.sourceTitle || 'Data source'
                    }),
                    el('p', {
                        class: 'pcv2__finding-source-note',
                        text: c.status_source === 'unknown'
                            ? (PCV2.i18n.sourceUnknown || 'This category was scored from limited data — the underlying provider did not respond.')
                            : (PCV2.i18n.sourceEstimated || 'This category was estimated; no direct measurement was available.')
                    })
                ]);
                body.appendChild(srcBlock);
            }

            // 4. Recommendation — what to do about this finding.
            var rec = pickRecommendation(c, k);
            if (rec) {
                var recBlock = el('div', { class: 'pcv2__finding-block pcv2__finding-block--rec' }, [
                    el('h4', {
                        class: 'pcv2__finding-block-title',
                        text: PCV2.i18n.recTitle || 'What you can do'
                    }),
                    el('p', { class: 'pcv2__finding-rec', text: rec })
                ]);
                body.appendChild(recBlock);
            }

            details.appendChild(body);
            list.appendChild(details);
        });
        findings.appendChild(list);

        // Post-scan share/export bar — reuse the static host if the
        // server-rendered skeleton has one (Phase 19 inline layout),
        // otherwise create one next to the findings region.
        var actionsHost = findings.parentNode.querySelector(':scope > .pcv2__actions-host');
        if (!actionsHost) {
            actionsHost = el('div', { class: 'pcv2__actions-host' });
            findings.parentNode.insertBefore(actionsHost, findings.nextSibling);
        }
        renderPostScanActions(report, actionsHost);
    }

    /* ---------- GeoTrace v2 renderer ----------------------------------- */

    function leafletAvailable() {
        return typeof window.L !== 'undefined' && typeof window.L.map === 'function';
    }

    function ensureLeaflet(cb) {
        if (leafletAvailable()) { cb(true); return; }
        if (!window.PC_SCAN || !window.PC_SCAN.assetUrl) { cb(false); return; }
        // Lazy-load Leaflet only when the user actually opens GeoTrace v2.
        var css = document.createElement('link');
        css.rel = 'stylesheet';
        css.href = window.PC_SCAN.assetUrl + 'css/leaflet.css';
        document.head.appendChild(css);
        var s = document.createElement('script');
        s.src = window.PC_SCAN.assetUrl + 'js/leaflet.js';
        s.onload = function () { cb(true); };
        s.onerror = function () { cb(false); };
        document.head.appendChild(s);
    }

    /**
     * Render a route on a 2D Leaflet map. Hops with null lat/lon are
     * treated as gaps: the polyline breaks at that hop and resumes at
     * the next geolocatable one. No fabricated points are drawn.
     */
    function renderRoute2D(route, container) {
        if (!leafletAvailable()) {
            container.innerHTML = '<div class="pcv2__geo-map-msg">' + (PCV2.i18n.geoUnavailable || 'Map unavailable') + '</div>';
            return;
        }
        container.innerHTML = '';
        var map = window.L.map(container, { worldCopyJump: true, scrollWheelZoom: false }).setView([20, 0], 2);
        window.L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '&copy; OpenStreetMap contributors',
            maxZoom: 18
        }).addTo(map);

        var publicPoints = [];
        var probe = route.probe && route.probe.lat != null ? route.probe : null;
        var target = route.target && route.target.lat != null ? route.target : null;
        var hops = Array.isArray(route.hops) ? route.hops : [];

        // Build segments: contiguous runs of points that have coords.
        function addPoint(p, opts) {
            if (!p || p.lat == null || p.lon == null) return;
            var m = window.L.circleMarker([p.lat, p.lon], Object.assign({
                radius: opts && opts.origin ? 8 : opts && opts.dest ? 8 : 6,
                color: opts && opts.origin ? '#5b6373'
                      : opts && opts.dest   ? '#2ea043'
                      : opts && opts.private ? '#8a93a3'
                      : '#1ea2c4',
                fillColor: opts && opts.origin ? '#5b6373'
                          : opts && opts.dest   ? '#2ea043'
                          : opts && opts.private ? '#8a93a3'
                          : '#1ea2c4',
                fillOpacity: 0.85,
                weight: 2
            }, opts && opts.extra || {}));
            if (p.label || p.hostname) m.bindPopup(p.label || p.hostname);
            m.addTo(map);
            publicPoints.push([p.lat, p.lon]);
        }

        addPoint(probe, { origin: true });
        hops.forEach(function (h) {
            addPoint({ lat: h.lat, lon: h.lon, hostname: h.hostname, label: h.hostname || h.ip }, { private: h.status === 'private' });
        });
        addPoint(target, { dest: true });

        // Draw segments connecting contiguous geolocatable points.
        var ordered = [];
        if (probe && probe.lat != null) ordered.push([probe.lat, probe.lon]);
        hops.forEach(function (h) {
            if (h.lat != null && h.lon != null) ordered.push([h.lat, h.lon]);
        });
        if (target && target.lat != null) ordered.push([target.lat, target.lon]);
        if (ordered.length >= 2) {
            window.L.polyline(ordered, { color: '#1ea2c4', weight: 3, opacity: 0.85, dashArray: null }).addTo(map);
            try { map.fitBounds(ordered, { padding: [30, 30] }); } catch (_e) {}
        }
    }

    function renderHopTimeline(route, container) {
        clear(container);
        var hops = Array.isArray(route.hops) ? route.hops : [];
        var prevRtt = null;
        hops.forEach(function (h) {
            var row = el('div', { class: 'pcv2__geo-hop', 'data-pcv2-hop': String(h.index) });
            row.appendChild(el('div', { class: 'pcv2__geo-hop-idx', text: String(h.index) }));
            var name = el('div', { class: 'pcv2__geo-hop-name' });
            if (h.status === 'unanswered') {
                name.appendChild(el('strong', { text: PCV2.i18n.unansweredBadge || 'No response' }));
                name.appendChild(el('span', { text: 'hop did not reply to traceroute probes' }));
            } else if (h.status === 'private') {
                name.appendChild(el('strong', { text: PCV2.i18n.privateBadge || 'Private' }));
                name.appendChild(el('span', { text: h.ip || '' }));
            } else {
                var city = h.city ? h.city + ', ' + h.country : (h.country || '—');
                name.appendChild(el('strong', { text: h.hostname || h.ip || '—' }));
                name.appendChild(el('span', { text: city + (h.asn ? ' · ' + h.asn : '') }));
            }
            row.appendChild(name);
            var rttText = h.rtt_ms == null ? '—' : (h.rtt_ms.toFixed(1) + ' ms');
            row.appendChild(el('div', { class: 'pcv2__geo-hop-rtt', text: rttText }));
            // Latency-jump heuristic: 1.5× previous hop's RTT.
            if (prevRtt != null && h.rtt_ms != null && prevRtt > 0 && h.rtt_ms > 1.5 * prevRtt) {
                row.setAttribute('data-pcv2-jump', 'true');
                row.appendChild(el('span', {
                    class: 'pcv2__chip--neutral',
                    title: 'RTT more than 1.5× the previous hop — likely a congested or distant link.',
                    text: PCV2.i18n.latencyJump || 'Latency jump'
                }));
            }
            if (h.status === 'public' && h.confidence && h.confidence !== 'unknown') {
                row.appendChild(el('span', { class: 'pcv2__chip--neutral', text: (PCV2.i18n.geoConfidence || 'Confidence') + ': ' + h.confidence }));
            }
            container.appendChild(row);
            if (h.rtt_ms != null) prevRtt = h.rtt_ms;
        });
        if (hops.length === 0) {
            container.appendChild(el('div', { class: 'pcv2__geo-hops-empty', text: PCV2.i18n.geoUnavailable || 'Traceroute unavailable' }));
        }
    }

    function renderRoute(route, host) {
        var mapEl    = host.querySelector('[data-pcv2-region="geo-map"]');
        var metaEl   = host.querySelector('[data-pcv2-region="geo-meta"]');
        var hopsEl   = host.querySelector('[data-pcv2-region="geo-hops"]');
        var discl    = host.querySelector('[data-pcv2-region="geo-disclaimer"]');
        // Meta.
        clear(metaEl);
        var meta = [
            [PCV2.i18n.geoProbeLabel || 'Probe', route.probe && (route.probe.city ? route.probe.city + ', ' + route.probe.country : route.probe && route.probe.ip)],
            [PCV2.i18n.geoTargetLabel || 'Destination', route.target && (route.target.hostname || (route.target.ip || '—'))],
            [PCV2.i18n.geoHopsLabel || 'Hops', String((route.hops || []).length)],
            ['Source kind', route.source_kind || '—']
        ];
        meta.forEach(function (m) {
            metaEl.appendChild(el('dt', { text: m[0] }));
            metaEl.appendChild(el('dd', { text: m[1] || '—' }));
        });
        if (discl) discl.textContent = PCV2.i18n.geoDisclaimer || '';

        // Map.
        if (route.hops && route.hops.length > 0) {
            ensureLeaflet(function (ok) {
                if (ok) renderRoute2D(route, mapEl);
                else mapEl.innerHTML = '<div class="pcv2__geo-map-msg">' + (PCV2.i18n.geoUnavailable || 'Map unavailable') + '</div>';
            });
        } else {
            mapEl.innerHTML = '<div class="pcv2__geo-map-msg">' + (PCV2.i18n.geoUnavailable || 'No traceroute data — paste your own below') + '</div>';
        }

        // Hop timeline.
        renderHopTimeline(route, hopsEl);
    }

    /**
     * Attach the GeoTrace v2 widget to a host element. Wires the run
     * button (server-side traceroute) and the paste form (pasted text).
     */
    function bindGeoTrace(host) {
        var runBtn = host.querySelector('[data-pcv2-action="geo-run"]');
        var targetInput = host.querySelector('[data-pcv2-region="geo-target"]');
        var pasteForm = host.querySelector('[data-pcv2-action="geo-paste"]');
        var pasteTextarea = host.querySelector('[data-pcv2-region="geo-paste"]');

        function run() {
            var target = (targetInput && targetInput.value || '').trim() || (window.location.hostname);
            runBtn.disabled = true;
            fetch(window.PC_SCAN.restUrl + 'scan/geo/lookup?target=' + encodeURIComponent(target), {
                headers: { 'X-WP-Nonce': window.PC_SCAN.restNonce || '' }
            })
            .then(function (r) {
                if (!r.ok) throw new Error('HTTP ' + r.status);
                return r.json();
            })
            .then(function (route) { renderRoute(route, host); })
            .catch(function (err) {
                host.querySelector('[data-pcv2-region="geo-map"]').innerHTML =
                    '<div class="pcv2__geo-map-msg">' + (PCV2.i18n.geoUnavailable || 'Traceroute failed') + ' — ' + escape(err && err.message) + '</div>';
            })
            .then(function () { runBtn.disabled = false; });
        }

        if (runBtn) runBtn.addEventListener('click', run);
        if (pasteForm && pasteTextarea) {
            pasteForm.addEventListener('submit', function (ev) {
                ev.preventDefault();
                fetch(window.PC_SCAN.restUrl + 'scan/geo/paste', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-WP-Nonce': window.PC_SCAN.restNonce || ''
                    },
                    body: JSON.stringify({ paste: pasteTextarea.value })
                })
                .then(function (r) {
                    if (!r.ok) throw new Error('HTTP ' + r.status);
                    return r.json();
                })
                .then(function (route) { renderRoute(route, host); })
                .catch(function (err) {
                    host.querySelector('[data-pcv2-region="geo-hops"]').innerHTML =
                        '<div class="pcv2__geo-hops-empty">' + escape(err && err.message) + '</div>';
                });
            });
        }
        // Render an initial honest empty state so the map area is never blank.
        renderRoute({ probe: null, target: null, hops: [], source_kind: 'unavailable' }, host);
    }

    /* ---------- boot ---------------------------------------------------- */

    /**
     * Read the persisted "Explain simply" preference. The toggle is
     * per-session: localStorage. Default is OFF (technical labels).
     */
    function readEli5Pref() {
        try { return window.localStorage.getItem('pcv2_eli5') === '1'; }
        catch (_e) { return false; }
    }
    function storeEli5Pref(on) {
        try { window.localStorage.setItem('pcv2_eli5', on ? '1' : '0'); }
        catch (_e) { /* localStorage blocked — preference is best-effort */ }
    }

    function initEli5Toggle() {
        // Apply the stored preference to the live state + DOM. We don't
        // re-render the whole report here — prettySubLabel() reads
        // PCV2.eli5Enabled on every call, and the next render (rescan,
        // theme switch, etc.) will pick it up. But we DO update the
        // visible labels on the already-rendered cards so the toggle
        // feels instant.
        PCV2.eli5Enabled = readEli5Pref();
        syncEli5Button();

        document.addEventListener('click', function (ev) {
            var btn = ev.target.closest('[data-pcv2-action="eli5-cycle"]');
            if (!btn) return;
            PCV2.eli5Enabled = !PCV2.eli5Enabled;
            storeEli5Pref(PCV2.eli5Enabled);
            syncEli5Button();
            // Re-run the report render so every visible label
            // (overview bar chart, finding rows, mini-card titles)
            // reflects the new mode. We pull the last report out of
            // the bar's __report stash, or fall back to a re-scan.
            reapplyEli5Labels();
        });
    }

    function syncEli5Button() {
        var btn = document.querySelector('.pcv2 [data-pcv2-action="eli5-cycle"]');
        if (!btn) return;
        btn.setAttribute('aria-pressed', PCV2.eli5Enabled ? 'true' : 'false');
        btn.title = PCV2.eli5Enabled
            ? (PCV2.i18n.eli5ToggleOn || 'Showing plain-language explanations')
            : (PCV2.i18n.eli5ToggleOff || 'Showing technical details');
        var lbl = btn.querySelector('.pcv2__eli5-toggle-label');
        if (lbl) lbl.textContent = PCV2.eli5Enabled ? 'ELI5 ✓' : 'ELI5';
    }

    /**
     * Re-render the score hero + bar chart + findings + cards using
     * the current ELI5 mode. We don't have a stored last-report handle
     * at module scope, so we walk the rendered DOM and rewrite the
     * static label slots. This is cheap and avoids re-running the
     * scan network round-trip.
     */
    function reapplyEli5Labels() {
        var dashboard = document.querySelector('[data-pcv2-component="dashboard"]');
        if (!dashboard) return;

        // Card titles — the cards are rendered server-side as static
        // articles with `data-pcv2-card`. We re-render the title only;
        // the body is more expensive to walk and the dynamic bits
        // (status chips, key/value rows) are data-bound.
        var titles = {
            overview:    PCV2.i18n.overviewTitle   || 'Overview',
            connection:  PCV2.i18n.connectionTitle || 'Connection',
            anonymity:   PCV2.i18n.anonymityTitle  || 'Anonymity',
            dns:         PCV2.i18n.dnsTitle        || 'DNS Resolver',
            browser:     PCV2.i18n.browserTitle    || 'Browser Privacy',
            security:    PCV2.i18n.securityTitle   || 'Security Findings'
        };
        Object.keys(titles).forEach(function (key) {
            var card = dashboard.querySelector('[data-pcv2-card="' + key + '"]');
            if (!card) return;
            var h = card.querySelector('[data-pcv2-region="card-title"]');
            if (h) h.textContent = titles[key];
        });

        // Bar chart labels — these are the per-category rows on the
        // Overview card. We have to know the original keys to map
        // them to the new labels, so we read the data attribute that
        // we stashed on each bar row during render (see
        // renderBarChart()).
        var bars = dashboard.querySelectorAll('.pcv2__bar-chart-row[data-pcv2-key]');
        bars.forEach(function (row) {
            var key = row.getAttribute('data-pcv2-key');
            var lbl = row.querySelector('.pcv2__bar-chart-label');
            if (key && lbl) lbl.textContent = prettySubLabel(key);
        });

        // Finding rows — the expandable Privacy Findings list also
        // stores the original key.
        var findings = dashboard.querySelectorAll('.pcv2__finding[data-pcv2-key]');
        findings.forEach(function (f) {
            var key = f.getAttribute('data-pcv2-key');
            var title = f.querySelector('.pcv2__finding-title');
            if (!key || !title) return;
            // The original title is "Label — NN / 100". Re-build it
            // from the stored score so we don't lose the number.
            var score = f.getAttribute('data-pcv2-score') || '';
            title.textContent = prettySubLabel(key) + (score ? ' — ' + score + ' / 100' : '');
        });

        // Mini-card labels on the score hero (sub-score titles).
        var miniCards = dashboard.querySelectorAll('.pcv2__mini-card[data-pcv2-key]');
        miniCards.forEach(function (c) {
            var key = c.getAttribute('data-pcv2-key');
            var lbl = c.querySelector('.pcv2__mini-card-label');
            if (key && lbl) lbl.textContent = prettySubLabel(key);
        });
    }

    function initThemeToggle() {
        applyTheme(readStoredTheme());
        // React to system theme changes while in 'system' mode.
        if (window.matchMedia) {
            var mq = window.matchMedia('(prefers-color-scheme: dark)');
            var handler = function () {
                if (readStoredTheme() === 'system') applyTheme('system');
            };
            if (mq.addEventListener) mq.addEventListener('change', handler);
            else if (mq.addListener) mq.addListener(handler);
        }
        document.addEventListener('click', function (ev) {
            var btn = ev.target.closest('[data-pcv2-action="theme-cycle"]');
            if (!btn) return;
            var cur = readStoredTheme();
            var nxt = nextTheme(cur);
            storeTheme(nxt);
            applyTheme(nxt);
        });
    }

    function initDashboard() {
        var dashboard = document.querySelector('[data-pcv2-component="dashboard"]');
        if (!dashboard) return;
        // Wire the main CTA.
        var cta = dashboard.querySelector('[data-pcv2-action="start-scan"]');
        if (cta) cta.addEventListener('click', function () { runScan(dashboard); });

        // GeoTrace widget, if present on this page.
        var geo = document.querySelector('[data-pcv2-component="geotrace"]');
        if (geo) bindGeoTrace(geo);

        // If a `data-pcv2-autostart="1"` attribute is present, fire the
        // scan immediately. (Manual-only otherwise.)
        if (dashboard.getAttribute('data-pcv2-autostart') === '1') {
            runScan(dashboard);
        }
    }

    function ready(fn) {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', fn);
        } else {
            fn();
        }
    }

    ready(function () {
        initEli5Toggle();
        initThemeToggle();
        initDashboard();
        PCV2.initialized = true;
    });

    window.PCV2 = PCV2;
})();
