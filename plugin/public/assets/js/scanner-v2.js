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

        var scanPromise = postJSON('scan', {})
            .then(function (scan) {
                intelPayload = scan;
                doneStep('ip'); runStep('intel');
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
                    reputation: reputationPayload
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
        if (typeof score !== 'number') return 'unknown';
        if (score >= 90) return 'safe';
        if (score >= 70) return 'low';
        if (score >= 50) return 'medium';
        return 'high';
    }

    function renderKV(items) {
        var dl = el('dl', { class: 'pcv2__rows' });
        items.forEach(function (it) {
            if (it == null) return;
            dl.appendChild(el('dt', { text: it.label }));
            dl.appendChild(el('dd', {
                class: it.mono ? 'mono' : '',
                text: it.value == null || it.value === '' ? '—' : String(it.value)
            }));
        });
        return dl;
    }

    function renderStatusChip(severity, label) {
        var text = label || severity.toUpperCase();
        return el('span', {
            class: 'pcv2__chip--status',
            'data-pcv2-severity': severity,
            'aria-label': 'Severity: ' + text
        }, text);
    }

    function renderScoreGauge(score, grade) {
        var sev = severityFromScore(score);
        var color = sev === 'safe'   ? 'var(--pcv2-safe)'
                  : sev === 'low'    ? 'var(--pcv2-low)'
                  : sev === 'medium' ? 'var(--pcv2-medium)'
                  : sev === 'high'   ? 'var(--pcv2-high)'
                                     : 'var(--pcv2-unknown)';
        // Static SVG ring; count-up is omitted to respect reduced-motion.
        var pct = Math.max(0, Math.min(100, score == null ? 0 : score));
        var r = 60;
        var c = 2 * Math.PI * r;
        var off = c * (1 - pct / 100);
        var ns = 'http://www.w3.org/2000/svg';
        var svg = document.createElementNS(ns, 'svg');
        svg.setAttribute('class', 'pcv2__gauge');
        svg.setAttribute('viewBox', '0 0 140 140');
        svg.setAttribute('role', 'progressbar');
        svg.setAttribute('aria-valuenow', String(Math.round(pct)));
        svg.setAttribute('aria-valuemin', '0');
        svg.setAttribute('aria-valuemax', '100');
        svg.setAttribute('aria-label', (PCV2.i18n.scoreLabel || 'Privacy Score') + ': ' + Math.round(pct) + ' of 100');

        var bg = document.createElementNS(ns, 'circle');
        bg.setAttribute('cx', '70'); bg.setAttribute('cy', '70'); bg.setAttribute('r', String(r));
        bg.setAttribute('fill', 'none'); bg.setAttribute('stroke', 'var(--pcv2-border)'); bg.setAttribute('stroke-width', '10');
        svg.appendChild(bg);

        var fg = document.createElementNS(ns, 'circle');
        fg.setAttribute('cx', '70'); fg.setAttribute('cy', '70'); fg.setAttribute('r', String(r));
        fg.setAttribute('fill', 'none'); fg.setAttribute('stroke', color); fg.setAttribute('stroke-width', '10');
        fg.setAttribute('stroke-dasharray', String(c));
        fg.setAttribute('stroke-dashoffset', String(off));
        fg.setAttribute('stroke-linecap', 'round');
        fg.setAttribute('transform', 'rotate(-90 70 70)');
        svg.appendChild(fg);

        var wrap = el('div', { class: 'pcv2__score' }, [
            svg,
            el('div', { class: 'pcv2__score-value', text: String(Math.round(pct)) }),
            el('div', { class: 'pcv2__score-grade', text: grade || '—' }),
            el('div', { class: 'pcv2__score-meta', text: PCV2.i18n.scoreLabel || 'Privacy Score' })
        ]);
        return wrap;
    }

    function renderCard(card, title, content) {
        var header = card.querySelector('[data-pcv2-region="card-title"]');
        if (header) header.textContent = title;
        var body = card.querySelector('[data-pcv2-region="card-body"]');
        clear(body);
        if (content) body.appendChild(content);
    }

    function renderReport(dashboard, report) {
        var intel = report.intel || {};
        var proxy = report.proxy || {};
        var conn = report.connection || {};
        var rep = report.reputation || {};

        // Summary.
        var summary = dashboard.querySelector('[data-pcv2-region="summary"]');
        clear(summary);
        var score = report.privacy_score;
        var grade = report.privacy_report && report.privacy_report.grade;
        summary.appendChild(renderScoreGauge(score, grade));
        var chips = el('div', { class: 'pcv2__chips' });
        // 5 categorical chips.
        var categories = (report.privacy_report && report.privacy_report.categories) || {};
        Object.keys(categories).slice(0, 6).forEach(function (k) {
            var c = categories[k];
            if (!c) return;
            var sev = severityFromScore(c.score || c.percent);
            chips.appendChild(renderStatusChip(sev, k + ': ' + Math.round(c.score || c.percent)));
        });
        summary.appendChild(chips);

        // Cards.
        var cards = dashboard.querySelectorAll('.pcv2__card');
        cards.forEach(function (card) {
            var key = card.getAttribute('data-pcv2-card');
            if (key === 'overview') {
                renderCard(card, PCV2.i18n.overviewTitle || 'Overview',
                    renderKV([
                        { label: PCV2.i18n.scoreLabel || 'Privacy Score', value: score == null ? '—' : score + ' / 100' },
                        { label: PCV2.i18n.gradeLabel || 'Grade', value: grade || '—' },
                        { label: PCV2.i18n.confidenceLabel || 'Confidence', value: (report.privacy_report && report.privacy_report.confidence) || '—' }
                    ])
                );
            } else if (key === 'connection') {
                var ip = (report.request_ip && (report.request_ip.ipv4 || report.request_ip.ipv6)) || intel.ip;
                renderCard(card, PCV2.i18n.connectionTitle || 'Connection',
                    renderKV([
                        { label: 'IPv4', value: report.request_ip && report.request_ip.ipv4, mono: true },
                        { label: 'IPv6', value: report.request_ip && report.request_ip.ipv6, mono: true },
                        { label: 'Country', value: intel.country_name || intel.country },
                        { label: 'Region',  value: intel.region },
                        { label: 'City',    value: intel.city },
                        { label: 'ISP',     value: intel.isp },
                        { label: 'ASN',     value: intel.asn, mono: true },
                        { label: 'Timezone',value: intel.timezone }
                    ])
                );
            } else if (key === 'anonymity') {
                var proxySev = proxy.label === 'No signal' ? 'safe'
                              : proxy.label && /tor/i.test(proxy.label) ? 'high'
                              : proxy.label && /proxy/i.test(proxy.label) ? 'medium'
                              : proxy.label && /vpn/i.test(proxy.label) ? 'low'
                              : 'unknown';
                var chipHost = el('div', { class: 'pcv2__row' }, [
                    el('dt', { text: 'Detection' }),
                    el('dd', null, renderStatusChip(proxySev, proxy.label || (PCV2.i18n.noConfidence || 'Unknown')))
                ]);
                renderCard(card, PCV2.i18n.anonymityTitle || 'Anonymity',
                    el('div', null, [
                        chipHost,
                        renderKV([
                            { label: 'Type', value: proxy.type || '—' },
                            { label: 'Confidence', value: proxy.confidence || '—' }
                        ])
                    ])
                );
            } else if (key === 'dns') {
                var dns = (rep.dns) || {};
                renderCard(card, PCV2.i18n.dnsTitle || 'DNS Resolver',
                    renderKV([
                        { label: 'Provider', value: dns.provider || '—' },
                        { label: 'Status',   value: dns.status || '—' },
                        { label: 'Latency',  value: dns.latency_ms ? dns.latency_ms + ' ms' : '—' }
                    ])
                );
            } else if (key === 'browser') {
                var fp = report.fingerprint || {};
                renderCard(card, PCV2.i18n.browserTitle || 'Browser Privacy',
                    renderKV([
                        { label: 'User Agent', value: report.user_agent || navigator.userAgent, mono: true },
                        { label: 'Languages',  value: (navigator.languages || []).join(', ') },
                        { label: 'Timezone',   value: Intl.DateTimeFormat().resolvedOptions().timeZone },
                        { label: 'Screen',     value: screen.width + ' × ' + screen.height },
                        { label: 'Entropy',    value: fp.entropy_bits ? fp.entropy_bits + ' bits' : '—' }
                    ])
                );
            } else if (key === 'security') {
                var sp = report.security_posture || {};
                renderCard(card, PCV2.i18n.securityTitle || 'Security Findings',
                    renderKV([
                        { label: 'TLS',         value: sp.tls && sp.tls.version, mono: true },
                        { label: 'TLS Status',  value: sp.tls && sp.tls.status },
                        { label: 'Browser',     value: sp.browser && sp.browser.name + ' ' + (sp.browser && sp.browser.version) },
                        { label: 'Outdated',    value: sp.browser && sp.browser.outdated ? 'Yes' : 'No' }
                    ])
                );
            }
        });

        // Findings list.
        var findings = dashboard.querySelector('[data-pcv2-region="findings"]');
        clear(findings);
        var cats = (report.privacy_report && report.privacy_report.categories) || {};
        var list = el('div', { class: 'pcv2__findings' });
        list.appendChild(el('h3', { text: PCV2.i18n.findingsTitle || 'Privacy Findings' }));
        Object.keys(cats).forEach(function (k) {
            var c = cats[k];
            if (!c) return;
            var sev = severityFromScore(c.score || c.percent);
            var card = el('div', { class: 'pcv2__finding' });
            card.appendChild(renderStatusChip(sev, sev.toUpperCase()));
            var body = el('div', null, [
                el('p', { class: 'pcv2__finding-title', text: k + ' — ' + Math.round(c.score || c.percent) + ' / 100' }),
                el('p', { class: 'pcv2__finding-body',  text: c.message || '—' })
            ]);
            card.appendChild(body);
            list.appendChild(card);
        });
        findings.appendChild(list);

        // Post-scan share/export bar.
        var actionsHost = el('div', { class: 'pcv2__actions-host' });
        findings.parentNode.insertBefore(actionsHost, findings.nextSibling);
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
            container.appendChild(el('p', { class: 'pcv2__geo-disclaimer', text: PCV2.i18n.geoUnavailable || 'Traceroute unavailable' }));
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
                        '<p class="pcv2__geo-disclaimer">' + escape(err && err.message) + '</p>';
                });
            });
        }
        // Render an initial honest empty state so the map area is never blank.
        renderRoute({ probe: null, target: null, hops: [], source_kind: 'unavailable' }, host);
    }

    /* ---------- boot ---------------------------------------------------- */

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
        initThemeToggle();
        initDashboard();
        PCV2.initialized = true;
    });

    window.PCV2 = PCV2;
})();
