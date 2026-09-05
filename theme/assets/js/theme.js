/**
 * Privacy Checker theme — minimal interactivity.
 *
 * - Mobile nav toggle.
 * - Light / dark theme toggle (persisted in localStorage).
 */
(function () {
    'use strict';

    var STORAGE_KEY = 'pc-theme';

    function currentTheme() {
        return document.documentElement.getAttribute('data-pc-theme') || 'light';
    }

    function applyTheme(theme) {
        var prev = document.documentElement.getAttribute('data-pc-theme');
        document.documentElement.setAttribute('data-pc-theme', theme);
        try { localStorage.setItem(STORAGE_KEY, theme); } catch (e) { /* ignore */ }
        var btn = document.querySelector('[data-pc-action="theme-toggle"]');
        if (btn) {
            btn.setAttribute('aria-pressed', theme === 'dark' ? 'true' : 'false');
            btn.setAttribute('aria-label',
                theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'
            );
        }
        var meta = document.querySelector('meta[name="theme-color"]');
        if (meta) {
            meta.setAttribute('content', theme === 'dark' ? '#143b52' : '#17a2b8');
        }
        // Color-change shine pulse on the header.
        if (prev !== theme) {
            var header = document.querySelector('.pc-header');
            if (header) {
                header.classList.remove('is-changing');
                // Force reflow so the animation can replay.
                void header.offsetWidth;
                header.classList.add('is-changing');
                setTimeout(function () { header.classList.remove('is-changing'); }, 700);
            }
        }
    }

    document.addEventListener('DOMContentLoaded', function () {
        // Mobile nav
        var navToggle = document.querySelector('.pc-nav-toggle');
        var nav = document.getElementById('pc-primary-nav');
        if (navToggle && nav) {
            navToggle.addEventListener('click', function () {
                var open = nav.classList.toggle('is-open');
                navToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
            });
        }

        // Theme toggle
        var themeBtn = document.querySelector('[data-pc-action="theme-toggle"]');
        if (themeBtn) {
            // Sync initial state from current attribute
            applyTheme(currentTheme());
            themeBtn.addEventListener('click', function () {
                var next = currentTheme() === 'dark' ? 'light' : 'dark';
                applyTheme(next);
            });
        }
    });
})();
