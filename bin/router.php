<?php
/**
 * Router for PHP's built-in dev server (`php -S 127.0.0.1:8080 router.php`).
 *
 * Mimics WordPress's .htaccess rewrites by routing all non-existing files
 * through index.php. PHP's built-in server doesn't natively support
 * `RewriteRule`, so we need this shim.
 *
 * Usage:
 *   cd wp && php -S 127.0.0.1:8080 ../bin/router.php
 *
 * Or invoke from anywhere with an explicit docroot:
 *   php -S 127.0.0.1:8080 -t wp bin/router.php
 */

// Document root for WP (one level up from this file if invoked from /wp).
$root = $_SERVER['DOCUMENT_ROOT'];

// If this router is being run with the WP install as the document root,
// existing static files are served directly by the built-in server.
// Otherwise route to index.php (handles permalink rewrites).
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$file = $root . $path;

if ($path !== '/' && file_exists($file) && !is_dir($file)) {
    // Let the built-in server serve the static file directly.
    return false;
}

// Otherwise, route to WordPress's front controller.
require $root . '/index.php';
