#!/bin/bash
# WP install + activate theme/plugin for the Privacy Checker project.
set -e

cd "$(dirname "$0")/.."

echo "=== Step 1: DB check ==="
mysql -uroot wp_privacy_checker -e "SHOW TABLES;" 2>&1 | head -3

echo "=== Step 2: Symlink plugin + theme into wp/wp-content ==="
mkdir -p wp/wp-content/plugins wp/wp-content/themes
if [ ! -e wp/wp-content/plugins/privacy-checker ]; then
    ln -s "$(pwd)/plugin" wp/wp-content/plugins/privacy-checker
fi
if [ ! -e wp/wp-content/themes/privacy-checker-theme ]; then
    ln -s "$(pwd)/theme" wp/wp-content/themes/privacy-checker-theme
fi
echo "Plugin symlink: $(readlink wp/wp-content/plugins/privacy-checker 2>&1)"
echo "Theme symlink:  $(readlink wp/wp-content/themes/privacy-checker-theme 2>&1)"

echo "=== Step 3: WP core install (only if not already installed) ==="
if ! mysql -uroot wp_privacy_checker -e "SHOW TABLES LIKE 'wp_options';" 2>/dev/null | grep -q wp_options; then
    php tools/wp-cli-phar --path=wp core install \
        --url=http://localhost:8080 \
        --title="Privacy Checker" \
        --admin_user=admin \
        --admin_password=admin \
        --admin_email=admin@example.test \
        --skip-email 2>&1 || true
else
    echo "wp_options exists, skipping install"
fi

echo "=== Step 4: Activate theme ==="
php tools/wp-cli-phar --path=wp theme activate privacy-checker-theme 2>&1 || true

echo "=== Step 5: Activate plugin ==="
php tools/wp-cli-phar --path=wp plugin activate privacy-checker 2>&1 || true

echo "=== Step 6: Verify ==="
php tools/wp-cli-phar --path=wp plugin list 2>&1
php tools/wp-cli-phar --path=wp theme list 2>&1

echo "=== Step 7: Create uploads dir + .htaccess (under wp/wp-content/) ==="
mkdir -p wp/wp-content/uploads/maxmind
cat > wp/wp-content/uploads/.htaccess <<'EOF'
# Deny direct HTTP access to MaxMind database files.
<FilesMatch "\.(mmdb|tar\.gz|tar|zip)$">
    Require all denied
</Files>
EOF
cat > wp/wp-content/uploads/maxmind/.htaccess <<'EOF'
Require all denied
EOF

echo "=== Step 8: Start PHP server in background ==="
if ! pgrep -f "php -S 127.0.0.1:8080" > /dev/null; then
    cd wp && nohup php -S 127.0.0.1:8080 -t . > /tmp/wp-server.log 2>&1 &
    disown
    echo "Server PID: $!"
    sleep 2
else
    echo "Server already running on :8080"
fi

echo "=== Step 9: HTTP smoke tests ==="
echo "--- Homepage ---"
curl -s -o /tmp/home.html -w "HTTP %{http_code}\n" http://127.0.0.1:8080/ 2>&1
head -c 400 /tmp/home.html 2>&1

echo ""
echo "--- /wp-json/privacy-checker/v1/scan/ip ---"
curl -s "http://127.0.0.1:8080/?rest_route=/privacy-checker/v1/scan/ip" 2>&1 | head -3

echo ""
echo "--- /wp-json/privacy-checker/v1/lookup/ip?ip=1.1.1.1 ---"
curl -s -G 'http://127.0.0.1:8080/index.php' \
    --data-urlencode 'rest_route=/privacy-checker/v1/lookup/ip' \
    --data-urlencode 'ip=1.1.1.1' 2>&1 | head -3

echo ""
echo "--- /wp-json/privacy-checker/v1/settings (no auth) ---"
curl -s "http://127.0.0.1:8080/?rest_route=/privacy-checker/v1/settings" 2>&1 | head -3

echo "=== Step 10: Diagnostics probes (Phase 8) ==="
echo "--- /scan/dns-test/run ---"
curl -s -G 'http://127.0.0.1:8080/index.php' \
    --data-urlencode 'rest_route=/privacy-checker/v1/scan/dns-test/run' \
    -w "\nHTTP %{http_code}\n" 2>&1 | head -2

echo "--- /scan/ping?target=cloudflare.com:443 ---"
curl -s -G 'http://127.0.0.1:8080/index.php' \
    --data-urlencode 'rest_route=/privacy-checker/v1/scan/ping' \
    --data-urlencode 'target=cloudflare.com:443' \
    -w "\nHTTP %{http_code}\n" 2>&1 | head -2

echo "--- /scan/port (self, 443) ---"
curl -s -X POST 'http://127.0.0.1:8080/?rest_route=/privacy-checker/v1/scan/port' \
    -H "Content-Type: application/json" \
    -d '{"host":"127.0.0.1","port":8080}' \
    -w "\nHTTP %{http_code}\n" 2>&1 | head -2

echo "--- /scan/port (denied: 169.254.169.254) ---"
curl -s -X POST 'http://127.0.0.1:8080/?rest_route=/privacy-checker/v1/scan/port' \
    -H "Content-Type: application/json" \
    -d '{"host":"169.254.169.254","port":80}' \
    -w "\nHTTP %{http_code}\n" 2>&1 | head -2

echo "--- /scan (full report incl. privacy_report) ---"
curl -s -X POST 'http://127.0.0.1:8080/?rest_route=/privacy-checker/v1/scan' \
    -H "Content-Type: application/json" \
    -d '{}' \
    -w "\nHTTP %{http_code}\n" 2>&1 | python3 -c "import json,sys;d=json.loads(sys.stdin.read().split('HTTP')[0]);pr=d.get('privacy_report',{});print('overall:',pr.get('overall'),'grade:',pr.get('grade'),'confidence:',pr.get('confidence'),'cats:',list((pr.get('categories') or {}).keys()))"

echo "=== Done ==="
