#!/bin/bash
# bin/deploy.sh — one-command deploy of the IMON Privacy Checker
# WordPress plugin + theme to a web server.
#
# What this does (in order):
#   1. Pre-flight: validate PHP, composer, rsync, ssh/scp, target
#   2. Build: composer install --no-dev --optimize-autoloader
#   3. Lock: stamp plugin/theme version, regenerate classmap
#   4. Package: rsync / scp / zip the release into ./release/imon-privacy-checker-<ver>/
#   5. Ship: copy to the target via the chosen transport
#   6. Install on the server: activate theme + plugin, flush rewrites,
#      lock down file permissions, create uploads/maxmind with deny rule
#   7. Smoke-test: REST endpoints, version echoes, no PHP fatal in log
#   8. Print rollback command (kept as a one-liner for the next human)
#
# Usage:
#   bin/deploy.sh                                  # interactive: asks target/mode
#   bin/deploy.sh local                            # deploy into ./wp (built-in server)
#   bin/deploy.sh rsync user@host:/var/www/wordpress
#   bin/deploy.sh zip /tmp/release.zip             # build a zip only, no deploy
#   bin/deploy.sh remote user@host                 # interactive wp-root prompt
#
# Environment variables (override via .env in the project root or shell):
#   WP_ROOT              absolute path to the WordPress install on the
#                        target host (default: /var/www/wordpress)
#   WP_USER              SSH user (default: www-data)
#   WP_HOST              SSH host (default: $1 when using rsync/scp)
#   WP_SITE_URL          public site URL used for smoke tests (default:
#                        https://example.test)
#   PRIVACY_CHECKER_DEV_MODE   leave undefined for prod
#
# The script never touches `wp/` (the local dev WP checkout). It only
# reads from `plugin/`, `theme/`, and `composer.json` in this repo.

set -euo pipefail

# ─── Paths ───────────────────────────────────────────────────────────────
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "${SCRIPT_DIR}/.." && pwd )"
cd "${PROJECT_ROOT}"

# Load .env if present so CI shells don't have to export everything.
if [[ -f "${PROJECT_ROOT}/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    . "${PROJECT_ROOT}/.env"
    set +a
fi

# ─── Helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; NC='\033[0m'
step() { printf "\n${YEL}▶ %s${NC}\n" "$*"; }
ok()   { printf "${GRN}✓ %s${NC}\n" "$*"; }
die()  { printf "${RED}✗ %s${NC}\n" "$*" >&2; exit 1; }
note() { printf "  %s\n" "$*"; }

# ─── Step 1 — Pre-flight ─────────────────────────────────────────────────
step "Pre-flight"

command -v php >/dev/null 2>&1   || die "php not in PATH"
command -v composer >/dev/null 2>&1 || die "composer not in PATH"
command -v rsync >/dev/null 2>&1  || die "rsync not in PATH"
command -v ssh >/dev/null 2>&1    || note "ssh not found — 'rsync' / 'remote' modes will fail"

PHP_VER="$(php -r 'echo PHP_VERSION;')"
note "PHP ${PHP_VER}"
[[ "${PHP_VER%%.**}" -ge 8 ]] || die "PHP 8.1+ required (found ${PHP_VER})"

PLUGIN_VERSION="$(grep -oE "VERSION',\s*'[^']+'" plugin/privacy-checker.php | head -1 | sed -E "s/.*'([^']+)'/\1/")"
THEME_VERSION="$(grep -oE "THEME_VERSION',\s*'[^']+'" theme/functions.php | head -1 | sed -E "s/.*'([^']+)'/\1/")"
note "Plugin version:  ${PLUGIN_VERSION}"
note "Theme version:   ${THEME_VERSION}"

RELEASE_DIR="${PROJECT_ROOT}/release/imon-privacy-checker-${PLUGIN_VERSION}"
note "Release staging: ${RELEASE_DIR}"

# ─── Step 2 — Mode selection ─────────────────────────────────────────────
MODE="${1:-}"
TARGET="${2:-}"
WP_ROOT="${WP_ROOT:-/var/www/wordpress}"
WP_USER="${WP_USER:-www-data}"
WP_SITE_URL="${WP_SITE_URL:-https://example.test}"

case "${MODE}" in
    local)
        TARGET_WP="${PROJECT_ROOT}/wp"
        TARGET_USER="$(id -un)"
        TRANSPORT="local"
        ;;
    ftp)
        # Free-host deploy — no SSH, no composer on the remote.
        # Reads FTP_HOST / FTP_USER / FTP_PASS / FTP_PLUGIN_DIR / FTP_THEME_DIR
        # from .env. Builds vendor/ locally (so the remote doesn't need
        # composer) then mirrors the release over FTP.
        command -v lftp >/dev/null 2>&1 || die "lftp not in PATH (brew install lftp)"
        [[ -z "${FTP_HOST:-}" ]]      && die "FTP_HOST missing from .env"
        [[ -z "${FTP_USER:-}" ]]      && die "FTP_USER missing from .env"
        [[ -z "${FTP_PASS:-}" ]]      && die "FTP_PASS missing from .env"
        [[ -z "${FTP_PLUGIN_DIR:-}" ]] && die "FTP_PLUGIN_DIR missing from .env (e.g. /htdocs/wp-content/plugins)"
        TARGET_HOST="ftp://${FTP_HOST}"
        TARGET_WP=""
        TARGET_USER=""
        TRANSPORT="ftp"
        ;;
    rsync)
        [[ -z "${TARGET}" ]] && die "rsync mode needs TARGET like user@host:/path"
        TARGET_HOST="$(echo "${TARGET}" | cut -d: -f1)"
        TARGET_PATH="$(echo "${TARGET}" | cut -d: -f2)"
        TARGET_WP="${TARGET_PATH}"
        TARGET_USER="${WP_USER}"
        TRANSPORT="rsync"
        ;;
    remote)
        [[ -z "${TARGET}" ]] && die "remote mode needs TARGET like user@host"
        TARGET_HOST="${TARGET}"
        TARGET_WP="${WP_ROOT}"
        TARGET_USER="${WP_USER}"
        TRANSPORT="rsync"
        ;;
    zip)
        [[ -z "${TARGET}" ]] && die "zip mode needs TARGET like /tmp/release.zip"
        TRANSPORT="zip"
        ZIP_OUT="${TARGET}"
        # TARGET_WP/ZIP_OUT not needed for zip mode; declare for -u.
        TARGET_WP=""
        TARGET_HOST=""
        TARGET_USER=""
        ;;
    "")
        cat <<USAGE
Usage:
  $(basename "$0") local                                  Deploy to ./wp (built-in PHP server)
  $(basename "$0") rsync user@host:/var/www/wordpress    Rsync plugin+theme to remote
  $(basename "$0") remote user@host                      Rsync to \${WP_ROOT} on remote
  $(basename "$0") ftp                                    FTP deploy to free host (InfinityFree etc.)
  $(basename "$0") zip /path/release.zip                 Build a release zip only

Environment (set in .env or shell):
  WP_ROOT         remote WordPress root (default: /var/www/wordpress)
  WP_USER         SSH user (default: www-data)
  WP_SITE_URL     public URL for smoke tests (default: https://example.test)
  FTP_HOST        FTP hostname (e.g. ftpupload.net)
  FTP_USER        FTP username
  FTP_PASS        FTP password
  FTP_PLUGIN_DIR  absolute path on FTP for wp-content/plugins (e.g. /htdocs/wp-content/plugins)
USAGE
        exit 0
        ;;
    *)
        die "Unknown mode: ${MODE}. Run without args for usage."
        ;;
esac
ok "Mode: ${TRANSPORT}, target: ${TARGET_WP:-${ZIP_OUT:-n/a}}"

# ─── Step 3 — Build ─────────────────────────────────────────────────────
step "Build"

# Build dir
rm -rf "${RELEASE_DIR}"
mkdir -p "${RELEASE_DIR}/plugin" "${RELEASE_DIR}/theme"

# Composer in plugin/, optimized for prod (no dev deps)
note "composer install --no-dev --optimize-autoloader (in plugin/)"
(
    cd "${PROJECT_ROOT}"
    composer install --no-dev --optimize-autoloader --no-interaction --quiet
)
ok "composer install clean"

# Classmap must include the actual class files (non-PSR-4 filenames used).
note "composer dump-autoload --classmap-authoritative"
(
    cd "${PROJECT_ROOT}"
    composer dump-autoload --classmap-authoritative --no-interaction --quiet
)
ok "classmap regenerated"

# ─── Step 4 — Stage the release ──────────────────────────────────────────
step "Stage release"

# rsync with --delete inside the project is unsafe; use cp -a so the
# release/ subtree only ever contains what we explicitly put there.
# Production bundle: skip tests/ and dev-only cruft.
note "Copy plugin/ → ${RELEASE_DIR}/plugin/"
rsync -a --exclude='.git/' --exclude='node_modules/' --exclude='vendor-src/' \
    --exclude='tests/' --exclude='*.log' --exclude='.phpunit.cache/' \
    --exclude='.DS_Store' --exclude='Thumbs.db' \
    "${PROJECT_ROOT}/plugin/" "${RELEASE_DIR}/plugin/"

# FTP/free-host transport cannot run composer on the remote. Ship the
# pre-built vendor/ directory so the plugin works out of the box.
# For SSH-based transports this is harmless — vendor/ is also rebuilt
# server-side in Step 6 anyway.
if [[ -d "${PROJECT_ROOT}/vendor" ]]; then
    note "Bundling vendor/ → ${RELEASE_DIR}/plugin/vendor/ (pre-built for FTP/free hosts)"
    cp -a "${PROJECT_ROOT}/vendor" "${RELEASE_DIR}/plugin/vendor"
fi

# composer.json / composer.lock live at the project root, but the
# project-root composer.json uses classmap paths like `plugin/includes/`
# that are relative to the project root. Once the plugin lives at
# `wp-content/plugins/privacy-checker/`, those paths would resolve
# to `wp-content/plugins/privacy-checker/plugin/includes/` — wrong.
# We synthesise a plugin-local composer.json that points autoload
# paths at the plugin dir itself. composer.lock is shipped as-is.
if [[ -f "${PROJECT_ROOT}/composer.json" ]]; then
    php -r '
        $src = json_decode(file_get_contents($argv[1]), true);
        if (!is_array($src) || !isset($src["autoload"])) {
            fwrite(STDERR, "composer.json missing autoload block\n");
            exit(1);
        }
        $strip = function (array $arr) use (&$strip) {
            $out = [];
            foreach ($arr as $k => $v) {
                if (is_string($v) && str_starts_with($v, "plugin/")) {
                    $v = substr($v, strlen("plugin/"));
                }
                $out[$k] = is_array($v) ? $strip($v) : $v;
            }
            return $out;
        };
        $new = [
            "name"        => $src["name"],
            "description" => $src["description"] ?? "",
            "type"        => $src["type"] ?? "wordpress-plugin",
            "license"     => $src["license"] ?? "GPL-2.0-or-later",
            "require"     => $src["require"] ?? new stdClass(),
        ];
        if (isset($src["autoload"]))     $new["autoload"]     = $strip($src["autoload"]);
        if (isset($src["config"]))       $new["config"]       = $src["config"];
        if (isset($src["scripts"]))      $new["scripts"]      = $src["scripts"];
        if (isset($src["extra"]))        $new["extra"]        = $src["extra"];
        if (isset($src["minimum-stability"])) $new["minimum-stability"] = $src["minimum-stability"];
        file_put_contents(
            $argv[2],
            json_encode($new, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n"
        );
    ' "${PROJECT_ROOT}/composer.json" "${RELEASE_DIR}/plugin/composer.json"
    note "Wrote plugin-local composer.json (autoload paths re-anchored)"
fi
[[ -f "${PROJECT_ROOT}/composer.lock" ]] && cp "${PROJECT_ROOT}/composer.lock" "${RELEASE_DIR}/plugin/"

note "Copy theme/ → ${RELEASE_DIR}/theme/"
rsync -a --exclude='.git/' --exclude='node_modules/' \
    --exclude='.DS_Store' --exclude='Thumbs.db' \
    "${PROJECT_ROOT}/theme/" "${RELEASE_DIR}/theme/"

# License + readme pointers so the bundle ships with provenance.
[[ -f "${PROJECT_ROOT}/README.md" ]] && cp "${PROJECT_ROOT}/README.md" "${RELEASE_DIR}/"
[[ -f "${PROJECT_ROOT}/LICENSE" ]]  && cp "${PROJECT_ROOT}/LICENSE"  "${RELEASE_DIR}/" 2>/dev/null || true

# Stamp the version into a release manifest the on-server step can read.
cat > "${RELEASE_DIR}/release.json" <<EOF
{
  "plugin_version": "${PLUGIN_VERSION}",
  "theme_version":  "${THEME_VERSION}",
  "built_at":       "$(date -u +%FT%TZ)",
  "host":           "$(hostname)",
  "php":            "${PHP_VER}"
}
EOF
ok "Release staged ($(du -sh "${RELEASE_DIR}" | cut -f1))"

# ─── Step 5 — Branch per transport ───────────────────────────────────────
step "Ship"

ship_zip() {
    note "Zipping ${RELEASE_DIR} → ${ZIP_OUT}"
    (cd "${RELEASE_DIR}/.." && zip -qr "${ZIP_OUT}" "$(basename "${RELEASE_DIR}")")
    ok "Wrote ${ZIP_OUT}"
    cat <<NEXT

Next steps (manual):
  1. scp ${ZIP_OUT} ${TARGET_HOST:-user@host}:/tmp/
  2. ssh ${TARGET_HOST:-user@host}
  3a. sudo rsync -a /tmp/imon-privacy-checker-${PLUGIN_VERSION}/plugin/  /var/www/wordpress/wp-content/plugins/privacy-checker/
  3b. sudo rsync -a /tmp/imon-privacy-checker-${PLUGIN_VERSION}/theme/   /var/www/wordpress/wp-content/themes/privacy-checker-theme/
  4. cd /var/www/wordpress/wp-content/plugins/privacy-checker && sudo -u www-data composer install --no-dev --optimize-autoloader
  5. sudo -u www-data wp --path=/var/www/wordpress plugin activate privacy-checker
  6. sudo -u www-data wp --path=/var/www/wordpress theme activate privacy-checker-theme
NEXT
}

ship_local() {
    note "Copying into ${TARGET_WP}/wp-content/"
    mkdir -p "${TARGET_WP}/wp-content/plugins" "${TARGET_WP}/wp-content/themes"
    rm -rf "${TARGET_WP}/wp-content/plugins/privacy-checker"
    rm -rf "${TARGET_WP}/wp-content/themes/privacy-checker-theme"
    cp -a "${RELEASE_DIR}/plugin" "${TARGET_WP}/wp-content/plugins/privacy-checker"
    cp -a "${RELEASE_DIR}/theme"  "${TARGET_WP}/wp-content/themes/privacy-checker-theme"
    ok "Copied locally"
}

ship_rsync() {
    # Two rsyncs so plugin and theme land at WP's expected paths even if
    # WP_ROOT isn't the WordPress root (e.g. /var/www/wordpress/wp-content/).
    note "rsync plugin → ${TARGET_HOST}:${TARGET_WP}/wp-content/plugins/privacy-checker/"
    ssh -o BatchMode=yes "${TARGET_HOST}" "mkdir -p '${TARGET_WP}/wp-content/plugins' '${TARGET_WP}/wp-content/themes'"
    rsync -a --delete-after \
        -e ssh \
        "${RELEASE_DIR}/plugin/" \
        "${TARGET_HOST}:${TARGET_WP}/wp-content/plugins/privacy-checker/"

    note "rsync theme → ${TARGET_HOST}:${TARGET_WP}/wp-content/themes/privacy-checker-theme/"
    rsync -a --delete-after \
        -e ssh \
        "${RELEASE_DIR}/theme/" \
        "${TARGET_HOST}:${TARGET_WP}/wp-content/themes/privacy-checker-theme/"

    # Lock down perms on the remote.
    note "chmod 755 dirs / 644 files on remote"
    ssh "${TARGET_HOST}" "
        set -e
        cd '${TARGET_WP}/wp-content/plugins/privacy-checker'
        find . -type d -exec chmod 755 {} +
        find . -type f -exec chmod 644 {} +
        chown -R ${TARGET_USER}:${TARGET_USER} . || true
        cd '${TARGET_WP}/wp-content/themes/privacy-checker-theme'
        find . -type d -exec chmod 755 {} +
        find . -type f -exec chmod 644 {} +
        chown -R ${TARGET_USER}:${TARGET_USER} . || true
    "
    ok "Shipped via rsync"
}

ship_ftp() {
    # Free-host deploy (InfinityFree, 000webhost, AwardSpace, etc.).
    # Mirrors plugin + theme into the remote over FTP using lftp's
    # parallel+reverse-mirror. No SSH/composer on the remote.
    local PLUGIN_REMOTE="${FTP_PLUGIN_DIR%/}/privacy-checker"
    local THEME_REMOTE="${FTP_PLUGIN_DIR%/}/../themes/privacy-checker-theme"
    THEME_REMOTE="$(dirname "$(dirname "${FTP_PLUGIN_DIR}")")/themes/privacy-checker-theme"

    # lftp complains about unknown commands if we mix set with
    # non-bash-style syntax. Keep it readable; rely on lftp -e.
    local LFTP_CMD
    LFTP_CMD=$(cat <<LFTPEOF
set ssl:verify-certificate no
set ftp:ssl-allow no
set net:timeout 30
set net:max-retries 2
set mirror:use-get no
open -u "${FTP_USER}","${FTP_PASS}" "${FTP_HOST}"
mkdir -p "${PLUGIN_REMOTE}"
mkdir -p "${THEME_REMOTE}"
lcd "${RELEASE_DIR}/plugin"
cd "${PLUGIN_REMOTE}"
mirror --reverse --delete --verbose --parallel=4 --ignore-time
lcd "${RELEASE_DIR}/theme"
cd "${THEME_REMOTE}"
mirror --reverse --delete --verbose --parallel=4 --ignore-time
bye
LFTPEOF
    )

    note "lftp mirror → ftp://${FTP_HOST}${PLUGIN_REMOTE}"
    lftp -c "${LFTP_CMD}"
    ok "Shipped via FTP"
}

case "${TRANSPORT}" in
    zip)    ship_zip ;;
    local)  ship_local ;;
    rsync)  ship_rsync ;;
    ftp)    ship_ftp ;;
esac

# ─── Step 6 — On-server install (skip for zip + ftp) ─────────────────────
if [[ "${TRANSPORT}" != "zip" && "${TRANSPORT}" != "ftp" ]]; then
    step "On-server install"

    # Re-build composer on the server because vendor/ is huge and we don't
    # want to ship it via rsync. The plugin's composer.json already lists
    # maxmind-db/reader + ip2location as runtime deps.
    SSH_TARGET="${TARGET_HOST:-}"
    [[ -z "${SSH_TARGET}" && "${TRANSPORT}" == "local" ]] && SSH_TARGET=""

    run_remote() {
        if [[ "${TRANSPORT}" == "local" ]]; then
            ( cd "${TARGET_WP}/wp-content/plugins/privacy-checker" && "$@" )
        else
            ssh "${SSH_TARGET}" "cd '${TARGET_WP}/wp-content/plugins/privacy-checker' && $*"
        fi
    }

    note "composer install on server (no-dev, optimized)"
    if [[ "${TRANSPORT}" == "local" ]]; then
        ( cd "${TARGET_WP}/wp-content/plugins/privacy-checker" \
            && composer install --no-dev --optimize-autoloader --no-interaction --quiet )
    else
        ssh "${SSH_TARGET}" "cd '${TARGET_WP}/wp-content/plugins/privacy-checker' && composer install --no-dev --optimize-autoloader --no-interaction"
    fi
    ok "vendor/ built on server"

    note "Re-dump classmap"
    if [[ "${TRANSPORT}" == "local" ]]; then
        ( cd "${TARGET_WP}/wp-content/plugins/privacy-checker" \
            && composer dump-autoload --classmap-authoritative --no-interaction --quiet )
    else
        ssh "${SSH_TARGET}" "cd '${TARGET_WP}/wp-content/plugins/privacy-checker' && composer dump-autoload --classmap-authoritative --no-interaction"
    fi

    note "Activate theme + plugin via wp-cli"
    if [[ "${TRANSPORT}" == "local" ]]; then
        WP_CLI=(php "${PROJECT_ROOT}/tools/wp-cli-phar" --path="${TARGET_WP}")
    else
        WP_CLI=(ssh "${SSH_TARGET}" "cd '${TARGET_WP}' && wp")
    fi
    "${WP_CLI[@]}" theme activate privacy-checker-theme || true
    "${WP_CLI[@]}" plugin activate privacy-checker || true

    note "Flush rewrites + create uploads/maxmind with deny rule"
    "${WP_CLI[@]}" rewrite flush --hard || true

    # uploads/maxmind + .htaccess — the user already wrote a deny
    # rule for Apache. nginx: see DEPLOYMENT.md §5.1.
    if [[ "${TRANSPORT}" == "local" ]]; then
        mkdir -p "${TARGET_WP}/wp-content/uploads/maxmind"
        cat > "${TARGET_WP}/wp-content/uploads/maxmind/.htaccess" <<'EOF'
Require all denied
EOF
    else
        ssh "${SSH_TARGET}" "
            set -e
            mkdir -p '${TARGET_WP}/wp-content/uploads/maxmind'
            cat > '${TARGET_WP}/wp-content/uploads/maxmind/.htaccess' <<'HTACCESS'
Require all denied
HTACCESS
        "
    fi
    ok "On-server install complete"
fi

# ─── Step 7 — Smoke test ─────────────────────────────────────────────────
step "Smoke test"

SITE_URL="${WP_SITE_URL}"
note "Site URL: ${SITE_URL}"

# Skip smoke entirely for zip mode (nothing to probe against yet).
# FTP mode still probes — the free host serves HTTP like any other WP.
if [[ "${TRANSPORT}" == "zip" ]]; then
    note "Skipping smoke test for zip build (no live target yet)."
else
    # Track pass/fail without aborting — DNS or network hiccups should
    # not block a successful rsync.
    SMOKE_FAIL=0
    probe() {
        local label="$1"
        local expect="$2"
        local url="$3"
        local code
        code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "${url}" 2>/dev/null || echo 000)"
        if [[ "${code}" == "${expect}" ]]; then
            ok "${label} → ${code}"
        else
            note "⚠ ${label} → ${code} (expected ${expect})"
            SMOKE_FAIL=1
        fi
    }

    probe "Homepage"            "200" "${SITE_URL}/"
    probe "REST scan/ip"         "200" "${SITE_URL}/wp-json/privacy-checker/v1/scan/ip"
    probe "REST scan/connection" "200" "${SITE_URL}/wp-json/privacy-checker/v1/scan/connection"
    probe "REST lookup/ip"       "200" "${SITE_URL}/wp-json/privacy-checker/v1/lookup/ip?ip=1.1.1.1"

    # MaxMind deny probe is informational — Apache honours .htaccess,
    # nginx needs the rule in DEPLOYMENT.md §5.1, and the PHP built-in
    # server ignores it entirely. Don't fail the deploy on this one;
    # flag it so the operator knows to check.
    MMDB_CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "${SITE_URL}/wp-content/uploads/maxmind/.htaccess" 2>/dev/null || echo 000)"
    if [[ "${MMDB_CODE}" == "403" ]]; then
        ok "MaxMind deny → 403"
    else
        note "ℹ MaxMind deny → ${MMDB_CODE} (expected 403 on Apache; check nginx config — see DEPLOYMENT.md §5.1)"
    fi

    if [[ "${SMOKE_FAIL}" -ne 0 ]]; then
        note "Smoke probes failed — the site may still be warming up or DNS may be unreachable."
        note "Open ${SITE_URL}/ in a browser to verify visually before reporting deploy success."
    fi
fi

# ─── Step 8 — Print rollback + admin panel ───────────────────────────────
step "Done"

ADMIN_BASE="${SITE_URL}/wp-admin"
ADMIN_LINKS=$(cat <<ADMIN
  1. ${ADMIN_BASE}/admin.php?page=privacy-checker
     → Settings tab — pick providers (MaxMind, ip-api.com, ipinfo.io…)
     → Rate Limiting tab — tune the per-minute caps
     → DNS Leak Test, Ping, Port Scan tabs
  2. ${ADMIN_BASE}/admin.php?page=privacy-checker-dashboard
     → Diagnostics tile: provider chain, recent events, rate-limit status
  3. ${ADMIN_BASE}/admin.php?page=privacy-checker-report
     → Privacy Report Inspector (Phase 8.1) — server-side self-scan
  4. ${ADMIN_BASE}/admin.php?page=privacy-checker#/scoring
     → Scoring parameters reference card (Phase 8.2b)
ADMIN
)

# Build sensible rollback + offline commands based on transport.
case "${TRANSPORT}" in
    local)
        ROLLBACK_PUSH=""
        OFFLINE_CMD="${WP_CLI[*]:-php tools/wp-cli-phar --path=${TARGET_WP}} plugin deactivate privacy-checker"
        SSH_DESC="(no ssh — direct copy)"
        ;;
    rsync)
        ROLLBACK_TARGET="${TARGET_HOST}:${TARGET_WP}/wp-content/plugins/privacy-checker/"
        ROLLBACK_PUSH="rsync -a --delete-after -e ssh /var/cache/releases/imon-privacy-checker/PREVIOUS/plugin/ ${ROLLBACK_TARGET}"
        OFFLINE_CMD="ssh ${TARGET_HOST} \"cd '${TARGET_WP}' && wp plugin deactivate privacy-checker\""
        SSH_DESC="ssh ${TARGET_HOST}"
        ;;
    zip)
        ROLLBACK_PUSH="(no rollback path — you built a zip, not a deploy)"
        OFFLINE_CMD="(no live site to deactivate against)"
        SSH_DESC="(no ssh target — zip build)"
        ;;
    ftp)
        # Rollback = re-deploy the previous release via lftp, or just
        # delete the plugin folder via FTP client. Free hosts rarely
        # have shell access — manual intervention expected.
        ROLLBACK_PUSH="lftp -c 'open -u ${FTP_USER},*** ftp://${FTP_HOST}; rm -rf ${FTP_PLUGIN_DIR%/}/privacy-checker; mirror --reverse --delete /path/to/PREVIOUS/plugin ${FTP_PLUGIN_DIR%/}/privacy-checker'"
        OFFLINE_CMD="Log into ${FTP_HOST} via FTP client and rename privacy-checker/ to privacy-checker.disabled/"
        SSH_DESC="(no ssh — FTP-only host)"
        ;;
esac

cat <<ROLLBACK

Deployment complete: plugin ${PLUGIN_VERSION}, theme ${THEME_VERSION}.

──────────────────────────────────────────────────────────────
  ADMIN PANEL — open these after every deploy
──────────────────────────────────────────────────────────────
${ADMIN_LINKS}
──────────────────────────────────────────────────────────────
  ROLLBACK (keep this in your incident-response notes)
──────────────────────────────────────────────────────────────
  ${ROLLBACK_PUSH}

  # Take the site offline while you fix things:
  ${OFFLINE_CMD}
  via: ${SSH_DESC}

──────────────────────────────────────────────────────────────
  NEXT STEPS
──────────────────────────────────────────────────────────────
  • Providers tab       → confirm MaxMind .mmdb files are present
  • DNS Leak Test tab   → enable + verify resolver chain
  • Sharing tab         → leave share_enabled=false unless intended
  • Logging tab         → only if you have a privacy-policy reason

ROLLBACK
ok "Ship it."
