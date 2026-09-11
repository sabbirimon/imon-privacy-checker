# Deploying to a free PHP host (InfinityFree / 000webhost / AwardSpace)

This guide walks you through getting the Privacy Checker plugin live on
a **free** PHP host — no SSH, no composer, no credit card. The host
gives you FTP, a MySQL DB, and a free subdomain.

Total time: ~15 minutes once you have the host credentials.

---

## 1. Sign up & create a site

**InfinityFree** (recommended, easiest):
1. https://infinityfree.com → Sign up → confirm email
2. Click **Create Account** for a free hosting account
3. Pick a subdomain like `yourname.infinityfreeapp.com`
4. Wait ~1 minute for the account to provision

**000webhost**: similar flow at https://www.000webhost.com
**AwardSpace**: similar at https://www.awardspace.com

## 2. Gather your FTP + DB credentials

In the host's client area (cPanel-style dashboard):

| Item | Where to find it |
|---|---|
| **FTP host** | e.g. `ftpupload.net` — listed under "FTP Details" |
| **FTP user** | usually `epiz_12345678` style |
| **FTP password** | you set this during signup |
| **FTP path** | usually `/htdocs/` (InfinityFree) or `/public_html/` (others) |
| **MySQL host** | e.g. `sql123.epizy.com` |
| **MySQL DB** | usually the same as the FTP user with a suffix |
| **MySQL user** | usually same as FTP user |
| **MySQL password** | you set this when creating the DB |

## 3. Install WordPress

InfinityFree has Softaculous in cPanel:
1. cPanel → **Softaculous** → **WordPress** → Install Now
2. Protocol: `https://`
3. Domain: pick your subdomain
4. Admin username / password → email
5. Install → wait 30s → visit your URL

Manual install is also fine — same WP zip you already have works.

## 4. Install lftp on your Mac

```bash
brew install lftp
```

(`brew` is the macOS package manager; install it from https://brew.sh
if you don't already have it.)

## 5. Set up `.env`

```bash
cd '/Users/code/Documents/browser checking WEBsite /Browser Checker'
cp .env.example .env
$EDITOR .env   # nano, vim, TextEdit, whatever
```

Fill in:

```ini
FTP_HOST=ftpupload.net
FTP_USER=epiz_12345678
FTP_PASS=your-ftp-password
FTP_PLUGIN_DIR=/htdocs/wp-content/plugins
WP_SITE_URL=https://yourname.infinityfreeapp.com
```

The `FTP_PLUGIN_DIR` is **always** `${wp-content-dir}/plugins` on the
remote. On InfinityFree that's `/htdocs/wp-content/plugins` because
WP lives at `/htdocs/`. On 000webhost it's `/public_html/wp-content/plugins`.

## 6. Deploy

```bash
bin/deploy.sh ftp
```

Expected output:
- composer install runs locally (builds `vendor/`)
- plugin + theme get mirrored over FTP
- a smoke-test passes against your live URL
- the admin panel links are printed at the end

## 7. Activate the plugin

Log into your live site's wp-admin:
1. https://yourname.infinityfreeapp.com/wp-admin
2. **Plugins** → **Privacy Checker** → **Activate**
3. **Appearance** → **Themes** → **Privacy Checker Theme** → **Activate**

That's it. The plugin is live.

## 8. Free-host gotchas

- **MaxMind GeoLite2 .mmdb files** — can't be uploaded via the wp-admin
  uploader on free hosts (most disable that route for security). Either:
  - Skip the GeoIP path entirely (the plugin gracefully falls back to
    ip-api.com / ipinfo.io / IP2Location web APIs).
  - Or upload the .mmdb manually via FTP to `/htdocs/wp-content/uploads/maxmind/`.
- **Daily hit limits** — InfinityFree caps at ~50,000 hits/day. Plenty
  for personal use, low for public traffic.
- **Disabled PHP functions** — `exec`, `shell_exec`, `proc_open`, and
  friends are usually disabled. The plugin doesn't use them; the only
  feature that needs shell is `traceroute` (which is also disabled in
  the v2 inspector with a friendly "paste your own traceroute" hint).
- **Composer-free** — we ship `vendor/` pre-built in the release so
  the remote doesn't need composer. After every plugin update, just
  re-run `bin/deploy.sh ftp`.

## 9. Updating

After you make local changes:

```bash
git pull                                      # if collaborating
bin/deploy.sh ftp                             # ships new version
```

Free hosts re-cache aggressively. If a change doesn't show up:
- Hard refresh browser (Cmd+Shift+R)
- Or trigger a flush in the host's cPanel → "Clear Cache"

## 10. Rollback

The deploy script prints a rollback one-liner at the end. Save it
next to the deploy log:

```bash
# Example rollback (re-deploys the previous known-good release):
bin/deploy.sh zip /tmp/release-2026-09-12.zip
# then upload that zip via File Manager and overwrite plugin/theme dirs
```
