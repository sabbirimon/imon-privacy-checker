# Deploy to InfinityFree — Quick Guide

Your setup:
- Domain: `https://imon.infinityfree.me`
- FTP host: `imon.infinityfree.me` (blocked from our Mac — use File Manager instead)
- WP admin URL (after install): `https://imon.infinityfree.me/wp-admin/`
- WP admin user: `admin`
- WP admin password: `4y%ExIPDXy`

Files already prepared in `/tmp/`:
- `/tmp/pc-plugin.zip` (5.0 MB — the Privacy Checker plugin)
- `/tmp/pc-theme.zip` (18 KB — the Privacy Checker theme)

---

## Step 1 — Finish the WP install

You're already on the Softaculous install form. Everything is filled correctly:

| Field | Value |
|---|---|
| Choose Domain | `imon.infinityfree.me` ✓ |
| In Directory | **leave blank** (empty box = root install) |
| Version | `7.0.2` ✓ |
| Admin Username | `admin` ✓ |
| Admin Password | `4y%ExIPDXy` ✓ (Strong 65/100) |
| Admin Email | `admin@imon.infinityfree.me` ✓ |

Click the **blue Install button at the bottom**. Wait ~30s.

You'll see a success page. The URL shown will be:
`https://imon.infinityfree.me/wp-admin/`

Bookmark that. Login with `admin` / `4y%ExIPDXy`.

---

## Step 2 — Open cPanel File Manager

1. Go to https://cpanel.infinityfree.com (or your client-area → cPanel link)
2. Login with the **same account** as the FTP (different password — the one you set when signing up)
3. Click **File Manager**
4. When prompted to pick a folder, choose **`htdocs`** — this is your WP root
5. You'll see WP's files: `wp-admin/`, `wp-content/`, `wp-includes/`, `index.php`, etc.

---

## Step 3 — Upload the plugin

1. Inside `htdocs`, double-click `wp-content/` to enter it
2. Double-click `plugins/` to enter it
3. You should see `akismet/` and `hello.php` (default WP plugins)
4. At the top toolbar, click **Upload**
5. Click **Select File** or drag-drop **`/tmp/pc-plugin.zip`** from Finder
6. Wait for upload to finish (5 MB, ~30 seconds on typical home broadband)
7. Click **Back to /htdocs/wp-content/plugins/** (link in the upload screen)
8. **Right-click** the new `pc-plugin.zip` → **Extract**
9. Confirm extraction destination: `/htdocs/wp-content/plugins/`
10. After extraction, you'll have a folder named `plugin/`. **Rename it to `privacy-checker`** (right-click → Rename).
11. **Delete `pc-plugin.zip`** (right-click → Delete) — keeping it on the server is a security risk.

Final state should look like:

```
/htdocs/wp-content/plugins/
├── akismet/
├── hello.php
└── privacy-checker/      ← your plugin
    ├── privacy-checker.php
    ├── composer.json
    ├── vendor/
    ├── admin/
    ├── includes/
    └── public/
```

---

## Step 4 — Upload the theme

1. In File Manager, navigate to `/htdocs/wp-content/themes/`
2. Upload **`/tmp/pc-theme.zip`**
3. Extract it — you'll get a folder called `theme/`
4. Rename it to `privacy-checker-theme`
5. Delete `pc-theme.zip`

---

## Step 5 — Activate

1. Open `https://imon.infinityfree.me/wp-admin/`
2. Login: `admin` / `4y%ExIPDXy`
3. **Appearance → Themes** → hover "Privacy Checker Theme" → **Activate**
4. **Plugins** → find "Privacy Checker — IMON" → **Activate**

That's it. The site is live.

---

## Step 6 — Verify

Visit `https://imon.infinityfree.me/` — you should see the Privacy Checker landing page.

The plugin runs entirely from the server, so IP scanning, GeoIP lookups, and REST endpoints all work dynamically.

---

## If something goes wrong

- **Plugin activation error**: open `https://imon.infinityfree.me/wp-admin/` → **Plugins → Plugin File Editor** is blocked on free hosts. Check the error via **Plugins → Add New → Commercial** tab (no, that's a joke). Real path: cPanel → File Manager → `htdocs/wp-content/plugins/privacy-checker/` and check for missing files. Most common cause: extraction failed midway. Re-upload and re-extract.
- **500 Internal Server Error**: cPanel → File Manager → `htdocs/wp-content/debug.log` (if you enabled WP_DEBUG_LOG) — open it in cPanel's text editor to see the PHP fatal.
- **MaxMind upload**: skip it. The plugin gracefully falls back to `ip-api.com` / `ipinfo.io` / `IP2Location` web APIs when no .mmdb file is present. Configure providers at `https://imon.infinityfree.me/wp-admin/admin.php?page=privacy-checker#/providers`.
