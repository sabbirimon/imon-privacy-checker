# Deploy IMON — Netlify / Vercel / GitHub Pages

> How to push this repo to GitHub and host IMON on a free static host
> (Netlify or Vercel), plus the recommended production target for the
> full WordPress plugin.

---

## What this repo is

IMON ships in **two halves**:

| Half | What it is | Where it can run |
|---|---|---|
| **Plugin** (PHP + JS + CSS) | The full-featured WordPress plugin with v1 + v2 scanner, GeoTrace tab, admin dashboard, logs, MaxMind integration, etc. | Any PHP 8.1+ host with MySQL/MariaDB |
| **Static demo** (HTML + JS) | A single-page demo of the scan UI that talks to a deployed IMON REST endpoint. | Any static host: Netlify, Vercel, GitHub Pages, Cloudflare Pages |

**You can't run the plugin on Netlify / Vercel** — they don't ship PHP at the edge (Vercel does via "Functions" but you'd need to wire up MySQL). For the **plugin**, point users at your WordPress site. For the **demo**, point them at your Netlify/Vercel URL.

The repo is designed so a GitHub push starts both deploys automatically.

---

## 1. Push to GitHub

### 1.1 Create the GitHub repo

1. Go to https://github.com/new
2. Name: `imon-privacy-checker` (or whatever you like — the existing remote is `sabbirimon/imon-privacy-checker` so mirror that to keep history).
3. Visibility: **Public** if you want the demo on Netlify free tier; private is fine if you don't mind paying for Netlify Pro.
4. **Do NOT** initialize with README / .gitignore / license — this repo already has all of that.
5. Click "Create repository".

### 1.2 Push the code

```bash
cd "/Users/code/Documents/browser checking WEBsite /Browser Checker"
git remote -v                      # confirm origin points at your new repo
git push -u origin main
```

If you're using a different remote:

```bash
git remote remove origin
git remote add origin git@github.com:YOUR_USER/imon-privacy-checker.git
git push -u origin main
```

That's it. CI runs automatically (see `.github/workflows/ci.yml`).

---

## 2. Deploy the static demo to Netlify

### 2.1 Connect the repo

1. Sign in to https://app.netlify.com/
2. Click "Add new site → Import an existing project → GitHub".
3. Authorize the Netlify GitHub app and pick this repo.
4. Netlify auto-detects `netlify.toml` and:
   - build command: `echo 'No build step — static demo only.'`
   - publish directory: `.` (project root)
5. Click "Deploy site".

You'll get a `https://random-name.netlify.app` URL in ~30 seconds.

### 2.2 Point at your WordPress REST endpoint

The static demo on Netlify doesn't have access to a PHP backend, so it shows the **client-side** portion of the scanner (browser fingerprint, Canvas hash, WebGL probe, WebRTC, etc.) and reads IP intel from a public mirror.

To make it use **your** WordPress REST endpoint instead of a public mirror:

1. Netlify dashboard → Site settings → Environment variables
2. Add `IMON_REST_BASE` = `https://your-wp-site.test/wp-json/privacy-checker/v1`
3. Redeploy.

### 2.3 Custom domain

1. Domain settings → Add custom domain → `example.com`
2. Netlify gives you a CNAME target; add it at your DNS provider.
3. HTTPS is automatic (Let's Encrypt).

---

## 3. Deploy the static demo to Vercel

### 3.1 Connect the repo

1. Sign in to https://vercel.com/
2. Click "Add New → Project → Import" the IMON repo.
3. Vercel auto-detects `vercel.json`. Framework: "Other".
4. Click "Deploy".

You'll get a `https://imon-privacy-checker.vercel.app` URL in ~30 seconds.

### 3.2 Environment variables + custom domain

Same as Netlify — set `IMON_REST_BASE` to your WP endpoint and `vercel domains add example.com`.

---

## 4. Deploy the **plugin** (WordPress)

The plugin needs PHP 8.1+ + MySQL/MariaDB. Recommended hosts:

| Host | Free? | Notes |
|---|---|---|
| [WordPress.com](https://wordpress.com/) | Yes (basic plan) | Cannot install custom plugins on free plan. Business plan ~$25/mo. |
| [InstaWP](https://instawp.com/) | Yes (1 free site) | Real WP install, plugins OK, great for staging. |
| [InfinityFree](https://www.infinityfree.com/) | Yes | PHP + MySQL but their free tier blocks outbound SMTP and many ports. |
| [000webhost](https://www.000webhost.com/) | Yes | PHP + MySQL. Some features paid. |
| [Hostinger](https://www.hostinger.com/) | ~$2/mo | Cheapest real hosting. |
| [DigitalOcean](https://www.digitalocean.com/) | $6/mo | VPS — full control. |
| Self-host on a Raspberry Pi | Free | Your own hardware, your own NAT. |

### 4.1 Local quick-start (no host)

The project ships with a one-shot local installer:

```bash
cd "/Users/code/Documents/browser checking WEBsite /Browser Checker"
bin/deploy.sh local                  # deploy to ./wp and start php -S 127.0.0.1:8080
bin/wp-install.sh                    # install WP + activate theme + plugin
```

After that, open http://localhost:8080/ and login at /wp-admin/ with the credentials `bin/wp-install.sh` prints.

### 4.2 Self-hosted on a real server

```bash
# On the server:
sudo apt install php8.1 php8.1-{cli,curl,mbstring,xml,zip,mysql} mysql-server nginx
# Add WP + database, then:
git clone https://github.com/YOUR_USER/imon-privacy-checker.git /opt/imon
ln -s /opt/imon/plugin /var/www/wordpress/wp-content/plugins/privacy-checker
ln -s /opt/imon/theme  /var/www/wordpress/wp-content/themes/privacy-checker-theme
cd /var/www/wordpress && sudo -u www-data wp plugin activate privacy-checker
cd /var/www/wordpress && sudo -u www-data wp theme activate privacy-checker-theme
```

See `DEPLOYMENT.md` for the full production runbook (nginx rewrite rules, SSL, MaxMind download).

---

## 5. Continuous Integration

Every push to `main` and every PR runs:

1. **PHP lint** (`php -l` on every `.php` file)
2. **PHPUnit** (against a real MySQL test DB)
3. **Playwright** (against the local WP install at :8080)

If all three pass, the PR gets a green check. See `.github/workflows/ci.yml`.

---

## 6. Recommended environment variables (for the static demo)

| Var | Purpose | Default |
|---|---|---|
| `IMON_REST_BASE` | Override the REST base URL the demo hits. | (empty — falls back to a public mirror) |

---

## 7. Troubleshooting

### "Site can't reach the REST API" on the static demo

- The plugin host must serve `Access-Control-Allow-Origin: *` (the plugin does this in `class-rest-api.php` for any origin — change it if you're worried about abuse).
- The demo host's CSP must allow `connect-src` to your REST base. Edit `netlify.toml` / `vercel.json` and redeploy.

### GitHub push rejected: file too large

Likely cause: a `.mmdb` or `.sql` file slipped into the repo. They're gitignored but a `git add -f` will force-add them.

```bash
git status --short | grep -i "\.mmdb\|\.sql"   # find the offender
git rm --cached <file>
echo "*.mmdb" >> .gitignore
git commit --amend --no-edit                  # or new commit if push hasn't gone yet
```

### Netlify build fails

Almost always: missing `package.json` script. Netlify ignores a `command = "echo ..."` when something else is broken. Check the deploy log under Deploys → failed build → "log".

### Vercel build fails

Same: check the deploy log. Vercel is more permissive about custom builders.

---

## 8. License

GPL-3.0. See `LICENSE` in repo root.
