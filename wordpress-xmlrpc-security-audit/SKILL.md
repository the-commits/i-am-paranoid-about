---
name: wordpress-xmlrpc-security-audit
description: Audits a WordPress site's XML-RPC (xmlrpc.php) exposure, checks for CVE-2026-8832 (WPCode plugin RCE via wp.newPost), and applies/verifies hardening. Use when the user sets up WordPress, is about to deploy/release, mentions xmlrpc.php, or asks for a WordPress security check.
assets: ./assets/apache.md
scripts: [./scripts/xmlrpc-bruteforce.php, ./scripts/xmlrpc-enumerate.php]
---

## Overview
XML-RPC (`xmlrpc.php`) is a legacy WordPress remote-API endpoint. Its main
risks are:
- **Brute force**: `system.multicall` lets an attacker try many username/password
  pairs in a single HTTP request, bypassing simple rate limiting.
- **DDoS amplification**: `pingback.ping` can be abused to relay/amplify
  requests against third-party targets.
- **Plugin RCE via XML-RPC**: outdated plugins that expose custom post types
  through `wp.newPost` without proper capability checks can allow authenticated
  low-privilege users to plant executable content (e.g. CVE-2026-8832).

## When to use
- User is setting up a new WordPress site, or about to push code / do a release.
- User mentions `xmlrpc.php`, brute force, pingback DDoS, or asks "is my WordPress vulnerable?".
- User explicitly wants active testing — only then invoke `./scripts/xmlrpc-bruteforce.php`
  and `./scripts/xmlrpc-enumerate.php`, and only against sites the user is authorized to test.

## Instructions

### Step 1 — Baseline hardening (always applicable)
Confirm whether XML-RPC is needed (Jetpack, the WordPress mobile app, and some
pingback workflows require it). If not needed, disable/block it entirely.

### Step 2 — Check for CVE-2026-8832 (WPCode plugin)
Applies only if the site runs **WPCode – Insert Headers and Footers + Custom
Code Snippets** (plugin slug `insert-headers-and-footers`), version **≤ 2.3.5**
(CVSS 8.8). Root cause: `wpcode_register_post_type()` registers the `wpcode`
custom post type without a `capability_type`/capability restriction, so
WordPress falls back to default post capabilities for *all* creation paths,
including XML-RPC `wp.newPost`. An author-level (or higher) account can create
a `wpcode` post whose content is later executed via `eval()` in `run_eval()`
when rendered through the `[wpcode]` shortcode.

**Indicators of Compromise**
- POST requests to `/xmlrpc.php` containing `wp.newPost` with `post_type=wpcode`.
- New `wp_posts` rows with `post_type='wpcode'` authored by non-administrator (e.g. author-role) users.
- PHP-FPM/web-server processes making outbound network connections shortly after `[wpcode]` shortcode rendering.
- Unexpected web shells, cron entries, or modified plugin files appearing right after a new `wpcode` snippet is published.

**Detection**
- Grep access logs for `xmlrpc.php` traffic from non-admin accounts correlated with HTTP 200.
- Query `wp_posts` for `wpcode` entries by non-admin authors and review `post_content` for PHP.
- Alert on web-server-spawned PHP processes performing shell/network/filesystem actions outside normal request handling.

**Monitoring**
- Enable WordPress audit logging (post creation, role changes, XML-RPC method calls).
- Ship web server + PHP-FPM logs to a SIEM; alert on `wp.newPost` and `post_type>wpcode`.
- Inventory plugin versions continuously to catch hosts still on WPCode ≤ 2.3.5.

**Mitigation (immediate)**
1. Upgrade WPCode to **2.3.6+** on every affected site.
2. Audit `wp_posts` for `wpcode` entries by non-admins; remove unauthorized snippets.
3. Rotate credentials; review the user list for unexpected author+ accounts.

**Patch info**: fixed in WPCode 2.3.6 — `wpcode_register_post_type()` now
restricts `wpcode` post creation to administrators (Changeset 3549060).

**Workarounds** (if you cannot patch immediately)
- Disable the WPCode plugin until the 2.3.6 upgrade is verified.
- Block/restrict `xmlrpc.php` at the web server or WAF, especially for non-admin flows.
- Remove/downgrade unnecessary author-level accounts; enforce least privilege.
- Monitor/restrict outbound egress from the WordPress PHP process.

### Step 3 — Apply hardening

**Nginx** — block XML-RPC:
```nginx
location = /xmlrpc.php {
    deny all;
    return 403;
}
```

**Apache** — `.htaccess` (see `./assets/apache.md` for the full example):
```apache
<Files xmlrpc.php>
  Require all denied
</Files>
```

**WP-CLI** — find `wpcode` posts made by non-admins:
```bash
wp post list --post_type=wpcode --fields=ID,post_author,post_status,post_date
```

**WP-CLI** — patch the plugin:
```bash
wp plugin update insert-headers-and-footers --version=2.3.6
```

## Verification (provide proof to the user)
- `curl -I https://SITE/xmlrpc.php` → expect `403` after hardening.
- `wp plugin get insert-headers-and-footers --field=version` → expect `>= 2.3.6`.
- Re-run the `wp post list --post_type=wpcode ...` query → expect no unauthorized entries.
- Show before/after log or command output as evidence hardening succeeded.

