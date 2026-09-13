---
name: web-xmlrpc-security-audit
description: >
  Audits a web application's XML-RPC (or equivalent legacy remote-API) endpoint
  for common weakness classes (CWE-307, CWE-400, CWE-749, CWE-862, CWE-94, CWE-918).
  Applies and verifies hardening. Use when the user sets up or deploys a web app
  (WordPress, Drupal, custom PHP, etc.), mentions xmlrpc.php or a legacy RPC
  endpoint, asks for a security review, or when a CVE touching XML-RPC or
  unauthenticated/low-privilege remote execution surfaces.
assets: ./assets/apache.md
scripts: [./scripts/xmlrpc-bruteforce.php, ./scripts/xmlrpc-enumerate.php]
---

## Overview

XML-RPC and similar legacy remote-API endpoints expose a large attack surface
through a single, often publicly reachable URL. The weaknesses map to the
following CWE classes:

| CWE | Name | Manifestation in XML-RPC context |
|-----|------|----------------------------------|
| **CWE-749** | Exposed Dangerous Method or Function | `xmlrpc.php` (or equivalent) accessible without authentication or IP restriction |
| **CWE-307** | Improper Restriction of Excessive Authentication Attempts | `system.multicall` allows hundreds of credential pairs per HTTP request, defeating rate limiting |
| **CWE-400** | Uncontrolled Resource Consumption | `pingback.ping` abused to amplify outbound requests or cause application-layer DoS |
| **CWE-918** | Server-Side Request Forgery (SSRF) | `pingback.ping` and similar methods relay requests to arbitrary internal/external hosts |
| **CWE-862** | Missing Authorization | Custom post types or methods registered without capability checks allow low-privilege users to invoke privileged operations |
| **CWE-94** | Improper Control of Generation of Code (Code Injection) | User-supplied content passed to `eval()` or similar sinks after an unauthorized create/update operation |
| **CWE-521** | Weak Password Requirements | Weak credentials amplify CWE-307 exposure |

---

## When to use

- User is setting up or about to release/deploy a web app with XML-RPC or a similar legacy endpoint.
- User mentions `xmlrpc.php`, pingback abuse, brute force, or asks "is my app vulnerable?".
- A CVE or advisory touching XML-RPC, low-privilege RCE, or plugin/module misauthorization surfaces.
- User explicitly requests active testing — **only then** invoke
  `./scripts/xmlrpc-bruteforce.php` and `./scripts/xmlrpc-enumerate.php`,
  and **only against hosts the user is authorized to test**.

---

## Instructions

### Step 1 — Enumerate and assess the exposed surface (CWE-749)

1. Determine whether `xmlrpc.php` (or the equivalent endpoint) is reachable
   and responding.
2. List all advertised methods using `system.listMethods`.
3. Flag any dangerous methods present (multicall, pingback, custom
   application-specific methods).
4. Decide whether the endpoint is *required* (e.g. Jetpack, mobile app, B2B
   integration) or can be disabled entirely.

Use `./scripts/xmlrpc-enumerate.php` for automated method enumeration.

---

### Step 2 — Test for authentication brute force (CWE-307)

`system.multicall` lets an attacker submit hundreds of `wp.getUsersBlogs`
(or equivalent) calls in a single request, completely bypassing per-request
rate limiting.

- Use `./scripts/xmlrpc-bruteforce.php` to confirm the site is susceptible
  (only when authorized).
- Check whether an account-lockout or intrusion-detection mechanism intercepts
  multicall payloads specifically (most out-of-the-box lockout plugins do not).

**Mitigation**
- Disable `system.multicall` at the application layer if possible.
- Block / rate-limit `xmlrpc.php` at the web server or WAF (see Step 4).
- Enforce strong passwords and MFA (reduces CWE-521 exposure).

---

### Step 3 — Test for SSRF / DDoS amplification (CWE-918, CWE-400)

`pingback.ping` accepts an arbitrary source URL and a target URL; the server
will fetch the source on behalf of the caller, enabling:

- **SSRF**: probing internal network resources (`http://192.168.x.x/`, cloud
  metadata endpoints, etc.).
- **Amplification DDoS**: using the server as a relay to flood third-party
  targets.

**Detection**
- Send a crafted `pingback.ping` call pointing to an out-of-band callback
  server (e.g. Burp Collaborator, interactsh) to confirm outbound requests.
- Review web-server egress logs for unexpected outbound HTTP(S) from the
  PHP/app process.

**Mitigation**
- Disable the `pingback.ping` method or all of XML-RPC if not needed.
- Restrict outbound egress from the application process to required hosts only.

---

### Step 4 — Check for missing authorization on registered methods/post types (CWE-862, CWE-94)

This is the class of weaknesses most commonly exploited through XML-RPC in
plugin/module ecosystems. The pattern:

1. A plugin/module registers a new resource type or XML-RPC method.
2. The registration omits capability checks or inherits overly permissive
   defaults.
3. An attacker with a low-privilege account (author, contributor, subscriber)
   creates or modifies a resource via XML-RPC.
4. The application later processes the stored content through a sink such as
   `eval()`, `preg_replace()` with `/e`, or `call_user_func()` — producing RCE.

#### Worked example — CVE-2026-8832 (WPCode plugin ≤ 2.3.5, CVSS 8.8)

**CWE mapping**: CWE-862 (missing authorization) + CWE-94 (code injection via `eval()`).

**Root cause**: `wpcode_register_post_type()` registers the `wpcode` custom
post type without a `capability_type` restriction. WordPress falls back to
default post capabilities for all creation paths, including XML-RPC
`wp.newPost`. An author-level account can create a `wpcode` post whose
`post_content` is later executed via `eval()` in `run_eval()` when the
`[wpcode]` shortcode renders it.

**Indicators of Compromise**
- POST requests to `/xmlrpc.php` containing `wp.newPost` with `post_type=wpcode`.
- Rows in `wp_posts` with `post_type='wpcode'` authored by non-administrator users.
- PHP-FPM / web-server processes making outbound connections shortly after `[wpcode]` shortcode rendering.
- Unexpected web shells, cron entries, or modified files appearing after a new `wpcode` snippet is published.

**Detection**
```bash
# Find wpcode posts by non-admin authors
wp post list --post_type=wpcode --fields=ID,post_author,post_status,post_date

# Grep access logs for xmlrpc.php hits returning HTTP 200
grep 'xmlrpc.php' /var/log/nginx/access.log | grep ' 200 '
