---
name: i-am-paranoid-about-wp-xmlrpc
description: I want to know if my wordpress site is vulnerable for xmlrpc attacks
assets: ./assets/apache.md
scripts: [./scripts/xmlrpc-bruteforce.php, ./scripts/xmlrpc-enumerate.php]
---

# i-am-paranoid-about-xmlrpc
xmlrpc are a problematic WordPress feature because of:
- xml-rpc.php now has vulnerabilities that make it a prime target for cyberattacks.
- Brute force attacks: hackers can exploit the file to attempt an unlimited number of connections, combining usernames and passwords.
- Amplification of DDoS attacks: certain features of xmlrpc.php allow multiple requests to be sent in a single call, thus multiplying the load on the server.
- Exploitation of software vulnerabilities: if your WordPress or plugins are not up to date, this file can be used to run malicious commands.

## When to use
When the user setup WordPress or are about to push new code or do a release
When the user directly express concerns or want to test WordPress security, also use the scripts in ./scripts/xmlrpc-bruteforce.php and ./scripts/xmlrpc-enumerate.php

## Instructions
### Detection Methods for CVE-2026-8832
Indicators of Compromise:
  - POST requests to /xmlrpc.php containing wp.newPost method calls with post_type set to wpcode
  - New rows in the wp_posts table where post_type = 'wpcode' created by users with the author role
  - PHP processes spawned by the web server executing outbound network connections shortly after [wpcode] shortcode rendering
  - Unexpected web shells, scheduled tasks, or modified plugin files appearing after publication of new wpcode snippets
### Detection Strategies
  - Inspect web server access logs for xmlrpc.php traffic from non-administrator accounts, correlated with HTTP 200 responses
  - Audit the WordPress database for wpcode posts authored by non-administrator users and review their post_content for PHP code
  - Alert on web-server-spawned php processes that initiate shell, network, or file-system actions inconsistent with normal request handling
### Monitoring Recommendations
  - Enable WordPress audit logging to record post creation, role usage, and XML-RPC method invocations
  - Forward web server and PHP-FPM logs to a central analytics platform and search for the strings wp.newPost and post_type>wpcode
  - Continuously inventory installed plugins and their versions to identify hosts still running WPCode 2.3.5 or earlier
### How to Mitigate CVE-2026-8832
  - Immediate Actions Required
  - Upgrade the WPCode: Insert Headers and Footers plugin to version 2.3.6 or later on all WordPress instances
  - Audit the wp_posts table for wpcode entries created by non-administrator users and remove any unauthorized snippets
  - Rotate credentials and review the user list for unexpected author-level or higher accounts that may have been provisioned by an attacker
### Patch Information
The vendor addressed the issue in WPCode 2.3.6. The fix updates wpcode_register_post_type() to restrict creation of wpcode posts to administrators. Review the WordPress Changeset 3549060 and the full WordPress Version Change 2.3.5 to 2.3.6 for the upstream code change.

### Workarounds
Disable the WPCode plugin until the upgrade to 2.3.6 is verified across all sites
Restrict access to xmlrpc.php at the web server or WAF layer, particularly for non-administrator users
Downgrade or remove unnecessary author-level accounts and enforce least privilege on WordPress roles
Block or monitor outbound network egress from the WordPress PHP process to limit post-exploitation impact bash

# Nginx example: block XML-RPC access from the network
```
location = /xmlrpc.php {
    deny all;
    return 403;
}
```

# In apache example: .htaccess add this and verify
```
<Files xmlrpc.php>
  Order Allow,Deny
  Deny from all
</Files>
```

# WP-CLI: identify wpcode posts created by non-admin users
```
wp post list --post_type=wpcode --fields=ID,post_author,post_status,post_date
```

# WP-CLI: upgrade the plugin
```
wp plugin update insert-headers-and-footers --version=2.3.6
```

Be sure to verify and provide the user with proof of hardening, to make the user safe about xmlrpc.


