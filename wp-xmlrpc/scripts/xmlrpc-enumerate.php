#!/usr/bin/env php
<?php
//
// PoC: WordPress XML-RPC capability/method enumeration
// Source for methods: https://codex.wordpress.org/XML-RPC_WordPress_API
//
// Usage: php enumerate.php -t <url-till-xmlrpc.php> [-u user -p pass]
//

$options = getopt('t:u:p:');

if (!isset($options['t'])) {
    echo "Usage:\n";
    echo "  php enumerate.php -t <url to xmlrpc.php> [-u username -p password]\n";
    exit(1);
}

$target   = $options['t'];
$username = isset($options['u']) ? $options['u'] : null;
$password = isset($options['p']) ? $options['p'] : null;

// List from codex.wordpress.org/XML-RPC_WordPress_API 2026-09-12
$known_methods = array(
    // Core (WordPress API)
    'wp.getUsersBlogs', 'wp.getPost', 'wp.getPosts', 'wp.newPost',
    'wp.editPost', 'wp.deletePost', 'wp.getPostType', 'wp.getPostTypes',
    'wp.getPostFormats', 'wp.getPostStatusList',
    'wp.getTaxonomy', 'wp.getTaxonomies', 'wp.getTerm', 'wp.getTerms',
    'wp.newTerm', 'wp.editTerm', 'wp.deleteTerm',
    'wp.getMediaItem', 'wp.getMediaLibrary', 'wp.uploadFile',
    'wp.getCommentCount', 'wp.getComment', 'wp.getComments',
    'wp.newComment', 'wp.editComment', 'wp.deleteComment',
    'wp.getCommentStatusList',
    'wp.getOptions', 'wp.setOptions',
    'wp.getUser', 'wp.getUsers', 'wp.getProfile', 'wp.editProfile',
    'wp.getAuthors',
    // Obsolete may be usable on older installations
    'wp.getCategories', 'wp.suggestCategories', 'wp.newCategory',
    'wp.deleteCategory', 'wp.getTags',
    'wp.getPage', 'wp.getPages', 'wp.getPageList', 'wp.newPage',
    'wp.editPage', 'wp.deletePage', 'wp.getPageStatusList',
    'wp.getPageTemplates',
    // System
    'system.listMethods', 'system.multicall',
    // Movable Type / Blogger / metaWeblog
    'mt.getRecentPostTitles', 'blogger.getUsersBlogs',
    'metaWeblog.getRecentPosts',
);

// ---------------------------------------------------------------------
// XML-RPC helpers
// ---------------------------------------------------------------------
function xmlrpc_call($method, $params = array())
{
    $xml  = '<?xml version="1.0"?>' . "\n<methodCall>\n";
    $xml .= '<methodName>' . htmlspecialchars($method, ENT_XML1) . "</methodName>\n<params>\n";
    foreach ($params as $p) {
        $xml .= '<param><value><string>'
             . htmlspecialchars((string)$p, ENT_XML1)
             . "</string></value></param>\n";
    }
    $xml .= "</params>\n</methodCall>";

    $ch = curl_init($GLOBALS['target']);
    curl_setopt_array($ch, array(
        CURLOPT_POST           => true,
        CURLOPT_HTTPHEADER     => array('Content-Type: text/xml'),
        CURLOPT_POSTFIELDS     => $xml,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 15,
    ));
    $resp = curl_exec($ch);
    if ($resp === false) {
        die("Request failed: " . curl_error($ch) . "\n");
    }
    curl_close($ch);
    return $resp;
}

function parse_fault($response)
{
    // Returns array(faultCode, faultString) or null on none fault
    if (preg_match('#<name>faultCode</name>\s*<value>\s*<int>(\d+)</int>#i', $response, $m)) {
        $code = (int)$m[1];
        preg_match('#<name>faultString</name>\s*<value>(.*?)</value>#is', $response, $m2);
        $str = isset($m2[1]) ? strip_tags(trim($m2[1])) : '';
        return array($code, $str);
    }
    return null;
}

// ---------------------------------------------------------------------
// Step 1: system.listMethods
// ---------------------------------------------------------------------
echo "[*] Querying system.listMethods at $target\n";
$resp = xmlrpc_call('system.listMethods');
$listed = array();
if (preg_match_all('#<string>([a-zA-Z0-9_.]+)</string>#', $resp, $m)) {
    $listed = $m[1];
    echo "[+] Server reports " . count($listed) . " methods via system.listMethods\n";
} else {
    echo "[-] system.listMethods unavailable (" . trim(strip_tags($resp)) . ")\n";
    echo "[*] Falling back to active probing only\n";
}
$listed_map = array_flip($listed);

// ---------------------------------------------------------------------
// Step 2: Clasify every known method
// ---------------------------------------------------------------------
echo "\n[*] Probing known WordPress XML-RPC methods\n\n";
printf("%-30s %-12s %s\n", 'METHOD', 'STATUS', 'DETAIL');
echo str_repeat('-', 78) . "\n";

$results = array('exposed' => array(), 'requires_auth' => array(), 'blocked' => array());

foreach ($known_methods as $method) {
    $status = null; $detail = '';

    if (isset($listed_map[$method])) {
        // Listed by server -> exists. Try if auth is needed
        $resp = xmlrpc_call($method, array('', ''));
        $fault = parse_fault($resp);
        if ($fault !== null) {
            list($code, $str) = $fault;
            $status = (stripos($str, 'username') !== false || stripos($str, 'password') !== false
                       || stripos($str, 'Incorrect') !== false || stripos($str, 'authenticat') !== false)
                       ? 'AUTH' : 'EXPOSED';
            $detail = $str;
        } else {
            $status = 'EXPOSED';
            $detail = 'returned data without fault';
        }
    } else {
        // Not listed -> probe if active, to seperate actuve but hidden from removed
        $resp = xmlrpc_call($method, array('', ''));
        $fault = parse_fault($resp);
        if ($fault === null) {
            $status = 'EXPOSED';
            $detail = 'responded without fault';
        } else {
            list($code, $str) = $fault;
            if (stripos($str, 'does not exist') !== false
                || stripos($str, 'not available') !== false
                || stripos($str, 'Invalid method') !== false
                || $code === 405) {
                $status = 'BLOCKED';
                $detail = $str;
            } else {
                // Parameter-/auth-errors -> methods exists, just not listed
                $status = 'EXPOSED';
                $detail = $str . ' (not listed, but reachable)';
            }
        }
    }

    printf("%-30s %-12s %s\n", $method, $status, substr($detail, 0, 40));
    $results[strtolower($status)][] = $method;
}

// ---------------------------------------------------------------------
// SUMMARY
// ---------------------------------------------------------------------
echo "\n" . str_repeat('=', 78) . "\nSUMMARY\n" . str_repeat('=', 78) . "\n";
echo "Exposed / reachable:   " . count($results['exposed']) . "\n";
echo "Requires auth:         " . count($results['requires_auth']) . "\n";
echo "Blocked / removed:     " . count($results['blocked']) . "\n\n";

if (empty($results['blocked']) && !empty($results['exposed'])) {
    echo "[!] All probed methods reachable - xmlrpc.php is fully exposed.\n";
    echo "    Attack surface includes: " . implode(', ', array_slice($results['exposed'], 0, 8)) . "...\n";
}
if (isset($listed_map['system.multicall'])) {
    echo "[!] system.multicall is available - enables credential stuffing (up to ~199\n";
    echo "    credential pairs per request, bypassing login rate limits).\n";
}
echo "\n";

