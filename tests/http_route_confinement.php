#!/usr/bin/env php
<?php

if (!function_exists('proc_open') || !function_exists('stream_socket_server')) {
    fwrite(STDERR, "SKIP: proc_open and stream sockets are required\n");
    exit(0);
}

$checks = 0;
$cookie = '';
$mutationOrigin = '';

function http_check($condition, $message)
{
    global $checks;
    $checks++;
    if (!$condition) {
        throw new RuntimeException("not ok $checks - $message");
    }
    echo "ok $checks - $message\n";
}

function http_remove_tree($path)
{
    if (is_link($path) || is_file($path)) {
        @unlink($path);
        return;
    }
    if (!is_dir($path)) return;
    foreach (scandir($path) as $name) {
        if ($name !== '.' && $name !== '..') http_remove_tree($path . '/' . $name);
    }
    @rmdir($path);
}

function http_copy_tree($source, $dest)
{
    if (is_dir($source)) {
        mkdir($dest, 0700, true);
        foreach (scandir($source) as $name) {
            if ($name !== '.' && $name !== '..' && $name !== '.git') {
                http_copy_tree($source . '/' . $name, $dest . '/' . $name);
            }
        }
    } else {
        copy($source, $dest);
    }
}

function http_request($url, $method = 'GET', $body = null, $contentType = null,
    $originMode = 'default')
{
    global $cookie, $mutationOrigin;
    $headers = array('Connection: close');
    if ($cookie !== '') $headers[] = 'Cookie: ' . $cookie;
    if ($contentType !== null) $headers[] = 'Content-Type: ' . $contentType;
    if ($method === 'POST' && $originMode !== false) {
        $origin = $originMode === 'default' ? $mutationOrigin : $originMode;
        if ($origin !== '') $headers[] = 'Origin: ' . $origin;
    }
    $options = array(
        'method' => $method,
        'ignore_errors' => true,
        'follow_location' => 0,
        'timeout' => 5,
        'header' => implode("\r\n", $headers),
    );
    if ($body !== null) $options['content'] = $body;
    $context = stream_context_create(array('http' => $options));
    $response = @file_get_contents($url, false, $context);
    $response = $response === false ? '' : $response;
    $status = 0;
    $received = isset($http_response_header) ? $http_response_header : array();
    foreach ($received as $header) {
        if (preg_match('#^HTTP/\S+ ([0-9]{3})#', $header, $match)) {
            $status = (int) $match[1];
        } elseif (preg_match('/^Set-Cookie:\s*([^;]+)/i', $header, $match)) {
            $cookie = $match[1];
        }
    }
    return array($status, $response, $received);
}

function http_tree_digest($root)
{
    $rows = array();
    $walk = function ($path, $relative) use (&$walk, &$rows) {
        $status = lstat($path);
        if ($status === false) {
            $rows[] = $relative . "\tmissing";
            return;
        }
        if (is_link($path)) {
            $rows[] = $relative . "\tlink\t" . readlink($path);
            return;
        }
        if (is_file($path)) {
            $rows[] = $relative . "\tfile\t" . hash_file('sha256', $path)
                . "\t" . ($status['mode'] & 07777);
            return;
        }
        if (is_dir($path)) {
            $rows[] = $relative . "\tdir\t" . ($status['mode'] & 07777);
            $names = scandir($path);
            foreach ($names as $name) {
                if ($name !== '.' && $name !== '..') {
                    $walk($path . '/' . $name,
                        $relative === '' ? $name : $relative . '/' . $name);
                }
            }
            return;
        }
        $rows[] = $relative . "\tother\t" . ($status['mode'] & 07777);
    };
    $walk($root, '');
    sort($rows, SORT_STRING);
    return hash('sha256', implode("\n", $rows));
}

function http_mutation_snapshot($data, $outside, $app)
{
    return hash('sha256', http_tree_digest($data) . "\n"
        . http_tree_digest($outside) . "\n"
        . http_tree_digest($app));
}

function http_rejected_without_delta($label, $expectedStatus, $url, $method,
    $body, $contentType, $originMode, $data, $outside, $app)
{
    $before = http_mutation_snapshot($data, $outside, $app);
    $response = http_request(
        $url, $method, $body, $contentType, $originMode);
    clearstatcache();
    $after = http_mutation_snapshot($data, $outside, $app);
    http_check($response[0] === $expectedStatus,
        "$label returns HTTP $expectedStatus");
    http_check($before === $after,
        "$label leaves every synthetic filesystem object unchanged");
}

function http_header_is($headers, $name, $value)
{
    foreach ($headers as $header) {
        if (stripos($header, $name . ':') === 0) {
            return trim(substr($header, strlen($name) + 1)) === $value;
        }
    }
    return false;
}

function http_header_starts_with($headers, $name, $value)
{
    foreach ($headers as $header) {
        if (stripos($header, $name . ':') === 0) {
            return strpos(trim(substr($header, strlen($name) + 1)), $value) === 0;
        }
    }
    return false;
}

function form_body($values)
{
    return http_build_query($values, '', '&');
}

function multipart_body($fields, $fileField, $filename, $contents, &$contentType)
{
    $boundary = '----tinyfm' . bin2hex(random_bytes(8));
    $lines = '';
    foreach ($fields as $name => $value) {
        $lines .= '--' . $boundary . "\r\n";
        $lines .= 'Content-Disposition: form-data; name="' . $name . '"' . "\r\n\r\n";
        $lines .= $value . "\r\n";
    }
    $lines .= '--' . $boundary . "\r\n";
    $lines .= 'Content-Disposition: form-data; name="' . $fileField
        . '"; filename="' . $filename . '"' . "\r\n";
    $lines .= "Content-Type: application/octet-stream\r\n\r\n";
    $lines .= $contents . "\r\n--" . $boundary . "--\r\n";
    $contentType = 'multipart/form-data; boundary=' . $boundary;
    return $lines;
}

$source = dirname(__DIR__);
$sandbox = sys_get_temp_dir() . '/tinyfm-http-' . bin2hex(random_bytes(6));
$app = $sandbox . '/app';
$data = $sandbox . '/data';
$outside = $sandbox . '/outside';
$process = null;

try {
    mkdir($sandbox, 0700, true);
    http_copy_tree($source, $app);
    mkdir($data, 0700, true);
    mkdir($outside, 0700, true);
    mkdir($data . '/dest', 0700);
    file_put_contents($data . '/inside.txt', 'inside-route-data');
    file_put_contents($data . '/move.txt', 'move-route-data');
    file_put_contents($outside . '/krb5cc-delegated', 'outside-cache-secret');
    if (DIRECTORY_SEPARATOR !== '\\' && function_exists('symlink')) {
        symlink($outside . '/krb5cc-delegated', $data . '/delegated-cache-link');
    }

    $config = "<?php\n"
        . '$use_auth = false;' . "\n"
        . '$global_readonly = false;' . "\n"
        . '$root_path = ' . var_export($data, true) . ';' . "\n"
        . '$root_url = "";' . "\n"
        . '$online_viewer = false;' . "\n"
        . '$afsSupport = false;' . "\n"
        . '$require_post_for_mutations = true;' . "\n"
        . '$required_mutation_origin = "https://afs-auth.example.test:8444";' . "\n";
    file_put_contents($app . '/config.php', $config);
    $mutationOrigin = 'https://afs-auth.example.test:8444';

    $socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
    if ($socket === false) throw new RuntimeException('unable to reserve a test port');
    $address = stream_socket_get_name($socket, false);
    fclose($socket);
    $port = (int) substr(strrchr($address, ':'), 1);
    $log = $sandbox . '/server.log';
    $command = escapeshellarg(PHP_BINARY) . ' -d phar.readonly=0 -S 127.0.0.1:'
        . $port . ' -t ' . escapeshellarg($app);
    $descriptors = array(
        0 => array('pipe', 'r'),
        1 => array('file', $log, 'a'),
        2 => array('file', $log, 'a'),
    );
    $process = proc_open($command, $descriptors, $pipes, $app);
    if (!is_resource($process)) throw new RuntimeException('unable to start PHP test server');
    fclose($pipes[0]);
    $base = 'http://127.0.0.1:' . $port . '/tinyfilemanager.php';

    $page = array(0, '', array());
    for ($attempt = 0; $attempt < 50; $attempt++) {
        $page = http_request($base . '?p=');
        if ($page[0] === 200) break;
        usleep(100000);
    }
    http_check($page[0] === 200, 'list route starts with a confined root');
    http_check(preg_match("/window\\.csrf = '([0-9a-f]+)'/", $page[1], $match) === 1, 'list route issues a CSRF token');
    $token = $match[1];
    http_check(strpos($page[1], 'delegated-cache-link') === false, 'list route hides an escaping delegated-cache symlink');
    http_check(strpos($page[1], 'raw=inside.txt') !== false, 'direct file link returns through guarded raw streaming');
    http_check(strpos($page[1], 'edit=inside.txt') !== false, 'list route exposes the ordinary editor');

    $createBody = form_body(array(
        'newfilename' => 'must-not-exist.txt',
        'newfile' => 'file',
        'token' => $token,
    ));
    http_rejected_without_delta(
        'create without Origin', 403, $base . '?p=', 'POST',
        $createBody, 'application/x-www-form-urlencoded', false,
        $data, $outside, $app);
    http_rejected_without_delta(
        'create with wrong Origin', 403, $base . '?p=', 'POST',
        $createBody, 'application/x-www-form-urlencoded',
        'https://wrong.example.test:8444', $data, $outside, $app);
    http_rejected_without_delta(
        'create with comma-coalesced Origin', 403, $base . '?p=', 'POST',
        $createBody, 'application/x-www-form-urlencoded',
        $mutationOrigin . ', https://wrong.example.test:8444',
        $data, $outside, $app);
    http_rejected_without_delta(
        'create without CSRF', 403, $base . '?p=', 'POST',
        form_body(array(
            'newfilename' => 'must-not-exist.txt',
            'newfile' => 'file',
        )),
        'application/x-www-form-urlencoded', 'default',
        $data, $outside, $app);
    http_rejected_without_delta(
        'create with wrong CSRF', 403, $base . '?p=', 'POST',
        form_body(array(
            'newfilename' => 'must-not-exist.txt',
            'newfile' => 'file',
            'token' => str_repeat('f', 64),
        )),
        'application/x-www-form-urlencoded', 'default',
        $data, $outside, $app);
    http_rejected_without_delta(
        'JSON cannot invoke a form create route', 403,
        $base . '?p=', 'POST',
        json_encode(array(
            'newfilename' => 'must-not-exist.txt',
            'newfile' => 'file',
            'token' => $token,
        )),
        'application/json', 'default', $data, $outside, $app);
    http_rejected_without_delta(
        'legacy GET delete attempt', 405,
        $base . '?p=&del=inside.txt', 'GET', null, null, false,
        $data, $outside, $app);

    foreach (array(
        'missing token' => array(),
        'wrong token' => array('token' => str_repeat('f', 64)),
    ) as $label => $tokenFields) {
        http_rejected_without_delta(
            "savedata $label", 403,
            $base . '?p=&edit=inside.txt', 'POST',
            form_body(array_merge(array('savedata' => 'forbidden-write'),
                $tokenFields)),
            'application/x-www-form-urlencoded', 'default',
            $data, $outside, $app);
    }
    http_rejected_without_delta(
        'savedata without Origin', 403,
        $base . '?p=&edit=inside.txt', 'POST',
        form_body(array(
            'savedata' => 'forbidden-write',
            'token' => $token,
        )),
        'application/x-www-form-urlencoded', false,
        $data, $outside, $app);
    http_rejected_without_delta(
        'savedata with wrong Origin', 403,
        $base . '?p=&edit=inside.txt', 'POST',
        form_body(array(
            'savedata' => 'forbidden-write',
            'token' => $token,
        )),
        'application/x-www-form-urlencoded',
        'https://wrong.example.test:8444', $data, $outside, $app);

    $savedata = http_request(
        $base . '?p=&edit=inside.txt', 'POST',
        form_body(array(
            'savedata' => 'plain-form-route-data',
            'token' => $token,
        )),
        'application/x-www-form-urlencoded');
    http_check($savedata[0] === 200
        && file_get_contents($data . '/inside.txt') === 'plain-form-route-data',
        'savedata accepts the exact configured Origin and session CSRF token');
    $savedataRestore = http_request(
        $base . '?p=&edit=inside.txt', 'POST',
        form_body(array(
            'savedata' => 'inside-route-data',
            'token' => $token,
        )),
        'application/x-www-form-urlencoded');
    http_check($savedataRestore[0] === 200
        && file_get_contents($data . '/inside.txt') === 'inside-route-data',
        'savedata restoration succeeds through the same central gate');

    $editPage = http_request($base . '?p=&edit=inside.txt');
    http_check($editPage[0] === 200
        && strpos($editPage[1], 'id="normal-editor"') !== false
        && strpos($editPage[1], 'inside-route-data') !== false
        && strpos($editPage[1], '&amp;env=ace') === false,
        'ordinary editor remains available without the active Ace editor');

    $raw = http_request($base . '?p=&raw=inside.txt');
    http_check($raw[0] === 200 && $raw[1] === 'inside-route-data', 'direct-link route streams an in-root file');
    http_check(http_header_is($raw[2], 'Content-Type', 'application/octet-stream'), 'direct-link stream uses a non-active content type');
    http_check(http_header_starts_with($raw[2], 'Content-Disposition', 'attachment;'), 'direct-link stream is an attachment');
    http_check(http_header_is($raw[2], 'X-Content-Type-Options', 'nosniff'), 'direct-link stream disables content sniffing');
    $view = http_request($base . '?p=&view=inside.txt');
    http_check($view[0] === 200 && $view[1] === 'inside-route-data', 'legacy view route streams an in-root file');
    http_check(http_header_is($view[2], 'Content-Type', 'application/octet-stream'), 'legacy view stream uses a non-active content type');
    http_check(http_header_starts_with($view[2], 'Content-Disposition', 'attachment;'), 'legacy view stream is an attachment');
    http_check(http_header_is($view[2], 'X-Content-Type-Options', 'nosniff'), 'legacy view stream disables content sniffing');
    $download = http_request($base . '?p=&dl=inside.txt', 'POST',
        form_body(array('token' => $token)), 'application/x-www-form-urlencoded');
    http_check($download[0] === 200 && $download[1] === 'inside-route-data', 'download route streams an in-root file');
    http_check(http_header_is($download[2], 'Content-Type', 'application/octet-stream'), 'download stream uses a non-active content type');
    http_check(http_header_starts_with($download[2], 'Content-Disposition', 'attachment;'), 'download stream is an attachment');
    http_check(http_header_is($download[2], 'X-Content-Type-Options', 'nosniff'), 'download stream disables content sniffing');

    if (is_link($data . '/delegated-cache-link')) {
        foreach (array(
            'view' => http_request($base . '?p=&view=delegated-cache-link'),
            'direct' => http_request($base . '?p=&raw=delegated-cache-link'),
            'download' => http_request($base . '?p=&dl=delegated-cache-link', 'POST',
                form_body(array('token' => $token)), 'application/x-www-form-urlencoded'),
        ) as $name => $response) {
            http_check($response[0] !== 200
                && strpos($response[1], 'outside-cache-secret') === false,
                "$name route rejects the delegated-cache symlink");
        }
        http_request($base . '?p=dest', 'POST', form_body(array(
            'copy' => 'delegated-cache-link', 'finish' => '1', 'token' => $token,
        )), 'application/x-www-form-urlencoded');
        http_check(!file_exists($data . '/dest/delegated-cache-link'), 'copy route rejects the delegated-cache symlink');
    }

    http_request($base . '?p=', 'POST', form_body(array(
        'newfilename' => 'created.txt', 'newfile' => 'file', 'token' => $token,
    )), 'application/x-www-form-urlencoded');
    http_check(is_file($data . '/created.txt'), 'create route creates only an in-root file');

    $save = http_request($base . '?p=&edit=created.txt', 'POST', json_encode(array(
        'ajax' => true, 'type' => 'save', 'content' => 'edited-route-data', 'token' => $token,
    )), 'application/json');
    http_check($save[0] === 200 && file_get_contents($data . '/created.txt') === 'edited-route-data', 'edit route writes an in-root file');

    http_request($base . '?p=dest', 'POST', form_body(array(
        'copy' => 'created.txt', 'finish' => '1', 'token' => $token,
    )), 'application/x-www-form-urlencoded');
    http_check(file_get_contents($data . '/dest/created.txt') === 'edited-route-data', 'copy route confines its destination');

    http_request($base . '?p=dest', 'POST', form_body(array(
        'copy' => 'move.txt', 'finish' => '1', 'move' => '1', 'token' => $token,
    )), 'application/x-www-form-urlencoded');
    http_check(!file_exists($data . '/move.txt') && is_file($data . '/dest/move.txt'), 'move route confines both endpoints');

    http_request($base . '?p=dest', 'POST', form_body(array(
        'rename_from' => 'move.txt', 'rename_to' => 'renamed.txt', 'token' => $token,
    )), 'application/x-www-form-urlencoded');
    http_check(!file_exists($data . '/dest/move.txt') && is_file($data . '/dest/renamed.txt'), 'rename route remains in root');

    $multipartType = '';
    $multipart = multipart_body(array(
        'token' => $token, 'dzchunkindex' => '0', 'dztotalchunkcount' => '0',
        'fullpath' => 'uploaded.txt',
    ), 'file', 'uploaded.txt', 'uploaded-route-data', $multipartType);
    $upload = http_request($base . '?p=', 'POST', $multipart, $multipartType);
    http_check($upload[0] === 200 && file_get_contents($data . '/uploaded.txt') === 'uploaded-route-data', 'upload route imports only below root');

    if (is_link($data . '/delegated-cache-link')) {
        $blockedType = '';
        $blocked = multipart_body(array(
            'token' => $token, 'dzchunkindex' => '0', 'dztotalchunkcount' => '0',
            'fullpath' => 'delegated-cache-link',
        ), 'file', 'delegated-cache-link', 'overwrite-attempt', $blockedType);
        http_request($base . '?p=', 'POST', $blocked, $blockedType);
        http_check(file_get_contents($outside . '/krb5cc-delegated') === 'outside-cache-secret', 'upload cannot overwrite a delegated cache through a symlink');

        $beforeArchives = glob($data . '/*.tar');
        http_request($base . '?p=', 'POST', form_body(array(
            'group' => '1', 'tar' => 'tar', 'file' => array('delegated-cache-link'),
            'token' => $token,
        )), 'application/x-www-form-urlencoded');
        http_check(count(glob($data . '/*.tar')) === count($beforeArchives), 'archive creation rejects an escaping symlink');
    }

    $beforeArchives = glob($data . '/dest/*.tar');
    http_request($base . '?p=dest', 'POST', form_body(array(
        'group' => '1', 'tar' => 'tar', 'file' => array('renamed.txt'), 'token' => $token,
    )), 'application/x-www-form-urlencoded');
    http_check(count(glob($data . '/dest/*.tar')) === count($beforeArchives)
        && file_get_contents($data . '/dest/renamed.txt') === 'move-route-data',
        'archive creation remains disabled without changing the source file');

    http_request($base . '?p=dest&del=renamed.txt', 'POST',
        form_body(array('token' => $token)), 'application/x-www-form-urlencoded');
    http_check(!file_exists($data . '/dest/renamed.txt'), 'delete route removes an in-root file');

    if (is_link($data . '/delegated-cache-link')) {
        http_request($base . '?p=&del=delegated-cache-link', 'POST',
            form_body(array('token' => $token)), 'application/x-www-form-urlencoded');
        clearstatcache(true, $data . '/delegated-cache-link');
        http_check(!is_link($data . '/delegated-cache-link'), 'delete route unlinks an escaping link');
        http_check(file_get_contents($outside . '/krb5cc-delegated') === 'outside-cache-secret', 'delete route never follows the escaping link');
    }
} catch (Throwable $error) {
    fwrite(STDERR, $error->getMessage() . "\n");
    if (isset($log) && is_file($log)) {
        $contents = file_get_contents($log);
        fwrite(STDERR, "server log tail:\n" . substr($contents, -4000) . "\n");
    }
    exit(1);
} finally {
    if (is_resource($process)) {
        proc_terminate($process);
        proc_close($process);
    }
    http_remove_tree($sandbox);
}

echo "PASS: $checks HTTP route-confinement checks\n";
