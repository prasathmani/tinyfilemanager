<?php
/**
 * Tiny File Manager – protected JSON API core
 *
 * This file is loaded by api.php.
 * It loads config.php first and api.config.php second.
 */

header('Content-Type: application/json; charset=utf-8');

$api_start_time = microtime(true);

function api_json_response($ok, $data = array(), $status = 200)
{
    http_response_code($status);
    echo json_encode(array(
        'ok' => (bool) $ok,
        'data' => $data,
        'meta' => array(
            'elapsed_ms' => round((microtime(true) - $GLOBALS['api_start_time']) * 1000, 2),
        ),
    ), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    exit;
}

function api_error($message, $status = 400, $extra = array())
{
    api_json_response(false, array_merge(array('error' => $message), $extra), $status);
}

function api_get_header_value($name)
{
    $key = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
    return isset($_SERVER[$key]) ? trim($_SERVER[$key]) : '';
}

function api_get_bearer_token()
{
    $auth = api_get_header_value('Authorization');
    if (preg_match('/^Bearer\s+(.+)$/i', $auth, $m)) {
        return trim($m[1]);
    }
    $api_key = api_get_header_value('X-TFM-API-Key');
    if ($api_key !== '') {
        return $api_key;
    }
    return '';
}

function api_read_input()
{
    $raw = file_get_contents('php://input');
    if ($raw === false || trim($raw) === '') {
        return array();
    }
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        api_error('Invalid JSON body.', 400);
    }
    return $data;
}

function api_normalize_relative_path($path)
{
    $path = str_replace('\\', '/', (string) $path);
    $path = preg_replace('#/+#', '/', $path);
    $path = trim($path);
    $path = ltrim($path, '/');

    if ($path === '' || $path === '.') {
        return '';
    }

    $parts = array();
    foreach (explode('/', $path) as $part) {
        if ($part === '' || $part === '.') {
            continue;
        }
        if ($part === '..') {
            api_error('Path traversal is not allowed.', 403);
        }
        if (strpos($part, "\0") !== false) {
            api_error('Invalid path.', 400);
        }
        $parts[] = $part;
    }

    return implode('/', $parts);
}

function api_path_join($root, $relative)
{
    $relative = api_normalize_relative_path($relative);
    return rtrim($root, DIRECTORY_SEPARATOR) . ($relative === '' ? '' : DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relative));
}

function api_real_root($root)
{
    $real = realpath($root);
    if ($real === false || !is_dir($real)) {
        api_error('API root path does not exist or is not a directory.', 500);
    }
    return rtrim($real, DIRECTORY_SEPARATOR);
}

function api_resolve_existing_path($root, $relative)
{
    $target = api_path_join($root, $relative);
    $real = realpath($target);
    if ($real === false) {
        api_error('Path not found.', 404, array('path' => api_normalize_relative_path($relative)));
    }
    $root_real = api_real_root($root);
    if ($real !== $root_real && strpos($real, $root_real . DIRECTORY_SEPARATOR) !== 0) {
        api_error('Resolved path is outside API root.', 403);
    }
    return $real;
}

function api_resolve_writable_path($root, $relative)
{
    $relative = api_normalize_relative_path($relative);
    $root_real = api_real_root($root);
    $target = api_path_join($root_real, $relative);
    $parent = dirname($target);
    $parent_real = realpath($parent);

    if ($parent_real === false || !is_dir($parent_real)) {
        api_error('Parent directory does not exist.', 404, array('path' => $relative));
    }
    if ($parent_real !== $root_real && strpos($parent_real, $root_real . DIRECTORY_SEPARATOR) !== 0) {
        api_error('Target parent is outside API root.', 403);
    }
    return $target;
}

function api_relative_from_root($root, $absolute)
{
    $root_real = api_real_root($root);
    $real = realpath($absolute);
    if ($real === false) {
        return null;
    }
    if ($real === $root_real) {
        return '';
    }
    if (strpos($real, $root_real . DIRECTORY_SEPARATOR) !== 0) {
        return null;
    }
    return str_replace(DIRECTORY_SEPARATOR, '/', substr($real, strlen($root_real) + 1));
}

function api_file_info($root, $path)
{
    return array(
        'name' => basename($path),
        'path' => api_relative_from_root($root, $path),
        'type' => is_dir($path) ? 'dir' : 'file',
        'size' => is_file($path) ? filesize($path) : null,
        'modified_at' => date('c', filemtime($path)),
        'readable' => is_readable($path),
        'writable' => is_writable($path),
    );
}

function api_delete_recursive($path)
{
    if (is_file($path) || is_link($path)) {
        return unlink($path);
    }
    if (!is_dir($path)) {
        return false;
    }
    $items = scandir($path);
    if ($items === false) {
        return false;
    }
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }
        if (!api_delete_recursive($path . DIRECTORY_SEPARATOR . $item)) {
            return false;
        }
    }
    return rmdir($path);
}

function api_copy_recursive($source, $dest)
{
    if (is_file($source)) {
        return copy($source, $dest);
    }
    if (!is_dir($source)) {
        return false;
    }
    if (!is_dir($dest) && !mkdir($dest, 0775, true)) {
        return false;
    }
    $items = scandir($source);
    if ($items === false) {
        return false;
    }
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }
        if (!api_copy_recursive($source . DIRECTORY_SEPARATOR . $item, $dest . DIRECTORY_SEPARATOR . $item)) {
            return false;
        }
    }
    return true;
}

function api_require_capability($capabilities, $capability)
{
    if (empty($capabilities[$capability])) {
        api_error('API token is not allowed to perform this action.', 403, array('required' => $capability));
    }
}

function api_http_post_json($url, array $payload, array $headers = array(), $timeout = 60)
{
    $body = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($body === false) {
        api_error('Unable to encode assistant request.', 500);
    }

    $request_headers = array(
        'Content-Type: application/json',
        'Accept: application/json',
    );

    foreach ($headers as $header) {
        $request_headers[] = $header;
    }

    if (function_exists('curl_init')) {
        $curl = curl_init($url);
        if ($curl === false) {
            api_error('Unable to initialize HTTP client.', 500);
        }

        curl_setopt_array($curl, array(
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_HTTPHEADER => $request_headers,
            CURLOPT_CONNECTTIMEOUT => $timeout,
            CURLOPT_TIMEOUT => $timeout,
        ));

        $response_body = curl_exec($curl);
        if ($response_body === false) {
            $error = curl_error($curl);
            curl_close($curl);
            api_error('Assistant request failed: ' . $error, 502);
        }

        $status = (int) curl_getinfo($curl, CURLINFO_HTTP_CODE);
        curl_close($curl);

        return array(
            'status' => $status,
            'body' => (string) $response_body,
        );
    }

    $request_headers[] = 'Content-Length: ' . strlen($body);

    $context = stream_context_create(array(
        'http' => array(
            'method' => 'POST',
            'header' => implode("\r\n", $request_headers),
            'content' => $body,
            'timeout' => $timeout,
            'ignore_errors' => true,
        ),
        'ssl' => array(
            'verify_peer' => true,
            'verify_peer_name' => true,
        ),
    ));

    $response_body = @file_get_contents($url, false, $context);
    $status = 0;
    if (isset($http_response_header[0]) && preg_match('/\s(\d{3})\s/', $http_response_header[0], $matches)) {
        $status = (int) $matches[1];
    }

    return array(
        'status' => $status,
        'body' => $response_body === false ? '' : $response_body,
    );
}

function api_assistant_collect_files($api_root, $requested_files, $max_files, $max_file_bytes, $allowed_extensions)
{
    if (!is_array($requested_files)) {
        $requested_files = array($requested_files);
    }

    $requested_files = array_values(array_filter(array_map('trim', $requested_files), 'strlen'));

    if ($requested_files === array()) {
        return array('files' => array(), 'context' => '');
    }

    if ($max_files > 0 && count($requested_files) > $max_files) {
        api_error('Too many files requested for assistant context.', 400, array('max_files' => $max_files));
    }

    $allowed_extensions = array_map('strtolower', array_filter(array_map('trim', (array) $allowed_extensions), 'strlen'));
    $files = array();
    $context_blocks = array();

    foreach ($requested_files as $requested_file) {
        $resolved_file = api_resolve_existing_path($api_root, $requested_file);

        if (!is_file($resolved_file)) {
            api_error('Assistant can only inspect files, not directories.', 400, array('path' => api_normalize_relative_path($requested_file)));
        }

        $relative_path = api_normalize_relative_path($requested_file);
        $extension = strtolower(pathinfo($resolved_file, PATHINFO_EXTENSION));

        if ($allowed_extensions !== array() && !in_array($extension, $allowed_extensions, true)) {
            api_error('File type is not allowed for assistant inspection.', 400, array('path' => $relative_path));
        }

        $size = filesize($resolved_file);
        $read_length = $max_file_bytes > 0 ? $max_file_bytes : null;
        $content = $read_length === null
            ? file_get_contents($resolved_file)
            : file_get_contents($resolved_file, false, null, 0, $read_length);

        if ($content === false) {
            api_error('Unable to read requested file.', 500, array('path' => $relative_path));
        }

        if (strpos($content, "\0") !== false) {
            api_error('Binary files are not supported by the assistant.', 400, array('path' => $relative_path));
        }

        $files[] = array(
            'path' => $relative_path,
            'size' => $size,
            'truncated' => $read_length !== null && is_int($size) && $size > $read_length,
            'content' => $content,
        );

        $context_blocks[] = array(
            'path' => $relative_path,
            'size' => $size,
            'truncated' => $read_length !== null && is_int($size) && $size > $read_length,
            'content' => $content,
        );
    }

    $context = '';
    foreach ($context_blocks as $block) {
        $context .= "### File: " . $block['path'] . "\n";
        $context .= 'Size: ' . (string) $block['size'] . " bytes\n";
        if (!empty($block['truncated'])) {
            $context .= "Note: content was truncated to the configured maximum size.\n";
        }
        $context .= "```\n" . $block['content'] . "\n```\n\n";
    }

    return array(
        'files' => $files,
        'context' => trim($context),
    );
}

function api_assistant_scope_root($api_root)
{
    if (isset($GLOBALS['assistant_root_path']) && trim((string) $GLOBALS['assistant_root_path']) !== '') {
        return api_real_root((string) $GLOBALS['assistant_root_path']);
    }
    return $api_root;
}

function api_assistant_target_path($assistant_scope_root, $path)
{
    $relative = api_normalize_relative_path($path);
    $root_real = api_real_root($assistant_scope_root);
    $target = api_path_join($root_real, $relative);

    if ($target !== $root_real && strpos($target, $root_real . DIRECTORY_SEPARATOR) !== 0) {
        api_error('Target path is outside assistant root.', 403, array('path' => $relative));
    }

    return array($target, $relative);
}

function api_assistant_apply_operations($assistant_scope_root, $operations, $require_confirmation = false, $confirmed = array())
{
    if (!is_array($operations) || empty($operations)) {
        api_error('Missing operations payload.', 400);
    }

    $confirmed_map = array();
    if ($require_confirmation) {
        foreach ((array) $confirmed as $confirmed_index) {
            $confirmed_map[(int) $confirmed_index] = true;
        }
    }

    $results = array();
    $applied_count = 0;

    foreach ($operations as $index => $operation) {
        if (!is_array($operation)) {
            api_error('Invalid operation item.', 400);
        }

        if ($require_confirmation && !isset($confirmed_map[(int) $index])) {
            $results[] = array(
                'index' => (int) $index,
                'action' => isset($operation['action']) ? strtolower(trim((string) $operation['action'])) : 'write',
                'status' => 'skipped',
            );
            continue;
        }

        $action = isset($operation['action']) ? strtolower(trim((string) $operation['action'])) : '';
        if ($action === '') {
            $action = 'write';
        }

        switch ($action) {
            case 'write':
                if (!isset($operation['path']) || trim((string) $operation['path']) === '') {
                    api_error('Write path is required.', 400);
                }
                list($write_target, $write_relative) = api_assistant_target_path($assistant_scope_root, (string) $operation['path']);
                $write_parent = dirname($write_target);
                if (!is_dir($write_parent) && !mkdir($write_parent, 0775, true)) {
                    api_error('Unable to create parent directory for write operation.', 500, array('path' => $write_relative));
                }
                $write_content = isset($operation['content']) ? (string) $operation['content'] : '';
                $write_bytes = file_put_contents($write_target, $write_content, LOCK_EX);
                if ($write_bytes === false) {
                    api_error('Unable to apply write operation.', 500, array('path' => $write_relative));
                }
                $results[] = array(
                    'index' => (int) $index,
                    'action' => 'write',
                    'path' => $write_relative,
                    'bytes' => $write_bytes,
                    'status' => 'applied',
                );
                $applied_count++;
                break;

            case 'mkdir':
                if (!isset($operation['path']) || trim((string) $operation['path']) === '') {
                    api_error('Mkdir path is required.', 400);
                }
                list($mkdir_target, $mkdir_relative) = api_assistant_target_path($assistant_scope_root, (string) $operation['path']);
                $mkdir_created = false;
                if (!is_dir($mkdir_target)) {
                    if (!mkdir($mkdir_target, 0775, true)) {
                        api_error('Unable to create directory.', 500, array('path' => $mkdir_relative));
                    }
                    $mkdir_created = true;
                }
                $results[] = array(
                    'index' => (int) $index,
                    'action' => 'mkdir',
                    'path' => $mkdir_relative,
                    'created' => $mkdir_created,
                    'status' => 'applied',
                );
                $applied_count++;
                break;

            case 'delete':
                if (!isset($operation['path']) || trim((string) $operation['path']) === '') {
                    api_error('Delete path is required.', 400);
                }
                $delete_target = api_resolve_existing_path($assistant_scope_root, (string) $operation['path']);
                if ($delete_target === api_real_root($assistant_scope_root)) {
                    api_error('Refusing to delete assistant root.', 403);
                }
                if (!api_delete_recursive($delete_target)) {
                    api_error('Unable to delete path.', 500, array('path' => api_normalize_relative_path((string) $operation['path'])));
                }
                $results[] = array(
                    'index' => (int) $index,
                    'action' => 'delete',
                    'path' => api_normalize_relative_path((string) $operation['path']),
                    'status' => 'applied',
                );
                $applied_count++;
                break;

            case 'move':
            case 'rename':
                if (!isset($operation['from']) || !isset($operation['to'])) {
                    api_error('Move operation requires from and to paths.', 400);
                }
                $move_from = api_resolve_existing_path($assistant_scope_root, (string) $operation['from']);
                list($move_to, $move_to_relative) = api_assistant_target_path($assistant_scope_root, (string) $operation['to']);
                $move_parent = dirname($move_to);
                if (!is_dir($move_parent) && !mkdir($move_parent, 0775, true)) {
                    api_error('Unable to create destination directory.', 500, array('to' => $move_to_relative));
                }
                if (!rename($move_from, $move_to)) {
                    api_error('Unable to move path.', 500, array(
                        'from' => api_normalize_relative_path((string) $operation['from']),
                        'to' => $move_to_relative,
                    ));
                }
                $results[] = array(
                    'index' => (int) $index,
                    'action' => 'move',
                    'from' => api_normalize_relative_path((string) $operation['from']),
                    'to' => $move_to_relative,
                    'status' => 'applied',
                );
                $applied_count++;
                break;

            case 'copy':
                if (!isset($operation['from']) || !isset($operation['to'])) {
                    api_error('Copy operation requires from and to paths.', 400);
                }
                $copy_from = api_resolve_existing_path($assistant_scope_root, (string) $operation['from']);
                list($copy_to, $copy_to_relative) = api_assistant_target_path($assistant_scope_root, (string) $operation['to']);
                $copy_parent = dirname($copy_to);
                if (!is_dir($copy_parent) && !mkdir($copy_parent, 0775, true)) {
                    api_error('Unable to create destination directory.', 500, array('to' => $copy_to_relative));
                }
                if (!api_copy_recursive($copy_from, $copy_to)) {
                    api_error('Unable to copy path.', 500, array(
                        'from' => api_normalize_relative_path((string) $operation['from']),
                        'to' => $copy_to_relative,
                    ));
                }
                $results[] = array(
                    'index' => (int) $index,
                    'action' => 'copy',
                    'from' => api_normalize_relative_path((string) $operation['from']),
                    'to' => $copy_to_relative,
                    'status' => 'applied',
                );
                $applied_count++;
                break;

            default:
                api_error('Unsupported assistant operation.', 400, array('action' => $action));
        }
    }

    if ($require_confirmation && $applied_count === 0) {
        api_error('No operations were confirmed for apply.', 400);
    }

    return $results;
}

$config_file = __DIR__ . '/config.php';
if (is_file($config_file)) {
    require $config_file;
}

if (!isset($api_tokens) || !is_array($api_tokens)) {
    $api_tokens = array();
}

$api_config_file = __DIR__ . '/api.config.php';
if (is_file($api_config_file)) {
    require $api_config_file;
}

if (!isset($api_tokens) || !is_array($api_tokens)) {
    $api_tokens = array();
}

if (isset($api_extra_tokens) && is_array($api_extra_tokens)) {
    $api_tokens = array_merge($api_tokens, $api_extra_tokens);
}

if (empty($api_enabled)) {
    api_error('API is disabled.', 403);
}

if (empty($api_tokens)) {
    api_error('No API tokens configured.', 500);
}

$token = api_get_bearer_token();
if ($token === '') {
    api_error('Missing API token.', 401);
}

$token_config = null;
foreach ($api_tokens as $configured_token => $config) {
    if (hash_equals((string) $configured_token, (string) $token)) {
        $token_config = is_array($config) ? $config : array();
        break;
    }
}

if ($token_config === null) {
    api_error('Invalid API token.', 401);
}

$api_root = isset($token_config['root_path']) ? $token_config['root_path'] : (isset($root_path) ? $root_path : __DIR__);
$api_root = api_real_root($api_root);

$default_capabilities = array(
    'list' => true,
    'read' => true,
    'write' => true,
    'mkdir' => true,
    'delete' => true,
    'rename' => true,
    'copy' => true,
    'move' => true,
    'stat' => true,
);
$capabilities = isset($token_config['capabilities']) && is_array($token_config['capabilities'])
    ? array_merge($default_capabilities, $token_config['capabilities'])
    : $default_capabilities;

$method = strtoupper(isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET');
$input = api_read_input();
$action = isset($_GET['action']) ? $_GET['action'] : (isset($input['action']) ? $input['action'] : 'ping');
$action = strtolower(trim((string) $action));

if ($method === 'OPTIONS') {
    api_json_response(true, array('message' => 'OK'));
}

switch ($action) {
    case 'ping':
        api_json_response(true, array('message' => 'TinyFileManager API is available.', 'root' => $api_root));
        break;

    case 'list':
        api_require_capability($capabilities, 'list');
        $path = isset($_GET['path']) ? $_GET['path'] : (isset($input['path']) ? $input['path'] : '');
        $dir = api_resolve_existing_path($api_root, $path);
        if (!is_dir($dir)) {
            api_error('Path is not a directory.', 400);
        }
        $items = scandir($dir);
        if ($items === false) {
            api_error('Unable to read directory.', 500);
        }
        $result = array();
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $result[] = api_file_info($api_root, $dir . DIRECTORY_SEPARATOR . $item);
        }
        api_json_response(true, array('path' => api_normalize_relative_path($path), 'items' => $result));
        break;

    case 'stat':
        api_require_capability($capabilities, 'stat');
        $path = isset($_GET['path']) ? $_GET['path'] : (isset($input['path']) ? $input['path'] : '');
        $target = api_resolve_existing_path($api_root, $path);
        api_json_response(true, api_file_info($api_root, $target));
        break;

    case 'read':
        api_require_capability($capabilities, 'read');
        $path = isset($_GET['path']) ? $_GET['path'] : (isset($input['path']) ? $input['path'] : '');
        $target = api_resolve_existing_path($api_root, $path);
        if (!is_file($target) || !is_readable($target)) {
            api_error('File is not readable.', 400);
        }
        $content = file_get_contents($target);
        if ($content === false) {
            api_error('Unable to read file.', 500);
        }
        api_json_response(true, array('path' => api_normalize_relative_path($path), 'encoding' => 'utf-8', 'content' => $content));
        break;

    case 'write':
        api_require_capability($capabilities, 'write');
        if (!isset($input['path'])) {
            api_error('Missing path.', 400);
        }
        $target = api_resolve_writable_path($api_root, $input['path']);
        $content = isset($input['content']) ? (string) $input['content'] : '';
        if (!empty($input['base64'])) {
            $decoded = base64_decode($content, true);
            if ($decoded === false) {
                api_error('Invalid base64 content.', 400);
            }
            $content = $decoded;
        }
        $bytes = file_put_contents($target, $content, LOCK_EX);
        if ($bytes === false) {
            api_error('Unable to write file.', 500);
        }
        api_json_response(true, array('path' => api_normalize_relative_path($input['path']), 'bytes' => $bytes));
        break;

    case 'mkdir':
        api_require_capability($capabilities, 'mkdir');
        if (!isset($input['path'])) {
            api_error('Missing path.', 400);
        }
        $target = api_resolve_writable_path($api_root, $input['path']);
        if (is_dir($target)) {
            api_json_response(true, array('path' => api_normalize_relative_path($input['path']), 'created' => false));
        }
        if (!mkdir($target, 0775, true)) {
            api_error('Unable to create directory.', 500);
        }
        api_json_response(true, array('path' => api_normalize_relative_path($input['path']), 'created' => true));
        break;

    case 'delete':
        api_require_capability($capabilities, 'delete');
        if (!isset($input['path'])) {
            api_error('Missing path.', 400);
        }
        $target = api_resolve_existing_path($api_root, $input['path']);
        if ($target === $api_root) {
            api_error('Refusing to delete API root.', 403);
        }
        if (!api_delete_recursive($target)) {
            api_error('Unable to delete path.', 500);
        }
        api_json_response(true, array('path' => api_normalize_relative_path($input['path']), 'deleted' => true));
        break;

    case 'rename':
    case 'move':
        api_require_capability($capabilities, $action === 'rename' ? 'rename' : 'move');
        if (!isset($input['from']) || !isset($input['to'])) {
            api_error('Missing from/to path.', 400);
        }
        $from = api_resolve_existing_path($api_root, $input['from']);
        $to = api_resolve_writable_path($api_root, $input['to']);
        if ($from === $api_root) {
            api_error('Refusing to move API root.', 403);
        }
        if (!rename($from, $to)) {
            api_error('Unable to move path.', 500);
        }
        api_json_response(true, array('from' => api_normalize_relative_path($input['from']), 'to' => api_normalize_relative_path($input['to'])));
        break;

    case 'copy':
        api_require_capability($capabilities, 'copy');
        if (!isset($input['from']) || !isset($input['to'])) {
            api_error('Missing from/to path.', 400);
        }
        $from = api_resolve_existing_path($api_root, $input['from']);
        $to = api_resolve_writable_path($api_root, $input['to']);
        if (!api_copy_recursive($from, $to)) {
            api_error('Unable to copy path.', 500);
        }
        api_json_response(true, array('from' => api_normalize_relative_path($input['from']), 'to' => api_normalize_relative_path($input['to'])));
        break;

    case 'assistant':
        api_require_capability($capabilities, 'assistant');

        if (empty($assistant_enabled)) {
            api_error('Assistant is disabled.', 403);
        }

        $assistant_api_key = isset($assistant_openai_api_key) ? trim((string) $assistant_openai_api_key) : '';
        if ($assistant_api_key === '') {
            api_error('OpenAI assistant API key is not configured.', 500);
        }

        $message = isset($input['message']) ? trim((string) $input['message']) : '';
        if ($message === '') {
            $message = isset($input['prompt']) ? trim((string) $input['prompt']) : '';
        }
        if ($message === '') {
            $message = isset($input['query']) ? trim((string) $input['query']) : '';
        }
        if ($message === '') {
            api_error('Missing assistant message.', 400);
        }

        $requested_files = array();
        if (isset($input['files']) && is_array($input['files'])) {
            $requested_files = $input['files'];
        } elseif (isset($input['files']) && is_string($input['files'])) {
            $requested_files = preg_split('/\s*,\s*/', $input['files']);
        } elseif (isset($input['paths']) && is_array($input['paths'])) {
            $requested_files = $input['paths'];
        }

        $max_files = isset($assistant_max_files) ? (int) $assistant_max_files : 8;
        $max_file_bytes = isset($assistant_max_file_bytes) ? (int) $assistant_max_file_bytes : 200000;
        $allowed_extensions = isset($assistant_allowed_extensions) ? $assistant_allowed_extensions : array('php', 'md', 'txt', 'json', 'js', 'css', 'html', 'xml', 'yml', 'yaml', 'ini', 'sh', 'sql', 'env');
        $assistant_model = isset($assistant_openai_model) && trim((string) $assistant_openai_model) !== ''
            ? trim((string) $assistant_openai_model)
            : 'gpt-4o-mini';
        $assistant_base_url = isset($assistant_openai_base_url) && trim((string) $assistant_openai_base_url) !== ''
            ? rtrim(trim((string) $assistant_openai_base_url), '/')
            : 'https://api.openai.com/v1';
        $assistant_temperature = isset($assistant_openai_temperature) ? (float) $assistant_openai_temperature : 0.2;
        $assistant_system_prompt = isset($assistant_system_prompt) && trim((string) $assistant_system_prompt) !== ''
            ? trim((string) $assistant_system_prompt)
            : 'You are a careful coding assistant for Tiny File Manager. Work only with the files provided in context, explain changes clearly, and avoid assuming access to anything outside the configured project root.';

        $assistant_scope_root = api_assistant_scope_root($api_root);

        $file_context = api_assistant_collect_files($assistant_scope_root, $requested_files, $max_files, $max_file_bytes, $allowed_extensions);

        $messages = array(
            array(
                'role' => 'system',
                'content' => $assistant_system_prompt,
            ),
        );

        $user_content = $message;
        if (!empty($file_context['context'])) {
            $user_content .= "\n\nProject file context:\n" . $file_context['context'];
        }

        $messages[] = array(
            'role' => 'user',
            'content' => $user_content,
        );

        $response = api_http_post_json(
            $assistant_base_url . '/chat/completions',
            array(
                'model' => $assistant_model,
                'messages' => $messages,
                'temperature' => $assistant_temperature,
                'stream' => false,
            ),
            array(
                'Authorization: Bearer ' . $assistant_api_key,
            ),
            60
        );

        if ($response['status'] < 200 || $response['status'] >= 300) {
            $provider_error = json_decode($response['body'], true);
            api_error('OpenAI assistant request failed.', 502, array(
                'provider_status' => $response['status'],
                'provider_error' => is_array($provider_error) ? $provider_error : $response['body'],
            ));
        }

        $decoded = json_decode($response['body'], true);
        if (!is_array($decoded)) {
            api_error('OpenAI assistant returned invalid JSON.', 502);
        }

        $assistant_reply = '';
        if (isset($decoded['choices'][0]['message']['content'])) {
            $assistant_reply = (string) $decoded['choices'][0]['message']['content'];
        }

        if ($assistant_reply === '') {
            api_error('OpenAI assistant response did not contain a reply.', 502, array('provider_response' => $decoded));
        }

        api_json_response(true, array(
            'reply' => $assistant_reply,
            'model' => $assistant_model,
            'files' => $file_context['files'],
        ));
        break;

    case 'assistant_apply':
        api_require_capability($capabilities, 'assistant');

        if (empty($assistant_enabled)) {
            api_error('Assistant is disabled.', 403);
        }

        $assistant_scope_root = api_assistant_scope_root($api_root);
        $operations = isset($input['operations']) ? $input['operations'] : (isset($input['edits']) ? $input['edits'] : null);
        $require_confirmation = !empty($input['require_confirmation']);
        $confirmed = isset($input['confirmed']) ? $input['confirmed'] : array();
        $results = api_assistant_apply_operations($assistant_scope_root, $operations, $require_confirmation, $confirmed);

        api_json_response(true, array(
            'applied' => true,
            'operations' => $results,
        ));
        break;

    default:
        api_error('Unknown action.', 404, array('action' => $action));
}
