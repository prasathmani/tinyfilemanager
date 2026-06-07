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

$config_file = __DIR__ . '/config.php';
if (is_file($config_file)) {
    require $config_file;
}

$api_config_file = __DIR__ . '/api.config.php';
if (is_file($api_config_file)) {
    require $api_config_file;
}

if (empty($api_enabled)) {
    api_error('API is disabled.', 403);
}

if (empty($api_tokens) || !is_array($api_tokens)) {
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

    default:
        api_error('Unknown action.', 404, array('action' => $action));
}
