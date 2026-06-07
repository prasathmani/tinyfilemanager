<?php
/**
 * Joyee Bridge for Tiny File Manager API.
 *
 * This endpoint is for clients that cannot send custom HTTP headers.
 * It uses a separate bridge key and maps requests internally to api.core.php
 * by setting X-TFM-API-Key on the server side.
 *
 * Use only over HTTPS.
 */

header('Content-Type: application/json; charset=utf-8');

function joyee_bridge_error($message, $status = 400, $extra = array())
{
    http_response_code($status);
    echo json_encode(array(
        'ok' => false,
        'data' => array_merge(array('error' => $message), $extra),
    ), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    exit;
}

$bridge_config_file = __DIR__ . '/joyee-bridge.config.php';

if (!is_file($bridge_config_file)) {
    joyee_bridge_error('Joyee bridge config is missing.', 500);
}

require $bridge_config_file;

if (empty($joyee_bridge_enabled)) {
    joyee_bridge_error('Joyee bridge is disabled.', 403);
}

if (empty($joyee_bridge_key) || empty($joyee_api_token)) {
    joyee_bridge_error('Joyee bridge is not configured.', 500);
}

if (hash_equals((string) $joyee_bridge_key, (string) $joyee_api_token)) {
    joyee_bridge_error('Bridge key must be different from API token.', 500);
}

$provided_bridge_key = isset($_GET['bridge_key']) ? (string) $_GET['bridge_key'] : '';

if ($provided_bridge_key === '') {
    joyee_bridge_error('Missing bridge key.', 401);
}

if (!hash_equals((string) $joyee_bridge_key, $provided_bridge_key)) {
    joyee_bridge_error('Invalid bridge key.', 401);
}

unset($_GET['bridge_key']);
unset($_REQUEST['bridge_key']);

$action = isset($_GET['action']) ? strtolower(trim((string) $_GET['action'])) : 'ping';

$allowed_actions = isset($joyee_bridge_allowed_actions) && is_array($joyee_bridge_allowed_actions)
    ? $joyee_bridge_allowed_actions
    : array('ping', 'list', 'stat', 'read', 'write', 'mkdir', 'rename', 'move', 'copy', 'delete');

$allowed_actions = array_map('strtolower', $allowed_actions);

if (!in_array($action, $allowed_actions, true)) {
    joyee_bridge_error('Action is not allowed through Joyee bridge.', 403, array(
        'action' => $action,
    ));
}

// Force the whitelisted action path that api.core.php will consume first.
$_GET['action'] = $action;

$_SERVER['HTTP_X_TFM_API_KEY'] = (string) $joyee_api_token;

require __DIR__ . '/api.core.php';
