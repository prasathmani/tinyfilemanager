<?php
// Joyee Bridge local configuration sample.
// Copy this file on the server to joyee-bridge.config.php and edit there.
// Do not commit the real joyee-bridge.config.php with live credentials.

$joyee_bridge_enabled = true;

// Public-facing bridge key used only for this bridge.
// Must be different from the real API token.
$joyee_bridge_key = 'replace_with_long_random_bridge_key';

// Real TinyFileManager API token from api.config.php.
// This value stays on the server and is never exposed in repository.
$joyee_api_token = 'replace_with_real_api_token_from_api_config';

// Joyee bridge isolated workspace root.
// Keep Joyee operations separated from other workspaces (for example Mirko).
$joyee_bridge_root_path = __DIR__ . '/Joyee';

// Optional Joyee token config override.
// root_path is always enforced to $joyee_bridge_root_path by joyee-bridge.php.
$joyee_api_token_config = array(
    'label' => 'Joyee Bridge API',
    'role' => 'admin',
    'capabilities' => array(
        'list' => true,
        'stat' => true,
        'read' => true,
        'write' => true,
        'mkdir' => true,
        'delete' => true,
        'rename' => true,
        'move' => true,
        'copy' => true,
    ),
);

// Restrict what Joyee can do through this bridge.
// Start conservative; enable write/delete only after testing.
$joyee_bridge_allowed_actions = array(
    'ping',
    'list',
    'stat',
    'read',
    'write',
    'mkdir',
    'rename',
    'move',
    'copy',
    'delete',
);
