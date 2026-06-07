<?php
// Tiny File Manager API local configuration sample.
// Copy this file on the server to api.config.php and edit there.
// Do not commit the real api.config.php with live credentials.

$api_enabled = true;

$api_tokens = array(
    'replace_with_long_random_token' => array(
        'label' => 'Joyee API',
        'role' => 'admin',
        'root_path' => isset($root_path) ? $root_path : __DIR__,
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
    ),
);
