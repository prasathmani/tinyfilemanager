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
            'assistant' => true,
        ),
    ),
);

// OpenAI assistant configuration.
// Copy this file to api.config.php on the server and keep the real API key there only.
$assistant_enabled = true;
$assistant_openai_api_key = 'replace_with_real_openai_api_key';
$assistant_openai_model = 'gpt-4o-mini';
$assistant_openai_base_url = 'https://api.openai.com/v1';
$assistant_openai_temperature = 0.2;
$assistant_max_files = 8;
$assistant_max_file_bytes = 200000;
$assistant_allowed_extensions = array('php', 'md', 'txt', 'json', 'js', 'css', 'html', 'xml', 'yml', 'yaml', 'ini', 'sh', 'sql', 'env');
$assistant_system_prompt = 'You are a careful coding assistant for Tiny File Manager. Work only with the files provided in context, explain changes clearly, and avoid assuming access to anything outside the configured project root.';
