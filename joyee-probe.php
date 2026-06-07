<?php
/**
 * Public diagnostic probe for Joyee/ChatGPT runtime connectivity.
 *
 * This endpoint is intentionally public and does not expose secrets.
 * It is used only to confirm whether external runtimes can reach this host.
 */

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

echo json_encode(array(
    'ok' => true,
    'service' => 'joyee-probe',
    'message' => 'Dremont Joyee public probe works',
    'time' => date('c'),
    'request' => array(
        'method' => $_SERVER['REQUEST_METHOD'] ?? null,
        'host' => $_SERVER['HTTP_HOST'] ?? null,
        'uri' => $_SERVER['REQUEST_URI'] ?? null,
        'remote_addr' => $_SERVER['REMOTE_ADDR'] ?? null,
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
        'accept' => $_SERVER['HTTP_ACCEPT'] ?? null,
        'cf_ray' => $_SERVER['HTTP_CF_RAY'] ?? null,
        'x_forwarded_for' => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? null,
    ),
), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);