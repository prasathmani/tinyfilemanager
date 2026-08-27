<?php

if (PHP_SAPI !== 'cli' || $argc !== 2) {
    fwrite(STDERR, "invalid configuration-validator invocation\n");
    exit(2);
}

$use_auth = null;
$auth_users = null;
$readonly_users = null;
$directories_users = null;
$global_readonly = null;
$root_path = null;
$root_url = null;
$path_display_mode = null;
$container_tls_proxy = null;
$online_viewer = null;
$settings_enabled = null;
$direct_links_enabled = null;
$raw_previews_enabled = null;
$url_upload_enabled = null;

$constantsBefore = get_defined_constants();
ob_start();
include $argv[1];
$output = ob_get_clean();
$constantsAfter = get_defined_constants();

$errors = array();
if ($output !== '') {
    $errors[] = 'config.php must not produce output';
}
if ($use_auth !== true) {
    $errors[] = 'local authentication must be enabled';
}
if (!is_array($auth_users) || $auth_users === array()) {
    $errors[] = 'at least one local user is required';
} else {
    $defaultHashes = array(
        '$2y$10$/K.hjNr84lLNDt8fTXjoI.DBp6PpeyoJ.mGwrrLuCZfAwfSAGqhOW',
        '$2y$10$Fg6Dz8oH9fPoZ2jJan5tZuv6Z4Kp7avtQ9bDfrdRntXtPeiMAZyGO',
    );
    foreach ($auth_users as $name => $hash) {
        $hashInfo = is_string($hash) ? password_get_info($hash) : array();
        if (!is_string($name) || $name === '') {
            $errors[] = 'user names must be non-empty strings';
        }
        if (!is_string($hash)
            || in_array($hash, $defaultHashes, true)
            || !isset($hashInfo['algoName'])
            || $hashInfo['algoName'] === 'unknown') {
            $errors[] = 'every user must have a non-default password_hash value';
        }
    }
}
if (!is_array($readonly_users)) {
    $errors[] = 'readonly_users must be an array';
}
if (!is_bool($global_readonly)) {
    $errors[] = 'global_readonly must be a boolean';
}
if ($directories_users !== array()) {
    $errors[] = 'per-user data roots are not supported by this container';
}
if ($root_path !== '/srv/tinyfilemanager/data' || $root_url !== '') {
    $errors[] = 'the data root must remain outside the Apache document root';
}
if ($path_display_mode !== 'relative') {
    $errors[] = 'path display mode must remain relative';
}
$allowedConstants = array(
    'FM_ROOT_URL' => '',
    'FM_SELF_URL' => '/index.php',
);
$newConstants = array_diff_key($constantsAfter, $constantsBefore);
foreach ($newConstants as $name => $value) {
    if (!array_key_exists($name, $allowedConstants)
        || $value !== $allowedConstants[$name]) {
        $errors[] = 'config.php defined an unsupported constant';
    }
}
foreach ($allowedConstants as $name => $value) {
    if (!defined($name) || constant($name) !== $value) {
        $errors[] = 'config.php must define the fixed relative URL constants';
    }
}
if (!is_bool($container_tls_proxy)) {
    $errors[] = 'container_tls_proxy must be a boolean';
} else {
    $secureCookie = filter_var(
        ini_get('session.cookie_secure'), FILTER_VALIDATE_BOOLEAN);
    if ($secureCookie !== $container_tls_proxy) {
        $errors[] = 'TLS proxy mode and the Secure session cookie must match';
    }
}
$requiredSessionSettings = array(
    'session.use_only_cookies' => '1',
    'session.use_strict_mode' => '1',
    'session.use_trans_sid' => '0',
    'session.cookie_httponly' => '1',
    'session.cookie_samesite' => 'Lax',
);
foreach ($requiredSessionSettings as $name => $value) {
    if ((string) ini_get($name) !== $value) {
        $errors[] = 'required session hardening was changed';
    }
}
if ($online_viewer !== false
    || $settings_enabled !== false
    || $direct_links_enabled !== false
    || $raw_previews_enabled !== false
    || $url_upload_enabled !== false) {
    $errors[] = 'unsafe network and direct-access features must remain disabled';
}

if ($errors !== array()) {
    foreach (array_unique($errors) as $error) {
        fwrite(STDERR, "tinyfilemanager: $error\n");
    }
    exit(1);
}
