<?php
/**
 * Migrate runtime config.php values and UI preferences into SQLite config store.
 *
 * Usage:
 *   php scripts/migrate-config-to-db.php          # dry-run
 *   php scripts/migrate-config-to-db.php --apply   # write into SQLite
 */

declare(strict_types=1);

$appRoot = dirname(__DIR__);
$apply = in_array('--apply', $argv, true);

if (!function_exists('fm_runtime_state_dir')) {
    function fm_runtime_state_dir()
    {
        global $state_storage_path;

        $candidate = '';
        if (isset($state_storage_path) && is_string($state_storage_path)) {
            $candidate = trim($state_storage_path);
        }

        if ($candidate === '') {
            $candidate = dirname(__DIR__) . '/.fm_usercfg';
        }

        if (!preg_match('~^(?:[a-zA-Z]:[\\/]|/)~', $candidate)) {
            $candidate = dirname(__DIR__) . '/' . ltrim($candidate, '/\\');
        }

        return rtrim(str_replace('\\', '/', $candidate), '/');
    }
}

require_once $appRoot . '/src/ConfigStore.php';

$configFile = $appRoot . '/config.php';
if (!is_file($configFile) || !is_readable($configFile)) {
    fwrite(STDERR, "Cannot read config.php\n");
    exit(1);
}

$loadConfig = static function ($filePath) {
    $CONFIG = '';
    $use_auth = null;
    $machine_login_token = null;
    $machine_login_user = null;
    $auth_users = array();
    $readonly_users = array();
    $upload_only_users = array();
    $manager_users = array();
    $bulk_actions_disabled_users = array();
    $user_welcome_messages = array();
    $welcome_message_shown_users = array();
    $global_readonly = null;
    $directories_users = array();
    $user_manager_owners = array();
    $user_notes = array();
    $user_home_root = null;
    $use_highlightjs = null;
    $highlightjs_style = null;
    $edit_files = null;
    $default_timezone = null;
    $root_path = null;
    $root_url = null;
    $http_host = null;
    $iconv_input_encoding = null;
    $datetime_format = null;
    $path_display_mode = null;
    $allowed_file_extensions = null;
    $allowed_upload_extensions = null;
    $favicon_path = null;
    $exclude_items = array();
    $online_viewer = null;
    $docx_preview_mode = null;
    $sticky_navbar = null;
    $max_upload_size_bytes = null;
    $upload_chunk_size_bytes = null;
    $ip_ruleset = null;
    $ip_silent = null;
    $ip_whitelist = array();
    $ip_blacklist = array();
    $state_storage_path = null;
    include $filePath;

    return get_defined_vars();
};

$vars = $loadConfig($configFile);
$runtimeValues = array();
foreach (fm_config_store_runtime_keys() as $key) {
    if (array_key_exists($key, $vars)) {
        $runtimeValues[$key] = $vars[$key];
    }
}

$uiDefaults = array();
if (!empty($vars['CONFIG']) && is_string($vars['CONFIG'])) {
    $decoded = json_decode($vars['CONFIG'], true);
    if (is_array($decoded)) {
        $uiDefaults = $decoded;
    }
}

$userUiSettings = array();
$stateDir = fm_runtime_state_dir();
if (is_dir($stateDir)) {
    $authUsers = isset($vars['auth_users']) && is_array($vars['auth_users']) ? $vars['auth_users'] : array();
    foreach (array_keys($authUsers) as $username) {
        $profileFile = $stateDir . '/' . md5((string) $username) . '.json';
        if (!is_file($profileFile) || !is_readable($profileFile)) {
            continue;
        }

        $decoded = json_decode((string) @file_get_contents($profileFile), true);
        if (is_array($decoded)) {
            $userUiSettings[(string) $username] = $decoded;
        }
    }
}

fwrite(STDOUT, "Mode: " . ($apply ? 'APPLY' : 'DRY-RUN') . "\n");
fwrite(STDOUT, "Runtime config keys: " . count($runtimeValues) . "\n");
fwrite(STDOUT, "UI default keys: " . count($uiDefaults) . "\n");
fwrite(STDOUT, "User profiles: " . count($userUiSettings) . "\n\n");

if (!$apply) {
    fwrite(STDOUT, "Plan:\n");
    foreach ($runtimeValues as $key => $value) {
        fwrite(STDOUT, "  runtime_config/global: {$key}\n");
    }
    foreach ($uiDefaults as $key => $value) {
        fwrite(STDOUT, "  ui_preferences/global: {$key}\n");
    }
    foreach ($userUiSettings as $username => $settings) {
        fwrite(STDOUT, "  ui_preferences/{$username}: " . count($settings) . " keys\n");
    }
    fwrite(STDOUT, "\nRe-run with --apply to write into SQLite config store.\n");
    exit(0);
}

$createdAt = time();
$actor = isset($vars['machine_login_user']) && is_string($vars['machine_login_user']) && $vars['machine_login_user'] !== '' ? $vars['machine_login_user'] : 'system';

$runtimeResult = fm_config_store_save_runtime_config($runtimeValues, array(
    'label' => 'runtime_config_global',
    'reason' => 'migrate-config-to-db',
    'source' => 'migration',
    'created_at' => $createdAt,
    'created_by' => $actor,
    'updated_by' => $actor,
    'snapshot_label' => 'runtime_config_global',
    'snapshot_reason' => 'Migrated runtime configuration from config.php',
    'source_file' => $configFile,
    'backup_name' => 'config.php migration snapshot',
));

if (empty($runtimeResult['ok'])) {
    fwrite(STDERR, "Failed to save runtime config: " . (isset($runtimeResult['error']) ? $runtimeResult['error'] : 'unknown error') . "\n");
    exit(1);
}

$uiResult = fm_config_store_save_ui_preferences('global', $uiDefaults, array(
    'label' => 'ui_preferences_global',
    'reason' => 'migrate-config-to-db',
    'source' => 'migration',
    'created_at' => $createdAt,
    'created_by' => $actor,
    'updated_by' => $actor,
    'snapshot_label' => 'ui_preferences_global',
    'snapshot_reason' => 'Migrated default UI preferences from config.php',
    'source_file' => $configFile,
    'backup_name' => 'config.php UI snapshot',
));

if (empty($uiResult['ok'])) {
    fwrite(STDERR, "Failed to save UI defaults: " . (isset($uiResult['error']) ? $uiResult['error'] : 'unknown error') . "\n");
    exit(1);
}

$profileCount = 0;
foreach ($userUiSettings as $username => $settings) {
    $profileResult = fm_config_store_save_ui_preferences($username, $settings, array(
        'label' => 'ui_preferences:' . $username,
        'reason' => 'migrate-config-to-db',
        'source' => 'migration',
        'created_at' => $createdAt,
        'created_by' => $actor,
        'updated_by' => $actor,
        'snapshot_label' => 'ui_preferences:' . $username,
        'snapshot_reason' => 'Migrated user profile settings from legacy JSON',
    ));
    if (empty($profileResult['ok'])) {
        fwrite(STDERR, "Failed to save UI profile for {$username}: " . (isset($profileResult['error']) ? $profileResult['error'] : 'unknown error') . "\n");
        exit(1);
    }
    $profileCount++;
}

fwrite(STDOUT, "\nMigration finished successfully.\n");
fwrite(STDOUT, "  runtime config keys: " . count($runtimeValues) . "\n");
fwrite(STDOUT, "  ui defaults keys: " . count($uiDefaults) . "\n");
fwrite(STDOUT, "  user profiles saved: {$profileCount}\n");

exit(0);