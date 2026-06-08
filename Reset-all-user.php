<?php
/**
 * Reset-all-user.php
 *
 * CLI utility for generating initial passwords for all users in config.php,
 * excluding admin.
 *
 * Rule:
 * - password = username with first letter uppercased + "/01"
 * - example: rehak => Rehak/01
 *
 * Usage:
 *   php Reset-all-user.php
 *   php Reset-all-user.php /absolute/path/to/config.php
 */

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "This script can run only in CLI mode.\n");
    exit(1);
}

$configFile = isset($argv[1]) && trim((string) $argv[1]) !== ''
    ? (string) $argv[1]
    : __DIR__ . '/config.php';

if (!is_file($configFile) || !is_readable($configFile)) {
    fwrite(STDERR, "Config file is not readable: {$configFile}\n");
    exit(1);
}

$configData = loadConfigArrays($configFile);
if (!$configData['ok']) {
    fwrite(STDERR, $configData['error'] . "\n");
    exit(1);
}

$usernames = collectUsernames($configData);
$usernames = array_values(array_filter(array_unique($usernames), 'strlen'));
sort($usernames);

$authUsers = $configData['auth_users'];
$generatedPlainPasswords = array();
$updatedCount = 0;

foreach ($usernames as $username) {
    if ($username === 'admin') {
        continue;
    }

    $initialPassword = buildInitialPassword($username);
    $authUsers[$username] = password_hash($initialPassword, PASSWORD_DEFAULT);
    $generatedPlainPasswords[$username] = $initialPassword;
    $updatedCount++;
}

$persistResult = persistAuthUsersArray($configFile, $authUsers);
if (!$persistResult['ok']) {
    fwrite(STDERR, $persistResult['error'] . "\n");
    exit(1);
}

fwrite(STDOUT, "Updated users: {$updatedCount}\n");
fwrite(STDOUT, "Config backup: {$persistResult['backup_file']}\n\n");
fwrite(STDOUT, "Generated initial passwords (plain):\n");
foreach ($generatedPlainPasswords as $username => $plainPassword) {
    fwrite(STDOUT, "- {$username}: {$plainPassword}\n");
}

exit(0);

function loadConfigArrays($configFile)
{
    $loader = static function ($__configFile) {
        $auth_users = array();
        $readonly_users = array();
        $upload_only_users = array();
        $manager_users = array();
        $directories_users = array();
        $user_notes = array();
        include $__configFile;

        return array(
            'auth_users' => is_array($auth_users) ? $auth_users : array(),
            'readonly_users' => is_array($readonly_users) ? $readonly_users : array(),
            'upload_only_users' => is_array($upload_only_users) ? $upload_only_users : array(),
            'manager_users' => is_array($manager_users) ? $manager_users : array(),
            'directories_users' => is_array($directories_users) ? $directories_users : array(),
            'user_notes' => is_array($user_notes) ? $user_notes : array(),
        );
    };

    try {
        $data = $loader($configFile);
    } catch (Throwable $e) {
        return array('ok' => false, 'error' => 'Failed to load config: ' . $e->getMessage());
    }

    $data['ok'] = true;
    return $data;
}

function collectUsernames(array $configData)
{
    $authUsers = isset($configData['auth_users']) && is_array($configData['auth_users']) ? $configData['auth_users'] : array();
    $readonlyUsers = isset($configData['readonly_users']) && is_array($configData['readonly_users']) ? $configData['readonly_users'] : array();
    $uploadOnlyUsers = isset($configData['upload_only_users']) && is_array($configData['upload_only_users']) ? $configData['upload_only_users'] : array();
    $managerUsers = isset($configData['manager_users']) && is_array($configData['manager_users']) ? $configData['manager_users'] : array();
    $directoriesUsers = isset($configData['directories_users']) && is_array($configData['directories_users']) ? $configData['directories_users'] : array();
    $userNotes = isset($configData['user_notes']) && is_array($configData['user_notes']) ? $configData['user_notes'] : array();

    return array_merge(
        array_keys($authUsers),
        $readonlyUsers,
        $uploadOnlyUsers,
        $managerUsers,
        array_keys($directoriesUsers),
        array_keys($userNotes)
    );
}

function buildInitialPassword($username)
{
    $username = (string) $username;
    if ($username === '') {
        return '/01';
    }

    if (function_exists('mb_substr') && function_exists('mb_strtoupper')) {
        $first = mb_substr($username, 0, 1, 'UTF-8');
        $rest = mb_substr($username, 1, null, 'UTF-8');
        return mb_strtoupper($first, 'UTF-8') . $rest . '/01';
    }

    return strtoupper(substr($username, 0, 1)) . substr($username, 1) . '/01';
}

function exportAuthUsersCode(array $authUsers)
{
    ksort($authUsers);
    $code = '$auth_users = array(' . "\n";
    foreach ($authUsers as $username => $hash) {
        $safeUser = str_replace(array('\\', "'"), array('\\\\', "\\'"), (string) $username);
        $safeHash = str_replace(array('\\', "'"), array('\\\\', "\\'"), (string) $hash);
        $code .= "    '{$safeUser}' => '{$safeHash}'," . "\n";
    }
    $code .= ');';
    return $code;
}

function persistAuthUsersArray($configFile, array $authUsers)
{
    $content = @file_get_contents($configFile);
    if ($content === false) {
        return array('ok' => false, 'error' => 'Failed to read config file for writing.');
    }

    $newCode = exportAuthUsersCode($authUsers);

    $patterns = array(
        '/\$auth_users\s*=\s*array\s*\((?:.|[\r\n])*?\)\s*;/U',
        '/\$auth_users\s*=\s*\[(?:.|[\r\n])*?\]\s*;/U',
    );

    $updated = null;
    foreach ($patterns as $pattern) {
        $count = 0;
        $candidate = preg_replace($pattern, $newCode, $content, 1, $count);
        if ($candidate !== null && $count === 1) {
            $updated = $candidate;
            break;
        }
    }

    if (!is_string($updated)) {
        return array('ok' => false, 'error' => 'Failed to locate $auth_users declaration in config.php.');
    }

    $backupFile = $configFile . '.bak.reset.' . date('Ymd_His');
    if (@file_put_contents($backupFile, $content) === false) {
        return array('ok' => false, 'error' => 'Failed to create backup file: ' . $backupFile);
    }

    if (@file_put_contents($configFile, $updated) === false) {
        return array('ok' => false, 'error' => 'Failed to write updated config file.');
    }

    return array('ok' => true, 'backup_file' => $backupFile);
}
