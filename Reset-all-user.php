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

    $bounds = findAuthUsersAssignmentBounds($content);
    if (!$bounds['ok']) {
        return array('ok' => false, 'error' => 'Failed to locate $auth_users declaration in config.php.');
    }

    $start = (int) $bounds['start'];
    $length = (int) $bounds['length'];
    $updated = substr_replace($content, $newCode, $start, $length);

    $backupFile = $configFile . '.bak.reset.' . date('Ymd_His');
    if (@file_put_contents($backupFile, $content) === false) {
        return array('ok' => false, 'error' => 'Failed to create backup file: ' . $backupFile);
    }

    if (@file_put_contents($configFile, $updated) === false) {
        return array('ok' => false, 'error' => 'Failed to write updated config file.');
    }

    return array('ok' => true, 'backup_file' => $backupFile);
}

function findAuthUsersAssignmentBounds($content)
{
    if (!is_string($content) || $content === '') {
        return array('ok' => false);
    }

    if (!preg_match('/\$auth_users\s*=\s*(array\s*\(|\[)/', $content, $m, PREG_OFFSET_CAPTURE)) {
        return array('ok' => false);
    }

    $start = (int) $m[0][1];
    $token = (string) $m[1][0];
    $openPos = 0;
    $closeChar = ')';

    if (strpos($token, 'array') === 0) {
        $openPos = strpos($content, '(', $start);
        $closeChar = ')';
    } else {
        $openPos = strpos($content, '[', $start);
        $closeChar = ']';
    }

    if ($openPos === false) {
        return array('ok' => false);
    }

    $closePos = findMatchingBracketPos($content, $openPos, $closeChar);
    if ($closePos < 0) {
        return array('ok' => false);
    }

    $end = $closePos + 1;
    $len = strlen($content);
    while ($end < $len && ctype_space($content[$end])) {
        $end++;
    }
    if ($end < $len && $content[$end] === ';') {
        $end++;
    }

    return array(
        'ok' => true,
        'start' => $start,
        'length' => $end - $start,
    );
}

function findMatchingBracketPos($content, $openPos, $closeChar)
{
    $openChar = $content[$openPos];
    $depth = 1;
    $inSingle = false;
    $inDouble = false;
    $escaped = false;
    $len = strlen($content);

    for ($i = $openPos + 1; $i < $len; $i++) {
        $ch = $content[$i];

        if ($escaped) {
            $escaped = false;
            continue;
        }

        if ($ch === '\\') {
            $escaped = true;
            continue;
        }

        if ($inSingle) {
            if ($ch === "'") {
                $inSingle = false;
            }
            continue;
        }

        if ($inDouble) {
            if ($ch === '"') {
                $inDouble = false;
            }
            continue;
        }

        if ($ch === "'") {
            $inSingle = true;
            continue;
        }

        if ($ch === '"') {
            $inDouble = true;
            continue;
        }

        if ($ch === $openChar) {
            $depth++;
            continue;
        }

        if ($ch === $closeChar) {
            $depth--;
            if ($depth === 0) {
                return $i;
            }
        }
    }

    return -1;
}
