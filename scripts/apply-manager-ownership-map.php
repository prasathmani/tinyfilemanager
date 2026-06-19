<?php
/**
 * Apply explicit manager ownership mapping to $user_manager_owners in config.php.
 *
 * Usage:
 *   php scripts/apply-manager-ownership-map.php --map scripts/manager-assignments.sample.json
 *   php scripts/apply-manager-ownership-map.php --map /path/manager_assignments.json --apply
 *
 * JSON format (object):
 * {
 *   "username": "manager_username_or_admin",
 *   "username2": "admin"
 * }
 *
 * Behavior:
 * - admin and manager accounts are always forced to owner "admin".
 * - Mapping updates only listed users; others keep current value.
 * - Values are validated against current manager_users list.
 */

declare(strict_types=1);

$appRoot = dirname(__DIR__);
$configPath = $appRoot . '/config.php';

$argvList = is_array($argv ?? null) ? $argv : array();
$apply = in_array('--apply', $argvList, true);

$mapPath = '';
for ($i = 0; $i < count($argvList); $i++) {
    if ($argvList[$i] === '--map' && isset($argvList[$i + 1])) {
        $mapPath = (string) $argvList[$i + 1];
        break;
    }
}

if ($mapPath === '') {
    fwrite(STDERR, "Missing required argument: --map <json_file>\n");
    exit(1);
}

if (!preg_match('/^(?:[a-zA-Z]:[\\\\\/]|\/)/', $mapPath)) {
    $mapPath = $appRoot . '/' . ltrim($mapPath, '/\\');
}

if (!is_file($configPath) || !is_readable($configPath)) {
    fwrite(STDERR, "Config file not readable: {$configPath}\n");
    exit(1);
}

if (!is_file($mapPath) || !is_readable($mapPath)) {
    fwrite(STDERR, "Map file not readable: {$mapPath}\n");
    exit(1);
}

$configLoader = static function (string $__configFile): array {
    $auth_users = array();
    $manager_users = array();
    $user_manager_owners = array();

    /** @noinspection PhpIncludeInspection */
    include $__configFile;

    return array(
        'auth_users' => is_array($auth_users) ? $auth_users : array(),
        'manager_users' => is_array($manager_users) ? $manager_users : array(),
        'user_manager_owners' => is_array($user_manager_owners) ? $user_manager_owners : array(),
    );
};

$normalizeOwners = static function (array $owners, array $managerUsers, array $authUsers): array {
    $managerSet = array_fill_keys(array_values(array_unique(array_map('strval', $managerUsers))), true);
    $knownUsers = array_fill_keys(array_values(array_unique(array_map('strval', array_keys($authUsers)))), true);

    $normalized = array();
    foreach ($owners as $username => $owner) {
        $username = trim((string) $username);
        $owner = trim((string) $owner);
        if ($username === '' || !isset($knownUsers[$username])) {
            continue;
        }
        if ($owner === 'admin' || isset($managerSet[$owner])) {
            $normalized[$username] = $owner;
        }
    }

    return $normalized;
};

$exportOwnersCode = static function (array $owners): string {
    ksort($owners);
    $code = '$user_manager_owners = array(' . "\n";
    foreach ($owners as $user => $owner) {
        $safeUser = str_replace(array('\\\\', "'"), array('\\\\\\\\', "\\\\'"), (string) $user);
        $safeOwner = str_replace(array('\\\\', "'"), array('\\\\\\\\', "\\\\'"), (string) $owner);
        $code .= "    '{$safeUser}' => '{$safeOwner}',\n";
    }
    $code .= ');';
    return $code;
};

$replaceOwnersAssignment = static function (string $configContent, string $newCode): array {
    $patterns = array(
        '/\\$user_manager_owners\\s*=\\s*array\\s*\\((?:.|[\\r\\n])*?\\)\\s*;/U',
        '/\\$user_manager_owners\\s*=\\s*\\[(?:.|[\\r\\n])*?\\]\\s*;/U',
    );

    foreach ($patterns as $pattern) {
        $count = 0;
        $updated = preg_replace($pattern, $newCode, $configContent, 1, $count);
        if (is_string($updated) && $count === 1) {
            return array('ok' => true, 'content' => $updated);
        }
    }

    if (preg_match('/\\?>\\s*$/', $configContent) === 1) {
        $updated = preg_replace('/\\?>\\s*$/', "\n\n{$newCode}\n?>", $configContent, 1);
    } else {
        $updated = rtrim($configContent) . "\n\n{$newCode}\n";
    }

    if (!is_string($updated) || $updated === '') {
        return array('ok' => false, 'error' => 'Failed to append $user_manager_owners assignment.');
    }

    return array('ok' => true, 'content' => $updated);
};

$config = $configLoader($configPath);
$authUsers = $config['auth_users'];
$managerUsers = array_values(array_unique(array_map('strval', $config['manager_users'])));
$currentOwners = $normalizeOwners($config['user_manager_owners'], $managerUsers, $authUsers);

$rawJson = file_get_contents($mapPath);
if (!is_string($rawJson) || trim($rawJson) === '') {
    fwrite(STDERR, "Map file is empty: {$mapPath}\n");
    exit(1);
}

$decoded = json_decode($rawJson, true);
if (!is_array($decoded)) {
    fwrite(STDERR, "Invalid JSON object in map file: {$mapPath}\n");
    exit(1);
}

$isList = array_keys($decoded) === range(0, count($decoded) - 1);
if ($isList) {
    fwrite(STDERR, "Map JSON must be an object: {\"username\":\"owner\"}\n");
    exit(1);
}

$knownUsers = array_fill_keys(array_map('strval', array_keys($authUsers)), true);
$managerSet = array_fill_keys($managerUsers, true);

$targetOwners = $currentOwners;
$errors = array();
$warnings = array();
$changes = array();

foreach ($decoded as $usernameRaw => $ownerRaw) {
    $username = trim((string) $usernameRaw);
    $owner = trim((string) $ownerRaw);

    if ($username === '') {
        $errors[] = 'Empty username key in mapping.';
        continue;
    }

    if (!isset($knownUsers[$username])) {
        $errors[] = 'Unknown username in mapping: ' . $username;
        continue;
    }

    if ($owner === '') {
        $errors[] = 'Empty owner for username: ' . $username;
        continue;
    }

    if ($owner !== 'admin' && !isset($managerSet[$owner])) {
        $errors[] = 'Invalid owner for ' . $username . ': ' . $owner . ' (must be admin or existing manager)';
        continue;
    }

    if ($username === 'admin' || isset($managerSet[$username])) {
        if ($owner !== 'admin') {
            $warnings[] = 'Owner for ' . $username . ' forced to admin.';
        }
        $owner = 'admin';
    }

    $old = isset($targetOwners[$username]) ? (string) $targetOwners[$username] : '-';
    $targetOwners[$username] = $owner;
    if ($old !== $owner) {
        $changes[] = $username . ': ' . $old . ' -> ' . $owner;
    }
}

foreach (array_keys($authUsers) as $username) {
    $username = (string) $username;
    if ($username === 'admin' || isset($managerSet[$username])) {
        $old = isset($targetOwners[$username]) ? (string) $targetOwners[$username] : '-';
        $targetOwners[$username] = 'admin';
        if ($old !== 'admin') {
            $changes[] = $username . ': ' . $old . ' -> admin (forced)';
        }
    }
}

$targetOwners = $normalizeOwners($targetOwners, $managerUsers, $authUsers);
ksort($targetOwners);

fwrite(STDOUT, 'Mode: ' . ($apply ? 'APPLY' : 'DRY-RUN') . "\n");
fwrite(STDOUT, 'Config: ' . $configPath . "\n");
fwrite(STDOUT, 'Map: ' . $mapPath . "\n\n");

if (!empty($warnings)) {
    fwrite(STDOUT, "Warnings:\n");
    foreach ($warnings as $w) {
        fwrite(STDOUT, '  - ' . $w . "\n");
    }
    fwrite(STDOUT, "\n");
}

if (!empty($errors)) {
    fwrite(STDERR, "Validation errors:\n");
    foreach ($errors as $e) {
        fwrite(STDERR, '  - ' . $e . "\n");
    }
    exit(2);
}

if (empty($changes)) {
    fwrite(STDOUT, "No ownership changes required.\n");
    exit(0);
}

fwrite(STDOUT, "Planned changes:\n");
foreach ($changes as $line) {
    fwrite(STDOUT, '  - ' . $line . "\n");
}

fwrite(STDOUT, "\nPlanned owner entries: " . count($targetOwners) . "\n");

if (!$apply) {
    fwrite(STDOUT, "\nDry-run complete. Re-run with --apply to write config.php.\n");
    exit(0);
}

$configContent = file_get_contents($configPath);
if (!is_string($configContent) || $configContent === '') {
    fwrite(STDERR, "Failed to read config.php content.\n");
    exit(1);
}

$newOwnersCode = $exportOwnersCode($targetOwners);
$replaceResult = $replaceOwnersAssignment($configContent, $newOwnersCode);
if (empty($replaceResult['ok']) || !isset($replaceResult['content'])) {
    fwrite(STDERR, (isset($replaceResult['error']) ? $replaceResult['error'] : 'Failed to update config content.') . "\n");
    exit(1);
}

$backupPath = $configPath . '.bak.' . date('Ymd_His');
if (file_put_contents($backupPath, $configContent) === false) {
    fwrite(STDERR, "Failed to create backup: {$backupPath}\n");
    exit(1);
}

if (file_put_contents($configPath, $replaceResult['content']) === false) {
    fwrite(STDERR, "Failed to write config.php\n");
    exit(1);
}

fwrite(STDOUT, "\nApplied successfully. Backup created: {$backupPath}\n");
exit(0);
