<?php
/**
 * Backfill and normalize $user_manager_owners in config.php.
 *
 * Usage:
 *   php scripts/migrate-user-manager-owners.php               # dry-run
 *   php scripts/migrate-user-manager-owners.php --apply       # write changes
 *   php scripts/migrate-user-manager-owners.php --apply --rebuild
 *
 * Rules:
 * - admin and all manager accounts are always owned by 'admin'.
 * - Existing valid ownership entries are preserved by default.
 * - Missing/invalid ownership entries are inferred:
 *   - if exactly one manager shares at least one exact allowed directory path,
 *     assign that manager;
 *   - otherwise assign 'admin'.
 */

declare(strict_types=1);

$appRoot = dirname(__DIR__);
$configPath = $appRoot . '/config.php';

$apply = in_array('--apply', $argv, true);
$rebuild = in_array('--rebuild', $argv, true);

if (!is_file($configPath) || !is_readable($configPath)) {
    fwrite(STDERR, "Config file not readable: {$configPath}\n");
    exit(1);
}

$configLoader = static function (string $__configFile): array {
    $auth_users = array();
    $manager_users = array();
    $directories_users = array();
    $user_manager_owners = array();

    /** @noinspection PhpIncludeInspection */
    include $__configFile;

    return array(
        'auth_users' => is_array($auth_users) ? $auth_users : array(),
        'manager_users' => is_array($manager_users) ? $manager_users : array(),
        'directories_users' => is_array($directories_users) ? $directories_users : array(),
        'user_manager_owners' => is_array($user_manager_owners) ? $user_manager_owners : array(),
    );
};

/**
 * @param array<int|string,mixed> $dirsRaw
 * @param string $rootPath
 * @return array<int,string>
 */
$normalizeDirs = static function ($dirsRaw, string $rootPath): array {
    $items = is_array($dirsRaw) ? $dirsRaw : array($dirsRaw);
    $out = array();

    foreach ($items as $entry) {
        if (!is_string($entry)) {
            continue;
        }

        $dir = trim(str_replace('\\', '/', $entry));
        if ($dir === '') {
            continue;
        }

        $isAbsolute = (bool) preg_match('/^(?:[a-zA-Z]:\/|\/)/', $dir);
        $candidate = $isAbsolute ? $dir : ($rootPath . '/' . ltrim($dir, '/'));
        $candidate = rtrim(str_replace('\\', '/', $candidate), '/');
        if ($candidate === '') {
            continue;
        }

        $resolved = realpath($candidate);
        if ($resolved !== false) {
            $candidate = rtrim(str_replace('\\', '/', $resolved), '/');
        }

        $out[] = $candidate;
    }

    $out = array_values(array_unique(array_filter($out, 'strlen')));
    sort($out, SORT_NATURAL | SORT_FLAG_CASE);
    return $out;
};

/**
 * @param string $configContent
 * @param string $newCode
 * @return array{ok:bool,content?:string,error?:string}
 */
$replaceOwnersAssignment = static function (string $configContent, string $newCode): array {
    $patterns = array(
        '/\$user_manager_owners\s*=\s*array\s*\((?:.|[\r\n])*?\)\s*;/U',
        '/\$user_manager_owners\s*=\s*\[(?:.|[\r\n])*?\]\s*;/U',
    );

    foreach ($patterns as $pattern) {
        $count = 0;
        $updated = preg_replace($pattern, $newCode, $configContent, 1, $count);
        if (is_string($updated) && $count === 1) {
            return array('ok' => true, 'content' => $updated);
        }
    }

    if (preg_match('/\?>\s*$/', $configContent) === 1) {
        $updated = preg_replace('/\?>\s*$/', "\n\n{$newCode}\n?>", $configContent, 1);
    } else {
        $updated = rtrim($configContent) . "\n\n{$newCode}\n";
    }

    if (!is_string($updated) || $updated === '') {
        return array('ok' => false, 'error' => 'Failed to append $user_manager_owners assignment.');
    }

    return array('ok' => true, 'content' => $updated);
};

/**
 * @param array<string,string> $owners
 * @return string
 */
$exportOwnersCode = static function (array $owners): string {
    ksort($owners);
    $code = '$user_manager_owners = array(' . "\n";
    foreach ($owners as $user => $owner) {
        $safeUser = str_replace(array('\\', "'"), array('\\\\', "\\'"), (string) $user);
        $safeOwner = str_replace(array('\\', "'"), array('\\\\', "\\'"), (string) $owner);
        $code .= "    '{$safeUser}' => '{$safeOwner}',\n";
    }
    $code .= ');';
    return $code;
};

$config = $configLoader($configPath);
$authUsers = $config['auth_users'];
$managerUsers = array_values(array_unique(array_map('strval', $config['manager_users'])));
$directoriesUsers = $config['directories_users'];
$existingOwners = $config['user_manager_owners'];

$knownUsers = array_values(array_unique(array_map('strval', array_keys($authUsers))));
sort($knownUsers, SORT_NATURAL | SORT_FLAG_CASE);

$managerSet = array_fill_keys($managerUsers, true);
$knownSet = array_fill_keys($knownUsers, true);

$rootPath = rtrim(str_replace('\\', '/', $appRoot), '/');

$userDirs = array();
foreach ($knownUsers as $username) {
    $rawDirs = array_key_exists($username, $directoriesUsers) ? $directoriesUsers[$username] : array();
    $userDirs[$username] = $normalizeDirs($rawDirs, $rootPath);
}

$normalizedExisting = array();
foreach ($existingOwners as $username => $owner) {
    $username = trim((string) $username);
    $owner = trim((string) $owner);
    if ($username === '' || !isset($knownSet[$username])) {
        continue;
    }
    if ($owner === 'admin' || isset($managerSet[$owner])) {
        $normalizedExisting[$username] = $owner;
    }
}

$resultOwners = array();
$report = array();

foreach ($knownUsers as $username) {
    $forcedAdmin = ($username === 'admin' || isset($managerSet[$username]));

    if ($forcedAdmin) {
        $resultOwners[$username] = 'admin';
        $report[] = array($username, isset($normalizedExisting[$username]) ? $normalizedExisting[$username] : '-', 'admin', 'forced_admin_or_manager');
        continue;
    }

    if (!$rebuild && isset($normalizedExisting[$username])) {
        $resultOwners[$username] = $normalizedExisting[$username];
        $report[] = array($username, $normalizedExisting[$username], $normalizedExisting[$username], 'kept_existing');
        continue;
    }

    $dirs = isset($userDirs[$username]) ? $userDirs[$username] : array();
    $matches = array();

    if (!empty($dirs)) {
        $dirSet = array_fill_keys($dirs, true);
        foreach ($managerUsers as $managerName) {
            $managerDirs = isset($userDirs[$managerName]) ? $userDirs[$managerName] : array();
            $intersects = false;
            foreach ($managerDirs as $managerDir) {
                if (isset($dirSet[$managerDir])) {
                    $intersects = true;
                    break;
                }
            }
            if ($intersects) {
                $matches[] = $managerName;
            }
        }
    }

    if (count($matches) === 1) {
        $resultOwners[$username] = $matches[0];
        $report[] = array($username, isset($normalizedExisting[$username]) ? $normalizedExisting[$username] : '-', $matches[0], 'inferred_single_manager_match');
    } elseif (count($matches) > 1) {
        $resultOwners[$username] = 'admin';
        $report[] = array($username, isset($normalizedExisting[$username]) ? $normalizedExisting[$username] : '-', 'admin', 'fallback_ambiguous_managers:' . implode('|', $matches));
    } else {
        $resultOwners[$username] = 'admin';
        $report[] = array($username, isset($normalizedExisting[$username]) ? $normalizedExisting[$username] : '-', 'admin', 'fallback_no_manager_match');
    }
}

ksort($resultOwners);

fwrite(STDOUT, 'Mode: ' . ($apply ? 'APPLY' : 'DRY-RUN') . "\n");
fwrite(STDOUT, 'Config: ' . $configPath . "\n");
fwrite(STDOUT, 'Rebuild: ' . ($rebuild ? 'yes' : 'no') . "\n\n");

$changes = 0;
foreach ($report as $row) {
    $username = $row[0];
    $oldOwner = $row[1];
    $newOwner = $row[2];
    $reason = $row[3];
    $oldComparable = isset($normalizedExisting[$username]) ? $normalizedExisting[$username] : '-';
    if ($oldComparable !== $newOwner) {
        $changes++;
    }
    fwrite(STDOUT, sprintf("%-16s old=%-12s new=%-12s %s\n", $username, $oldOwner, $newOwner, $reason));
}

fwrite(STDOUT, "\nPlanned owner entries: " . count($resultOwners) . "\n");
fwrite(STDOUT, "Changes vs normalized existing: {$changes}\n");

if (!$apply) {
    fwrite(STDOUT, "\nDry-run complete. Re-run with --apply to write config.php.\n");
    exit(0);
}

$configContent = file_get_contents($configPath);
if (!is_string($configContent) || $configContent === '') {
    fwrite(STDERR, "Failed to read config.php content.\n");
    exit(1);
}

$newOwnersCode = $exportOwnersCode($resultOwners);
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
