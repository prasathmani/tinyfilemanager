<?php
/**
 * One-time migration helper for runtime state files.
 *
 * Usage:
 *   php scripts/migrate-legacy-state.php           # dry-run
 *   php scripts/migrate-legacy-state.php --apply   # copy + cleanup migrated files
 */

declare(strict_types=1);

$appRoot = dirname(__DIR__);
$legacyDir = $appRoot . '/.fm_usercfg';

$apply = in_array('--apply', $argv, true);

if (!is_dir($legacyDir)) {
    fwrite(STDOUT, "Legacy directory not found: {$legacyDir}\n");
    exit(0);
}

$configPath = $appRoot . '/config.php';
$stateStoragePath = '';
if (is_file($configPath)) {
    /** @noinspection PhpIncludeInspection */
    include $configPath;
    if (isset($state_storage_path) && is_string($state_storage_path)) {
        $stateStoragePath = trim($state_storage_path);
    }
}

if ($stateStoragePath === '') {
    $targetDir = $legacyDir;
} else {
    if (!preg_match('/^(?:[a-zA-Z]:[\\\\\/]|\/)/', $stateStoragePath)) {
        $stateStoragePath = $appRoot . '/' . ltrim($stateStoragePath, '/\\');
    }
    $targetDir = rtrim(str_replace('\\', '/', $stateStoragePath), '/');
}

if ($targetDir === '') {
    fwrite(STDERR, "Invalid target directory resolved from config.\n");
    exit(1);
}

if (!is_dir($targetDir) && !@mkdir($targetDir, 0750, true)) {
    fwrite(STDERR, "Cannot create target directory: {$targetDir}\n");
    exit(1);
}

$targetHtaccess = $targetDir . '/.htaccess';
if (!is_file($targetHtaccess)) {
    @file_put_contents($targetHtaccess, "Order Deny,Allow\nDeny from all\n");
}

if (realpath($legacyDir) === realpath($targetDir)) {
    fwrite(STDOUT, "Legacy and target directories are identical: {$targetDir}\n");
    fwrite(STDOUT, "Nothing to migrate.\n");
    exit(0);
}

$entries = scandir($legacyDir);
if (!is_array($entries)) {
    fwrite(STDERR, "Cannot read legacy directory: {$legacyDir}\n");
    exit(1);
}

$copied = 0;
$already = 0;
$conflicts = 0;
$removed = 0;
$skipped = 0;

fwrite(STDOUT, "Mode: " . ($apply ? 'APPLY' : 'DRY-RUN') . "\n");
fwrite(STDOUT, "Legacy: {$legacyDir}\n");
fwrite(STDOUT, "Target: {$targetDir}\n\n");

foreach ($entries as $name) {
    if ($name === '.' || $name === '..' || $name === '.htaccess') {
        continue;
    }

    $from = $legacyDir . '/' . $name;
    if (!is_file($from)) {
        $skipped++;
        fwrite(STDOUT, "SKIP   {$name} (not a regular file)\n");
        continue;
    }

    $to = $targetDir . '/' . $name;

    if (!is_file($to)) {
        if ($apply) {
            if (@copy($from, $to)) {
                $copied++;
                fwrite(STDOUT, "COPY   {$name}\n");
                if (@hash_file('sha256', $from) === @hash_file('sha256', $to)) {
                    if (@unlink($from)) {
                        $removed++;
                        fwrite(STDOUT, "REMOVE {$name}\n");
                    }
                }
            } else {
                $conflicts++;
                fwrite(STDOUT, "ERROR  {$name} (copy failed)\n");
            }
        } else {
            fwrite(STDOUT, "PLAN   copy {$name}\n");
        }
        continue;
    }

    $same = (@hash_file('sha256', $from) === @hash_file('sha256', $to));
    if ($same) {
        $already++;
        fwrite(STDOUT, "OK     {$name} (already in target)\n");
        if ($apply) {
            if (@unlink($from)) {
                $removed++;
                fwrite(STDOUT, "REMOVE {$name}\n");
            }
        }
    } else {
        $conflicts++;
        fwrite(STDOUT, "KEEP   {$name} (target differs, manual review needed)\n");
    }
}

$remaining = 0;
foreach (scandir($legacyDir) ?: array() as $name) {
    if ($name === '.' || $name === '..' || $name === '.htaccess') {
        continue;
    }
    if (is_file($legacyDir . '/' . $name) || is_dir($legacyDir . '/' . $name)) {
        $remaining++;
    }
}

if ($apply && $remaining === 0) {
    @unlink($legacyDir . '/.htaccess');
    @rmdir($legacyDir);
}

fwrite(STDOUT, "\nSummary:\n");
fwrite(STDOUT, "  copied: {$copied}\n");
fwrite(STDOUT, "  already present: {$already}\n");
fwrite(STDOUT, "  removed from legacy: {$removed}\n");
fwrite(STDOUT, "  conflicts/errors: {$conflicts}\n");
fwrite(STDOUT, "  skipped: {$skipped}\n");
fwrite(STDOUT, "  remaining in legacy: {$remaining}\n");

exit($conflicts > 0 ? 2 : 0);
