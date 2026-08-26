#!/usr/bin/env php
<?php

define('FM_IS_WIN', DIRECTORY_SEPARATOR === '\\');
require_once dirname(__DIR__) . '/lib/fm_root_confinement.php';

$checks = 0;

function confinement_check($condition, $message)
{
    global $checks;
    $checks++;
    if (!$condition) {
        fwrite(STDERR, "not ok $checks - $message\n");
        exit(1);
    }
    echo "ok $checks - $message\n";
}

function confinement_remove_tree($path)
{
    if (is_link($path) || is_file($path)) {
        @unlink($path);
        return;
    }
    if (!is_dir($path)) {
        return;
    }
    foreach (scandir($path) as $name) {
        if ($name !== '.' && $name !== '..') {
            confinement_remove_tree($path . '/' . $name);
        }
    }
    @rmdir($path);
}

$sandbox = sys_get_temp_dir() . '/tinyfm-confinement-' . bin2hex(random_bytes(6));
$root = $sandbox . '/root';
$outside = $sandbox . '/outside';
mkdir($root, 0700, true);
mkdir($outside, 0700, true);
file_put_contents($root . '/inside.txt', 'inside');
file_put_contents($outside . '/krb5cc-delegated', 'delegated-cache-secret');

try {
    $canonicalRoot = fm_guard_init($root);
    confinement_check($canonicalRoot === realpath($root), 'initializes one canonical file-manager root');
    $rootDevice = stat($canonicalRoot)['dev'];
    $simulatedVolumeDevice = $rootDevice === PHP_INT_MAX
        ? $rootDevice - 1 : $rootDevice + 1;
    confinement_check(
        !fm_guard_device_is_allowed($canonicalRoot . '/volume/file',
            $simulatedVolumeDevice),
        'default policy rejects a simulated descendant st_dev transition');
    confinement_check(fm_guard_read($root . '/inside.txt') === 'inside', 'view/download read an in-root file');

    confinement_check(fm_guard_write($root . '/edited.txt', 'edited'), 'edit/create writes an in-root file');
    confinement_check(file_get_contents($root . '/edited.txt') === 'edited', 'edit/create content is retained');

    confinement_check(fm_guard_mkdir($root . '/created/nested', true), 'create makes nested in-root directories');
    confinement_check(is_dir($root . '/created/nested'), 'created directory remains below the root');

    $import = $outside . '/upload.tmp';
    file_put_contents($import, 'upload');
    confinement_check(fm_guard_import_file($import, $root . '/uploaded.txt'), 'URL/upload import enters a new in-root file');
    confinement_check(fm_guard_read($root . '/uploaded.txt') === 'upload', 'uploaded content is readable in root');

    confinement_check(fm_guard_copy_file($root . '/inside.txt', $root . '/copy.txt', false), 'copy creates an in-root file');
    confinement_check(fm_guard_rename($root . '/copy.txt', $root . '/moved.txt') === true, 'move stays in root');
    confinement_check(fm_guard_rename($root . '/moved.txt', $root . '/renamed.txt') === true, 'rename stays in root');

    mkdir($root . '/tree');
    file_put_contents($root . '/tree/leaf.txt', 'leaf');
    confinement_check(fm_guard_copy_tree($root . '/tree', $root . '/tree-copy'), 'recursive copy stays in root');
    confinement_check(fm_guard_read($root . '/tree-copy/leaf.txt') === 'leaf', 'recursive copy preserves file data');

    if (!FM_IS_WIN && function_exists('symlink')) {
        symlink($root . '/inside.txt', $root . '/inside-link');
        confinement_check(fm_guard_read($root . '/inside-link') === 'inside', 'an in-root symlink remains usable');
        confinement_check(fm_guard_copy_tree($root . '/inside-link', $root . '/inside-link-copy'), 'copy preserves a valid in-root symlink');
        confinement_check(is_link($root . '/inside-link-copy')
            && fm_guard_read($root . '/inside-link-copy') === 'inside', 'copied in-root symlink remains confined and usable');

        $secretLink = $root . '/delegated-cache-link';
        symlink($outside . '/krb5cc-delegated', $secretLink);
        confinement_check(fm_guard_existing($secretLink, 'file') === false, 'view rejects an out-of-root delegated-cache symlink');
        confinement_check(fm_guard_open_read($secretLink) === false, 'download/direct streaming rejects the secret symlink');
        confinement_check(fm_guard_write($secretLink, 'overwrite') === false, 'edit rejects writes through the secret symlink');
        confinement_check(fm_guard_copy_file($secretLink, $root . '/leak.txt', false) === false, 'copy rejects the secret symlink');
        confinement_check(fm_guard_copy_tree($secretLink, $root . '/leak-tree') === false, 'recursive copy rejects the secret symlink');

        $blockedImport = $outside . '/blocked-upload.tmp';
        file_put_contents($blockedImport, 'blocked');
        confinement_check(fm_guard_import_file($blockedImport, $secretLink) === false, 'upload rejects a symlink destination');
        confinement_check(file_exists($blockedImport), 'rejected upload leaves its source intact');

        $listing = fm_guard_scandir($root);
        confinement_check(is_array($listing) && !in_array('delegated-cache-link', $listing, true), 'list/search omit an escaping symlink');
        confinement_check(fm_guard_delete($secretLink), 'delete unlinks an escaping link without following it');
        confinement_check(file_get_contents($outside . '/krb5cc-delegated') === 'delegated-cache-secret', 'delete leaves the outside cache unchanged');
    }

    mkdir($root . '/nested-mount');
    $GLOBALS['FM_ROOT_GUARD_MOUNTINFO'] =
        "100 0 0:1 / / rw - overlay overlay rw\n"
        . '101 100 0:42 / ' . $root . '/nested-mount rw - tmpfs tmpfs rw' . "\n";
    confinement_check(fm_guard_existing($root . '/nested-mount', 'dir') === false, 'list/read reject a nested mountpoint');
    confinement_check(fm_guard_create_path($root . '/nested-mount/new.txt') === false, 'writes reject a nested mountpoint');
    unset($GLOBALS['FM_ROOT_GUARD_MOUNTINFO']);

    confinement_check(fm_guard_archive_member('folder/file.txt') === 'folder/file.txt', 'archive accepts a relative in-root member');
    confinement_check(fm_guard_archive_member('../krb5cc') === false, 'archive rejects parent traversal');
    confinement_check(fm_guard_archive_member('/run/secrets/keytab') === false, 'archive rejects an absolute secret path');
    confinement_check(fm_guard_archive_member('C:\\secrets\\keytab') === false, 'archive rejects a drive-qualified secret path');

    confinement_check(fm_guard_delete($root . '/tree-copy'), 'recursive delete removes only an in-root tree');
    confinement_check(!file_exists($root . '/tree-copy'), 'deleted in-root tree is gone');
} finally {
    unset($GLOBALS['FM_ROOT_GUARD_MOUNTINFO']);
    confinement_remove_tree($sandbox);
}

echo "PASS: $checks filesystem-confinement behavior checks\n";
