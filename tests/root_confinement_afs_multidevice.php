#!/usr/bin/env php
<?php

define('FM_IS_WIN', DIRECTORY_SEPARATOR === '\\');
require_once dirname(__DIR__) . '/lib/fm_root_confinement.php';

$checks = 0;

function afs_multidevice_check($condition, $message)
{
    global $checks;
    $checks++;
    if (!$condition) {
        fwrite(STDERR, "not ok $checks - $message\n");
        exit(1);
    }
    echo "ok $checks - $message\n";
}

function afs_multidevice_remove_tree($path)
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
            afs_multidevice_remove_tree($path . '/' . $name);
        }
    }
    @rmdir($path);
}

$sandbox = sys_get_temp_dir() . '/tinyfm-afs-multidevice-' . bin2hex(random_bytes(6));
$root = $sandbox . '/root';
$outside = $sandbox . '/outside';
mkdir($root, 0700, true);
mkdir($outside, 0700, true);
mkdir($root . '/nested-mount', 0700);
file_put_contents($root . '/inside.txt', 'inside');
file_put_contents($outside . '/secret', 'outside');

try {
    $namespaceRoot = "10 0 0:1 / / rw - overlay overlay rw\n";
    $auristorMountinfo = $namespaceRoot
        . "11 10 0:2 / /afs rw - auristorfs none rw\n";
    $openafsMountinfo = $namespaceRoot
        . "11 10 0:2 / /afs rw - afs none rw\n";
    $ordinaryMountinfo = $namespaceRoot
        . "11 10 8:1 / /afs rw - ext4 /dev/root rw\n";
    $ordinaryXfsMountinfo = $namespaceRoot
        . "11 10 8:2 / /afs rw - xfs /dev/root rw\n";
    $outsideAfsMountinfo = $namespaceRoot
        . "11 10 0:2 / /srv/openafs rw - auristorfs none rw\n";
    $rhelNsfsMountinfo = $namespaceRoot
        . "12 10 0:4 net:[4026532693] /run/netns/host rw - nsfs nsfs rw\n";

    $auristorRecords = fm_guard_parse_mountinfo($auristorMountinfo);
    $openafsRecords = fm_guard_parse_mountinfo($openafsMountinfo);
    $ordinaryRecords = fm_guard_parse_mountinfo($ordinaryMountinfo);
    $ordinaryXfsRecords = fm_guard_parse_mountinfo($ordinaryXfsMountinfo);
    $outsideAfsRecords = fm_guard_parse_mountinfo($outsideAfsMountinfo);

    afs_multidevice_check(is_array($auristorRecords),
        'strict mountinfo parser accepts a complete AuriStor mount table');
    $rhelNsfsRecords = fm_guard_parse_mountinfo($rhelNsfsMountinfo);
    afs_multidevice_check(is_array($rhelNsfsRecords)
        && count($rhelNsfsRecords) === 2
        && $rhelNsfsRecords[1]['mountpoint'] === '/run/netns/host'
        && $rhelNsfsRecords[1]['filesystem'] === 'nsfs',
        'parser accepts a RHEL 9 nsfs record with opaque net namespace root');
    afs_multidevice_check(
        fm_guard_root_uses_allowlisted_afs('/afs', $auristorRecords)
            && fm_guard_root_uses_allowlisted_afs('/afs/example/path', $auristorRecords),
        'auristorfs enables AFS device transitions only at or below /afs');
    afs_multidevice_check(
        fm_guard_root_uses_allowlisted_afs('/afs/example/path', $openafsRecords),
        'Linux OpenAFS filesystem type afs is allowlisted below /afs');
    afs_multidevice_check(
        !fm_guard_root_uses_allowlisted_afs('/afs/example/path', $ordinaryRecords)
            && !fm_guard_root_uses_allowlisted_afs('/afs/example/path', $ordinaryXfsRecords),
        'ordinary ext4 and xfs mounts on /afs do not enable transitions');
    afs_multidevice_check(
        !fm_guard_root_uses_allowlisted_afs('/srv/openafs', $outsideAfsRecords)
            && !fm_guard_root_uses_allowlisted_afs('/afs2', $outsideAfsRecords),
        'an AFS-type mount outside the exact /afs namespace does not enable transitions');
    foreach (array('openafs', 'AuristorFS', 'AFS', 'fuse.auristorfs') as $alias) {
        $aliasRecords = fm_guard_parse_mountinfo($namespaceRoot
            . '11 10 0:2 / /afs rw - ' . $alias . " none rw\n");
        afs_multidevice_check(
            !fm_guard_root_uses_allowlisted_afs('/afs', $aliasRecords),
            "non-exact AFS filesystem type $alias is rejected");
    }
    afs_multidevice_check(
        !fm_guard_root_uses_allowlisted_afs('/afs',
            fm_guard_parse_mountinfo(false)),
        'unreadable mountinfo fails closed');
    afs_multidevice_check(
        fm_guard_parse_mountinfo($namespaceRoot
            . "11 10 0:2 / /afs rw auristorfs none rw\n") === false,
        'malformed mountinfo fails closed');
    afs_multidevice_check(
        fm_guard_parse_mountinfo($namespaceRoot
            . "11 10 0:2 / /afs\\999 rw - auristorfs none rw\n") === false,
        'an invalid mountinfo path escape fails closed');
    afs_multidevice_check(
        fm_guard_parse_mountinfo($namespaceRoot
            . "11 10 0:2 net:\\999 /afs rw - auristorfs none rw\n") === false,
        'an invalid opaque mount-root escape fails closed');
    afs_multidevice_check(
        fm_guard_parse_mountinfo($namespaceRoot
            . "11 10 0:2  /afs rw - auristorfs none rw\n") === false,
        'an empty mount-root field fails closed');
    afs_multidevice_check(
        fm_guard_parse_mountinfo('') === false,
        'empty mountinfo fails closed');
    $stackedOrdinaryRecords = fm_guard_parse_mountinfo($auristorMountinfo
        . "12 10 8:1 / /afs rw - ext4 /dev/root rw\n");
    afs_multidevice_check(
        !fm_guard_root_uses_allowlisted_afs('/afs', $stackedOrdinaryRecords),
        'the later record wins for an ordinary filesystem stacked on /afs');
    $stackedAfsRecords = fm_guard_parse_mountinfo($ordinaryMountinfo
        . "12 10 0:2 / /afs rw - afs none rw\n");
    afs_multidevice_check(
        fm_guard_root_uses_allowlisted_afs('/afs', $stackedAfsRecords),
        'the later record wins for OpenAFS stacked on /afs');
    afs_multidevice_check(
        fm_guard_covering_filesystem('/afs', array(array(
            'mountpoint' => '/srv', 'filesystem' => 'auristorfs'))) === false,
        'a mount table with no enclosing record fails closed');

    $GLOBALS['FM_ROOT_GUARD_MOUNTINFO'] = $namespaceRoot
        . '11 10 0:2 / ' . $root . " rw - auristorfs none rw\n";
    $canonicalRoot = fm_guard_init($root);
    afs_multidevice_check(
        empty(fm_guard_config()['allow_afs_device_transitions']),
        'initialization rejects an AFS-type mount whose root is outside /afs');
    unset($GLOBALS['FM_ROOT_GUARD_MOUNTINFO']);

    $rootDevice = stat($canonicalRoot)['dev'];
    $simulatedVolumeDevice = $rootDevice === PHP_INT_MAX
        ? $rootDevice - 1 : $rootDevice + 1;

    $config = fm_guard_config();
    $config['allow_afs_device_transitions'] =
        fm_guard_root_uses_allowlisted_afs('/afs', $auristorRecords);
    $GLOBALS['FM_ROOT_GUARD'] = $config;

    afs_multidevice_check(
        fm_guard_device_is_allowed($canonicalRoot . '/volume/file',
            $simulatedVolumeDevice),
        'verified AFS mode accepts a simulated descendant st_dev transition');
    afs_multidevice_check(
        !fm_guard_device_is_allowed($canonicalRoot, $simulatedVolumeDevice),
        'verified AFS mode still requires the configured root device');
    afs_multidevice_check(
        fm_guard_read($root . '/inside.txt') === 'inside',
        'verified AFS mode preserves ordinary same-device reads');

    if (!FM_IS_WIN && function_exists('symlink')) {
        symlink($outside . '/secret', $root . '/escaping-link');
        afs_multidevice_check(
            fm_guard_existing($root . '/escaping-link', 'file') === false,
            'verified AFS mode still rejects a canonical symlink escape');
        $listing = fm_guard_scandir($root);
        afs_multidevice_check(is_array($listing)
            && !in_array('escaping-link', $listing, true),
            'verified AFS mode still omits an escaping link from listings');
    }

    $GLOBALS['FM_ROOT_GUARD_MOUNTINFO'] =
        $namespaceRoot
        . '101 10 0:42 / ' . $root . '/nested-mount rw - auristorfs none rw' . "\n";
    afs_multidevice_check(
        fm_guard_existing($root . '/nested-mount', 'dir') === false,
        'verified AFS mode rejects a nested mount even with an allowlisted AFS type');
} finally {
    unset($GLOBALS['FM_ROOT_GUARD_MOUNTINFO']);
    afs_multidevice_remove_tree($sandbox);
}

echo "PASS: $checks AFS multi-device confinement checks\n";
