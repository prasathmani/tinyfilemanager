<?php
/**
 * Dependency-free AFS I/O call-site audit.
 *
 * Request routes use a filesystem-neutral root guard before any optional AFS
 * helper. This audit prevents a route from silently returning to raw PHP I/O.
 */

$root = dirname(__DIR__);
$manager = @file_get_contents($root . '/tinyfilemanager.php');
$afs = @file_get_contents($root . '/afs.php');
$guard = @file_get_contents($root . '/lib/fm_root_confinement.php');

if ($manager === false || $afs === false || $guard === false) {
    fwrite(STDERR, "FAIL: unable to read manager, AFS, and root-guard sources\n");
    exit(2);
}

$auditFailures = array();
$auditProtected = 0;
$auditFailClosed = 0;
$auditExpectedFailures = 0;
$auditChecks = 0;

function afs_audit_result($status, $name, $detail)
{
    echo $status . ': ' . $name . ' - ' . $detail . "\n";
}

function afs_audit_require($condition, $message)
{
    global $auditChecks, $auditFailures;
    $auditChecks++;

    if ($condition) {
        return true;
    }

    $auditFailures[] = $message;
    afs_audit_result('FAIL', 'source baseline', $message);
    return false;
}

function afs_audit_section($source, $startMarker, $endMarker, $label)
{
    $start = strpos($source, $startMarker);
    $end = $start === false ? false : strpos($source, $endMarker, $start + strlen($startMarker));

    if (!afs_audit_require($start !== false, $label . ' start marker is missing')) {
        return '';
    }
    if (!afs_audit_require($end !== false && $end > $start, $label . ' end marker is missing or reordered')) {
        return '';
    }

    return substr($source, $start, $end - $start);
}

function afs_audit_unwired($source)
{
    $guardMarkers = array(
        '$afsSupport',
        'new Afs',
        'makePathAFSlocal',
        'pathSecurity',
        '->copy(',
        '->copy_dirs(',
        '->readfile(',
        '->removeFolder(',
        '->deleteFiles(',
        '->moveFiles(',
        '->afsRename('
    );

    foreach ($guardMarkers as $marker) {
        if (strpos($source, $marker) !== false) {
            return false;
        }
    }

    return true;
}

function afs_audit_matching_lines($source, $needle)
{
    $matches = array();
    foreach (preg_split('/\r?\n/', $source) as $line) {
        if (strpos($line, $needle) !== false) {
            $matches[] = $line;
        }
    }

    return implode("\n", $matches);
}

function afs_audit_protected($name, $condition, $detail)
{
    global $auditProtected, $auditChecks, $auditFailures;
    $auditChecks++;

    if (!$condition) {
        $auditFailures[] = $name . ' no longer matches its protected baseline';
        afs_audit_result('FAIL', $name, 'protected baseline changed; review required');
        return;
    }

    $auditProtected++;
    afs_audit_result('PROTECTED', $name, $detail);
}

function afs_audit_fail_closed($name, $condition, $detail)
{
    global $auditFailClosed, $auditChecks, $auditFailures;
    $auditChecks++;

    if (!$condition) {
        $auditFailures[] = $name . ' no longer matches its fail-closed baseline';
        afs_audit_result('FAIL', $name, 'fail-closed baseline changed; review required');
        return;
    }

    $auditFailClosed++;
    afs_audit_result('FAIL-CLOSED', $name, $detail);
}

function afs_audit_xfail($name, $condition, $detail)
{
    global $auditExpectedFailures, $auditChecks, $auditFailures;
    $auditChecks++;

    if (!$condition) {
        $auditFailures[] = $name . ' changed from its expected-gap baseline';
        afs_audit_result('FAIL', $name, 'expected-gap baseline changed; inspect and reclassify');
        return;
    }

    $auditExpectedFailures++;
    afs_audit_result('XFAIL', $name, $detail);
}

echo "AFS I/O path audit\n";

// Guarded primitives retained in afs.php. These checks do not imply that the
// Tiny File Manager request handlers call them.
$pathSecurity = afs_audit_section($afs, 'function pathSecurity', 'public function makePathAFSlocal', 'Afs::pathSecurity');
$makeLocal = afs_audit_section($afs, 'public function makePathAFSlocal', '// Checks to see if there is a folder', 'Afs::makePathAFSlocal');
$removeFolder = afs_audit_section($afs, 'public function removeFolder', 'public function deleteFiles', 'Afs::removeFolder');
$copyFilesPrimitive = afs_audit_section($afs, 'function copyFiles()', 'protected function copyItem', 'Afs::copyFiles');
$copyItem = afs_audit_section($afs, 'protected function copyItem', '/* A helper function for copyFiles()', 'Afs::copyItem');
$copyDirs = afs_audit_section($afs, 'public function copy_dirs', 'public function copy(', 'Afs::copy_dirs');
$copyPrimitive = afs_audit_section($afs, 'public function copy(', '// A AFS safe version of the PHP readfile', 'Afs::copy');
$readPrimitive = afs_audit_section($afs, 'function readfile()', '// Change the ACL for a given path', 'Afs::readfile');

afs_audit_fail_closed(
    'path acceptance on a non-AFS device',
    strpos($pathSecurity, '@stat( $path )') !== false
        && preg_match('/\$this->afsStat\[[\'\"]dev[\'\"]\]\s*!=\s*\$pathStat\[[\'\"]dev[\'\"]\]/', $pathSecurity) === 1
        && strpos($pathSecurity, 'return false;') !== false,
    'pathSecurity rejects a path whose st_dev differs from /afs'
);
afs_audit_fail_closed(
    'directory-local operation on a non-AFS device',
    strpos($makeLocal, '@chdir( $path )') !== false
        && preg_match('/\$this->afsStat\[[\'\"]dev[\'\"]\]\s*!=\s*\$stat\[[\'\"]dev[\'\"]\]/', $makeLocal) === 1
        && strpos($makeLocal, 'Path not in AFS') !== false
        && strpos($makeLocal, '@chdir( $this->startCWD )') !== false
        && strpos($makeLocal, 'return false;') !== false,
    'makePathAFSlocal restores cwd and rejects the device mismatch'
);
afs_audit_protected(
    'AFS file-copy primitive',
    strpos($copyPrimitive, 'fstat( $sourceHdl )') !== false
        && strpos($copyPrimitive, '$sourceStat[\'dev\'] != $this->afsStat[\'dev\']') !== false
        && substr_count($copyPrimitive, 'makePathAFSlocal(') >= 2
        && strpos($copyPrimitive, 'fopen( basename( $dest ), "xb" )') !== false,
    'source handle st_dev and destination directory are checked; overwrite is refused'
);
afs_audit_protected(
    'AFS file-read primitive',
    strpos($readPrimitive, 'fstat( $handle )') !== false
        && strpos($readPrimitive, '$stat[\'dev\'] == $this->afsStat[\'dev\']') !== false,
    'bytes are emitted only after checking the opened handle device'
);
afs_audit_protected(
    'AFS recursive delete helper',
    strpos($removeFolder, 'makePathAFSlocal( $folderPath )') !== false
        && strpos($removeFolder, '!is_link( $itemPath )') !== false
        && strpos($removeFolder, '$this->removeFolder( $itemPath )') !== false,
    'each directory is rechecked and symlinks are unlinked rather than traversed'
);
afs_audit_protected(
    'AFS recursive copy helper',
    substr_count($copyDirs, 'makePathAFSlocal(') >= 2
        && strpos($copyFilesPrimitive, 'copyItem(') !== false
        && strpos($copyDirs, 'copyItem(') !== false
        && strpos($copyDirs, 'is_link( $source )') !== false
        && strpos($copyItem, 'is_link( $source )') !== false
        && strpos($copyItem, '@filetype( $source )') !== false
        && strpos($copyItem, 'is_link( $source )')
            < strpos($copyItem, '@filetype( $source )')
        && strpos($copyPrimitive, 'if ( is_link( $source ))') !== false
        && strpos($copyPrimitive, 'readlink( $name )') !== false,
    'copyFiles and copy_dirs dispatch links before directory checks, then reproduce them'
);

// Snapshot the request handlers and generic filesystem helpers.
$save = afs_audit_section($manager, '// save editor file', '// backup files', 'save route');
$backup = afs_audit_section($manager, '// backup files', '// Save Config', 'backup route');
$deleteRoute = afs_audit_section($manager, '// Delete file / folder', '// Create a new file/folder', 'single-delete route');
$createRoute = afs_audit_section($manager, '// Create a new file/folder', '// Copy folder / file', 'create route');
$copyRoute = afs_audit_section($manager, '// Copy folder / file', '// Mass copy files/ folders', 'single-copy route');
$massCopyRoute = afs_audit_section($manager, '// Mass copy files/ folders', '// Rename', 'mass-copy route');
$renameRoute = afs_audit_section($manager, '// Rename', '// Download', 'rename route');
$downloadRoute = afs_audit_section($manager, '// Download', '// Upload', 'download route');
$uploadRoute = afs_audit_section($manager, '// Upload', '// Mass deleting', 'upload route');
$massDeleteRoute = afs_audit_section($manager, '// Mass deleting', '// Pack files zip, tar', 'mass-delete route');
$archiveCreateRoute = afs_audit_section($manager, '// Pack files zip, tar', '// Unpack zip, tar', 'archive-create route');
$archiveExtractRoute = afs_audit_section($manager, '// Unpack zip, tar', '// Change POSIX permissions', 'archive-extract route');
$viewer = afs_audit_section($manager, '// file viewer', '// file editor', 'file-view route');
$listing = afs_audit_section($manager, '// --- TINYFILEMANAGER MAIN ---', '// --- END HTML ---', 'main listing');
$directLinks = afs_audit_matching_lines($listing, "lng('DirectLink')");

$deleteHelper = afs_audit_section($manager, 'function fm_rdelete($path)', 'function fm_rchmod', 'fm_rdelete');
$renameHelper = afs_audit_section($manager, 'function fm_rename($old, $new)', 'function fm_rcopy', 'fm_rename');
$recursiveCopy = afs_audit_section($manager, 'function fm_rcopy($path, $dest', 'function fm_mkdir', 'fm_rcopy');
$mkdirHelper = afs_audit_section($manager, 'function fm_mkdir($dir, $force)', 'function fm_copy', 'fm_mkdir');
$copyHelper = afs_audit_section($manager, 'function fm_copy($f1, $f2, $upd)', 'function fm_get_mime_type', 'fm_copy');
$downloadHelper = afs_audit_section($manager, 'function fm_download_file(', 'class FM_Zipper', 'fm_download_file');
$archiveHelpers = afs_audit_section($manager, 'class FM_Zipper', '//--- Templates Functions ---', 'archive helper classes');

afs_audit_protected(
    'save/edit writes',
    strpos($save, 'fm_guard_existing(') !== false
        && strpos($save, 'fm_guard_write(') !== false,
    'editor writes require a canonical guarded file path'
);
afs_audit_protected(
    'backup writes',
    strpos($backup, 'fm_guard_existing(') !== false
        && strpos($backup, 'fm_guard_copy_file(') !== false,
    'backup reads and creates only guard-approved files'
);
afs_audit_protected(
    'file and directory creation',
    strpos($createRoute, 'fm_guard_open_write(') !== false
        && strpos($createRoute, "fm_mkdir(\$path . '/' . \$new, false)") !== false
        && strpos($mkdirHelper, 'fm_guard_mkdir(') !== false,
    'file and directory creation dispatch through guarded primitives'
);
afs_audit_protected(
    'copy',
    strpos($copyRoute, 'fm_rcopy($from, $dest)') !== false
        && strpos($recursiveCopy, 'fm_guard_copy_tree(') !== false
        && strpos($copyHelper, 'fm_guard_copy_file(') !== false,
    'copy recursion revalidates each source and destination'
);
afs_audit_protected(
    'duplicate',
    strpos($copyRoute, 'fm_rcopy($from, $fn_duplicate, False)') !== false
        && strpos($recursiveCopy, 'fm_guard_copy_tree(') !== false,
    'same-directory duplicate uses guarded recursive copy'
);
afs_audit_protected(
    'move',
    strpos($copyRoute, 'fm_rename($from, $dest)') !== false
        && strpos($massCopyRoute, 'fm_rename($from, $dest)') !== false
        && strpos($renameHelper, 'fm_guard_rename(') !== false,
    'single and mass move validate both entries'
);
afs_audit_protected(
    'rename',
    strpos($renameRoute, "fm_rename(\$path . '/' . \$old, \$path . '/' . \$new)") !== false
        && strpos($renameHelper, 'fm_guard_rename(') !== false,
    'rename is confined independently of the backing filesystem'
);
afs_audit_protected(
    'single and bulk delete',
    strpos($deleteRoute, "fm_rdelete(\$path . '/' . \$del)") !== false
        && strpos($massDeleteRoute, 'fm_rdelete($new_path)') !== false
        && strpos($deleteHelper, 'fm_guard_delete(') !== false,
    'delete unlinks links but never descends through an unapproved target'
);
afs_audit_protected(
    'single-part upload',
    strpos($uploadRoute, 'fm_guard_import_uploaded_file(') !== false
        && strpos($uploadRoute, 'fm_guard_create_path(') !== false,
    'uploaded bytes enter only a guarded, new destination'
);
afs_audit_protected(
    'chunked upload',
    strpos($uploadRoute, 'fm_guard_open_write("{$fullPath}.part"') !== false
        && strpos($uploadRoute, 'fm_guard_rename("{$fullPath}.part"') !== false,
    'chunk append and final rename remain confined'
);
afs_audit_protected(
    'download/read',
    strpos($downloadRoute, 'fm_guard_existing(') !== false
        && strpos($downloadHelper, 'fm_guard_open_read(') !== false
        && strpos($downloadHelper, 'readfile(') === false,
    'download streams only from a validated open handle'
);
afs_audit_protected(
    'view/preview reads',
    strpos($viewer, 'fm_guard_existing(') !== false
        && strpos($viewer, 'fm_guard_read($file_path)') !== false,
    'viewer resolves and reads through the root guard'
);
afs_audit_protected(
    'direct links',
    substr_count($directLinks, "lng('DirectLink')") === 2
        && strpos($directLinks, 'FM_ROOT_URL') === false
        && strpos($directLinks, '&amp;raw=') !== false
        && strpos($manager, "if (isset(\$_GET['raw']))") !== false,
    'file links return through guarded application streaming; folders navigate in-app'
);
afs_audit_protected(
    'archive creation',
    strpos($archiveCreateRoute, 'new FM_Zipper()') !== false
        && strpos($archiveCreateRoute, 'new FM_Zipper_Tar()') !== false
        && substr_count($archiveHelpers, 'fm_guard_existing(') >= 8
        && substr_count($archiveHelpers, 'fm_guard_scandir(') >= 2,
    'archive writers validate every recursively visited object'
);
afs_audit_protected(
    'archive extraction',
    strpos($archiveExtractRoute, 'new FM_Zipper_Tar()') !== false
        && strpos($archiveExtractRoute . $archiveHelpers, 'extractTo(') === false
        && substr_count($archiveHelpers, 'fm_guard_archive_member(') >= 4
        && substr_count($archiveHelpers, 'fm_guard_open_write(') >= 2,
    'archive members are validated before guarded per-file extraction'
);
afs_audit_protected(
    'symlink traversal',
    strpos($guard, 'function fm_guard_existing') !== false
        && strpos($guard, 'realpath($absolute)') !== false
        && strpos($guard, 'fm_guard_path_is_within($real, $config[\'root\'])') !== false,
    'resolved symlink targets must remain below the canonical root'
);
afs_audit_protected(
    'mount-point traversal',
    strpos($guard, "if (\$device == \$config['device'])") !== false
        && strpos($guard, 'FM_ROOT_GUARD_ALLOW_AFS_DEVICE_TRANSITIONS') === false
        && strpos($guard, 'fm_guard_root_uses_allowlisted_afs($real, $mountinfo)') !== false
        && strpos($guard, "return \$filesystem === 'auristorfs' || \$filesystem === 'afs';") !== false
        && strpos($guard, "&& \$path !== \$config['root']") !== false
        && strpos($guard, "file_get_contents('/proc/self/mountinfo')") !== false
        && strpos($guard, 'fm_guard_crosses_nested_mount($real)') !== false,
    'device changes require a mount-proven /afs root and Linux nested/bind mountpoints remain rejected'
);

echo 'SUMMARY: ' . $auditProtected . ' protected, '
    . $auditFailClosed . ' fail-closed, '
    . $auditExpectedFailures . ' expected failures, '
    . count($auditFailures) . ' unexpected failures across '
    . $auditChecks . " checks\n";

if (!empty($auditFailures)) {
    exit(1);
}

exit(0);
