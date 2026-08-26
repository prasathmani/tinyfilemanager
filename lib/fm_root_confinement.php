<?php
/**
 * Filesystem confinement for Tiny File Manager.
 *
 * All paths supplied to these helpers are constrained to one canonical root.
 * Existing paths may use symbolic links only when their resolved target remains
 * below that root.  Paths crossing onto a nested filesystem are rejected.  On
 * Linux, mountinfo is also consulted so same-device bind mounts are rejected.
 * AFS volume device transitions are accepted only for a canonical root at or
 * below /afs whose covering Linux filesystem is verified as AuriStor or
 * OpenAFS by that same mountinfo view.
 */

function fm_guard_init($root)
{
    $real = @realpath($root);
    $stat = $real === false ? false : @stat($real);
    if ($real === false || !is_array($stat) || !is_dir($real)) {
        return false;
    }

    $real = fm_guard_normalize_absolute($real);
    $mountinfo = fm_guard_mountinfo_records();
    $GLOBALS['FM_ROOT_GUARD'] = array(
        'root' => $real,
        'device' => $stat['dev'],
        'allow_afs_device_transitions' =>
            fm_guard_root_uses_allowlisted_afs($real, $mountinfo),
    );
    return $real;
}

function fm_guard_normalize_absolute($path)
{
    if (!is_string($path) || $path === '' || strpos($path, "\0") !== false) {
        return false;
    }

    $path = str_replace('\\', '/', $path);
    $prefix = '';
    if (preg_match('/^[A-Za-z]:\//', $path)) {
        $prefix = strtoupper(substr($path, 0, 2));
        $path = substr($path, 2);
    } elseif (substr($path, 0, 1) !== '/') {
        return false;
    }

    $parts = array();
    foreach (explode('/', $path) as $part) {
        if ($part === '' || $part === '.') {
            continue;
        }
        if ($part === '..') {
            if (empty($parts)) {
                return false;
            }
            array_pop($parts);
            continue;
        }
        $parts[] = $part;
    }

    return $prefix . '/' . implode('/', $parts);
}

function fm_guard_absolute($path)
{
    if (!is_string($path) || $path === '' || strpos($path, "\0") !== false) {
        return false;
    }
    $unix = str_replace('\\', '/', $path);
    if (substr($unix, 0, 1) !== '/' && !preg_match('/^[A-Za-z]:\//', $unix)) {
        $cwd = @getcwd();
        if ($cwd === false) {
            return false;
        }
        $unix = rtrim(str_replace('\\', '/', $cwd), '/') . '/' . $unix;
    }
    return fm_guard_normalize_absolute($unix);
}

function fm_guard_path_is_within($path, $root)
{
    $isWin = defined('FM_IS_WIN') ? FM_IS_WIN : DIRECTORY_SEPARATOR === '\\';
    if ($isWin) {
        $path = strtolower($path);
        $root = strtolower($root);
    }
    return $path === $root || strpos($path, rtrim($root, '/') . '/') === 0;
}

function fm_guard_config()
{
    return isset($GLOBALS['FM_ROOT_GUARD'])
        && is_array($GLOBALS['FM_ROOT_GUARD'])
        ? $GLOBALS['FM_ROOT_GUARD'] : false;
}

/**
 * AFS volume traversal can report a different st_dev below /afs without
 * creating a Linux VFS mountpoint. This exception is derived only from a
 * verified, allowlisted AFS mount covering the configured root.
 */
function fm_guard_device_is_allowed($path, $device)
{
    $config = fm_guard_config();
    if ($config === false || !is_string($path) || !is_int($device)) {
        return false;
    }
    if ($device == $config['device']) {
        return true;
    }

    return !empty($config['allow_afs_device_transitions'])
        && $path !== $config['root']
        && fm_guard_path_is_within($path, $config['root']);
}

function fm_guard_mount_unescape($path)
{
    if (!is_string($path) || preg_match('/\\\\(?!011|012|040|134)/', $path)) {
        return false;
    }
    return strtr($path, array(
        '\\011' => "\t",
        '\\012' => "\n",
        '\\040' => ' ',
        '\\134' => '\\',
    ));
}

function fm_guard_parse_mountinfo($contents)
{
    $mounts = array();
    $hasNamespaceRoot = false;
    if (!is_string($contents) || trim($contents) === '') {
        return false;
    }
    foreach (preg_split('/\r?\n/', $contents) as $line) {
        if ($line === '') {
            continue;
        }
        $fields = preg_split('/ +/', trim($line));
        $separator = array_search('-', $fields, true);
        if ($separator === false || $separator < 6
            || count($fields) < $separator + 4
            || !preg_match('/\A[0-9]+\z/', $fields[0])
            || !preg_match('/\A[0-9]+\z/', $fields[1])
            || !preg_match('/\A[0-9]+:[0-9]+\z/', $fields[2])) {
            return false;
        }

        // mountinfo field 4 is the root within the mounted filesystem. Linux
        // permits opaque values here (for example nsfs net:[...]); only field
        // 5 is the absolute mountpoint used for path confinement.
        $mountRoot = fm_guard_mount_unescape($fields[3]);
        $mount = fm_guard_normalize_absolute(fm_guard_mount_unescape($fields[4]));
        $filesystem = $fields[$separator + 1];
        if ($mountRoot === false || $mountRoot === ''
            || $mount === false || $filesystem === '') {
            return false;
        }
        $mounts[] = array(
            'mountpoint' => $mount,
            'filesystem' => $filesystem,
        );
        $hasNamespaceRoot = $hasNamespaceRoot || $mount === '/';
    }
    return $hasNamespaceRoot ? $mounts : false;
}

function fm_guard_mountinfo_records()
{
    static $cache = null;
    if (array_key_exists('FM_ROOT_GUARD_MOUNTINFO', $GLOBALS)) {
        return fm_guard_parse_mountinfo($GLOBALS['FM_ROOT_GUARD_MOUNTINFO']);
    }
    if ($cache === null) {
        $contents = @file_get_contents('/proc/self/mountinfo');
        if ($contents === false && stripos(PHP_OS, 'Linux') === 0) {
            $cache = false;
        } elseif ($contents === false) {
            $cache = array();
        } else {
            $cache = fm_guard_parse_mountinfo($contents);
        }
    }
    return $cache;
}

function fm_guard_mountpoints()
{
    $records = fm_guard_mountinfo_records();
    if ($records === false) {
        return false;
    }
    $mounts = array();
    foreach ($records as $record) {
        if (!is_array($record) || !isset($record['mountpoint'])
            || !is_string($record['mountpoint'])) {
            return false;
        }
        $mounts[$record['mountpoint']] = true;
    }
    return array_keys($mounts);
}

/** Return the filesystem type of the deepest, latest mount covering path. */
function fm_guard_covering_filesystem($path, $records)
{
    $path = fm_guard_normalize_absolute($path);
    if ($path === false || !is_array($records)) {
        return false;
    }

    $bestLength = -1;
    $filesystem = false;
    foreach ($records as $record) {
        if (!is_array($record) || !isset($record['mountpoint'], $record['filesystem'])
            || !is_string($record['mountpoint']) || !is_string($record['filesystem'])
            || $record['filesystem'] === '') {
            return false;
        }
        $mount = fm_guard_normalize_absolute($record['mountpoint']);
        if ($mount === false || !fm_guard_path_is_within($path, $mount)) {
            continue;
        }
        $length = strlen($mount);
        if ($length >= $bestLength) {
            $bestLength = $length;
            $filesystem = $record['filesystem'];
        }
    }

    return $bestLength >= 0 ? $filesystem : false;
}

function fm_guard_root_uses_allowlisted_afs($root, $records)
{
    $root = fm_guard_normalize_absolute($root);
    if ($root === false || !fm_guard_path_is_within($root, '/afs')) {
        return false;
    }
    $filesystem = fm_guard_covering_filesystem($root, $records);
    return $filesystem === 'auristorfs' || $filesystem === 'afs';
}

function fm_guard_crosses_nested_mount($path)
{
    $config = fm_guard_config();
    if ($config === false) {
        return true;
    }
    $mountpoints = fm_guard_mountpoints();
    if ($mountpoints === false) {
        return true;
    }
    foreach ($mountpoints as $mount) {
        if ($mount === $config['root'] || !fm_guard_path_is_within($mount, $config['root'])) {
            continue;
        }
        if ($path === $mount || fm_guard_path_is_within($path, $mount)) {
            return true;
        }
    }
    return false;
}

function fm_guard_existing($path, $type = null)
{
    $config = fm_guard_config();
    $absolute = fm_guard_absolute($path);
    if ($config === false || $absolute === false
        || !fm_guard_path_is_within($absolute, $config['root'])) {
        return false;
    }

    $real = @realpath($absolute);
    if ($real === false) {
        return false;
    }
    $real = fm_guard_normalize_absolute($real);
    if ($real === false || !fm_guard_path_is_within($real, $config['root'])
        || fm_guard_crosses_nested_mount($real)) {
        return false;
    }

    $stat = @stat($real);
    if (!is_array($stat) || !fm_guard_device_is_allowed($real, $stat['dev'])) {
        return false;
    }
    if ($type === 'file' && !is_file($real)) {
        return false;
    }
    if ($type === 'dir' && !is_dir($real)) {
        return false;
    }
    return $real;
}

/** Validate an entry without following its final symbolic link. */
function fm_guard_entry($path, $mustExist = true)
{
    $config = fm_guard_config();
    $absolute = fm_guard_absolute($path);
    if ($config === false || $absolute === false || $absolute === $config['root']
        || !fm_guard_path_is_within($absolute, $config['root'])) {
        return false;
    }
    $parent = fm_guard_existing(dirname($absolute), 'dir');
    $name = basename($absolute);
    if ($parent === false || $name === '' || $name === '.' || $name === '..') {
        return false;
    }
    $entry = rtrim($parent, '/') . '/' . $name;
    if ($mustExist && @lstat($entry) === false) {
        return false;
    }
    return $entry;
}

function fm_guard_create_path($path, $recursive = false)
{
    $config = fm_guard_config();
    $absolute = fm_guard_absolute($path);
    if ($config === false || $absolute === false || $absolute === $config['root']
        || !fm_guard_path_is_within($absolute, $config['root'])) {
        return false;
    }

    if (@lstat($absolute) !== false) {
        return fm_guard_existing($absolute);
    }
    if (!$recursive) {
        return fm_guard_entry($absolute, false);
    }

    $tail = array();
    $cursor = $absolute;
    while (@lstat($cursor) === false && $cursor !== $config['root']) {
        array_unshift($tail, basename($cursor));
        $cursor = dirname($cursor);
    }
    $base = fm_guard_existing($cursor, 'dir');
    if ($base === false || empty($tail)) {
        return false;
    }
    foreach ($tail as $name) {
        if ($name === '' || $name === '.' || $name === '..' || strpos($name, '/') !== false) {
            return false;
        }
        $base .= '/' . $name;
    }
    return $base;
}

function fm_guard_scandir($path)
{
    $dir = fm_guard_existing($path, 'dir');
    if ($dir === false) {
        return false;
    }
    $entries = @scandir($dir);
    if (!is_array($entries)) {
        return false;
    }
    $safe = array();
    foreach ($entries as $entry) {
        if ($entry === '.' || $entry === '..') {
            $safe[] = $entry;
            continue;
        }
        if (fm_guard_existing($dir . '/' . $entry) !== false) {
            $safe[] = $entry;
        }
    }
    return $safe;
}

function fm_guard_open_read($path)
{
    $config = fm_guard_config();
    $file = fm_guard_existing($path, 'file');
    if ($config === false || $file === false) {
        return false;
    }
    $handle = @fopen($file, 'rb');
    if ($handle === false) {
        return false;
    }
    $stat = @fstat($handle);
    clearstatcache(true, $file);
    $current = @realpath($file);
    $currentStat = $current === false ? false : @stat($current);
    if (!is_array($stat) || !fm_guard_device_is_allowed($file, $stat['dev'])
        || !is_array($currentStat) || $currentStat['dev'] != $stat['dev']
        || $currentStat['ino'] != $stat['ino']
        || fm_guard_existing($current, 'file') === false) {
        fclose($handle);
        return false;
    }
    return $handle;
}

function fm_guard_read($path)
{
    $handle = fm_guard_open_read($path);
    if ($handle === false) {
        return false;
    }
    $contents = stream_get_contents($handle);
    fclose($handle);
    return $contents;
}

function fm_guard_open_write($path, $mode = 'wb')
{
    $config = fm_guard_config();
    if ($config === false || !preg_match('/^(?:[waxc][bt+]*|r\+[bt]*)$/', $mode)) {
        return false;
    }

    $absolute = fm_guard_absolute($path);
    if ($absolute === false) {
        return false;
    }
    $exclusive = substr($mode, 0, 1) === 'x';
    if (@lstat($absolute) !== false) {
        if (is_link($absolute) || $exclusive) {
            return false;
        }
        $target = fm_guard_existing($absolute, 'file');
    } else {
        $target = fm_guard_create_path($absolute, false);
    }
    if ($target === false) {
        return false;
    }

    // c+b never truncates before the opened object has been verified. x+b is
    // used for exclusive creation. Truncation/append positioning happens only
    // after device and inode checks below.
    $handle = @fopen($target, $exclusive ? 'x+b' : 'c+b');
    if ($handle === false) {
        return false;
    }
    $stat = @fstat($handle);
    clearstatcache(true, $target);
    $resolved = @realpath($target);
    $resolvedStat = $resolved === false ? false : @stat($resolved);
    if (!is_array($stat) || !fm_guard_device_is_allowed($target, $stat['dev'])
        || !is_array($resolvedStat) || $resolvedStat['dev'] != $stat['dev']
        || $resolvedStat['ino'] != $stat['ino']
        || fm_guard_existing($resolved, 'file') === false) {
        fclose($handle);
        return false;
    }
    if (substr($mode, 0, 1) === 'w' && !ftruncate($handle, 0)) {
        fclose($handle);
        return false;
    }
    if (substr($mode, 0, 1) === 'a') {
        fseek($handle, 0, SEEK_END);
    } else {
        rewind($handle);
    }
    return $handle;
}

function fm_guard_write($path, $contents)
{
    $handle = fm_guard_open_write($path, 'wb');
    if ($handle === false) {
        return false;
    }
    $length = strlen($contents);
    $written = 0;
    while ($written < $length) {
        $count = fwrite($handle, substr($contents, $written));
        if ($count === false || $count === 0) {
            fclose($handle);
            return false;
        }
        $written += $count;
    }
    return fclose($handle);
}

function fm_guard_mkdir($path, $recursive = false)
{
    $target = fm_guard_create_path($path, $recursive);
    if ($target === false) {
        return false;
    }
    if (@lstat($target) !== false) {
        return fm_guard_existing($target, 'dir') !== false ? $target : false;
    }

    if (!$recursive) {
        if (!@mkdir($target, 0777, false)) {
            return false;
        }
        return fm_guard_existing($target, 'dir') !== false;
    }

    $config = fm_guard_config();
    $relative = ltrim(substr($target, strlen($config['root'])), '/');
    $cursor = $config['root'];
    foreach ($relative === '' ? array() : explode('/', $relative) as $part) {
        $cursor .= '/' . $part;
        if (@lstat($cursor) === false && !@mkdir($cursor, 0777, false)) {
            return false;
        }
        $safe = fm_guard_existing($cursor, 'dir');
        if ($safe === false) {
            return false;
        }
        $cursor = $safe;
    }
    return true;
}

function fm_guard_unlink($path)
{
    $entry = fm_guard_entry($path, true);
    if ($entry === false || (!is_link($entry) && fm_guard_existing($entry, 'file') === false)) {
        return false;
    }
    return @unlink($entry);
}

function fm_guard_delete($path)
{
    $entry = fm_guard_entry($path, true);
    if ($entry === false) {
        return false;
    }
    if (is_link($entry)) {
        return @unlink($entry);
    }
    $safe = fm_guard_existing($entry);
    if ($safe === false) {
        return false;
    }
    if (is_dir($safe)) {
        $objects = @scandir($safe);
        if (!is_array($objects)) {
            return false;
        }
        foreach ($objects as $name) {
            if ($name !== '.' && $name !== '..' && !fm_guard_delete($safe . '/' . $name)) {
                return false;
            }
        }
        return @rmdir($safe);
    }
    return is_file($safe) ? @unlink($safe) : false;
}

function fm_guard_rename($old, $new)
{
    $sourceEntry = fm_guard_entry($old, true);
    $destEntry = fm_guard_entry($new, false);
    if ($sourceEntry === false || $destEntry === false || @lstat($destEntry) !== false) {
        return @lstat($destEntry) !== false ? null : false;
    }
    if (!is_link($sourceEntry) && fm_guard_existing($sourceEntry) === false) {
        return false;
    }
    return @rename($sourceEntry, $destEntry);
}

function fm_guard_copy_file($source, $dest, $update = true)
{
    $sourcePath = fm_guard_existing($source, 'file');
    $destEntry = fm_guard_entry($dest, false);
    if ($sourcePath === false || $destEntry === false || is_link($destEntry)) {
        return false;
    }
    $sourceTime = @filemtime($sourcePath);
    if (@lstat($destEntry) !== false) {
        $destPath = fm_guard_existing($destEntry, 'file');
        if ($destPath === false || ($update && @filemtime($destPath) >= $sourceTime)) {
            return false;
        }
    }
    $input = fm_guard_open_read($sourcePath);
    $output = fm_guard_open_write($destEntry, 'wb');
    if ($input === false || $output === false) {
        if (is_resource($input)) fclose($input);
        if (is_resource($output)) fclose($output);
        return false;
    }
    $ok = stream_copy_to_stream($input, $output) !== false;
    $ok = fclose($input) && $ok;
    $ok = fclose($output) && $ok;
    if ($ok && $sourceTime !== false) {
        @touch($destEntry, $sourceTime);
    }
    return $ok;
}

function fm_guard_copy_tree($source, $dest, $update = true, $force = true)
{
    $sourceEntry = fm_guard_entry($source, true);
    if ($sourceEntry !== false && is_link($sourceEntry)) {
        $sourceTarget = fm_guard_existing($sourceEntry);
        $destEntry = fm_guard_entry($dest, false);
        $linkTarget = @readlink($sourceEntry);
        if ($sourceTarget === false || $destEntry === false || $linkTarget === false
            || @lstat($destEntry) !== false || !@symlink($linkTarget, $destEntry)) {
            return false;
        }
        if (fm_guard_existing($destEntry) === false) {
            @unlink($destEntry);
            return false;
        }
        return true;
    }
    $sourcePath = fm_guard_existing($source);
    if ($sourcePath === false) {
        return false;
    }
    if (is_file($sourcePath)) {
        return fm_guard_copy_file($sourcePath, $dest, $update);
    }
    if (!is_dir($sourcePath) || !fm_guard_mkdir($dest, false)) {
        return false;
    }
    $destPath = fm_guard_existing($dest, 'dir');
    $objects = fm_guard_scandir($sourcePath);
    if ($destPath === false || !is_array($objects)) {
        return false;
    }
    foreach ($objects as $name) {
        if ($name !== '.' && $name !== '..'
            && !fm_guard_copy_tree($sourcePath . '/' . $name,
                $destPath . '/' . $name, $update, $force)) {
            return false;
        }
    }
    return true;
}

function fm_guard_import_file($source, $dest)
{
    $target = fm_guard_entry($dest, false);
    if ($target === false || @lstat($target) !== false || !is_file($source)) {
        return false;
    }
    if (!@rename($source, $target)) {
        return false;
    }
    if (fm_guard_existing($target, 'file') === false) {
        @unlink($target);
        return false;
    }
    return true;
}

function fm_guard_import_uploaded_file($source, $dest)
{
    $target = fm_guard_entry($dest, false);
    if ($target === false || @lstat($target) !== false || !is_uploaded_file($source)) {
        return false;
    }
    if (!@move_uploaded_file($source, $target)) {
        return false;
    }
    if (fm_guard_existing($target, 'file') === false) {
        @unlink($target);
        return false;
    }
    return true;
}

function fm_guard_archive_member($name)
{
    if (!is_string($name) || $name === '' || strpos($name, "\0") !== false) {
        return false;
    }
    $name = str_replace('\\', '/', $name);
    if (substr($name, 0, 1) === '/' || preg_match('/^[A-Za-z]:\//', $name)) {
        return false;
    }
    $directory = substr($name, -1) === '/';
    $parts = array();
    foreach (explode('/', trim($name, '/')) as $part) {
        if ($part === '' || $part === '.' || $part === '..') {
            return false;
        }
        $parts[] = $part;
    }
    $safe = implode('/', $parts);
    return $safe . ($directory ? '/' : '');
}
