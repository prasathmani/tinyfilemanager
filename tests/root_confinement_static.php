#!/usr/bin/env php
<?php

$root = dirname(__DIR__);
$manager = file_get_contents($root . '/tinyfilemanager.php');
$guard = file_get_contents($root . '/lib/fm_root_confinement.php');
if ($manager === false || $guard === false) {
    fwrite(STDERR, "FAIL: unable to load confinement sources\n");
    exit(2);
}

$checks = 0;

function static_check($condition, $message)
{
    global $checks;
    $checks++;
    if (!$condition) {
        fwrite(STDERR, "not ok $checks - $message\n");
        exit(1);
    }
    echo "ok $checks - $message\n";
}

function route_section($source, $start, $end)
{
    $from = strpos($source, $start);
    $to = $from === false ? false : strpos($source, $end, $from + strlen($start));
    return $from !== false && $to !== false ? substr($source, $from, $to - $from) : '';
}

$routes = array(
    'edit/save' => array('// save editor file', '// backup files', array('fm_guard_existing(', 'fm_guard_write(')),
    'backup' => array('// backup files', '// Save Config', array('fm_guard_copy_file(')),
    'delete' => array('// Delete file / folder', '// Create a new file/folder', array('fm_rdelete(')),
    'create' => array('// Create a new file/folder', '// Copy folder / file', array('fm_guard_open_write(', 'fm_mkdir(')),
    'copy/move' => array('// Copy folder / file', '// Mass copy files/ folders', array('fm_rcopy(', 'fm_rename(')),
    'bulk copy/move' => array('// Mass copy files/ folders', '// Rename', array('fm_rcopy(', 'fm_rename(')),
    'rename' => array('// Rename', '// Download', array('fm_rename(')),
    'download/direct' => array('// Download', '// Upload', array('fm_guard_existing(', "isset(\$_GET['raw'])", 'fm_download_file(')),
    'upload' => array('// Upload', '// Mass deleting', array('fm_guard_create_path(', 'fm_guard_open_write(', 'fm_guard_import_uploaded_file(')),
    'archive create' => array('// Pack files zip, tar', '// Unpack zip, tar', array('FM_Zipper', 'FM_Zipper_Tar')),
    'archive extract' => array('// Unpack zip, tar', '// Change POSIX permissions', array('FM_Zipper', 'FM_Zipper_Tar')),
    'view' => array('// file viewer', '// file editor', array('fm_guard_existing(', 'fm_guard_read(')),
);

foreach ($routes as $name => $definition) {
    $section = route_section($manager, $definition[0], $definition[1]);
    static_check($section !== '', "$name route is present");
    foreach ($definition[2] as $marker) {
        static_check(strpos($section, $marker) !== false, "$name route contains $marker");
    }
}

$directLines = array_filter(preg_split('/\r?\n/', $manager), function ($line) {
    return strpos($line, "lng('DirectLink')") !== false;
});
static_check(count($directLines) === 2, 'folder and file direct-link controls remain present');
static_check(strpos(implode("\n", $directLines), 'FM_ROOT_URL') === false, 'direct links never bypass the PHP guard');
static_check(strpos(implode("\n", $directLines), '&amp;raw=') !== false, 'file direct link uses guarded raw streaming');

static_check(strpos($manager, 'extractTo(') === false, 'built-in unconfined archive extraction is absent');
static_check(strpos($manager, 'readfile(') === false, 'download does not reopen a checked path by name');
static_check(strpos($manager, 'move_uploaded_file($tmp_name, $fullPath)') === false, 'upload does not use an unchecked final destination');
static_check(strpos($guard, 'FM_ROOT_GUARD_ALLOW_AFS_DEVICE_TRANSITIONS') === false,
    'generic deployment opt-in for device transitions is absent');
static_check(strpos($guard, 'ctype_') === false,
    'root guard has no optional ctype extension dependency');

foreach (array(
    'realpath($absolute)',
    "if (\$device == \$config['device'])",
    'fm_guard_root_uses_allowlisted_afs($real, $mountinfo)',
    "return \$filesystem === 'auristorfs' || \$filesystem === 'afs';",
    "&& \$path !== \$config['root']",
    "file_get_contents('/proc/self/mountinfo')",
    "array_search('-', \$fields, true)",
    'fm_guard_crosses_nested_mount($real)',
    'function fm_guard_device_is_allowed',
    'function fm_guard_open_read',
    'function fm_guard_open_write',
    'function fm_guard_archive_member',
) as $marker) {
    static_check(strpos($guard, $marker) !== false, "root guard contains $marker");
}

echo "PASS: $checks route-confinement static checks\n";
