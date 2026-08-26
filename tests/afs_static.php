<?php
/**
 * Dependency-free source-contract checks for the AFS replay.
 *
 * This file deliberately inspects source instead of loading
 * tinyfilemanager.php, whose top-level request dispatcher would execute.
 */

$root = dirname(__DIR__);
$managerPath = $root . '/tinyfilemanager.php';
$afsPath = $root . '/afs.php';
$manager = @file_get_contents($managerPath);
$afs = @file_get_contents($afsPath);

if ($manager === false || $afs === false) {
    fwrite(STDERR, "FAIL: unable to read tinyfilemanager.php and afs.php\n");
    exit(2);
}

$afsTestFailures = array();
$afsTestPasses = 0;

function afs_test_ok($condition, $message)
{
    global $afsTestFailures, $afsTestPasses;

    if ($condition) {
        $afsTestPasses++;
        echo "PASS: " . $message . "\n";
        return;
    }

    $afsTestFailures[] = $message;
    echo "FAIL: " . $message . "\n";
}

function afs_test_section($source, $startMarker, $endMarker, $label)
{
    $start = strpos($source, $startMarker);
    $end = $start === false ? false : strpos($source, $endMarker, $start + strlen($startMarker));

    afs_test_ok($start !== false, $label . ' start marker is present');
    afs_test_ok($end !== false && $end > $start, $label . ' end marker follows its start marker');

    if ($start === false || $end === false || $end <= $start) {
        return '';
    }

    return substr($source, $start, $end - $start);
}

function afs_test_contains($haystack, $needle, $message)
{
    afs_test_ok(strpos($haystack, $needle) !== false, $message);
}

echo "AFS static integration contract\n";

// AFS must be an explicit config.php opt-in, and the include must be resolved
// before the optional dependency is loaded.
$defaultPos = strpos($manager, '$afsSupport = false;');
$configPos = strpos($manager, '@include($config_file);');
$guardPos = strpos($manager, 'if ($afsSupport) {');
$requirePos = strpos($manager, "require_once __DIR__ . '/afs.php';");

afs_test_ok($defaultPos !== false, 'AFS support defaults to disabled');
afs_test_ok($configPos !== false, 'external config.php is included');
afs_test_ok($guardPos !== false, 'AFS dependency load is conditional');
afs_test_ok($requirePos !== false, 'AFS dependency uses an __DIR__-anchored path');
afs_test_ok(
    $defaultPos !== false && $configPos !== false && $guardPos !== false && $requirePos !== false
        && $defaultPos < $configPos && $configPos < $guardPos && $guardPos < $requirePos,
    'config.php can override the default before afs.php is required'
);

// Preserve the upstream request-token checks around every route that already
// had one. The legacy single-item GET copy route is intentionally audited in
// afs_io_path_audit.php instead of being misrepresented as CSRF-protected.
$ajax = afs_test_section($manager, '// Handle all AJAX Request', '// Delete file / folder', 'AJAX dispatcher');
afs_test_contains($ajax, "isset(\$_POST['ajax'], \$_POST['token'])", 'AJAX dispatcher requires a token field');
$ajaxVerify = strpos($ajax, "verifyToken(\$_POST['token'])");
$ajaxAction = strpos($ajax, '// save editor file');
afs_test_ok(
    $ajaxVerify !== false && $ajaxAction !== false && $ajaxVerify < $ajaxAction,
    'AJAX token is verified before request-specific actions'
);

$csrfSections = array(
    'single delete' => afs_test_section($manager, '// Delete file / folder', '// Create a new file/folder', 'single-delete route'),
    'create' => afs_test_section($manager, '// Create a new file/folder', '// Copy folder / file', 'create route'),
    'single copy/move' => afs_test_section($manager, '// Complete a single copy/move', '// Mass copy files/ folders', 'single-copy route'),
    'mass copy/move' => afs_test_section($manager, '// Mass copy files/ folders', '// Rename', 'mass-copy route'),
    'rename' => afs_test_section($manager, '// Rename', '// Download', 'rename route'),
    'download' => afs_test_section($manager, '// Download', '// Upload', 'download route'),
    'upload' => afs_test_section($manager, '// Upload', '// Mass deleting', 'upload route'),
    'mass delete' => afs_test_section($manager, '// Mass deleting', '// Pack files zip, tar', 'mass-delete route'),
    'archive create' => afs_test_section($manager, '// Pack files zip, tar', '// Unpack zip, tar', 'archive-create route'),
    'archive extract' => afs_test_section($manager, '// Unpack zip, tar', '// Change POSIX permissions', 'archive-extract route'),
    'POSIX chmod' => afs_test_section($manager, '// Change POSIX permissions', '// Change AFS ACLs', 'POSIX-chmod route'),
    'AFS ACL write' => afs_test_section($manager, '// Change AFS ACLs', '/*************************** ACTIONS', 'AFS-ACL-write route')
);

foreach ($csrfSections as $label => $section) {
    afs_test_contains($section, "verifyToken(\$_POST['token'])", $label . ' preserves token verification');
}

// This was a pre-existing upstream GET mutation, not an AFS replay change.
// Completion must remain a token-verified POST while GET is navigation-only.
$singleCopy = $csrfSections['single copy/move'];
afs_test_contains(
    $singleCopy,
    "isset(\$_POST['copy'], \$_POST['finish'], \$_POST['token'])",
    'single-copy completion requires POST fields and a CSRF token'
);
afs_test_ok(
    strpos($singleCopy, "\$_GET['finish']") === false,
    'single-copy completion has no mutating GET finish route'
);
$singleCopyVerify = strpos($singleCopy, "verifyToken(\$_POST['token'])");
$singleCopyMutation = strpos($singleCopy, 'fm_rename(');
afs_test_ok(
    $singleCopyVerify !== false && $singleCopyMutation !== false
        && $singleCopyVerify < $singleCopyMutation,
    'single-copy token verification precedes copy or move mutation'
);

$singleCopyUi = afs_test_section(
    $manager,
    "// copy form\nif (isset(\$_GET['copy'])",
    "if (isset(\$_GET['settings'])",
    'single-copy navigation form'
);
afs_test_contains($singleCopyUi, 'method="post"',
    'single-copy completion UI submits by POST');
afs_test_contains($singleCopyUi, 'name="token"',
    'single-copy completion UI submits the session token');
afs_test_contains($singleCopyUi, 'name="copy"',
    'single-copy completion UI submits the source path');
afs_test_contains($singleCopyUi, 'name="finish" value="1"',
    'single-copy completion UI submits the completion marker');
afs_test_contains($singleCopyUi, 'name="move" value="1"',
    'single-copy completion UI distinguishes move from copy');
afs_test_ok(
    strpos($singleCopyUi, '&amp;finish=1') === false,
    'single-copy completion UI emits no state-changing GET links'
);

$verifyFunction = afs_test_section($manager, 'function verifyToken($token)', 'function fm_rdelete($path)', 'verifyToken function');
afs_test_contains($verifyFunction, 'hash_equals(', 'token comparison remains timing-safe');

// Preserve exclusion behavior added upstream: configured exact names, wildcard
// extensions, and full paths all remain excluded from listing/view/edit.
afs_test_contains(
    $manager,
    "version_compare(PHP_VERSION, '7.0.0', '<') ? serialize(\$exclude_items) : \$exclude_items",
    'FM_EXCLUDE_ITEMS preserves the PHP 5 serialization compatibility path'
);
$excludeFunction = afs_test_section($manager, 'function fm_is_exclude_items($name, $path)', 'function fm_get_translations($tr)', 'exclusion helper');
afs_test_contains($excludeFunction, 'in_array($name, $exclude_items)', 'exclusion helper checks exact names');
afs_test_contains($excludeFunction, 'in_array("*.$ext", $exclude_items)', 'exclusion helper checks wildcard extensions');
afs_test_contains($excludeFunction, 'in_array($path, $exclude_items)', 'exclusion helper checks full paths');
afs_test_ok(
    substr_count($manager, 'fm_is_exclude_items(') >= 6,
    'listing, view, and edit paths retain exclusion checks'
);
afs_test_contains($manager, "strpbrk(\$text, '/?%*:|\"<>' . chr(0))", 'current null-byte filename rejection is preserved');

// ACL write handling must round-trip both lists. Accept either two explicit
// branches or a normal=>false/negative=>true mode map feeding the batched
// negative-mode argument.
$aclSubmit = $csrfSections['AFS ACL write'];
$readBeforeChange = strpos($aclSubmit, '$afs->readAcl($aclPath)');
$changeCall = strpos($aclSubmit, '$afs->changeAclEntries(');
afs_test_ok(
    $readBeforeChange !== false && $changeCall !== false && $readBeforeChange < $changeCall,
    'ACL writes re-read current inheritance state before fs setacl'
);
afs_test_contains($aclSubmit, "!empty(\$currentAcl['inherited'])",
    'inherited AuriStor ACL writes fail closed server-side');
$mappedAclSets = preg_match('/[\'\"]normal[\'\"]\s*=>\s*false.*[\'\"]negative[\'\"]\s*=>\s*true/s', $aclSubmit) === 1;
$dynamicAclLookup = strpos($aclSubmit, '$_POST[$setName]') !== false;
afs_test_ok(
    strpos($aclSubmit, "\$_POST['normal']") !== false || ($mappedAclSets && $dynamicAclLookup),
    'positive ACL submissions are handled'
);
afs_test_ok(
    strpos($aclSubmit, "\$_POST['negative']") !== false || ($mappedAclSets && $dynamicAclLookup),
    'negative ACL submissions are handled'
);
$sentinelIgnored = strpos($aclSubmit, "unset(\$perms['acl'])") !== false
    || (strpos($aclSubmit, '$allowedRights') !== false
        && strpos($aclSubmit, 'isset($perms[$right])') !== false);
afs_test_ok($sentinelIgnored, 'ACL empty-rights sentinel is excluded from assembled rights');
$emptyBecomesNone = strpos($aclSubmit, "empty(\$perms) ? 'none'") !== false
    || preg_match('/\$newAcl\s*=\s*\$newAcl\s*==={0,1}\s*[\'\"]{2}\s*\?\s*[\'\"]none[\'\"]/', $aclSubmit) === 1;
afs_test_ok($emptyBecomesNone, 'clearing every right is translated to fs none');

$directNegativeCall = preg_match('/changeAclEntries\s*\([^;]*,\s*true\s*\)/s', $aclSubmit) === 1;
$modeMap = $mappedAclSets;
$variableNegativeCall = preg_match('/changeAclEntries\s*\([^;]*,\s*\$[A-Za-z_][A-Za-z0-9_]*\s*\)/s', $aclSubmit) === 1;
afs_test_ok(
    $directNegativeCall || ($modeMap && $variableNegativeCall),
    'negative ACL writes pass true to changeAcl negative mode'
);
afs_test_contains($aclSubmit, '$aclBatches', 'ACL entries are batched by positive/negative set');

$aclUi = afs_test_section($manager, '// Edit AFS ACLs', '// --- TINYFILEMANAGER MAIN ---', 'AFS ACL editor');
afs_test_contains($aclUi, '$afs->readAcl($file_path)', 'ACL editor reads the current AFS ACL');
afs_test_contains($aclUi, "!empty(\$mode['inherited'])", 'ACL editor detects inherited AuriStor ACLs');
afs_test_contains($aclUi, "<fieldset<?php echo \$acl_readonly ? ' disabled' : ''; ?>",
    'unreadable and inherited ACL controls are disabled');

$rights = array('l', 'r', 'w', 'i', 'd', 'k', 'a',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H');
$aclTypes = array('normal', 'negative');
foreach ($aclTypes as $aclType) {
    foreach ($rights as $right) {
        $pattern = '/name="' . preg_quote($aclType, '/') . '\[[^"]+\]\[' . preg_quote($right, '/') . '\]"/';
        afs_test_ok(
            preg_match($pattern, $aclUi) === 1,
            $aclType . ' ACL editor exposes the ' . $right . ' right'
        );
    }
}

afs_test_ok(
    preg_match('/name="normal\[[^"]+\]\[acl\]"/', $aclUi) === 1,
    'positive ACL rows post an empty-rights sentinel'
);
afs_test_ok(
    preg_match('/name="negative\[[^"]+\]\[acl\]"/', $aclUi) === 1,
    'negative ACL rows post an empty-rights sentinel'
);

$lockRows = 0;
foreach (preg_split('/\r?\n/', $aclUi) as $line) {
    if (strpos($line, '][k]"') === false) {
        continue;
    }
    $lockRows++;
    afs_test_ok(
        strpos($line, "\$perms['k']") !== false && strpos($line, "\$perms['l']") === false,
        'lock checkbox state is derived from the k right'
    );
}
afs_test_ok($lockRows === 2, 'both positive and negative ACL tables contain one lock row');

// Constructing an Afs object used to shell out once, after which each listing
// row called getcalleraccess again. Keep exactly one subprocess per item.
$constructor = afs_test_section($afs, 'public function __construct', 'public function getType', 'Afs constructor');
afs_test_ok(
    substr_count($constructor, 'getACLAccess(') === 0,
    'Afs construction does not perform an implicit getcalleraccess query'
);
afs_test_contains($constructor, '@stat( $this->afsRoot )',
    'Afs construction retains the /afs stat availability check');
afs_test_ok(strpos($constructor, "@stat( '/' )") === false,
    'Afs construction does not stat the open_basedir-inaccessible filesystem root');
afs_test_contains($constructor, 'fm_guard_mountinfo_records()',
    'Afs construction reads the fail-closed mountinfo records');
afs_test_contains($constructor, 'fm_guard_root_uses_allowlisted_afs( \'/afs\', $records )',
    'Afs construction requires an allowlisted AFS filesystem covering /afs');
afs_test_ok(strpos($constructor, 'error_log(') === false,
    'Afs constructor failure paths do not call disabled error_log');

$runFs = afs_test_section($afs, 'protected function runFs', 'public function get_foldercontents_js', 'AFS command runner');
afs_test_contains($runFs, "function_exists( 'exec' )",
    'AFS command runner checks whether exec is available');
afs_test_contains($runFs, '$this->lastFsStatus = 126;',
    'AFS command runner records a fail-closed unavailable-shell status');

$folderListing = afs_test_section($manager, '$ii = 3399;', '$ik = 8002;', 'folder-listing loop');
$fileListing = afs_test_section($manager, '$ik = 8002;', 'if (empty($folders) && empty($files))', 'file-listing loop');
afs_test_ok(substr_count($folderListing, '->getACLAccess(') === 1, 'each folder row has one explicit getcalleraccess call');
afs_test_ok(substr_count($fileListing, '->getACLAccess(') === 1, 'each file row has one explicit getcalleraccess call');
afs_test_ok(substr_count($manager, '->getACLAccess(') === 2, 'Tiny File Manager has only the two per-row getcalleraccess call sites');

echo "SUMMARY: " . $afsTestPasses . " passed, " . count($afsTestFailures) . " failed\n";
if (!empty($afsTestFailures)) {
    exit(1);
}

exit(0);
