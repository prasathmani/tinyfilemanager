<?php
/**
 * Dependency-free audit of every active Tiny File Manager AFS I/O surface.
 *
 * TRANSITIONAL means that AFS mode reaches AfsDataPlaneProvider before any
 * generic filesystem fallback, but no descriptor-backed production provider
 * is present in this repository. GUARDED-DISABLED means that AFS mode cannot
 * reach the generic implementation. LIVE-YFS records a checked, fail-closed
 * source policy whose real mount-point mutation semantics still require the
 * separate live test plan.
 *
 * No item in this audit is counted as production PROTECTED. There are no
 * expected failures: every known surface must have one explicit current
 * classification, and any source drift fails the audit.
 */

$root = dirname(__DIR__);
$manager = @file_get_contents($root . '/tinyfilemanager.php');
$afs = @file_get_contents($root . '/afs.php');
$contract = @file_get_contents($root . '/afs_contract.php');

if ($manager === false || $afs === false || $contract === false) {
    fwrite(STDERR,
        "FAIL: unable to read tinyfilemanager.php, afs.php, and afs_contract.php\n");
    exit(2);
}

$auditFailures = array();
$auditAssertions = 0;
$auditClassifications = 0;
$auditCounts = array(
    'TRANSITIONAL' => 0,
    'GUARDED-DISABLED' => 0,
    'LIVE-YFS' => 0,
    'PROTECTED' => 0,
    'XFAIL' => 0
);
$noRawAfsUrls = false;

function audit_fail($message)
{
    global $auditFailures;
    $auditFailures[] = $message;
    echo 'FAIL: ' . $message . "\n";
}

function audit_assert($condition, $message)
{
    global $auditAssertions;
    $auditAssertions++;
    if (!$condition) {
        audit_fail($message);
        return false;
    }
    return true;
}

function audit_section($source, $startMarker, $endMarker, $label)
{
    $start = strpos($source, $startMarker);
    $end = $start === false ? false
        : strpos($source, $endMarker, $start + strlen($startMarker));

    audit_assert($start !== false, $label . ' start marker is missing');
    audit_assert(
        $end !== false && $start !== false && $end > $start,
        $label . ' end marker is missing or reordered'
    );
    if ($start === false || $end === false || $end <= $start) {
        return '';
    }
    return substr($source, $start, $end - $start);
}

function audit_tail($source, $startMarker, $label)
{
    $start = strpos($source, $startMarker);
    audit_assert($start !== false, $label . ' start marker is missing');
    return $start === false ? '' : substr($source, $start);
}

function audit_ordered($source, $needles)
{
    $offset = 0;
    foreach ($needles as $needle) {
        $position = strpos($source, $needle, $offset);
        if ($position === false) {
            return false;
        }
        $offset = $position + strlen($needle);
    }
    return true;
}

function audit_matching_lines($source, $needle)
{
    $matches = array();
    foreach (preg_split('/\r?\n/', $source) as $line) {
        if (strpos($line, $needle) !== false) {
            $matches[] = $line;
        }
    }
    return implode("\n", $matches);
}

function audit_classify($status, $name, $condition, $detail)
{
    global $auditAssertions, $auditClassifications, $auditCounts,
        $noRawAfsUrls;

    $auditAssertions++;
    $auditClassifications++;
    $known = array_key_exists($status, $auditCounts);
    $condition = $condition && $noRawAfsUrls;
    if (!$known || !$condition) {
        audit_fail($name . ' no longer matches its ' . $status . ' baseline');
        return;
    }

    $auditCounts[$status]++;
    echo $status . ': ' . $name . ' - ' . $detail . "\n";
}

echo "AFS current I/O path audit\n";

// Request routes.
$saveRoute = audit_section(
    $manager, '// save editor file', '// backup files', 'save route');
$searchRoute = audit_section(
    $manager, '//search : get list of files from the current folder',
    'if(FM_READONLY){', 'AJAX search route');
$backupRoute = audit_section(
    $manager, '// backup files', '// Save Config', 'backup route');
$urlUploadRoute = audit_section(
    $manager, '//upload using url', '// Delete file / folder',
    'URL-upload route');
$deleteRoute = audit_section(
    $manager, '// Delete file / folder', '// Create a new file/folder',
    'single-delete route');
$createRoute = audit_section(
    $manager, '// Create a new file/folder', '// Copy folder / file',
    'create route');
$copyRoute = audit_section(
    $manager, '// Copy folder / file', '// Mass copy files/ folders',
    'single-copy route');
$massCopyRoute = audit_section(
    $manager, '// Mass copy files/ folders', '// Rename', 'mass-copy route');
$renameRoute = audit_section(
    $manager, '// Rename', '// Download', 'rename route');
$downloadRoute = audit_section(
    $manager, '// Download', '// Upload', 'download route');
$uploadRoute = audit_section(
    $manager, '// Upload', '// Mass deleting', 'upload route');
$massDeleteRoute = audit_section(
    $manager, '// Mass deleting', '// Pack files zip, tar',
    'mass-delete route');
$archiveCreateRoute = audit_section(
    $manager, '// Pack files zip, tar', '// Unpack zip, tar',
    'archive-create route');
$archiveExtractRoute = audit_section(
    $manager, '// Unpack zip, tar', '// Change POSIX permissions',
    'archive-extract route');
$aclPostRoute = audit_section(
    $manager, '// Change AFS ACLs', '/*************************** ACTIONS',
    'ACL mutation route');
$navigationRoute = audit_section(
    $manager,
    "/*************************** ACTIONS ***************************/\n\n// get current path",
    '// upload form', 'navigation/list route');
$uploadPage = audit_section(
    $manager, '// upload form', '// file viewer',
    'upload page and client script');
$urlUploadClient = audit_section(
    $manager,
    "            <?php if (FM_URL_UPLOAD_ENABLED === true): ?>\n"
        . '            // Upload files using URL @param {Object}',
    '            // Search template',
    'footer URL-upload client script');
$viewerRoute = audit_section(
    $manager, '// file viewer', '// file editor', 'file-view route');
$editorRoute = audit_section(
    $manager, '// file editor', '// chmod (not for Windows or AFS)',
    'file-editor route');
$aclGetRoute = audit_section(
    $manager, '// Edit AFS ACLs', '// --- TINYFILEMANAGER MAIN ---',
    'ACL editor route');
$listingRoute = audit_section(
    $manager, '// --- TINYFILEMANAGER MAIN ---', '// --- END HTML ---',
    'main listing');
$rootUrlBlock = audit_section(
    $manager, '// abs path for site. AFS mode uses', '// logout',
    'AFS controller/raw-root URL block');
$featureConstants = audit_section(
    $manager, "if (\$afsSupport && ((defined('FM_SETTINGS_ENABLED')",
    '$afsDataPlane = null;', 'production feature constants');
$profileBootstrap = audit_section(
    $manager, "if (is_readable(__DIR__ . '/afs_contract.php')) {",
    "define('ACE_FONTSIZE'", 'production profile bootstrap');
$rootBinding = audit_section(
    $manager, '// update root path', "defined('FM_LANG')",
    'production root binding');

// Provider-aware wrappers. Each guard condition below proves that the AFS
// branch precedes the generic pathname fallback in the same function.
$aclReadHelper = audit_section(
    $manager, 'function fm_read_afs_acl(',
    "\nfunction fm_change_afs_acl_entries(", 'ACL read helper');
$aclChangeHelper = audit_section(
    $manager, 'function fm_change_afs_acl_entries(',
    "\nfunction fm_get_afs_acl_access(", 'ACL mutation helper');
$aclAccessHelper = audit_section(
    $manager, 'function fm_get_afs_acl_access(',
    "\nfunction fm_resolve_existing_path(", 'caller-access helper');
$resolveHelper = audit_section(
    $manager, 'function fm_resolve_existing_path(',
    "\nfunction fm_resolve_write_path(", 'resolve helper');
$resolveWriteHelper = audit_section(
    $manager, 'function fm_resolve_write_path(',
    "\nfunction fm_inspect_path(", 'write-path resolver');
$inspectHelper = audit_section(
    $manager, 'function fm_inspect_path(',
    "\nfunction fm_path_exists(", 'inspect helper');
$existsHelper = audit_section(
    $manager, 'function fm_path_exists(',
    "\nfunction fm_read_file_contents(", 'exists helper');
$readHelper = audit_section(
    $manager, 'function fm_read_file_contents(',
    "\nfunction fm_write_file_contents(", 'read helper');
$writeHelper = audit_section(
    $manager, 'function fm_write_file_contents(',
    "\nfunction fm_create_file(", 'write helper');
$createHelper = audit_section(
    $manager, 'function fm_create_file(',
    "\nfunction fm_import_file(", 'create helper');
$importHelper = audit_section(
    $manager, 'function fm_import_file(',
    "\nfunction fm_afs_archives_supported(", 'import helper');
$archiveGateHelper = audit_section(
    $manager, 'function fm_afs_archives_supported(',
    "\n/**\n * Delete  file or folder", 'archive gate helper');
$deleteHelper = audit_section(
    $manager, 'function fm_rdelete(',
    "\n/**\n * Recursive chmod", 'delete helper');
$renameHelper = audit_section(
    $manager, 'function fm_rename(',
    "\n/**\n * Copy file or folder", 'rename helper');
$recursiveCopyHelper = audit_section(
    $manager, 'function fm_rcopy(',
    "\n\n/**\n * Safely create folder", 'recursive-copy helper');
$mkdirHelper = audit_section(
    $manager, 'function fm_mkdir(',
    "\n/**\n * Safely copy file", 'mkdir helper');
$copyHelper = audit_section(
    $manager, 'function fm_copy(',
    "\n/**\n * Get mime type", 'copy helper');
$mimeHelper = audit_section(
    $manager, 'function fm_get_mime_type(',
    "\n/**\n * HTTP Redirect", 'MIME helper');
$sizeHelper = audit_section(
    $manager, 'function fm_get_size(',
    "\n\n/**\n * Get nice filesize", 'size helper');
$searchHelper = audit_section(
    $manager, 'function scan(',
    "\n/**\n * Parameters: downloadFile", 'search helper');
$afsDownloadHelper = audit_section(
    $manager, 'function fm_afs_download_file(',
    "\nfunction fm_download_file(", 'AFS download helper');
$downloadHelper = audit_section(
    $manager, 'function fm_download_file(',
    "\n/**\n * Class to work with zip files", 'download helper');

$resolveGuard = audit_ordered($resolveHelper, array(
    'if (fm_is_afs_mode())', '$provider->resolveExistingPath(',
    "if ((\$type === 'file' && !is_file(\$path))"));
$resolveWriteGuard = audit_ordered($resolveWriteHelper, array(
    'if (fm_is_afs_mode())', '$provider->resolveWritePath(',
    'return $path;'));
$inspectGuard = audit_ordered($inspectHelper, array(
    'if (fm_is_afs_mode())', '$provider->inspectPath(',
    '$stat = $allowLinkObject ? @lstat($path) : @stat($path);'));
$existsGuard = audit_ordered($existsHelper, array(
    'if (fm_is_afs_mode())', 'fm_inspect_path(', 'file_exists($path)'));
$readGuard = audit_ordered($readHelper, array(
    'if (fm_is_afs_mode())', '$provider->readContents(',
    '@file_get_contents($path)'));
$writeGuard = audit_ordered($writeHelper, array(
    'if (fm_is_afs_mode())', '$provider->writeFile(',
    '$handle = @fopen($path'))
    && strpos($writeHelper, ') === true;') !== false;
$createGuard = audit_ordered($createHelper, array(
    'if (fm_is_afs_mode())', '$provider->createFile(',
    '$handle = @fopen($path'))
    && strpos($createHelper, ') === true;') !== false;
$importGuard = audit_ordered($importHelper, array(
    'if (fm_is_afs_mode())', '$provider->importFile(',
    '$input = @fopen($source'))
    && strpos($importHelper, '$append) === true;') !== false;
$deleteGuard = audit_ordered($deleteHelper, array(
    'if (fm_is_afs_mode())', '$provider->removePath(',
    'if (is_link($path))'))
    && strpos($deleteHelper, ') === true;') !== false;
$renameGuard = $inspectGuard && audit_ordered($renameHelper, array(
    'if (fm_is_afs_mode())', 'fm_inspect_path(',
    '$provider->renamePath(', 'if (!is_dir($old))'))
    && strpos($renameHelper, '$result === true') !== false;
$recursiveCopyGuard = audit_ordered($recursiveCopyHelper, array(
    'if (fm_is_afs_mode())', '$provider->copyPath(',
    'if (!is_dir($path)'))
    && strpos($recursiveCopyHelper, ') === true;') !== false;
$mkdirGuard = $resolveGuard && audit_ordered($mkdirHelper, array(
    'if (fm_is_afs_mode())', 'fm_resolve_existing_path(',
    '$provider->makeDirectory(', 'if (file_exists($dir))'))
    && strpos($mkdirHelper, ') === true;') !== false;
$copyGuard = audit_ordered($copyHelper, array(
    'if (fm_is_afs_mode())', '$provider->copyPath(',
    '$time1 = filemtime($f1)'))
    && strpos($copyHelper, ') === true;') !== false;
$mimeGuard = audit_ordered($mimeHelper, array(
    'if (fm_is_afs_mode())', '$provider->detectMimeType(',
    "if (function_exists('finfo_open'))"));
$sizeGuard = audit_ordered($sizeHelper, array(
    'if (fm_is_afs_mode())', 'fm_inspect_path($file)',
    "static \$iswin = null;"));
$searchGuard = audit_ordered($searchHelper, array(
    'if (fm_is_afs_mode())', '$provider->searchFiles(',
    'new RecursiveDirectoryIterator($path)'));
$downloadGuard = audit_ordered($downloadHelper, array(
    'if (fm_is_afs_mode())', 'fm_afs_download_file(',
    '$size = filesize($fileLocation)'))
    && audit_ordered($afsDownloadHelper, array(
        '$provider->openRead(', '@fstat($handle)', 'fread($handle'));
$aclReadGuard = audit_ordered($aclReadHelper, array(
    'fm_afs_provider()', '$provider->readAcl(', 'return is_array($acl)'));
$aclChangeGuard = audit_ordered($aclChangeHelper, array(
    'fm_afs_provider()', '$provider->changeAclEntries(', '=== true;'));
$aclAccessGuard = audit_ordered($aclAccessHelper, array(
    'fm_afs_provider()', '$provider->getACLAccess(',
    "preg_match('/^[lrwidkaA-H]{0,15}$/", "? \$rights : '';"));

$productionProfileValidator = audit_section(
    $afs, 'public static function validateProductionProfile(',
    'public static function applicationTemplatesSupportStrictCsp(',
    'production profile validator');

// URL upload remains available by default to non-AFS deployments, but the
// immutable AFS profile and its final constant disable the entire egress path.
$urlUploadDefaultPos = strpos($manager, '$url_upload_enabled = true;');
$configIncludePos = strpos($manager, '@include($config_file);');
$urlUploadProfileGate = $urlUploadDefaultPos !== false
    && $configIncludePos !== false
    && $urlUploadDefaultPos < $configIncludePos
    && strpos(
        $productionProfileValidator,
        "'url_upload_enabled' => false") !== false
    && audit_ordered($featureConstants, array(
        "defined('FM_URL_UPLOAD_ENABLED')",
        'FM_URL_UPLOAD_ENABLED !== false',
        "define('FM_URL_UPLOAD_ENABLED', \$url_upload_enabled)",
        'FM_URL_UPLOAD_ENABLED !== false'));

$urlUploadGatePos = strpos(
    $urlUploadRoute,
    'if ($urlUploadRequested && FM_URL_UPLOAD_ENABLED !== true)'
);
$urlUploadDenyExitPos = $urlUploadGatePos === false ? false
    : strpos($urlUploadRoute, 'exit();', $urlUploadGatePos);
$urlUploadParsePos = strpos(
    $urlUploadRoute, 'parse_url($url, PHP_URL_HOST)');
$urlUploadTempPos = strpos(
    $urlUploadRoute, 'tempnam(sys_get_temp_dir(), "upload-")');
$urlUploadCopyPos = strpos(
    $urlUploadRoute, 'copy($url, $temp_file, $ctx)');
$urlUploadHandlerGate = strpos(
        $urlUploadRoute,
        '$urlUploadRequested = isset($_POST[\'type\'])') !== false
    && strpos($urlUploadRoute, "\$_POST['type'] === 'upload'") !== false
    && strpos(
        $urlUploadRoute,
        "array_key_exists('uploadurl', \$_REQUEST)") !== false
    && $urlUploadGatePos !== false
    && strpos($urlUploadRoute, "header('HTTP/1.1 403 Forbidden');") !== false
    && strpos(
        $urlUploadRoute,
        "'message' => 'URL upload is disabled'") !== false
    && $urlUploadDenyExitPos !== false
    && $urlUploadParsePos !== false
    && $urlUploadTempPos !== false
    && $urlUploadCopyPos !== false
    && $urlUploadGatePos < $urlUploadDenyExitPos
    && $urlUploadDenyExitPos < $urlUploadParsePos
    && $urlUploadDenyExitPos < $urlUploadTempPos
    && $urlUploadDenyExitPos < $urlUploadCopyPos;

$urlUploadUiGuard = '<?php if (FM_URL_UPLOAD_ENABLED === true): ?>';
$urlUploadTabGuardPos = strpos($uploadPage, $urlUploadUiGuard);
$urlUploadTabPos = strpos($uploadPage, 'href="#urlUploader"');
$urlUploadTabEndPos = $urlUploadTabPos === false ? false
    : strpos($uploadPage, '<?php endif; ?>', $urlUploadTabPos);
$urlUploadFormGuardPos = $urlUploadTabEndPos === false ? false
    : strpos($uploadPage, $urlUploadUiGuard, $urlUploadTabEndPos);
$urlUploadFormPos = strpos($uploadPage, 'id="js-form-url-upload"');
$urlUploadFormEndPos = $urlUploadFormPos === false ? false
    : strpos($uploadPage, '<?php endif; ?>', $urlUploadFormPos);
$urlUploadUiGate = substr_count($uploadPage, $urlUploadUiGuard) === 2
    && $urlUploadTabGuardPos !== false && $urlUploadTabPos !== false
    && $urlUploadTabEndPos !== false
    && $urlUploadTabGuardPos < $urlUploadTabPos
    && $urlUploadTabPos < $urlUploadTabEndPos
    && $urlUploadFormGuardPos !== false && $urlUploadFormPos !== false
    && $urlUploadFormEndPos !== false
    && $urlUploadFormGuardPos < $urlUploadFormPos
    && $urlUploadFormPos < $urlUploadFormEndPos;

$urlUploadScriptGuardPos = strpos($urlUploadClient, $urlUploadUiGuard);
$urlUploadScriptPos = strpos(
    $urlUploadClient,
    'function upload_from_url($this)'
);
$urlUploadScriptEndPos = $urlUploadScriptPos === false ? false
    : strpos($urlUploadClient, '<?php endif; ?>', $urlUploadScriptPos);
$urlUploadScriptGate = substr_count(
        $urlUploadClient, $urlUploadUiGuard) === 1
    && $urlUploadScriptGuardPos !== false
    && $urlUploadScriptPos !== false && $urlUploadScriptEndPos !== false
    && $urlUploadScriptGuardPos < $urlUploadScriptPos
    && $urlUploadScriptPos < $urlUploadScriptEndPos;

audit_assert(
    $urlUploadProfileGate,
    'AFS URL-upload profile/default/final-constant gate changed'
);
audit_assert(
    $urlUploadHandlerGate,
    'AFS URL-upload denial no longer precedes parse/temp/network I/O'
);
audit_assert(
    $urlUploadUiGate,
    'disabled URL-upload tab or form can be emitted'
);
audit_assert(
    $urlUploadScriptGate,
    'disabled URL-upload JavaScript can be emitted'
);

// A single raw-URL invariant is conjoined with every route classification.
// FM_ROOT_URL may remain in explicit non-AFS branches, but an AFS link/view
// must stay on FM_SELF_URL/?p= and external viewers/media must stay disabled.
$directLinkLines = audit_matching_lines($listingRoute, "lng('DirectLink')");
$noRawAfsUrls = audit_ordered($rootUrlBlock, array(
        'if ($afsSupport)', '$afsSelfUrl',
        "defined('FM_ROOT_URL') && FM_ROOT_URL !== ''",
        'fm_afs_readiness_error(', "define('FM_ROOT_URL', '')",
        '} else {', "define('FM_ROOT_URL', (\$is_https"))
    && audit_ordered($viewerRoute, array(
        '$file_url = $afsSupport', '? FM_SELF_URL', ': FM_ROOT_URL'))
    && audit_ordered($editorRoute, array(
        '$file_url = $afsSupport', '? FM_SELF_URL', ': FM_ROOT_URL'))
    && strpos($viewerRoute, 'if (!$afsSupport && $is_onlineViewer)') !== false
    && substr_count(
        $viewerRoute,
        'elseif (!$afsSupport && FM_RAW_PREVIEWS_ENABLED && $is_') === 3
    && strpos(
        $productionProfileValidator,
        "'direct_links_enabled' => false") !== false
    && strpos(
        $productionProfileValidator,
        "'raw_previews_enabled' => false") !== false
    && audit_ordered($featureConstants, array(
        "defined('FM_DIRECT_LINKS_ENABLED')",
        'FM_DIRECT_LINKS_ENABLED !== false',
        "define('FM_DIRECT_LINKS_ENABLED', \$direct_links_enabled)",
        'FM_DIRECT_LINKS_ENABLED !== false',
        'fm_afs_readiness_error('))
    && substr_count($directLinkLines, 'FM_ROOT_URL') === 2
    && substr_count($directLinkLines, 'href="?p=') === 2
    && substr_count(
        $listingRoute,
        '<?php if ($afsSupport && FM_DIRECT_LINKS_ENABLED): ?>') === 1
    && substr_count(
        $listingRoute,
        '<?php if ($afsSupport && !$is_link && FM_DIRECT_LINKS_ENABLED): ?>') === 1;
audit_assert(
    $noRawAfsUrls,
    'global AFS raw protected-URL invariant changed'
);

// The side-effect-free provider contract and pathname preview. These source
// checks are not a production descriptor-boundary claim.
$factoryInterface = audit_section(
    $contract, 'interface AfsDataPlaneProviderFactory',
    'interface AfsDataPlaneProvider', 'provider factory interface');
$providerInterface = audit_tail(
    $contract, 'interface AfsDataPlaneProvider', 'provider interface');
$dataPlane = audit_tail(
    $afs, 'class AfsDataPlane extends Afs implements AfsDataPlaneProvider',
    'bundled data-plane provider');
$productionReadyMethod = audit_section(
    $dataPlane, 'public function isProductionReady()',
    'public function getReadinessFailure()', 'production readiness method');
$strictCspMethod = audit_section(
    $afs, 'public static function applicationTemplatesSupportStrictCsp()',
    'public static function validateContentSecurityPolicy(',
    'strict-CSP readiness method');
$canonicalCspDefinition = audit_section(
    $afs, 'const LOCAL_ONLY_CONTENT_SECURITY_POLICY =',
    'public static function validateProductionProfile(',
    'canonical CSP definition');
$manifestFileBuilder = audit_section(
    $afs, 'public static function buildLocalAssetTagsFromManifestFile(',
    'public static function validateLocalAsset(',
    'asset manifest-file builder');
$inspectMethod = audit_section(
    $dataPlane, 'public function inspectPath(',
    'public function listDirectory(', 'provider inspect method');
$copyMethod = audit_section(
    $dataPlane, 'public function copyPath(',
    'public function renamePath(', 'provider copy method');
$renameMethod = audit_section(
    $dataPlane, 'public function renamePath(',
    'public function removePath(', 'provider rename method');
$removeMethod = audit_section(
    $dataPlane, 'public function removePath(',
    'protected function resolveObjectPath(', 'provider remove method');
$resolveMethod = audit_section(
    $dataPlane, 'protected function resolveConfinedPath(',
    'protected function validateOpenHandle(', 'provider resolver');
$searchMethod = audit_section(
    $dataPlane, 'protected function searchDirectory(',
    'protected function preflightRecursiveTree(', 'provider search walk');
$preflightMethod = audit_section(
    $dataPlane, 'protected function preflightRecursiveTree(',
    'protected function copyResolvedPath(', 'provider recursive preflight');
$mountProbeMethod = audit_section(
    $dataPlane, 'protected function probeAfsVolumeMountPoint(',
    'protected function loadKernelMountPoints(', 'provider volume probe');

// Exact route classes.
audit_classify(
    'TRANSITIONAL', 'save/edit writes',
    $resolveGuard && $writeGuard && $readGuard
        && strpos($saveRoute, 'fm_write_file_contents(') !== false
        && strpos($editorRoute, 'fm_write_file_contents(') !== false
        && strpos($saveRoute . $editorRoute, 'fopen($file_path') === false,
    'AJAX and form saves resolve and write through the provider; descriptor implementation absent'
);
audit_classify(
    'TRANSITIONAL', 'backup writes',
    $resolveGuard && $copyGuard
        && audit_ordered($backupRoute, array(
            'fm_resolve_existing_path(', 'fm_copy('))
        && preg_match('/(?<!fm_)copy\(\$fullyQualifiedFileName/',
            $backupRoute) !== 1,
    'backup uses the provider-aware copy wrapper'
);
audit_classify(
    'TRANSITIONAL', 'file and directory creation',
    $existsGuard && $createGuard && $mkdirGuard
        && strpos($createRoute, 'fm_path_exists(') !== false
        && strpos($createRoute, 'fm_create_file(') !== false
        && strpos($createRoute, 'fm_mkdir(') !== false,
    'existence, exclusive file creation, and directory creation are provider-owned in AFS mode'
);
audit_classify(
    'TRANSITIONAL', 'copy',
    $recursiveCopyGuard && $copyGuard
        && strpos($copyRoute, 'fm_rcopy($from, $dest)') !== false,
    'single copy reaches copyPath before recursive PHP fallback'
);
audit_classify(
    'TRANSITIONAL', 'duplicate',
    $existsGuard && $recursiveCopyGuard
        && strpos($copyRoute, 'fm_path_exists($fn_duplicate, true)') !== false
        && strpos($copyRoute, 'fm_rcopy($from, $fn_duplicate, False)') !== false,
    'same-directory duplicate uses provider inspection and copyPath'
);
audit_classify(
    'TRANSITIONAL', 'move',
    $renameGuard
        && strpos($copyRoute, '$rename = fm_rename($from, $dest)') !== false
        && strpos($massCopyRoute, '$rename = fm_rename($from, $dest)') !== false,
    'single and bulk move reach provider inspect/rename before PHP rename fallback'
);
audit_classify(
    'TRANSITIONAL', 'rename',
    $renameGuard
        && strpos($renameRoute, 'fm_rename($path . \'/\' . $old, $path . \'/\' . $new)') !== false,
    'rename is CSRF-checked and provider-owned in AFS mode'
);
audit_classify(
    'TRANSITIONAL', 'single and bulk delete',
    $resolveGuard && $deleteGuard
        && strpos($deleteRoute, 'fm_rdelete($path . \'/\' . $del)') !== false
        && strpos($massDeleteRoute, 'fm_rdelete($new_path)') !== false,
    'single and bulk delete reach removePath before unlink/rmdir fallback'
);
audit_classify(
    'TRANSITIONAL', 'single-part upload',
    $resolveGuard && $importGuard
        && audit_ordered($uploadRoute, array(
            'if (fm_is_afs_mode())', 'fm_import_file(',
            'move_uploaded_file($tmp_name, $fullPath)')),
    'AFS upload imports through the provider; move_uploaded_file remains only in the non-AFS branch'
);
audit_classify(
    'TRANSITIONAL', 'chunked upload',
    $resolveGuard && $importGuard && $renameGuard
        && strpos($uploadRoute, 'fm_import_file(') !== false
        && strpos($uploadRoute, 'fm_rename($partPath, $fullPathTarget) === true') !== false
        && strpos($uploadRoute, 'fopen("{$fullPath}.part"') === false,
    'chunk append and finalization are strict provider operations'
);
audit_classify(
    'GUARDED-DISABLED', 'URL upload egress',
    $urlUploadProfileGate && $urlUploadHandlerGate
        && $urlUploadUiGate && $urlUploadScriptGate,
    'AFS production denies the request before URL parsing, temporary-file allocation, network fetch, or import and emits no URL-upload UI/JavaScript'
);
audit_classify(
    'TRANSITIONAL', 'download/read',
    $resolveGuard && $downloadGuard
        && audit_ordered($downloadRoute, array(
            'fm_resolve_existing_path(', 'fm_download_file(')),
    'download streams the same provider-opened handle and generic readfile is non-AFS only'
);
audit_classify(
    'TRANSITIONAL', 'view/preview reads',
    $resolveGuard && $inspectGuard && $mimeGuard && $readGuard
        && strpos($viewerRoute, 'fm_inspect_path(') !== false
        && strpos($viewerRoute, 'fm_get_mime_type(') !== false
        && strpos($viewerRoute, 'fm_read_file_contents(') !== false
        && strpos($viewerRoute, 'elseif (!$afsSupport && ($ext == \'zip\'') !== false
        && strpos(
            $viewerRoute,
            'if (!$afsSupport && FM_RAW_PREVIEWS_ENABLED && $is_image)') !== false,
    'metadata, MIME, and text bytes are provider-owned; archive/image pathname readers are non-AFS only'
);
audit_classify(
    'GUARDED-DISABLED', 'direct-link controls',
    strpos(
        $productionProfileValidator,
        "'direct_links_enabled' => false") !== false
        && audit_ordered($featureConstants, array(
            "defined('FM_DIRECT_LINKS_ENABLED')",
            'FM_DIRECT_LINKS_ENABLED !== false',
            "define('FM_DIRECT_LINKS_ENABLED', \$direct_links_enabled)",
            'FM_DIRECT_LINKS_ENABLED !== false'))
        && substr_count($directLinkLines, 'href="?p=') === 2
        && substr_count($directLinkLines, 'FM_ROOT_URL') === 2
        && substr_count(
            $listingRoute,
            '<?php if ($afsSupport && FM_DIRECT_LINKS_ENABLED): ?>') === 1
        && substr_count(
            $listingRoute,
            '<?php if ($afsSupport && !$is_link && FM_DIRECT_LINKS_ENABLED): ?>') === 1,
    'production rejects enabled constants and omits direct-link controls; ordinary view/download remain transitional'
);
audit_classify(
    'GUARDED-DISABLED', 'archive creation',
    strpos($archiveGateHelper, 'return !fm_is_afs_mode();') !== false
        && audit_ordered($archiveCreateRoute, array(
            'if (!fm_afs_archives_supported())', 'chdir($path)',
            'new FM_Zipper()'))
        && strpos($listingRoute, 'if (fm_afs_archives_supported()):') !== false,
    'AFS rejects the request before chdir/ZipArchive/PharData and hides archive UI'
);
audit_classify(
    'GUARDED-DISABLED', 'archive extraction',
    strpos($archiveGateHelper, 'return !fm_is_afs_mode();') !== false
        && audit_ordered($archiveExtractRoute, array(
            'if (!fm_afs_archives_supported())',
            "is_file(\$path . '/' . \$unzip)", 'extractTo(')),
    'AFS rejects extraction before any archive pathname read or write'
);
audit_classify(
    'TRANSITIONAL', 'symlink traversal and link-object mutation',
    $inspectGuard && $deleteGuard && $renameGuard
        && strpos($providerInterface, 'inspectPath(') !== false
        && strpos($resolveMethod, 'POSIX symbolic links are not traversable') !== false
        && strpos($copyMethod, '$source = $this->resolveExistingPath(') !== false
        && strpos($renameMethod, '$source = $this->resolveObjectPath(') !== false
        && strpos($removeMethod, '$info[\'type\'] === \'link\'') !== false
        && strpos($removeMethod, 'return @unlink( $path );') !== false
        && strpos($listingRoute, "fm_enc(\$info['link_target'])") !== false,
    'traversal/copy fail closed while final-link rename/delete operate on and escape the link object'
);
audit_classify(
    'LIVE-YFS', 'AFS volume mount-point traversal and mutation',
    strpos($afs, 'exact mutation semantics still require live YFS tests') !== false
        && strpos($resolveMethod, 'probeAfsVolumeMountPoint(') !== false
        && strpos($resolveMethod, 'Unable to classify an AFS volume mount point') !== false
        && strpos($searchMethod, 'a parent search never crosses it') !== false
        && strpos($preflightMethod, 'Recursive mutation stops at an AFS volume mount point') !== false
        && audit_ordered($mountProbeMethod, array(
            '$this->runFs( array( \'lsmount\'', '$this->lastFsStatus === 0',
            '$this->lastFsStatus !== 0', 'return null;')),
    'classification failures are closed and recursive mutation stops; real YFS volume behavior remains live-only'
);

// Six additional surfaces made explicit by the provider/readiness lane.
audit_classify(
    'TRANSITIONAL', 'navigation and directory listing',
    $resolveGuard && $inspectGuard
        && audit_ordered($navigationRoute, array(
            'fm_resolve_existing_path($path, \'dir\')',
            'if ($afsSupport)', 'fm_afs_provider()->listDirectory($path)',
            'scandir($path)'))
        && strpos($navigationRoute, 'fm_inspect_path($new_path, true)') !== false,
    'current directory, entries, metadata, and link objects are provider-checked before scandir fallback'
);
audit_classify(
    'TRANSITIONAL', 'recursive search',
    $searchGuard
        && strpos($searchRoute, '$response = scan(') !== false,
    'AJAX search dispatches to provider searchFiles before RecursiveDirectoryIterator fallback'
);
audit_classify(
    'TRANSITIONAL', 'ACL read/write and caller-access UI',
    $resolveGuard && $aclReadGuard && $aclChangeGuard && $aclAccessGuard
        && strpos($providerInterface, 'public function readAcl(') !== false
        && strpos($providerInterface, 'public function changeAclEntries(') !== false
        && strpos($providerInterface, 'public function getACLAccess(') !== false
        && strpos($aclPostRoute, 'fm_read_afs_acl(') !== false
        && strpos($aclPostRoute, 'fm_change_afs_acl_entries(') !== false
        && strpos($aclGetRoute, 'fm_read_afs_acl(') !== false
        && substr_count($listingRoute, 'fm_get_afs_acl_access(') === 2
        && strpos($manager, 'new Afs(') === false,
    'ACL subprocess ownership is part of the provider contract; no route instantiates legacy Afs directly'
);
audit_classify(
    'TRANSITIONAL', 'MIME and file metadata',
    $inspectGuard && $mimeGuard && $sizeGuard
        && strpos($providerInterface, 'public function detectMimeType(') !== false
        && strpos($viewerRoute, '$fileInfo = fm_inspect_path(') !== false
        && strpos($viewerRoute, 'fm_get_mime_type(') !== false
        && strpos($editorRoute, 'fm_get_mime_type(') !== false,
    'provider owns stat-like metadata and content sampling before finfo/filesize fallbacks'
);
audit_classify(
    'GUARDED-DISABLED', 'raw protected URLs and external document viewers',
    strpos($manager, '$online_viewer = false;') !== false
        && strpos($manager,
            "defined('FM_DOC_VIEWER') && FM_DOC_VIEWER !== false") !== false
        && strpos(
            $productionProfileValidator,
            "'raw_previews_enabled' => false") !== false
        && strpos($featureConstants,
            'FM_RAW_PREVIEWS_ENABLED !== false') !== false
        && $noRawAfsUrls,
    'AFS protected objects are never exposed through FM_ROOT_URL or delegated to online viewers/media tags'
);

$readinessBlock = audit_section(
    $manager, '$afsReadinessError = \'\';',
    '// --- EDIT BELOW CAREFULLY OR DO NOT EDIT AT ALL ---',
    'top-level readiness block');
$providerInit = audit_section(
    $manager, '$afsDataPlane = null;', '// always use ?p=',
    'provider initialization block');
audit_classify(
    'TRANSITIONAL', 'production readiness gate',
    audit_ordered($profileBootstrap, array(
        "is_readable(__DIR__ . '/afs_contract.php')",
        "require_once __DIR__ . '/afs_contract.php'",
        '$config_file', '@include($config_file)',
        "(\$afsSupport || defined('AFS_PRODUCTION_PROFILE'))",
        "interface_exists('AfsDataPlaneProviderFactory', false)",
        'fm_afs_readiness_error(',
        "if (\$afsSupport || defined('AFS_PRODUCTION_PROFILE'))",
        "require_once __DIR__ . '/afs.php'",
        '$afsSelfUrl', '$afsRequestIdentity', '$afsDataRoot = $root_path',
        "'profile' => defined('AFS_PRODUCTION_PROFILE')",
        "'request_identity' => \$afsRequestIdentity",
        "'data_root' => \$afsDataRoot",
        "'asset_manifest_sha256' => \$afs_asset_manifest_sha256",
        'AfsProductionReadiness::validateProductionProfile(',
        "defined('FM_ROOT_PATH') && FM_ROOT_PATH !== \$afsDataRoot",
        'fm_afs_readiness_error('))
        && strpos(
            $afs,
            "const PRODUCTION_PROFILE = 'afs-descriptor-v1'") !== false
        && audit_ordered($productionProfileValidator, array(
            "'afs_enabled' => true",
            "'external_auth' => true",
            "'local_auth' => false",
            "'local_users_empty' => true",
            "'settings_enabled' => false",
            "'embed_enabled' => false",
            "'direct_links_enabled' => false",
            "'raw_previews_enabled' => false",
            "'url_upload_enabled' => false",
            "'root_url' => ''",
            "\$state['request_identity']",
            "\$state['self_url']",
            "\$state['data_root']",
            "strpos( \$state['data_root'], '/afs/' ) !== 0",
            "rtrim( \$state['data_root'], '/' ) !== \$state['data_root']",
            "explode( '/', substr( \$state['data_root'], 5 ))",
            "\$segment === '..'",
            "\$state['asset_manifest_sha256']",
            "preg_match( '/^[a-f0-9]{64}$/',",
            "'expected_factory_class'",
            "'expected_factory_id'",
            "'expected_provider_class'",
            "'expected_provider_id'"))
        && strpos($factoryInterface,
            'public function getFactoryIdentity();') !== false
        && strpos($factoryInterface,
            'public function createProvider( $root, $requestIdentity );') !== false
        && strpos($providerInterface,
            'public function getProviderIdentity();') !== false
        && strpos($providerInterface,
            'public function getCredentialIdentity();') !== false
        && audit_ordered($canonicalCspDefinition, array(
            'const LOCAL_ONLY_CONTENT_SECURITY_POLICY =',
            "default-src 'none'",
            "base-uri 'none'; connect-src 'self'; font-src 'self'",
            "form-action 'self'; frame-ancestors 'none'; frame-src 'none'",
            "img-src 'self' data:; media-src 'self'; object-src 'none'",
            "script-src 'self'; style-src 'self'; worker-src 'self'"))
        && strpos($canonicalCspDefinition,
            "font-src 'self' data:") === false
        && strpos($afs,
            '$policy !== self::LOCAL_ONLY_CONTENT_SECURITY_POLICY') !== false
        && audit_ordered($readinessBlock, array(
        'AfsProductionReadiness::buildLocalAssetTagsFromManifestFile(',
        '$afs_asset_manifest_file', '$external_asset_root',
        '$afs_asset_manifest_sha256', '$afsReadinessError',
        'if ($external === false)',
        '$favicon_path !== \'\'',
        'AfsProductionReadiness::validateLocalAsset(',
        'fm_content_security_policy_is_ready(',
        '$content_security_policy_approved !== true',
        'headers_list()',
        'Duplicate Content-Security-Policy response header.',
        'header(\'Content-Security-Policy: \' . $content_security_policy, true)',
        'AfsProductionReadiness::applicationTemplatesSupportStrictCsp()',
        '!== true', 'fm_afs_readiness_error('))
        && audit_ordered($manifestFileBuilder, array(
            '$manifestFile, $assetRoot, $manifestSha256',
            'substr( $manifestFile, 0, 1 ) === \'/\'',
            'foreach ( explode( \'/\', $manifestFile ) as $segment )',
            '@lstat( $candidate )',
            '@realpath( $candidate )',
            '@file_get_contents( $resolved )',
            "preg_match( '/^[a-f0-9]{64}$/', \$manifestSha256 )",
            "hash_equals( \$manifestSha256, hash( 'sha256', \$raw ))",
            'json_decode( $raw, true )',
            '$decoded[\'version\'] !== 1',
            'self::buildLocalAssetTags('))
        && audit_ordered($rootBinding, array(
            'if ($use_auth && isset($_SESSION[FM_SESSION_ID][\'logged\']))',
            'if ($afsSupport)', '$root_path = $afsDataRoot',
            'if (!is_string($root_path))',
            '$root_path = rtrim($root_path',
            '$root_path = str_replace(\'\\\\\', \'/\', $root_path)',
            'AFS root path must be an absolute pathname.',
            "define('FM_ROOT_PATH', \$root_path)",
            'FM_ROOT_PATH !== $afsDataRoot',
            'fm_afs_readiness_error('))
        && substr_count($manager, '$afsDataRoot = $root_path;') === 1
        && substr_count($manager, '$root_path = $afsDataRoot;') === 1
        && audit_ordered($providerInit, array(
            'instanceof AfsDataPlaneProviderFactory',
            'get_class($afsDataPlaneFactory)',
            'getFactoryIdentity()',
            '$afsDataPlaneFactory->createProvider(',
            'FM_ROOT_PATH, $afsRequestIdentity',
            'instanceof AfsDataPlaneProvider',
            'get_class($afsDataPlane)',
            'getProviderIdentity()',
            'getCredentialIdentity()',
            '!== $afsRequestIdentity',
            'isProductionReady() !== true',
            'getSecurityBoundary()',
            'initializeDataPlane(FM_ROOT_PATH) !== true'))
        && substr_count($providerInit, 'FM_ROOT_PATH') === 2
        && audit_ordered($featureConstants, array(
            "defined('FM_SETTINGS_ENABLED')",
            "defined('FM_DIRECT_LINKS_ENABLED')",
            "defined('FM_RAW_PREVIEWS_ENABLED')",
            "defined('FM_URL_UPLOAD_ENABLED')",
            'fm_afs_readiness_error(',
            "define('FM_SETTINGS_ENABLED', \$settings_enabled)",
            "define('FM_DIRECT_LINKS_ENABLED', \$direct_links_enabled)",
            "define('FM_RAW_PREVIEWS_ENABLED', \$raw_previews_enabled)",
            "define('FM_URL_UPLOAD_ENABLED', \$url_upload_enabled)",
            'FM_SETTINGS_ENABLED !== false',
            'FM_DIRECT_LINKS_ENABLED !== false',
            'FM_RAW_PREVIEWS_ENABLED !== false',
            'FM_URL_UPLOAD_ENABLED !== false',
            'fm_afs_readiness_error('))
        && strpos($productionReadyMethod, 'return false;') !== false
        && strpos($dataPlane,
            "return 'tinyfilemanager-afs-pathname-preview-v1';") !== false
        && strpos($strictCspMethod, 'return false;') !== false
        && preg_match('/not a\s+\*\s+production security boundary/',
            $afs) === 1,
    'one normalized /afs profile root binds FM_ROOT_PATH, factory, and init; raw JSON manifest bytes, exact self-only CSP, identities, configured credential equality, boundary, and init all fail closed; external-auth/PAG binding remains live-only and the bundled provider remains nonproduction'
);

// The route inventory is intentionally exact. A new surface must be added and
// classified instead of silently changing these totals.
audit_assert(
    $auditClassifications === 24,
    'expected exactly 24 current AFS route/surface classifications'
);
audit_assert(
    $auditCounts['TRANSITIONAL'] === 18,
    'expected exactly 18 TRANSITIONAL classifications'
);
audit_assert(
    $auditCounts['GUARDED-DISABLED'] === 5,
    'expected exactly 5 GUARDED-DISABLED classifications'
);
audit_assert(
    $auditCounts['LIVE-YFS'] === 1,
    'expected exactly 1 LIVE-YFS classification'
);
audit_assert(
    $auditCounts['PROTECTED'] === 0,
    'production PROTECTED count must remain zero without a descriptor provider'
);
audit_assert(
    $auditCounts['XFAIL'] === 0,
    'current audit must contain no expected failures'
);

echo 'SUMMARY: ' . $auditCounts['TRANSITIONAL'] . ' TRANSITIONAL, '
    . $auditCounts['GUARDED-DISABLED'] . ' GUARDED-DISABLED, '
    . $auditCounts['LIVE-YFS'] . ' LIVE-YFS, '
    . $auditCounts['PROTECTED'] . ' PROTECTED, '
    . $auditCounts['XFAIL'] . ' XFAIL, '
    . count($auditFailures) . ' failures across '
    . $auditClassifications . ' classifications and '
    . $auditAssertions . " assertions\n";

exit(empty($auditFailures) ? 0 : 1);
