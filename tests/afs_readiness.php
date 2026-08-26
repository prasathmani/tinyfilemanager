<?php
/**
 * Dependency-free readiness checks for AFS production mode.
 *
 * tinyfilemanager.php is a request dispatcher and cannot safely be required by
 * an offline test. The side-effect-free readiness builder is exercised through
 * afs.php, while top-level dispatcher ordering is checked as source.
 */

$root = dirname(__DIR__);
$managerPath = $root . '/tinyfilemanager.php';
$afsPath = $root . '/afs.php';
$contractPath = $root . '/afs_contract.php';
$schemaPath = $root . '/docs/AFS_ASSET_MANIFEST.schema.json';
$manager = @file_get_contents($managerPath);
$afsSource = @file_get_contents($afsPath);
$contractSource = @file_get_contents($contractPath);
$schemaSource = @file_get_contents($schemaPath);

if ($manager === false || $afsSource === false || $contractSource === false
    || $schemaSource === false) {
    fwrite(
        STDERR,
        "FAIL: unable to read manager, AFS implementation, and contract\n"
    );
    exit(2);
}
$manifestSchema = json_decode($schemaSource, true);
if (!is_array($manifestSchema)) {
    fwrite(STDERR, "FAIL: unable to decode canonical AFS manifest schema\n");
    exit(2);
}

require_once $contractPath;
require_once $afsPath;

$readinessPasses = 0;
$readinessFailures = array();

function readiness_ok($condition, $message)
{
    global $readinessPasses, $readinessFailures;

    if ($condition) {
        $readinessPasses++;
        echo "PASS: " . $message . "\n";
        return;
    }

    $readinessFailures[] = $message;
    echo "FAIL: " . $message . "\n";
}

function readiness_section($source, $startMarker, $endMarker, $label)
{
    $start = strpos($source, $startMarker);
    $end = $start === false ? false
        : strpos($source, $endMarker, $start + strlen($startMarker));

    readiness_ok($start !== false, $label . ' start marker is present');
    readiness_ok(
        $end !== false && $end > $start,
        $label . ' end marker follows its start marker'
    );

    if ($start === false || $end === false || $end <= $start) {
        return '';
    }

    return substr($source, $start, $end - $start);
}

function readiness_remove_tree($path)
{
    if (is_link($path) || is_file($path)) {
        @unlink($path);
        return;
    }
    if (!is_dir($path)) {
        return;
    }
    $items = @scandir($path);
    if (is_array($items)) {
        foreach ($items as $item) {
            if ($item !== '.' && $item !== '..') {
                readiness_remove_tree($path . '/' . $item);
            }
        }
    }
    @rmdir($path);
}

function readiness_same_keys($actual, $expected)
{
    if (!is_array($actual) || !is_array($expected)) {
        return false;
    }
    $actualKeys = array_keys($actual);
    $expectedKeys = array_values($expected);
    sort($actualKeys);
    sort($expectedKeys);
    return $actualKeys === $expectedKeys;
}

function readiness_without_csp_directive($policy, $directive)
{
    $kept = array();
    foreach (explode(';', $policy) as $part) {
        $part = trim($part);
        if ($part === '') {
            continue;
        }
        $name = preg_split('/\s+/', $part, 2)[0];
        if ($name !== $directive) {
            $kept[] = $part;
        }
    }
    return implode('; ', $kept) . ';';
}

echo "AFS readiness contract\n";

$configPos = strpos($manager, '@include($config_file);');
$urlUploadDefaultPos = strpos($manager, '$url_upload_enabled = true;');
$contractReadablePos = strpos(
    $manager,
    "if (is_readable(__DIR__ . '/afs_contract.php'))"
);
$contractRequirePos = strpos(
    $manager,
    "require_once __DIR__ . '/afs_contract.php';"
);
$contractRequiredPos = strpos(
    $manager,
    "&& !interface_exists('AfsDataPlaneProviderFactory', false)"
);
$viewerOffPos = strpos(
    $manager,
    '$online_viewer = false;',
    $configPos === false ? 0 : $configPos
);
$manifestDefaultPos = strpos($manager, '$afs_asset_manifest_file = \'\';');
$manifestHashDefaultPos = strpos(
    $manager,
    '$afs_asset_manifest_sha256 = \'\';'
);
$resourceGuardPos = strpos(
    $manager,
    'AfsProductionReadiness::buildLocalAssetTagsFromManifestFile(',
    $configPos === false ? 0 : $configPos
);
$cspGuardPos = strpos($manager, 'fm_content_security_policy_is_ready(');
$cspHeaderPos = strpos(
    $manager,
    "header('Content-Security-Policy: ' . \$content_security_policy"
);
$strictTemplateGatePos = strpos(
    $manager,
    'AfsProductionReadiness::applicationTemplatesSupportStrictCsp()'
);
$profileValidationPos = strpos(
    $manager,
    'AfsProductionReadiness::validateProductionProfile('
);
$cspApprovalDefault = strpos(
    $manager,
    '$content_security_policy_approved = false;'
);
$readinessBlock = readiness_section(
    $manager,
    "\$afsReadinessError = '';",
    "if (\$content_security_policy !== '')",
    'top-level AFS readiness block'
);

readiness_ok($configPos !== false, 'config.php inclusion is present');
readiness_ok(
    $urlUploadDefaultPos !== false && $configPos !== false
        && $urlUploadDefaultPos < $configPos,
    'non-AFS URL upload defaults to literal true before config.php overrides'
);
readiness_ok(
    $contractReadablePos !== false && $contractRequirePos !== false
        && $configPos !== false
        && $contractReadablePos < $contractRequirePos
        && $contractRequirePos < $configPos,
    'side-effect-free provider contract loads before config.php'
);
readiness_ok(
    $contractRequiredPos !== false
        && strpos(
            $manager,
            'AFS production requires the packaged provider contract.',
            $contractRequiredPos
        ) !== false,
    'missing provider contract fails closed whenever AFS is requested'
);
readiness_ok(
    strpos($afsSource, "require_once __DIR__ . '/afs_contract.php';") !== false,
    'AFS implementation consumes the same provider contract'
);
readiness_ok(
    strpos($contractSource, 'interface AfsDataPlaneProviderFactory') !== false
        && strpos($contractSource, 'interface AfsDataPlaneProvider') !== false
        && strpos($contractSource, 'class AfsDataPlane') === false,
    'provider contract remains interface-only and runtime-independent'
);
readiness_ok(
    $manifestDefaultPos !== false && $configPos !== false
        && $manifestHashDefaultPos !== false
        && $manifestDefaultPos < $configPos
        && $manifestHashDefaultPos < $configPos,
    'canonical AFS manifest file and digest default empty before config.php'
);
readiness_ok(
    $configPos !== false && $resourceGuardPos !== false
        && $configPos < $resourceGuardPos,
    'canonical JSON local-asset tags are built after config.php overrides'
);
readiness_ok(
    substr_count(
        $manager,
        'AfsProductionReadiness::buildLocalAssetTagsFromManifestFile('
    ) === 1
        && strpos(
            $readinessBlock,
            '$afs_asset_manifest_file, $external_asset_root,'
        ) !== false
        && strpos(
            $readinessBlock,
            '$afs_asset_manifest_sha256, $afsReadinessError'
        ) !== false,
    'AFS runtime consumes one digest-pinned canonical manifest artifact'
);
readiness_ok(
    strpos($readinessBlock, 'if ($afsSupport) {') !== false
        && strpos(
            $readinessBlock,
            '} elseif (is_array($external_resources)'
        ) !== false,
    'raw external-resource HTML overrides are confined to non-AFS mode'
);
readiness_ok(
    strpos($manager, '$afs_asset_manifest = array();') === false,
    'AFS runtime has no independent mutable PHP asset-manifest array'
);
readiness_ok(
    strpos($readinessBlock, '$afsSupport && $favicon_path !==') !== false
        && strpos($readinessBlock, 'validateLocalAsset(') !== false,
    'configured favicon loads share the AFS local-resource readiness gate'
);
readiness_ok(
    strpos($afsSource, 'function validateExternalResources') === false
        && strpos($manager, 'fm_external_resources_are_local(') === false,
    'obsolete raw-HTML AFS resource validators are absent'
);
readiness_ok(
    $cspGuardPos !== false && strpos(
        $readinessBlock,
        'if ($afsSupport && !fm_content_security_policy_is_ready('
    ) !== false,
    'AFS mode calls the CSP readiness predicate'
);
readiness_ok(
    $cspApprovalDefault !== false && $configPos !== false
        && $cspApprovalDefault < $configPos
        && strpos(
            $readinessBlock,
            'if ($afsSupport && $content_security_policy_approved !== true)'
        ) !== false,
    'AFS CSP review approval defaults off and requires literal true'
);
readiness_ok(
    $cspGuardPos !== false && $cspHeaderPos !== false && $cspGuardPos < $cspHeaderPos,
    'AFS CSP readiness validation precedes header emission'
);
readiness_ok(
    strpos($manager, 'foreach (headers_list() as $configuredHeader)') !== false
        && strpos(
            $manager,
            'Duplicate Content-Security-Policy response header.'
        ) !== false,
    'AFS readiness rejects a duplicate PHP CSP header source'
);
readiness_ok(
    $strictTemplateGatePos !== false
        && $cspHeaderPos !== false && $cspHeaderPos < $strictTemplateGatePos
        && strpos(
            $manager,
            'fm_afs_readiness_error(',
            $strictTemplateGatePos
        ) !== false,
    'AFS readiness hard-fails while application templates require inline execution'
);
readiness_ok(
    $configPos !== false && $viewerOffPos !== false && $configPos < $viewerOffPos,
    'AFS mode overrides the configured online-viewer variable after config.php'
);

$viewerRoute = readiness_section(
    $manager,
    '// file viewer',
    '// file editor',
    'file-viewer route'
);
$viewerConstantForced = preg_match(
    "/define\\('FM_DOC_VIEWER',\\s*\\\$afsSupport\\s*\\?\\s*false\\s*:\\s*\\\$online_viewer\\)/",
    $manager
) === 1;
$viewerRouteForced = preg_match(
    '/\\$online_viewer\\s*=\\s*fm_is_afs_mode\\(\\)\\s*\\?\\s*false\\s*:/',
    $viewerRoute
) === 1;
$predefinedViewerCheck = strpos(
    $manager,
    "if (\$afsSupport && defined('FM_DOC_VIEWER') && FM_DOC_VIEWER !== false)"
);
$predefinedViewerError = $predefinedViewerCheck === false ? false
    : strpos($manager, 'fm_afs_readiness_error(', $predefinedViewerCheck);
$viewerConstantDefinition = strpos(
    $manager,
    "defined('FM_DOC_VIEWER') || define('FM_DOC_VIEWER', \$online_viewer);"
);
$predefinedViewerRejected = $predefinedViewerCheck !== false
    && $predefinedViewerError !== false && $viewerConstantDefinition !== false
    && $predefinedViewerCheck < $predefinedViewerError
    && $predefinedViewerError < $viewerConstantDefinition;
readiness_ok(
    $viewerConstantForced || $viewerRouteForced || $predefinedViewerRejected,
    'AFS mode cannot inherit a pre-defined online-viewer constant from config.php'
);

$finalFeatureBlock = readiness_section(
    $manager,
    "if (\$afsSupport && defined('FM_DOC_VIEWER')",
    '$afsDataPlane = null;',
    'final AFS feature-constant gate'
);
$predefinedFeatureGate = strpos(
    $finalFeatureBlock,
    "if (\$afsSupport && ((defined('FM_SETTINGS_ENABLED')"
);
$featureDefinitions = strpos(
    $finalFeatureBlock,
    "defined('FM_SETTINGS_ENABLED') || define('FM_SETTINGS_ENABLED'"
);
$finalFeatureGate = strpos(
    $finalFeatureBlock,
    'if ($afsSupport && (FM_SETTINGS_ENABLED !== false'
);
$urlUploadPredefinedGate = strpos(
    $finalFeatureBlock,
    "defined('FM_URL_UPLOAD_ENABLED')"
);
$urlUploadDefinition = strpos(
    $finalFeatureBlock,
    "defined('FM_URL_UPLOAD_ENABLED') || define('FM_URL_UPLOAD_ENABLED', "
        . '$url_upload_enabled);'
);
readiness_ok(
    $predefinedFeatureGate !== false && $featureDefinitions !== false
        && $predefinedFeatureGate < $featureDefinitions,
    'pre-defined settings/direct-link/raw-preview constants fail before use'
);
readiness_ok(
    $featureDefinitions !== false && $finalFeatureGate !== false
        && $featureDefinitions < $finalFeatureGate
        && strpos(
            $finalFeatureBlock,
            'FM_DIRECT_LINKS_ENABLED !== false',
            $finalFeatureGate
        ) !== false
        && strpos(
            $finalFeatureBlock,
            'FM_RAW_PREVIEWS_ENABLED !== false',
            $finalFeatureGate
        ) !== false,
    'final settings/direct-link/raw-preview constants remain fail-closed'
);
readiness_ok(
    $urlUploadPredefinedGate !== false && $urlUploadDefinition !== false
        && $urlUploadPredefinedGate < $urlUploadDefinition
        && strpos(
            $finalFeatureBlock,
            'FM_URL_UPLOAD_ENABLED !== false',
            $urlUploadPredefinedGate
        ) !== false,
    'AFS rejects a pre-defined URL-upload constant unless it is literal false'
);
readiness_ok(
    $urlUploadDefinition !== false && $finalFeatureGate !== false
        && $urlUploadDefinition < $finalFeatureGate
        && strpos(
            $finalFeatureBlock,
            'FM_URL_UPLOAD_ENABLED !== false',
            $finalFeatureGate
        ) !== false,
    'AFS rechecks the final URL-upload constant for literal false'
);

$settingsRoute = readiness_section(
    $manager,
    '// Save Config',
    '// new password hash',
    'settings-write route'
);
$settingsGuard = strpos(
    $settingsRoute,
    'if (!FM_SETTINGS_ENABLED || fm_is_afs_mode())'
);
$settingsMutation = strpos($settingsRoute, '$cfg->data[');
$settingsSave = strpos($settingsRoute, '$cfg->save();');
readiness_ok(
    $settingsGuard !== false && $settingsMutation !== false
        && $settingsGuard < $settingsMutation,
    'AFS settings rejection precedes in-memory configuration mutation'
);
readiness_ok(
    $settingsGuard !== false && $settingsSave !== false
        && $settingsGuard < $settingsSave,
    'AFS settings rejection precedes persistent configuration save'
);

$passwordHashRoute = readiness_section(
    $manager,
    '// new password hash',
    '//upload using url',
    'password-hash utility route'
);
$passwordHashGuard = strpos(
    $passwordHashRoute,
    'if (!FM_SETTINGS_ENABLED)'
);
$passwordHashWork = strpos($passwordHashRoute, 'password_hash(');
readiness_ok(
    $passwordHashGuard !== false && $passwordHashWork !== false
        && $passwordHashGuard < $passwordHashWork,
    'disabled settings gate rejects password-hash utility before work'
);

$urlUploadRoute = readiness_section(
    $manager,
    '//upload using url',
    '// Delete file / folder',
    'URL-upload handler'
);
$urlUploadRequestedPos = strpos(
    $urlUploadRoute,
    '$urlUploadRequested = isset('
);
$urlUploadDisabledPos = strpos(
    $urlUploadRoute,
    'if ($urlUploadRequested && FM_URL_UPLOAD_ENABLED !== true)'
);
$urlUploadActivePos = strpos(
    $urlUploadRoute,
    "if (\$urlUploadRequested && !empty(\$_REQUEST['uploadurl']))"
);
$urlUploadParsePos = strpos($urlUploadRoute, '$url = !empty(');
$urlUploadTempPos = strpos($urlUploadRoute, 'tempnam(');
$urlUploadCurlPos = strpos($urlUploadRoute, 'curl_init(');
$urlUploadStreamPos = strpos($urlUploadRoute, 'copy($url, $temp_file, $ctx)');
readiness_ok(
    $urlUploadRequestedPos !== false && $urlUploadDisabledPos !== false
        && $urlUploadActivePos !== false && $urlUploadParsePos !== false
        && $urlUploadTempPos !== false && $urlUploadCurlPos !== false
        && $urlUploadStreamPos !== false
        && $urlUploadRequestedPos < $urlUploadDisabledPos
        && $urlUploadDisabledPos < $urlUploadActivePos
        && $urlUploadDisabledPos < $urlUploadParsePos
        && $urlUploadDisabledPos < $urlUploadTempPos
        && $urlUploadDisabledPos < $urlUploadCurlPos
        && $urlUploadDisabledPos < $urlUploadStreamPos
        && strpos(
            $urlUploadRoute,
            "header('HTTP/1.1 403 Forbidden');",
            $urlUploadDisabledPos
        ) !== false,
    'disabled URL upload rejects before parsing, temporary files, or network I/O'
);

$uploadForm = readiness_section(
    $manager,
    '// upload form',
    '// file viewer',
    'upload-form UI'
);
$urlUiGuard = '<?php if (FM_URL_UPLOAD_ENABLED === true): ?>';
$urlTabGuardPos = strpos($uploadForm, $urlUiGuard);
$urlTabPos = strpos($uploadForm, 'href="#urlUploader"');
$urlTabEndPos = $urlTabPos === false ? false
    : strpos($uploadForm, '<?php endif; ?>', $urlTabPos);
$urlFormGuardPos = $urlTabEndPos === false ? false
    : strpos($uploadForm, $urlUiGuard, $urlTabEndPos + 1);
$localUploadFormPos = strpos($uploadForm, 'id="fileUploader"');
$urlFormPos = strpos($uploadForm, 'id="js-form-url-upload"');
$urlFormEndPos = $urlFormPos === false ? false
    : strpos($uploadForm, '<?php endif; ?>', $urlFormPos);
readiness_ok(
    $urlTabGuardPos !== false && $urlTabPos !== false
        && $urlTabEndPos !== false && $urlFormGuardPos !== false
        && $localUploadFormPos !== false && $urlFormPos !== false
        && $urlFormEndPos !== false
        && $urlTabGuardPos < $urlTabPos && $urlTabPos < $urlTabEndPos
        && $urlTabEndPos < $localUploadFormPos
        && $localUploadFormPos < $urlFormGuardPos
        && $urlFormGuardPos < $urlFormPos && $urlFormPos < $urlFormEndPos,
    'URL-upload tab and form are conditional while local upload remains available'
);

$urlScriptCommentPos = strpos(
    $manager,
    '// Upload files using URL @param {Object}'
);
$urlScriptGuardPos = $urlScriptCommentPos === false ? false
    : strrpos(substr($manager, 0, $urlScriptCommentPos), $urlUiGuard);
$urlScriptFunctionPos = strpos($manager, 'function upload_from_url(',
    $urlScriptCommentPos === false ? 0 : $urlScriptCommentPos);
$urlScriptEndPos = $urlScriptFunctionPos === false ? false
    : strpos($manager, '<?php endif; ?>', $urlScriptFunctionPos);
$searchScriptPos = strpos($manager, '// Search template',
    $urlScriptFunctionPos === false ? 0 : $urlScriptFunctionPos);
readiness_ok(
    $urlScriptGuardPos !== false && $urlScriptCommentPos !== false
        && $urlScriptFunctionPos !== false && $urlScriptEndPos !== false
        && $searchScriptPos !== false
        && $urlScriptGuardPos < $urlScriptCommentPos
        && $urlScriptCommentPos < $urlScriptFunctionPos
        && $urlScriptFunctionPos < $urlScriptEndPos
        && $urlScriptEndPos < $searchScriptPos,
    'URL-upload JavaScript is emitted only when the feature is literally true'
);

$configSave = readiness_section(
    $manager,
    '    function save()',
    "\n    }\n}",
    'FM_Config save method'
);
$saveGuard = strpos($configSave, 'if (fm_is_afs_mode())');
$saveReturn = strpos($configSave, 'return false;');
$saveOpen = strpos($configSave, '@fopen(');
readiness_ok(
    $saveGuard !== false && $saveReturn !== false && $saveOpen !== false
        && $saveGuard < $saveReturn && $saveReturn < $saveOpen,
    'FM_Config::save fails closed before opening configuration for write'
);
readiness_ok(
    strpos($manager, 'AFS production configuration is invalid and immutable.') !== false,
    'invalid AFS configuration fails readiness instead of invoking default save'
);

$expectedLocalOnlyCsp = "default-src 'none'; base-uri 'none'; "
    . "connect-src 'self'; font-src 'self'; form-action 'self'; "
    . "frame-ancestors 'none'; frame-src 'none'; img-src 'self' data:; "
    . "media-src 'self'; object-src 'none'; script-src 'self'; "
    . "style-src 'self'; worker-src 'self'";
$cspConstantName = 'AfsProductionReadiness::LOCAL_ONLY_CONTENT_SECURITY_POLICY';
$hasCspBaseline = defined($cspConstantName);
$documentedCsp = $hasCspBaseline ? constant($cspConstantName) : null;
readiness_ok(
    $hasCspBaseline && $documentedCsp === $expectedLocalOnlyCsp,
    'AFS exposes the documented strict local-origin/resource CSP baseline'
);

$cspError = null;
readiness_ok(
    AfsProductionReadiness::validateContentSecurityPolicy(
        $expectedLocalOnlyCsp, $cspError
    ) === true,
    'the strict local-origin/resource CSP baseline passes policy validation'
);
readiness_ok(
    method_exists(
        'AfsProductionReadiness',
        'applicationTemplatesSupportStrictCsp'
    ) && AfsProductionReadiness::applicationTemplatesSupportStrictCsp() === false,
    'current inline application templates explicitly block AFS readiness'
);
$extendedLocalPolicy = str_replace(
    "img-src 'self' data:", "img-src 'self'",
    $expectedLocalOnlyCsp
);
$cspError = null;
readiness_ok(
    AfsProductionReadiness::validateContentSecurityPolicy(
        $extendedLocalPolicy, $cspError
    ) === false && is_string($cspError) && $cspError !== '',
    'AFS CSP rejects even local-only reductions from the exact 13-directive policy'
);

$invalidPolicies = array(
    'empty CSP' => '',
    'whitespace-only CSP' => " \t ",
    'non-string CSP' => array($expectedLocalOnlyCsp),
    'CSP with carriage return' => $expectedLocalOnlyCsp . "\rX-Test: bad",
    'CSP with newline' => $expectedLocalOnlyCsp . "\nX-Test: bad",
    'CSP with NUL' => $expectedLocalOnlyCsp . "\0script-src *",
    'non-baseline minimal CSP' => "default-src 'self'; object-src 'none'"
);
foreach ($invalidPolicies as $label => $policy) {
    $cspError = null;
    readiness_ok(
        AfsProductionReadiness::validateContentSecurityPolicy(
            $policy, $cspError
        ) === false && is_string($cspError) && $cspError !== '',
        $label . ' fails readiness with an explicit error'
    );
}

$requiredCspDirectives = array(
    'default-src', 'base-uri', 'connect-src', 'font-src', 'form-action',
    'frame-ancestors', 'frame-src', 'img-src', 'media-src', 'object-src',
    'script-src', 'style-src', 'worker-src'
);
foreach ($requiredCspDirectives as $directive) {
    $cspError = null;
    readiness_ok(
        AfsProductionReadiness::validateContentSecurityPolicy(
            readiness_without_csp_directive($expectedLocalOnlyCsp, $directive),
            $cspError
        ) === false,
        'CSP readiness requires the ' . $directive . ' baseline directive'
    );
}

$remoteOrWildcardPolicies = array(
    'HTTP script origin' => str_replace(
        "script-src 'self'", "script-src 'self' http://cdn.example.invalid",
        $expectedLocalOnlyCsp
    ),
    'HTTPS script origin' => str_replace(
        "script-src 'self'", "script-src 'self' https://cdn.example.invalid",
        $expectedLocalOnlyCsp
    ),
    'protocol-relative origin' => str_replace(
        "style-src 'self'", "style-src 'self' //cdn.example.invalid",
        $expectedLocalOnlyCsp
    ),
    'bare remote host' => str_replace(
        "font-src 'self'",
        "font-src 'self' cdn.example.invalid",
        $expectedLocalOnlyCsp
    ),
    'remote HTTPS scheme' => str_replace(
        "connect-src 'self'", "connect-src 'self' https:",
        $expectedLocalOnlyCsp
    ),
    'remote WSS origin' => str_replace(
        "connect-src 'self'", "connect-src 'self' wss://api.example.invalid",
        $expectedLocalOnlyCsp
    ),
    'global wildcard' => str_replace(
        "default-src 'none'", 'default-src *', $expectedLocalOnlyCsp
    ),
    'host wildcard' => str_replace(
        "style-src 'self'", "style-src 'self' *.example.invalid",
        $expectedLocalOnlyCsp
    ),
    'script data scheme' => str_replace(
        "script-src 'self'", "script-src 'self' data:",
        $expectedLocalOnlyCsp
    ),
    'script blob scheme' => str_replace(
        "script-src 'self'", "script-src 'self' blob:",
        $expectedLocalOnlyCsp
    ),
    'worker data scheme' => str_replace(
        "worker-src 'self'", "worker-src 'self' data:",
        $expectedLocalOnlyCsp
    ),
    'worker blob scheme' => str_replace(
        "worker-src 'self'", "worker-src 'self' blob:",
        $expectedLocalOnlyCsp
    ),
    'empty required directive' => str_replace(
        "frame-ancestors 'none'", 'frame-ancestors',
        $expectedLocalOnlyCsp
    ),
    'unsafe inline script' => str_replace(
        "script-src 'self'", "script-src 'self' 'unsafe-inline'",
        $expectedLocalOnlyCsp
    ),
    'unsafe eval script' => str_replace(
        "script-src 'self'", "script-src 'self' 'unsafe-eval'",
        $expectedLocalOnlyCsp
    ),
    'unsafe WebAssembly eval' => str_replace(
        "script-src 'self'", "script-src 'self' 'wasm-unsafe-eval'",
        $expectedLocalOnlyCsp
    ),
    'unsafe inline style' => str_replace(
        "style-src 'self'", "style-src 'self' 'unsafe-inline'",
        $expectedLocalOnlyCsp
    ),
    'remote report endpoint' => $expectedLocalOnlyCsp
        . '; report-uri https://reports.example.invalid/csp',
    'comma-appended remote policy' => $expectedLocalOnlyCsp
        . ", script-src https://cdn.example.invalid"
);
foreach ($remoteOrWildcardPolicies as $label => $policy) {
    $cspError = null;
    readiness_ok(
        AfsProductionReadiness::validateContentSecurityPolicy(
            $policy, $cspError
        ) === false,
        $label . ' fails CSP readiness'
    );
}

$productionProfileKeys = array(
    'profile', 'afs_enabled', 'external_auth', 'request_identity',
    'local_auth', 'local_users_empty', 'settings_enabled', 'embed_enabled',
    'direct_links_enabled', 'raw_previews_enabled', 'url_upload_enabled',
    'root_url', 'self_url',
    'data_root', 'asset_manifest_sha256',
    'expected_factory_class', 'expected_factory_id',
    'expected_provider_class', 'expected_provider_id'
);
$profileStateBlock = readiness_section(
    $manager,
    '$afsProfileState = array(',
    'unset($afsProfileState, $afsProfileError);',
    'manager production-profile state'
);
$providerRuntime = readiness_section(
    $manager,
    '$afsDataPlane = null;',
    '// always use ?p=',
    'AFS provider-factory runtime'
);
$rootBindingBlock = readiness_section(
    $manager,
    '// update root path',
    '$afsDataPlane = null;',
    'AFS production-root binding'
);
$profileValidatorAvailable = method_exists(
    'AfsProductionReadiness',
    'validateProductionProfile'
);
readiness_ok(
    $profileValidatorAvailable,
    'immutable AFS production-profile validator is available'
);
readiness_ok(
    strpos($afsSource, "'url_upload_enabled' => false") !== false,
    'immutable AFS profile requires URL upload to be literal false'
);
readiness_ok(
    defined('AfsProductionReadiness::PRODUCTION_PROFILE')
        && AfsProductionReadiness::PRODUCTION_PROFILE === 'afs-descriptor-v1'
        && substr_count(
            $manager,
            "if (\$afsSupport || defined('AFS_PRODUCTION_PROFILE')) {"
        ) >= 2,
    'AFS activation requires the exact immutable production-profile constant'
);
readiness_ok(
    strpos($manager, '$afs_production_profile') === false,
    'AFS activation has no mutable production-profile configuration variable'
);
readiness_ok(
    $profileValidationPos !== false,
    'manager validates its constructed actual production state'
);

$profileStateMappings = array(
    'profile' => "'profile' => defined('AFS_PRODUCTION_PROFILE')",
    'afs_enabled' => "'afs_enabled' => \$afsSupport",
    'external_auth' => "'external_auth' => \$afs_external_auth",
    'request_identity' => "'request_identity' => \$afsRequestIdentity",
    'local_auth' => "'local_auth' => \$use_auth",
    'local_users_empty' => "'local_users_empty' => is_array(\$auth_users)",
    'settings_enabled' => "'settings_enabled' => \$settings_enabled",
    'embed_enabled' => "'embed_enabled' => defined('FM_EMBED')",
    'direct_links_enabled' => "'direct_links_enabled' => \$direct_links_enabled",
    'raw_previews_enabled' => "'raw_previews_enabled' => \$raw_previews_enabled",
    'url_upload_enabled' => "'url_upload_enabled' => \$url_upload_enabled",
    'root_url' => "'root_url' => \$root_url",
    'self_url' => "'self_url' => \$afsSelfUrl",
    'data_root' => "'data_root' => \$afsDataRoot",
    'asset_manifest_sha256' =>
        "'asset_manifest_sha256' => \$afs_asset_manifest_sha256",
    'expected_factory_class' =>
        "'expected_factory_class' => \$afs_expected_factory_class",
    'expected_factory_id' =>
        "'expected_factory_id' => \$afs_expected_factory_id",
    'expected_provider_class' =>
        "'expected_provider_class' => \$afs_expected_provider_class",
    'expected_provider_id' =>
        "'expected_provider_id' => \$afs_expected_provider_id"
);
foreach ($profileStateMappings as $key => $sourceFragment) {
    readiness_ok(
        strpos($profileStateBlock, $sourceFragment) !== false,
        'manager derives production-profile state field ' . $key
    );
}
readiness_ok(
    strpos(
        $manager,
        "\$afsSelfUrl = isset(\$_SERVER['SCRIPT_NAME'])"
    ) !== false
        && strpos(
            $manager,
            "\$afsRequestIdentity = isset(\$_SERVER['REMOTE_USER'])"
        ) !== false,
    'manager snapshots controller URL and request identity once'
);
readiness_ok(
    strpos($manager, '$afsDataRoot = $root_path;') !== false,
    'manager snapshots one post-config AFS data root'
);
$predefinedRootGate = strpos(
    $profileStateBlock,
    "if (defined('FM_ROOT_PATH') && FM_ROOT_PATH !== \$afsDataRoot)"
);
readiness_ok(
    $predefinedRootGate !== false
        && strpos(
            $profileStateBlock,
            'Pre-defined FM_ROOT_PATH does not match the production profile.',
            $predefinedRootGate
        ) !== false,
    'pre-defined FM_ROOT_PATH must exactly match the profile snapshot'
);
$rootSnapshotRestore = strpos($rootBindingBlock, '$root_path = $afsDataRoot;');
$rootConstantDefinition = strpos(
    $rootBindingBlock,
    "defined('FM_ROOT_PATH') || define('FM_ROOT_PATH', \$root_path);"
);
$finalRootGate = strpos(
    $rootBindingBlock,
    'if ($afsSupport && FM_ROOT_PATH !== $afsDataRoot)'
);
readiness_ok(
    $rootSnapshotRestore !== false && $rootConstantDefinition !== false
        && $finalRootGate !== false
        && $rootSnapshotRestore < $rootConstantDefinition
        && $rootConstantDefinition < $finalRootGate,
    'later per-user state cannot change the exact AFS root constant'
);
readiness_ok(
    strpos(
        $providerRuntime,
        '$afsDataPlaneFactory instanceof AfsDataPlaneProviderFactory'
    ) !== false
        && strpos(
            $providerRuntime,
            'get_class($afsDataPlaneFactory) !== $afs_expected_factory_class'
        ) !== false
        && strpos(
            $providerRuntime,
            '$afsDataPlaneFactory->getFactoryIdentity()'
        ) !== false
        && strpos(
            $providerRuntime,
            '!== $afs_expected_factory_id'
        ) !== false,
    'manager requires exact factory class and identity matches'
);
readiness_ok(
    strpos($providerRuntime, "\$_SERVER['REMOTE_USER']") === false
        && preg_match(
            '/->createProvider\(\s*FM_ROOT_PATH,\s*\$afsRequestIdentity\s*\)/',
            $providerRuntime
        ) === 1,
    'factory uses the exact root constant and snapshotted request identity'
);
readiness_ok(
    strpos(
        $providerRuntime,
        '$afsDataPlane instanceof AfsDataPlaneProvider'
    ) !== false
        && strpos(
            $providerRuntime,
            'get_class($afsDataPlane) !== $afs_expected_provider_class'
        ) !== false
        && strpos($providerRuntime, '$afsDataPlane->getProviderIdentity()') !== false
        && strpos($providerRuntime, '!== $afs_expected_provider_id') !== false,
    'manager requires exact provider class and identity matches'
);
readiness_ok(
    strpos($providerRuntime, '$afsDataPlane->getCredentialIdentity()') !== false
        && strpos($providerRuntime, '!== $afsRequestIdentity') !== false,
    'provider credential identity must exactly equal REMOTE_USER'
);
readiness_ok(
    preg_match(
        '/->initializeDataPlane\(\s*FM_ROOT_PATH\s*\)/',
        $providerRuntime
    ) === 1,
    'provider initialization uses the exact profile-bound root constant'
);
readiness_ok(
    $strictTemplateGatePos !== false
        && $profileValidationPos !== false
        && $profileValidationPos < $strictTemplateGatePos,
    'complete production-profile validation precedes the known CSP-template gate'
);
readiness_ok(
    interface_exists('AfsDataPlaneProviderFactory')
        && method_exists('AfsDataPlaneProviderFactory', 'getFactoryIdentity')
        && method_exists('AfsDataPlaneProviderFactory', 'createProvider'),
    'provider-factory interface exposes identity and credential-aware creation'
);
readiness_ok(
    method_exists('AfsDataPlaneProvider', 'getProviderIdentity')
        && method_exists('AfsDataPlaneProvider', 'getCredentialIdentity'),
    'provider interface exposes production and credential identities'
);

if ($profileValidatorAvailable) {
    $configuredProfile = array(
        'profile' => 'afs-descriptor-v1',
        'afs_enabled' => true,
        'external_auth' => true,
        'request_identity' => 'alice@example.test',
        'local_auth' => false,
        'local_users_empty' => true,
        'settings_enabled' => false,
        'embed_enabled' => false,
        'direct_links_enabled' => false,
        'raw_previews_enabled' => false,
        'url_upload_enabled' => false,
        'root_url' => '',
        'self_url' => '/tinyfilemanager.php',
        'data_root' => '/afs/example.test/users/alice',
        'asset_manifest_sha256' => str_repeat('a', 64),
        'expected_factory_class' => 'TrustedAfsFactory',
        'expected_factory_id' => 'trusted-factory-v1',
        'expected_provider_class' => 'TrustedAfsProvider',
        'expected_provider_id' => 'trusted-provider-v1'
    );
    $validateProfile = function ($state) {
        $error = null;
        $accepted = AfsProductionReadiness::validateProductionProfile(
            $state, $error
        );
        return array('accepted' => $accepted, 'error' => $error);
    };
    $rejectProfile = function ($state) use ($validateProfile) {
        $result = $validateProfile($state);
        return $result['accepted'] === false
            && is_string($result['error']) && $result['error'] !== '';
    };

    // This validates configuration shape only. It cannot prove that the web
    // server stripped client-supplied identity headers or authenticated the
    // REMOTE_USER value; that remains an exact-deployment integration check.
    $configuredResult = $validateProfile($configuredProfile);
    readiness_ok(
        $configuredResult['accepted'] === true
            && readiness_same_keys($configuredProfile, $productionProfileKeys),
        'complete configured profile reaches the CSP-template fail-closed gate'
    );
    $singleSegmentRootProfile = $configuredProfile;
    $singleSegmentRootProfile['data_root'] = '/afs/example.test';
    readiness_ok(
        $validateProfile($singleSegmentRootProfile)['accepted'] === true,
        'normalized nonempty data root directly below /afs is accepted'
    );
    foreach ($productionProfileKeys as $missingKey) {
        $partialProfile = $configuredProfile;
        unset($partialProfile[$missingKey]);
        readiness_ok(
            $rejectProfile($partialProfile),
            'partial production profile missing ' . $missingKey . ' is rejected'
        );
    }
    $extraProfile = $configuredProfile;
    $extraProfile['unreviewed'] = true;
    readiness_ok(
        $rejectProfile($extraProfile),
        'production profile with an arbitrary field is rejected'
    );

    $defaultProfile = $configuredProfile;
    $defaultProfile['profile'] = null;
    $defaultProfile['afs_enabled'] = false;
    $defaultProfile['external_auth'] = false;
    $defaultProfile['local_auth'] = true;
    $defaultProfile['local_users_empty'] = false;
    readiness_ok(
        $rejectProfile($defaultProfile),
        'default local-auth profile cannot activate AFS production mode'
    );

    $profileFailures = array(
        'wrong immutable profile' => array('profile', 'afs-preview-v1'),
        'AFS disabled' => array('afs_enabled', false),
        'non-boolean AFS enablement' => array('afs_enabled', 1),
        'external auth disabled' => array('external_auth', false),
        'local auth enabled' => array('local_auth', true),
        'local users present' => array('local_users_empty', false),
        'settings enabled' => array('settings_enabled', true),
        'embed enabled' => array('embed_enabled', true),
        'direct links enabled' => array('direct_links_enabled', true),
        'raw previews enabled' => array('raw_previews_enabled', true),
        'URL upload enabled' => array('url_upload_enabled', true),
        'non-boolean URL upload setting' => array(
            'url_upload_enabled', 'false'
        ),
        'raw root URL' => array('root_url', '/afs'),
        'bare AFS data root' => array('data_root', '/afs'),
        'empty AFS data root suffix' => array('data_root', '/afs/'),
        'outside AFS data root' => array('data_root', '/srv/files'),
        'relative AFS data root' => array('data_root', 'afs/example.test'),
        'trailing-slash AFS data root' => array(
            'data_root', '/afs/example.test/'
        ),
        'double-slash AFS data root' => array(
            'data_root', '/afs/example.test//users'
        ),
        'dot-segment AFS data root' => array(
            'data_root', '/afs/example.test/./users'
        ),
        'parent-segment AFS data root' => array(
            'data_root', '/afs/example.test/../users'
        ),
        'backslash AFS data root' => array(
            'data_root', '/afs/example.test\\users'
        ),
        'control-bearing AFS data root' => array(
            'data_root', "/afs/example.test/users\nadmin"
        ),
        'non-string AFS data root' => array(
            'data_root', array('/afs/example.test')
        ),
        'missing manifest digest' => array('asset_manifest_sha256', ''),
        'non-hex manifest digest' => array(
            'asset_manifest_sha256', str_repeat('z', 64)
        ),
        'uppercase manifest digest' => array(
            'asset_manifest_sha256', str_repeat('A', 64)
        ),
        'non-string manifest digest' => array(
            'asset_manifest_sha256', array(str_repeat('a', 64))
        ),
        'absolute self URL' => array(
            'self_url', 'https://files.example.test/tinyfilemanager.php'
        ),
        'protocol-relative self URL' => array(
            'self_url', '//files.example.test/tinyfilemanager.php'
        ),
        'non-root-relative self URL' => array(
            'self_url', 'tinyfilemanager.php'
        ),
        'query-bearing self URL' => array(
            'self_url', '/tinyfilemanager.php?raw=1'
        ),
        'empty request identity' => array('request_identity', ''),
        'unsafe request identity' => array(
            'request_identity', "alice\nadmin"
        ),
        'empty factory class' => array('expected_factory_class', ''),
        'unsafe factory class' => array(
            'expected_factory_class', 'Trusted Factory'
        ),
        'empty factory identity' => array('expected_factory_id', ''),
        'unsafe factory identity' => array(
            'expected_factory_id', "factory\nother"
        ),
        'empty provider class' => array('expected_provider_class', ''),
        'unsafe provider class' => array(
            'expected_provider_class', 'Trusted Provider'
        ),
        'empty provider identity' => array('expected_provider_id', ''),
        'unsafe provider identity' => array(
            'expected_provider_id', "provider\0other"
        )
    );
    foreach ($profileFailures as $label => $change) {
        $candidate = $configuredProfile;
        $candidate[$change[0]] = $change[1];
        readiness_ok(
            $rejectProfile($candidate),
            $label . ' fails production-profile readiness'
        );
    }
}

$builderAvailable = method_exists(
    'AfsProductionReadiness',
    'buildLocalAssetTagsFromManifestFile'
);
readiness_ok(
    $builderAvailable,
    'canonical JSON local-asset manifest builder is available'
);
$manifestLoader = readiness_section(
    $afsSource,
    'public static function buildLocalAssetTagsFromManifestFile(',
    'public static function validateLocalAsset(',
    'canonical manifest-file loader'
);
$manifestReadPos = strpos($manifestLoader, '@file_get_contents(');
$manifestDigestPos = strpos($manifestLoader, 'hash_equals(');
$manifestDecodePos = strpos($manifestLoader, 'json_decode(');
readiness_ok(
    $manifestReadPos !== false && $manifestDigestPos !== false
        && $manifestDecodePos !== false
        && $manifestReadPos < $manifestDigestPos
        && $manifestDigestPos < $manifestDecodePos
        && strpos(
            $manifestLoader,
            "preg_match( '/^[a-f0-9]{64}$/', \$manifestSha256 )"
        ) !== false,
    'loader verifies a lowercase digest over exact raw bytes before JSON parsing'
);

$schemaExpectedAssetKeys = array(
    'css-bootstrap', 'css-dropzone', 'css-font-awesome',
    'css-highlightjs', 'js-ace', 'js-bootstrap', 'js-dropzone',
    'js-jquery', 'js-jquery-datatables', 'js-highlightjs'
);
$schemaAssets = isset($manifestSchema['properties']['assets'])
    && is_array($manifestSchema['properties']['assets'])
    ? $manifestSchema['properties']['assets'] : array();
$schemaAssetProperties = isset($schemaAssets['properties'])
    && is_array($schemaAssets['properties'])
    ? $schemaAssets['properties'] : array();
$schemaCommon = isset($manifestSchema['$defs']['common'])
    && is_array($manifestSchema['$defs']['common'])
    ? $manifestSchema['$defs']['common'] : array();
$schemaCommonProperties = isset($schemaCommon['properties'])
    && is_array($schemaCommon['properties'])
    ? $schemaCommon['properties'] : array();
$schemaStyle = isset($manifestSchema['$defs']['style']['allOf'][1]['properties'])
    && is_array($manifestSchema['$defs']['style']['allOf'][1]['properties'])
    ? $manifestSchema['$defs']['style']['allOf'][1]['properties'] : array();
readiness_ok(
    isset($manifestSchema['properties']['version']['const'])
        && $manifestSchema['properties']['version']['const'] === 1
        && isset($schemaAssets['required'])
        && readiness_same_keys(
            $schemaAssetProperties,
            $schemaExpectedAssetKeys
        )
        && $schemaAssets['required'] === $schemaExpectedAssetKeys,
    'canonical schema source fixes version 1 and the exact ten logical keys'
);

$schemaMissingDeferFixture = array(
    'type' => 'script', 'path' => 'assets/app.js',
    'sha256' => str_repeat('a', 64), 'license' => 'MIT'
);
readiness_ok(
    isset($schemaCommon['required'])
        && in_array('defer', $schemaCommon['required'], true)
        && !array_key_exists('defer', $schemaMissingDeferFixture),
    'schema source rejects a row fixture with missing defer'
);
$schemaStyleTrueFixture = array('defer' => true);
readiness_ok(
    isset($schemaStyle['defer']['const'])
        && $schemaStyle['defer']['const'] === false
        && $schemaStyleTrueFixture['defer'] !== $schemaStyle['defer']['const'],
    'schema source rejects a style-row fixture with defer true'
);
$schemaNonBooleanDeferFixture = array('defer' => 'false');
readiness_ok(
    isset($schemaCommonProperties['defer']['type'])
        && $schemaCommonProperties['defer']['type'] === 'boolean'
        && !is_bool($schemaNonBooleanDeferFixture['defer']),
    'schema source rejects a row fixture with non-boolean defer'
);
$schemaUppercaseDigestFixture = strtoupper(str_repeat('a', 64));
readiness_ok(
    isset($schemaCommonProperties['sha256']['pattern'])
        && $schemaCommonProperties['sha256']['pattern'] === '^[a-f0-9]{64}$'
        && preg_match(
            '/' . $schemaCommonProperties['sha256']['pattern'] . '/',
            $schemaUppercaseDigestFixture
        ) !== 1,
    'schema source rejects an uppercase SHA-256 fixture'
);

$fixtureBase = sys_get_temp_dir() . '/tfm-afs-readiness-'
    . str_replace('.', '-', uniqid('', true));
$assetRoot = $fixtureBase . '/asset-root';
$assetDir = $assetRoot . '/assets';
$cssContents = 'body{}';
$jsContents = 'void 0;';
$outsideContents = 'outside();';
$fixtureReady = @mkdir($assetDir, 0700, true)
    && file_put_contents($assetDir . '/app.css', $cssContents) !== false
    && file_put_contents($assetDir . '/app.js', $jsContents) !== false
    && file_put_contents($assetDir . '/app&theme.css', $cssContents) !== false
    && file_put_contents($fixtureBase . '/outside.js', $outsideContents) !== false;
register_shutdown_function('readiness_remove_tree', $fixtureBase);
readiness_ok($fixtureReady, 'typed local-asset fixtures were created');

if ($fixtureReady && $builderAvailable) {
    $cssHash = hash('sha256', $cssContents);
    $jsHash = hash('sha256', $jsContents);
    $outsideHash = hash('sha256', $outsideContents);
    $requiredAssetKeys = array(
        'css-bootstrap', 'css-dropzone', 'css-font-awesome',
        'css-highlightjs', 'js-ace', 'js-bootstrap', 'js-dropzone',
        'js-jquery', 'js-jquery-datatables', 'js-highlightjs'
    );
    $generatedTagKeys = array_merge(
        $requiredAssetKeys,
        array('pre-jsdelivr', 'pre-cloudflare')
    );
    $assets = array(
        'css-bootstrap' => array(
            'type' => 'style', 'path' => 'assets/app.css',
            'sha256' => $cssHash, 'license' => 'MIT', 'defer' => false
        ),
        'css-dropzone' => array(
            'type' => 'style', 'path' => 'assets/app.css',
            'sha256' => $cssHash, 'license' => 'MIT', 'defer' => false
        ),
        'css-font-awesome' => array(
            'type' => 'style', 'path' => 'assets/app.css',
            'sha256' => $cssHash, 'license' => 'MIT', 'defer' => false
        ),
        'css-highlightjs' => array(
            'type' => 'style', 'path' => 'assets/app.css',
            'sha256' => $cssHash, 'license' => 'BSD-3-Clause',
            'defer' => false
        ),
        'js-ace' => array(
            'type' => 'script', 'path' => 'assets/app.js',
            'sha256' => $jsHash, 'license' => 'BSD-3-Clause',
            'defer' => false
        ),
        'js-bootstrap' => array(
            'type' => 'script', 'path' => 'assets/app.js',
            'sha256' => $jsHash, 'license' => 'MIT', 'defer' => false
        ),
        'js-dropzone' => array(
            'type' => 'script', 'path' => 'assets/app.js',
            'sha256' => $jsHash, 'license' => 'MIT', 'defer' => false
        ),
        'js-jquery' => array(
            'type' => 'script', 'path' => 'assets/app.js',
            'sha256' => $jsHash, 'license' => 'MIT', 'defer' => false
        ),
        'js-jquery-datatables' => array(
            'type' => 'script', 'path' => 'assets/app.js',
            'sha256' => $jsHash, 'license' => 'MIT', 'defer' => true
        ),
        'js-highlightjs' => array(
            'type' => 'script', 'path' => 'assets/app.js',
            'sha256' => $jsHash, 'license' => 'BSD-3-Clause',
            'defer' => false
        )
    );
    $artifact = array('version' => 1, 'assets' => $assets);
    $artifactCounter = 0;
    $writeArtifact = function ($candidateArtifact) use (
        $assetRoot, &$artifactCounter
    ) {
        $artifactCounter++;
        $file = 'asset-manifest-' . $artifactCounter . '.json';
        $path = $assetRoot . '/' . $file;
        $json = json_encode($candidateArtifact, JSON_UNESCAPED_SLASHES);
        if (!is_string($json) || file_put_contents($path, $json) === false) {
            return false;
        }
        return array(
            'file' => $file,
            'sha256' => hash('sha256', $json)
        );
    };
    $buildFile = function (
        $manifestFile, $candidateRoot, $manifestSha256
    ) {
        $error = null;
        $tags = AfsProductionReadiness::buildLocalAssetTagsFromManifestFile(
            $manifestFile, $candidateRoot, $manifestSha256, $error
        );
        return array('tags' => $tags, 'error' => $error);
    };
    $build = function ($candidateArtifact, $candidateRoot) use (
        $writeArtifact, $buildFile
    ) {
        $record = $writeArtifact($candidateArtifact);
        if (!is_array($record)) {
            return array('tags' => false, 'error' => 'fixture write failed');
        }
        return $buildFile(
            $record['file'], $candidateRoot, $record['sha256']
        );
    };
    $reject = function ($candidateArtifact, $candidateRoot) use ($build) {
        $result = $build($candidateArtifact, $candidateRoot);
        return $result['tags'] === false
            && is_string($result['error']) && $result['error'] !== '';
    };

    $built = $build($artifact, $assetRoot);
    readiness_ok(
        is_array($built['tags'])
            && readiness_same_keys($built['tags'], $generatedTagKeys),
        'canonical version-1 JSON artifact produces required tags and disabled preconnects'
    );
    $canonicalArtifactRecord = $writeArtifact($artifact);
    readiness_ok(
        is_array($canonicalArtifactRecord)
            && isset(
                $canonicalArtifactRecord['file'],
                $canonicalArtifactRecord['sha256']
            ),
        'digest-pinned canonical manifest fixture was created'
    );
    if (is_array($canonicalArtifactRecord)) {
        $actualManifestDigest = $canonicalArtifactRecord['sha256'];
        $mismatchedManifestDigest = substr($actualManifestDigest, 0, 63)
            . (substr($actualManifestDigest, -1) === '0' ? '1' : '0');
        $manifestDigestFailures = array(
            'missing manifest digest' => '',
            'non-hex manifest digest' => str_repeat('z', 64),
            'uppercase manifest digest' => str_repeat('A', 64),
            'mismatched manifest digest' => $mismatchedManifestDigest
        );
        foreach ($manifestDigestFailures as $label => $manifestDigest) {
            $digestResult = $buildFile(
                $canonicalArtifactRecord['file'],
                $assetRoot,
                $manifestDigest
            );
            readiness_ok(
                $digestResult['tags'] === false
                    && is_string($digestResult['error'])
                    && $digestResult['error'] !== '',
                $label . ' fails canonical artifact readiness'
            );
        }
    }

    $changedRawRecord = $writeArtifact($artifact);
    $changedRawReady = is_array($changedRawRecord)
        && file_put_contents(
            $assetRoot . '/' . $changedRawRecord['file'],
            "\n",
            FILE_APPEND
        ) !== false;
    readiness_ok($changedRawReady, 'raw-byte digest-change fixture was created');
    if ($changedRawReady) {
        $changedRawResult = $buildFile(
            $changedRawRecord['file'],
            $assetRoot,
            $changedRawRecord['sha256']
        );
        readiness_ok(
            $changedRawResult['tags'] === false,
            'any raw manifest byte change invalidates its pinned digest'
        );
    }
    $expectedTags = array();
    foreach ($assets as $key => $entry) {
        $escapedPath = htmlspecialchars(
            $entry['path'], ENT_QUOTES, 'UTF-8'
        );
        $expectedTags[$key] = $entry['type'] === 'style'
            ? '<link rel="stylesheet" href="' . $escapedPath . '">'
            : '<script src="' . $escapedPath . '"'
                . (!empty($entry['defer']) ? ' defer' : '') . '></script>';
    }
    $expectedTags['pre-jsdelivr'] = '';
    $expectedTags['pre-cloudflare'] = '';
    readiness_ok(
        $built['tags'] === $expectedTags,
        'builder generates only canonical path-based link and script tags'
    );
    readiness_ok(
        strpos($built['tags']['js-jquery-datatables'], ' defer') !== false,
        'typed true defer option is preserved on a generated script tag'
    );
    readiness_ok(
        strpos(implode("\n", $built['tags']), $cssHash) === false
            && strpos(implode("\n", $built['tags']), $jsHash) === false,
        'review hashes are verified but are not emitted into generated tags'
    );
    readiness_ok(
        strpos(implode("\n", $built['tags']), 'MIT') === false
            && strpos(implode("\n", $built['tags']), 'BSD-3-Clause') === false,
        'reviewed license metadata is validated but not emitted into tags'
    );

    $escapedArtifact = $artifact;
    $escapedArtifact['assets']['css-bootstrap']['path'] =
        'assets/app&theme.css';
    $escapedTags = $build($escapedArtifact, $assetRoot);
    readiness_ok(
        is_array($escapedTags['tags'])
            && strpos(
                $escapedTags['tags']['css-bootstrap'],
                'href="assets/app&amp;theme.css"'
            ) !== false,
        'generated asset paths are HTML-attribute encoded'
    );

    $uppercaseHash = $artifact;
    $uppercaseHash['assets']['js-ace']['sha256'] = strtoupper($jsHash);
    readiness_ok(
        $reject($uppercaseHash, $assetRoot),
        'uppercase hexadecimal SHA-256 fails canonical lowercase readiness'
    );

    $acceptedLicenses = array(
        'MIT', 'BSD-3-Clause', 'Apache-2.0', 'OFL-1.1'
    );
    foreach ($acceptedLicenses as $license) {
        $licensedArtifact = $artifact;
        $licensedArtifact['assets']['js-ace']['license'] = $license;
        readiness_ok(
            is_array($build($licensedArtifact, $assetRoot)['tags']),
            'reviewed SPDX license ' . $license . ' is accepted'
        );
    }
    foreach ($requiredAssetKeys as $assetKey) {
        $missingDeferArtifact = $artifact;
        unset($missingDeferArtifact['assets'][$assetKey]['defer']);
        readiness_ok(
            $reject($missingDeferArtifact, $assetRoot),
            'required defer is enforced for manifest row ' . $assetKey
        );
    }

    $versionFailures = array(
        'missing version' => null,
        'string version' => '1',
        'future version' => 2
    );
    foreach ($versionFailures as $label => $version) {
        $candidate = $artifact;
        if ($label === 'missing version') {
            unset($candidate['version']);
        } else {
            $candidate['version'] = $version;
        }
        readiness_ok(
            $reject($candidate, $assetRoot),
            $label . ' fails canonical manifest readiness'
        );
    }
    $extraTopLevel = $artifact;
    $extraTopLevel['metadata'] = array('reviewed' => true);
    readiness_ok(
        $reject($extraTopLevel, $assetRoot),
        'arbitrary top-level manifest field is rejected'
    );
    $missingAssets = $artifact;
    unset($missingAssets['assets']);
    readiness_ok(
        $reject($missingAssets, $assetRoot),
        'manifest missing its assets object is rejected'
    );
    $invalidAssets = $artifact;
    $invalidAssets['assets'] = 'not-an-object';
    readiness_ok(
        $reject($invalidAssets, $assetRoot),
        'non-object manifest assets value is rejected'
    );

    $missingKey = $artifact;
    unset($missingKey['assets']['js-ace']);
    readiness_ok(
        $reject($missingKey, $assetRoot),
        'manifest missing an exact required key fails readiness'
    );
    $extraKey = $artifact;
    $extraKey['assets']['js-extra'] = $assets['js-ace'];
    readiness_ok(
        $reject($extraKey, $assetRoot),
        'manifest with an extra key fails readiness'
    );

    $rowFailures = array();
    $rowFailures['non-array row'] = '<script src="assets/app.js"></script>';
    $rowFailures['missing type'] = $assets['js-ace'];
    unset($rowFailures['missing type']['type']);
    $rowFailures['missing path'] = $assets['js-ace'];
    unset($rowFailures['missing path']['path']);
    $rowFailures['missing SHA-256'] = $assets['js-ace'];
    unset($rowFailures['missing SHA-256']['sha256']);
    $rowFailures['missing license'] = $assets['js-ace'];
    unset($rowFailures['missing license']['license']);
    $rowFailures['empty license'] = $assets['js-ace'];
    $rowFailures['empty license']['license'] = '';
    $rowFailures['non-string license'] = $assets['js-ace'];
    $rowFailures['non-string license']['license'] = array('MIT');
    $rowFailures['unknown license'] = $assets['js-ace'];
    $rowFailures['unknown license']['license'] = 'Unreviewed-Proprietary';
    $rowFailures['markup license'] = $assets['js-ace'];
    $rowFailures['markup license']['license'] = '<script>alert(1)</script>';
    $rowFailures['extra field'] = $assets['js-ace'];
    $rowFailures['extra field']['html'] = '<script>alert(1)</script>';
    $rowFailures['wrong key type'] = $assets['js-ace'];
    $rowFailures['wrong key type']['type'] = 'style';
    $rowFailures['style key wrong type'] = $assets['css-bootstrap'];
    $rowFailures['style key wrong type']['type'] = 'script';
    $rowFailures['unknown type'] = $assets['js-ace'];
    $rowFailures['unknown type']['type'] = 'module';
    $rowFailures['non-string path'] = $assets['js-ace'];
    $rowFailures['non-string path']['path'] = array('assets/app.js');
    $rowFailures['non-string SHA-256'] = $assets['js-ace'];
    $rowFailures['non-string SHA-256']['sha256'] = array($jsHash);
    $rowFailures['short SHA-256'] = $assets['js-ace'];
    $rowFailures['short SHA-256']['sha256'] = substr($jsHash, 1);
    $rowFailures['non-hex SHA-256'] = $assets['js-ace'];
    $rowFailures['non-hex SHA-256']['sha256'] = str_repeat('z', 64);
    $rowFailures['mismatched SHA-256'] = $assets['js-ace'];
    $rowFailures['mismatched SHA-256']['sha256'] = str_repeat('0', 64);
    $rowFailures['style defer option'] = $assets['css-bootstrap'];
    $rowFailures['style defer option']['defer'] = true;
    $rowFailures['non-boolean defer'] = $assets['js-ace'];
    $rowFailures['non-boolean defer']['defer'] = 'true';
    foreach ($rowFailures as $label => $row) {
        $candidate = $artifact;
        $candidate['assets'][strpos($label, 'style ') === 0
            ? 'css-bootstrap' : 'js-ace'] = $row;
        readiness_ok(
            $reject($candidate, $assetRoot),
            $label . ' fails typed manifest readiness'
        );
    }

    $pathFailures = array(
        'HTTP URL' => 'http://example.invalid/app.js',
        'HTTPS URL' => 'https://example.invalid/app.js',
        'protocol-relative URL' => '//example.invalid/app.js',
        'javascript URL' => 'javascript:alert(1)',
        'data URL' => 'data:text/javascript,alert(1)',
        'blob URL' => 'blob:deadbeef',
        'file URL' => 'file:///tmp/app.js',
        'mixed-case scheme' => 'JaVaScRiPt:alert(1)',
        'arbitrary URI scheme' => 'custom+asset:payload',
        'percent-encoded scheme' => 'https%3A%2F%2Fexample.invalid/app.js',
        'percent-encoded network path' => '%2F%2Fexample.invalid/app.js',
        'absolute path' => '/assets/app.js',
        'backslash path' => 'assets\\app.js',
        'parent traversal' => '../outside.js',
        'encoded parent traversal' => '%2e%2e/outside.js',
        'encoded question mark' => 'assets/app.js%3Fmissing',
        'lowercase encoded question mark' => 'assets/app.js%3fmissing',
        'encoded fragment delimiter' => 'assets/app.js%23missing',
        'missing file' => 'assets/missing.js',
        'directory path' => 'assets'
    );
    foreach ($pathFailures as $label => $path) {
        $candidate = $artifact;
        $candidate['assets']['js-ace']['path'] = $path;
        if ($label === 'parent traversal'
            || $label === 'encoded parent traversal') {
            $candidate['assets']['js-ace']['sha256'] = $outsideHash;
        }
        readiness_ok(
            $reject($candidate, $assetRoot),
            $label . ' fails typed local-path readiness'
        );
    }
    readiness_ok(
        $reject($artifact, $assetRoot . '/missing'),
        'missing configured asset root fails readiness'
    );

    $manifestPathFailures = array(
        'empty manifest path' => '',
        'absolute manifest path' => '/asset-manifest.json',
        'HTTP manifest URL' => 'http://example.invalid/assets.json',
        'HTTPS manifest URL' => 'https://example.invalid/assets.json',
        'protocol-relative manifest URL' => '//example.invalid/assets.json',
        'manifest parent traversal' => '../asset-manifest.json',
        'manifest dot segment' => './asset-manifest.json',
        'encoded manifest delimiter' => 'asset-manifest%2ejson',
        'query-bearing manifest path' => 'asset-manifest.json?version=1',
        'fragment-bearing manifest path' => 'asset-manifest.json#v1',
        'backslash manifest path' => 'assets\\asset-manifest.json',
        'whitespace manifest path' => ' asset-manifest.json',
        'missing manifest file' => 'missing-manifest.json'
    );
    foreach ($manifestPathFailures as $label => $manifestPath) {
        $manifestPathResult = $buildFile(
            $manifestPath, $assetRoot, str_repeat('a', 64)
        );
        readiness_ok(
            $manifestPathResult['tags'] === false
                && is_string($manifestPathResult['error'])
                && $manifestPathResult['error'] !== '',
            $label . ' fails canonical manifest-artifact readiness'
        );
    }

    $invalidJsonFile = 'invalid-manifest.json';
    $invalidJsonPath = $assetRoot . '/' . $invalidJsonFile;
    $invalidJsonRaw = '{"version":1,"assets":';
    $invalidJsonReady = file_put_contents(
        $invalidJsonPath,
        $invalidJsonRaw
    ) !== false;
    readiness_ok($invalidJsonReady, 'invalid JSON manifest fixture was created');
    if ($invalidJsonReady) {
        $invalidJsonResult = $buildFile(
            $invalidJsonFile,
            $assetRoot,
            hash('sha256', $invalidJsonRaw)
        );
        readiness_ok(
            $invalidJsonResult['tags'] === false
                && is_string($invalidJsonResult['error'])
                && $invalidJsonResult['error'] !== '',
            'malformed JSON manifest artifact fails readiness'
        );
    }

    $manifestSymlinkFile = 'manifest-link.json';
    $manifestSymlink = $assetRoot . '/' . $manifestSymlinkFile;
    $manifestLinkReady = is_array($canonicalArtifactRecord)
        && @symlink($canonicalArtifactRecord['file'], $manifestSymlink);
    readiness_ok($manifestLinkReady, 'manifest-artifact symlink fixture was created');
    if ($manifestLinkReady) {
        $manifestLinkResult = $buildFile(
            $manifestSymlinkFile,
            $assetRoot,
            $canonicalArtifactRecord['sha256']
        );
        readiness_ok(
            $manifestLinkResult['tags'] === false,
            'canonical manifest artifact itself cannot be a symlink'
        );
    }

    $outsideLink = $assetDir . '/outside-link.js';
    $insideLink = $assetDir . '/inside-link.js';
    $insideDirectoryLink = $assetRoot . '/linked-assets';
    $symlinksReady = @symlink('../../outside.js', $outsideLink)
        && @symlink('app.js', $insideLink)
        && @symlink('assets', $insideDirectoryLink);
    readiness_ok($symlinksReady, 'asset-symlink fixtures were created');
    if ($symlinksReady) {
        $outsideLinkManifest = $artifact;
        $outsideLinkManifest['assets']['js-ace']['path'] =
            'assets/outside-link.js';
        $outsideLinkManifest['assets']['js-ace']['sha256'] = $outsideHash;
        readiness_ok(
            $reject($outsideLinkManifest, $assetRoot),
            'out-of-root asset symlink fails readiness'
        );
        $insideLinkManifest = $artifact;
        $insideLinkManifest['assets']['js-ace']['path'] =
            'assets/inside-link.js';
        readiness_ok(
            $reject($insideLinkManifest, $assetRoot),
            'in-root asset symlink also fails reviewed-manifest readiness'
        );
        $insideDirectoryLinkManifest = $artifact;
        $insideDirectoryLinkManifest['assets']['js-ace']['path'] =
            'linked-assets/app.js';
        readiness_ok(
            $reject($insideDirectoryLinkManifest, $assetRoot),
            'an in-root intermediate directory symlink fails readiness'
        );
    }
}

echo "\n" . $readinessPasses . " readiness assertions passed";
if (!empty($readinessFailures)) {
    echo ", " . count($readinessFailures) . " failed\n";
    exit(1);
}
echo ", 0 failed\n";
exit(0);
