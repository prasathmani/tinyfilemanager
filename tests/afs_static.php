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
$contractPath = $root . '/afs_contract.php';
$manager = @file_get_contents($managerPath);
$afs = @file_get_contents($afsPath);
$contract = @file_get_contents($contractPath);

if ($manager === false || $afs === false || $contract === false) {
    fwrite(
        STDERR,
        "FAIL: unable to read tinyfilemanager.php, afs.php, and afs_contract.php\n"
    );
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

function afs_test_not_contains($haystack, $needle, $message)
{
    afs_test_ok(strpos($haystack, $needle) === false, $message);
}

echo "AFS static integration contract\n";

// The side-effect-free provider contract is available to config.php, while the
// runtime AFS helper remains an explicit post-config opt-in/profile dependency.
$defaultPos = strpos($manager, '$afsSupport = false;');
$contractPos = strpos(
    $manager,
    "require_once __DIR__ . '/afs_contract.php';"
);
$configPos = strpos($manager, '@include($config_file);');
$urlUploadDefaultPos = strpos($manager, '$url_upload_enabled = true;');
$guardPos = strpos(
    $manager,
    "if (\$afsSupport || defined('AFS_PRODUCTION_PROFILE')) {"
);
$requirePos = strpos($manager, "require_once __DIR__ . '/afs.php';");

afs_test_ok($defaultPos !== false, 'AFS support defaults to disabled');
afs_test_ok($contractPos !== false, 'side-effect-free AFS contract is loaded');
afs_test_ok($configPos !== false, 'external config.php is included');
afs_test_ok(
    $urlUploadDefaultPos !== false && $configPos !== false
        && $urlUploadDefaultPos < $configPos,
    'URL upload defaults enabled for non-AFS before config.php overrides it'
);
afs_test_ok(
    $guardPos !== false,
    'AFS helper load is conditional on opt-in or the immutable profile'
);
afs_test_ok($requirePos !== false, 'AFS dependency uses an __DIR__-anchored path');
afs_test_ok(
    $defaultPos !== false && $contractPos !== false && $configPos !== false
        && $defaultPos < $contractPos && $contractPos < $configPos,
    'provider contract is loaded before config.php constructs its factory'
);
afs_test_ok(
    $configPos !== false && $guardPos !== false && $requirePos !== false
        && $configPos < $guardPos && $guardPos < $requirePos,
    'config.php resolves the AFS opt-in/profile before afs.php is required'
);
afs_test_contains(
    $afs,
    "require_once __DIR__ . '/afs_contract.php';",
    'standalone afs.php loads the shared provider contract'
);
$contractGate = afs_test_section(
    $manager,
    "if ((\$afsSupport || defined('AFS_PRODUCTION_PROFILE'))",
    "if (\$afsSupport || defined('AFS_PRODUCTION_PROFILE')) {",
    'packaged AFS contract readiness gate'
);
afs_test_contains(
    $contractGate,
    "!interface_exists('AfsDataPlaneProviderFactory', false)",
    'AFS activation requires the packaged provider contract'
);
afs_test_contains(
    $contractGate,
    'AFS production requires the packaged provider contract.',
    'missing packaged provider contract fails readiness'
);
afs_test_not_contains(
    $contract,
    'extension_loaded(',
    'provider contract has no extension-load side effects'
);
afs_test_not_contains(
    $contract,
    'exit(',
    'provider contract cannot terminate config loading'
);

// A production provider must advertise both readiness and the exact reviewed
// descriptor boundary. The bundled pathname model remains an offline preview.
$factoryInterface = afs_test_section(
    $contract,
    'interface AfsDataPlaneProviderFactory',
    "interface AfsDataPlaneProvider\n",
    'AFS provider-factory interface'
);
afs_test_contains(
    $factoryInterface,
    'public function getFactoryIdentity();',
    'provider factory declares its reviewed identity'
);
afs_test_contains(
    $factoryInterface,
    'public function createProvider( $root, $requestIdentity );',
    'provider factory binds root and request identity at creation'
);

$providerInterface = afs_test_section(
    $contract . "\n/* END AFS CONTRACT */\n",
    "interface AfsDataPlaneProvider\n",
    '/* END AFS CONTRACT */',
    'AFS provider interface'
);
afs_test_contains(
    $providerInterface,
    'SECURITY_BOUNDARY_DESCRIPTOR_BENEATH_V1',
    'provider interface names the reviewed descriptor boundary token'
);
afs_test_contains(
    $providerInterface,
    "'descriptor-beneath-v1'",
    'provider boundary token has the expected versioned value'
);
$providerMethods = array(
    'initializeDataPlane', 'isProductionReady', 'getReadinessFailure',
    'getSecurityBoundary', 'getProviderIdentity', 'getCredentialIdentity',
    'resolveExistingPath', 'resolveWritePath',
    'inspectPath', 'listDirectory', 'searchFiles', 'openRead',
    'readContents', 'detectMimeType', 'createFile', 'writeFile',
    'importFile', 'makeDirectory', 'copyPath', 'renamePath', 'removePath',
    'archivesSupported', 'readAcl', 'changeAclEntries', 'getACLAccess'
);
foreach ($providerMethods as $method) {
    afs_test_contains(
        $providerInterface,
        'public function ' . $method . '(',
        'provider interface declares ' . $method
    );
}

$bundledReadiness = afs_test_section(
    $afs,
    'class AfsDataPlane extends Afs implements AfsDataPlaneProvider',
    'public function initializeDataPlane',
    'bundled provider readiness'
);
afs_test_contains(
    $bundledReadiness,
    "public function isProductionReady()\n    {\n        return false;",
    'bundled pathname provider cannot claim production readiness'
);
afs_test_contains(
    $bundledReadiness,
    "return 'pathname-preview';",
    'bundled pathname provider cannot advertise the descriptor boundary token'
);

$providerReadiness = afs_test_section(
    $manager,
    '$afsDataPlane = null;',
    '// always use ?p=',
    'provider startup readiness'
);
afs_test_contains(
    $providerReadiness,
    'if (!($afsDataPlaneFactory instanceof AfsDataPlaneProviderFactory))',
    'AFS startup requires the typed provider-factory interface'
);
afs_test_not_contains(
    $providerReadiness,
    'is_callable(',
    'AFS startup has no legacy untyped callable-factory fallback'
);
afs_test_contains(
    $providerReadiness,
    'get_class($afsDataPlaneFactory) !== $afs_expected_factory_class',
    'AFS startup requires the exact configured factory class'
);
afs_test_contains(
    $providerReadiness,
    '$afsDataPlaneFactory->getFactoryIdentity()',
    'AFS startup reads the factory-declared identity'
);
afs_test_contains(
    $providerReadiness,
    '!== $afs_expected_factory_id',
    'AFS startup requires the exact configured factory identity'
);
afs_test_contains(
    $providerReadiness,
    '$afsDataPlaneFactory->createProvider(',
    'AFS startup obtains the provider from the typed factory'
);
afs_test_contains(
    $providerReadiness,
    'FM_ROOT_PATH, $afsRequestIdentity);',
    'factory creation binds the reviewed root and snapshotted request identity'
);
afs_test_contains(
    $providerReadiness,
    'if (!($afsDataPlane instanceof AfsDataPlaneProvider))',
    'AFS startup requires the provider interface'
);
afs_test_contains(
    $providerReadiness,
    'get_class($afsDataPlane) !== $afs_expected_provider_class',
    'AFS startup requires the exact configured provider class'
);
afs_test_contains(
    $providerReadiness,
    '$afsDataPlane->getProviderIdentity()',
    'AFS startup reads the provider-declared identity'
);
afs_test_contains(
    $providerReadiness,
    '!== $afs_expected_provider_id',
    'AFS startup requires the exact configured provider identity'
);
afs_test_contains(
    $providerReadiness,
    '$afsDataPlane->getCredentialIdentity()',
    'AFS startup reads the provider credential identity'
);
afs_test_contains(
    $providerReadiness,
    '!== $afsRequestIdentity',
    'AFS startup binds provider credentials to the snapshotted request identity'
);
afs_test_not_contains(
    $providerReadiness,
    "\$_SERVER['REMOTE_USER']",
    'provider startup never re-reads mutable request identity state'
);
afs_test_contains(
    $providerReadiness,
    'if ($afsDataPlane->isProductionReady() !== true)',
    'AFS startup accepts only literal true readiness'
);
afs_test_contains(
    $providerReadiness,
    '!== AfsDataPlaneProvider::SECURITY_BOUNDARY_DESCRIPTOR_BENEATH_V1',
    'AFS startup requires the exact descriptor boundary token'
);
afs_test_contains(
    $providerReadiness,
    'if ($afsDataPlane->initializeDataPlane(FM_ROOT_PATH) !== true)',
    'AFS startup accepts only literal true provider initialization'
);
$providerReadyPos = strpos($providerReadiness, '->isProductionReady() !== true');
$providerBoundaryPos = strpos($providerReadiness, '->getSecurityBoundary()');
$providerInitPos = strpos($providerReadiness, '->initializeDataPlane(FM_ROOT_PATH) !== true');
$factoryClassPos = strpos($providerReadiness, 'get_class($afsDataPlaneFactory)');
$providerCreatePos = strpos($providerReadiness, '->createProvider(');
$credentialPos = strpos($providerReadiness, '->getCredentialIdentity()');
afs_test_ok(
    $factoryClassPos !== false && $providerCreatePos !== false
        && $credentialPos !== false && $providerReadyPos !== false
        && $providerBoundaryPos !== false
        && $providerInitPos !== false
        && $factoryClassPos < $providerCreatePos
        && $providerCreatePos < $credentialPos
        && $credentialPos < $providerReadyPos
        && $providerReadyPos < $providerBoundaryPos
        && $providerBoundaryPos < $providerInitPos,
    'factory/provider identity, readiness, and boundary checks precede initialization'
);

$legacyReturnUri = afs_test_section(
    $afs,
    'function get_returnToURI()',
    'Return a string escaped for a javascript string literal.',
    'legacy AFS return URI'
);
afs_test_contains(
    $legacyReturnUri,
    'FM_SELF_URL',
    'legacy AFS return URI uses the validated controller URL'
);
afs_test_not_contains(
    $legacyReturnUri,
    'HTTP_HOST',
    'legacy AFS return URI never trusts the request Host header'
);
afs_test_not_contains(
    $legacyReturnUri,
    "\$_SERVER['PHP_SELF']",
    'legacy AFS return URI never re-reads an unvalidated request path'
);

// The immutable profile validates the application's constructed state, not a
// deployment-supplied assertion. Its trusted request identity is snapshotted
// once and later passed unchanged to the provider factory.
$profileState = afs_test_section(
    $manager,
    '$afsSelfUrl = isset($_SERVER[\'SCRIPT_NAME\'])',
    "define('ACE_FONTSIZE'",
    'AFS actual production-profile state'
);
afs_test_contains(
    $profileState,
    "\$afsRequestIdentity = isset(\$_SERVER['REMOTE_USER'])",
    'AFS profile snapshots the externally authenticated request identity'
);
afs_test_contains(
    $profileState,
    '$afsDataRoot = $root_path;',
    'AFS profile snapshots its configured data root once'
);
$actualProfileFields = array(
    "'profile' => defined('AFS_PRODUCTION_PROFILE')" =>
        'profile state reads the immutable profile constant',
    '? AFS_PRODUCTION_PROFILE : null' =>
        'profile state records the actual immutable profile value',
    "'afs_enabled' => \$afsSupport" =>
        'profile state records actual AFS enablement',
    "'external_auth' => \$afs_external_auth" =>
        'profile state records actual external-auth enablement',
    "'request_identity' => \$afsRequestIdentity" =>
        'profile state records the snapshotted request identity',
    "'local_auth' => \$use_auth" =>
        'profile state records actual local-auth state',
    "'local_users_empty' => is_array(\$auth_users)" =>
        'profile state validates the actual local-user collections',
    '&& empty($auth_users) && empty($readonly_users)' =>
        'profile state requires auth and readonly user maps to be empty',
    '&& empty($directories_users)' =>
        'profile state requires per-user directory mappings to be empty',
    "'settings_enabled' => \$settings_enabled" =>
        'profile state records actual settings enablement',
    "'embed_enabled' => defined('FM_EMBED')" =>
        'profile state records the actual embed constant',
    "'direct_links_enabled' => \$direct_links_enabled" =>
        'profile state records actual direct-link enablement',
    "'raw_previews_enabled' => \$raw_previews_enabled" =>
        'profile state records actual raw-preview enablement',
    "'url_upload_enabled' => \$url_upload_enabled" =>
        'profile state records actual URL-upload enablement',
    "'root_url' => \$root_url" =>
        'profile state records the actual managed-root URL',
    "'self_url' => \$afsSelfUrl" =>
        'profile state records the actual controller URL',
    "'data_root' => \$afsDataRoot" =>
        'profile state records the snapshotted data root',
    "'asset_manifest_sha256' => \$afs_asset_manifest_sha256" =>
        'profile state records the reviewed manifest digest',
    "'expected_factory_class' => \$afs_expected_factory_class" =>
        'profile state records the expected factory class',
    "'expected_factory_id' => \$afs_expected_factory_id" =>
        'profile state records the expected factory identity',
    "'expected_provider_class' => \$afs_expected_provider_class" =>
        'profile state records the expected provider class',
    "'expected_provider_id' => \$afs_expected_provider_id" =>
        'profile state records the expected provider identity'
);
foreach ($actualProfileFields as $needle => $message) {
    afs_test_contains($profileState, $needle, $message);
}
afs_test_contains(
    $profileState,
    'AfsProductionReadiness::validateProductionProfile(',
    'manager validates the constructed actual production-profile state'
);
afs_test_contains(
    $profileState,
    "if (defined('FM_ROOT_PATH') && FM_ROOT_PATH !== \$afsDataRoot)",
    'AFS rejects a pre-defined FM_ROOT_PATH that differs from the profile root'
);
$profileStateValidationPos = strpos(
    $profileState,
    'AfsProductionReadiness::validateProductionProfile('
);
$predefinedRootGatePos = strpos(
    $profileState,
    "if (defined('FM_ROOT_PATH') && FM_ROOT_PATH !== \$afsDataRoot)"
);
afs_test_ok(
    $profileStateValidationPos !== false && $predefinedRootGatePos !== false
        && $profileStateValidationPos < $predefinedRootGatePos,
    'profile validation precedes the pre-defined FM_ROOT_PATH equality gate'
);

$profileValidator = afs_test_section(
    $afs,
    'public static function validateProductionProfile(',
    'public static function applicationTemplatesSupportStrictCsp',
    'immutable AFS production-profile validator'
);
afs_test_contains(
    $profileValidator,
    "'profile' => self::PRODUCTION_PROFILE",
    'profile validator requires its immutable version token'
);
$fixedProfileValues = array(
    "'afs_enabled' => true",
    "'external_auth' => true",
    "'local_auth' => false",
    "'local_users_empty' => true",
    "'settings_enabled' => false",
    "'embed_enabled' => false",
    "'direct_links_enabled' => false",
    "'raw_previews_enabled' => false",
    "'url_upload_enabled' => false",
    "'root_url' => ''"
);
foreach ($fixedProfileValues as $fixedProfileValue) {
    afs_test_contains(
        $profileValidator,
        $fixedProfileValue,
        'immutable profile fixes ' . $fixedProfileValue
    );
}
afs_test_contains(
    $profileValidator,
    "preg_match( '/[\\x00-\\x1f\\x7f]/', \$state['request_identity'] )",
    'profile rejects control bytes in the trusted external identity'
);
afs_test_contains(
    $profileValidator,
    "!is_string( \$state['data_root'] )",
    'profile requires a string data root'
);
afs_test_contains(
    $profileValidator,
    "strpos( \$state['data_root'], '/afs/' ) !== 0",
    'profile requires the data root to be strictly below /afs'
);
afs_test_contains(
    $profileValidator,
    "rtrim( \$state['data_root'], '/' ) !== \$state['data_root']",
    'profile rejects a trailing slash in the data root'
);
afs_test_contains(
    $profileValidator,
    "strpos( \$state['data_root'], '\\\\' ) !== false",
    'profile rejects backslashes in the data root'
);
afs_test_contains(
    $profileValidator,
    "preg_match( '/[\\x00-\\x1f\\x7f]/', \$state['data_root'] )",
    'profile rejects control bytes in the data root'
);
afs_test_contains(
    $profileValidator,
    "explode( '/', substr( \$state['data_root'], 5 ))",
    'profile validates every data-root path segment'
);
afs_test_contains(
    $profileValidator,
    "\$segment === '' || \$segment === '.' || \$segment === '..'",
    'profile rejects empty and dot segments in the data root'
);
afs_test_contains(
    $profileValidator,
    "!is_string( \$state['asset_manifest_sha256'] )",
    'profile requires a string manifest digest'
);
afs_test_contains(
    $profileValidator,
    "preg_match( '/^[a-f0-9]{64}$/',",
    'profile requires a lowercase 64-hex manifest digest'
);
afs_test_contains(
    $profileValidator,
    "\$state['asset_manifest_sha256']",
    'profile validates the reviewed manifest digest from actual state'
);
afs_test_contains(
    $afs,
    "const PRODUCTION_PROFILE = 'afs-descriptor-v1';",
    'immutable AFS production profile has the reviewed versioned value'
);
$profileKeys = array(
    'profile', 'afs_enabled', 'external_auth', 'request_identity',
    'local_auth', 'local_users_empty', 'settings_enabled', 'embed_enabled',
    'direct_links_enabled', 'raw_previews_enabled', 'url_upload_enabled',
    'root_url', 'self_url',
    'data_root', 'asset_manifest_sha256',
    'expected_factory_class', 'expected_factory_id',
    'expected_provider_class', 'expected_provider_id'
);
foreach ($profileKeys as $profileKey) {
    afs_test_contains(
        $profileValidator,
        "'" . $profileKey . "'",
        'immutable profile declares actual-state field ' . $profileKey
    );
}
afs_test_contains(
    $profileValidator,
    'count( $state ) !== count( $keys )',
    'immutable profile rejects missing or extra actual-state field counts'
);
afs_test_contains(
    $profileValidator,
    'array_diff_key( array_flip( $keys ), $state )',
    'immutable profile rejects missing actual-state fields'
);
afs_test_contains(
    $profileValidator,
    'array_diff_key( $state, array_flip( $keys ))',
    'immutable profile rejects unreviewed actual-state fields'
);
$profileValidationPos = strpos(
    $manager,
    'AfsProductionReadiness::validateProductionProfile('
);
$embedRuntimePos = strpos($manager, "if (defined('FM_EMBED')) {");
$localAuthRuntimePos = strpos($manager, 'if ($use_auth) {');
afs_test_ok(
    $profileValidationPos !== false && $embedRuntimePos !== false
        && $localAuthRuntimePos !== false
        && $profileValidationPos < $embedRuntimePos
        && $profileValidationPos < $localAuthRuntimePos,
    'profile rejects embed/local-auth state before authentication dispatch'
);

$rootBinding = afs_test_section(
    $manager,
    '// Use the single post-config profile snapshot;',
    "defined('FM_LANG')",
    'final AFS data-root binding'
);
afs_test_contains(
    $rootBinding,
    '$root_path = $afsDataRoot;',
    'AFS rebinds mutable root_path to the single profile snapshot'
);
afs_test_contains(
    $rootBinding,
    "defined('FM_ROOT_PATH') || define('FM_ROOT_PATH', \$root_path);",
    'FM_ROOT_PATH is defined from the rebound profile root'
);
afs_test_contains(
    $rootBinding,
    'if ($afsSupport && FM_ROOT_PATH !== $afsDataRoot)',
    'AFS asserts the final FM_ROOT_PATH still equals the profile snapshot'
);
$dataRootSnapshotPos = strpos($manager, '$afsDataRoot = $root_path;');
$rootRebindPos = strpos(
    $manager,
    '$root_path = $afsDataRoot;',
    $dataRootSnapshotPos === false ? 0 : $dataRootSnapshotPos
);
$rootDefinePos = strpos(
    $manager,
    "defined('FM_ROOT_PATH') || define('FM_ROOT_PATH', \$root_path);"
);
$rootFinalGatePos = strpos(
    $manager,
    'if ($afsSupport && FM_ROOT_PATH !== $afsDataRoot)'
);
$factoryRootPos = strpos(
    $manager,
    'FM_ROOT_PATH, $afsRequestIdentity);'
);
$initializeRootPos = strpos(
    $manager,
    '->initializeDataPlane(FM_ROOT_PATH) !== true'
);
afs_test_ok(
    $dataRootSnapshotPos !== false && $rootRebindPos !== false
        && $rootDefinePos !== false && $rootFinalGatePos !== false
        && $factoryRootPos !== false && $initializeRootPos !== false
        && $dataRootSnapshotPos < $rootRebindPos
        && $rootRebindPos < $rootDefinePos
        && $rootDefinePos < $rootFinalGatePos
        && $rootFinalGatePos < $factoryRootPos
        && $factoryRootPos < $initializeRootPos,
    'one snapshotted FM_ROOT_PATH reaches factory creation and initialization'
);

// Configurable and pre-defined feature flags are both checked. The final
// constants must still be literal false before any provider or route runs.
$featureConstants = afs_test_section(
    $manager,
    "if (\$afsSupport && ((defined('FM_SETTINGS_ENABLED')",
    '$afsDataPlane = null;',
    'final AFS feature-constant gates'
);
$featureConstantNames = array(
    'FM_SETTINGS_ENABLED', 'FM_DIRECT_LINKS_ENABLED',
    'FM_RAW_PREVIEWS_ENABLED', 'FM_URL_UPLOAD_ENABLED'
);
foreach ($featureConstantNames as $featureConstantName) {
    afs_test_contains(
        $featureConstants,
        "defined('" . $featureConstantName . "')",
        'AFS rejects a pre-defined ' . $featureConstantName
    );
    afs_test_contains(
        $featureConstants,
        $featureConstantName . ' !== false',
        'AFS requires literal false ' . $featureConstantName
    );
}
afs_test_contains(
    $featureConstants,
    "defined('FM_SETTINGS_ENABLED') || define('FM_SETTINGS_ENABLED', \$settings_enabled);",
    'final settings constant derives from validated actual state'
);
afs_test_contains(
    $featureConstants,
    "defined('FM_DIRECT_LINKS_ENABLED') || define('FM_DIRECT_LINKS_ENABLED', \$direct_links_enabled);",
    'final direct-link constant derives from validated actual state'
);
afs_test_contains(
    $featureConstants,
    "defined('FM_RAW_PREVIEWS_ENABLED') || define('FM_RAW_PREVIEWS_ENABLED', \$raw_previews_enabled);",
    'final raw-preview constant derives from validated actual state'
);
afs_test_contains(
    $featureConstants,
    "defined('FM_URL_UPLOAD_ENABLED') || define('FM_URL_UPLOAD_ENABLED', \$url_upload_enabled);",
    'final URL-upload constant derives from validated actual state'
);
afs_test_contains(
    $featureConstants,
    'AFS production features did not remain fail-closed.',
    'AFS rechecks final feature constants after definition'
);

$settingsAjax = afs_test_section(
    $manager,
    '// Save Config',
    '//upload using url',
    'settings AJAX utilities'
);
afs_test_contains(
    $settingsAjax,
    'if (!FM_SETTINGS_ENABLED || fm_is_afs_mode())',
    'settings mutation is rejected when disabled and always in AFS mode'
);
afs_test_contains(
    $settingsAjax,
    'if (!FM_SETTINGS_ENABLED)',
    'password-hash utility is rejected when settings are disabled'
);
$settingsPage = afs_test_section(
    $manager,
    "if (isset(\$_GET['settings']) && !FM_SETTINGS_ENABLED)",
    '// file viewer',
    'settings page route'
);
afs_test_contains(
    $settingsPage,
    "if (isset(\$_GET['settings']) && !FM_SETTINGS_ENABLED)",
    'disabled settings page requests are explicitly rejected'
);
afs_test_contains(
    $settingsPage,
    "isset(\$_GET['settings']) && !FM_READONLY && FM_SETTINGS_ENABLED",
    'settings page rendering requires the enabled flag'
);
$configWriter = afs_test_section(
    $manager,
    'class FM_Config',
    'function fm_show_nav_path($path)',
    'configuration writer'
);
afs_test_contains(
    $configWriter,
    "function save()\n    {\n        if (fm_is_afs_mode()) {\n            return false;",
    'configuration writer independently refuses AFS mutations'
);

// AFS assets are structured input: exact typed rows and reviewed SHA-256
// digests. Raw config-provided HTML remains a non-AFS-only compatibility path.
$readinessClass = afs_test_section(
    $afs,
    'class AfsProductionReadiness',
    'class AfsDataPlane extends Afs implements AfsDataPlaneProvider',
    'AFS production-readiness class'
);
$assetBuilder = afs_test_section(
    $readinessClass,
    'public static function buildLocalAssetTags(',
    'public static function buildLocalAssetTagsFromManifestFile(',
    'typed local-asset builder'
);
$assetKeys = array(
    'css-bootstrap', 'css-dropzone', 'css-font-awesome',
    'css-highlightjs', 'js-ace', 'js-bootstrap', 'js-dropzone',
    'js-jquery', 'js-jquery-datatables', 'js-highlightjs'
);
foreach ($assetKeys as $assetKey) {
    afs_test_contains(
        $assetBuilder,
        "'" . $assetKey . "' =>",
        'typed asset manifest requires ' . $assetKey
    );
}
afs_test_contains(
    $assetBuilder,
    'count( $manifest ) !== count( $types )',
    'typed asset manifest rejects missing or extra key counts'
);
afs_test_contains(
    $assetBuilder,
    'array_diff_key( $manifest, $types )',
    'typed asset manifest rejects unreviewed keys'
);
afs_test_contains(
    $assetBuilder,
    "'type' => true, 'path' => true, 'sha256' => true,",
    'each asset row allowlists type, path, and digest fields'
);
afs_test_contains(
    $assetBuilder,
    "'license' => true, 'defer' => true",
    'each asset row allowlists license and defer fields'
);
afs_test_contains(
    $assetBuilder,
    "|| !isset( \$entry['type'], \$entry['path'], \$entry['sha256'],",
    'type, path, and SHA-256 are mandatory in every asset row'
);
afs_test_contains(
    $assetBuilder,
    "\$entry['license'], \$entry['defer'] )",
    'license and defer are mandatory in every asset row'
);
afs_test_contains(
    $assetBuilder,
    "|| !is_bool( \$entry['defer'] )",
    'defer metadata must be boolean for every asset row'
);
afs_test_contains(
    $assetBuilder,
    "\$expectedType === 'style' && \$entry['defer'] !== false",
    'style assets require literal false defer metadata'
);
afs_test_contains(
    $assetBuilder,
    "'MIT', 'BSD-3-Clause', 'Apache-2.0', 'OFL-1.1'",
    'asset licenses use the reviewed SPDX allowlist'
);
afs_test_contains(
    $assetBuilder,
    '<link rel="stylesheet" href="',
    'style tags are generated from canonical fields'
);
afs_test_contains(
    $assetBuilder,
    '<script src="',
    'script tags are generated from canonical fields'
);
afs_test_contains(
    $assetBuilder,
    "\$tags['pre-jsdelivr'] = '';",
    'AFS asset generation disables jsDelivr preconnect'
);
afs_test_contains(
    $assetBuilder,
    "\$tags['pre-cloudflare'] = '';",
    'AFS asset generation disables Cloudflare preconnect'
);

$assetValidator = afs_test_section(
    $readinessClass . "\n/* END AFS READINESS CLASS */\n",
    'public static function validateLocalAsset(',
    '/* END AFS READINESS CLASS */',
    'SHA-256 local-asset validator'
);
afs_test_contains(
    $assetValidator,
    "preg_match( '/^[a-f0-9]{64}$/', \$sha256 )",
    'asset digests must be exactly 64 lowercase hexadecimal characters'
);
afs_test_contains(
    $assetValidator,
    "@hash_file( 'sha256', \$candidate )",
    'asset validator hashes the resolved local file with SHA-256'
);
afs_test_contains(
    $assetValidator,
    "hash_equals( \$sha256, \$actual )",
    'asset validator compares the lowercase reviewed and actual digests exactly'
);
afs_test_contains(
    $assetValidator,
    "substr( \$reference, 0, 1 ) === '/'",
    'asset validator rejects absolute paths'
);
afs_test_contains(
    $assetValidator,
    "strpos( \$reference, '%' ) !== false",
    'asset validator rejects encoded path ambiguity'
);
afs_test_contains(
    $assetValidator,
    "\$segment === '.' || \$segment === '..'",
    'asset validator rejects dot-segment traversal'
);
afs_test_not_contains(
    $readinessClass,
    'function validateExternalResources',
    'obsolete raw-HTML external-resource validator is absent'
);

$manifestFileBuilder = afs_test_section(
    $readinessClass,
    'public static function buildLocalAssetTagsFromManifestFile(',
    'public static function validateLocalAsset(',
    'canonical JSON asset-manifest loader'
);
afs_test_contains(
    $manifestFileBuilder,
    '$manifestFile, $assetRoot, $manifestSha256, &$error=null',
    'manifest loader requires the reviewed digest as an explicit argument'
);
afs_test_contains(
    $manifestFileBuilder,
    "preg_match( '/^[a-f0-9]{64}$/', \$manifestSha256 )",
    'manifest loader accepts only a lowercase 64-hex expected digest'
);
afs_test_contains(
    $manifestFileBuilder,
    "hash_equals( \$manifestSha256, hash( 'sha256', \$raw ))",
    'manifest loader hashes the exact raw artifact bytes'
);
afs_test_contains(
    $manifestFileBuilder,
    'json_decode( $raw, true )',
    'asset manifest is decoded from JSON'
);
$manifestReadPos = strpos(
    $manifestFileBuilder,
    '$raw = @file_get_contents( $resolved );'
);
$manifestDigestPos = strpos(
    $manifestFileBuilder,
    "hash_equals( \$manifestSha256, hash( 'sha256', \$raw ))"
);
$manifestDecodePos = strpos($manifestFileBuilder, 'json_decode( $raw, true )');
afs_test_ok(
    $manifestReadPos !== false && $manifestDigestPos !== false
        && $manifestDecodePos !== false
        && $manifestReadPos < $manifestDigestPos
        && $manifestDigestPos < $manifestDecodePos,
    'raw manifest bytes are verified before any JSON parsing'
);
afs_test_contains(
    $manifestFileBuilder,
    'count( $decoded ) !== 2',
    'asset manifest rejects extra or missing top-level fields'
);
afs_test_contains(
    $manifestFileBuilder,
    "!array_key_exists( 'version', \$decoded )",
    'asset manifest requires its version field'
);
afs_test_contains(
    $manifestFileBuilder,
    "!array_key_exists( 'assets', \$decoded )",
    'asset manifest requires its assets object'
);
afs_test_contains(
    $manifestFileBuilder,
    "\$decoded['version'] !== 1",
    'asset manifest accepts only schema version 1'
);
afs_test_contains(
    $manifestFileBuilder,
    "\$decoded['assets'], \$root, \$error",
    'only decoded JSON assets reach the typed tag builder'
);

$productionGates = afs_test_section(
    $manager,
    "\$afsReadinessError = '';",
    '// --- EDIT BELOW CAREFULLY OR DO NOT EDIT AT ALL ---',
    'AFS asset and CSP startup gates'
);
afs_test_contains(
    $productionGates,
    'AfsProductionReadiness::buildLocalAssetTagsFromManifestFile(',
    'AFS startup builds tags from one canonical JSON manifest file'
);
afs_test_contains(
    $productionGates,
    "\$afs_asset_manifest_file, \$external_asset_root,\n"
        . "        \$afs_asset_manifest_sha256, \$afsReadinessError",
    'AFS startup passes filename, root, and reviewed digest to the loader'
);
afs_test_contains(
    $manager,
    "\$afs_asset_manifest_file = '';",
    'single JSON manifest filename defaults fail-closed before config.php'
);
afs_test_contains(
    $manager,
    "\$afs_asset_manifest_sha256 = '';",
    'reviewed JSON manifest digest defaults fail-closed before config.php'
);
$manifestFileDefaultPos = strpos($manager, "\$afs_asset_manifest_file = '';");
$manifestDigestDefaultPos = strpos(
    $manager,
    "\$afs_asset_manifest_sha256 = '';"
);
afs_test_ok(
    $manifestFileDefaultPos !== false && $manifestDigestDefaultPos !== false
        && $configPos !== false
        && $manifestFileDefaultPos < $configPos
        && $manifestDigestDefaultPos < $configPos,
    'manifest filename and digest are both fixed before config overrides'
);
afs_test_not_contains(
    $manager,
    '$afs_asset_manifest = array();',
    'AFS startup has no independently mutable PHP manifest array'
);
afs_test_contains(
    $productionGates,
    '} elseif (is_array($external_resources) && !empty($external_resources)) {',
    'raw external-resource HTML overrides are confined to non-AFS mode'
);
afs_test_contains(
    $productionGates,
    'AfsProductionReadiness::validateLocalAsset(',
    'configured AFS favicon uses the typed local-file validator'
);
afs_test_contains(
    $productionGates,
    '$favicon_path, $external_asset_root, $favicon_sha256,',
    'configured AFS favicon requires its reviewed SHA-256 digest'
);

// The strict local-only policy is the target, but current inline templates
// deliberately keep production AFS startup unavailable.
$strictCspConstant = afs_test_section(
    $readinessClass,
    'const LOCAL_ONLY_CONTENT_SECURITY_POLICY',
    'public static function applicationTemplatesSupportStrictCsp',
    'strict CSP template'
);
$expectedStrictCsp = "default-src 'none'; base-uri 'none'; "
    . "connect-src 'self'; font-src 'self'; form-action 'self'; "
    . "frame-ancestors 'none'; frame-src 'none'; img-src 'self' data:; "
    . "media-src 'self'; object-src 'none'; script-src 'self'; "
    . "style-src 'self'; worker-src 'self'";
$cspLiteralMatches = array();
$cspLiteral = '';
if (preg_match_all(
        '/"((?:[^"\\\\]|\\\\.)*)"/s',
        $strictCspConstant,
        $cspLiteralMatches
    )) {
    foreach ($cspLiteralMatches[1] as $cspLiteralPart) {
        $cspLiteral .= stripcslashes($cspLiteralPart);
    }
}
afs_test_ok(
    $cspLiteral === $expectedStrictCsp,
    'strict CSP constant exactly matches the canonical 13-directive policy'
);
$strictCspFragments = explode('; ', $expectedStrictCsp);
afs_test_ok(
    count($strictCspFragments) === 13,
    'canonical strict CSP contains exactly 13 directives'
);
foreach ($strictCspFragments as $fragment) {
    afs_test_contains(
        $strictCspConstant,
        $fragment,
        'strict CSP template contains ' . $fragment
    );
}
afs_test_not_contains(
    $strictCspConstant,
    "'unsafe-inline'",
    'strict CSP template does not permit inline execution'
);
afs_test_not_contains(
    $strictCspConstant,
    "'unsafe-eval'",
    'strict CSP template does not permit evaluated code'
);

$cspValidator = afs_test_section(
    $readinessClass,
    'public static function validateContentSecurityPolicy',
    'protected static function validateLocalCspSources',
    'strict CSP validator'
);
afs_test_contains(
    $cspValidator,
    '$policy !== self::LOCAL_ONLY_CONTENT_SECURITY_POLICY',
    'CSP validation requires exact equality with the canonical policy'
);
$requiredCspDirectives = array(
    'default-src', 'base-uri', 'connect-src', 'font-src', 'form-action',
    'frame-ancestors', 'frame-src', 'img-src', 'media-src', 'object-src',
    'script-src', 'style-src', 'worker-src'
);
foreach ($requiredCspDirectives as $requiredCspDirective) {
    afs_test_contains(
        $cspValidator,
        "'" . $requiredCspDirective . "'",
        'strict CSP validator requires ' . $requiredCspDirective
    );
}

$templateCapability = afs_test_section(
    $readinessClass,
    'public static function applicationTemplatesSupportStrictCsp',
    'public static function validateContentSecurityPolicy',
    'strict-CSP template capability'
);
afs_test_contains(
    $templateCapability,
    'return false;',
    'current inline templates explicitly report strict-CSP incompatibility'
);
afs_test_contains(
    $productionGates,
    '$content_security_policy_approved !== true',
    'AFS CSP requires a literal true review approval'
);
afs_test_contains(
    $productionGates,
    'AfsProductionReadiness::applicationTemplatesSupportStrictCsp()',
    'AFS startup checks strict-CSP template capability'
);
afs_test_contains(
    $productionGates,
    '!== true)',
    'strict-CSP template capability accepts only literal true'
);
$templateGatePos = strpos(
    $productionGates,
    'AfsProductionReadiness::applicationTemplatesSupportStrictCsp()'
);
$templateFailurePos = strpos(
    $productionGates,
    'AFS production mode requires nonce/hash CSP template support.'
);
afs_test_ok(
    $templateGatePos !== false && $templateFailurePos !== false
        && $templateGatePos < $templateFailurePos,
    'strict-template readiness failure terminates AFS startup'
);

// AFS URLs never derive protected links from Host. Logout is a token-verified
// POST action both in the dispatcher and in its only navigation control.
$urlContract = afs_test_section(
    $manager,
    '// abs path for site. AFS mode uses a same-origin relative controller URL',
    '// logout',
    'AFS controller URL contract'
);
afs_test_contains(
    $profileState,
    "\$afsSelfUrl = isset(\$_SERVER['SCRIPT_NAME'])",
    'AFS profile snapshots its controller URL from the local script path'
);
afs_test_contains(
    $urlContract,
    "substr(\$afsSelfUrl, 0, 1) !== '/'",
    'AFS controller URL must be origin-relative'
);
afs_test_contains(
    $urlContract,
    "if (defined('FM_ROOT_URL') && FM_ROOT_URL !== '')",
    'AFS startup rejects a pre-defined raw root URL'
);
afs_test_contains(
    $urlContract,
    "defined('FM_ROOT_URL') || define('FM_ROOT_URL', '');",
    'AFS mode defines no raw managed-root URL'
);
afs_test_contains(
    $urlContract,
    "defined('FM_SELF_URL') || define('FM_SELF_URL', \$afsSelfUrl);",
    'AFS mode uses the validated relative controller URL'
);
$urlElsePos = strpos($urlContract, '} else {');
$hostUrlPos = strpos($urlContract, '$http_host');
afs_test_ok(
    $urlElsePos !== false && $hostUrlPos !== false && $urlElsePos < $hostUrlPos,
    'Host-derived absolute URLs remain confined to non-AFS mode'
);

$logoutRoute = afs_test_section(
    $manager,
    '// logout',
    '// Validate connection IP',
    'logout route'
);
afs_test_contains(
    $logoutRoute,
    "if (isset(\$_POST['logout']))",
    'logout completion is POST-only'
);
afs_test_not_contains(
    $logoutRoute,
    "\$_GET['logout']",
    'logout route has no GET mutation'
);
afs_test_contains(
    $logoutRoute,
    "verifyToken(\$_POST['token'])",
    'logout requires the CSRF token'
);
$logoutVerifyPos = strpos($logoutRoute, "verifyToken(\$_POST['token'])");
$logoutUnsetPos = strpos(
    $logoutRoute,
    "unset(\$_SESSION[FM_SESSION_ID]['logged'])"
);
afs_test_ok(
    $logoutVerifyPos !== false && $logoutUnsetPos !== false
        && $logoutVerifyPos < $logoutUnsetPos,
    'logout verifies the token before clearing authentication state'
);
$navigationTemplate = afs_test_section(
    $manager,
    'function fm_show_nav_path($path)',
    'function fm_show_message()',
    'navigation template'
);
afs_test_contains(
    $navigationTemplate,
    '<form method="post" action="<?php echo fm_enc(FM_SELF_URL) ?>"',
    'logout control submits to the same-origin controller by POST'
);
afs_test_contains(
    $navigationTemplate,
    '<input type="hidden" name="token"',
    'logout form submits the CSRF token'
);
afs_test_contains(
    $navigationTemplate,
    '<button type="submit" name="logout" value="1"',
    'logout form has a POST submit control instead of a link'
);

// Preserve the upstream request-token checks around every route that already
// had one. The legacy single-item GET copy route is intentionally audited in
// afs_io_path_audit.php instead of being misrepresented as CSRF-protected.
$ajax = afs_test_section($manager, '// Handle all AJAX Request', '// Delete file / folder', 'AJAX dispatcher');
afs_test_contains($ajax, "isset(\$_POST['ajax'], \$_POST['token'])", 'AJAX dispatcher requires a token field');
$ajaxVerify = strpos($ajax, "verifyToken(\$_POST['token'])");
$ajaxSearch = strpos($ajax, '//search');
afs_test_ok(
    $ajaxVerify !== false && $ajaxSearch !== false && $ajaxVerify < $ajaxSearch,
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

// Every AFS path, metadata, content, MIME, and mutation helper must delegate
// to the provider without accepting loose truthy success values.
$resolveExisting = afs_test_section(
    $manager,
    'function fm_resolve_existing_path(',
    'function fm_resolve_write_path(',
    'existing-path provider wrapper'
);
afs_test_contains(
    $resolveExisting,
    '$provider->resolveExistingPath($path, $type)',
    'existing-path resolution delegates to the provider'
);
afs_test_contains(
    $resolveExisting,
    "return is_string(\$resolved) && \$resolved !== '' ? \$resolved : false;",
    'existing-path resolution accepts only a nonempty provider string'
);

$resolveWrite = afs_test_section(
    $manager,
    'function fm_resolve_write_path(',
    'function fm_inspect_path(',
    'write-path provider wrapper'
);
afs_test_contains(
    $resolveWrite,
    '$provider->resolveWritePath($path, $allowExisting)',
    'write-path resolution delegates to the provider'
);
afs_test_contains(
    $resolveWrite,
    "return is_string(\$resolved) && \$resolved !== '' ? \$resolved : false;",
    'write-path resolution accepts only a nonempty provider string'
);

$inspectPath = afs_test_section(
    $manager,
    'function fm_inspect_path(',
    'function fm_path_exists(',
    'metadata provider wrapper'
);
afs_test_contains(
    $inspectPath,
    '$provider->inspectPath($path, $allowLinkObject)',
    'AFS metadata inspection delegates to the provider'
);
afs_test_contains(
    $inspectPath,
    "\$info['path'], \$info['type'], \$info['size'],",
    'provider metadata requires path, type, size, timestamp, and mode'
);
afs_test_contains(
    $inspectPath,
    "in_array(\$info['type'], array('file', 'dir', 'link'), true)",
    'provider metadata type uses a strict allowlist'
);
afs_test_contains(
    $inspectPath,
    "|| !is_string(\$info['link_target'])",
    'provider link metadata requires a string target'
);

$readContents = afs_test_section(
    $manager,
    'function fm_read_file_contents(',
    'function fm_write_file_contents(',
    'content-read provider wrapper'
);
afs_test_contains(
    $readContents,
    '$provider->readContents($path)',
    'AFS content reads delegate to the provider'
);
afs_test_contains(
    $readContents,
    'return is_string($contents) ? $contents : false;',
    'AFS content reads reject non-string provider results'
);

$mimeType = afs_test_section(
    $manager,
    'function fm_get_mime_type(',
    'function fm_redirect(',
    'MIME provider wrapper'
);
afs_test_contains(
    $mimeType,
    '$provider->detectMimeType($file_path)',
    'AFS MIME detection delegates to the provider'
);
afs_test_contains(
    $mimeType,
    "? \$mime : 'application/octet-stream';",
    'invalid provider MIME output fails to the binary-safe default'
);

$strictMutationFunctions = array(
    array(
        'write-file', 'function fm_write_file_contents(',
        'function fm_create_file(', '->writeFile('
    ),
    array(
        'create-file', 'function fm_create_file(',
        'function fm_import_file(', '->createFile('
    ),
    array(
        'import-file', 'function fm_import_file(',
        'function fm_afs_archives_supported(', '->importFile('
    ),
    array(
        'delete', 'function fm_rdelete(',
        'function fm_rchmod(', '->removePath('
    ),
    array(
        'recursive-copy', 'function fm_rcopy(',
        'function fm_mkdir(', '->copyPath('
    ),
    array(
        'make-directory', 'function fm_mkdir(',
        'function fm_copy(', '->makeDirectory('
    ),
    array(
        'single-copy', 'function fm_copy(',
        'function fm_get_mime_type(', '->copyPath('
    )
);
foreach ($strictMutationFunctions as $mutationContract) {
    $mutationSection = afs_test_section(
        $manager,
        $mutationContract[1],
        $mutationContract[2],
        $mutationContract[0] . ' provider wrapper'
    );
    afs_test_contains(
        $mutationSection,
        $mutationContract[3],
        $mutationContract[0] . ' delegates mutation to the provider'
    );
    afs_test_contains(
        $mutationSection,
        '=== true',
        $mutationContract[0] . ' accepts only literal true provider success'
    );
}

$renameWrapper = afs_test_section(
    $manager,
    'function fm_rename(',
    'function fm_rcopy(',
    'rename provider wrapper'
);
afs_test_contains(
    $renameWrapper,
    '$result = $provider->renamePath($old, $new);',
    'rename delegates mutation to the provider'
);
afs_test_contains(
    $renameWrapper,
    'return $result === true ? true : ($result === null ? null : false);',
    'rename preserves only literal true, null collision, or false failure'
);
afs_test_contains(
    $manager,
    '$stored = fm_rename($partPath, $fullPathTarget) === true;',
    'chunk finalization requires literal true rename success'
);
afs_test_ok(
    strpos($manager, 'new Afs(') === false,
    'active Tiny File Manager routes never bypass the configured provider with new Afs'
);

// AFS production rejects URL-upload egress before URL parsing, temporary-file
// creation, or network I/O. Non-AFS mode retains the upstream validation and
// the fork's proxy path behind that early feature gate.
$urlUpload = afs_test_section($manager, '//upload using url', "    exit();\n}", 'URL-upload route');
afs_test_contains(
    $urlUpload,
    '$urlUploadRequested = isset($_POST[\'type\'])',
    'URL-upload request detection starts from the POST action'
);
afs_test_contains(
    $urlUpload,
    "\$_POST['type'] === 'upload'",
    'URL-upload request detection requires the upload action'
);
afs_test_contains(
    $urlUpload,
    "array_key_exists('uploadurl', \$_REQUEST)",
    'URL-upload request detection requires the URL field'
);
afs_test_contains(
    $urlUpload,
    'if ($urlUploadRequested && FM_URL_UPLOAD_ENABLED !== true)',
    'disabled URL upload is rejected for every detected request'
);
afs_test_contains(
    $urlUpload,
    "header('HTTP/1.1 403 Forbidden');",
    'disabled URL upload returns HTTP 403'
);
afs_test_contains(
    $urlUpload,
    "'message' => 'URL upload is disabled'",
    'disabled URL upload returns an explicit failure response'
);
$urlUploadGatePos = strpos(
    $urlUpload,
    'if ($urlUploadRequested && FM_URL_UPLOAD_ENABLED !== true)'
);
$urlUploadDenyExitPos = $urlUploadGatePos === false ? false
    : strpos($urlUpload, 'exit();', $urlUploadGatePos);
$urlUploadParsePos = strpos($urlUpload, 'parse_url($url, PHP_URL_HOST)');
$urlUploadTempPos = strpos($urlUpload, 'tempnam(sys_get_temp_dir(), "upload-")');
$urlUploadCopyPos = strpos($urlUpload, 'copy($url, $temp_file, $ctx)');
afs_test_ok(
    $urlUploadGatePos !== false && $urlUploadDenyExitPos !== false
        && $urlUploadParsePos !== false && $urlUploadTempPos !== false
        && $urlUploadCopyPos !== false
        && $urlUploadGatePos < $urlUploadDenyExitPos
        && $urlUploadDenyExitPos < $urlUploadParsePos
        && $urlUploadDenyExitPos < $urlUploadTempPos
        && $urlUploadDenyExitPos < $urlUploadCopyPos,
    'URL-upload denial exits before parse_url, tempnam, and network copy'
);
afs_test_contains($urlUpload, 'preg_match("|^http(s)?://.+$|"', 'URL upload accepts only HTTP(S)-shaped URLs');
afs_test_contains($urlUpload, 'parse_url($url, PHP_URL_HOST)', 'URL upload parses the destination host');
afs_test_contains($urlUpload, 'parse_url($url, PHP_URL_PORT)', 'URL upload parses the destination port');
afs_test_contains($urlUpload, '^localhost$', 'URL upload rejects localhost');
afs_test_contains($urlUpload, '^127', 'URL upload rejects IPv4 loopback');
afs_test_contains($urlUpload, '0*1$', 'URL upload rejects IPv6 loopback');
afs_test_contains($urlUpload, '$knownPorts = [22, 23, 25, 3306];', 'URL upload preserves the blocked-port baseline');
afs_test_contains($urlUpload, 'basename($fileinfo->name)', 'URL-upload destination is reduced to a basename');
afs_test_contains($urlUpload, "strtok(get_file_path(), '?')", 'URL-upload destination strips a query suffix');
afs_test_contains($urlUpload, "'proxy' => 'tcp://' . \$proxyServer", 'non-cURL URL upload preserves configured proxy support');
afs_test_contains($urlUpload, "'request_fulluri' => true", 'proxy requests retain absolute request URIs');

$uploadPage = afs_test_section(
    $manager,
    '// upload form',
    '// file viewer',
    'upload page and client script'
);
$urlUploadUiGuard = '<?php if (FM_URL_UPLOAD_ENABLED === true): ?>';
$urlUploadTabPos = strpos($uploadPage, 'href="#urlUploader"');
$urlUploadTabGuardPos = strpos($uploadPage, $urlUploadUiGuard);
$urlUploadTabEndPos = $urlUploadTabPos === false ? false
    : strpos($uploadPage, '<?php endif; ?>', $urlUploadTabPos);
$urlUploadFormGuardPos = $urlUploadTabEndPos === false ? false
    : strpos($uploadPage, $urlUploadUiGuard, $urlUploadTabEndPos);
$urlUploadFormPos = strpos($uploadPage, 'id="js-form-url-upload"');
$urlUploadFormEndPos = $urlUploadFormPos === false ? false
    : strpos($uploadPage, '<?php endif; ?>', $urlUploadFormPos);
afs_test_ok(
    substr_count($uploadPage, $urlUploadUiGuard) === 2
        && $urlUploadTabGuardPos !== false && $urlUploadTabPos !== false
        && $urlUploadTabEndPos !== false
        && $urlUploadTabGuardPos < $urlUploadTabPos
        && $urlUploadTabPos < $urlUploadTabEndPos
        && $urlUploadFormGuardPos !== false && $urlUploadFormPos !== false
        && $urlUploadFormEndPos !== false
        && $urlUploadFormGuardPos < $urlUploadFormPos
        && $urlUploadFormPos < $urlUploadFormEndPos,
    'URL-upload tab and form are both omitted unless explicitly enabled'
);

$urlUploadClient = afs_test_section(
    $manager,
    "            <?php if (FM_URL_UPLOAD_ENABLED === true): ?>\n"
        . '            // Upload files using URL @param {Object}',
    '            // Search template',
    'footer URL-upload client script'
);
$urlUploadScriptGuardPos = strpos($urlUploadClient, $urlUploadUiGuard);
$urlUploadScriptPos = strpos(
    $urlUploadClient,
    'function upload_from_url($this)'
);
$urlUploadScriptEndPos = $urlUploadScriptPos === false ? false
    : strpos($urlUploadClient, '<?php endif; ?>', $urlUploadScriptPos);
afs_test_ok(
    substr_count($urlUploadClient, $urlUploadUiGuard) === 1
        && $urlUploadScriptGuardPos !== false && $urlUploadScriptPos !== false
        && $urlUploadScriptEndPos !== false
        && $urlUploadScriptGuardPos < $urlUploadScriptPos
        && $urlUploadScriptPos < $urlUploadScriptEndPos,
    'URL-upload JavaScript is omitted unless explicitly enabled'
);

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
$readBeforeChange = strpos($aclSubmit, 'fm_read_afs_acl($aclPath)');
$changeCall = strpos($aclSubmit, 'fm_change_afs_acl_entries(');
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

$directNegativeCall = preg_match('/(?:changeAclEntries|fm_change_afs_acl_entries)\s*\([^;]*,\s*true\s*\)/s', $aclSubmit) === 1;
$modeMap = $mappedAclSets;
$variableNegativeCall = preg_match('/(?:changeAclEntries|fm_change_afs_acl_entries)\s*\([^;]*,\s*\$[A-Za-z_][A-Za-z0-9_]*\s*\)/s', $aclSubmit) === 1;
afs_test_ok(
    $directNegativeCall || ($modeMap && $variableNegativeCall),
    'negative ACL writes pass true to changeAcl negative mode'
);
afs_test_contains($aclSubmit, '$aclBatches', 'ACL entries are batched by positive/negative set');

$aclUi = afs_test_section($manager, '// Edit AFS ACLs', '// --- TINYFILEMANAGER MAIN ---', 'AFS ACL editor');
afs_test_contains($aclUi, 'fm_read_afs_acl($file_path)', 'ACL editor reads the current AFS ACL');
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

// ACL reads, writes, and display access must use typed wrappers around the
// configured provider.
afs_test_contains(
    $aclSubmit,
    'fm_read_afs_acl($aclPath)',
    'ACL mutation route re-reads through the typed provider wrapper'
);
afs_test_contains(
    $aclSubmit,
    'fm_change_afs_acl_entries(',
    'ACL mutation route writes through the strict provider wrapper'
);
afs_test_contains(
    $aclSubmit,
    '$aclBatches[$setName], $aclPath, $negative)',
    'ACL mutation passes the mapped positive/negative mode to its wrapper'
);
afs_test_contains(
    $aclUi,
    'fm_read_afs_acl($file_path)',
    'ACL editor reads through the typed provider wrapper'
);

$aclReadWrapper = afs_test_section(
    $manager,
    'function fm_read_afs_acl(',
    'function fm_change_afs_acl_entries(',
    'ACL-read provider wrapper'
);
afs_test_contains(
    $aclReadWrapper,
    '$provider->readAcl($path)',
    'ACL-read wrapper delegates to the configured provider'
);
afs_test_contains(
    $aclReadWrapper,
    "isset(\$acl['normal'], \$acl['negative'])",
    'ACL-read wrapper requires normal and negative result sets'
);
afs_test_contains(
    $aclReadWrapper,
    "is_array(\$acl['normal']) && is_array(\$acl['negative'])",
    'ACL-read wrapper validates both result-set types'
);

$aclWriteWrapper = afs_test_section(
    $manager,
    'function fm_change_afs_acl_entries(',
    'function fm_get_afs_acl_access(',
    'ACL-write provider wrapper'
);
afs_test_contains(
    $aclWriteWrapper,
    '$provider->changeAclEntries(',
    'ACL-write wrapper delegates to the configured provider'
);
afs_test_contains(
    $aclWriteWrapper,
    '$entries, $path, $negative) === true;',
    'ACL-write wrapper accepts only literal true provider success'
);

$aclAccessWrapper = afs_test_section(
    $manager,
    'function fm_get_afs_acl_access(',
    'function fm_resolve_existing_path(',
    'caller-access provider wrapper'
);
afs_test_contains(
    $aclAccessWrapper,
    '$provider->getACLAccess($path)',
    'caller-access wrapper delegates to the configured provider'
);
afs_test_contains(
    $aclAccessWrapper,
    "preg_match('/^[lrwidkaA-H]{0,15}$/', \$rights)",
    'caller-access wrapper validates all standard and auxiliary rights'
);

$mainListing = afs_test_section(
    $manager,
    "/*************************** ACTIONS ***************************/\n\n// get current path",
    '// upload form',
    'main AFS listing'
);
afs_test_contains(
    $mainListing,
    '$path = fm_resolve_existing_path($path, \'dir\');',
    'main listing resolves its directory through the provider wrapper'
);
afs_test_contains(
    $mainListing,
    '$objects = fm_afs_provider()->listDirectory($path);',
    'AFS listing obtains names from the provider'
);
afs_test_contains(
    $mainListing,
    '$info = fm_inspect_path($new_path, true);',
    'AFS listing obtains typed metadata through the provider wrapper'
);
afs_test_contains(
    $mainListing,
    '$objectInfo[$file] = $info;',
    'AFS listing retains provider metadata for rendering'
);

$fileViewer = afs_test_section(
    $manager,
    '// file viewer',
    '// file editor',
    'file-viewer route'
);
$fileEditor = afs_test_section(
    $manager,
    '// file editor',
    '// chmod (not for Windows or AFS)',
    'file-editor route'
);
foreach (array(
    'viewer' => $fileViewer,
    'editor' => $fileEditor
) as $surface => $surfaceSource) {
    afs_test_contains(
        $surfaceSource,
        'fm_inspect_path($file_path)',
        $surface . ' obtains metadata through the provider wrapper'
    );
    afs_test_contains(
        $surfaceSource,
        'fm_get_mime_type($file_path)',
        $surface . ' obtains MIME through the provider wrapper'
    );
    afs_test_contains(
        $surfaceSource,
        'fm_read_file_contents($file_path)',
        $surface . ' reads text through the provider wrapper'
    );
}

// Online viewers, raw media/Open URLs, and generic archive code remain
// unreachable whenever AFS support is active.
afs_test_contains(
    $manager,
    '$online_viewer = false;',
    'AFS mode disables the configured online-viewer variable after config.php'
);
afs_test_contains(
    $manager,
    "if (\$afsSupport && defined('FM_DOC_VIEWER') && FM_DOC_VIEWER !== false)",
    'AFS startup rejects a pre-defined non-false online-viewer constant'
);
afs_test_contains(
    $fileViewer,
    'if (!$afsSupport && $is_onlineViewer)',
    'online viewer rendering is guarded out of AFS mode'
);
afs_test_contains(
    $fileViewer,
    '<?php if (!$afsSupport && FM_DIRECT_LINKS_ENABLED): ?>',
    'raw Open action requires non-AFS mode and enabled direct links'
);
afs_test_contains(
    $fileViewer,
    'if (!$afsSupport && FM_RAW_PREVIEWS_ENABLED && $is_image)',
    'raw image inspection requires non-AFS mode and enabled previews'
);
afs_test_contains(
    $fileViewer,
    '} elseif (!$afsSupport && FM_RAW_PREVIEWS_ENABLED && $is_image) {',
    'raw image rendering requires non-AFS mode and enabled previews'
);
afs_test_contains(
    $fileViewer,
    '} elseif (!$afsSupport && FM_RAW_PREVIEWS_ENABLED && $is_audio) {',
    'raw audio rendering requires non-AFS mode and enabled previews'
);
afs_test_contains(
    $fileViewer,
    '} elseif (!$afsSupport && FM_RAW_PREVIEWS_ENABLED && $is_video) {',
    'raw video rendering requires non-AFS mode and enabled previews'
);
afs_test_contains(
    $fileViewer,
    '} elseif (!$afsSupport && ($ext == \'zip\' || $ext == \'tar\')) {',
    'archive inspection is guarded out of AFS mode'
);

$archiveCapability = afs_test_section(
    $manager,
    'function fm_afs_archives_supported(',
    '/**' . "\n" . ' * Delete  file or folder',
    'archive capability gate'
);
afs_test_contains(
    $archiveCapability,
    'return !fm_is_afs_mode();',
    'generic archive support is unconditionally disabled in AFS mode'
);
afs_test_not_contains(
    $manager,
    '->archivesSupported(',
    'a provider capability cannot re-enable generic archive walkers'
);
$archiveCreate = $csrfSections['archive create'];
$archiveExtract = $csrfSections['archive extract'];
$archiveCreateGuard = strpos($archiveCreate, 'if (!fm_afs_archives_supported())');
$archiveCreateMutation = strpos($archiveCreate, 'new FM_Zipper()');
$archiveExtractGuard = strpos($archiveExtract, 'if (!fm_afs_archives_supported())');
$archiveExtractMutation = strpos($archiveExtract, 'new FM_Zipper()');
afs_test_ok(
    $archiveCreateGuard !== false && $archiveCreateMutation !== false
        && $archiveCreateGuard < $archiveCreateMutation,
    'archive-create rejection precedes generic archive construction'
);
afs_test_ok(
    $archiveExtractGuard !== false && $archiveExtractMutation !== false
        && $archiveExtractGuard < $archiveExtractMutation,
    'archive-extract rejection precedes generic extraction construction'
);
afs_test_contains(
    $manager,
    '<?php if (fm_afs_archives_supported()): ?>',
    'bulk archive controls are hidden when AFS disables archives'
);

// Constructing an Afs object used to shell out once, after which each listing
// row called getcalleraccess again. Keep exactly one subprocess per item.
$constructor = afs_test_section($afs, 'public function __construct', 'public function getType', 'Afs constructor');
afs_test_ok(
    substr_count($constructor, 'getACLAccess(') === 0,
    'Afs construction does not perform an implicit getcalleraccess query'
);

$folderListing = afs_test_section($manager, '$ii = 3399;', '$ik = 8002;', 'folder-listing loop');
$fileListing = afs_test_section($manager, '$ik = 8002;', 'if (empty($folders) && empty($files))', 'file-listing loop');
afs_test_ok(substr_count($folderListing, 'fm_get_afs_acl_access(') === 1, 'each folder row has one explicit getcalleraccess wrapper call');
afs_test_ok(substr_count($fileListing, 'fm_get_afs_acl_access(') === 1, 'each file row has one explicit getcalleraccess wrapper call');
afs_test_ok(substr_count($manager, 'fm_get_afs_acl_access(') === 3, 'Tiny File Manager has one wrapper definition and only two per-row callers');

afs_test_contains(
    $fileViewer,
    "\$file_url = \$afsSupport\n        ? FM_SELF_URL",
    'AFS viewer builds its action URL from the relative controller'
);
afs_test_contains(
    $fileEditor,
    "\$file_url = \$afsSupport\n        ? FM_SELF_URL",
    'AFS editor builds its save URL from the relative controller'
);
afs_test_contains(
    $folderListing,
    '<?php if ($afsSupport && FM_DIRECT_LINKS_ENABLED): ?>',
    'AFS folder DirectLink is gated by the production-disabled flag'
);
afs_test_contains(
    $folderListing,
    'href="?p=<?php echo urlencode(trim(FM_PATH . \'/\' . $f, \'/\')) ?>"',
    'any explicitly enabled AFS folder DirectLink remains PHP-mediated navigation'
);
afs_test_contains(
    $fileListing,
    '<?php if ($afsSupport && !$is_link && FM_DIRECT_LINKS_ENABLED): ?>',
    'AFS file DirectLink is gated by the production-disabled flag'
);
afs_test_contains(
    $fileListing,
    '&amp;view=<?php echo urlencode($f) ?>',
    'any explicitly enabled AFS file DirectLink remains a PHP-mediated view'
);
afs_test_contains(
    $fileListing,
    'if (!$afsSupport && FM_RAW_PREVIEWS_ENABLED && in_array(',
    'raw hover-image URLs require non-AFS mode and enabled previews'
);

echo "SUMMARY: " . $afsTestPasses . " passed, " . count($afsTestFailures) . " failed\n";
if (!empty($afsTestFailures)) {
    exit(1);
}

exit(0);
