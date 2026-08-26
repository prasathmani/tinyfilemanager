#!/usr/bin/env php
<?php

$root = dirname(__DIR__);
$manager = @file_get_contents($root . '/tinyfilemanager.php');
$manifestPath = $root . '/assets/SHA256SUMS';
$manifest = @file_get_contents($manifestPath);
if ($manager === false || $manifest === false) {
    fwrite(STDERR, "FAIL: unable to read pilot source inputs\n");
    exit(2);
}

$checks = 0;
function pilot_check($condition, $message)
{
    global $checks;
    $checks++;
    if (!$condition) {
        fwrite(STDERR, "not ok $checks - $message\n");
        exit(1);
    }
    echo "ok $checks - $message\n";
}

pilot_check(strpos($manager, "define('FM_ENABLE_SEARCH', false);") !== false,
    'search is fixed off before deployment configuration');
pilot_check(strpos($manager, "define('FM_ENABLE_ARCHIVE_OPERATIONS', false);") !== false,
    'archive routes are fixed off before deployment configuration');
pilot_check(strpos($manager, "define('FM_ALLOW_INLINE_PREVIEW', false);") !== false,
    'active preview is fixed off before deployment configuration');

foreach (array('uploadurl', 'upload_from_url', 'curl_exec(', 'copy($url', 'set_time_limit(') as $forbidden) {
    pilot_check(strpos($manager, $forbidden) === false,
        "server-side network or execution feature is absent: $forbidden");
}

pilot_check(strpos($manager, '$_POST[\'type\'] == "search"') === false,
    'server-side recursive search route is absent');
pilot_check(strpos($manager, 'advanced-search') === false
    && strpos($manager, 'fm_search') === false
    && strpos($manager, 'js-search-modal') === false,
    'recursive search UI and client are absent');
pilot_check(substr_count($manager, 'if (FM_ENABLE_ARCHIVE_OPERATIONS') >= 2,
    'archive create and extract routes require the fixed-false gate');
pilot_check(strpos($manager, '<?php if (FM_ENABLE_ARCHIVE_OPERATIONS): ?>') !== false,
    'archive controls require the fixed-false gate');

pilot_check(strpos($manager, 'if (!FM_ALLOW_INLINE_PREVIEW && isset($_GET[\'view\']))') !== false,
    'legacy view requests use the attachment-only path');
pilot_check(strpos($manager, 'if (FM_ALLOW_INLINE_PREVIEW && isset($_GET[\'view\']))') !== false,
    'active viewer is unreachable behind the fixed-false gate');
pilot_check(strpos($manager, 'data-preview-image') === false,
    'hover preview client hooks are absent');
pilot_check(strpos($manager, '<iframe') === false,
    'remote document iframe markup is absent');
pilot_check(strpos($manager, '&amp;edit=<?php echo urlencode($f) ?>') !== false
    && strpos($manager, '&amp;env=ace') === false,
    'ordinary edit remains reachable without the active Ace editor link');

pilot_check(strpos($manager, "header('Content-Type: application/octet-stream');") !== false,
    'all application-mediated streams use a non-active content type');
pilot_check(strpos($manager, 'Content-Disposition: attachment;') !== false
    && strpos($manager, 'Content-Disposition: $contentDisposition') === false,
    'all application-mediated streams are attachments');
pilot_check(strpos($manager, "header('X-Content-Type-Options: nosniff');") !== false,
    'attachment streams forbid content sniffing');

$remoteMarkup = '/<(?:script|link|iframe)[^>]+(?:src|href)=["\'][[:space:]]*https?:\/\//i';
pilot_check(preg_match($remoteMarkup, $manager) !== 1,
    'HTML source contains no remote script stylesheet or iframe resource');
pilot_check(preg_match('/rel=["\'](?:preconnect|dns-prefetch)["\']/i', $manager) !== 1,
    'HTML source contains no connection hints');
pilot_check(strpos($manager, "'css-bootstrap' => '<link href=\"' . \$asset_base_url") !== false
    && strpos($manager, "'js-jquery' => '<script src=\"' . \$asset_base_url") !== false,
    'browser dependencies resolve through the local configurable asset base');

foreach (array(
    '// Delete file / folder',
    '// Create a new file/folder',
    '// Copy folder / file',
    '// Mass copy files/ folders',
    '// Rename',
    '// Download',
    '// Upload',
    '// Mass deleting',
) as $routeMarker) {
    pilot_check(strpos($manager, $routeMarker) !== false,
        "required file operation remains present: $routeMarker");
}

$expectedAssets = array(
    'assets/THIRD_PARTY_LICENSES.css',
    'assets/css/bootstrap.min.css',
    'assets/css/dropzone.min.css',
    'assets/css/font-awesome.min.css',
    'assets/fonts/fontawesome-webfont.woff2',
    'assets/js/bootstrap.bundle.min.js',
    'assets/js/dropzone.min.js',
    'assets/js/jquery.dataTables.min.js',
    'assets/js/jquery.min.js',
);
$manifestAssets = array();
foreach (preg_split('/\r?\n/', trim($manifest)) as $line) {
    if (!preg_match('/^([0-9a-f]{64})  (assets\/[A-Za-z0-9._\/-]+)$/', $line, $match)) {
        fwrite(STDERR, "FAIL: malformed browser asset manifest line\n");
        exit(1);
    }
    $path = $match[2];
    pilot_check(is_file($root . '/' . $path) && !is_link($root . '/' . $path),
        "manifested browser asset is a regular file: $path");
    pilot_check(hash_file('sha256', $root . '/' . $path) === $match[1],
        "manifested browser asset hash matches: $path");
    $manifestAssets[] = $path;
}
sort($manifestAssets, SORT_STRING);
sort($expectedAssets, SORT_STRING);
pilot_check($manifestAssets === $expectedAssets,
    'asset manifest covers the exact vendored browser closure');

$fontCss = file_get_contents($root . '/assets/css/font-awesome.min.css');
pilot_check(substr_count($fontCss, 'url(') === 1
    && strpos($fontCss, '../fonts/fontawesome-webfont.woff2') !== false,
    'Font Awesome references only the vendored WOFF2 font');

$licenses = file_get_contents($root . '/assets/THIRD_PARTY_LICENSES.css');
foreach (array('Bootstrap 5.3.3', 'jQuery 3.6.1', 'Dropzone 5.9.3',
    'DataTables 1.13.1', 'Font Awesome 4.7.0', 'SIL OPEN FONT LICENSE') as $notice) {
    pilot_check(strpos($licenses, $notice) !== false,
        "third-party license closure includes $notice");
}

echo "PASS: $checks pilot feature-gate checks\n";
