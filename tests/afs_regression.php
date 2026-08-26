<?php

require_once dirname(__DIR__) . '/afs.php';

final class AfsTestDouble extends Afs
{
    public $commands = array();
    public $responses = array();

    public function __construct()
    {
        // Offline tests intentionally bypass the live /afs constructor probe.
    }

    protected function pathSecurity($path = '')
    {
        return $path === '' ? false : rtrim($path, '/');
    }

    protected function runFs($arguments)
    {
        $this->commands[] = $arguments;
        $this->lastFsStatus = 0;
        return empty($this->responses) ? '' : array_shift($this->responses);
    }
}

final class AfsFilesystemDouble extends Afs
{
    public function __construct()
    {
        // configureFilesystem() supplies an offline device model.
    }

    public function configureFilesystem($device, $startCwd)
    {
        $this->afsAvailable = true;
        $this->afsStat = array('dev' => $device);
        $this->startCWD = $startCwd;
    }

    public function setTestPath($path)
    {
        $this->path = $path;
    }

    public function copyItemForTest($source, $target)
    {
        return $this->copyItem($source, $target);
    }

    public function configureCopyRequest($originPath, $destinationPath, $selectedItems)
    {
        $this->originPath = $originPath;
        $this->path = $destinationPath;
        $this->selectedItems = $selectedItems;
    }
}

final class AfsDataPlaneTestDouble extends AfsDataPlane
{
    private $testVolumeMounts = array();

    public function __construct()
    {
        // configureDataPlane() supplies an offline AFS model.
    }

    public function configureDataPlane($root, $startCwd)
    {
        $stat = stat($root);
        $this->afsAvailable = true;
        $this->afsStat = array('dev' => $stat['dev']);
        $this->startCWD = $startCwd;
        return $this->initializeDataPlane($root);
    }

    public function addVolumeMount($path, $target)
    {
        $this->testVolumeMounts[$path] = $target;
        unset($this->volumeMountCache[$path]);
    }

    public function addKernelMount($path)
    {
        $this->kernelMountPoints[$path] = true;
    }

    protected function loadKernelMountPoints()
    {
        return array();
    }

    protected function probeAfsIdentity($path, $nofollow = false, $fresh = false)
    {
        if (!is_array(@lstat($path))) {
            return false;
        }
        $volume = '100';
        foreach ($this->testVolumeMounts as $mountPath => $target) {
            if ($path === $mountPath || strpos($path, $mountPath . '/') === 0) {
                $volume = '200';
            }
        }
        return array('fid' => $volume . '.1.1', 'volume' => $volume);
    }

    protected function probeAfsVolumeMountPoint($path)
    {
        return array_key_exists($path, $this->testVolumeMounts)
            ? $this->testVolumeMounts[$path] : false;
    }
}

final class AfsDataPlaneProbeDouble extends AfsDataPlane
{
    private $testResponses = array();

    public function __construct()
    {
        // Probe parser tests do not need a live constructor.
    }

    public function queueResponse($status, $output)
    {
        $this->testResponses[] = array($status, $output);
    }

    public function probeMountForTest($path)
    {
        return $this->probeAfsVolumeMountPoint($path);
    }

    public function probeIdentityForTest($path, $nofollow = false)
    {
        return $this->probeAfsIdentity($path, $nofollow, true);
    }

    protected function runFs($arguments)
    {
        if (empty($this->testResponses)) {
            $this->lastFsStatus = 127;
            return false;
        }
        list($this->lastFsStatus, $output) = array_shift($this->testResponses);
        return $output;
    }
}

$tests = 0;

function check($condition, $message)
{
    global $tests;
    $tests++;
    if (!$condition) {
        fwrite(STDERR, "not ok $tests - $message\n");
        exit(1);
    }
    echo "ok $tests - $message\n";
}

function remove_test_tree($path)
{
    if (is_link($path) || is_file($path)
        || (file_exists($path) && !is_dir($path))) {
        @unlink($path);
        return;
    }
    if (!is_dir($path)) {
        return;
    }
    foreach (scandir($path) as $entry) {
        if ($entry !== '.' && $entry !== '..') {
            remove_test_tree($path . '/' . $entry);
        }
    }
    @rmdir($path);
}

$aclOutput = "Access list for /afs/example is\n"
    . "Normal rights:\n"
    . "  system:anyuser rl\n"
    . "  alice rlidwkaABCDEFGH\n"
    . "  auxiliary AD\n"
    . "Negative rights:\n"
    . "  blocked lkAH\n";

$afs = new AfsTestDouble();
check($afs->get_returnToURI() === '',
    'legacy AFS return URI fails closed until FM_SELF_URL is defined');
$afs->path = '/afs/example.test/users/alice/My Folder';
$afs->sid = 'fixed-session-id';
$_SERVER['HTTP_HOST'] = 'attacker.example';
$_SERVER['PHP_SELF'] = '//attacker.example/redirect';
define('FM_SELF_URL', '/tinyfilemanager.php');
check(
    $afs->get_returnToURI()
        === '/tinyfilemanager.php?path=%2Fafs%2Fexample.test%2Fusers%2Falice%2FMy+Folder'
            . '&finishid=fixed-session-id',
    'legacy AFS return URI uses FM_SELF_URL instead of request host or script data'
);
$acl = $afs->parseAclOutput($aclOutput);
check($acl['inherited'] === false, 'marks a normal ACL as explicit');
check(isset($acl['normal']['alice']), 'parses a normal ACL principal');
check($acl['normal']['alice']['l'] && $acl['normal']['alice']['r']
    && $acl['normal']['alice']['w'] && $acl['normal']['alice']['i']
    && $acl['normal']['alice']['d'] && $acl['normal']['alice']['k']
    && $acl['normal']['alice']['a'] && $acl['normal']['alice']['A']
    && $acl['normal']['alice']['B'] && $acl['normal']['alice']['C']
    && $acl['normal']['alice']['D'] && $acl['normal']['alice']['E']
    && $acl['normal']['alice']['F'] && $acl['normal']['alice']['G']
    && $acl['normal']['alice']['H'],
    'parses seven standard and eight AuriStor auxiliary rights');
check($acl['normal']['system:anyuser']['l']
    && $acl['normal']['system:anyuser']['r']
    && !$acl['normal']['system:anyuser']['w'], 'tracks unset normal rights');
check($acl['negative']['blocked']['l'] && $acl['negative']['blocked']['k']
    && $acl['negative']['blocked']['A'] && $acl['negative']['blocked']['H']
    && !$acl['negative']['blocked']['a'], 'parses negative ACL rights');
check($acl['normal']['auxiliary']['A'] && $acl['normal']['auxiliary']['D']
    && $acl['normal']['auxiliary']['a'] === false
    && $acl['normal']['auxiliary']['d'] === false,
    'auxiliary rights remain case-distinct from admin and delete');

$inheritedOutput = str_replace('Access list for', 'Access list (inherited) for', $aclOutput);
$inheritedAcl = $afs->parseAclOutput($inheritedOutput);
check($inheritedAcl['inherited'] === true,
    'detects an inherited AuriStor ACL without materializing it');
check($afs->parseAclOutput("unexpected output\n") === false,
    'rejects listacl output without the expected headers');
$unknownRightOutput = str_replace('system:anyuser rl', 'system:anyuser rlZ', $aclOutput);
check($afs->parseAclOutput($unknownRightOutput) === false,
    'rejects an unknown ACL right instead of dropping it');

$maxAclFixture = file_get_contents(
    __DIR__ . '/fixtures/auristor-listacl-with-volume-acl.txt');
check($maxAclFixture !== false, 'loads the AuriStor Volume ACL fixture');
check($afs->parseAclOutput($maxAclFixture) === false,
    'fails closed instead of merging a Volume ACL into the object ACL');
$inheritedMaxAclFixture = preg_replace(
    '/^Access list for /', 'Access list (inherited) for ', $maxAclFixture);
check($afs->parseAclOutput($inheritedMaxAclFixture) === false,
    'fails closed when an inherited object ACL is followed by a Volume ACL');
check($afs->parseAclOutput($aclOutput . $aclOutput) === false,
    'rejects a second object ACL header in one parser invocation');
$repeatedNormal = str_replace(
    "Negative rights:\n", "Normal rights:\n", $aclOutput);
check($afs->parseAclOutput($repeatedNormal) === false,
    'rejects a repeated Normal rights section');
$repeatedNegative = $aclOutput . "Negative rights:\n  another r\n";
check($afs->parseAclOutput($repeatedNegative) === false,
    'rejects a repeated Negative rights section');

$nestedAclPost = array();
parse_str(
    'normal[user%40cell.example][l]=1&normal[user%20name][r]=1',
    $nestedAclPost);
check(isset($nestedAclPost['normal']['user@cell.example']['l']),
    'PHP preserves a dot in a nested ACL principal key');
check(isset($nestedAclPost['normal']['user name']['r']),
    'PHP preserves a space in a nested ACL principal key');

$afs->responses[] = $aclOutput;
$readAcl = $afs->readAcl('/afs/example');
check($readAcl === $acl, 'readAcl returns the parsed ACL structure');
check($afs->commands[0] === array('listacl', '/afs/example'),
    'readAcl invokes fs listacl with an argument vector');

$afs->responses[] = $maxAclFixture;
check($afs->readAcl('/afs/example') === false
    && strpos($afs->errorMsg, 'Unable to parse') !== false,
    'readAcl reports a fail-closed Volume ACL parse result');

$afs->responses[] = "fs: permission denied\n";
check($afs->readAcl('/afs/example') === false,
    'readAcl rejects fs-reported failures');

$afs->responses[] = "Callers access to /afs/example is rlidwkaABCDEFGH\n";
check($afs->getACLAccess('/afs/example') === 'rlidwkaABCDEFGH',
    'getcalleraccess preserves standard and auxiliary right case');
check($afs->lookupPriv === 1 && $afs->readPriv === 1
    && $afs->writePriv === 1 && $afs->insertPriv === 1
    && $afs->deletePriv === 1 && $afs->lockPriv === 1
    && $afs->adminPriv === 1, 'getcalleraccess maps all privilege flags');

$afs->responses[] = "unexpected output\n";
check($afs->getACLAccess('/afs/example') === '',
    'malformed getcalleraccess output fails closed');
check($afs->lookupPriv === 0 && $afs->readPriv === 0
    && $afs->writePriv === 0 && $afs->insertPriv === 0
    && $afs->deletePriv === 0 && $afs->lockPriv === 0
    && $afs->adminPriv === 0, 'failed parsing clears stale privilege flags');

$afs->responses[] = '';
check($afs->changeAcl('user;touch /tmp/not-run', 'rl', '/afs/a path') === true,
    'normal ACL changes accept shell-sensitive names as data');
check($afs->commands[count($afs->commands) - 1]
    === array('sa', '/afs/a path', 'user;touch /tmp/not-run', 'rl'),
    'normal ACL command remains a structured argument vector');

$afs->responses[] = '';
check($afs->changeAcl('blocked', 'lkAH', '/afs/example', false, true) === true,
    'negative ACL changes are supported');
check($afs->commands[count($afs->commands) - 1]
    === array('sa', '-negative', '/afs/example', 'blocked', 'lkAH'),
    'negative ACL command uses the explicit -negative argument');
check($afs->changeAcl('alice', 'rl;bad', '/afs/example') === false,
    'invalid ACL rights fail before invoking fs');

$afs->responses[] = '';
check($afs->changeAclEntries(
    array('alice' => 'rl', 'system:anyuser' => 'l'), '/afs/example') === true,
    'multiple ACL entries are changed in one batch');
check($afs->commands[count($afs->commands) - 1]
    === array('sa', '/afs/example', 'alice', 'rl', 'system:anyuser', 'l'),
    'batched ACL entries share one fs setacl invocation');

$probe = new AfsDataPlaneProbeDouble();
$probe->queueResponse(
    0, "'/afs/example/child' is a mount point for volume '#child.volume'");
check($probe->probeMountForTest('/afs/example/child') === '#child.volume',
    'checked fs lsmount output identifies an AFS volume mount point');
$probe->queueResponse(
    1, "'/afs/example/ordinary' is not a mount point.");
check($probe->probeMountForTest('/afs/example/ordinary') === false,
    'checked fs lsmount error status identifies an ordinary directory');
$probe->queueResponse(1, 'fs: permission denied');
check($probe->probeMountForTest('/afs/example/unknown') === null,
    'an unrecognized lsmount failure remains fail-closed');
$probe->queueResponse(
    0, 'File /afs/example/file (536870918.20404.20997) contained in volume 536870918');
$identity = $probe->probeIdentityForTest('/afs/example/file');
check($identity === array(
        'fid' => '536870918.20404.20997',
        'volume' => '536870918'),
    'checked fs getfid output records the resolved AFS identity');
$probe->queueResponse(1, 'fs: path is not in AFS');
check($probe->probeIdentityForTest('/tmp/not-afs') === false,
    'failed fs getfid classification rejects a non-AFS path');

$tempRoot = sys_get_temp_dir() . '/tinyfm-afs-test-' . bin2hex(random_bytes(8));
check(mkdir($tempRoot, 0700), 'creates an isolated test directory');
$originalCwd = getcwd();

try {
    $inside = $tempRoot . '/inside';
    check(mkdir($inside, 0700), 'creates an in-device path');
    $device = stat($inside)['dev'];
    $fsAfs = new AfsFilesystemDouble();
    $fsAfs->configureFilesystem($device, $originalCwd);

    check($fsAfs->makePathAFSlocal($inside) === true,
        'same-device directory passes the final chdir/stat guard');
    chdir($originalCwd);
    check($fsAfs->setPath($inside) === true && $fsAfs->path === $inside,
        'setPath accepts a same-device path');

    $fsAfs->configureFilesystem($device + 1, $originalCwd);
    check($fsAfs->makePathAFSlocal($inside) === false,
        'different-device directory fails the final guard');
    check(getcwd() === $originalCwd, 'failed device guard restores the cwd');
    check($fsAfs->setPath($inside) === false && $fsAfs->path === '',
        'setPath rejects a different-device path');

    $source = $tempRoot . '/source.bin';
    $destination = $tempRoot . '/destination.bin';
    $payload = "\x00AFS\n" . random_bytes(2048);
    file_put_contents($source, $payload);
    $fsAfs->configureFilesystem($device, $originalCwd);
    check($fsAfs->copy($source, $destination) === true,
        'handle-checked copy succeeds on the modeled AFS device');
    check(file_get_contents($destination) === $payload,
        'handle-checked copy preserves binary content');
    check($fsAfs->copy($source, $destination) === false,
        'handle-checked copy refuses to overwrite an existing destination');

    $outsideDestination = $tempRoot . '/wrong-device.bin';
    $fsAfs->configureFilesystem($device + 1, $originalCwd);
    check($fsAfs->copy($source, $outsideDestination) === false
        && !file_exists($outsideDestination),
        'source handle device mismatch creates no destination');

    $fsAfs->configureFilesystem($device, $originalCwd);
    $fsAfs->setTestPath($source);
    ob_start();
    $readResult = $fsAfs->readfile();
    $readPayload = ob_get_clean();
    check($readResult === true && $readPayload === $payload,
        'handle-checked read emits exact binary content');

    if (function_exists('symlink')) {
        $broken = $tempRoot . '/broken-link';
        @symlink('missing-target', $broken);
        check($fsAfs->linkSafeFileExists($broken) === true,
            'lstat recognizes a broken symlink without following it');

        $outside = $tempRoot . '/outside';
        $treeSource = $tempRoot . '/tree-source';
        $treeTarget = $tempRoot . '/tree-target';
        check(mkdir($outside, 0700) && mkdir($treeSource, 0700),
            'creates isolated source and outside directories');
        check(stat($outside)['dev'] === $device,
            'outside symlink target is on the modeled AFS device');
        file_put_contents($outside . '/sentinel.txt', 'outside-data');
        check(symlink($outside, $treeSource . '/outside-link'),
            'creates a directory symlink to an outside same-device tree');
        check($fsAfs->copy_dirs($treeSource, $treeTarget) === true,
            'recursive copy completes with a nested directory symlink');
        check(is_link($treeTarget . '/outside-link')
            && readlink($treeTarget . '/outside-link') === $outside,
            'recursive copy reproduces the directory symlink without traversing it');
        check(file_get_contents($outside . '/sentinel.txt') === 'outside-data',
            'recursive copy leaves the outside sentinel unchanged');

        $directTarget = $tempRoot . '/direct-symlink-target';
        check($fsAfs->copy_dirs($treeSource . '/outside-link', $directTarget) === false
            && !file_exists($directTarget) && !is_link($directTarget),
            'copy_dirs rejects a directory symlink passed as its top-level source');

        $copiedTopLink = $tempRoot . '/copied-top-link';
        check($fsAfs->copyItemForTest(
            $treeSource . '/outside-link', $copiedTopLink) === true
            && is_link($copiedTopLink)
            && readlink($copiedTopLink) === $outside,
            'copy dispatcher handles a top-level directory symlink as a link');

        $copiedBroken = $tempRoot . '/copied-broken-link';
        check($fsAfs->copyItemForTest($broken, $copiedBroken) === true
            && is_link($copiedBroken)
            && readlink($copiedBroken) === 'missing-target',
            'copy dispatcher preserves a broken symlink');

        $requestTarget = $tempRoot . '/copy-request-target';
        check(mkdir($requestTarget, 0700),
            'creates a destination for the copyFiles request path');
        $fsAfs->configureCopyRequest(
            $treeSource, $requestTarget, 'outside-link');
        check($fsAfs->copyFiles() === true
            && is_link($requestTarget . '/outside-link')
            && readlink($requestTarget . '/outside-link') === $outside,
            'copyFiles dispatches a directory symlink without traversing it');
    }

    if (function_exists('posix_mkfifo')) {
        $fifo = $tempRoot . '/source.fifo';
        $fifoTarget = $tempRoot . '/copied.fifo';
        check(posix_mkfifo($fifo, 0600), 'creates an unsupported special file');
        check($fsAfs->copyItemForTest($fifo, $fifoTarget) === false
            && !file_exists($fifoTarget),
            'copy dispatcher fails closed for unsupported special files');
    }

    $guardRoot = $tempRoot . '/guard-root';
    $guardOutside = $tempRoot . '/guard-outside';
    check(mkdir($guardRoot, 0700) && mkdir($guardOutside, 0700),
        'creates rooted and outside trees for the data-plane facade');
    file_put_contents($guardOutside . '/sentinel.txt', 'outside-sentinel');

    $dataPlane = new AfsDataPlaneTestDouble();
    check($dataPlane->configureDataPlane($guardRoot, $originalCwd) === true,
        'initializes the offline pathname-policy AFS data-plane preview');
    check($dataPlane instanceof AfsDataPlaneProvider,
        'pathname preview implements the reusable provider contract');
    check($dataPlane->isProductionReady() === false
        && $dataPlane->getSecurityBoundary() === 'pathname-preview',
        'pathname preview cannot satisfy the production descriptor boundary');
    check(AfsDataPlaneProvider::SECURITY_BOUNDARY_DESCRIPTOR_BENEATH_V1
        === 'descriptor-beneath-v1',
        'provider contract names the required descriptor-beneath boundary');
    check($dataPlane->getDataRoot() === realpath($guardRoot),
        'pins the data-plane boundary to the resolved configured root');
    check($dataPlane->resolveExistingPath($guardOutside) === false,
        'rejects an existing path outside the configured root');
    check($dataPlane->resolveExistingPath(
        $guardRoot . '/../guard-outside/sentinel.txt') === false,
        'rejects dot-segment traversal before filesystem access');

    if (function_exists('symlink')) {
        $leafLink = $guardRoot . '/outside-file-link';
        $parentLink = $guardRoot . '/outside-dir-link';
        check(symlink($guardOutside . '/sentinel.txt', $leafLink)
            && symlink($guardOutside, $parentLink),
            'creates final and intermediate POSIX symlink escape fixtures');
        check($dataPlane->resolveExistingPath($leafLink) === false,
            'rejects a final POSIX symlink instead of following it');
        check($dataPlane->resolveExistingPath(
            $parentLink . '/sentinel.txt') === false,
            'rejects an intermediate POSIX symlink instead of following it');
        check($dataPlane->writeFile($leafLink, 'changed') === false
            && file_get_contents($guardOutside . '/sentinel.txt')
                === 'outside-sentinel',
            'guarded writes leave a same-device outside symlink target unchanged');
        $listed = $dataPlane->listDirectory($guardRoot);
        $linkInfo = $dataPlane->inspectPath($leafLink, true);
        check(is_array($listed) && in_array('outside-file-link', $listed, true)
            && is_array($linkInfo) && $linkInfo['type'] === 'link'
            && $linkInfo['link_target'] === $guardOutside . '/sentinel.txt',
            'listing exposes a final symlink only as no-follow object metadata');
        $renamedLink = $guardRoot . '/renamed-outside-file-link';
        check($dataPlane->renamePath($leafLink, $renamedLink) === true
            && is_link($renamedLink)
            && file_get_contents($guardOutside . '/sentinel.txt')
                === 'outside-sentinel',
            'rename moves a verified symlink object without traversing it');
        check($dataPlane->removePath($renamedLink) === true
            && !is_link($renamedLink)
            && file_get_contents($guardOutside . '/sentinel.txt')
                === 'outside-sentinel',
            'delete unlinks a verified symlink object without touching its target');

        $linkTree = $guardRoot . '/link-tree';
        check(mkdir($linkTree, 0700)
            && symlink($guardOutside, $linkTree . '/outside-link'),
            'creates a recursive-delete tree containing an outside symlink');
        check($dataPlane->removePath($linkTree) === true
            && !file_exists($linkTree)
            && file_get_contents($guardOutside . '/sentinel.txt')
                === 'outside-sentinel',
            'recursive delete unlinks nested symlinks without following them');
    }

    $kernelMount = $guardRoot . '/kernel-mount';
    check(mkdir($kernelMount, 0700), 'creates a modeled nested kernel mount');
    $dataPlane->addKernelMount(realpath($kernelMount));
    check($dataPlane->resolveExistingPath($kernelMount) === false,
        'rejects a nested kernel mount without using st_dev as a volume model');

    $childVolume = $guardRoot . '/child-volume';
    check(mkdir($childVolume, 0700), 'creates a modeled child AFS volume root');
    $dataPlane->addVolumeMount(realpath($childVolume), '#child.volume');
    $childWork = $childVolume . '/work';
    check(mkdir($childWork, 0700), 'creates a working directory in the child volume');
    check($dataPlane->resolveExistingPath($childWork, 'dir')
        === realpath($childWork),
        'allows logical navigation beneath a classified child AFS volume');
    $crossed = $dataPlane->getCrossedVolumeMounts();
    check(isset($crossed[realpath($childVolume)])
        && $crossed[realpath($childVolume)]['target'] === '#child.volume',
        'records the crossed AFS volume target and resolved identity');

    $insideFile = $guardRoot . '/inside.txt';
    check($dataPlane->createFile($insideFile) === true,
        'exclusively creates a regular file inside the guarded root');
    check($dataPlane->createFile($insideFile) === false,
        'exclusive creation refuses an existing destination');
    $binary = "\x00guarded\n" . random_bytes(64);
    check($dataPlane->writeFile($insideFile, $binary) === true,
        'writes an existing confined file through a validated handle');
    check($dataPlane->readContents($insideFile) === $binary,
        'reads exact binary bytes through the same rooted facade');
    check(is_string($dataPlane->detectMimeType($insideFile))
        && $dataPlane->detectMimeType($insideFile) !== '',
        'MIME sampling is provider-owned and returns a checked string');

    $nestedDirectory = $guardRoot . '/new/path/tree';
    check($dataPlane->makeDirectory($nestedDirectory, true) === true
        && is_dir($nestedDirectory),
        'creates and post-validates each missing directory component');

    $importSource = $tempRoot . '/import-source.bin';
    $importTarget = $nestedDirectory . '/imported.bin';
    file_put_contents($importSource, 'first-');
    check($dataPlane->importFile(
        $importSource, $importTarget, false, false) === true,
        'imports a local upload-style payload into a guarded target');
    file_put_contents($importSource, 'second');
    check($dataPlane->importFile(
        $importSource, $importTarget, true, true) === true
        && file_get_contents($importTarget) === 'first-second',
        'appends a chunk payload through a post-validated AFS handle');

    $copyTarget = $guardRoot . '/inside-copy.txt';
    check($dataPlane->copyPath($insideFile, $copyTarget, false) === true
        && file_get_contents($copyTarget) === $binary,
        'copies a regular file without falling back to PHP copy');
    $renamedTarget = $guardRoot . '/inside-renamed.txt';
    check($dataPlane->renamePath($copyTarget, $renamedTarget) === true
        && !file_exists($copyTarget) && is_file($renamedTarget),
        'renames and post-validates a confined regular file');

    $childFile = $childWork . '/child.txt';
    file_put_contents($childFile, 'child-data');
    $childCopy = $childWork . '/child-copy.txt';
    check($dataPlane->copyPath($childFile, $childCopy, false) === true
        && file_get_contents($childCopy) === 'child-data',
        'permits an operation explicitly started inside a child AFS volume');
    check($dataPlane->removePath($childCopy) === true
        && !file_exists($childCopy),
        'permits deletion of a regular object inside a child AFS volume');

    $recursiveSource = $guardRoot . '/recursive-source';
    $recursiveMount = $recursiveSource . '/nested-volume';
    check(mkdir($recursiveSource, 0700)
        && mkdir($recursiveMount, 0700),
        'creates a recursive child-volume boundary fixture');
    file_put_contents($recursiveSource . '/ordinary.txt', 'ordinary');
    file_put_contents($recursiveMount . '/volume-sentinel.txt', 'volume-data');
    $dataPlane->addVolumeMount(realpath($recursiveMount), '#nested.volume');
    $recursiveTarget = $guardRoot . '/recursive-copy';
    check($dataPlane->copyPath(
        $recursiveSource, $recursiveTarget, false) === false
        && !file_exists($recursiveTarget),
        'recursive copy stops before entering a child AFS volume mount');
    check($dataPlane->removePath($recursiveSource) === false
        && file_get_contents($recursiveMount . '/volume-sentinel.txt')
            === 'volume-data',
        'recursive delete preflights and leaves a child-volume sentinel intact');

    $searchRootFile = $guardRoot . '/search-hit.txt';
    file_put_contents($searchRootFile, 'search');
    file_put_contents($childWork . '/search-hit-child.txt', 'search-child');
    $searchResults = $dataPlane->searchFiles($guardRoot, 'search-hit');
    check(is_array($searchResults) && count($searchResults) === 1
        && $searchResults[0]['name'] === 'search-hit.txt',
        'recursive search stays in its starting volume and stops at child mounts');

    check($dataPlane->archivesSupported() === false,
        'archive mutation is explicitly unavailable in guarded AFS mode');
    check(file_get_contents($guardOutside . '/sentinel.txt')
        === 'outside-sentinel',
        'all facade operations leave the outside escape sentinel unchanged');

    check($fsAfs->escape_js("a'b\\c\r\n") === "a\\'b\\\\c\\r\\n",
        'JavaScript escaping covers quote, slash, CR, and LF');

    $requiredMethods = array('copy', 'copy_dirs', 'deleteFiles', 'removeFolder',
        'readfile', 'changeAcl', 'readAcl', 'getACLAccess', 'makePathAFSlocal');
    $reflection = new ReflectionClass('Afs');
    foreach ($requiredMethods as $method) {
        check($reflection->hasMethod($method), "retains Afs::$method");
    }
    $dataReflection = new ReflectionClass('AfsDataPlane');
    foreach (array('initializeDataPlane', 'resolveExistingPath', 'inspectPath',
        'openRead', 'readContents', 'detectMimeType', 'writeFile', 'createFile',
        'importFile', 'makeDirectory', 'copyPath', 'renamePath', 'removePath',
        'listDirectory', 'searchFiles', 'readAcl', 'changeAclEntries',
        'getACLAccess', 'getSecurityBoundary')
        as $method) {
        check($dataReflection->hasMethod($method),
            "retains AfsDataPlane::$method");
    }
} finally {
    @chdir($originalCwd);
    remove_test_tree($tempRoot);
}

$urlUploadDisabledProfile = array(
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
$profileError = null;
check(AfsProductionReadiness::validateProductionProfile(
        $urlUploadDisabledProfile, $profileError) === true,
    'production profile accepts URL upload only when literally false');
$urlUploadEnabledProfile = $urlUploadDisabledProfile;
$urlUploadEnabledProfile['url_upload_enabled'] = true;
$profileError = null;
check(AfsProductionReadiness::validateProductionProfile(
        $urlUploadEnabledProfile, $profileError) === false
    && is_string($profileError)
    && strpos($profileError, 'url_upload_enabled') !== false,
    'production profile rejects enabled URL upload');

echo "1..$tests\n";
