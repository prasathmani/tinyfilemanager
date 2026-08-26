<?php

require_once dirname(__DIR__) . '/lib/fm_root_confinement.php';
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

final class AfsMountAvailabilityDouble extends Afs
{
    public function __construct()
    {
        // availabilityForTest() supplies a synthetic /afs stat result.
    }

    public function availabilityForTest($statAvailable)
    {
        $this->afsStat = $statAvailable ? array('dev' => 1) : false;
        return $this->afsMountIsAvailable();
    }
}

final class AfsNoShellDouble extends Afs
{
    public function __construct()
    {
        // The disabled-exec regression exercises the parent command runner.
    }

    protected function pathSecurity($path = '')
    {
        return $path === '' ? false : rtrim($path, '/');
    }

    public function lastFsStatusForTest()
    {
        return $this->lastFsStatus;
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

$namespaceRoot = "10 0 0:1 / / rw - overlay overlay rw\n";
$GLOBALS['FM_ROOT_GUARD_MOUNTINFO'] = $namespaceRoot
    . "11 10 0:2 / /afs rw - auristorfs none rw\n";
$availability = new AfsMountAvailabilityDouble();
check($availability->availabilityForTest(true) === true,
    'constructor availability accepts a statable auristorfs mount at /afs');
$GLOBALS['FM_ROOT_GUARD_MOUNTINFO'] = $namespaceRoot
    . "11 10 0:2 / /afs rw - afs none rw\n";
check($availability->availabilityForTest(true) === true,
    'constructor availability accepts a statable OpenAFS mount at /afs');
$GLOBALS['FM_ROOT_GUARD_MOUNTINFO'] = $namespaceRoot
    . "11 10 8:1 / /afs rw - ext4 /dev/root rw\n";
check($availability->availabilityForTest(true) === false,
    'constructor availability rejects an ordinary filesystem at /afs');
$GLOBALS['FM_ROOT_GUARD_MOUNTINFO'] = "malformed mountinfo\n";
check($availability->availabilityForTest(true) === false,
    'constructor availability fails closed for malformed mountinfo');
$GLOBALS['FM_ROOT_GUARD_MOUNTINFO'] = $namespaceRoot
    . "11 10 0:2 / /afs rw - auristorfs none rw\n";
check($availability->availabilityForTest(false) === false,
    'constructor availability still requires a successful /afs stat');
unset($GLOBALS['FM_ROOT_GUARD_MOUNTINFO']);

if (!function_exists('exec')) {
    $noShell = new AfsNoShellDouble();
    check($noShell->getACLAccess('/afs/example') === '',
        'getcalleraccess fails closed when exec is disabled');
    check($noShell->lastFsStatusForTest() === 126,
        'disabled exec records the unavailable-shell status');
    check($noShell->lookupPriv === 0 && $noShell->readPriv === 0
        && $noShell->writePriv === 0 && $noShell->insertPriv === 0
        && $noShell->deletePriv === 0 && $noShell->lockPriv === 0
        && $noShell->adminPriv === 0,
        'disabled exec grants no caller-access rights');
}

$aclOutput = "Access list for /afs/example is\n"
    . "Normal rights:\n"
    . "  system:anyuser rl\n"
    . "  alice rlidwkaABCDEFGH\n"
    . "  auxiliary AD\n"
    . "Negative rights:\n"
    . "  blocked lkAH\n";

$afs = new AfsTestDouble();
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

    check($fsAfs->escape_js("a'b\\c\r\n") === "a\\'b\\\\c\\r\\n",
        'JavaScript escaping covers quote, slash, CR, and LF');

    $requiredMethods = array('copy', 'copy_dirs', 'deleteFiles', 'removeFolder',
        'readfile', 'changeAcl', 'readAcl', 'getACLAccess', 'makePathAFSlocal');
    $reflection = new ReflectionClass('Afs');
    foreach ($requiredMethods as $method) {
        check($reflection->hasMethod($method), "retains Afs::$method");
    }
} finally {
    @chdir($originalCwd);
    remove_test_tree($tempRoot);
}

echo "1..$tests\n";
