<?php

declare(strict_types=1);

require __DIR__ . '/../bootstrap.php';

require_once __DIR__ . '/../../src/services/FileManager.php';
require_once __DIR__ . '/../../src/handlers/DeleteHandler.php';
require_once __DIR__ . '/../../src/handlers/RenameHandler.php';
require_once __DIR__ . '/../../src/handlers/UploadHandler.php';
require_once __DIR__ . '/../../src/Router.php';

if (!function_exists('fm_clean_path')) {
    function fm_clean_path($path, $trim = true)
    {
        $path = str_replace('\\', '/', (string) $path);
        $path = preg_replace('#/+#', '/', $path);
        return $trim ? trim($path, '/') : $path;
    }
}

if (!function_exists('fm_isvalid_filename')) {
    function fm_isvalid_filename($text)
    {
        return $text !== '' && !preg_match('#[\\/\x00-\x1F]#', $text);
    }
}

$format = 'text';
foreach ($argv as $argument) {
    if (str_starts_with($argument, '--format=')) {
        $format = substr($argument, 9);
    }
}

$benchmarkRoot = TEMP_DIR . '/benchmark';
if (!is_dir($benchmarkRoot)) {
    mkdir($benchmarkRoot, 0755, true);
}

$logger = new class {
    public function log($level, $message, $context = []): void
    {
    }
};

$fileManager = new TFM_FileManager($benchmarkRoot, $logger);

$targets = [
    'router_initialization_ms' => 20.0,
    'list_100_files_ms' => 50.0,
    'list_1000_files_ms' => 200.0,
    'delete_file_ms' => 10.0,
    'csrf_validation_ms' => 1.0,
];

function measure(callable $callback, int $iterations = 1): float
{
    $total = 0.0;
    for ($index = 0; $index < $iterations; $index++) {
        $start = hrtime(true);
        $callback();
        $total += (hrtime(true) - $start) / 1000000;
    }

    return $total / $iterations;
}

function prepareFiles(string $directory, int $count): void
{
    if (!is_dir($directory)) {
        mkdir($directory, 0755, true);
    }

    for ($index = 1; $index <= $count; $index++) {
        $path = $directory . '/file_' . $index . '.txt';
        if (!is_file($path)) {
            file_put_contents($path, 'benchmark-' . $index);
        }
    }
}

prepareFiles($benchmarkRoot . '/list100', 100);
prepareFiles($benchmarkRoot . '/list1000', 1000);
file_put_contents($benchmarkRoot . '/delete_me.txt', 'delete');

$results = [];

$results['router_initialization_ms'] = measure(function () use ($benchmarkRoot, $logger): void {
    $_SERVER['REQUEST_METHOD'] = 'GET';
    $_GET['action'] = 'list';
    $_GET['p'] = '';
    new TFM_Router($benchmarkRoot, $logger);
}, 20);

$results['list_100_files_ms'] = measure(function () use ($fileManager): void {
    $fileManager->setPath('list100');
    $fileManager->listDirectory();
}, 10);

$results['list_1000_files_ms'] = measure(function () use ($fileManager): void {
    $fileManager->setPath('list1000');
    $fileManager->listDirectory();
}, 5);

$results['delete_file_ms'] = measure(function () use ($benchmarkRoot, $logger): void {
    $deletePath = $benchmarkRoot . '/delete_me.txt';
    file_put_contents($deletePath, 'delete');
    $handler = new TFM_DeleteHandler($benchmarkRoot, $logger);
    $handler->delete('', 'delete_me.txt');
}, 10);

$token = tfm_get_token();
$results['csrf_validation_ms'] = measure(function () use ($token): void {
    tfm_verify_token($token);
}, 500);

$failures = [];
foreach ($targets as $metric => $target) {
    if ($results[$metric] > $target) {
        $failures[] = sprintf('%s %.2fms exceeds target %.2fms', $metric, $results[$metric], $target);
    }
}

if ($format === 'github') {
    echo "| Metric | Result | Target | Status |\n";
    echo "| --- | ---: | ---: | --- |\n";
    foreach ($targets as $metric => $target) {
        $status = $results[$metric] <= $target ? 'PASS' : 'FAIL';
        echo sprintf("| %s | %.2f ms | %.2f ms | %s |\n", $metric, $results[$metric], $target, $status);
    }
} else {
    foreach ($targets as $metric => $target) {
        $status = $results[$metric] <= $target ? 'PASS' : 'FAIL';
        echo sprintf("%-28s %8.2f ms  target %-8.2f %s\n", $metric, $results[$metric], $target, $status);
    }
}

if ($failures !== []) {
    fwrite(STDERR, implode(PHP_EOL, $failures) . PHP_EOL);
    exit(1);
}