<?php
/**
 * Test Suite Bootstrap
 * 
 * Sets up the test environment and autoloads necessary files.
 */

// Define test constants
define('TEST_ROOT_PATH', __DIR__);
define('TEST_FILES_PATH', __DIR__ . '/fixtures');
define('TEMP_DIR', sys_get_temp_dir() . '/tinyfilemanager_tests');

// Create temp directory if it doesn't exist
if (!is_dir(TEMP_DIR)) {
    mkdir(TEMP_DIR, 0755, true);
}

// Autoload Composer dependencies when available.
$composerAutoload = __DIR__ . '/../vendor/autoload.php';
if (is_readable($composerAutoload)) {
    require $composerAutoload;
}

// Mock WordPress-style constants if they don't exist
if (!defined('__FILE__')) {
    define('__FILE__', '');
}

if (!function_exists('realpath_safe')) {
    /**
     * Safe realpath wrapper for testing
     */
    function realpath_safe($path) {
        return realpath($path) ?: $path;
    }
}

// Bootstrap the application (loads security.php and helpers)
require __DIR__ . '/../src/bootstrap.php';

// Helper function for test data
function create_test_file($path, $content = '') {
    $dir = dirname($path);
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
    file_put_contents($path, $content);
    return $path;
}

// Helper to clean up test files
function cleanup_test_files() {
    if (is_dir(TEMP_DIR)) {
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator(TEMP_DIR, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($files as $file) {
            if ($file->isDir()) {
                @rmdir($file->getRealPath());
            } else {
                @unlink($file->getRealPath());
            }
        }
    }
}

// Register cleanup
register_shutdown_function('cleanup_test_files');

echo "Test bootstrap loaded successfully.\n";
echo "Test root: " . TEST_ROOT_PATH . "\n";
echo "Temp dir: " . TEMP_DIR . "\n";
