<?php
/**
 * Test Utilities and Fixtures
 * 
 * Provides common test data, mock generators, and helper functions.
 */

namespace TFM\Tests;

use PHPUnit\Framework\TestCase;

class TestHelpers
{
    /**
     * Create test files with specific magic bytes
     */
    public static function createTestFile($filename, $magicBytes = '')
    {
        $path = TEMP_DIR . '/' . $filename;
        $dir = dirname($path);
        
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }
        
        if ($magicBytes) {
            file_put_contents($path, $magicBytes);
        } else {
            touch($path);
        }
        
        return $path;
    }

    /**
     * Magic bytes for various file types (common test cases)
     */
    public static function getMagicBytes($type)
    {
        $bytes = [
            'jpeg' => "\xFF\xD8\xFF\xE0",
            'png' => "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A",
            'gif' => "GIF89a",
            'pdf' => "%PDF-1.4",
            'zip' => "\x50\x4B\x03\x04",
            'php' => "<?php",
            'exe' => "MZ",
            'elf' => "\x7F\x45\x4C\x46",
        ];
        
        return $bytes[$type] ?? '';
    }

    /**
     * Create a fake spoofed file (PHP content with JPEG header)
     */
    public static function createSpoofedFile($filename, $webshellCode = '<?php phpinfo(); ?>')
    {
        $path = TEMP_DIR . '/' . $filename;
        $content = self::getMagicBytes('jpeg') . $webshellCode;
        file_put_contents($path, $content);
        return $path;
    }

    /**
     * Create large file for size testing
     */
    public static function createLargeFile($filename, $sizeInMB)
    {
        $path = TEMP_DIR . '/' . $filename;
        $handle = fopen($path, 'w');
        fwrite($handle, str_repeat('A', $sizeInMB * 1024 * 1024));
        fclose($handle);
        return $path;
    }

    /**
     * Create test directory structure
     */
    public static function createTestDirStructure()
    {
        $dirs = [
            'documents',
            'images',
            'images/thumbnails',
            'uploads',
            'uploads/temp',
            'private',
        ];
        
        foreach ($dirs as $dir) {
            $path = TEMP_DIR . '/' . $dir;
            if (!is_dir($path)) {
                mkdir($path, 0755, true);
            }
        }
    }

    /**
     * Get test file paths
     */
    public static function getTestFilePaths()
    {
        return [
            'valid_jpg' => TEMP_DIR . '/test.jpg',
            'valid_png' => TEMP_DIR . '/test.png',
            'valid_pdf' => TEMP_DIR . '/test.pdf',
            'spoofed_php' => TEMP_DIR . '/shell.php.jpg',
            'malicious_exe' => TEMP_DIR . '/malware.exe',
        ];
    }

    /**
     * Create test user data
     */
    public static function getTestUsers()
    {
        return [
            'admin' => [
                'password_hash' => password_hash('admin123', PASSWORD_BCRYPT),
                'role' => 'admin',
                'readonly' => false,
            ],
            'user1' => [
                'password_hash' => password_hash('user123', PASSWORD_BCRYPT),
                'role' => 'user',
                'readonly' => false,
            ],
            'viewer' => [
                'password_hash' => password_hash('viewer123', PASSWORD_BCRYPT),
                'role' => 'user',
                'readonly' => true,
            ],
        ];
    }

    /**
     * Get path traversal attack payloads
     */
    public static function getPathTraversalPayloads()
    {
        return [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            '....//....//....//etc/passwd',
            '..%2F..%2F..%2Fetc%2Fpasswd',
            '..%252F..%252Fetc%252Fpasswd',
            'files/../../../etc/passwd',
            '/var/www/html/../../../../../../etc/passwd',
            'null.jpg%00.php',
            'image.jpg\x00.php',
        ];
    }

    /**
     * Get dangerous MIME types
     */
    public static function getDangerousMimeTypes()
    {
        return [
            'application/x-php',
            'application/x-php3',
            'application/x-php4',
            'application/x-php5',
            'application/x-phtml',
            'application/x-httpd-php',
            'application/x-msdownload',
            'application/x-msdos-program',
            'application/x-executable',
            'application/x-elf-executable',
        ];
    }

    /**
     * Get safe MIME types
     */
    public static function getSafeMimeTypes()
    {
        return [
            'image/jpeg',
            'image/png',
            'image/gif',
            'application/pdf',
            'text/plain',
            'application/zip',
            'audio/mpeg',
        ];
    }

    /**
     * Create rate limiter test data
     */
    public static function createRateLimiterTestData()
    {
        return [
            'ip' => '192.168.1.100',
            'username' => 'testuser',
            'attempts' => [
                time() - 100,
                time() - 50,
                time() - 10,
                time(),
            ],
        ];
    }

    /**
     * Get test audit log entries
     */
    public static function getTestAuditLogs()
    {
        return [
            [
                'timestamp' => date('Y-m-d H:i:s'),
                'ip' => '192.168.1.1',
                'user' => 'admin',
                'action' => 'login',
                'details' => 'User logged in successfully',
            ],
            [
                'timestamp' => date('Y-m-d H:i:s'),
                'ip' => '192.168.1.1',
                'user' => 'admin',
                'action' => 'delete',
                'details' => 'Deleted file: oldfile.txt',
            ],
            [
                'timestamp' => date('Y-m-d H:i:s'),
                'ip' => '192.168.1.1',
                'user' => 'user1',
                'action' => 'upload',
                'details' => 'Uploaded file: document.pdf (2.5 MB)',
            ],
        ];
    }

    /**
     * Clean up all test files and directories
     */
    public static function cleanup()
    {
        if (is_dir(TEMP_DIR)) {
            $files = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator(TEMP_DIR, \RecursiveDirectoryIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::CHILD_FIRST
            );

            foreach ($files as $fileinfo) {
                $func = $fileinfo->isDir() ? 'rmdir' : 'unlink';
                @$func($fileinfo->getRealPath());
            }
        }
    }
}

/**
 * Base test case for all TinyFileManager tests
 */
abstract class BaseTestCase extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        TestHelpers::createTestDirStructure();
    }

    protected function tearDown(): void
    {
        TestHelpers::cleanup();
        parent::tearDown();
    }

    /**
     * Assert that a value is a valid JSON string
     */
    protected function assertValidJson(string $json, string $message = ''): void
    {
        json_decode($json);
        $this->assertSame(JSON_ERROR_NONE, json_last_error(), $message);
    }

    /**
     * Assert that a path is absolute and normalized
     */
    protected function assertAbsolutePath(string $path, string $message = ''): void
    {
        $this->assertStringStartsWith('/', $path, $message);
        $this->assertStringNotContainsEqual('..', $path, $message);
    }
}
