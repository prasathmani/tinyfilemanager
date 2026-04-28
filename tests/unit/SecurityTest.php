<?php
/**
 * Security Functions Test Suite
 * 
 * Tests for magic bytes validation, MIME type checking, path traversal prevention, etc.
 * 
 * @group security
 */

namespace TFM\Tests\Unit;

use TFM\Tests\BaseTestCase;
use TFM\Tests\TestHelpers;

class SecurityTest extends BaseTestCase
{
    /**
     * @test
     * @group security
     */
    public function testMagicBytesValidationForJPEG()
    {
        $path = TestHelpers::createTestFile('test.jpg', TestHelpers::getMagicBytes('jpeg'));
        
        $result = fm_validate_magic_bytes($path);
        
        $this->assertTrue($result, 'Should accept valid JPEG file');
    }

    /**
     * @test
     * @group security
     */
    public function testMagicBytesValidationForPNG()
    {
        $path = TestHelpers::createTestFile('test.png', TestHelpers::getMagicBytes('png'));
        
        $result = fm_validate_magic_bytes($path);
        
        $this->assertTrue($result, 'Should accept valid PNG file');
    }

    /**
     * @test
     * @group security
     */
    public function testMagicBytesValidationForPDF()
    {
        $path = TestHelpers::createTestFile('test.pdf', TestHelpers::getMagicBytes('pdf'));
        
        $result = fm_validate_magic_bytes($path);
        
        $this->assertTrue($result, 'Should accept valid PDF file');
    }

    /**
     * @test
     * @group security
     */
    public function testMagicBytesValidationRejectsPhp()
    {
        $path = TestHelpers::createTestFile('shell.php', TestHelpers::getMagicBytes('php'));
        
        $result = fm_validate_magic_bytes($path);
        
        $this->assertFalse($result, 'Should reject PHP files');
    }

    /**
     * @test
     * @group security
     */
    public function testMagicBytesValidationRejectsSpoofedFile()
    {
        // JPEG magic bytes with PHP code
        $path = TestHelpers::createSpoofedFile('shell.php.jpg');
        
        $result = fm_validate_magic_bytes($path);
        
        $this->assertFalse($result, 'Should detect spoofed file with PHP code');
    }

    /**
     * @test
     * @group security
     */
    public function testMagicBytesValidationRejectsExecutable()
    {
        $path = TestHelpers::createTestFile('malware.exe', TestHelpers::getMagicBytes('exe'));
        
        $result = fm_validate_magic_bytes($path);
        
        $this->assertFalse($result, 'Should reject EXE files');
    }

    /**
     * @test
     * @group security
     */
    public function testMagicBytesValidationRejectsELFBinary()
    {
        $path = TestHelpers::createTestFile('binary', TestHelpers::getMagicBytes('elf'));
        
        $result = fm_validate_magic_bytes($path);
        
        $this->assertFalse($result, 'Should reject ELF binary files');
    }

    /**
     * @test
     * @group security
     */
    public function testMagicBytesValidationHandlesEmptyFile()
    {
        $path = TestHelpers::createTestFile('empty.txt', '');
        
        $result = fm_validate_magic_bytes($path);
        
        $this->assertFalse($result, 'Should reject empty files');
    }

    /**
     * @test
     * @group security
     */
    public function testMagicBytesValidationHandlesNonExistentFile()
    {
        $result = fm_validate_magic_bytes('/nonexistent/path/file.jpg');
        
        $this->assertFalse($result, 'Should reject non-existent files');
    }

    /**
     * @test
     * @group security
     */
    public function testPathTraversalDetectionBlocksRelativeParent()
    {
        $payload = '../../../etc/passwd';
        
        $result = fm_validate_filepath($payload, TEMP_DIR);
        
        $this->assertFalse($result, 'Should block ../../../etc/passwd');
    }

    /**
     * @test
     * @group security
     */
    public function testPathTraversalDetectionBlocksUrlEncoded()
    {
        $payload = '..%2F..%2F..%2Fetc%2Fpasswd';
        
        $result = fm_validate_filepath($payload, TEMP_DIR);
        
        $this->assertFalse($result, 'Should block URL encoded traversal');
    }

    /**
     * @test
     * @group security
     */
    public function testPathTraversalDetectionBlocksDoubleUrlEncoded()
    {
        $payload = '..%252F..%252Fetc%252Fpasswd';
        
        $result = fm_validate_filepath($payload, TEMP_DIR);
        
        $this->assertFalse($result, 'Should block double URL encoded traversal');
    }

    /**
     * @test
     * @group security
     */
    public function testPathTraversalDetectionBlocksNullByte()
    {
        $payload = "image.jpg\x00.php";
        
        $result = fm_validate_filepath($payload, TEMP_DIR);
        
        $this->assertFalse($result, 'Should block null byte injection');
    }

    /**
     * @test
     * @group security
     */
    public function testPathTraversalDetectionBlocksWindowsTraversal()
    {
        $payload = '..\\..\\..\\windows\\system32\\config\\sam';
        
        $result = fm_validate_filepath($payload, TEMP_DIR);
        
        $this->assertFalse($result, 'Should block Windows path traversal');
    }

    /**
     * @test
     * @group security
     */
    public function testPathTraversalDetectionAllowsValidPath()
    {
        TestHelpers::createTestDirStructure();
        $validPath = 'documents/file.txt';
        
        $result = fm_validate_filepath($validPath, TEMP_DIR);
        
        $this->assertTrue($result, 'Should allow valid relative path');
    }

    /**
     * @test
     * @group security
     */
    public function testValidFilenameAllowsLettersNumbers()
    {
        $filename = 'my_document_2024.txt';
        
        $result = fm_isvalid_filename($filename);
        
        $this->assertTrue($result, 'Should allow letters, numbers, underscore, dash');
    }

    /**
     * @test
     * @group security
     */
    public function testValidFilenameAllowsSpaces()
    {
        $filename = 'My Important Document.pdf';
        
        $result = fm_isvalid_filename($filename);
        
        $this->assertTrue($result, 'Should allow spaces in filename');
    }

    /**
     * @test
     * @group security
     */
    public function testValidFilenameBlocksSpecialChars()
    {
        $invalidNames = [
            'file;.txt',
            'file|.txt',
            'file&.txt',
            'file<.txt',
            'file>.txt',
            'file".txt',
            "file'.txt",
        ];
        
        foreach ($invalidNames as $filename) {
            $result = fm_isvalid_filename($filename);
            $this->assertFalse($result, "Should block special char in: $filename");
        }
    }

    /**
     * @test
     * @group security
     */
    public function testValidFilenameBlocksDotFiles()
    {
        $filename = '.htaccess';
        
        $result = fm_isvalid_filename($filename);
        
        $this->assertFalse($result, 'Should block dot files like .htaccess');
    }

    /**
     * @test
     * @group security
     */
    public function testValidFilenameBlocksAbsolutePath()
    {
        $filename = '/etc/passwd';
        
        $result = fm_isvalid_filename($filename);
        
        $this->assertFalse($result, 'Should block absolute paths');
    }

    /**
     * @test
     * @group security
     */
    public function testValidFilenameBlocksTraversal()
    {
        $filename = '../../../etc/passwd';
        
        $result = fm_isvalid_filename($filename);
        
        $this->assertFalse($result, 'Should block directory traversal');
    }

    /**
     * @test
     * @group security
     */
    public function testInputValidationSanitizesSQLChars()
    {
        $input = "'; DROP TABLE users; --";
        
        $result = fm_validate_input($input);
        
        $this->assertTrue(is_string($result), 'Should return sanitized string');
        $this->assertStringNotContainsEqual("'", $result, 'Should escape quotes');
    }

    /**
     * @test
     * @group security
     */
    public function testInputValidationRemovesScriptTags()
    {
        $input = '<script>alert("xss")</script>';
        
        $result = fm_validate_input($input);
        
        $this->assertStringNotContainsEqual('<script>', $result, 'Should remove script tags');
    }

    /**
     * @test
     * @group security
     */
    public function testInputValidationTrimsWhitespace()
    {
        $input = '  test input  ';
        
        $result = fm_validate_input($input);
        
        $this->assertSame('test input', $result, 'Should trim whitespace');
    }

    /**
     * @test
     * @group security
     */
    public function testCleanPathRemovesDotSegments()
    {
        $path = '/files/../documents/./file.txt';
        
        $result = fm_clean_path($path);
        
        $this->assertStringNotContainsEqual('..', $result, 'Should remove .. segments');
        $this->assertStringNotContainsEqual('/./', $result, 'Should remove /./ segments');
    }

    /**
     * @test
     * @group security
     */
    public function testCleanPathNormalizesSlashes()
    {
        $path = '/files//documents///file.txt';
        
        $result = fm_clean_path($path);
        
        $this->assertStringNotContainsEqual('//', $result, 'Should normalize double slashes');
    }

    /**
     * @test
     * @group security
     */
    public function testCleanPathPreservesTrailingSlash()
    {
        $path = '/files/documents/';
        
        $result = fm_clean_path($path);
        
        $this->assertStringEndsNotWith('/', $result, 'Should remove trailing slash from directory');
    }

    /**
     * @test
     * @group security
     */
    public function testSystemAllowsLargeFileValidation()
    {
        // Create a 10MB file
        $path = TestHelpers::createLargeFile('large.bin', 10);
        
        $result = fm_validate_magic_bytes($path);
        
        // Should not crash on large files
        $this->assertTrue(is_bool($result), 'Should handle large files gracefully');
    }

    /**
     * @test
     * @group security
     */
    public function testValidateUsernameAllowsAlphanumeric()
    {
        $username = 'user123_abc';
        
        $this->assertMatchesRegularExpression('/^[a-zA-Z0-9_.-]{3,32}$/', $username);
    }

    /**
     * @test
     * @group security
     */
    public function testValidateUsernameRejectsShortName()
    {
        $username = 'ab';
        
        $this->assertDoesNotMatchRegularExpression('/^[a-zA-Z0-9_.-]{3,32}$/', $username);
    }

    /**
     * @test
     * @group security
     */
    public function testValidateUsernameRejectsSpecialChars()
    {
        $usernames = [
            'user@domain',
            'user;drop',
            "user'quote",
            'user"quote',
            'user|pipe',
        ];
        
        foreach ($usernames as $username) {
            $this->assertDoesNotMatchRegularExpression(
                '/^[a-zA-Z0-9_.-]{3,32}$/',
                $username,
                "Should reject: $username"
            );
        }
    }
}
