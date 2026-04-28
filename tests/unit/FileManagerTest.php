<?php
/**
 * FileManager Service Test Suite
 * 
 * Tests for core file operations: list, read, write, create, delete, info.
 * 
 * @group services
 */

namespace TFM\Tests\Unit;

use TFM\Tests\BaseTestCase;
use TFM\Tests\TestHelpers;

class FileManagerTest extends BaseTestCase
{
    private $fileManager;
    private $testDir;
    private $logger;

    protected function setUp(): void
    {
        parent::setUp();
        
        $this->testDir = TEMP_DIR . '/filemanager_test';
        if (!is_dir($this->testDir)) {
            mkdir($this->testDir, 0755, true);
        }
        
        $this->logger = new class {
            public function log($level, $message, $context = []) {}
        };
        
        $this->fileManager = new \TFM_FileManager($this->testDir, $this->logger);
    }

    /**
     * LIST DIRECTORY TESTS
     */

    /**
     * @test
     * @group services
     */
    public function testListDirectoryReturnsArray()
    {
        $result = $this->fileManager->listDirectory('');
        
        $this->assertIsArray($result, 'Should return array');
    }

    /**
     * @test
     * @group services
     */
    public function testListDirectoryIncludesFiles()
    {
        file_put_contents($this->testDir . '/test.txt', 'content');
        
        $result = $this->fileManager->listDirectory('');
        
        $this->assertArrayHasKey('files', $result, 'Should have files key');
        $this->assertCount(1, $result['files'], 'Should list one file');
    }

    /**
     * @test
     * @group services
     */
    public function testListDirectoryIncludesDirectories()
    {
        mkdir($this->testDir . '/subdir');
        
        $result = $this->fileManager->listDirectory('');
        
        $this->assertArrayHasKey('dirs', $result, 'Should have dirs key');
        $this->assertCount(1, $result['dirs'], 'Should list one directory');
    }

    /**
     * @test
     * @group services
     */
    public function testListDirectorySortsAlphabetically()
    {
        file_put_contents($this->testDir . '/zzz.txt', 'content');
        file_put_contents($this->testDir . '/aaa.txt', 'content');
        file_put_contents($this->testDir . '/mmm.txt', 'content');
        
        $result = $this->fileManager->listDirectory('');
        
        $files = array_column($result['files'], 'name');
        $this->assertEquals($files, ['aaa.txt', 'mmm.txt', 'zzz.txt'], 'Should sort alphabetically');
    }

    /**
     * @test
     * @group services
     */
    public function testListDirectoryIgnoresHiddenFiles()
    {
        file_put_contents($this->testDir . '/.hidden', 'secret');
        file_put_contents($this->testDir . '/visible.txt', 'public');
        
        $result = $this->fileManager->listDirectory('');
        
        $files = array_column($result['files'], 'name');
        $this->assertNotContains('.hidden', $files, 'Should exclude hidden files');
        $this->assertContains('visible.txt', $files, 'Should include visible files');
    }

    /**
     * @test
     * @group services
     */
    public function testListDirectoryValidatesPath()
    {
        try {
            $this->fileManager->listDirectory('../../../etc');
            $this->fail('Should prevent path traversal');
        } catch (\Exception $e) {
            $this->assertTrue(true, 'Path traversal prevented');
        }
    }

    /**
     * GET FILE INFO TESTS
     */

    /**
     * @test
     * @group services
     */
    public function testGetFileInfoReturnsDetails()
    {
        file_put_contents($this->testDir . '/test.txt', 'Hello World');
        
        $info = $this->fileManager->getFileInfo('test.txt');
        
        $this->assertIsArray($info, 'Should return array');
        $this->assertEquals('test.txt', $info['name'] ?? null, 'Should include name');
        $this->assertGreaterThan(0, $info['size'] ?? 0, 'Should include size');
    }

    /**
     * @test
     * @group services
     */
    public function testGetFileInfoIncludesModifiedTime()
    {
        file_put_contents($this->testDir . '/test.txt', 'content');
        
        $info = $this->fileManager->getFileInfo('test.txt');
        
        $this->assertArrayHasKey('modified', $info, 'Should include modified time');
    }

    /**
     * @test
     * @group services
     */
    public function testGetFileInfoIncludesType()
    {
        file_put_contents($this->testDir . '/test.txt', 'content');
        
        $info = $this->fileManager->getFileInfo('test.txt');
        
        $this->assertArrayHasKey('type', $info, 'Should include type (file/dir)');
        $this->assertEquals('file', $info['type'], 'Should be marked as file');
    }

    /**
     * @test
     * @group services
     */
    public function testGetFileInfoHandlesDirectory()
    {
        mkdir($this->testDir . '/subdir');
        
        $info = $this->fileManager->getFileInfo('subdir');
        
        $this->assertEquals('dir', $info['type'] ?? null, 'Should be marked as directory');
    }

    /**
     * @test
     * @group services
     */
    public function testGetFileInfoRejectsNonExistent()
    {
        try {
            $this->fileManager->getFileInfo('nonexistent.txt');
            $this->fail('Should throw exception for non-existent file');
        } catch (\Exception $e) {
            $this->assertTrue(true, 'Exception thrown as expected');
        }
    }

    /**
     * READ FILE TESTS
     */

    /**
     * @test
     * @group services
     */
    public function testReadFileReturnsContent()
    {
        $content = 'Hello, World!';
        file_put_contents($this->testDir . '/test.txt', $content);
        
        $result = $this->fileManager->readFile('test.txt');
        
        $this->assertEquals($content, $result, 'Should return file content');
    }

    /**
     * @test
     * @group services
     */
    public function testReadFileHandlesEmptyFile()
    {
        touch($this->testDir . '/empty.txt');
        
        $result = $this->fileManager->readFile('empty.txt');
        
        $this->assertEquals('', $result, 'Should return empty string for empty file');
    }

    /**
     * @test
     * @group services
     */
    public function testReadFileHandlesLargeFile()
    {
        $content = str_repeat('A', 1024 * 1024);  // 1MB
        file_put_contents($this->testDir . '/large.txt', $content);
        
        $result = $this->fileManager->readFile('large.txt');
        
        $this->assertEquals(strlen($content), strlen($result), 'Should read entire large file');
    }

    /**
     * @test
     * @group services
     */
    public function testReadFileRejectsNonExistent()
    {
        try {
            $this->fileManager->readFile('nonexistent.txt');
            $this->fail('Should throw exception');
        } catch (\Exception $e) {
            $this->assertTrue(true);
        }
    }

    /**
     * @test
     * @group services
     */
    public function testReadFileValidatesPath()
    {
        try {
            $this->fileManager->readFile('../../../etc/passwd');
            $this->fail('Should prevent path traversal');
        } catch (\Exception $e) {
            $this->assertTrue(true);
        }
    }

    /**
     * WRITE FILE TESTS
     */

    /**
     * @test
     * @group services
     */
    public function testWriteFileCreatesFile()
    {
        $path = $this->testDir . '/new.txt';
        
        $this->fileManager->writeFile('new.txt', 'New content');
        
        $this->assertTrue(file_exists($path), 'File should be created');
        $this->assertEquals('New content', file_get_contents($path), 'Content should match');
    }

    /**
     * @test
     * @group services
     */
    public function testWriteFileOverwritesExisting()
    {
        file_put_contents($this->testDir . '/test.txt', 'Old content');
        
        $this->fileManager->writeFile('test.txt', 'New content');
        
        $this->assertEquals('New content', file_get_contents($this->testDir . '/test.txt'));
    }

    /**
     * @test
     * @group services
     */
    public void testWriteFileHandlesEmptyContent()
    {
        $this->fileManager->writeFile('empty.txt', '');
        
        $this->assertEquals('', file_get_contents($this->testDir . '/empty.txt'));
    }

    /**
     * @test
     * @group services
     */
    public function testWriteFileValidatesPath()
    {
        try {
            $this->fileManager->writeFile('../../../etc/passwd', 'content');
            $this->fail('Should prevent path traversal');
        } catch (\Exception $e) {
            $this->assertTrue(true);
        }
    }

    /**
     * CREATE DIRECTORY TESTS
     */

    /**
     * @test
     * @group services
     */
    public function testCreateDirectoryMakesNewDir()
    {
        $dir = $this->testDir . '/newdir';
        
        $this->fileManager->createDirectory('newdir');
        
        $this->assertTrue(is_dir($dir), 'Directory should be created');
    }

    /**
     * @test
     * @group services
     */
    public function testCreateDirectoryValidatesPath()
    {
        try {
            $this->fileManager->createDirectory('../../../etc/newdir');
            $this->fail('Should prevent path traversal');
        } catch (\Exception $e) {
            $this->assertTrue(true);
        }
    }

    /**
     * @test
     * @group services
     */
    public function testCreateDirectoryRejectsExisting()
    {
        mkdir($this->testDir . '/existing');
        
        try {
            $this->fileManager->createDirectory('existing');
            $this->fail('Should reject existing directory');
        } catch (\Exception $e) {
            $this->assertTrue(true);
        }
    }

    /**
     * @test
     * @group services
     */
    public function testCreateDirectoryValidatesName()
    {
        try {
            $this->fileManager->createDirectory('invalid;name');
            $this->fail('Should reject invalid name');
        } catch (\Exception $e) {
            $this->assertTrue(true);
        }
    }

    /**
     * INTEGRATION TESTS
     */

    /**
     * @test
     * @group services
     */
    public function testCompleteFileWorkflow()
    {
        // Create directory
        $this->fileManager->createDirectory('documents');
        
        // Write file
        $this->fileManager->writeFile('documents/readme.txt', 'Important info');
        
        // Read file
        $content = $this->fileManager->readFile('documents/readme.txt');
        $this->assertEquals('Important info', $content);
        
        // Get info
        $info = $this->fileManager->getFileInfo('documents/readme.txt');
        $this->assertEquals('file', $info['type']);
        
        // List directory
        $listing = $this->fileManager->listDirectory('documents');
        $this->assertCount(1, $listing['files']);
    }

    /**
     * @test
     * @group services
     */
    public function testPathValidationConsistent()
    {
        // All methods should validate paths the same way
        $invalidPaths = [
            '../../../root',
            '..%2F..%2F..%2Froot',
            'file\x00.txt',
        ];
        
        foreach ($invalidPaths as $path) {
            try {
                $this->fileManager->listDirectory($path);
                $this->fail("Should reject: $path");
            } catch (\Exception $e) {
                $this->assertTrue(true);
            }
        }
    }
}
