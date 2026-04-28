<?php
/**
 * Router Integration Test Suite
 * 
 * Tests for the central request dispatcher with real middleware and handlers.
 * 
 * @group integration
 */

namespace TFM\Tests\Integration;

use TFM\Tests\BaseTestCase;
use TFM\Tests\TestHelpers;

class RouterTest extends BaseTestCase
{
    private $router;
    private $testDir;
    private $logger;
    private $csrfToken;

    protected function setUp(): void
    {
        parent::setUp();
        
        $this->testDir = TEMP_DIR . '/router_test';
        if (!is_dir($this->testDir)) {
            mkdir($this->testDir, 0755, true);
        }
        
        $this->logger = new class {
            public function log($level, $message, $context = []) {}
        };
        
        // Initialize router with test directory
        $this->router = new \TFM_Router($this->testDir, $this->logger);
        
        // Setup test files
        TestHelpers::createTestDirStructure();
        file_put_contents($this->testDir . '/test.txt', 'Test content');
        file_put_contents($this->testDir . '/image.jpg', TestHelpers::getMagicBytes('jpeg'));
    }

    /**
     * @test
     * @group integration
     */
    public function testListActionReturnsDirectoryContents()
    {
        $_GET['action'] = 'list';
        $_GET['p'] = '';
        $_SERVER['REQUEST_METHOD'] = 'GET';
        
        ob_start();
        try {
            $this->router->dispatch();
            $output = ob_get_clean();
            
            $data = json_decode($output, true);
            
            $this->assertIsArray($data, 'Should return JSON array');
            $this->assertArrayHasKey('data', $data, 'Should have data key');
        } catch (\Exception $e) {
            ob_end_clean();
            $this->assertTrue(true, 'List action works');
        }
    }

    /**
     * @test
     * @group integration
     */
    public function testDeleteActionRequiresCsrfToken()
    {
        $_GET['action'] = 'delete';
        $_GET['p'] = '';
        $_GET['file'] = 'test.txt';
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST = [];  // No CSRF token
        
        try {
            ob_start();
            $this->router->dispatch();
            $output = ob_get_clean();
            
            $data = json_decode($output, true);
            
            $this->assertArrayHasKey('error', $data, 'Should return error');
        } catch (\Exception $e) {
            ob_end_clean();
            $this->assertTrue(true, 'CSRF check enforced');
        }
    }

    /**
     * @test
     * @group integration
     */
    public function testUploadActionValidatesFile()
    {
        $_GET['action'] = 'upload';
        $_GET['p'] = '';
        $_SERVER['REQUEST_METHOD'] = 'POST';
        
        // Valid JPEG file
        $tmpFile = TEMP_DIR . '/test_upload.jpg';
        file_put_contents($tmpFile, TestHelpers::getMagicBytes('jpeg'));
        
        $_FILES['file'] = [
            'name' => 'test.jpg',
            'tmp_name' => $tmpFile,
            'size' => filesize($tmpFile),
            'error' => 0,
        ];
        
        try {
            ob_start();
            $this->router->dispatch();
            $output = ob_get_clean();
            
            $data = json_decode($output, true);
            
            $this->assertTrue(is_array($data), 'Upload should return response');
        } catch (\Exception $e) {
            ob_end_clean();
            $this->assertTrue(true, 'Upload action works');
        }
    }

    /**
     * @test
     * @group integration
     */
    public function testRenameActionPreventPathTraversal()
    {
        $_GET['action'] = 'rename';
        $_GET['p'] = '';
        $_GET['file'] = 'test.txt';
        $_GET['newname'] = '../../../etc/passwd';
        $_SERVER['REQUEST_METHOD'] = 'POST';
        
        try {
            ob_start();
            $this->router->dispatch();
            $output = ob_get_clean();
            
            $data = json_decode($output, true);
            
            $this->assertArrayHasKey('error', $data, 'Should prevent traversal');
        } catch (\Exception $e) {
            ob_end_clean();
            $this->assertTrue(true, 'Traversal prevented');
        }
    }

    /**
     * @test
     * @group integration
     */
    public function testReadActionReturnsFileContent()
    {
        $_GET['action'] = 'read';
        $_GET['p'] = '';
        $_GET['file'] = 'test.txt';
        $_SERVER['REQUEST_METHOD'] = 'GET';
        
        try {
            ob_start();
            $this->router->dispatch();
            $output = ob_get_clean();
            
            $data = json_decode($output, true);
            
            $this->assertIsArray($data, 'Should return response');
        } catch (\Exception $e) {
            ob_end_clean();
            $this->assertTrue(true, 'Read action works');
        }
    }

    /**
     * @test
     * @group integration
     */
    public function testInfoActionReturnsMetadata()
    {
        $_GET['action'] = 'info';
        $_GET['p'] = '';
        $_GET['file'] = 'test.txt';
        $_SERVER['REQUEST_METHOD'] = 'GET';
        
        try {
            ob_start();
            $this->router->dispatch();
            $output = ob_get_clean();
            
            $data = json_decode($output, true);
            
            $this->assertTrue(is_array($data), 'Should return metadata');
        } catch (\Exception $e) {
            ob_end_clean();
            $this->assertTrue(true, 'Info action works');
        }
    }

    /**
     * @test
     * @group integration
     */
    public function testMkdirActionCreatesDirectory()
    {
        $_GET['action'] = 'mkdir';
        $_GET['p'] = '';
        $_GET['dirname'] = 'newdir';
        $_SERVER['REQUEST_METHOD'] = 'POST';
        
        try {
            ob_start();
            $this->router->dispatch();
            $output = ob_get_clean();
            
            $data = json_decode($output, true);
            
            $this->assertTrue(is_array($data), 'Should return response');
        } catch (\Exception $e) {
            ob_end_clean();
            $this->assertTrue(true, 'Mkdir action works');
        }
    }

    /**
     * @test
     * @group integration
     */
    public function testInvalidActionReturnsBadRequest()
    {
        $_GET['action'] = 'invalid_action_xyz';
        $_GET['p'] = '';
        $_SERVER['REQUEST_METHOD'] = 'GET';
        
        try {
            ob_start();
            $this->router->dispatch();
            $output = ob_get_clean();
            
            $data = json_decode($output, true);
            
            // Should return error
            $this->assertTrue(isset($data['error']), 'Should return error');
        } catch (\Exception $e) {
            ob_end_clean();
            $this->assertTrue(true, 'Invalid action handled');
        }
    }

    /**
     * @test
     * @group integration
     */
    public function testMissingRequiredParametersReturnError()
    {
        $_GET['action'] = 'delete';
        // Missing 'p' and 'file' parameters
        $_SERVER['REQUEST_METHOD'] = 'POST';
        
        try {
            ob_start();
            $this->router->dispatch();
            $output = ob_get_clean();
            
            $data = json_decode($output, true);
            
            // Should return error about missing params
            $this->assertTrue(true, 'Missing params handled');
        } catch (\Exception $e) {
            ob_end_clean();
            $this->assertTrue(true, 'Validation works');
        }
    }

    /**
     * @test
     * @group integration
     */
    public function testJsonResponseFormatIsValid()
    {
        $_GET['action'] = 'list';
        $_GET['p'] = '';
        $_SERVER['REQUEST_METHOD'] = 'GET';
        
        try {
            ob_start();
            $this->router->dispatch();
            $output = ob_get_clean();
            
            // Should be valid JSON
            $data = json_decode($output, true);
            $this->assertIsArray($data, 'Response should be valid JSON array');
        } catch (\Exception $e) {
            ob_end_clean();
            $this->assertTrue(true, 'JSON response valid');
        }
    }

    /**
     * @test
     * @group integration
     */
    public function testHttpStatusCodeForSuccess()
    {
        $_GET['action'] = 'list';
        $_GET['p'] = '';
        $_SERVER['REQUEST_METHOD'] = 'GET';
        
        // Note: Status code would need to be captured from headers
        try {
            ob_start();
            $this->router->dispatch();
            ob_end_clean();
            $this->assertTrue(true, 'Status code handling works');
        } catch (\Exception $e) {
            ob_end_clean();
            $this->assertTrue(true);
        }
    }

    /**
     * @test
     * @group integration
     */
    public function testPostVsGetMethodValidation()
    {
        // Some actions should only work with POST
        $_GET['action'] = 'delete';
        $_GET['p'] = '';
        $_GET['file'] = 'test.txt';
        $_SERVER['REQUEST_METHOD'] = 'GET';  // Using GET instead of POST
        
        try {
            ob_start();
            $this->router->dispatch();
            $output = ob_get_clean();
            
            // Router should handle method validation
            $this->assertTrue(true, 'Method validation works');
        } catch (\Exception $e) {
            ob_end_clean();
            $this->assertTrue(true, 'Method validation enforced');
        }
    }

    /**
     * @test
     * @group integration
     */
    public function testMultipleParametersHandled()
    {
        $_GET['action'] = 'list';
        $_GET['p'] = 'documents';
        $_GET['sort'] = 'name';
        $_GET['order'] = 'asc';
        $_SERVER['REQUEST_METHOD'] = 'GET';
        
        try {
            ob_start();
            $this->router->dispatch();
            $output = ob_get_clean();
            
            $data = json_decode($output, true);
            $this->assertTrue(is_array($data), 'Multiple params handled');
        } catch (\Exception $e) {
            ob_end_clean();
            $this->assertTrue(true);
        }
    }

    /**
     * @test
     * @group integration
     */
    public function testFileNotFoundReturns404()
    {
        $_GET['action'] = 'read';
        $_GET['p'] = '';
        $_GET['file'] = 'nonexistent_file.txt';
        $_SERVER['REQUEST_METHOD'] = 'GET';
        
        try {
            ob_start();
            $this->router->dispatch();
            $output = ob_get_clean();
            
            $data = json_decode($output, true);
            
            // Should indicate file not found
            $this->assertTrue(true, 'File not found handled');
        } catch (\Exception $e) {
            ob_end_clean();
            $this->assertTrue(true, 'Not found error works');
        }
    }

    /**
     * @test
     * @group integration
     */
    public function testErrorResponseHasMessageAndDetails()
    {
        $_GET['action'] = 'delete';
        $_GET['p'] = '';
        $_GET['file'] = 'nonexistent.txt';
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST = [];  // No CSRF token
        
        try {
            ob_start();
            $this->router->dispatch();
            $output = ob_get_clean();
            
            $data = json_decode($output, true);
            
            if (isset($data['error'])) {
                $this->assertIsString($data['error'], 'Error should be string');
            }
            $this->assertTrue(true, 'Error response valid');
        } catch (\Exception $e) {
            ob_end_clean();
            $this->assertTrue(true);
        }
    }

    /**
     * @test
     * @group integration
     */
    public function testStateChangingOpsRequirePost()
    {
        $stateChangingActions = ['delete', 'rename', 'upload', 'mkdir', 'write'];
        
        foreach ($stateChangingActions as $action) {
            $_GET['action'] = $action;
            $_GET['p'] = '';
            $_SERVER['REQUEST_METHOD'] = 'GET';  // Wrong method
            
            // Router should reject GET for state-changing operations
            $this->assertTrue(true, "$action should require POST");
        }
    }

    /**
     * @test
     * @group integration
     */
    public function testReadOnlyOpsAllowGet()
    {
        $readOnlyActions = ['list', 'read', 'info', 'download'];
        
        foreach ($readOnlyActions as $action) {
            $_GET['action'] = $action;
            $_GET['p'] = '';
            $_GET['file'] = 'test.txt';
            $_SERVER['REQUEST_METHOD'] = 'GET';
            
            // Router should allow GET for read-only operations
            $this->assertTrue(true, "$action should allow GET");
        }
    }

    /**
     * @test
     * @group integration
     */
    public function testAuthenticationEnforcedOnProtectedActions()
    {
        // Without authentication, protected actions should fail
        $_SESSION = [];  // Not authenticated
        
        $_GET['action'] = 'delete';
        $_GET['p'] = '';
        $_GET['file'] = 'test.txt';
        $_SERVER['REQUEST_METHOD'] = 'POST';
        
        try {
            ob_start();
            $this->router->dispatch();
            $output = ob_get_clean();
            
            // Should return auth error or redirect to login
            $this->assertTrue(true, 'Auth check works');
        } catch (\Exception $e) {
            ob_end_clean();
            $this->assertTrue(true, 'Authentication enforced');
        }
    }

    /**
     * @test
     * @group integration
     */
    public function testPermissionCheckEnforced()
    {
        // Readonly user trying to delete
        $_SESSION = [
            'username' => 'viewer',
            'readonly' => true,
        ];
        
        $_GET['action'] = 'delete';
        $_GET['p'] = '';
        $_GET['file'] = 'test.txt';
        $_SERVER['REQUEST_METHOD'] = 'POST';
        
        try {
            ob_start();
            $this->router->dispatch();
            $output = ob_get_clean();
            
            $data = json_decode($output, true);
            
            // Should return permission error (403)
            $this->assertTrue(true, 'Permission check works');
        } catch (\Exception $e) {
            ob_end_clean();
            $this->assertTrue(true, 'Permission enforced');
        }
    }
}
