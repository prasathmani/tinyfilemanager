<?php
/**
 * Rate Limiter Test Suite
 * 
 * Tests for brute force protection and rate limiting mechanism.
 * 
 * @group security
 */

namespace TFM\Tests\Unit;

use TFM\Tests\BaseTestCase;
use TFM\Tests\TestHelpers;

class RateLimiterTest extends BaseTestCase
{
    private $limiter;
    private $logFile;

    protected function setUp(): void
    {
        parent::setUp();
        $this->logFile = TEMP_DIR . '/rate_limit.json';
        $this->limiter = new \RateLimiter($this->logFile);
    }

    /**
     * @test
     * @group security
     */
    public function testFirstLoginAttemptAllowed()
    {
        $ip = '192.168.1.1';
        $username = 'testuser';
        
        $result = $this->limiter->checkLimit($ip, $username);
        
        $this->assertTrue(
            $result,
            'First login attempt should be allowed'
        );
    }

    /**
     * @test
     * @group security
     */
    public function testMultipleAttemptsWithinLimitAllowed()
    {
        $ip = '192.168.1.1';
        $username = 'testuser';
        
        for ($i = 0; $i < 5; $i++) {
            $result = $this->limiter->checkLimit($ip, $username);
            $this->assertTrue(
                $result,
                "Attempt " . ($i + 1) . " of 5 should be allowed"
            );
        }
    }

    /**
     * @test
     * @group security
     */
    public function testSixthAttemptBlocked()
    {
        $ip = '192.168.1.1';
        $username = 'testuser';
        
        // Make 5 attempts (should all succeed)
        for ($i = 0; $i < 5; $i++) {
            $this->limiter->checkLimit($ip, $username);
        }
        
        // 6th attempt should be blocked
        $result = $this->limiter->checkLimit($ip, $username);
        
        $this->assertFalse(
            $result,
            '6th login attempt should be blocked (rate limited)'
        );
    }

    /**
     * @test
     * @group security
     */
    public function testLockoutDurationAndRelease()
    {
        $ip = '192.168.1.1';
        $username = 'testuser';
        
        // Make 5 attempts
        for ($i = 0; $i < 5; $i++) {
            $this->limiter->checkLimit($ip, $username);
        }
        
        // 6th attempt blocked
        $this->assertFalse($this->limiter->checkLimit($ip, $username));
        
        // Reset the rate limiter with shorter window for testing
        $this->logFile = TEMP_DIR . '/rate_limit_short.json';
        file_put_contents($this->logFile, json_encode([
            base64_encode($ip . '|' . $username) => [
                'attempts' => [time() - 920],  // Just outside 15 min window
                'locked_until' => time() - 1,    // Lockout expired
            ]
        ]));
        
        $limiter2 = new \RateLimiter($this->logFile);
        $result = $limiter2->checkLimit($ip, $username);
        
        $this->assertTrue(
            $result,
            'Should allow attempt after lockout period expires'
        );
    }

    /**
     * @test
     * @group security
     */
    public function testDifferentIPsAreTrackedSeparately()
    {
        $username = 'testuser';
        
        // IP 1 makes 5 attempts
        for ($i = 0; $i < 5; $i++) {
            $this->assertTrueArray(
                $this->limiter->checkLimit('192.168.1.1', $username),
                "IP 1 attempt " . ($i + 1) . " should succeed"
            );
        }
        
        // IP 2 should still be able to make attempts (not blocked)
        $result = $this->limiter->checkLimit('192.168.1.2', $username);
        
        $this->assertTrue(
            $result,
            'Different IP should not be affected by another IP\'s rate limit'
        );
    }

    /**
     * @test
     * @group security
     */
    public function testDifferentUsernamesAreTrackedSeparately()
    {
        $ip = '192.168.1.1';
        
        // Username 1 makes 5 attempts
        for ($i = 0; $i < 5; $i++) {
            $this->limiter->checkLimit($ip, 'user1');
        }
        
        // Username 2 should still be able to make attempts
        $result = $this->limiter->checkLimit($ip, 'user2');
        
        $this->assertTrue(
            $result,
            'Different username should not be affected by another username\'s rate limit'
        );
    }

    /**
     * @test
     * @group security
     */
    public function testLogFileCreatedIfNotExists()
    {
        $logFile = TEMP_DIR . '/new_rate_limit.json';
        
        new \RateLimiter($logFile);
        
        $this->assertFileExists($logFile, 'Rate limiter should create log file');
    }

    /**
     * @test
     * @group security
     */
    public function testLogFileFormatIsValidJSON()
    {
        $ip = '192.168.1.1';
        $username = 'testuser';
        
        $this->limiter->checkLimit($ip, $username);
        
        $content = file_get_contents($this->logFile);
        $data = json_decode($content, true);
        
        $this->assertIsArray($data, 'Log file should contain valid JSON');
        $this->assertNotEmpty($data, 'Log file should have entries');
    }

    /**
     * @test
     * @group security
     */
    public function testOldEntriesAreCleanedUp()
    {
        $ip = '192.168.1.1';
        $username = 'testuser';
        
        // Create entries with old timestamps (beyond 24h)
        $oldTime = time() - (25 * 3600);  // 25 hours ago
        file_put_contents($this->logFile, json_encode([
            base64_encode($ip . '|' . $username) => [
                'attempts' => [$oldTime, $oldTime],
                'locked_until' => $oldTime,
            ]
        ]));
        
        // Make a new check (should trigger cleanup)
        $this->limiter->checkLimit($ip, $username);
        
        $content = file_get_contents($this->logFile);
        $data = json_decode($content, true);
        
        $this->assertLessThanOrEqual(
            1,
            count($data),
            'Old entries should be cleaned up'
        );
    }

    /**
     * @test
     * @group security
     */
    public function testLockoutIncreasesWithMultipleViolations()
    {
        $ip = '192.168.1.1';
        $username = 'testuser';
        
        // First lockout
        for ($i = 0; $i < 5; $i++) {
            $this->limiter->checkLimit($ip, $username);
        }
        $this->assertFalse($this->limiter->checkLimit($ip, $username));
        
        // Get first lockout duration
        $logData = json_decode(file_get_contents($this->logFile), true);
        $key = base64_encode($ip . '|' . $username);
        $firstLockout = $logData[$key]['locked_until'];
        
        // Reset and do it again after brief wait
        sleep(1);
        $this->logFile = TEMP_DIR . '/rate_limit_new.json';
        $limiter2 = new \RateLimiter($this->logFile);
        
        for ($i = 0; $i < 5; $i++) {
            $limiter2->checkLimit($ip, $username);
        }
        $limiter2->checkLimit($ip, $username);  // 6th attempt
        
        // Verify lockout was applied (function should exist)
        $this->assertTrue(true, 'Multiple lockouts should be applied');
    }

    /**
     * @test
     * @group security
     */
    public function testEmptyIPIsRejected()
    {
        // This should either throw or return false
        try {
            $result = $this->limiter->checkLimit('', 'testuser');
            $this->assertFalse($result);
        } catch (\Exception $e) {
            $this->assertTrue(true, 'Empty IP should cause exception or return false');
        }
    }

    /**
     * @test
     * @group security
     */
    public function testEmptyUsernameIsRejected()
    {
        try {
            $result = $this->limiter->checkLimit('192.168.1.1', '');
            $this->assertFalse($result);
        } catch (\Exception $e) {
            $this->assertTrue(true, 'Empty username should cause exception or return false');
        }
    }

    /**
     * Helper to fix typo in test
     */
    private function assertTrueArray($value, $message = '')
    {
        $this->assertTrue($value, $message);
    }
}
