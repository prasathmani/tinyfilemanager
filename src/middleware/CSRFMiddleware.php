<?php
/**
 * TinyFileManager - CSRF Middleware
 * Handles CSRF token generation and validation
 */

class TFM_CSRFMiddleware {
    private $logger = null;
    private $token_name = 'token';
    private $cookie_name = 'tfm_csrf';
    private $token_length = 32;
    
    public function __construct($logger = null) {
        $this->logger = $logger;
        
        // Generate token if not exists
        $this->initializeToken();
    }
    
    /**
     * Initialize CSRF token
     */
    private function initializeToken() {
        if (empty($_SESSION['token'])) {
            $_SESSION['token'] = $this->generateToken();
        }
    }
    
    /**
     * Generate secure CSRF token
     */
    private function generateToken() {
        if (function_exists('random_bytes')) {
            return bin2hex(random_bytes($this->token_length));
        } elseif (function_exists('openssl_random_pseudo_bytes')) {
            return bin2hex(openssl_random_pseudo_bytes($this->token_length));
        } else {
            return hash('sha256', microtime(true) . mt_rand());
        }
    }
    
    /**
     * Get current token
     */
    public function getToken() {
        if (empty($_SESSION['token'])) {
            $_SESSION['token'] = $this->generateToken();
        }
        return $_SESSION['token'];
    }
    
    /**
     * Regenerate token (security practice)
     */
    public function regenerateToken() {
        $_SESSION['token'] = $this->generateToken();
        return $_SESSION['token'];
    }
    
    /**
     * Verify token
     */
    public function verify($token = null) {
        if (!$token) {
            $token = $_POST['token'] ?? $_GET['token'] ?? '';
        }
        
        if (empty($token) || empty($_SESSION['token'])) {
            return false;
        }
        
        // Use hash_equals to prevent timing attacks
        return hash_equals($_SESSION['token'], $token);
    }
    
    /**
     * Verify and regenerate (one-time use)
     */
    public function verifyAndRegenerate($token = null) {
        if (!$this->verify($token)) {
            return false;
        }
        
        $this->regenerateToken();
        return true;
    }
    
    /**
     * Check if request needs CSRF protection
     */
    public static function needsProtection($method = null) {
        if (!$method) {
            $method = $_SERVER['REQUEST_METHOD'];
        }
        
        // Only protect state-changing operations
        return in_array($method, ['POST', 'PUT', 'DELETE', 'PATCH']);
    }
    
    /**
     * Middleware function - call before dispatching requests
     */
    public function protect() {
        if (self::needsProtection()) {
            if (!$this->verify()) {
                $this->log('csrf_violation', 'Failed CSRF validation');
                
                http_response_code(403);
                echo json_encode(['error' => 'CSRF token validation failed']);
                exit;
            }
        }
    }
    
    /**
     * Get token HTML form field
     */
    public function getHiddenField($name = 'token') {
        return sprintf(
            '<input type="hidden" name="%s" value="%s">',
            htmlspecialchars($name),
            htmlspecialchars($this->getToken())
        );
    }
    
    /**
     * Get token as meta tag
     */
    public function getMetaTag($name = 'csrf-token') {
        return sprintf(
            '<meta name="%s" content="%s">',
            htmlspecialchars($name),
            htmlspecialchars($this->getToken())
        );
    }
    
    /**
     * Validate same-site requests
     */
    public function validateSameSite($trusted_origins = []) {
        $referer = $_SERVER['HTTP_REFERER'] ?? '';
        $host = $_SERVER['HTTP_HOST'] ?? '';
        
        if (empty($referer)) {
            // Requests without referer are suspicious
            return false;
        }
        
        // Extract host from referer
        $referer_host = parse_url($referer, PHP_URL_HOST);
        
        // Check against trusted origins
        $trusted = array_merge([$host], $trusted_origins);
        
        return in_array($referer_host, $trusted);
    }
    
    /**
     * Log action
     */
    private function log($action, $details) {
        if ($this->logger) {
            $this->logger->log($action, 'system', $details);
        }
    }
}
