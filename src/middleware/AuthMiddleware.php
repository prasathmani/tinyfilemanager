<?php
/**
 * TinyFileManager - Auth Middleware
 * Handles authentication and authorization checks
 */

class TFM_AuthMiddleware {
    private $auth_enabled = false;
    private $auth_users = [];
    private $readonly_users = [];
    private $upload_only_users = [];
    private $manager_users = [];
    private $current_user = null;
    private $logger = null;
    
    // User roles
    const ROLE_GUEST = 'guest';
    const ROLE_USER = 'user';
    const ROLE_MANAGER = 'manager';
    const ROLE_ADMIN = 'admin';
    
    public function __construct($config = [], $logger = null) {
        $this->auth_enabled = $config['enabled'] ?? false;
        $this->auth_users = $config['users'] ?? [];
        $this->readonly_users = $config['readonly'] ?? [];
        $this->upload_only_users = $config['upload_only'] ?? [];
        $this->manager_users = $config['managers'] ?? [];
        $this->logger = $logger;
        
        // Check session
        $this->checkSession();
    }
    
    /**
     * Check current session
     */
    private function checkSession() {
        if (!$this->auth_enabled) {
            $this->current_user = self::ROLE_GUEST;
            return;
        }
        
        // Check if already logged in
        if (isset($_SESSION['fm_logged']) && !empty($_SESSION['fm_logged'])) {
            if ($this->validateUser($_SESSION['fm_logged'])) {
                $this->current_user = $_SESSION['fm_logged'];
                return;
            }
        }
        
        // Check login attempt
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['fm_usr'], $_POST['fm_pwd'], $_POST['token'])) {
            $this->handleLogin($_POST['fm_usr'], $_POST['fm_pwd'], $_POST['token']);
        }
        
        $this->current_user = self::ROLE_GUEST;
    }
    
    /**
     * Handle login attempt
     */
    private function handleLogin($username, $password, $token) {
        // Validate CSRF token
        if (!tfm_verify_token($token)) {
            $this->log('login_failed', $username, 'Invalid CSRF token');
            return false;
        }
        
        // Check rate limiting
        $rate_limiter = Bootstrap::getRateLimiter();
        if ($rate_limiter && !$rate_limiter->check_limit('login')) {
            $this->log('login_blocked', $username, 'Rate limit exceeded');
            return false;
        }
        
        // Validate username
        if (!$this->validateUsername($username)) {
            $this->log('login_failed', $username, 'Invalid username format');
            $rate_limiter?->record_attempt('login');
            return false;
        }
        
        // Check credentials
        if (!isset($this->auth_users[$username])) {
            $this->log('login_failed', $username, 'User not found');
            $rate_limiter?->record_attempt('login');
            return false;
        }
        
        // Verify password
        if (!function_exists('password_verify')) {
            $this->log('login_error', $username, 'password_verify not available');
            return false;
        }
        
        if (!password_verify($password, $this->auth_users[$username])) {
            $this->log('login_failed', $username, 'Invalid password');
            $rate_limiter?->record_attempt('login');
            return false;
        }
        
        // Successful login
        $_SESSION['fm_logged'] = $username;
        $this->current_user = $username;
        $rate_limiter?->reset('login');
        
        $this->log('login_success', $username, 'User logged in');
        return true;
    }
    
    /**
     * Validate username format
     */
    private function validateUsername($username) {
        return preg_match('/^[a-zA-Z0-9_\-\.]{3,32}$/', $username);
    }
    
    /**
     * Validate user exists
     */
    private function validateUser($username) {
        return isset($this->auth_users[$username]);
    }
    
    /**
     * Handle logout
     */
    public function logout() {
        if ($this->current_user && $this->current_user !== self::ROLE_GUEST) {
            $this->log('logout', $this->current_user, 'User logged out');
        }
        
        $_SESSION = [];
        session_destroy();
        $this->current_user = self::ROLE_GUEST;
    }
    
    /**
     * Check if user is logged in
     */
    public function isLoggedIn() {
        return $this->current_user && $this->current_user !== self::ROLE_GUEST;
    }
    
    /**
     * Get current user
     */
    public function getCurrentUser() {
        return $this->current_user;
    }
    
    /**
     * Get user role
     */
    public function getRole($user = null) {
        if (!$user) {
            $user = $this->current_user;
        }
        
        if (!$user || $user === self::ROLE_GUEST) {
            return self::ROLE_GUEST;
        }
        
        if (in_array($user, $this->manager_users)) {
            return self::ROLE_MANAGER;
        }
        
        return self::ROLE_USER;
    }
    
    /**
     * Check if user is readonly
     */
    public function isReadonly($user = null) {
        if (!$user) {
            $user = $this->current_user;
        }
        
        return in_array($user, $this->readonly_users);
    }
    
    /**
     * Check if user can upload only
     */
    public function isUploadOnly($user = null) {
        if (!$user) {
            $user = $this->current_user;
        }
        
        return in_array($user, $this->upload_only_users);
    }
    
    /**
     * Check if user is manager
     */
    public function isManager($user = null) {
        if (!$user) {
            $user = $this->current_user;
        }
        
        return in_array($user, $this->manager_users);
    }
    
    /**
     * Check if user is admin
     */
    public function isAdmin($user = null) {
        if (!$user) {
            $user = $this->current_user;
        }
        
        // Admin is someone not in any restriction group
        return !$this->isReadonly($user) && !$this->isUploadOnly($user) && !$this->isManager($user);
    }
    
    /**
     * Require authentication
     */
    public function require($role = 'user') {
        if (!$this->auth_enabled) {
            return true;
        }
        
        if (!$this->isLoggedIn()) {
            http_response_code(401);
            echo json_encode(['error' => 'Authentication required']);
            exit;
        }
        
        // Check role
        $current_role = $this->getRole();
        
        switch ($role) {
            case 'admin':
                if (!$this->isAdmin()) {
                    http_response_code(403);
                    echo json_encode(['error' => 'Admin access required']);
                    exit;
                }
                break;
                
            case 'manager':
                if (!$this->isManager() && !$this->isAdmin()) {
                    http_response_code(403);
                    echo json_encode(['error' => 'Manager access required']);
                    exit;
                }
                break;
                
            case 'user':
            default:
                // Any logged-in user
                break;
        }
        
        return true;
    }
    
    /**
     * Check permission for action
     */
    public function checkPermission($action) {
        if (!$this->isLoggedIn()) {
            return false;
        }
        
        $user = $this->current_user;
        
        // Readonly users can't write
        if ($this->isReadonly($user)) {
            if (in_array($action, ['delete', 'rename', 'write', 'upload', 'mkdir', 'move'])) {
                return false;
            }
        }
        
        // Upload-only users can't delete/rename
        if ($this->isUploadOnly($user)) {
            if (in_array($action, ['delete', 'rename', 'write'])) {
                return false;
            }
        }
        
        // Managers can't delete
        if ($this->isManager($user)) {
            if (in_array($action, ['delete'])) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Log action
     */
    private function log($action, $user, $details) {
        if ($this->logger) {
            $this->logger->log($action, $user, $details);
        }
    }
}
