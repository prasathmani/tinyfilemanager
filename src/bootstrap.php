<?php
/**
 * TinyFileManager - Bootstrap & Initialization
 * Handles application initialization, autoloading, and core setup
 */

class Bootstrap {
    private static $initialized = false;
    public static $config = [];
    public static $logger = null;
    public static $rate_limiter = null;
    
    /**
     * Initialize the application
     */
    public static function init() {
        if (self::$initialized) {
            return;
        }
        
        // Set error handling
        error_reporting(E_ALL);
        ini_set('display_errors', getenv('TFM_DEV') ? 1 : 0);
        
        // Set default timezone
        date_default_timezone_set('UTC');
        
        // Session configuration
        ini_set('session.name', 'tinyfilemanager');
        ini_set('session.cookie_httponly', 1);
        ini_set('session.cookie_secure', isset($_SERVER['HTTPS']) ? 1 : 0);
        ini_set('session.cookie_samesite', 'Lax');
        
        // Start session
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        // Register autoloader
        spl_autoload_register([self::class, 'autoload']);
        
        // Load security layer
        if (file_exists(__DIR__ . '/security.php')) {
            require_once __DIR__ . '/security.php';
        }
        
        // Initialize core services
        self::initializeServices();
        
        self::$initialized = true;
    }
    
    /**
     * Autoloader for src/ modules
     */
    public static function autoload($class) {
        // Only autoload our own classes
        if (strpos($class, 'TFM\\') !== 0) {
            return;
        }
        
        // Remove TFM\ prefix
        $class = str_replace('TFM\\', '', $class);
        
        // Convert class name to file path
        $file = __DIR__ . '/' . str_replace('\\', '/', $class) . '.php';
        
        if (file_exists($file)) {
            require_once $file;
        }
    }
    
    /**
     * Initialize core services
     */
    private static function initializeServices() {
        // Initialize logger
        if (class_exists('AuditLogger')) {
            self::$logger = new AuditLogger();
        }
        
        // Initialize rate limiter
        if (class_exists('RateLimiter')) {
            self::$rate_limiter = new RateLimiter();
        }
    }
    
    /**
     * Get logger instance
     */
    public static function getLogger() {
        return self::$logger;
    }
    
    /**
     * Get rate limiter instance
     */
    public static function getRateLimiter() {
        return self::$rate_limiter;
    }
    
    /**
     * Log an action
     */
    public static function log($action, $user = '', $details = '') {
        if (self::$logger) {
            self::$logger->log($action, $user, $details);
        }
    }
    
    /**
     * Set configuration value
     */
    public static function setConfig($key, $value) {
        self::$config[$key] = $value;
    }
    
    /**
     * Get configuration value
     */
    public static function getConfig($key, $default = null) {
        return self::$config[$key] ?? $default;
    }
    
    /**
     * Check if app is initialized
     */
    public static function isInitialized() {
        return self::$initialized;
    }
}

/**
 * Helper to check if user is authenticated
 */
function tfm_is_logged_in() {
    return isset($_SESSION['fm_logged']) && !empty($_SESSION['fm_logged']);
}

/**
 * Helper to get current user
 */
function tfm_get_user() {
    return $_SESSION['fm_logged'] ?? 'guest';
}

/**
 * Helper to redirect
 */
function tfm_redirect($url) {
    header('Location: ' . $url);
    exit;
}

/**
 * Helper to log
 */
function tfm_log($action, $user = '', $details = '') {
    Bootstrap::log($action, $user, $details);
}

/**
 * Helper to check CSRF token
 */
function tfm_verify_token($token = null) {
    if (!$token) {
        $token = $_POST['token'] ?? $_GET['token'] ?? '';
    }
    
    if (empty($_SESSION['token'])) {
        return false;
    }
    
    return hash_equals($_SESSION['token'], $token);
}

/**
 * Helper to get CSRF token
 */
function tfm_get_token() {
    if (empty($_SESSION['token'])) {
        if (function_exists('random_bytes')) {
            $_SESSION['token'] = bin2hex(random_bytes(32));
        } else {
            $_SESSION['token'] = bin2hex(openssl_random_pseudo_bytes(32));
        }
    }
    return $_SESSION['token'];
}

/**
 * Safe include helper
 */
function tfm_include_safe($file) {
    if (is_readable($file) && fnmatch('*.php', $file)) {
        include_once $file;
        return true;
    }
    return false;
}

// Initialize on include
Bootstrap::init();
