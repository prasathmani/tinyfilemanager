<?php
/**
 * TinyFileManager - Security Layer
 * Handles validation, rate limiting, logging, and file security
 */

// Magic bytes signatures for common file types
const MAGIC_BYTES = [
    // Images
    'jpg' => ['\xFF\xD8\xFF\xE0', '\xFF\xD8\xFF\xE1', '\xFF\xD8\xFF\xEE'],
    'png' => ['\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'],
    'gif' => ['\x47\x49\x46\x38\x37\x61', '\x47\x49\x46\x38\x39\x61'],
    'webp' => ['\x52\x49\x46\x46.*\x57\x45\x42\x50'],
    'bmp' => ['\x42\x4D'],
    'ico' => ['\x00\x00\x01\x00'],
    
    // Documents
    'pdf' => ['\x25\x50\x44\x46'],
    'zip' => ['\x50\x4B\x03\x04', '\x50\x4B\x05\x06', '\x50\x4B\x07\x08'],
    'tar' => 'ustar',
    'gzip' => ['\x1F\x8B'],
    
    // Videos
    'mp4' => 'ftyp',
    'webm' => ['\x1A\x45\xDF\xA3'],
    
    // Audio
    'mp3' => ['\xFF\xFB', '\xFF\xFA', '\x49\x44\x33'],
    'wav' => ['\x52\x49\x46\x46.*\x57\x41\x56\x45'],
];

/**
 * Validate file by magic bytes (file signature)
 */
function fm_validate_magic_bytes($filepath, $ext) {
    if (!is_file($filepath) || !is_readable($filepath)) {
        return false;
    }
    
    $ext = strtolower($ext);
    
    // Extensions without strict validation
    $no_validation = ['txt', 'md', 'html', 'xml', 'json', 'csv', 'js', 'css'];
    if (in_array($ext, $no_validation)) {
        return true;
    }
    
    if (!isset(MAGIC_BYTES[$ext])) {
        return false; // Unknown file type
    }
    
    $signatures = MAGIC_BYTES[$ext];
    if (!is_array($signatures)) {
        $signatures = [$signatures];
    }
    
    // Read file header
    $handle = fopen($filepath, 'rb');
    if (!$handle) {
        return false;
    }
    
    $header = fread($handle, 12);
    fclose($handle);
    
    foreach ($signatures as $sig) {
        if (strpos($sig, '*') !== false) {
            // Wildcard pattern (simple regex)
            $pattern = str_replace('*', '.', preg_quote($sig, '/'));
            if (preg_match("/$pattern/", $header)) {
                return true;
            }
        } else {
            // Exact match
            if (strpos($header, $sig) === 0) {
                return true;
            }
        }
    }
    
    return false;
}

/**
 * Validate MIME type using finfo
 */
function fm_validate_mime_type($filepath, $allowed_types = []) {
    if (!function_exists('finfo_file')) {
        return true; // Skip if finfo not available
    }
    
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    if (!$finfo) {
        return true;
    }
    
    $mime = finfo_file($finfo, $filepath);
    finfo_close($finfo);
    
    if (empty($allowed_types)) {
        return true; // No restriction
    }
    
    // Check for executable MIME types
    $dangerous = ['application/x-php', 'application/x-executable', 'application/x-sh', 'application/x-perl'];
    if (in_array($mime, $dangerous)) {
        return false;
    }
    
    return in_array($mime, $allowed_types);
}

/**
 * Enhanced file path validation with strict checks
 */
function fm_validate_filepath($path, $root_path) {
    // Get real paths
    $real_root = realpath($root_path);
    $real_file = realpath($path);
    
    if ($real_root === false || $real_file === false) {
        return false;
    }
    
    // Check if file is within root
    if (strpos($real_file, $real_root) !== 0 && $real_file !== $real_root) {
        return false; // Path traversal detected
    }
    
    return true;
}

/**
 * Rate limiter for login attempts
 */
class RateLimiter {
    private $storage_file;
    private $max_attempts = 5;
    private $lockout_time = 900; // 15 minutes
    
    public function __construct($storage_dir = null) {
        if (!$storage_dir) {
            $storage_dir = sys_get_temp_dir();
        }
        $this->storage_file = $storage_dir . '/tfm_ratelimit.json';
    }
    
    public function check_limit($key) {
        $limits = $this->load_limits();
        $ip = $this->get_client_ip();
        $identifier = md5($ip . ':' . $key);
        
        if (isset($limits[$identifier])) {
            $data = $limits[$identifier];
            
            // Check if lockout expired
            if (time() - $data['first_attempt'] > $this->lockout_time) {
                unset($limits[$identifier]);
                $this->save_limits($limits);
                return true;
            }
            
            // Check attempt count
            if ($data['attempts'] >= $this->max_attempts) {
                return false; // Locked out
            }
        }
        
        return true; // Not limited
    }
    
    public function record_attempt($key) {
        $limits = $this->load_limits();
        $ip = $this->get_client_ip();
        $identifier = md5($ip . ':' . $key);
        
        if (!isset($limits[$identifier])) {
            $limits[$identifier] = [
                'first_attempt' => time(),
                'attempts' => 0
            ];
        }
        
        $limits[$identifier]['attempts']++;
        $this->save_limits($limits);
    }
    
    public function reset($key) {
        $limits = $this->load_limits();
        $ip = $this->get_client_ip();
        $identifier = md5($ip . ':' . $key);
        
        if (isset($limits[$identifier])) {
            unset($limits[$identifier]);
            $this->save_limits($limits);
        }
    }
    
    private function load_limits() {
        if (!file_exists($this->storage_file)) {
            return [];
        }
        $data = json_decode(file_get_contents($this->storage_file), true);
        return $data ?: [];
    }
    
    private function save_limits($limits) {
        @file_put_contents($this->storage_file, json_encode($limits), LOCK_EX);
        @chmod($this->storage_file, 0600);
    }
    
    private function get_client_ip() {
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            return $_SERVER['HTTP_CF_CONNECTING_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            return explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
        }
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
}

/**
 * Audit logger - log all important actions
 */
class AuditLogger {
    private $log_file;
    
    public function __construct($log_file = null) {
        if (!$log_file) {
            $log_file = sys_get_temp_dir() . '/tfm_audit.log';
        }
        $this->log_file = $log_file;
    }
    
    public function log($action, $user = '', $details = '') {
        $entry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'ip' => $this->get_client_ip(),
            'user' => $user ?: 'anonymous',
            'action' => $action,
            'details' => $details,
        ];
        
        $log_line = json_encode($entry) . "\n";
        @file_put_contents($this->log_file, $log_line, FILE_APPEND | LOCK_EX);
        @chmod($this->log_file, 0600);
    }
    
    public function get_logs($limit = 100, $filter = []) {
        if (!file_exists($this->log_file)) {
            return [];
        }
        
        $lines = file($this->log_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!$lines) {
            return [];
        }
        
        $logs = [];
        foreach (array_reverse($lines) as $line) {
            $entry = @json_decode($line, true);
            if (!$entry) continue;
            
            // Apply filters
            if (!empty($filter['user']) && $entry['user'] !== $filter['user']) continue;
            if (!empty($filter['action']) && $entry['action'] !== $filter['action']) continue;
            
            $logs[] = $entry;
            if (count($logs) >= $limit) break;
        }
        
        return $logs;
    }
    
    private function get_client_ip() {
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            return $_SERVER['HTTP_CF_CONNECTING_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            return explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
        }
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
}

/**
 * Session security - add timeout and validation
 */
class SessionManager {
    private $timeout = 3600; // 1 hour default
    
    public function __construct($timeout = 3600) {
        $this->timeout = $timeout;
    }
    
    public function validate_session() {
        $session_id = session_id();
        
        if (empty($_SESSION['__created__'])) {
            $_SESSION['__created__'] = time();
            $_SESSION['__ip__'] = $this->get_client_ip();
            $_SESSION['__user_agent__'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
            return true;
        }
        
        // Check timeout
        if (time() - $_SESSION['__created__'] > $this->timeout) {
            $this->destroy();
            return false;
        }
        
        // Check IP spoofing
        if ($_SESSION['__ip__'] !== $this->get_client_ip()) {
            $this->destroy();
            return false;
        }
        
        // Check User-Agent spoofing
        if (($_SERVER['HTTP_USER_AGENT'] ?? '') !== $_SESSION['__user_agent__']) {
            // Warn but don't destroy (UA can change)
        }
        
        return true;
    }
    
    public function destroy() {
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
        }
        session_destroy();
    }
    
    private function get_client_ip() {
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            return $_SERVER['HTTP_CF_CONNECTING_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            return explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
        }
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
}

/**
 * Input validation helper
 */
function fm_validate_input($input, $type = 'filename') {
    switch ($type) {
        case 'filename':
            // Remove dangerous characters
            $input = str_replace(['../', '..\\', "\x00"], '', $input);
            // Check for invalid characters
            if (preg_match('/[\/\\\?\%\*\:\"\<\>\|]/', $input)) {
                return false;
            }
            return $input;
            
        case 'path':
            $input = str_replace(['../', '..\\', "\x00"], '', $input);
            return $input;
            
        case 'username':
            return preg_match('/^[a-zA-Z0-9_\-\.]{3,32}$/', $input) ? $input : false;
            
        case 'email':
            return filter_var($input, FILTER_VALIDATE_EMAIL) ? $input : false;
            
        default:
            return $input;
    }
}

/**
 * Safe file deletion with logging
 */
function fm_safe_delete($filepath, $root_path, $logger = null) {
    // Validate path
    if (!fm_validate_filepath($filepath, $root_path)) {
        if ($logger) $logger->log('delete_failed', '', "Path traversal attempt: $filepath");
        return false;
    }
    
    // Log deletion
    if ($logger) {
        $logger->log('file_delete', '', basename($filepath));
    }
    
    // Safe delete
    if (is_file($filepath)) {
        return @unlink($filepath);
    } elseif (is_dir($filepath)) {
        return fm_rdelete($filepath);
    }
    
    return false;
}

/**
 * Generate secure download token (prevents direct access)
 */
function fm_create_download_token($file, $expiry = 300) {
    $token = [
        'file' => $file,
        'created' => time(),
        'expiry' => $expiry,
        'hash' => hash_hmac('sha256', $file . time(), $_SESSION['token'] ?? '')
    ];
    
    $_SESSION['download_tokens'] = $_SESSION['download_tokens'] ?? [];
    $_SESSION['download_tokens'][] = $token;
    
    return base64_encode(json_encode($token));
}

/**
 * Verify download token
 */
function fm_verify_download_token($token) {
    try {
        $data = json_decode(base64_decode($token), true);
        if (!$data) return false;
        
        if (time() - $data['created'] > $data['expiry']) {
            return false; // Expired
        }
        
        $expected_hash = hash_hmac('sha256', $data['file'] . date('Y-m-d H:i:00', $data['created']), $_SESSION['token'] ?? '');
        return hash_equals($data['hash'], $expected_hash) ? $data['file'] : false;
    } catch (Exception $e) {
        return false;
    }
}
