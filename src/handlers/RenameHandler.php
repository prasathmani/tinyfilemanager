<?php
/**
 * TinyFileManager - Rename Handler
 * Handles file and folder renaming with validation and logging
 */

class TFM_RenameHandler {
    private $root_path;
    private $logger;
    private $user;
    private $allowed_extensions = '';
    
    public function __construct($root_path, $logger = null, $allowed_extensions = '') {
        $this->root_path = rtrim($root_path, '/\\');
        $this->logger = $logger;
        $this->user = tfm_get_user();
        $this->allowed_extensions = $allowed_extensions;
    }
    
    /**
     * Rename a file or directory
     */
    public function rename($path, $old_name, $new_name) {
        // Validate inputs
        if (empty($old_name) || empty($new_name)) {
            return ['success' => false, 'error' => 'Invalid file names'];
        }
        
        if (in_array($old_name, ['.', '..']) || in_array($new_name, ['.', '..'])) {
            return ['success' => false, 'error' => 'Invalid file name'];
        }
        
        // Clean paths
        $old_name = str_replace('/', '', fm_clean_path($old_name));
        $new_name = str_replace('/', '', fm_clean_path(strip_tags($new_name)));
        
        // Validate new name
        if (!fm_isvalid_filename($new_name)) {
            $this->log('rename_blocked', "Invalid characters in: $new_name");
            return ['success' => false, 'error' => 'Invalid file name characters'];
        }
        
        // Build full paths
        $full_path_old = $this->root_path;
        if (!empty($path)) {
            $full_path_old .= '/' . fm_clean_path($path);
        }
        $full_path_old .= '/' . $old_name;
        
        $full_path_new = dirname($full_path_old) . '/' . $new_name;
        
        // Validate paths (prevent traversal)
        if (!fm_validate_filepath($full_path_old, $this->root_path)) {
            $this->log('rename_blocked', 'Path traversal attempt: ' . $full_path_old);
            return ['success' => false, 'error' => 'Access denied'];
        }
        
        if (!fm_validate_filepath($full_path_new, $this->root_path)) {
            $this->log('rename_blocked', 'Path traversal in new name: ' . $full_path_new);
            return ['success' => false, 'error' => 'Access denied'];
        }
        
        // Check if file exists
        if (!file_exists($full_path_old) && !is_dir($full_path_old)) {
            return ['success' => false, 'error' => 'File not found'];
        }
        
        // Check if new name already exists
        if (file_exists($full_path_new) || is_dir($full_path_new)) {
            $this->log('rename_blocked', "Target exists: $new_name");
            return ['success' => false, 'error' => 'Target file already exists'];
        }
        
        // Check file extensions for files
        if (is_file($full_path_old)) {
            if (!$this->isValidExtension($new_name)) {
                $this->log('rename_blocked', "Invalid extension: $new_name");
                return ['success' => false, 'error' => 'File extension not allowed'];
            }
        }
        
        // Log rename attempt
        $is_dir = is_dir($full_path_old);
        $type = $is_dir ? 'DIR' : 'FILE';
        $this->log('rename_attempt', "$type: $old_name -> $new_name");
        
        // Perform rename
        try {
            $success = @rename($full_path_old, $full_path_new);
            
            if ($success) {
                $msg = "Renamed: $old_name -> $new_name";
                $this->log('rename_success', $msg);
                return ['success' => true, 'message' => $msg];
            } else {
                $msg = "Failed to rename: $old_name";
                $this->log('rename_failed', $msg);
                return ['success' => false, 'error' => $msg];
            }
        } catch (Exception $e) {
            $this->log('rename_error', $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
    
    /**
     * Check if file extension is valid
     */
    private function isValidExtension($filename) {
        // If no restrictions, allow all
        if (empty($this->allowed_extensions)) {
            return true;
        }
        
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        $allowed = array_map('trim', explode(',', $this->allowed_extensions));
        
        return in_array($ext, $allowed);
    }
    
    /**
     * Log action
     */
    private function log($action, $details) {
        if ($this->logger) {
            $this->logger->log($action, $this->user, $details);
        }
    }
}
