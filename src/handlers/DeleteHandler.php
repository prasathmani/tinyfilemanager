<?php
/**
 * TinyFileManager - Delete Handler
 * Handles file and folder deletion with security checks and logging
 */

class TFM_DeleteHandler {
    private $root_path;
    private $logger;
    private $user;
    
    public function __construct($root_path, $logger = null) {
        $this->root_path = rtrim($root_path, '/\\');
        $this->logger = $logger;
        $this->user = tfm_get_user();
    }
    
    /**
     * Delete a file or directory
     */
    public function delete($path, $name) {
        // Validate inputs
        if (empty($name) || in_array($name, ['.', '..'])) {
            return ['success' => false, 'error' => 'Invalid file name'];
        }
        
        // Clean path
        $name = str_replace('/', '', fm_clean_path($name));
        
        // Build full path
        $full_path = $this->root_path;
        if (!empty($path)) {
            $full_path .= '/' . fm_clean_path($path);
        }
        $full_path .= '/' . $name;
        
        // Validate path (prevent traversal)
        if (!fm_validate_filepath($full_path, $this->root_path)) {
            $this->log('delete_blocked', 'Path traversal attempt: ' . $full_path);
            return ['success' => false, 'error' => 'Access denied'];
        }
        
        // Check if file/dir exists
        if (!file_exists($full_path) && !is_dir($full_path)) {
            return ['success' => false, 'error' => 'File not found'];
        }
        
        // Log deletion attempt
        $is_dir = is_dir($full_path);
        $type = $is_dir ? 'DIR' : 'FILE';
        $this->log('delete_attempt', "$type: $name");
        
        // Perform deletion
        try {
            if (is_dir($full_path)) {
                $success = fm_rdelete($full_path);
                $msg = $success ? "Folder deleted: $name" : "Failed to delete folder: $name";
            } else {
                $success = @unlink($full_path);
                $msg = $success ? "File deleted: $name" : "Failed to delete file: $name";
            }
            
            if ($success) {
                $this->log('delete_success', $msg);
                return ['success' => true, 'message' => $msg];
            } else {
                $this->log('delete_failed', $msg);
                return ['success' => false, 'error' => $msg];
            }
        } catch (Exception $e) {
            $this->log('delete_error', $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
    
    /**
     * Delete multiple files/directories
     */
    public function deleteMultiple($path, $names) {
        if (!is_array($names)) {
            $names = [$names];
        }
        
        $results = [];
        foreach ($names as $name) {
            $results[] = $this->delete($path, $name);
        }
        
        return $results;
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
