<?php
/**
 * TinyFileManager - Upload Handler
 * Handles file uploads with security, validation, and chunking support
 */

class TFM_UploadHandler {
    private $root_path;
    private $logger;
    private $user;
    private $max_size;
    private $chunk_size;
    private $allowed_extensions = '';
    
    public function __construct($root_path, $logger = null, $max_size = 5000000000, $chunk_size = 5242880, $allowed_ext = '') {
        $this->root_path = rtrim($root_path, '/\\');
        $this->logger = $logger;
        $this->user = tfm_get_user();
        $this->max_size = $max_size;
        $this->chunk_size = $chunk_size;
        $this->allowed_extensions = $allowed_ext;
    }
    
    /**
     * Process file upload
     */
    public function upload($path = '', $files = null) {
        if (!$files) {
            $files = $_FILES;
        }
        
        if (empty($files) || !isset($files['file'])) {
            return ['status' => 'error', 'message' => 'No file uploaded'];
        }
        
        // Build target directory
        $target_dir = $this->root_path;
        if (!empty($path)) {
            $path = fm_clean_path($path);
            if (!fm_validate_filepath($this->root_path . '/' . $path, $this->root_path)) {
                $this->log('upload_blocked', 'Path traversal attempt');
                return ['status' => 'error', 'message' => 'Invalid path'];
            }
            $target_dir .= '/' . $path;
        }
        
        // Ensure directory exists and is writable
        if (!is_dir($target_dir)) {
            if (!@mkdir($target_dir, 0755, true)) {
                $this->log('upload_error', 'Failed to create directory');
                return ['status' => 'error', 'message' => 'Cannot create directory'];
            }
        }
        
        if (!is_writable($target_dir)) {
            $this->log('upload_blocked', 'Directory not writable');
            return ['status' => 'error', 'message' => 'Directory not writable'];
        }
        
        // Get file info
        $filename = $files['file']['name'];
        $tmp_name = $files['file']['tmp_name'];
        $error = $files['file']['error'] ?? UPLOAD_ERR_NO_FILE;
        
        // Check upload errors
        if ($error !== UPLOAD_ERR_OK) {
            $error_msgs = [
                UPLOAD_ERR_INI_SIZE => 'File exceeds upload_max_filesize',
                UPLOAD_ERR_FORM_SIZE => 'File exceeds form MAX_FILE_SIZE',
                UPLOAD_ERR_PARTIAL => 'File was only partially uploaded',
                UPLOAD_ERR_NO_FILE => 'No file was uploaded',
                UPLOAD_ERR_NO_TMP_DIR => 'Missing temporary directory',
                UPLOAD_ERR_CANT_WRITE => 'Failed to write file',
                UPLOAD_ERR_EXTENSION => 'Upload extension blocked by server',
            ];
            $msg = $error_msgs[$error] ?? 'Unknown upload error';
            $this->log('upload_error', $msg);
            return ['status' => 'error', 'message' => $msg];
        }
        
        // Validate filename
        if (!fm_isvalid_filename($filename)) {
            $this->log('upload_blocked', "Invalid filename: $filename");
            return ['status' => 'error', 'message' => 'Invalid filename'];
        }
        
        // Validate extension
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        if (!$this->isValidExtension($ext)) {
            $this->log('upload_blocked', "Extension not allowed: $ext");
            return ['status' => 'error', 'message' => 'File extension not allowed'];
        }
        
        // Validate MIME type
        if (function_exists('fm_validate_mime_type')) {
            if (!fm_validate_mime_type($tmp_name)) {
                $this->log('upload_rejected', "Dangerous MIME: $filename");
                @unlink($tmp_name);
                return ['status' => 'error', 'message' => 'Dangerous file MIME type'];
            }
        }
        
        // Validate magic bytes
        if (function_exists('fm_validate_magic_bytes')) {
            if (!fm_validate_magic_bytes($tmp_name, $ext)) {
                $this->log('upload_rejected', "Invalid magic bytes: $filename");
                @unlink($tmp_name);
                return ['status' => 'error', 'message' => 'File signature does not match extension'];
            }
        }
        
        // Check file size
        $file_size = filesize($tmp_name);
        if ($file_size > $this->max_size) {
            $this->log('upload_rejected', "File too large: " . fm_get_filesize($file_size));
            @unlink($tmp_name);
            return ['status' => 'error', 'message' => 'File too large'];
        }
        
        // Generate safe filename if duplicate exists
        $target_file = $target_dir . '/' . $filename;
        if (file_exists($target_file)) {
            $basename = pathinfo($filename, PATHINFO_FILENAME);
            $ext = pathinfo($filename, PATHINFO_EXTENSION);
            $timestamp = date('YmdHis');
            $filename = "{$basename}_{$timestamp}.{$ext}";
            $target_file = $target_dir . '/' . $filename;
        }
        
        // Move uploaded file
        try {
            if (!@move_uploaded_file($tmp_name, $target_file)) {
                $this->log('upload_failed', "move_uploaded_file failed: $filename");
                return ['status' => 'error', 'message' => 'Failed to save file'];
            }
            
            // Set proper permissions
            @chmod($target_file, 0644);
            
            // Log successful upload
            $this->log('upload_success', "File uploaded: $filename");
            
            return [
                'status' => 'success',
                'message' => 'File uploaded successfully',
                'filename' => $filename,
                'size' => $file_size
            ];
        } catch (Exception $e) {
            $this->log('upload_error', $e->getMessage());
            @unlink($tmp_name);
            return ['status' => 'error', 'message' => $e->getMessage()];
        }
    }
    
    /**
     * Check if file extension is allowed
     */
    private function isValidExtension($ext) {
        if (empty($this->allowed_extensions)) {
            return true;
        }
        
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

// Helper function
function fm_get_filesize($bytes) {
    $units = ['B', 'KB', 'MB', 'GB'];
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= (1 << (10 * $pow));
    return round($bytes, 2) . ' ' . $units[$pow];
}
