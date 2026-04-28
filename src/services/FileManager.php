<?php
/**
 * TinyFileManager - File Manager Service
 * Core file operations: list, read, write, copy, move, chmod, etc.
 */

class TFM_FileManager {
    private $root_path;
    private $current_path = '';
    private $logger;
    private $user;
    private $readonly = false;
    
    public function __construct($root_path, $logger = null, $readonly = false) {
        $this->root_path = rtrim($root_path, '/\\');
        $this->logger = $logger;
        $this->user = tfm_get_user();
        $this->readonly = $readonly;
        
        if (!is_dir($this->root_path)) {
            throw new Exception("Root path does not exist: $root_path");
        }
        }
    
    /**
     * Set current path
     */
    public function setPath($path) {
        $path = fm_clean_path($path);
        $full_path = $this->root_path . '/' . $path;
        
        if (!fm_validate_filepath($full_path, $this->root_path)) {
            throw new Exception("Invalid path: $path");
        }
        
        if (!is_dir($full_path) && !empty($path)) {
            throw new Exception("Directory not found: $path");
        }
        
        $this->current_path = $path;
    }
    
    /**
     * Get current path
     */
    public function getPath() {
        return $this->current_path;
    }
    
    /**
     * Get full path
     */
    public function getFullPath($relative = '') {
        $path = $this->root_path;
        if (!empty($this->current_path)) {
            $path .= '/' . $this->current_path;
        }
        if (!empty($relative)) {
            $path .= '/' . fm_clean_path($relative);
        }
        return $path;
    }
    
    /**
     * List directory contents
     */
    public function listDirectory($path = null) {
        if ($path !== null) {
            $this->setPath($path);
        }
        
        $full_path = $this->getFullPath();
        
        if (!is_dir($full_path)) {
            throw new Exception("Not a directory: $full_path");
        }
        
        $files = [];
        $folders = [];
        
        try {
            $items = @scandir($full_path);
            if ($items === false) {
                throw new Exception("Cannot read directory");
            }
            
            foreach ($items as $name) {
                if ($name === '.' || $name === '..') {
                    continue;
                }
                
                $item_path = $full_path . '/' . $name;
                
                // Skip if doesn't exist
                if (!file_exists($item_path) && !is_link($item_path)) {
                    continue;
                }
                
                $item_info = [
                    'name' => $name,
                    'type' => is_dir($item_path) ? 'dir' : 'file',
                    'size' => is_file($item_path) ? filesize($item_path) : 0,
                    'modified' => filemtime($item_path) ?: 0,
                    'perms' => substr(decoct(fileperms($item_path)), -4),
                ];
                
                if ($item_info['type'] === 'dir') {
                    $folders[] = $item_info;
                } else {
                    $files[] = $item_info;
                }
            }
            
            // Sort
            usort($folders, fn($a, $b) => strcasecmp($a['name'], $b['name']));
            usort($files, fn($a, $b) => strcasecmp($a['name'], $b['name']));
            
            return [
                'path' => $this->current_path,
                'folders' => $folders,
                'files' => $files,
                'total_folders' => count($folders),
                'total_files' => count($files),
            ];
        } catch (Exception $e) {
            $this->log('list_error', $e->getMessage());
            throw $e;
        }
    }
    
    /**
     * Get file info
     */
    public function getFileInfo($filename) {
        $full_path = $this->getFullPath($filename);
        
        if (!file_exists($full_path)) {
            throw new Exception("File not found: $filename");
        }
        
        $is_file = is_file($full_path);
        $is_dir = is_dir($full_path);
        
        $info = [
            'name' => basename($full_path),
            'path' => $this->current_path . '/' . $filename,
            'type' => $is_dir ? 'dir' : 'file',
            'size' => $is_file ? filesize($full_path) : 0,
            'modified' => filemtime($full_path) ?: 0,
            'created' => filectime($full_path) ?: 0,
            'perms' => substr(decoct(fileperms($full_path)), -4),
            'readable' => is_readable($full_path),
            'writable' => is_writable($full_path),
            'is_link' => is_link($full_path),
        ];
        
        if (is_link($full_path)) {
            $info['link_target'] = readlink($full_path);
        }
        
        if ($is_file) {
            $info['extension'] = strtolower(pathinfo($full_path, PATHINFO_EXTENSION));
            $info['mime'] = mime_content_type($full_path) ?? 'application/octet-stream';
        }
        
        return $info;
    }
    
    /**
     * Read file content
     */
    public function readFile($filename, $limit = null) {
        $full_path = $this->getFullPath($filename);
        
        if (!is_file($full_path)) {
            throw new Exception("File not found: $filename");
        }
        
        if (!is_readable($full_path)) {
            throw new Exception("File not readable: $filename");
        }
        
        $content = file_get_contents($full_path, false, null, 0, $limit);
        if ($content === false) {
            throw new Exception("Failed to read file: $filename");
        }
        
        $this->log('file_read', "File read: $filename");
        return $content;
    }
    
    /**
     * Write file content
     */
    public function writeFile($filename, $content) {
        if ($this->readonly) {
            throw new Exception("Read-only mode");
        }
        
        $full_path = $this->getFullPath($filename);
        
        // Ensure directory exists
        $dir = dirname($full_path);
        if (!is_dir($dir)) {
            if (!@mkdir($dir, 0755, true)) {
                throw new Exception("Failed to create directory");
            }
        }
        
        if (@file_put_contents($full_path, $content, LOCK_EX) === false) {
            throw new Exception("Failed to write file: $filename");
        }
        
        @chmod($full_path, 0644);
        $this->log('file_write', "File written: $filename");
        return true;
    }
    
    /**
     * Create directory
     */
    public function createDirectory($dirname) {
        if ($this->readonly) {
            throw new Exception("Read-only mode");
        }
        
        if (!fm_isvalid_filename($dirname)) {
            throw new Exception("Invalid directory name");
        }
        
        $full_path = $this->getFullPath($dirname);
        
        if (file_exists($full_path)) {
            throw new Exception("Directory already exists");
        }
        
        if (!@mkdir($full_path, 0755, true)) {
            throw new Exception("Failed to create directory");
        }
        
        $this->log('dir_create', "Directory created: $dirname");
        return true;
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
