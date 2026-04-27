<?php
/**
 * TinyFileManager - Request Router
 * Central dispatcher for all file manager operations
 * Routes requests to appropriate handlers and manages responses
 */

class TFM_Router {
    private $root_path;
    private $config = [];
    private $request = [];
    private $response = [];
    private $logger = null;
    private $handlers = [];
    
    // Supported action handlers
    private $actions = [
        'list'   => 'listDirectory',
        'delete' => 'handleDelete',
        'rename' => 'handleRename',
        'upload' => 'handleUpload',
        'info'   => 'handleFileInfo',
        'read'   => 'handleReadFile',
        'write'  => 'handleWriteFile',
        'mkdir'  => 'handleMakeDir',
        'copy'   => 'handleCopy',
        'move'   => 'handleMove',
        'download' => 'handleDownload',
    ];
    
    public function __construct($root_path, $logger = null) {
        $this->root_path = rtrim($root_path, '/\\');
        $this->logger = $logger;
        
        // Initialize handlers
        $this->initializeHandlers();
        
        // Parse request
        $this->parseRequest();
    }
    
    /**
     * Initialize all handlers
     */
    private function initializeHandlers() {
        // File operations handlers
        $this->handlers['delete'] = new TFM_DeleteHandler($this->root_path, $this->logger);
        $this->handlers['rename'] = new TFM_RenameHandler($this->root_path, $this->logger);
        $this->handlers['upload'] = new TFM_UploadHandler(
            $this->root_path,
            $this->logger,
            $this->config['max_upload_size'] ?? 5000000000,
            $this->config['chunk_size'] ?? 5242880,
            $this->config['allowed_extensions'] ?? ''
        );
        
        // File manager service
        $this->handlers['fm'] = new TFM_FileManager($this->root_path, $this->logger);
    }
    
    /**
     * Parse incoming request
     */
    private function parseRequest() {
        $this->request = [
            'method' => $_SERVER['REQUEST_METHOD'],
            'action' => $_GET['action'] ?? $_POST['action'] ?? 'list',
            'path' => $_GET['p'] ?? $_POST['p'] ?? '',
            'file' => $_GET['file'] ?? $_POST['file'] ?? '',
            'token' => $_GET['token'] ?? $_POST['token'] ?? '',
            'data' => $_POST,
            'json' => $this->parseJsonInput(),
        ];
    }
    
    /**
     * Parse JSON input from request body
     */
    private function parseJsonInput() {
        if (in_array($_SERVER['CONTENT_TYPE'] ?? '', ['application/json', 'application/json; charset=utf-8'])) {
            $input = file_get_contents('php://input');
            return json_decode($input, true) ?? [];
        }
        return [];
    }
    
    /**
     * Route request to appropriate handler
     */
    public function dispatch() {
        try {
            // Validate CSRF token for state-changing operations
            if (!in_array($this->request['action'], ['list', 'info', 'read', 'download'])) {
                if (!tfm_verify_token($this->request['token'])) {
                    $this->respond(['error' => 'Invalid CSRF token'], 403);
                }
            }
            
            // Check if action is supported
            if (!isset($this->actions[$this->request['action']])) {
                $this->respond(['error' => 'Unknown action: ' . $this->request['action']], 400);
            }
            
            // Call action handler
            $method = $this->actions[$this->request['action']];
            if (method_exists($this, $method)) {
                $this->$method();
            } else {
                $this->respond(['error' => 'Handler not implemented'], 501);
            }
            
        } catch (Exception $e) {
            $this->log('router_error', $e->getMessage());
            $this->respond(['error' => $e->getMessage()], 500);
        }
    }
    
    /**
     * List directory contents
     */
    private function listDirectory() {
        try {
            /** @var TFM_FileManager $fm */
            $fm = $this->handlers['fm'];
            $fm->setPath($this->request['path']);
            
            $contents = $fm->listDirectory();
            $this->respond(['success' => true, 'data' => $contents], 200);
            
        } catch (Exception $e) {
            $this->respond(['error' => $e->getMessage()], 400);
        }
    }
    
    /**
     * Handle file deletion
     */
    private function handleDelete() {
        try {
            if (empty($this->request['file'])) {
                throw new Exception('No file specified');
            }
            
            /** @var TFM_DeleteHandler $handler */
            $handler = $this->handlers['delete'];
            $result = $handler->delete($this->request['path'], $this->request['file']);
            
            if ($result['success']) {
                $this->respond(['success' => true, 'message' => $result['message']], 200);
            } else {
                $this->respond(['error' => $result['error']], 400);
            }
            
        } catch (Exception $e) {
            $this->respond(['error' => $e->getMessage()], 400);
        }
    }
    
    /**
     * Handle file rename
     */
    private function handleRename() {
        try {
            $old_name = $this->request['data']['oldname'] ?? $this->request['file'] ?? '';
            $new_name = $this->request['data']['newname'] ?? '';
            
            if (!$old_name || !$new_name) {
                throw new Exception('Old and new filenames required');
            }
            
            /** @var TFM_RenameHandler $handler */
            $handler = $this->handlers['rename'];
            $result = $handler->rename($this->request['path'], $old_name, $new_name);
            
            if ($result['success']) {
                $this->respond(['success' => true, 'message' => $result['message']], 200);
            } else {
                $this->respond(['error' => $result['error']], 400);
            }
            
        } catch (Exception $e) {
            $this->respond(['error' => $e->getMessage()], 400);
        }
    }
    
    /**
     * Handle file upload
     */
    private function handleUpload() {
        try {
            if (empty($_FILES)) {
                throw new Exception('No file uploaded');
            }
            
            /** @var TFM_UploadHandler $handler */
            $handler = $this->handlers['upload'];
            $result = $handler->upload($this->request['path'], $_FILES);
            
            $code = ($result['status'] === 'success') ? 200 : 400;
            $this->respond($result, $code);
            
        } catch (Exception $e) {
            $this->respond(['error' => $e->getMessage()], 400);
        }
    }
    
    /**
     * Handle get file info
     */
    private function handleFileInfo() {
        try {
            if (empty($this->request['file'])) {
                throw new Exception('No file specified');
            }
            
            /** @var TFM_FileManager $fm */
            $fm = $this->handlers['fm'];
            $fm->setPath($this->request['path']);
            
            $info = $fm->getFileInfo($this->request['file']);
            $this->respond(['success' => true, 'data' => $info], 200);
            
        } catch (Exception $e) {
            $this->respond(['error' => $e->getMessage()], 400);
        }
    }
    
    /**
     * Handle read file
     */
    private function handleReadFile() {
        try {
            if (empty($this->request['file'])) {
                throw new Exception('No file specified');
            }
            
            /** @var TFM_FileManager $fm */
            $fm = $this->handlers['fm'];
            $fm->setPath($this->request['path']);
            
            $limit = $this->request['data']['limit'] ?? null;
            $content = $fm->readFile($this->request['file'], $limit);
            
            $this->respond([
                'success' => true,
                'file' => $this->request['file'],
                'content' => $content
            ], 200);
            
        } catch (Exception $e) {
            $this->respond(['error' => $e->getMessage()], 400);
        }
    }
    
    /**
     * Handle write file
     */
    private function handleWriteFile() {
        try {
            $file = $this->request['data']['file'] ?? '';
            $content = $this->request['data']['content'] ?? '';
            
            if (!$file) {
                throw new Exception('No file specified');
            }
            
            /** @var TFM_FileManager $fm */
            $fm = $this->handlers['fm'];
            $fm->setPath($this->request['path']);
            
            $fm->writeFile($file, $content);
            $this->respond(['success' => true, 'message' => 'File written'], 200);
            
        } catch (Exception $e) {
            $this->respond(['error' => $e->getMessage()], 400);
        }
    }
    
    /**
     * Handle create directory
     */
    private function handleMakeDir() {
        try {
            $dirname = $this->request['data']['name'] ?? '';
            
            if (!$dirname) {
                throw new Exception('No directory name specified');
            }
            
            /** @var TFM_FileManager $fm */
            $fm = $this->handlers['fm'];
            $fm->setPath($this->request['path']);
            
            $fm->createDirectory($dirname);
            $this->respond(['success' => true, 'message' => 'Directory created'], 201);
            
        } catch (Exception $e) {
            $this->respond(['error' => $e->getMessage()], 400);
        }
    }
    
    /**
     * Handle copy file
     */
    private function handleCopy() {
        try {
            if (empty($this->request['file'])) {
                throw new Exception('No file specified');
            }
            
            /** @var TFM_FileManager $fm */
            $fm = $this->handlers['fm'];
            $fm->setPath($this->request['path']);
            
            // Get source file info
            $info = $fm->getFileInfo($this->request['file']);
            $source_path = $fm->getFullPath($this->request['file']);
            
            // Generate copy name
            $copy_name = $this->generateCopyName($this->request['file']);
            
            // Copy file
            if (!copy($source_path, $fm->getFullPath($copy_name))) {
                throw new Exception('Failed to copy file');
            }
            
            $this->log('file_copy', "Copied: {$this->request['file']} -> {$copy_name}");
            $this->respond([
                'success' => true,
                'message' => 'File copied',
                'new_file' => $copy_name
            ], 201);
            
        } catch (Exception $e) {
            $this->respond(['error' => $e->getMessage()], 400);
        }
    }
    
    /**
     * Handle move file
     */
    private function handleMove() {
        try {
            if (empty($this->request['file'])) {
                throw new Exception('No file specified');
            }
            
            $target_path = $this->request['data']['target'] ?? '';
            if (!$target_path) {
                throw new Exception('No target path specified');
            }
            
            /** @var TFM_FileManager $fm */
            $fm = $this->handlers['fm'];
            $fm->setPath($this->request['path']);
            
            // TODO: Implement move logic
            throw new Exception('Move operation not yet implemented');
            
        } catch (Exception $e) {
            $this->respond(['error' => $e->getMessage()], 400);
        }
    }
    
    /**
     * Handle file download
     */
    private function handleDownload() {
        try {
            if (empty($this->request['file'])) {
                throw new Exception('No file specified');
            }
            
            /** @var TFM_FileManager $fm */
            $fm = $this->handlers['fm'];
            $fm->setPath($this->request['path']);
            
            $full_path = $fm->getFullPath($this->request['file']);
            
            if (!file_exists($full_path)) {
                throw new Exception('File not found');
            }
            
            $this->log('file_download', "Downloaded: {$this->request['file']}");
            
            // Send file
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename=' . basename($this->request['file']));
            header('Content-Length: ' . filesize($full_path));
            readfile($full_path);
            exit;
            
        } catch (Exception $e) {
            $this->respond(['error' => $e->getMessage()], 400);
        }
    }
    
    /**
     * Generate unique copy filename
     */
    private function generateCopyName($filename) {
        $info = pathinfo($filename);
        $ext = isset($info['extension']) ? '.' . $info['extension'] : '';
        $name = $info['filename'];
        
        $copy_name = $name . '_copy' . $ext;
        $counter = 1;
        
        /** @var TFM_FileManager $fm */
        $fm = $this->handlers['fm'];
        
        while (@file_exists($fm->getFullPath($copy_name))) {
            $copy_name = $name . '_copy_' . $counter . $ext;
            $counter++;
        }
        
        return $copy_name;
    }
    
    /**
     * Send response
     */
    private function respond($data, $code = 200) {
        header('Content-Type: application/json; charset=utf-8');
        http_response_code($code);
        echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        exit;
    }
    
    /**
     * Log action
     */
    private function log($action, $details) {
        if ($this->logger) {
            $user = tfm_get_user();
            $this->logger->log($action, $user, $details);
        }
    }
    
    /**
     * Get response data
     */
    public function getResponse() {
        return $this->response;
    }
}
