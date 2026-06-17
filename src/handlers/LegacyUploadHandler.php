<?php
/**
 * TinyFileManager - Legacy Upload Handler
 * Incremental extraction that preserves the existing upload behavior.
 */

class TFM_LegacyUploadHandler {
    private $root_path;
    private $current_path;

    public function __construct($root_path, $current_path = '') {
        $this->root_path = rtrim((string) $root_path, '/\\');
        $this->current_path = (string) $current_path;
    }

    /**
     * Handle upload request and echo legacy JSON response.
     * @param array $files
     * @param array $post
     * @param array $request
     * @return void
     */
    public function handle($files, $post, $request) {
        if (isset($post['token'])) {
            if (!verifyToken($post['token'])) {
                echo json_encode(array('status' => 'error', 'info' => 'Invalid Token.'));
                exit();
            }
        } else {
            echo json_encode(array('status' => 'error', 'info' => 'Token Missing.'));
            exit();
        }

        $chunkIndex = isset($post['dzchunkindex']) ? $post['dzchunkindex'] : null;
        $chunkTotal = isset($post['dztotalchunkcount']) ? $post['dztotalchunkcount'] : null;
        $requestedUploadDir = fm_clean_path(isset($request['upload_dir']) ? $request['upload_dir'] : $this->current_path);
        $fullPathInput = fm_clean_path(isset($request['fullpath']) ? $request['fullpath'] : '');

        $f = $files;
        $ds = DIRECTORY_SEPARATOR;

        $allowed = (FM_UPLOAD_EXTENSION) ? explode(',', FM_UPLOAD_EXTENSION) : false;
        $response = array(
            'status' => 'error',
            'info'   => 'Oops! Try again'
        );

        $filename = isset($f['file']['name']) ? (string) $f['file']['name'] : '';
        $tmp_name = $f['file']['tmp_name'];
        $ext = pathinfo($filename, PATHINFO_FILENAME) != '' ? strtolower(pathinfo($filename, PATHINFO_EXTENSION)) : '';
        $isFileAllowed = ($allowed) ? in_array($ext, $allowed) : true;

        if ($filename === '' || !isset($f['file']['tmp_name'])) {
            $response = array(
                'status' => 'error',
                'info'   => 'No file received for upload.',
            );
            echo json_encode($response);
            exit();
        }

        $safeFileName = $this->sanitizeUploadFileName($fullPathInput !== '' ? $fullPathInput : $filename);
        if ($safeFileName === '') {
            $response = array(
                'status' => 'error',
                'info'   => 'Invalid file name for upload.',
            );
            echo json_encode($response);
            exit();
        }

        if (!fm_isvalid_filename($safeFileName)) {
            $response = array(
                'status' => 'error',
                'info'   => 'Invalid File name!',
            );
            echo json_encode($response);
            exit();
        }

        $targetPath = $this->resolveUploadBasePath($requestedUploadDir);
        if ($targetPath === null) {
            $response = array(
                'status' => 'error',
                'info'   => 'Upload target path is not allowed.',
            );
            echo json_encode($response);
            exit();
        }

        if (function_exists('fm_validate_mime_type')) {
            if (!fm_validate_mime_type($tmp_name)) {
                if (class_exists('AuditLogger')) {
                    $audit = new AuditLogger();
                    $audit->log('upload_rejected', $_SESSION[FM_SESSION_ID]['logged'] ?? 'unknown', "Dangerous MIME type: $filename");
                }
                $response = array(
                    'status' => 'error',
                    'info'   => 'Dangerous file MIME type detected!',
                );
                echo json_encode($response);
                @unlink($tmp_name);
                exit();
            }
        }

        if (function_exists('fm_validate_magic_bytes')) {
            if (!fm_validate_magic_bytes($tmp_name, $ext)) {
                if (class_exists('AuditLogger')) {
                    $audit = new AuditLogger();
                    $audit->log('upload_rejected', $_SESSION[FM_SESSION_ID]['logged'] ?? 'unknown', "Invalid magic bytes: $filename (ext: $ext)");
                }
                $response = array(
                    'status' => 'error',
                    'info'   => 'File signature does not match extension!',
                );
                echo json_encode($response);
                @unlink($tmp_name);
                exit();
            }
        }

        $targetPath = rtrim($targetPath, '/\\') . $ds;
        if (is_writable($targetPath)) {
            $fullPath = rtrim($targetPath, '/\\') . '/' . $safeFileName;
            $folder = substr($fullPath, 0, strrpos($fullPath, '/'));

            if (!is_dir($folder)) {
                $old = umask(0);
                if (!@mkdir($folder, 0777, true) && !is_dir($folder)) {
                    $response = array(
                        'status' => 'error',
                        'info'   => 'Unable to create upload destination folder.',
                    );
                    echo json_encode($response);
                    exit();
                }
                umask($old);
            }

            if (empty($f['file']['error']) && !empty($tmp_name) && $tmp_name != 'none' && $isFileAllowed) {
                if ($chunkTotal) {
                    $out = @fopen("{$fullPath}.part", $chunkIndex == 0 ? 'wb' : 'ab');
                    if ($out) {
                        $in = @fopen($tmp_name, 'rb');
                        if ($in) {
                            if (PHP_VERSION_ID < 80009) {
                                do {
                                    for (;;) {
                                        $buff = fread($in, 4096);
                                        if ($buff === false || $buff === '') {
                                            break;
                                        }
                                        fwrite($out, $buff);
                                    }
                                } while (!feof($in));
                            } else {
                                stream_copy_to_stream($in, $out);
                            }
                            $response = array(
                                'status' => 'success',
                                'info'   => 'file upload successful'
                            );
                        } else {
                            $response = array(
                                'status' => 'error',
                                'info'   => 'failed to open output stream',
                                'errorDetails' => error_get_last()
                            );
                        }
                        @fclose($in);
                        @fclose($out);
                        @unlink($tmp_name);

                        $response = array(
                            'status' => 'success',
                            'info'   => 'file upload successful'
                        );
                    } else {
                        $response = array(
                            'status' => 'error',
                            'info'   => 'failed to open output stream'
                        );
                    }

                    if ($chunkIndex == $chunkTotal - 1) {
                        if (file_exists($fullPath)) {
                            $ext_1 = $ext ? '.' . $ext : '';
                            $fullPathTarget = rtrim($targetPath, '/\\') . '/' . basename($safeFileName, $ext_1) . '_' . date('ymdHis') . $ext_1;
                        } else {
                            $fullPathTarget = $fullPath;
                        }
                        if (rename("{$fullPath}.part", $fullPathTarget) && function_exists('fm_owner_meta_touch')) {
                            fm_owner_meta_touch($fullPathTarget, 'upload');
                        }
                    }
                } else if (move_uploaded_file($tmp_name, $fullPath)) {
                    if (file_exists($fullPath)) {
                        if (function_exists('fm_owner_meta_touch')) {
                            fm_owner_meta_touch($fullPath, 'upload');
                        }
                        $response = array(
                            'status' => 'success',
                            'info'   => 'file upload successful'
                        );
                    } else {
                        $response = array(
                            'status' => 'error',
                            'info'   => 'Couldn\'t upload the requested file.'
                        );
                    }
                } else {
                    $response = array(
                        'status' => 'error',
                        'info'   => 'Error while moving uploaded file to destination.',
                    );
                }
            }
        } else {
            $response = array(
                'status' => 'error',
                'info'   => 'The specified folder for upload is not writable.'
            );
        }

        echo json_encode($response);
        exit();
    }

    /**
     * Handle upload-via-URL request and echo legacy JSON response.
     * @param array $request
     * @return void
     */
    public function handleUrlUpload($request) {
        $url = isset($request['uploadurl']) ? trim((string) stripslashes((string) $request['uploadurl'])) : '';
        $uploadDir = isset($request['upload_dir']) ? fm_clean_path((string) $request['upload_dir']) : $this->current_path;

        if ($url === '' || !filter_var($url, FILTER_VALIDATE_URL)) {
            $this->emitUrlUploadEvent(array('fail' => array('message' => 'Invalid URL parameter.')));
            exit();
        }

        if (!$this->isAllowedRemoteUrl($url)) {
            $this->emitUrlUploadEvent(array('fail' => array('message' => 'URL is not allowed.')));
            exit();
        }

        $targetBase = $this->resolveUploadBasePath($uploadDir);
        if ($targetBase === null || !is_dir($targetBase) || !is_writable($targetBase)) {
            $this->emitUrlUploadEvent(array('fail' => array('message' => 'Upload target path is not writable.')));
            exit();
        }

        $tempFile = tempnam(sys_get_temp_dir(), 'url-upload-');
        if ($tempFile === false) {
            $this->emitUrlUploadEvent(array('fail' => array('message' => 'Cannot create temporary file for download.')));
            exit();
        }

        $downloadResult = $this->downloadRemoteFile($url, $tempFile);
        if (!$downloadResult['success']) {
            @unlink($tempFile);
            $this->emitUrlUploadEvent(array('fail' => array('message' => $downloadResult['message'])));
            exit();
        }

        $resolvedName = $this->resolveUploadUrlFileName($url, $downloadResult['headers']);
        $sanitizedName = $this->sanitizeUploadFileName($resolvedName);
        if ($sanitizedName === '') {
            @unlink($tempFile);
            $this->emitUrlUploadEvent(array('fail' => array('message' => 'Cannot determine target file name from URL.')));
            exit();
        }

        $allowed = (FM_UPLOAD_EXTENSION) ? explode(',', FM_UPLOAD_EXTENSION) : false;
        $allowed = is_array($allowed) ? array_map('strtolower', array_map('trim', $allowed)) : false;
        $currentExt = strtolower(pathinfo($sanitizedName, PATHINFO_EXTENSION));
        if ($allowed) {
            if ($currentExt === '' || !in_array($currentExt, $allowed, true)) {
                $guessedExt = $this->guessExtensionFromContentType($downloadResult['contentType']);
                if ($guessedExt !== '' && in_array($guessedExt, $allowed, true)) {
                    $sanitizedName .= '.' . $guessedExt;
                    $currentExt = $guessedExt;
                }
            }
            if ($currentExt === '' || !in_array($currentExt, $allowed, true)) {
                @unlink($tempFile);
                $this->emitUrlUploadEvent(array('fail' => array('message' => 'File extension is not allowed.')));
                exit();
            }
        }

        $targetPath = $this->buildUniqueTargetPath($targetBase, $sanitizedName);
        if (!@rename($tempFile, $targetPath)) {
            @unlink($tempFile);
            $this->emitUrlUploadEvent(array('fail' => array('message' => 'Failed to persist downloaded file to destination.')));
            exit();
        }

        if (function_exists('fm_owner_meta_touch')) {
            fm_owner_meta_touch($targetPath, 'upload_url');
        }

        $result = new stdClass();
        $result->name = basename($targetPath);
        $result->size = (int) filesize($targetPath);
        $result->type = (string) $downloadResult['contentType'];
        $this->emitUrlUploadEvent(array('done' => $result));
        exit();
    }

    private function basePath() {
        $path = $this->root_path;
        if ($this->current_path !== '') {
            $path .= '/' . $this->current_path;
        }
        return $path;
    }

    private function emitUrlUploadEvent($message) {
        echo json_encode($message);
    }

    private function sanitizeUploadFileName($name) {
        $name = str_replace('\\', '/', (string) $name);
        $name = basename($name);
        $name = preg_replace('/[\x00-\x1F\x7F]+/', '', $name);
        $name = trim((string) $name, " .\t\n\r\0\x0B");

        if ($name === '' || $name === '.' || $name === '..') {
            return '';
        }

        return $name;
    }

    private function isAllowedRemoteUrl($url) {
        $parts = parse_url((string) $url);
        if (!is_array($parts)) {
            return false;
        }

        $scheme = isset($parts['scheme']) ? strtolower((string) $parts['scheme']) : '';
        if ($scheme !== 'http' && $scheme !== 'https') {
            return false;
        }

        $host = isset($parts['host']) ? strtolower((string) $parts['host']) : '';
        if ($host === '' || $host === 'localhost') {
            return false;
        }

        $port = isset($parts['port']) ? (int) $parts['port'] : 0;
        if (in_array($port, array(22, 23, 25, 3306), true)) {
            return false;
        }

        if (filter_var($host, FILTER_VALIDATE_IP)) {
            if (!filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return false;
            }
        } else {
            $resolved = @gethostbynamel($host);
            if (is_array($resolved)) {
                foreach ($resolved as $ip) {
                    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                        return false;
                    }
                }
            }
        }

        return true;
    }

    private function downloadRemoteFile($url, $tempFile) {
        $result = array(
            'success' => false,
            'message' => 'Failed to download file from URL.',
            'status' => 0,
            'headers' => array(),
            'contentType' => '',
        );

        if (function_exists('curl_init')) {
            $fp = @fopen($tempFile, 'wb');
            if ($fp === false) {
                $result['message'] = 'Cannot open temporary file for writing.';
                return $result;
            }

            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_FILE, $fp);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_MAXREDIRS, 3);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 8);
            curl_setopt($ch, CURLOPT_TIMEOUT, 25);
            if (defined('CURLOPT_PROTOCOLS') && defined('CURLPROTO_HTTP') && defined('CURLPROTO_HTTPS')) {
                curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
            }
            if (defined('CURLOPT_REDIR_PROTOCOLS') && defined('CURLPROTO_HTTP') && defined('CURLPROTO_HTTPS')) {
                curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
            }
            curl_setopt($ch, CURLOPT_USERAGENT, 'tinyfilemanager-url-upload/1.0');
            curl_setopt($ch, CURLOPT_HEADERFUNCTION, function ($ch, $headerLine) use (&$result) {
                $trimmed = trim((string) $headerLine);
                if ($trimmed !== '') {
                    $result['headers'][] = $trimmed;
                }
                return strlen($headerLine);
            });

            $ok = curl_exec($ch);
            $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $contentType = (string) curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
            $curlError = curl_error($ch);
            curl_close($ch);
            fclose($fp);

            $result['status'] = $httpCode;
            $result['contentType'] = $contentType;

            if ($ok !== true) {
                $result['message'] = $curlError !== '' ? $curlError : 'Remote download failed.';
                return $result;
            }
            if ($httpCode < 200 || $httpCode >= 300) {
                $result['message'] = 'Remote server returned HTTP ' . $httpCode . '.';
                return $result;
            }
            if (!is_file($tempFile) || filesize($tempFile) === 0) {
                $result['message'] = 'Remote download returned an empty file.';
                return $result;
            }

            $result['success'] = true;
            return $result;
        }

        $httpHeaders = array();
        $context = stream_context_create(array(
            'http' => array(
                'method' => 'GET',
                'timeout' => 25,
                'ignore_errors' => true,
                'follow_location' => 1,
                'max_redirects' => 3,
                'header' => "User-Agent: tinyfilemanager-url-upload/1.0\r\n",
            ),
        ));
        $content = @file_get_contents($url, false, $context);
        if (isset($http_response_header) && is_array($http_response_header)) {
            $httpHeaders = $http_response_header;
        }
        $result['headers'] = $httpHeaders;
        $status = $this->extractHttpStatus($httpHeaders);
        $result['status'] = $status;
        $result['contentType'] = $this->extractContentType($httpHeaders);

        if ($content === false) {
            $result['message'] = 'Remote download failed.';
            return $result;
        }
        if ($status < 200 || $status >= 300) {
            $result['message'] = 'Remote server returned HTTP ' . $status . '.';
            return $result;
        }
        if (@file_put_contents($tempFile, $content) === false || filesize($tempFile) === 0) {
            $result['message'] = 'Failed to persist downloaded content.';
            return $result;
        }

        $result['success'] = true;
        return $result;
    }

    private function extractHttpStatus($headers) {
        if (!is_array($headers)) {
            return 0;
        }
        for ($i = count($headers) - 1; $i >= 0; $i--) {
            if (preg_match('/^HTTP\/\d(?:\.\d)?\s+(\d{3})/i', (string) $headers[$i], $m)) {
                return (int) $m[1];
            }
        }
        return 0;
    }

    private function extractContentType($headers) {
        if (!is_array($headers)) {
            return '';
        }
        for ($i = count($headers) - 1; $i >= 0; $i--) {
            if (stripos((string) $headers[$i], 'content-type:') === 0) {
                return trim((string) substr((string) $headers[$i], strlen('content-type:')));
            }
        }
        return '';
    }

    private function resolveUploadUrlFileName($url, $headers) {
        $dispositionName = $this->extractFilenameFromHeaders($headers);
        if ($dispositionName !== '') {
            return $dispositionName;
        }

        $pathName = rawurldecode((string) basename((string) parse_url((string) $url, PHP_URL_PATH)));
        if ($pathName !== '' && $pathName !== '/' && $pathName !== '.') {
            return $pathName;
        }

        $query = (string) parse_url((string) $url, PHP_URL_QUERY);
        if ($query !== '') {
            parse_str($query, $params);
            foreach (array('filename', 'file', 'name', 'download') as $key) {
                if (!empty($params[$key]) && is_string($params[$key])) {
                    return (string) $params[$key];
                }
            }
        }

        return 'downloaded-file';
    }

    private function extractFilenameFromHeaders($headers) {
        if (!is_array($headers)) {
            return '';
        }

        for ($i = count($headers) - 1; $i >= 0; $i--) {
            $line = (string) $headers[$i];
            if (stripos($line, 'content-disposition:') !== 0) {
                continue;
            }

            if (preg_match('/filename\*=(?:UTF-8\'\')?([^;]+)/i', $line, $m)) {
                return rawurldecode(trim($m[1], " \t\"'"));
            }
            if (preg_match('/filename=([^;]+)/i', $line, $m)) {
                return trim($m[1], " \t\"'");
            }
        }

        return '';
    }

    private function guessExtensionFromContentType($contentType) {
        $contentType = strtolower(trim((string) $contentType));
        if ($contentType === '') {
            return '';
        }
        $contentType = trim((string) strtok($contentType, ';'));

        $map = array(
            'image/jpeg' => 'jpg',
            'image/png' => 'png',
            'image/gif' => 'gif',
            'image/webp' => 'webp',
            'application/pdf' => 'pdf',
            'text/plain' => 'txt',
            'text/csv' => 'csv',
            'application/zip' => 'zip',
            'application/json' => 'json',
            'application/msword' => 'doc',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => 'docx',
            'application/vnd.ms-excel' => 'xls',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' => 'xlsx',
            'application/vnd.ms-powerpoint' => 'ppt',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation' => 'pptx',
        );

        return isset($map[$contentType]) ? $map[$contentType] : '';
    }

    private function buildUniqueTargetPath($targetBase, $fileName) {
        $targetBase = rtrim(str_replace('\\', '/', (string) $targetBase), '/');
        $fileName = (string) $fileName;
        $candidate = $targetBase . '/' . $fileName;

        if (!file_exists($candidate)) {
            return $candidate;
        }

        $ext = pathinfo($fileName, PATHINFO_EXTENSION);
        $nameOnly = pathinfo($fileName, PATHINFO_FILENAME);
        $suffix = '_' . date('ymdHis');
        return $targetBase . '/' . $nameOnly . $suffix . ($ext !== '' ? '.' . $ext : '');
    }

    private function resolveUploadBasePath($requestedUploadDir) {
        $requestedUploadDir = fm_clean_path((string) $requestedUploadDir);
        $candidateBase = rtrim($this->root_path, '/\\');
        if ($requestedUploadDir !== '') {
            $candidateBase .= '/' . $requestedUploadDir;
        }

        $candidateBase = str_replace('\\', '/', $candidateBase);
        $normalizedRoot = rtrim(str_replace('\\', '/', (string) $this->root_path), '/');
        if (!fm_is_path_inside($candidateBase, $normalizedRoot)) {
            return null;
        }

        if (function_exists('fm_user_can_access_path') && !fm_user_can_access_path($candidateBase, false)) {
            return null;
        }

        return $candidateBase;
    }

    private function urlUploadTargetPath($path, $fileinfo, $temp_file) {
        return $path . '/' . basename($fileinfo->name);
    }
}
