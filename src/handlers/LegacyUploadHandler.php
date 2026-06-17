<?php
/**
 * TinyFileManager - Legacy Upload Handler
 * Incremental extraction that preserves the existing upload behavior.
 */

class TFM_LegacyUploadHandler {
    private $root_path;
    private $current_path;
    private $max_url_upload_bytes;

    public function __construct($root_path, $current_path = '') {
        $this->root_path = rtrim((string) $root_path, '/\\');
        $this->current_path = (string) $current_path;

        $this->max_url_upload_bytes = defined('MAX_UPLOAD_SIZE')
            ? (int) MAX_UPLOAD_SIZE
            : 134217728;
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
                $this->emitUploadResponse('error', 'TOKEN_INVALID', 'Invalid token.');
            }
        } else {
            $this->emitUploadResponse('error', 'TOKEN_INVALID', 'Token missing.');
        }

        if ((defined('FM_READONLY') && FM_READONLY && (!defined('FM_UPLOAD_ONLY') || !FM_UPLOAD_ONLY))) {
            $this->emitUploadResponse('error', 'ROLE_DENIED', 'You do not have permission to upload files.');
        }
        if (defined('FM_CAN_WRITE_IN_PATH') && !FM_CAN_WRITE_IN_PATH) {
            $this->emitUploadResponse('error', 'PATH_DENIED', 'Current path is not writable.');
        }

        $chunkIndex = isset($post['dzchunkindex']) ? $post['dzchunkindex'] : null;
        $chunkTotal = isset($post['dztotalchunkcount']) ? $post['dztotalchunkcount'] : null;
        $requestedUploadDir = fm_clean_path(isset($request['upload_dir']) ? (string) $request['upload_dir'] : $this->current_path);
        $rawFullPathInput = isset($request['fullpath']) ? (string) $request['fullpath'] : '';

        $f = $files;
        $ds = DIRECTORY_SEPARATOR;

        $allowed = (FM_UPLOAD_EXTENSION) ? explode(',', FM_UPLOAD_EXTENSION) : false;
        $allowed = is_array($allowed) ? array_map('strtolower', array_map('trim', $allowed)) : false;

        $filename = isset($f['file']['name']) ? (string) $f['file']['name'] : '';
        $tmp_name = isset($f['file']['tmp_name']) ? (string) $f['file']['tmp_name'] : '';
        $phpUploadError = isset($f['file']['error']) ? (int) $f['file']['error'] : UPLOAD_ERR_NO_FILE;

        if ($filename === '' || !isset($f['file']['tmp_name'])) {
            $this->emitUploadResponse('error', 'NO_FILE', 'No file received for upload.');
        }

        if ($phpUploadError !== UPLOAD_ERR_OK) {
            $this->emitUploadResponse('error', 'PHP_UPLOAD_ERROR', $this->phpUploadErrorMessage($phpUploadError));
        }

        $safeRelativePath = $this->sanitizeUploadRelativePath($rawFullPathInput !== '' ? $rawFullPathInput : $filename);
        if ($safeRelativePath === '') {
            $this->emitUploadResponse('error', 'INVALID_FILENAME', 'Invalid upload path or file name.');
        }

        $safeFileName = basename($safeRelativePath);
        if (!fm_isvalid_filename($safeFileName)) {
            $this->emitUploadResponse('error', 'INVALID_FILENAME', 'Invalid file name.');
        }

        $ext = pathinfo($safeFileName, PATHINFO_FILENAME) != '' ? strtolower(pathinfo($safeFileName, PATHINFO_EXTENSION)) : '';
        $isFileAllowed = ($allowed) ? in_array($ext, $allowed, true) : true;
        if (!$isFileAllowed) {
            $this->emitUploadResponse('error', 'EXTENSION_DENIED', 'File extension is not allowed.');
        }

        $targetPath = $this->resolveUploadBasePath($requestedUploadDir);
        if ($targetPath === null) {
            $this->emitUploadResponse('error', 'PATH_DENIED', 'Upload target path is not allowed.');
        }

        $targetPath = rtrim($targetPath, '/\\') . $ds;
        if (!is_writable($targetPath)) {
            $this->emitUploadResponse('error', 'NOT_WRITABLE', 'The specified folder for upload is not writable.');
        }

        $fullPath = rtrim($targetPath, '/\\') . '/' . $safeRelativePath;
        $fullPath = str_replace('\\', '/', $fullPath);
        $fullPath = preg_replace('#/+#', '/', $fullPath);

        if (!fm_is_path_inside($fullPath, rtrim($targetPath, '/\\'))) {
            $this->emitUploadResponse('error', 'PATH_DENIED', 'Resolved upload path is outside allowed directory.');
        }

        $folder = substr($fullPath, 0, strrpos($fullPath, '/'));
        if (!is_dir($folder)) {
            $old = umask(0);
            if (!@mkdir($folder, 0777, true) && !is_dir($folder)) {
                $this->emitUploadResponse('error', 'MOVE_FAILED', 'Unable to create upload destination folder.');
            }
            umask($old);
        }

        if ($chunkTotal) {
            $out = @fopen("{$fullPath}.part", $chunkIndex == 0 ? 'wb' : 'ab');
            if (!$out) {
                $this->emitUploadResponse('error', 'MOVE_FAILED', 'Failed to open output stream.');
            }

            $in = @fopen($tmp_name, 'rb');
            if (!$in) {
                @fclose($out);
                $this->emitUploadResponse('error', 'MOVE_FAILED', 'Failed to open input stream.');
            }

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
            @fclose($in);
            @fclose($out);
            @unlink($tmp_name);

            if ($chunkIndex == $chunkTotal - 1) {
                $partPath = "{$fullPath}.part";

                if (file_exists($fullPath)) {
                    $ext_1 = $ext ? '.' . $ext : '';
                    $relativeDir = dirname($safeRelativePath);
                    if ($relativeDir === '.' || $relativeDir === '/') {
                        $relativeDir = '';
                    }
                    $collisionName = basename($safeFileName, $ext_1) . '_' . date('ymdHis') . $ext_1;
                    $fullPathTarget = rtrim($targetPath, '/\\')
                        . ($relativeDir !== '' ? '/' . $relativeDir : '')
                        . '/' . $collisionName;
                    $fullPathTarget = str_replace('\\', '/', $fullPathTarget);
                    $fullPathTarget = preg_replace('#/+#', '/', $fullPathTarget);
                } else {
                    $fullPathTarget = $fullPath;
                }

                if (!fm_is_path_inside($fullPathTarget, rtrim($targetPath, '/\\'))) {
                    $this->emitUploadResponse('error', 'PATH_DENIED', 'Resolved upload path is outside allowed directory.');
                }

                if (!rename($partPath, $fullPathTarget)) {
                    $this->emitUploadResponse('error', 'MOVE_FAILED', 'Failed to finalize uploaded file.');
                }

                if (function_exists('fm_owner_meta_touch')) {
                    fm_owner_meta_touch($fullPathTarget, 'upload');
                }

                $this->emitUploadResponse('success', 'SUCCESS', 'Súbor bol uložený.');
            }

            $this->emitUploadResponse('success', 'CHUNK_RECEIVED', 'Chunk received.');
        }

        if (!move_uploaded_file($tmp_name, $fullPath)) {
            $this->emitUploadResponse('error', 'MOVE_FAILED', 'Error while moving uploaded file to destination.');
        }

        if (!file_exists($fullPath)) {
            $this->emitUploadResponse('error', 'MOVE_FAILED', 'Could not persist uploaded file to destination.');
        }

        if (function_exists('fm_owner_meta_touch')) {
            fm_owner_meta_touch($fullPath, 'upload');
        }

        $this->emitUploadResponse('success', 'SUCCESS', 'Súbor bol uložený.');
    }

    /**
     * Handle upload-via-URL request and echo legacy JSON response.
     * @param array $request
     * @return void
     */
    public function handleUrlUpload($request) {
        header('Content-Type: application/json; charset=utf-8');

        if ((defined('FM_READONLY') && FM_READONLY && (!defined('FM_UPLOAD_ONLY') || !FM_UPLOAD_ONLY))) {
            $this->emitUrlFail('ROLE_DENIED', 'Upload from URL is not allowed for this role.');
        }
        if (defined('FM_CAN_WRITE_IN_PATH') && !FM_CAN_WRITE_IN_PATH) {
            $this->emitUrlFail('PATH_DENIED', 'Current path is not writable.');
        }

        $url = isset($request['uploadurl']) ? trim((string) stripslashes((string) $request['uploadurl'])) : '';
        $uploadDir = isset($request['upload_dir']) ? fm_clean_path((string) $request['upload_dir']) : $this->current_path;

        if ($url === '' || !filter_var($url, FILTER_VALIDATE_URL)) {
            $this->emitUrlFail('INVALID_URL', 'Invalid URL parameter.');
        }

        if (!$this->isAllowedRemoteUrl($url)) {
            $this->emitUrlFail('URL_DENIED', 'URL is not allowed.');
        }

        $tempFile = tempnam(sys_get_temp_dir(), 'url-upload-');
        if ($tempFile === false) {
            $this->emitUrlFail('MOVE_FAILED', 'Cannot create temporary file for download.');
        }

        $downloadResult = $this->downloadRemoteFile($url, $tempFile, $this->max_url_upload_bytes);
        if (!$downloadResult['success']) {
            @unlink($tempFile);
            $this->emitUrlFail('DOWNLOAD_FAILED', $downloadResult['message']);
        }

        $resolvedName = $this->resolveUploadUrlFileName($url, $downloadResult['headers']);
        $preparedDestination = $this->prepareUploadDestination($uploadDir, $resolvedName);
        if (empty($preparedDestination['success'])) {
            @unlink($tempFile);
            $this->emitUrlFail((string) $preparedDestination['code'], (string) $preparedDestination['message']);
        }

        $targetPath = (string) $preparedDestination['targetPath'];
        $downloadedSize = (int) @filesize($tempFile);

        if (!@rename($tempFile, $targetPath)) {
            if (!@copy($tempFile, $targetPath)) {
                @unlink($tempFile);
                $this->emitUrlFail('MOVE_FAILED', 'Failed to persist downloaded file to destination.');
            }
            @unlink($tempFile);
        }

        if (!is_file($targetPath)) {
            $this->emitUrlFail('MOVE_FAILED', 'Failed to persist downloaded file to destination.');
        }

        if ($downloadedSize > 0 && (int) @filesize($targetPath) === 0) {
            @unlink($targetPath);
            $this->emitUrlFail('MOVE_FAILED', 'Failed to persist downloaded file to destination.');
        }

        if (function_exists('fm_owner_meta_touch')) {
            fm_owner_meta_touch($targetPath, 'upload_url');
        }

        $result = new stdClass();
        $result->name = basename($targetPath);
        $result->size = (int) filesize($targetPath);
        $result->type = (string) $downloadResult['contentType'];
        echo json_encode(array('done' => $result));
        exit();
    }

    private function prepareUploadDestination($uploadDir, $fileName) {
        $sanitizedName = $this->sanitizeUploadFileName($fileName);
        if ($sanitizedName === '') {
            return array(
                'success' => false,
                'code' => 'INVALID_FILENAME',
                'message' => 'Cannot determine target file name from URL.',
            );
        }

        if (!fm_isvalid_filename($sanitizedName)) {
            return array(
                'success' => false,
                'code' => 'INVALID_FILENAME',
                'message' => 'Invalid file name.',
            );
        }

        $allowed = (FM_UPLOAD_EXTENSION) ? explode(',', FM_UPLOAD_EXTENSION) : false;
        $allowed = is_array($allowed) ? array_map('strtolower', array_map('trim', $allowed)) : false;
        $ext = pathinfo($sanitizedName, PATHINFO_FILENAME) != '' ? strtolower(pathinfo($sanitizedName, PATHINFO_EXTENSION)) : '';
        $isFileAllowed = ($allowed) ? in_array($ext, $allowed, true) : true;
        if (!$isFileAllowed) {
            return array(
                'success' => false,
                'code' => 'EXTENSION_DENIED',
                'message' => 'File extension is not allowed.',
            );
        }

        $targetBase = $this->resolveUploadBasePath($uploadDir);
        if ($targetBase === null || !is_dir($targetBase)) {
            return array(
                'success' => false,
                'code' => 'PATH_DENIED',
                'message' => 'Upload target path is not allowed.',
            );
        }

        if (!is_writable($targetBase)) {
            return array(
                'success' => false,
                'code' => 'NOT_WRITABLE',
                'message' => 'Upload target path is not writable.',
            );
        }

        $targetPath = $this->buildUniqueTargetPath($targetBase, $sanitizedName);
        if (!fm_is_path_inside($targetPath, rtrim(str_replace('\\', '/', (string) $targetBase), '/'))) {
            return array(
                'success' => false,
                'code' => 'PATH_DENIED',
                'message' => 'Upload target path is not allowed.',
            );
        }

        return array(
            'success' => true,
            'targetPath' => $targetPath,
            'fileName' => $sanitizedName,
        );
    }

    private function emitUploadResponse($status, $code, $info, $extra = array()) {
        $payload = array(
            'status' => $status,
            'code' => $code,
            'info' => (string) $info,
        );
        if (!empty($extra) && is_array($extra)) {
            $payload = array_merge($payload, $extra);
        }
        echo json_encode($payload);
        exit();
    }

    private function emitUrlFail($code, $message) {
        echo json_encode(array(
            'fail' => array(
                'code' => (string) $code,
                'message' => (string) $message,
            ),
        ));
        exit();
    }

    private function phpUploadErrorMessage($errorCode) {
        switch ((int) $errorCode) {
            case UPLOAD_ERR_INI_SIZE:
            case UPLOAD_ERR_FORM_SIZE:
                return 'Uploaded file is too large.';
            case UPLOAD_ERR_PARTIAL:
                return 'Uploaded file was only partially uploaded.';
            case UPLOAD_ERR_NO_FILE:
                return 'No file was uploaded.';
            case UPLOAD_ERR_NO_TMP_DIR:
                return 'Temporary upload folder is missing.';
            case UPLOAD_ERR_CANT_WRITE:
                return 'Failed to write uploaded file to disk.';
            case UPLOAD_ERR_EXTENSION:
                return 'File upload stopped by a PHP extension.';
            default:
                return 'Unknown PHP upload error.';
        }
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

    private function sanitizeUploadRelativePath($path) {
        $path = str_replace('\\', '/', trim((string) $path));
        if ($path === '') {
            return '';
        }

        if (strpos($path, "\0") !== false) {
            return '';
        }

        if (preg_match('/^[a-zA-Z]:\//', $path) || strpos($path, '/') === 0 || strpos($path, '//') === 0) {
            return '';
        }

        if (strpos($path, '../') !== false || strpos($path, '/..') !== false || strpos($path, '..\\') !== false) {
            return '';
        }

        $parts = explode('/', $path);
        $safeParts = array();
        foreach ($parts as $part) {
            $part = preg_replace('/[\x00-\x1F\x7F]+/', '', (string) $part);
            $part = trim((string) $part, " .\t\n\r\0\x0B");
            if ($part === '' || $part === '.' || $part === '..') {
                continue;
            }
            if (!fm_isvalid_filename($part)) {
                return '';
            }
            $safeParts[] = $part;
        }

        if (empty($safeParts)) {
            return '';
        }

        return implode('/', $safeParts);
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

        if (isset($parts['user']) || isset($parts['pass'])) {
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
            if (!$this->isPublicIpAddress($host)) {
                return false;
            }
        } else {
            $resolvedIps = $this->resolveHostIps($host);
            if (empty($resolvedIps)) {
                return false;
            }
            foreach ($resolvedIps as $ip) {
                if (!$this->isPublicIpAddress($ip)) {
                    return false;
                }
            }
        }

        return true;
    }

    private function downloadRemoteFile($url, $tempFile, $maxBytes) {
        if (function_exists('curl_init')) {
            return $this->downloadRemoteFileWithCurl($url, $tempFile, $maxBytes);
        }

        $result = array(
            'success' => false,
            'message' => 'Failed to download file from URL.',
            'status' => 0,
            'headers' => array(),
            'contentType' => '',
        );

        $httpHeaders = array();
        $context = stream_context_create(array(
            'http' => array(
                'method' => 'GET',
                'timeout' => 25,
                'ignore_errors' => true,
                'follow_location' => 0,
                'max_redirects' => 0,
                'header' => "User-Agent: tinyfilemanager-url-upload/1.0\r\n",
            ),
        ));

        $in = @fopen($url, 'rb', false, $context);
        if ($in === false) {
            $result['message'] = 'Remote download failed.';
            return $result;
        }

        $meta = stream_get_meta_data($in);
        if (!empty($meta['wrapper_data']) && is_array($meta['wrapper_data'])) {
            $httpHeaders = $meta['wrapper_data'];
        }

        $result['headers'] = $httpHeaders;
        $status = $this->extractHttpStatus($httpHeaders);
        $result['status'] = $status;
        $result['contentType'] = $this->extractContentType($httpHeaders);

        if ($status >= 300 && $status < 400) {
            fclose($in);
            $result['message'] = 'Remote URL redirects are not allowed for security reasons.';
            return $result;
        }

        if ($status < 200 || $status >= 300) {
            fclose($in);
            $result['message'] = 'Remote server returned HTTP ' . $status . '.';
            return $result;
        }

        $out = @fopen($tempFile, 'wb');
        if ($out === false) {
            fclose($in);
            $result['message'] = 'Cannot open temporary file for writing.';
            return $result;
        }

        $bytesWritten = 0;
        while (!feof($in)) {
            $chunk = fread($in, 8192);
            if ($chunk === false) {
                fclose($in);
                fclose($out);
                $result['message'] = 'Remote download stream failed.';
                return $result;
            }

            $chunkLen = strlen($chunk);
            if ($chunkLen === 0) {
                continue;
            }

            $bytesWritten += $chunkLen;
            if ($maxBytes > 0 && $bytesWritten > $maxBytes) {
                fclose($in);
                fclose($out);
                $result['message'] = 'Downloaded file exceeds maximum allowed size.';
                return $result;
            }

            if (fwrite($out, $chunk) === false) {
                fclose($in);
                fclose($out);
                $result['message'] = 'Failed to persist downloaded content.';
                return $result;
            }
        }

        fclose($in);
        fclose($out);

        if (!is_file($tempFile) || filesize($tempFile) === 0) {
            $result['message'] = 'Failed to persist downloaded content.';
            return $result;
        }

        $result['success'] = true;
        return $result;
    }

    private function downloadRemoteFileWithCurl($url, $tempFile, $maxBytes) {
        $result = array(
            'success' => false,
            'message' => 'Failed to download file from URL.',
            'status' => 0,
            'headers' => array(),
            'contentType' => '',
        );

        $fp = @fopen($tempFile, 'wb');
        if ($fp === false) {
            $result['message'] = 'Cannot open temporary file for writing.';
            return $result;
        }

        $maxExceeded = false;
        $result['headers'] = array();
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        curl_setopt($ch, CURLOPT_MAXREDIRS, 0);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 8);
        curl_setopt($ch, CURLOPT_TIMEOUT, 25);
        curl_setopt($ch, CURLOPT_USERAGENT, 'tinyfilemanager-url-upload/1.0');
        if (defined('CURLOPT_PROTOCOLS') && defined('CURLPROTO_HTTP') && defined('CURLPROTO_HTTPS')) {
            curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
        }
        if (defined('CURLOPT_REDIR_PROTOCOLS') && defined('CURLPROTO_HTTP') && defined('CURLPROTO_HTTPS')) {
            curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
        }
        if (defined('CURLOPT_NOPROGRESS')) {
            curl_setopt($ch, CURLOPT_NOPROGRESS, false);
        }
        if (defined('CURLOPT_XFERINFOFUNCTION')) {
            curl_setopt($ch, CURLOPT_XFERINFOFUNCTION, function ($resource, $downloadSize, $downloaded, $uploadSize, $uploaded) use ($maxBytes, &$maxExceeded) {
                if ($maxBytes > 0 && $downloaded > $maxBytes) {
                    $maxExceeded = true;
                    return 1;
                }
                return 0;
            });
        }
        curl_setopt($ch, CURLOPT_HEADERFUNCTION, function ($ch, $headerLine) use (&$result) {
            $trimmed = trim((string) $headerLine);
            if ($trimmed !== '') {
                $result['headers'][] = $trimmed;
            }
            return strlen($headerLine);
        });
        curl_setopt($ch, CURLOPT_WRITEFUNCTION, function ($ch, $data) use ($fp, $maxBytes, &$maxExceeded) {
            if ($maxExceeded) {
                return 0;
            }
            if ($maxBytes > 0 && (ftell($fp) + strlen($data)) > $maxBytes) {
                $maxExceeded = true;
                return 0;
            }
            return fwrite($fp, $data);
        });

        $ok = curl_exec($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $contentType = (string) curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        $curlError = curl_error($ch);
        curl_close($ch);
        fclose($fp);

        $result['status'] = $httpCode;
        $result['contentType'] = $contentType;

        if ($maxExceeded) {
            $result['message'] = 'Downloaded file exceeds maximum allowed size.';
            return $result;
        }

        if ($ok !== true) {
            $result['message'] = $curlError !== '' ? $curlError : 'Remote download failed.';
            return $result;
        }

        if ($httpCode >= 300 && $httpCode < 400) {
            $result['message'] = 'Remote URL redirects are not allowed for security reasons.';
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

    private function isPublicIpAddress($ip) {
        return (bool) filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }

    private function resolveHostIps($host) {
        $ips = array();

        if (function_exists('dns_get_record')) {
            $aRecords = @dns_get_record($host, DNS_A);
            if (is_array($aRecords)) {
                foreach ($aRecords as $record) {
                    if (!empty($record['ip'])) {
                        $ips[] = (string) $record['ip'];
                    }
                }
            }

            $aaaaRecords = @dns_get_record($host, DNS_AAAA);
            if (is_array($aaaaRecords)) {
                foreach ($aaaaRecords as $record) {
                    if (!empty($record['ipv6'])) {
                        $ips[] = (string) $record['ipv6'];
                    }
                }
            }
        }

        if (empty($ips)) {
            $legacy = @gethostbynamel($host);
            if (is_array($legacy)) {
                $ips = array_merge($ips, $legacy);
            }
        }

        $ips = array_values(array_unique(array_filter(array_map('trim', $ips), function ($value) {
            return $value !== '';
        })));

        return $ips;
    }
}
