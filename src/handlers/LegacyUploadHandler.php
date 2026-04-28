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
        $fullPathInput = fm_clean_path(isset($request['fullpath']) ? $request['fullpath'] : '');

        $f = $files;
        $path = $this->basePath();
        $ds = DIRECTORY_SEPARATOR;

        $uploads = 0;
        $allowed = (FM_UPLOAD_EXTENSION) ? explode(',', FM_UPLOAD_EXTENSION) : false;
        $response = array(
            'status' => 'error',
            'info'   => 'Oops! Try again'
        );

        $filename = $f['file']['name'];
        $tmp_name = $f['file']['tmp_name'];
        $ext = pathinfo($filename, PATHINFO_FILENAME) != '' ? strtolower(pathinfo($filename, PATHINFO_EXTENSION)) : '';
        $isFileAllowed = ($allowed) ? in_array($ext, $allowed) : true;

        if (!fm_isvalid_filename($filename) && !fm_isvalid_filename($fullPathInput)) {
            $response = array(
                'status' => 'error',
                'info'   => 'Invalid File name!',
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

        $targetPath = $path . $ds;
        if (is_writable($targetPath)) {
            $fullPath = $path . '/' . $fullPathInput;
            $folder = substr($fullPath, 0, strrpos($fullPath, '/'));

            if (!is_dir($folder)) {
                $old = umask(0);
                mkdir($folder, 0777, true);
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
                            $fullPathTarget = $path . '/' . basename($fullPathInput, $ext_1) . '_' . date('ymdHis') . $ext_1;
                        } else {
                            $fullPathTarget = $fullPath;
                        }
                        rename("{$fullPath}.part", $fullPathTarget);
                    }
                } else if (move_uploaded_file($tmp_name, $fullPath)) {
                    if (file_exists($fullPath)) {
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
                        'info'   => "Error while uploading files. Uploaded files $uploads",
                    );
                }
            }
        } else {
            $response = array(
                'status' => 'error',
                'info'   => 'The specified folder for upload isn\'t writeable.'
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
        $path = $this->basePath();
        $url = !empty($request['uploadurl']) && preg_match("|^http(s)?://.+$|", stripslashes($request['uploadurl'])) ? stripslashes($request['uploadurl']) : null;

        $domain = parse_url($url, PHP_URL_HOST);
        $port = parse_url($url, PHP_URL_PORT);
        $knownPorts = array(22, 23, 25, 3306);

        if (preg_match("/^localhost$|^127(?:\.[0-9]+){0,2}\.[0-9]+$|^(?:0*\:)*?:?0*1$/i", $domain) || in_array($port, $knownPorts)) {
            $err = array('message' => 'URL is not allowed');
            $this->emitUrlUploadEvent(array('fail' => $err));
            exit();
        }

        $use_curl = false;
        $temp_file = tempnam(sys_get_temp_dir(), 'upload-');
        $fileinfo = new stdClass();
        $fileinfo->name = trim(urldecode(basename($url)), ".\x00..\x20");

        $allowed = (FM_UPLOAD_EXTENSION) ? explode(',', FM_UPLOAD_EXTENSION) : false;
        $ext = strtolower(pathinfo($fileinfo->name, PATHINFO_EXTENSION));
        $isFileAllowed = ($allowed) ? in_array($ext, $allowed) : true;

        $err = false;

        if (!$isFileAllowed) {
            $err = array('message' => 'File extension is not allowed');
            $this->emitUrlUploadEvent(array('fail' => $err));
            exit();
        }

        if (!$url) {
            $success = false;
        } else if ($use_curl) {
            @$fp = fopen($temp_file, 'w');
            @$ch = curl_init($url);
            curl_setopt($ch, CURLOPT_NOPROGRESS, false);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_FILE, $fp);
            @$success = curl_exec($ch);
            $curl_info = curl_getinfo($ch);
            if (!$success) {
                $err = array('message' => curl_error($ch));
            }
            @curl_close($ch);
            fclose($fp);
            $fileinfo->size = $curl_info['size_download'];
            $fileinfo->type = $curl_info['content_type'];
        } else {
            $ctx = stream_context_create();
            @$success = copy($url, $temp_file, $ctx);
            if (!$success) {
                $err = error_get_last();
            }
        }

        if ($success) {
            $success = rename($temp_file, strtok($this->urlUploadTargetPath($path, $fileinfo, $temp_file), '?'));
        }

        if ($success) {
            $this->emitUrlUploadEvent(array('done' => $fileinfo));
        } else {
            unlink($temp_file);
            if (!$err) {
                $err = array('message' => 'Invalid url parameter');
            }
            $this->emitUrlUploadEvent(array('fail' => $err));
        }

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

    private function urlUploadTargetPath($path, $fileinfo, $temp_file) {
        return $path . '/' . basename($fileinfo->name);
    }
}
