<?php
/**
 * TinyFileManager - AJAX Action Handler
 * Incremental extraction for POST type-dispatched AJAX actions.
 */

class TFM_AjaxActionHandler {
    private $root_path;
    private $current_path;
    private $app_root;

    public function __construct($root_path, $current_path = '', $app_root = null) {
        $this->root_path = rtrim((string) $root_path, '/\\');
        $this->current_path = (string) $current_path;
        $this->app_root = $app_root ?: dirname(__DIR__, 2);
    }

    /**
     * Dispatch AJAX actions and preserve legacy control flow.
     * @param array $post
     * @param array $get
     * @param array $request
     * @param array $auth_users
     * @return void
     */
    public function handle($post, $get, $request, $auth_users) {
        if (!verifyToken($post['token'])) {
            header('HTTP/1.0 401 Unauthorized');
            die('Invalid Token.');
        }

        // Self-service password change must work for any authenticated user,
        // including readonly and upload-only roles.
        if (isset($post['type']) && $post['type'] == 'changepwd') {
            $this->handleChangePassword($post, $auth_users);
        }

        // Profile/settings save must also work for any authenticated user.
        if (isset($post['type']) && $post['type'] == 'settings') {
            $this->handleSettings($post);
        }

        if (isset($post['type']) && $post['type'] == 'settings_clear_fallback_log') {
            $this->handleClearFallbackLog();
        }

        if (isset($post['type']) && $post['type'] == 'settings_fallback_log_stats') {
            $this->handleFallbackLogStats();
        }

        if (isset($post['type']) && $post['type'] == 'reset_runtime_state') {
            $this->handleResetRuntimeState();
        }

        if (isset($post['type']) && $post['type'] == 'search') {
            $dir = $post['path'] == '.' ? '' : $post['path'];
            $response = fm_search_files(fm_clean_path($dir), isset($post['content']) ? $post['content'] : '');
            echo json_encode($response);
            exit();
        }

        if (isset($post['type']) && $post['type'] == 'search_index_prepare') {
            header('Content-Type: application/json; charset=utf-8');
            if (!isset($_SESSION[FM_SESSION_ID]['logged']) || empty($_SESSION[FM_SESSION_ID]['logged'])) {
                echo json_encode(array(
                    'success' => false,
                    'status' => 'error',
                    'message' => 'Not authenticated',
                    'rebuilt' => false,
                    'count' => 0,
                    'scope' => '',
                    'last_full_index_at' => 0,
                    'elapsed_ms' => 0,
                ));
                exit();
            }

            if (function_exists('fm_search_index_prepare')) {
                echo json_encode(fm_search_index_prepare('ajax_prepare'));
            } else {
                echo json_encode(array(
                    'success' => false,
                    'status' => 'error',
                    'message' => 'Search index preparation is unavailable.',
                    'rebuilt' => false,
                    'count' => 0,
                    'scope' => '',
                    'last_full_index_at' => 0,
                    'elapsed_ms' => 0,
                ));
            }
            exit();
        }

        if (isset($post['type']) && $post['type'] == 'search_index_rebuild') {
            $isAdmin = function_exists('fm_is_admin') ? (bool) fm_is_admin() : false;
            header('Content-Type: application/json; charset=utf-8');
            if (!$isAdmin) {
                echo json_encode(array(
                    'success' => false,
                    'msg' => 'Admin only',
                ));
                exit();
            }

            $ok = function_exists('fm_search_index_rebuild_full') ? (bool) fm_search_index_rebuild_full() : false;
            echo json_encode(array(
                'success' => $ok,
                'msg' => $ok ? 'Search index rebuilt' : 'Search index rebuild failed',
            ));
            exit();
        }

        if (isset($post['type']) && $post['type'] == 'search_index_map') {
            header('Content-Type: application/json; charset=utf-8');
            $dir = isset($post['path']) ? fm_clean_path((string) $post['path']) : '';
            $limit = isset($post['limit']) ? (int) $post['limit'] : 1200;
            if (function_exists('fm_search_index_map')) {
                echo json_encode(fm_search_index_map($dir, $limit));
            } else {
                echo json_encode(array(
                    'success' => false,
                    'msg' => 'Search index map is unavailable.',
                    'items' => array(),
                    'meta' => array('dir' => $dir),
                ));
            }
            exit();
        }

        if (isset($post['type']) && $post['type'] == 'folder_tree_children') {
            header('Content-Type: application/json; charset=utf-8');

            if (!isset($_SESSION[FM_SESSION_ID]['logged']) || empty($_SESSION[FM_SESSION_ID]['logged'])) {
                http_response_code(401);
                echo json_encode(array(
                    'success' => false,
                    'message' => 'Not authenticated',
                ));
                exit();
            }

            $raw_requested_path = isset($post['path']) ? (string) $post['path'] : '';
            $decoded_requested_path = rawurldecode($raw_requested_path);
            if (strpos($decoded_requested_path, '..') !== false) {
                http_response_code(403);
                echo json_encode(array(
                    'success' => false,
                    'message' => 'Access denied',
                ));
                exit();
            }

            $requested_path = fm_clean_path($decoded_requested_path);
            $navigation_home = fm_get_navigation_home_root();
            if ($requested_path === '') {
                $requested_path = $navigation_home;
            } elseif ($navigation_home !== '' && strpos($requested_path . '/', $navigation_home . '/') !== 0) {
                $candidate_path = fm_clean_path($navigation_home . '/' . $requested_path);
                $candidate_abs_path = rtrim(str_replace('\\', '/', (string) FM_ROOT_PATH), '/')
                    . ($candidate_path !== '' ? '/' . $candidate_path : '');

                if (fm_is_within_navigation_home($candidate_abs_path)
                    && fm_user_can_access_path($candidate_abs_path, true)
                    && @is_dir($candidate_abs_path)
                ) {
                    $requested_path = $candidate_path;
                }
            }

            $response = function_exists('fm_search_index_get_child_directories')
                ? fm_search_index_get_child_directories($requested_path)
                : array(
                    'success' => false,
                    'message' => 'Folder tree index is unavailable.',
                    'path' => $requested_path,
                    'children' => array(),
                    'revision' => 0,
                );

            if (empty($response['success'])) {
                if (isset($response['message']) && $response['message'] === 'Access denied') {
                    http_response_code(403);
                } else {
                    http_response_code(503);
                }
            }

            echo json_encode(array(
                'success' => !empty($response['success']),
                'path' => isset($response['path']) ? (string) $response['path'] : $requested_path,
                'children' => isset($response['children']) && is_array($response['children']) ? $response['children'] : array(),
                'revision' => isset($response['revision']) ? (int) $response['revision'] : 0,
                'message' => isset($response['message']) ? (string) $response['message'] : '',
            ));
            exit();
        }

        if (isset($post['type']) && $post['type'] == 'folder_tree_revision') {
            header('Content-Type: application/json; charset=utf-8');
            if (!isset($_SESSION[FM_SESSION_ID]['logged']) || empty($_SESSION[FM_SESSION_ID]['logged'])) {
                http_response_code(401);
                echo json_encode(array(
                    'success' => false,
                    'message' => 'Not authenticated',
                    'revision' => 0,
                ));
                exit();
            }

            $revision = function_exists('fm_search_index_get_tree_revision')
                ? (int) fm_search_index_get_tree_revision()
                : 0;

            echo json_encode(array(
                'success' => true,
                'revision' => $revision,
            ));
            exit();
        }

        if (isset($post['type']) && $post['type'] == 'upload' && !empty($request['uploadurl'])) {
            header('Content-Type: application/json; charset=utf-8');
            if ((FM_READONLY && !FM_UPLOAD_ONLY) || !FM_CAN_WRITE_IN_PATH) {
                $message = !FM_CAN_WRITE_IN_PATH ? 'Current path is not writable.' : 'Upload from URL is not allowed for this role.';
                $code = !FM_CAN_WRITE_IN_PATH ? 'PATH_DENIED' : 'ROLE_DENIED';
                echo json_encode(array('fail' => array('code' => $code, 'message' => $message)));
                exit();
            }

            $legacy_upload_handler = new TFM_LegacyUploadHandler($this->root_path, $this->current_path);
            $legacy_upload_handler->handleUrlUpload($request);
        }

        if (FM_READONLY || FM_UPLOAD_ONLY) {
            exit();
        }

        if (isset($post['type']) && $post['type'] == 'save') {
            $this->handleSave($post, $get);
        }

        if (isset($post['type']) && $post['type'] == 'backup' && !empty($post['file'])) {
            $this->handleBackup($post);
        }

        if (isset($post['type']) && $post['type'] == 'pwdhash') {
            $res = isset($post['inputPassword2']) && !empty($post['inputPassword2']) ? password_hash($post['inputPassword2'], PASSWORD_DEFAULT) : '';
            echo $res;
            exit();
        }
        exit();
    }

    private function handleSave($post, $get) {
        $path = $this->basePath();
        if (!is_dir($path)) {
            fm_redirect(FM_SELF_URL . '?p=');
        }

        $file = $get['edit'];
        $file = fm_clean_path($file);
        $file = str_replace('/', '', $file);
        if ($file == '' || !is_file($path . '/' . $file)) {
            fm_set_msg(lng('File not found'), 'error');
            fm_redirect(FM_SELF_URL . '?p=' . urlencode($this->current_path));
        }

        header('X-XSS-Protection:0');
        $file_path = $path . '/' . $file;

        $writedata = $post['content'];
        $fd = fopen($file_path, 'w');
        $write_results = @fwrite($fd, $writedata);
        fclose($fd);
        if ($write_results === false) {
            header('HTTP/1.1 500 Internal Server Error');
            die('Could Not Write File! - Check Permissions / Ownership');
        }
        if (function_exists('fm_owner_meta_touch')) {
            fm_owner_meta_touch($file_path, 'edit');
        }
        if (function_exists('fm_search_index_sync_path')) {
            $ok = fm_search_index_sync_path($file_path, 'edit');
            if (!$ok && function_exists('fm_search_index_mark_dirty')) {
                fm_search_index_mark_dirty('edit_fallback', $file_path);
            }
        } elseif (function_exists('fm_search_index_mark_dirty')) {
            fm_search_index_mark_dirty('edit', $file_path);
        }
        die(true);
    }

    private function handleBackup($post) {
        $fileName = fm_clean_path($post['file']);
        $fullPath = $this->root_path . '/';
        if (!empty($post['path'])) {
            $relativeDirPath = fm_clean_path($post['path']);
            $fullPath .= $relativeDirPath . '/';
        }
        $date = date('dMy-His');
        $newFileName = $fileName . '-' . $date . '.bak';
        $fullyQualifiedFileName = $fullPath . $fileName;
        try {
            if (!file_exists($fullyQualifiedFileName)) {
                throw new Exception('File ' . $fileName . ' not found');
            }
            if (copy($fullyQualifiedFileName, $fullPath . $newFileName)) {
                if (function_exists('fm_owner_meta_touch')) {
                    fm_owner_meta_touch($fullPath . $newFileName, 'copy');
                }
                if (function_exists('fm_search_index_sync_path')) {
                    $ok = fm_search_index_sync_path($fullPath . $newFileName, 'backup_copy');
                    if (!$ok && function_exists('fm_search_index_mark_dirty')) {
                        fm_search_index_mark_dirty('backup_copy_fallback', $fullPath . $newFileName);
                    }
                } elseif (function_exists('fm_search_index_mark_dirty')) {
                    fm_search_index_mark_dirty('backup_copy', $fullPath . $newFileName);
                }
                echo 'Backup ' . $newFileName . ' created';
            } else {
                throw new Exception('Could not copy file ' . $fileName);
            }
        } catch (Exception $e) {
            echo $e->getMessage();
        }
        exit();
    }

    private function handleSettings($post) {
        global $cfg, $lang, $report_errors, $show_hidden_files, $lang_list, $hide_Cols, $theme, $list_density;

        if (!isset($_SESSION[FM_SESSION_ID]['logged']) || empty($_SESSION[FM_SESSION_ID]['logged'])) {
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(array(
                'success' => false,
                'theme' => $theme,
                'msg' => 'Not authenticated',
            ));
            exit();
        }

        $newLng = $post['js-language'];
        fm_get_translations(array());
        if (!array_key_exists($newLng, $lang_list)) {
            $newLng = 'sk';
        }

        $erp = isset($post['js-error-report']) && $post['js-error-report'] == 'true' ? true : false;
        $shf = isset($post['js-show-hidden']) && $post['js-show-hidden'] == 'true' ? true : false;
        $hco = isset($post['js-hide-cols']) && $post['js-hide-cols'] == 'true' ? true : false;
        $te3 = $post['js-theme-3'];
        $listDensity = isset($post['js-list-density']) ? strtolower(trim((string) $post['js-list-density'])) : 'compact';
        if ($listDensity !== 'normal' && $listDensity !== 'compact') {
            $listDensity = 'compact';
        }
        $fallbackLoggingEnabled = isset($post['js-fallback-log-enabled']) && $post['js-fallback-log-enabled'] == 'true' ? true : false;
        $canChangeInternalFlags = !FM_UPLOAD_ONLY;

        if ($cfg->data['lang'] != $newLng) {
            $cfg->data['lang'] = $newLng;
            $lang = $newLng;
        }
        if ($canChangeInternalFlags) {
            if ($cfg->data['error_reporting'] != $erp) {
                $cfg->data['error_reporting'] = $erp;
                $report_errors = $erp;
            }
            if ($cfg->data['show_hidden'] != $shf) {
                $cfg->data['show_hidden'] = $shf;
                $show_hidden_files = $shf;
            }
        }
        if ($cfg->data['hide_Cols'] != $hco) {
            $cfg->data['hide_Cols'] = $hco;
            $hide_Cols = $hco;
        }
        if ($cfg->data['theme'] != $te3) {
            $cfg->data['theme'] = $te3;
            $theme = $te3;
        }
        if (!isset($cfg->data['list_density']) || $cfg->data['list_density'] !== $listDensity) {
            $cfg->data['list_density'] = $listDensity;
            $list_density = $listDensity;
        }
        if (!isset($cfg->data['fallback_logging']) || (bool) $cfg->data['fallback_logging'] !== $fallbackLoggingEnabled) {
            $cfg->data['fallback_logging'] = $fallbackLoggingEnabled;
        }
        $saved = $cfg->save();
        $saveMessage = $saved ? 'Settings saved successfully' : ($cfg->getLastError() ? $cfg->getLastError() : 'Settings could not be saved.');

        if (!$saved && session_status() === PHP_SESSION_ACTIVE) {
            if (!isset($_SESSION[FM_SESSION_ID]) || !is_array($_SESSION[FM_SESSION_ID])) {
                $_SESSION[FM_SESSION_ID] = array();
            }

            // Safe fallback: keep user settings in session when disk persistence is unavailable.
            $_SESSION[FM_SESSION_ID]['user_settings'] = array(
                'lang' => isset($cfg->data['lang']) ? $cfg->data['lang'] : $lang,
                'error_reporting' => isset($cfg->data['error_reporting']) ? (bool) $cfg->data['error_reporting'] : (bool) $report_errors,
                'show_hidden' => isset($cfg->data['show_hidden']) ? (bool) $cfg->data['show_hidden'] : (bool) $show_hidden_files,
                'hide_Cols' => isset($cfg->data['hide_Cols']) ? (bool) $cfg->data['hide_Cols'] : (bool) $hide_Cols,
                'theme' => isset($cfg->data['theme']) ? $cfg->data['theme'] : $theme,
                'list_density' => isset($cfg->data['list_density']) ? (string) $cfg->data['list_density'] : $listDensity,
                'fallback_logging' => isset($cfg->data['fallback_logging']) ? (bool) $cfg->data['fallback_logging'] : $fallbackLoggingEnabled,
            );

            $saved = true;
            $saveMessage = 'Nastavenia ulozene len pre aktualnu session. Trvale ulozisko nie je zapisovatelne.';
            $this->writeFallbackLog('settings_session_fallback', 'Profile settings persisted to session because profile storage is not writable.');
        }

        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(array(
            'success' => (bool) $saved,
            'theme' => $theme,
            'msg' => $saveMessage,
        ));
        exit();
    }

    private function handleChangePassword($post, $auth_users) {
        header('Content-Type: application/json; charset=utf-8');
        $username = isset($_SESSION[FM_SESSION_ID]['logged']) ? $_SESSION[FM_SESSION_ID]['logged'] : '';
        if (empty($username)) {
            echo json_encode(array('success' => false, 'msg' => 'Not authenticated'));
            exit;
        }

        $newPwd = isset($post['new_password']) ? $post['new_password'] : '';
        $confirmPwd = isset($post['confirm_password']) ? $post['confirm_password'] : '';

        if (strlen($newPwd) < 6) {
            echo json_encode(array('success' => false, 'msg' => 'New password must be at least 6 characters'));
            exit;
        }
        if ($newPwd !== $confirmPwd) {
            echo json_encode(array('success' => false, 'msg' => 'Passwords do not match'));
            exit;
        }

        $newHash = password_hash($newPwd, PASSWORD_DEFAULT);

        $cfgFile = file_exists($this->app_root . '/config.php') ? $this->app_root . '/config.php' : '';
        if ($cfgFile === '' || !is_file($cfgFile) || !is_writable($cfgFile)) {
            $this->writeFallbackLog('changepwd_persist_failed', 'Password change failed: config.php is missing or not writable.');
            echo json_encode(array('success' => false, 'msg' => 'Could not update config file. Check write permissions.'));
            exit;
        }

        if (!function_exists('fm_admin_load_user_config_arrays') || !function_exists('fm_admin_persist_user_config_arrays')) {
            $this->writeFallbackLog('changepwd_persist_failed', 'Password change failed: helper functions are unavailable.');
            echo json_encode(array('success' => false, 'msg' => 'Password update helper is not available.'));
            exit;
        }

        $configData = fm_admin_load_user_config_arrays($cfgFile);
        if (empty($configData['ok'])) {
            $this->writeFallbackLog('changepwd_persist_failed', 'Password change failed: config read failed.');
            echo json_encode(array('success' => false, 'msg' => 'Could not read config file.'));
            exit;
        }

        $authUsersLocal = isset($configData['auth_users']) && is_array($configData['auth_users']) ? $configData['auth_users'] : array();
        if (!array_key_exists($username, $authUsersLocal)) {
            echo json_encode(array('success' => false, 'msg' => 'User account is not configured for password login.'));
            exit;
        }

        $authUsersLocal[$username] = $newHash;
        $persistResult = fm_admin_persist_user_config_arrays(
            $cfgFile,
            $authUsersLocal,
            isset($configData['readonly_users']) && is_array($configData['readonly_users']) ? $configData['readonly_users'] : array(),
            isset($configData['upload_only_users']) && is_array($configData['upload_only_users']) ? $configData['upload_only_users'] : array(),
            isset($configData['manager_users']) && is_array($configData['manager_users']) ? $configData['manager_users'] : array(),
            isset($configData['directories_users']) && is_array($configData['directories_users']) ? $configData['directories_users'] : array(),
            isset($configData['user_notes']) && is_array($configData['user_notes']) ? $configData['user_notes'] : array(),
            isset($configData['bulk_actions_disabled_users']) && is_array($configData['bulk_actions_disabled_users']) ? $configData['bulk_actions_disabled_users'] : array()
        );

        if (!empty($persistResult['ok'])) {
            echo json_encode(array('success' => true, 'msg' => 'Password changed successfully'));
        } else {
            $this->writeFallbackLog('changepwd_persist_failed', 'Password change failed: config write failed.');
            echo json_encode(array('success' => false, 'msg' => 'Could not update config file. Check write permissions.'));
        }
        exit;
    }

    private function handleClearFallbackLog() {
        header('Content-Type: application/json; charset=utf-8');

        $username = isset($_SESSION[FM_SESSION_ID]['logged']) ? (string) $_SESSION[FM_SESSION_ID]['logged'] : '';
        if ($username === '') {
            echo json_encode(array('success' => false, 'msg' => 'Neautorizovane'));
            exit;
        }

        if ($username !== 'admin') {
            echo json_encode(array('success' => false, 'msg' => 'Fallback log moze vycistit iba admin.'));
            exit;
        }

        $result = $this->clearFallbackLog();
        if (!empty($result['ok'])) {
            echo json_encode(array('success' => true, 'msg' => 'Fallback log bol vycisteny.'));
        } else {
            echo json_encode(array('success' => false, 'msg' => isset($result['error']) ? $result['error'] : 'Fallback log sa nepodarilo vycistit.'));
        }
        exit;
    }

    private function handleFallbackLogStats() {
        header('Content-Type: application/json; charset=utf-8');

        $username = isset($_SESSION[FM_SESSION_ID]['logged']) ? (string) $_SESSION[FM_SESSION_ID]['logged'] : '';
        if ($username === '') {
            echo json_encode(array('success' => false, 'msg' => 'Neautorizovane'));
            exit;
        }

        $stats = $this->getFallbackLogStats();
        echo json_encode(array('success' => true, 'stats' => $stats));
        exit;
    }

    private function fallbackLogPath() {
        if (function_exists('fm_runtime_state_dir')) {
            return fm_runtime_state_dir() . '/fallback-events.log';
        }
        return $this->app_root . '/.fm_usercfg/fallback-events.log';
    }

    private function runtimeStatePath($fileName) {
        $dir = $this->app_root . '/.fm_usercfg';
        if (function_exists('fm_runtime_state_dir')) {
            $dir = fm_runtime_state_dir();
        }
        if (!is_dir($dir)) {
            @mkdir($dir, 0750, true);
        }
        return rtrim($dir, '/\\') . '/' . ltrim((string) $fileName, '/\\');
    }

    private function handleResetRuntimeState() {
        header('Content-Type: application/json; charset=utf-8');

        $username = isset($_SESSION[FM_SESSION_ID]['logged']) ? (string) $_SESSION[FM_SESSION_ID]['logged'] : '';
        if ($username === '') {
            echo json_encode(array('success' => false, 'msg' => 'Neautorizovane'));
            exit;
        }

        if ($username !== 'admin') {
            echo json_encode(array('success' => false, 'msg' => 'Tato akcia je dostupna iba pre admina.'));
            exit;
        }

        $onlinePath = $this->runtimeStatePath('online_users.json');
        @file_put_contents($onlinePath, '{}', LOCK_EX);

        $fallbackPath = $this->runtimeStatePath('fallback-events.log');
        if (is_file($fallbackPath)) {
            @file_put_contents($fallbackPath, '', LOCK_EX);
        }

        if (function_exists('apcu_clear_cache')) {
            @apcu_clear_cache();
        }
        if (function_exists('opcache_reset')) {
            @opcache_reset();
        }
        clearstatcache(true);

        if (isset($_SESSION[FM_SESSION_ID]) && is_array($_SESSION[FM_SESSION_ID])) {
            unset($_SESSION[FM_SESSION_ID]['user_settings']);
            $_SESSION[FM_SESSION_ID]['runtime_reset_at'] = time();
        }

        echo json_encode(array('success' => true, 'msg' => 'Cache a pripojenia boli resetovane.'));
        exit;
    }

    private function isFallbackLoggingEnabled() {
        global $cfg;

        if (isset($_SESSION[FM_SESSION_ID]['user_settings']) && is_array($_SESSION[FM_SESSION_ID]['user_settings']) && array_key_exists('fallback_logging', $_SESSION[FM_SESSION_ID]['user_settings'])) {
            return (bool) $_SESSION[FM_SESSION_ID]['user_settings']['fallback_logging'];
        }

        if (isset($cfg) && is_object($cfg) && isset($cfg->data) && is_array($cfg->data) && array_key_exists('fallback_logging', $cfg->data)) {
            return (bool) $cfg->data['fallback_logging'];
        }

        return false;
    }

    private function writeFallbackLog($event, $details) {
        if (!$this->isFallbackLoggingEnabled()) {
            return;
        }

        $logDir = dirname($this->fallbackLogPath());
        if (!is_dir($logDir) && !@mkdir($logDir, 0750, true)) {
            return;
        }

        $username = isset($_SESSION[FM_SESSION_ID]['logged']) ? (string) $_SESSION[FM_SESSION_ID]['logged'] : 'anonymous';
        $entry = array(
            'timestamp' => date('c'),
            'user' => $username,
            'event' => (string) $event,
            'details' => (string) $details,
        );

        $line = json_encode($entry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
        @file_put_contents($this->fallbackLogPath(), $line, FILE_APPEND | LOCK_EX);

        $this->trimFallbackLog();
    }

    private function trimFallbackLog() {
        $logPath = $this->fallbackLogPath();
        if (!is_file($logPath)) {
            return;
        }

        $maxBytes = 262144; // 256KB hard cap
        $maxLines = 1000;
        $keepLines = 500;
        $fileSize = @filesize($logPath);

        if (($fileSize !== false && $fileSize <= $maxBytes)) {
            $lineCount = 0;
            $handle = @fopen($logPath, 'r');
            if ($handle) {
                while (!feof($handle)) {
                    $chunk = fgets($handle);
                    if ($chunk !== false) {
                        $lineCount++;
                    }
                    if ($lineCount > $maxLines) {
                        break;
                    }
                }
                fclose($handle);
            }

            if ($lineCount <= $maxLines) {
                return;
            }
        }

        $lines = @file($logPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!is_array($lines) || empty($lines)) {
            return;
        }

        if (count($lines) > $keepLines) {
            $lines = array_slice($lines, -$keepLines);
        }

        $content = implode("\n", $lines) . "\n";
        @file_put_contents($logPath, $content, LOCK_EX);
    }

    private function clearFallbackLog() {
        $logPath = $this->fallbackLogPath();
        if (!file_exists($logPath)) {
            return array('ok' => true);
        }

        if (@file_put_contents($logPath, '', LOCK_EX) === false) {
            return array('ok' => false, 'error' => 'Subor fallback logu nie je zapisovatelny.');
        }

        return array('ok' => true);
    }

    private function getFallbackLogStats() {
        $logPath = $this->fallbackLogPath();
        if (!is_file($logPath)) {
            return array(
                'exists' => false,
                'bytes' => 0,
                'lines' => 0,
                'updated_at' => '',
            );
        }

        $bytes = @filesize($logPath);
        if ($bytes === false) {
            $bytes = 0;
        }

        $lines = 0;
        $handle = @fopen($logPath, 'r');
        if ($handle) {
            while (!feof($handle)) {
                $line = fgets($handle);
                if ($line !== false) {
                    $lines++;
                }
            }
            fclose($handle);
        }

        $mtime = @filemtime($logPath);
        $updatedAt = $mtime ? date('Y-m-d H:i:s', $mtime) : '';

        return array(
            'exists' => true,
            'bytes' => (int) $bytes,
            'lines' => (int) $lines,
            'updated_at' => $updatedAt,
        );
    }

    private function basePath() {
        $path = $this->root_path;
        if ($this->current_path !== '') {
            $path .= '/' . $this->current_path;
        }
        return $path;
    }
}