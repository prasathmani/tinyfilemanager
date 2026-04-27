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

        if (isset($post['type']) && $post['type'] == 'search') {
            $dir = $post['path'] == '.' ? '' : $post['path'];
            $response = scan(fm_clean_path($dir), $post['content']);
            echo json_encode($response);
            exit();
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

        if (isset($post['type']) && $post['type'] == 'settings') {
            $this->handleSettings($post);
        }

        if (isset($post['type']) && $post['type'] == 'changepwd') {
            $this->handleChangePassword($post, $auth_users);
        }

        if (isset($post['type']) && $post['type'] == 'pwdhash') {
            $res = isset($post['inputPassword2']) && !empty($post['inputPassword2']) ? password_hash($post['inputPassword2'], PASSWORD_DEFAULT) : '';
            echo $res;
            exit();
        }

        if (isset($post['type']) && $post['type'] == 'upload' && !empty($request['uploadurl'])) {
            $legacy_upload_handler = new TFM_LegacyUploadHandler($this->root_path, $this->current_path);
            $legacy_upload_handler->handleUrlUpload($request);
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
        global $cfg, $lang, $report_errors, $show_hidden_files, $lang_list, $hide_Cols, $theme;

        $newLng = $post['js-language'];
        fm_get_translations(array());
        if (!array_key_exists($newLng, $lang_list)) {
            $newLng = 'en';
        }

        $erp = isset($post['js-error-report']) && $post['js-error-report'] == 'true' ? true : false;
        $shf = isset($post['js-show-hidden']) && $post['js-show-hidden'] == 'true' ? true : false;
        $hco = isset($post['js-hide-cols']) && $post['js-hide-cols'] == 'true' ? true : false;
        $te3 = $post['js-theme-3'];
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
        $saved = $cfg->save();
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(array(
            'success' => (bool) $saved,
            'theme' => $theme,
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

        $currentPwd = isset($post['current_password']) ? $post['current_password'] : '';
        $newPwd = isset($post['new_password']) ? $post['new_password'] : '';
        $confirmPwd = isset($post['confirm_password']) ? $post['confirm_password'] : '';

        if (!isset($auth_users[$username]) || !password_verify($currentPwd, $auth_users[$username])) {
            echo json_encode(array('success' => false, 'msg' => 'Current password is incorrect'));
            exit;
        }
        if (strlen($newPwd) < 6) {
            echo json_encode(array('success' => false, 'msg' => 'New password must be at least 6 characters'));
            exit;
        }
        if ($newPwd !== $confirmPwd) {
            echo json_encode(array('success' => false, 'msg' => 'Passwords do not match'));
            exit;
        }

        $newHash = password_hash($newPwd, PASSWORD_BCRYPT);

        $cfgFile = defined('FM_CONFIG_FILE') ? FM_CONFIG_FILE : (file_exists($this->app_root . '/config.php') ? $this->app_root . '/config.php' : '');
        $updated = false;
        if ($cfgFile && is_writable($cfgFile)) {
            $content = file_get_contents($cfgFile);
            $pattern = "/('[\"]" . preg_quote($username, '/') . "['\"]\s*=>\s*')['\"][^'\"]+['\"]/";
            $replacement = '${1}\'' . $newHash . "'";
            $newContent = preg_replace($pattern, $replacement, $content, 1, $count);
            if ($count > 0) {
                $updated = (file_put_contents($cfgFile, $newContent) !== false);
            }
        }

        if ($updated) {
            echo json_encode(array('success' => true, 'msg' => 'Password changed successfully'));
        } else {
            echo json_encode(array('success' => false, 'msg' => 'Could not update config file. Check write permissions.'));
        }
        exit;
    }

    private function basePath() {
        $path = $this->root_path;
        if ($this->current_path !== '') {
            $path .= '/' . $this->current_path;
        }
        return $path;
    }
}