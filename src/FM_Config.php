<?php

/**
 * Save configuration and load per-user overrides.
 */
class FM_Config
{
    var $data;
    // Directory where per-user setting JSON files are stored.
    const USER_CFG_DIR = '.fm_usercfg';

    function __construct()
    {
        global $root_path, $root_url, $CONFIG;
        $fm_url = $root_url . $_SERVER['PHP_SELF'];
        $this->data = array(
            'lang' => 'en',
            'error_reporting' => true,
            'show_hidden' => true
        );
        $data = false;
        if (strlen($CONFIG)) {
            $data = fm_object_to_array(json_decode($CONFIG));
        } else {
            $msg = 'Tiny File Manager<br>Error: Cannot load configuration';
            if (substr($fm_url, -1) == '/') {
                $fm_url = rtrim($fm_url, '/');
                $msg .= '<br>';
                $msg .= '<br>Seems like you have a trailing slash on the URL.';
                $msg .= '<br>Try this link: <a href="' . $fm_url . '">' . $fm_url . '</a>';
            }
            die($msg);
        }
        if (is_array($data) && count($data)) {
            $this->data = $data;
        } else {
            $this->save();
        }

        // Override with per-user settings if a user is already logged in (session started early).
        $logged = isset($_SESSION[FM_SESSION_ID]['logged']) ? $_SESSION[FM_SESSION_ID]['logged'] : null;
        if ($logged) {
            $user_data = $this->loadUserSettings($logged);
            if ($user_data) {
                $this->data = array_merge($this->data, $user_data);
            }
        }
    }

    /**
     * Return the path to a user's settings JSON file.
     */
    private function userCfgPath($username)
    {
        return __DIR__ . DIRECTORY_SEPARATOR . self::USER_CFG_DIR
             . DIRECTORY_SEPARATOR . md5($username) . '.json';
    }

    /**
     * Load per-user settings. Returns array on success, false if none saved yet.
     */
    function loadUserSettings($username)
    {
        $path = $this->userCfgPath($username);
        if (!is_readable($path)) {
            return false;
        }
        $decoded = json_decode(@file_get_contents($path), true);
        return is_array($decoded) ? $decoded : false;
    }

    /**
     * Ensure the per-user config directory exists and is protected from web access.
     */
    private function ensureUserCfgDir()
    {
        $dir = __DIR__ . DIRECTORY_SEPARATOR . self::USER_CFG_DIR;
        if (!is_dir($dir)) {
            @mkdir($dir, 0750, true);
        }
        $htaccess = $dir . DIRECTORY_SEPARATOR . '.htaccess';
        if (!file_exists($htaccess)) {
            @file_put_contents($htaccess, "Order Deny,Allow\nDeny from all\n");
        }
        return $dir;
    }

    function save()
    {
        // If a user is logged in, save to their personal settings file only.
        $logged = isset($_SESSION[FM_SESSION_ID]['logged']) ? $_SESSION[FM_SESSION_ID]['logged'] : null;
        if ($logged) {
            $this->ensureUserCfgDir();
            $path = $this->userCfgPath($logged);
            return (@file_put_contents($path, json_encode($this->data)) !== false);
        }

        // No user logged in – fall back to updating $CONFIG in config.php.
        global $config_file;
        $fm_file = is_readable($config_file) ? $config_file : __FILE__;
        $var_value = var_export(json_encode($this->data), true);
        $new_line = '\$CONFIG = ' . $var_value . ';';

        if (!is_writable($fm_file)) {
            return false;
        }

        $content = @file_get_contents($fm_file);
        if ($content === false) {
            return false;
        }

        if (preg_match('/^\s*\$CONFIG\s*=/m', $content)) {
            $new_content = preg_replace(
                '/^\s*\$CONFIG\s*=.*?;\s*$/m',
                $new_line,
                $content
            );
        } else {
            $new_content = rtrim($content) . "\n" . $new_line . "\n";
        }

        if ($new_content === null || $new_content === $content) {
            return ($new_content !== null);
        }

        return (@file_put_contents($fm_file, $new_content) !== false);
    }
}