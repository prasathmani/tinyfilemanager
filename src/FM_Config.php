<?php

/**
 * Save configuration and load per-user overrides.
 */
class FM_Config
{
    var $data;
    var $last_error;
    // Directory where per-user setting JSON files are stored.
    const USER_CFG_DIR = '.fm_usercfg';

    function __construct()
    {
        global $root_path, $root_url, $CONFIG;
        $fm_url = $root_url . $_SERVER['PHP_SELF'];
        $this->data = array(
            'lang' => 'en',
            'error_reporting' => true,
            'show_hidden' => true,
            'fallback_logging' => false
        );
        $this->last_error = '';
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

            // Fallback source when profile settings cannot be persisted to disk.
            if (isset($_SESSION[FM_SESSION_ID]['user_settings']) && is_array($_SESSION[FM_SESSION_ID]['user_settings'])) {
                $this->data = array_merge($this->data, $_SESSION[FM_SESSION_ID]['user_settings']);
            }
        }
    }

    /**
     * Return optional custom state directory from config.php.
     */
    private function configuredStateDir()
    {
        global $state_storage_path;

        if (!isset($state_storage_path) || !is_string($state_storage_path)) {
            return '';
        }

        $candidate = trim($state_storage_path);
        if ($candidate === '') {
            return '';
        }

        // Relative configured paths are anchored to app root.
        if (!preg_match('/^(?:[a-zA-Z]:[\\\\\/]|\/)/', $candidate)) {
            $candidate = dirname(__DIR__) . DIRECTORY_SEPARATOR . ltrim($candidate, '/\\');
        }

        $candidate = rtrim($candidate, '/\\');
        return $candidate;
    }

    /**
     * Return default per-user config directory in project root.
     */
    private function defaultUserCfgDir()
    {
        return dirname(__DIR__) . DIRECTORY_SEPARATOR . self::USER_CFG_DIR;
    }

    /**
     * Return the preferred per-user config directory in project root.
     */
    private function userCfgDir()
    {
        $configured = $this->configuredStateDir();
        if ($configured !== '') {
            return $configured;
        }

        return $this->defaultUserCfgDir();
    }

    /**
     * Return the legacy per-user config directory under src/.
     */
    private function legacyUserCfgDir()
    {
        return __DIR__ . DIRECTORY_SEPARATOR . self::USER_CFG_DIR;
    }

    /**
     * Pick an existing writable per-user config directory or create one.
     * Prefer project root, then legacy src/ location as fallback.
     */
    private function resolveWritableUserCfgDir()
    {
        $configured = $this->configuredStateDir();
        $candidates = array();
        if ($configured !== '') {
            $candidates[] = $configured;
        }
        $candidates[] = $this->userCfgDir();
        $candidates[] = $this->legacyUserCfgDir();
        $candidates = array_values(array_unique($candidates));

        foreach ($candidates as $dir) {
            if (is_dir($dir)) {
                if (is_writable($dir)) {
                    return $dir;
                }
                continue;
            }

            if (@mkdir($dir, 0750, true) && is_dir($dir) && is_writable($dir)) {
                return $dir;
            }
        }

        return false;
    }

    /**
     * Return the path to a user's settings JSON file.
     */
    private function userCfgPath($username)
    {
        return $this->userCfgDir()
             . DIRECTORY_SEPARATOR . md5($username) . '.json';
    }

    /**
     * Return the legacy path to a user's settings JSON file under src/.
     */
    private function legacyUserCfgPath($username)
    {
        return $this->legacyUserCfgDir()
             . DIRECTORY_SEPARATOR . md5($username) . '.json';
    }

    /**
     * Load per-user settings. Returns array on success, false if none saved yet.
     */
    function loadUserSettings($username)
    {
        $path = $this->userCfgPath($username);
        if (!is_readable($path)) {
            $defaultPath = $this->defaultUserCfgDir() . DIRECTORY_SEPARATOR . md5($username) . '.json';
            if (is_readable($defaultPath)) {
                $path = $defaultPath;
            } else {
            $legacyPath = $this->legacyUserCfgPath($username);
            if (!is_readable($legacyPath)) {
                return false;
            }
            $path = $legacyPath;
            }
        }
        $decoded = json_decode(@file_get_contents($path), true);
        return is_array($decoded) ? $decoded : false;
    }

    /**
     * Ensure the per-user config directory exists and is protected from web access.
     */
    private function ensureUserCfgDir()
    {
        $dir = $this->resolveWritableUserCfgDir();
        if ($dir === false) {
            $this->last_error = 'No writable profile settings directory is available.';
            return false;
        }
        $htaccess = $dir . DIRECTORY_SEPARATOR . '.htaccess';
        if (!file_exists($htaccess)) {
            @file_put_contents($htaccess, "Order Deny,Allow\nDeny from all\n");
        }
        return $dir;
    }

    function getLastError()
    {
        return (string) $this->last_error;
    }

    function save()
    {
        $this->last_error = '';
        // If a user is logged in, save to their personal settings file only.
        $logged = isset($_SESSION[FM_SESSION_ID]['logged']) ? $_SESSION[FM_SESSION_ID]['logged'] : null;
        if ($logged) {
            $dir = $this->ensureUserCfgDir();
            if ($dir === false) {
                return false;
            }

            $path = $dir . DIRECTORY_SEPARATOR . md5($logged) . '.json';
            $result = @file_put_contents($path, json_encode($this->data));
            if ($result === false) {
                $this->last_error = 'Could not write profile settings file.';
                return false;
            }
            return true;
        }

        // No user logged in – fall back to updating $CONFIG in config.php.
        global $config_file;
        $fm_file = is_readable($config_file) ? $config_file : __FILE__;
        $var_value = var_export(json_encode($this->data), true);
        $new_line = '\$CONFIG = ' . $var_value . ';';

        if (!is_writable($fm_file)) {
            $this->last_error = 'Main configuration file is not writable.';
            return false;
        }

        $content = @file_get_contents($fm_file);
        if ($content === false) {
            $this->last_error = 'Could not read main configuration file.';
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
            if ($new_content === null) {
                $this->last_error = 'Failed to prepare updated configuration content.';
            }
            return ($new_content !== null);
        }

        $result = @file_put_contents($fm_file, $new_content);
        if ($result === false) {
            $this->last_error = 'Could not write updated configuration file.';
            return false;
        }
        return true;
    }
}