<?php
//Default Configuration
$CONFIG = '{"lang":"en","error_reporting":false,"show_hidden":false,"hide_Cols":false,"theme":"light"}';

/**
 * DREMONT ~ správca súborov 
 * @author CCP Programmers
  * @github https://github.com/prasathmani/tinyfilemanager
 * @link https://tinyfilemanager.github.io
 */

//TFM version
define('VERSION', '2.6.13');

//Application Title
define('APP_TITLE', 'Správca súborov');
define('LOGIN_COMPANY_NAME', 'Dremont s.r.o. PIAR & team');
define('LOGIN_COMPANY_URL', 'https://dremont.in');
define('LOGIN_LOGO_PATH', 'KatalogMD.webp');

// --- EDIT BELOW CONFIGURATION CAREFULLY ---

// Auth with login/password
// set true/false to enable/disable it
// Is independent from IP white- and blacklisting
$use_auth = true;

// Login user name and password
// Users: array('Username' => 'Password', 'Username2' => 'Password2', ...)
// Generate secure password hash - https://tinyfilemanager.github.io/docs/pwd.html
// NOTE: All users, roles and directories are managed in config.php.
//       These defaults are only used if config.php is missing.
$auth_users = array();

// Readonly users (download/view only – no write access at all)
$readonly_users = array();

// Upload-only users (upload + download, cannot delete/rename/move/copy/edit)
$upload_only_users = array();

// Manager users (full access except delete)
$manager_users = array();

// Global readonly, including when auth is not being used
$global_readonly = false;

// User-specific directories (leave empty – managed in config.php)
// array('Username' => 'Directory path', 'Username2' => array('Dir1', 'Dir2'), ...)
$directories_users = array();

// Enable highlight.js (https://highlightjs.org/) on view's page
$use_highlightjs = true;

// highlight.js style
// for dark theme use 'ir-black'
$highlightjs_style = 'vs';

// Enable ace.js (https://ace.c9.io/) on view's page
$edit_files = true;

// Default timezone for date() and time()
// Doc - http://php.net/manual/en/timezones.php
$default_timezone = 'Etc/UTC'; // UTC

// Root path for file manager
// use absolute path of directory i.e: '/var/www/folder' or $_SERVER['DOCUMENT_ROOT'].'/folder'
//make sure update $root_url in next section
$root_path = $_SERVER['DOCUMENT_ROOT'];

// Root url for links in file manager.Relative to $http_host. Variants: '', 'path/to/subfolder'
// Will not working if $root_path will be outside of server document root
$root_url = '';

// Server hostname. Can set manually if wrong
// $_SERVER['HTTP_HOST'].'/folder'
$http_host = $_SERVER['HTTP_HOST'];

// input encoding for iconv
$iconv_input_encoding = 'UTF-8';

// date() format for file modification date
// Doc - https://www.php.net/manual/en/function.date.php
$datetime_format = 'm/d/Y g:i A';

// Path display mode when viewing file information
// 'full' => show full path
// 'relative' => show path relative to root_path
// 'host' => show path on the host
$path_display_mode = 'full';

// Allowed file extensions for create and rename files
// e.g. 'txt,html,css,js'
$allowed_file_extensions = '';

// Allowed file extensions for upload files
// e.g. 'gif,png,jpg,html,txt'
$allowed_upload_extensions = '';

// Favicon path. This can be either a full url to an .PNG image, or a path based on the document root.
// full path, e.g http://example.com/favicon.png
// local path, e.g images/icons/favicon.png
$favicon_path = '';

// Files and folders to excluded from listing
// e.g. array('myfile.html', 'personal-folder', '*.php', '/path/to/folder', ...)
$exclude_items = array();

// Online office Docs Viewer
// Available rules are 'google', 'microsoft' or false
// Google => View documents using Google Docs Viewer
// Microsoft => View documents using Microsoft Web Apps Viewer
// false => disable online doc viewer
$online_viewer = 'google';

// Sticky Nav bar
// true => enable sticky header
// false => disable sticky header
$sticky_navbar = true;

// Maximum file upload size
// Increase the following values in php.ini to work properly
// memory_limit, upload_max_filesize, post_max_size
$max_upload_size_bytes = 5000000000; // size 5,000,000,000 bytes (~5GB)

// chunk size used for upload
// eg. decrease to 1MB if nginx reports problem 413 entity too large
$upload_chunk_size_bytes = 2000000; // chunk size 2,000,000 bytes (~2MB)

// Possible rules are 'OFF', 'AND' or 'OR'
// OFF => Don't check connection IP, defaults to OFF
// AND => Connection must be on the whitelist, and not on the blacklist
// OR => Connection must be on the whitelist, or not on the blacklist
$ip_ruleset = 'OFF';

// Should users be notified of their block?
$ip_silent = true;

// IP-addresses, both ipv4 and ipv6
$ip_whitelist = array(
    '127.0.0.1',    // local ipv4
    '::1'           // local ipv6
);

// IP-addresses, both ipv4 and ipv6
$ip_blacklist = array(
    '0.0.0.0',      // non-routable meta ipv4
    '::'            // non-routable meta ipv6
);

// if User has the external config file, try to use it to override the default config above [config.php]
// sample config - https://tinyfilemanager.github.io/config-sample.txt
$config_file = __DIR__ . '/config.php';
if (is_readable($config_file)) {
    @include($config_file);
}

// Load security layer
$security_file = __DIR__ . '/src/security.php';
if (is_readable($security_file)) {
    @include($security_file);
} else {
    // Fallback: create minimal security functions if security.php missing
    function fm_validate_magic_bytes($f, $e) { return true; }
    function fm_validate_mime_type($f, $t=[]) { return true; }
    function fm_validate_filepath($p, $r) { return true; }
    function fm_validate_input($i, $t='filename') { return $i; }
}

// Modular handlers (incremental extraction from monolith)
require_once __DIR__ . '/src/ArchiveHelpers.php';
require_once __DIR__ . '/src/TemplateHelpers.php';
require_once __DIR__ . '/src/handlers/ArchiveActionHandler.php';
require_once __DIR__ . '/src/handlers/AjaxActionHandler.php';
require_once __DIR__ . '/src/handlers/CopyActionHandler.php';
require_once __DIR__ . '/src/handlers/DownloadPreviewHandler.php';
require_once __DIR__ . '/src/handlers/FileActionHandler.php';
require_once __DIR__ . '/src/handlers/LegacyUploadHandler.php';
require_once __DIR__ . '/src/services/DirectoryListingService.php';
require_once __DIR__ . '/src/services/ChmodPageContextService.php';
require_once __DIR__ . '/src/services/FileEditorContextService.php';
require_once __DIR__ . '/src/services/FileViewContextService.php';
require_once __DIR__ . '/src/services/FileViewInfoService.php';

// External CDN resources that can be used in the HTML (replace for GDPR compliance)
$external = array(
    'css-bootstrap' => '<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">',
    'css-dropzone' => '<link href="https://cdnjs.cloudflare.com/ajax/libs/dropzone/5.9.3/min/dropzone.min.css" rel="stylesheet">',
    'css-font-awesome' => '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css" crossorigin="anonymous">',
    'css-highlightjs' => '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/' . $highlightjs_style . '.min.css">',
    'js-ace' => '<script src="https://cdnjs.cloudflare.com/ajax/libs/ace/1.32.2/ace.js"></script>',
    'js-bootstrap' => '<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>',
    'js-dropzone' => '<script src="https://cdnjs.cloudflare.com/ajax/libs/dropzone/5.9.3/min/dropzone.min.js"></script>',
    'js-jquery' => '<script src="https://code.jquery.com/jquery-3.6.1.min.js" integrity="sha256-o88AwQnZB+VDvE9tvIXrMQaPlFFSUTR+nldQm1LuPXQ=" crossorigin="anonymous"></script>',
    'js-jquery-datatables' => '<script src="https://cdn.datatables.net/1.13.1/js/jquery.dataTables.min.js" crossorigin="anonymous" defer></script>',
    'js-highlightjs' => '<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>',
    'pre-jsdelivr' => '<link rel="preconnect" href="https://cdn.jsdelivr.net" crossorigin/><link rel="dns-prefetch" href="https://cdn.jsdelivr.net"/>',
    'pre-cloudflare' => '<link rel="preconnect" href="https://cdnjs.cloudflare.com" crossorigin/><link rel="dns-prefetch" href="https://cdnjs.cloudflare.com"/>'
);

// --- EDIT BELOW CAREFULLY OR DO NOT EDIT AT ALL ---

// max upload file size
define('MAX_UPLOAD_SIZE', $max_upload_size_bytes);

// upload chunk size
define('UPLOAD_CHUNK_SIZE', $upload_chunk_size_bytes);

// private key and session name to store to the session
if (!defined('FM_SESSION_ID')) {
    define('FM_SESSION_ID', 'filemanager');
}

// Start session early so FM_Config can read the logged-in user and load per-user settings.
if (!defined('FM_EMBED')) {
    @set_time_limit(600);
    date_default_timezone_set($default_timezone);
    ini_set('default_charset', 'UTF-8');
    if (version_compare(PHP_VERSION, '5.6.0', '<') && function_exists('mb_internal_encoding')) {
        mb_internal_encoding('UTF-8');
    }
    if (function_exists('mb_regex_encoding')) {
        mb_regex_encoding('UTF-8');
    }
    session_cache_limiter('nocache');
    session_name(FM_SESSION_ID);
    function session_error_handling_function($code, $msg, $file, $line)
    {
        if ($code == 2) {
            session_abort();
            session_id(session_create_id());
            @session_start();
        }
    }
    set_error_handler('session_error_handling_function');
    session_start();
    restore_error_handler();
}

// Configuration – loads global defaults, then overrides with per-user settings if logged in.
$cfg = new FM_Config();

// Default language
$lang = isset($cfg->data['lang']) ? $cfg->data['lang'] : 'en';

// Show or hide files and folders that starts with a dot
$show_hidden_files = isset($cfg->data['show_hidden']) ? $cfg->data['show_hidden'] : true;

// PHP error reporting - false = Turns off Errors, true = Turns on Errors
$report_errors = isset($cfg->data['error_reporting']) ? $cfg->data['error_reporting'] : true;

// Hide Permissions and Owner cols in file-listing
$hide_Cols = isset($cfg->data['hide_Cols']) ? $cfg->data['hide_Cols'] : true;

// Theme
$theme = isset($cfg->data['theme']) ? $cfg->data['theme'] : 'light';

define('FM_THEME', $theme);

//available languages
$lang_list = array(
    'en' => 'English',
    'sk' => 'Slovensky'
);

if ($report_errors == true) {
    @ini_set('error_reporting', E_ALL);
    @ini_set('display_errors', 1);
} else {
    @ini_set('error_reporting', E_ALL);
    @ini_set('display_errors', 0);
}

// if fm included
if (defined('FM_EMBED')) {
    $use_auth = false;
    $sticky_navbar = false;
}

//Generating CSRF Token
if (empty($_SESSION['token'])) {
    if (function_exists('random_bytes')) {
        $_SESSION['token'] = bin2hex(random_bytes(32));
    } else {
        $_SESSION['token'] = bin2hex(openssl_random_pseudo_bytes(32));
    }
}

if (empty($auth_users)) {
    $use_auth = false;
}

$forwarded_proto = '';
if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
    $forwarded_proto_parts = explode(',', (string) $_SERVER['HTTP_X_FORWARDED_PROTO']);
    $forwarded_proto = strtolower(trim($forwarded_proto_parts[0]));
}

$forwarded_ssl_on = !empty($_SERVER['HTTP_X_FORWARDED_SSL']) && strtolower((string) $_SERVER['HTTP_X_FORWARDED_SSL']) === 'on';
$front_end_https_on = !empty($_SERVER['HTTP_FRONT_END_HTTPS']) && strtolower((string) $_SERVER['HTTP_FRONT_END_HTTPS']) !== 'off';
$request_scheme_https = !empty($_SERVER['REQUEST_SCHEME']) && strtolower((string) $_SERVER['REQUEST_SCHEME']) === 'https';

$is_https = (isset($_SERVER['HTTPS']) && (strtolower((string) $_SERVER['HTTPS']) === 'on' || (string) $_SERVER['HTTPS'] === '1'))
    || $forwarded_proto === 'https'
    || $forwarded_ssl_on
    || $front_end_https_on
    || $request_scheme_https;

if (!empty($_SERVER['HTTP_X_FORWARDED_HOST'])) {
    $forwarded_host_parts = explode(',', (string) $_SERVER['HTTP_X_FORWARDED_HOST']);
    $http_host = trim($forwarded_host_parts[0]);
} elseif (!empty($_SERVER['HTTP_HOST'])) {
    $http_host = (string) $_SERVER['HTTP_HOST'];
}

$fm_user_allowed_dirs = array();

// If root_url is empty and root_path is inside web document root, derive it automatically.
if ((string) $root_url === '' && !empty($_SERVER['DOCUMENT_ROOT']) && !empty($root_path)) {
    $doc_root_norm = rtrim(str_replace('\\', '/', (string) $_SERVER['DOCUMENT_ROOT']), '/');
    $root_path_norm = rtrim(str_replace('\\', '/', (string) $root_path), '/');
    if ($doc_root_norm !== '' && strpos($root_path_norm . '/', $doc_root_norm . '/') === 0) {
        $derived_root_url = ltrim(substr($root_path_norm, strlen($doc_root_norm)), '/');
        if ($derived_root_url !== '') {
            $root_url = $derived_root_url;
        }
    }
}

// clean $root_url
$root_url = fm_clean_path($root_url);

// abs path for site
defined('FM_ROOT_URL') || define('FM_ROOT_URL', ($is_https ? 'https' : 'http') . '://' . $http_host . (!empty($root_url) ? '/' . $root_url : ''));
defined('FM_SELF_PATH') || define('FM_SELF_PATH', $_SERVER['PHP_SELF']);
defined('FM_SELF_URL') || define('FM_SELF_URL', ($is_https ? 'https' : 'http') . '://' . $http_host . FM_SELF_PATH);

// Lightweight PWA manifest endpoint (no service worker)
if (isset($_GET['manifest'])) {
    $icon_source = LOGIN_LOGO_PATH ? LOGIN_LOGO_PATH : $favicon_path;
    $icon_url = '';
    if (!empty($icon_source)) {
        if (preg_match('#^https?://#i', $icon_source)) {
            $icon_url = $icon_source;
        } else {
            $icon_url = FM_ROOT_URL . '/' . ltrim($icon_source, '/');
        }
    }

    $icon_type = 'image/png';
    $icon_ext = strtolower(pathinfo($icon_source, PATHINFO_EXTENSION));
    if ($icon_ext === 'webp') {
        $icon_type = 'image/webp';
    } elseif ($icon_ext === 'svg') {
        $icon_type = 'image/svg+xml';
    } elseif ($icon_ext === 'jpg' || $icon_ext === 'jpeg') {
        $icon_type = 'image/jpeg';
    } elseif ($icon_ext === 'avif') {
        $icon_type = 'image/avif';
    }

    $manifest = array(
        'name' => APP_TITLE,
        'short_name' => 'TFM',
        'start_url' => FM_SELF_URL . '?p=',
        'scope' => FM_SELF_URL,
        'display' => 'standalone',
        'orientation' => 'portrait',
        'background_color' => '#f7f7f7',
        'theme_color' => '#1f6feb',
        'icons' => array(),
    );

    if (!empty($icon_url)) {
        $manifest['icons'][] = array(
            'src' => $icon_url,
            'sizes' => '192x192',
            'type' => $icon_type,
            'purpose' => 'any'
        );
        $manifest['icons'][] = array(
            'src' => $icon_url,
            'sizes' => '512x512',
            'type' => $icon_type,
            'purpose' => 'any'
        );
    }

    header('Content-Type: application/manifest+json; charset=utf-8');
    echo json_encode($manifest, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

// On unexpected runtime failures, fallback to login page instead of exposing errors.
if (!defined('FM_EMBED')) {
    set_exception_handler('fm_unexpected_exception_handler');
    register_shutdown_function('fm_unexpected_shutdown_handler');
}

// logout
if (isset($_GET['logout'])) {
    if ($use_auth && isset($_SESSION[FM_SESSION_ID]['logged'])) {
        fm_online_remove_user($_SESSION[FM_SESSION_ID]['logged']);
        // Audit log logout
        if (class_exists('AuditLogger')) {
            $audit = new AuditLogger();
            $audit->log('user_logout', $_SESSION[FM_SESSION_ID]['logged']);
        }
    }
    // Unset all session variables
    $_SESSION = array();
    // Delete the session cookie to prevent the browser from reusing the session ID
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $p['path'], $p['domain'],
            $p['secure'], $p['httponly']
        );
    }
    // Destroy the session on the server side
    session_destroy();
    // Prevent browser from serving cached authenticated pages via Back button
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: Sat, 26 Jul 1997 05:00:00 GMT');
    fm_redirect(FM_SELF_URL);
}

// Validate connection IP
if ($ip_ruleset != 'OFF') {
    function getClientIP()
    {
        if (array_key_exists('HTTP_CF_CONNECTING_IP', $_SERVER)) {
            return  $_SERVER["HTTP_CF_CONNECTING_IP"];
        } else if (array_key_exists('HTTP_X_FORWARDED_FOR', $_SERVER)) {
            return  $_SERVER["HTTP_X_FORWARDED_FOR"];
        } else if (array_key_exists('REMOTE_ADDR', $_SERVER)) {
            return $_SERVER['REMOTE_ADDR'];
        } else if (array_key_exists('HTTP_CLIENT_IP', $_SERVER)) {
            return $_SERVER['HTTP_CLIENT_IP'];
        }
        return '';
    }

    $clientIp = getClientIP();
    $proceed = false;
    $whitelisted = in_array($clientIp, $ip_whitelist);
    $blacklisted = in_array($clientIp, $ip_blacklist);

    if ($ip_ruleset == 'AND') {
        if ($whitelisted == true && $blacklisted == false) {
            $proceed = true;
        }
    } else
    if ($ip_ruleset == 'OR') {
        if ($whitelisted == true || $blacklisted == false) {
            $proceed = true;
        }
    }

    if ($proceed == false) {
        trigger_error('User connection denied from: ' . $clientIp, E_USER_WARNING);

        if ($ip_silent == false) {
            fm_set_msg(lng('Access denied. IP restriction applicable'), 'error');
            fm_show_header_login();
            fm_show_message();
        }
        exit();
    }
}

// Checking if the user is logged in or not. If not, it will show the login form.
$fm_signed_preview_request = isset($_GET['preview'])
    && fm_has_valid_preview_signature(
        $_GET['p'] ?? '',
        $_GET['preview'] ?? '',
        $_GET['exp'] ?? '',
        $_GET['sig'] ?? ''
    );

if ($use_auth) {
    if (isset($_SESSION[FM_SESSION_ID]['logged'], $auth_users[$_SESSION[FM_SESSION_ID]['logged']]) || $fm_signed_preview_request) {
        // Logged. Prevent rendering or processing login form again.
        if (isset($_POST['fm_usr']) || isset($_POST['fm_pwd']) || (isset($_GET['login']) && $_GET['login'] == '1')) {
            fm_redirect(FM_SELF_URL . '?p=' . urlencode(''));
        }
    } elseif (isset($_POST['fm_usr'], $_POST['fm_pwd'], $_POST['token'])) {
        // Logging In - with rate limiting
        $username = isset($_POST['fm_usr']) ? fm_validate_input($_POST['fm_usr'], 'username') : '';
        $password = isset($_POST['fm_pwd']) ? $_POST['fm_pwd'] : '';
        $token = isset($_POST['token']) ? $_POST['token'] : '';
        
        // Rate limiting
        $rate_limiter = null;
        if (class_exists('RateLimiter')) {
            $rate_limiter = new RateLimiter();
            if (!$rate_limiter->check_limit('login')) {
                $audit = new AuditLogger();
                $audit->log('login_blocked_rate_limit', $username, 'Too many attempts');
                fm_set_msg(lng('Too many login attempts. Please try again later.'), 'error');
                fm_redirect(FM_SELF_URL);
            }
        }
        
        sleep(1); // Anti-brute force delay
        
        if (function_exists('password_verify')) {
            if ($username && isset($auth_users[$username]) && password_verify($password, $auth_users[$username]) && verifyToken($token)) {
                // Successful login
                $_SESSION[FM_SESSION_ID]['logged'] = $username;
                fm_online_touch_user($username);
                
                // Audit log
                if (class_exists('AuditLogger')) {
                    $audit = new AuditLogger();
                    $audit->log('user_login', $username, 'Successful login');
                }
                
                // Reset rate limiter
                if ($rate_limiter) {
                    $rate_limiter->reset('login');
                }
                
                fm_set_msg(lng('You are logged in'));
                fm_redirect(FM_SELF_URL);
            } else {
                // Failed login attempt
                $audit = new AuditLogger();
                $audit->log('login_failed', $username ?? 'unknown', 'Invalid username or password');
                
                // Record rate limit attempt
                if ($rate_limiter) {
                    $rate_limiter->record_attempt('login');
                }
                
                unset($_SESSION[FM_SESSION_ID]['logged']);
                fm_set_msg(lng('Login failed. Invalid username or password'), 'error');
                fm_redirect(FM_SELF_URL);
            }
        } else {
            fm_set_msg(lng('password_hash not supported, Upgrade PHP version'), 'error');;
        }
    } else {
        // Form
        unset($_SESSION[FM_SESSION_ID]['logged']);
        fm_show_header_login();
?>
        <section class="h-100">
            <div class="container h-100">
                <div class="row justify-content-md-center align-content-center h-100vh">
                    <div class="card-wrapper">
                        <div class="card fat" data-bs-theme="<?php echo FM_THEME; ?>">
                            <div class="card-body">
                                <form class="form-signin" action="" method="post" autocomplete="off">
                                    <div class="mb-3">
                                        <div class="brand">
                                            <img src="<?php echo fm_enc(LOGIN_LOGO_PATH); ?>" alt="<?php echo fm_enc(LOGIN_COMPANY_NAME); ?>">
                                        </div>
                                        <div class="text-center">
                                            <h1 class="card-title"><?php echo APP_TITLE; ?></h1>
                                            <div class="company-subtitle">
                                                <?php echo LOGIN_COMPANY_NAME; ?>
                                            </div>
                                        </div>
                                    </div>
                                    <hr />
                                    <div class="mb-3">
                                        <label for="fm_usr" class="pb-2"><?php echo lng('Username'); ?></label>
                                        <input type="text" class="form-control" id="fm_usr" name="fm_usr" required autofocus>
                                    </div>

                                    <div class="mb-3">
                                        <label for="fm_pwd" class="pb-2"><?php echo lng('Password'); ?></label>
                                        <input type="password" class="form-control" id="fm_pwd" name="fm_pwd" required>
                                    </div>

                                    <div class="mb-3">
                                        <?php fm_show_message(); ?>
                                    </div>
                                    <input type="hidden" name="token" value="<?php echo htmlentities($_SESSION['token']); ?>" />
                                    <div class="mb-3">
                                        <button type="submit" class="btn btn-success btn-block w-100 mt-4" role="button">
                                            <?php echo lng('Login'); ?>
                                        </button>
                                    </div>
                                </form>
                            </div>
                        </div>
                        <div class="footer text-center">
                            &mdash;&mdash; &copy;
                            <a href="<?php echo LOGIN_COMPANY_URL; ?>" target="_blank" class="text-decoration-none text-muted" data-version="<?php echo VERSION; ?>"><?php echo LOGIN_COMPANY_NAME; ?></a> &mdash;&mdash;
                        </div>
                    </div>
                </div>
            </div>
        </section>

    <?php
        fm_show_footer_login();
        exit;
    }
}

if ($use_auth && isset($_SESSION[FM_SESSION_ID]['logged'])) {
    fm_online_touch_user($_SESSION[FM_SESSION_ID]['logged']);
}

// clean and check $root_path
$root_path = rtrim($root_path, '\\/');
$root_path = str_replace('\\', '/', $root_path);
if (!@is_dir($root_path)) {
    echo "<h1>" . lng('Root path') . " \"{$root_path}\" " . lng('not found!') . " </h1>";
    exit;
}

// build per-user allowed directory list (optional restrictions)
if ($use_auth && isset($_SESSION[FM_SESSION_ID]['logged'], $directories_users[$_SESSION[FM_SESSION_ID]['logged']])) {
    $user_dirs = $directories_users[$_SESSION[FM_SESSION_ID]['logged']];
    if (!is_array($user_dirs)) {
        $user_dirs = array($user_dirs);
    }

    foreach ($user_dirs as $dir) {
        if (!is_string($dir) || trim($dir) === '') {
            continue;
        }

        $dir = str_replace('\\', '/', trim($dir));
        $is_absolute = preg_match('/^(?:[a-zA-Z]:\\/|\/)/', $dir) === 1;
        $candidate = $is_absolute ? $dir : ($root_path . '/' . ltrim($dir, '/'));
        $candidate = rtrim(str_replace('\\', '/', $candidate), '/');

        if (!fm_is_path_inside($candidate, $root_path)) {
            continue;
        }

        if (@is_dir($candidate)) {
            $fm_user_allowed_dirs[] = $candidate;
        }
    }

    $fm_user_allowed_dirs = array_values(array_unique($fm_user_allowed_dirs));

    if (empty($fm_user_allowed_dirs)) {
        // No valid personal directory found – fall back to the shared 'free' folder.
        $free_dir = rtrim(str_replace('\\', '/', $root_path), '/') . '/free';
        if (!@is_dir($free_dir)) {
            @mkdir($free_dir, 0755, true);
        }
        if (@is_dir($free_dir)) {
            $fm_user_allowed_dirs = array($free_dir);
        } else {
            fm_set_msg('Access denied. No valid project directories assigned to your account.', 'error');
            fm_show_header_login();
            fm_show_message();
            fm_show_footer_login();
            exit;
        }
    }
}

defined('FM_SHOW_HIDDEN') || define('FM_SHOW_HIDDEN', $show_hidden_files);
defined('FM_ROOT_PATH') || define('FM_ROOT_PATH', $root_path);
defined('FM_LANG') || define('FM_LANG', $lang);
defined('FM_FILE_EXTENSION') || define('FM_FILE_EXTENSION', $allowed_file_extensions);
defined('FM_UPLOAD_EXTENSION') || define('FM_UPLOAD_EXTENSION', $allowed_upload_extensions);
defined('FM_EXCLUDE_ITEMS') || define('FM_EXCLUDE_ITEMS', (version_compare(PHP_VERSION, '7.0.0', '<') ? serialize($exclude_items) : $exclude_items));
defined('FM_DOC_VIEWER') || define('FM_DOC_VIEWER', $online_viewer);
define('FM_READONLY', $global_readonly || ($use_auth && !empty($readonly_users) && isset($_SESSION[FM_SESSION_ID]['logged']) && in_array($_SESSION[FM_SESSION_ID]['logged'], $readonly_users)));
define('FM_UPLOAD_ONLY', $use_auth && !empty($upload_only_users) && isset($_SESSION[FM_SESSION_ID]['logged']) && in_array($_SESSION[FM_SESSION_ID]['logged'], $upload_only_users));
define('FM_MANAGER', $use_auth && !empty($manager_users) && isset($_SESSION[FM_SESSION_ID]['logged']) && in_array($_SESSION[FM_SESSION_ID]['logged'], $manager_users));
define('FM_IS_WIN', DIRECTORY_SEPARATOR == '\\');

// always use ?p=
if (!isset($_GET['p']) && empty($_FILES)) {
    fm_redirect(FM_SELF_URL . '?p=');
}

// get path
$p = isset($_GET['p']) ? $_GET['p'] : (isset($_POST['p']) ? $_POST['p'] : '');

// clean path
$p = fm_clean_path($p);

// for ajax request - save
$input = file_get_contents('php://input');
$_POST = (strpos($input, 'ajax') != FALSE && strpos($input, 'save') != FALSE) ? json_decode($input, true) : $_POST;

// instead globals vars
define('FM_PATH', $p);
define('FM_USE_AUTH', $use_auth);
define('FM_EDIT_FILE', $edit_files);
defined('FM_ICONV_INPUT_ENC') || define('FM_ICONV_INPUT_ENC', $iconv_input_encoding);
defined('FM_USE_HIGHLIGHTJS') || define('FM_USE_HIGHLIGHTJS', $use_highlightjs);
defined('FM_HIGHLIGHTJS_STYLE') || define('FM_HIGHLIGHTJS_STYLE', $highlightjs_style);
defined('FM_DATETIME_FORMAT') || define('FM_DATETIME_FORMAT', $datetime_format);

$fm_current_abs_path = FM_ROOT_PATH . (FM_PATH != '' ? '/' . FM_PATH : '');
if (!fm_user_can_access_path($fm_current_abs_path, true)) {
    $fm_fallback_path = fm_get_user_default_path();
    fm_set_msg('Access denied. Path restriction applicable.', 'error');
    fm_redirect(FM_SELF_URL . '?p=' . urlencode($fm_fallback_path));
}
define('FM_CAN_WRITE_IN_PATH', fm_user_can_access_path($fm_current_abs_path, false));

unset($p, $use_auth, $iconv_input_encoding, $use_highlightjs, $highlightjs_style);

/*************************** ACTIONS ***************************/

// Handle all AJAX Request
if ((isset($_SESSION[FM_SESSION_ID]['logged'], $auth_users[$_SESSION[FM_SESSION_ID]['logged']]) || !FM_USE_AUTH) && isset($_POST['ajax'], $_POST['token'])) {
    $ajax_action_handler = new TFM_AjaxActionHandler(FM_ROOT_PATH, FM_PATH, __DIR__);
    $ajax_action_handler->handle($_POST, $_GET, $_REQUEST, $auth_users);
}

// Delete file / folder
if (isset($_GET['del'], $_POST['token']) && !FM_READONLY && !FM_UPLOAD_ONLY && !FM_MANAGER && FM_CAN_WRITE_IN_PATH) {
    $file_action_handler = new TFM_FileActionHandler(FM_ROOT_PATH, FM_PATH);
    $file_action_handler->handleDelete($_GET, $_POST);
    exit;
}

// Create a new file/folder
if (isset($_POST['newfilename'], $_POST['newfile'], $_POST['token']) && !FM_READONLY && !FM_UPLOAD_ONLY && FM_CAN_WRITE_IN_PATH) {
    $file_action_handler = new TFM_FileActionHandler(FM_ROOT_PATH, FM_PATH);
    $file_action_handler->handleCreate($_POST);
    exit;
}

// Copy folder / file
if (isset($_GET['copy'], $_GET['finish']) && !FM_READONLY && !FM_UPLOAD_ONLY && FM_CAN_WRITE_IN_PATH) {
    $copy_action_handler = new TFM_CopyActionHandler(FM_ROOT_PATH, FM_PATH);
    $copy_action_handler->handleCopy($_GET);
    exit;
}

// Mass copy files/ folders
if (isset($_POST['file'], $_POST['copy_to'], $_POST['finish'], $_POST['token']) && !FM_READONLY && !FM_UPLOAD_ONLY && FM_CAN_WRITE_IN_PATH) {
    $copy_action_handler = new TFM_CopyActionHandler(FM_ROOT_PATH, FM_PATH);
    $copy_action_handler->handleMassCopy($_POST);
    exit;
}

// Rename
if (isset($_POST['rename_from'], $_POST['rename_to'], $_POST['token']) && !FM_READONLY && !FM_UPLOAD_ONLY && FM_CAN_WRITE_IN_PATH) {
    $file_action_handler = new TFM_FileActionHandler(FM_ROOT_PATH, FM_PATH);
    $file_action_handler->handleRename($_POST);
    exit;
}

// Download
if (class_exists('TFM_DownloadPreviewHandler')) {
    $download_preview_handler = new TFM_DownloadPreviewHandler(FM_ROOT_PATH, FM_PATH);
    if ($download_preview_handler->handleDownload($_GET, $_POST)) {
        exit;
    }

    // Inline preview (images/audio/videos/pdf/office) for authenticated UI cards and file view embeds
    if ($download_preview_handler->handlePreview($_GET)) {
        exit;
    }
}

// Upload
if (!empty($_FILES) && (!FM_READONLY || FM_UPLOAD_ONLY) && FM_CAN_WRITE_IN_PATH) {
    $legacy_upload_handler = new TFM_LegacyUploadHandler(FM_ROOT_PATH, FM_PATH);
    $legacy_upload_handler->handle($_FILES, $_POST, $_REQUEST);
}

// Mass deleting
if (isset($_POST['group'], $_POST['delete'], $_POST['token']) && !FM_READONLY && !FM_UPLOAD_ONLY && !FM_MANAGER && FM_CAN_WRITE_IN_PATH) {
    $file_action_handler = new TFM_FileActionHandler(FM_ROOT_PATH, FM_PATH);
    $file_action_handler->handleMassDelete($_POST);
    exit;
}

// Pack files zip, tar
if (isset($_POST['group'], $_POST['token']) && (isset($_POST['zip']) || isset($_POST['tar'])) && !FM_READONLY && !FM_UPLOAD_ONLY && FM_CAN_WRITE_IN_PATH) {
    $archive_action_handler = new TFM_ArchiveActionHandler(FM_ROOT_PATH, FM_PATH);
    $archive_action_handler->handlePack($_POST);
    exit;
}

// Unpack zip, tar
if (isset($_POST['unzip'], $_POST['token']) && !FM_READONLY && !FM_UPLOAD_ONLY && FM_CAN_WRITE_IN_PATH) {
    $archive_action_handler = new TFM_ArchiveActionHandler(FM_ROOT_PATH, FM_PATH);
    $archive_action_handler->handleUnpack($_POST);
    exit;
}

// Change Perms (not for Windows)
if (isset($_POST['chmod'], $_POST['token']) && !FM_READONLY && !FM_UPLOAD_ONLY && !FM_IS_WIN && FM_CAN_WRITE_IN_PATH) {
    $file_action_handler = new TFM_FileActionHandler(FM_ROOT_PATH, FM_PATH);
    $file_action_handler->handleChmod($_POST);
    exit;
}

/*************************** ACTIONS ***************************/

$directory_listing_service = new TFM_DirectoryListingService(FM_ROOT_PATH, FM_PATH);
$listing_context = $directory_listing_service->buildContext();

$path = $listing_context['path'];
$parent = $listing_context['parent'];
$objects = $listing_context['objects'];
$folders = $listing_context['folders'];
$files = $listing_context['files'];
$current_path = $listing_context['current_path'];

// upload form
if (isset($_GET['upload']) && (!FM_READONLY || FM_UPLOAD_ONLY) && FM_CAN_WRITE_IN_PATH) {
    fm_show_header(); // HEADER
    fm_show_nav_path(FM_PATH); // current path
    //get the allowed file extensions
    function getUploadExt()
    {
        $extArr = explode(',', FM_UPLOAD_EXTENSION);
        if (FM_UPLOAD_EXTENSION && $extArr) {
            array_walk($extArr, function (&$x) {
                $x = ".$x";
            });
            return implode(',', $extArr);
        }
        return '';
    }
    ?>
    <?php print_external('css-dropzone'); ?>
    <div class="path">

        <div class="card mb-2 fm-upload-wrapper" data-bs-theme="<?php echo FM_THEME; ?>">
            <div class="card-header">
                <ul class="nav nav-tabs card-header-tabs">
                    <li class="nav-item">
                        <a class="nav-link active" href="#fileUploader" data-target="#fileUploader"><i class="fa fa-arrow-circle-o-up"></i> <?php echo lng('UploadingFiles') ?></a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#urlUploader" class="js-url-upload" data-target="#urlUploader"><i class="fa fa-link"></i> <?php echo lng('Upload from URL') ?></a>
                    </li>
                </ul>
            </div>
            <div class="card-body">
                <p class="card-text">
                    <a href="?p=<?php echo FM_PATH ?>" class="float-right"><i class="fa fa-chevron-circle-left go-back"></i> <?php echo lng('Back') ?></a>
                    <strong><?php echo lng('DestinationFolder') ?></strong>: <?php echo fm_enc(fm_convert_win(FM_PATH)) ?>
                </p>

                <form action="<?php echo htmlspecialchars(FM_SELF_URL) . '?p=' . fm_enc(FM_PATH) ?>" class="dropzone card-tabs-container" id="fileUploader" enctype="multipart/form-data">
                    <input type="hidden" name="p" value="<?php echo fm_enc(FM_PATH) ?>">
                    <input type="hidden" name="fullpath" id="fullpath" value="<?php echo fm_enc(FM_PATH) ?>">
                    <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
                    <div class="fallback">
                        <input name="file" type="file" multiple />
                    </div>
                </form>

                <div class="upload-url-wrapper card-tabs-container hidden" id="urlUploader">
                    <form id="js-form-url-upload" class="row row-cols-lg-auto g-3 align-items-center" onsubmit="return upload_from_url(this);" method="POST" action="">
                        <input type="hidden" name="type" value="upload" aria-label="hidden" aria-hidden="true">
                        <input type="url" placeholder="URL" name="uploadurl" required class="form-control" style="width: 80%">
                        <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
                        <button type="submit" class="btn btn-primary ms-3"><?php echo lng('Upload') ?></button>
                        <div class="lds-facebook">
                            <div></div>
                            <div></div>
                            <div></div>
                        </div>
                    </form>
                    <div id="js-url-upload__list" class="col-9 mt-3"></div>
                </div>
            </div>
        </div>
    </div>
    <?php print_external('js-dropzone'); ?>
    <script>
        Dropzone.options.fileUploader = {
            chunking: true,
            chunkSize: <?php echo UPLOAD_CHUNK_SIZE; ?>,
            forceChunking: true,
            retryChunks: true,
            retryChunksLimit: 3,
            parallelUploads: 1,
            parallelChunkUploads: false,
            timeout: 120000,
            maxFilesize: "<?php echo MAX_UPLOAD_SIZE; ?>",
            acceptedFiles: "<?php echo getUploadExt() ?>",
            init: function() {
                this.on("sending", function(file, xhr, formData) {
                    let _path = (file.fullPath) ? file.fullPath : file.name;
                    document.getElementById("fullpath").value = _path;
                    xhr.ontimeout = (function() {
                        toast('Error: Server Timeout');
                    });
                }).on("success", function(res) {
                    try {
                        let _response = JSON.parse(res.xhr.response);

                        if (_response.status == "error") {
                            toast(_response.info);
                        }
                    } catch (e) {
                        toast("Error: Invalid JSON response");
                    }
                }).on("error", function(file, response) {
                    toast(response);
                });
            }
        }
    </script>
<?php
    fm_show_footer();
    exit;
}

// copy form POST
if (isset($_POST['copy']) && !FM_READONLY && !FM_UPLOAD_ONLY && FM_CAN_WRITE_IN_PATH) {
    $copy_files = isset($_POST['file']) ? $_POST['file'] : null;
    if (!is_array($copy_files) || empty($copy_files)) {
        fm_set_msg(lng('Nothing selected'), 'alert');
        $FM_PATH = FM_PATH;
        fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
    }

    fm_show_header(); // HEADER
    fm_show_nav_path(FM_PATH); // current path
?>
    <div class="path">
        <div class="card" data-bs-theme="<?php echo FM_THEME; ?>">
            <div class="card-header">
                <h6><?php echo lng('Copying') ?></h6>
            </div>
            <div class="card-body">
                <form action="" method="post">
                    <input type="hidden" name="p" value="<?php echo fm_enc(FM_PATH) ?>">
                    <input type="hidden" name="finish" value="1">
                    <?php
                    foreach ($copy_files as $cf) {
                        echo '<input type="hidden" name="file[]" value="' . fm_enc($cf) . '">' . PHP_EOL;
                    }
                    ?>
                    <p class="break-word"><strong><?php echo lng('Files') ?></strong>: <b><?php echo implode('</b>, <b>', $copy_files) ?></b></p>
                    <p class="break-word"><strong><?php echo lng('SourceFolder') ?></strong>: <?php echo fm_enc(fm_convert_win(FM_ROOT_PATH . '/' . FM_PATH)) ?><br>
                        <label for="inp_copy_to"><strong><?php echo lng('DestinationFolder') ?></strong>:</label>
                        <?php echo FM_ROOT_PATH ?>/<input type="text" name="copy_to" id="inp_copy_to" value="<?php echo fm_enc(FM_PATH) ?>">
                    </p>
                    <p class="custom-checkbox custom-control"><input type="checkbox" name="move" value="1" id="js-move-files" class="custom-control-input">
                        <label for="js-move-files" class="custom-control-label ms-2"><?php echo lng('Move') ?></label>
                    </p>
                    <p>
                        <b><a href="?p=<?php echo urlencode(FM_PATH) ?>" class="btn btn-outline-danger"><i class="fa fa-times-circle"></i> <?php echo lng('Cancel') ?></a></b>&nbsp;
                        <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
                        <button type="submit" class="btn btn-success"><i class="fa fa-check-circle"></i> <?php echo lng('Copy') ?></button>
                    </p>
                </form>
            </div>
        </div>
    </div>
<?php
    fm_show_footer();
    exit;
}

// copy form
if (isset($_GET['copy']) && !isset($_GET['finish']) && !FM_READONLY && !FM_UPLOAD_ONLY && FM_CAN_WRITE_IN_PATH) {
    $copy = $_GET['copy'];
    $copy = fm_clean_path($copy);
    if ($copy == '' || !file_exists(FM_ROOT_PATH . '/' . $copy)) {
        fm_set_msg(lng('File not found'), 'error');
        $FM_PATH = FM_PATH;
        fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
    }

    fm_show_header(); // HEADER
    fm_show_nav_path(FM_PATH); // current path
?>
    <div class="path">
        <p><b>Copying</b></p>
        <p class="break-word">
            <strong>Source path:</strong> <?php echo fm_enc(fm_convert_win(FM_ROOT_PATH . '/' . $copy)) ?><br>
            <strong>Destination folder:</strong> <?php echo fm_enc(fm_convert_win(FM_ROOT_PATH . '/' . FM_PATH)) ?>
        </p>
        <p>
            <b><a href="?p=<?php echo urlencode(FM_PATH) ?>&amp;copy=<?php echo urlencode($copy) ?>&amp;finish=1"><i class="fa fa-check-circle"></i> Copy</a></b> &nbsp;
            <b><a href="?p=<?php echo urlencode(FM_PATH) ?>&amp;copy=<?php echo urlencode($copy) ?>&amp;finish=1&amp;move=1"><i class="fa fa-check-circle"></i> Move</a></b> &nbsp;
            <b><a href="?p=<?php echo urlencode(FM_PATH) ?>" class="text-danger"><i class="fa fa-times-circle"></i> Cancel</a></b>
        </p>
        <p><i><?php echo lng('Select folder') ?></i></p>
        <ul class="folders break-word">
            <?php
            if ($parent !== false) {
            ?>
                <li><a href="?p=<?php echo urlencode($parent) ?>&amp;copy=<?php echo urlencode($copy) ?>"><i class="fa fa-chevron-circle-left"></i> ..</a></li>
            <?php
            }
            foreach ($folders as $f) {
            ?>
                <li>
                    <a href="?p=<?php echo urlencode(trim(FM_PATH . '/' . $f, '/')) ?>&amp;copy=<?php echo urlencode($copy) ?>"><i class="fa fa-folder-o"></i> <?php echo fm_convert_win($f) ?></a>
                </li>
            <?php
            }
            ?>
        </ul>
    </div>
<?php
    fm_show_footer();
    exit;
}

if (isset($_GET['settings']) && ((FM_USE_AUTH && !empty($_SESSION[FM_SESSION_ID]['logged'])) || (!FM_READONLY && FM_CAN_WRITE_IN_PATH))) {
    fm_show_header(); // HEADER
    fm_show_nav_path(FM_PATH); // current path
    global $cfg, $lang, $lang_list;
?>

    <div class="col-md-8 offset-md-2 pt-3">
        <div class="card mb-2" data-bs-theme="<?php echo FM_THEME; ?>">
            <h6 class="card-header d-flex justify-content-between">
                <span><i class="fa fa-cog"></i> <?php echo lng('Settings') ?></span>
                <a href="?p=<?php echo FM_PATH ?>" class="text-danger"><i class="fa fa-times-circle-o"></i> <?php echo lng('Cancel') ?></a>
            </h6>
            <div class="card-body">
                <form id="js-settings-form" action="" method="post" data-type="ajax" onsubmit="return save_settings(this)">
                    <input type="hidden" name="type" value="settings" aria-label="hidden" aria-hidden="true">
                    <div class="form-group row">
                        <label for="js-language" class="col-sm-3 col-form-label"><?php echo lng('Language') ?></label>
                        <div class="col-sm-5">
                            <select class="form-select" id="js-language" name="js-language">
                                <?php
                                function getSelected($l)
                                {
                                    global $lang;
                                    return ($lang == $l) ? 'selected' : '';
                                }
                                foreach ($lang_list as $k => $v) {
                                    echo "<option value='$k' " . getSelected($k) . ">$v</option>";
                                }
                                ?>
                            </select>
                        </div>
                    </div>
                    <?php if (!FM_UPLOAD_ONLY): ?>
                    <div class="mt-3 mb-3 row ">
                        <label for="js-error-report" class="col-sm-3 col-form-label"><?php echo lng('ErrorReporting') ?></label>
                        <div class="col-sm-9">
                            <div class="form-check form-switch">
                                <input class="form-check-input" type="checkbox" role="switch" id="js-error-report" name="js-error-report" value="true" <?php echo $report_errors ? 'checked' : ''; ?> />
                            </div>
                        </div>
                    </div>

                    <div class="mb-3 row">
                        <label for="js-show-hidden" class="col-sm-3 col-form-label"><?php echo lng('ShowHiddenFiles') ?></label>
                        <div class="col-sm-9">
                            <div class="form-check form-switch">
                                <input class="form-check-input" type="checkbox" role="switch" id="js-show-hidden" name="js-show-hidden" value="true" <?php echo $show_hidden_files ? 'checked' : ''; ?> />
                            </div>
                        </div>
                    </div>
                    <?php endif; ?>
                    <?php if (FM_UPLOAD_ONLY): ?>
                    <div class="alert alert-info py-2 px-3" role="alert">
                        <i class="fa fa-info-circle" aria-hidden="true"></i>
                        <?php echo lng('Some internal options are available only for managers'); ?>
                    </div>
                    <?php endif; ?>

                    <div class="mb-3 row">
                        <label for="js-hide-cols" class="col-sm-3 col-form-label"><?php echo lng('HideColumns') ?></label>
                        <div class="col-sm-9">
                            <div class="form-check form-switch">
                                <input class="form-check-input" type="checkbox" role="switch" id="js-hide-cols" name="js-hide-cols" value="true" <?php echo $hide_Cols ? 'checked' : ''; ?> />
                            </div>
                        </div>
                    </div>

                    <div class="mb-3 row">
                        <label for="js-3-1" class="col-sm-3 col-form-label"><?php echo lng('Theme') ?></label>
                        <div class="col-sm-5">
                            <select class="form-select w-100 text-capitalize" id="js-3-0" name="js-theme-3">
                                <option value='light' <?php if ($theme == "light") {
                                                            echo "selected";
                                                        } ?>>
                                    <?php echo lng('light') ?>
                                </option>
                                <option value='dark' <?php if ($theme == "dark") {
                                                            echo "selected";
                                                        } ?>>
                                    <?php echo lng('dark') ?>
                                </option>
                            </select>
                        </div>
                    </div>

                    <div class="mb-3 row">
                        <div class="col-sm-10">
                            <button type="submit" class="btn btn-success"> <i class="fa fa-check-circle"></i> <?php echo lng('Save'); ?></button>
                        </div>
                    </div>

                    <small class="text-body-secondary">* <?php echo lng('Sometimes the save action may not work on the first try, so please attempt it again') ?>.</small>
                </form>

                <?php if ($use_auth && !empty($_SESSION[FM_SESSION_ID]['logged'])): ?>
                <hr>
                <h6 class="mt-3 mb-3"><i class="fa fa-lock"></i> <?php echo lng('Change Password') ?></h6>
                <form id="js-changepwd-form" action="" method="post" onsubmit="return change_password(this)">
                    <input type="hidden" name="type" value="changepwd" aria-label="hidden" aria-hidden="true">
                    <div class="mb-2 row">
                        <label class="col-sm-3 col-form-label"><?php echo lng('Current password') ?></label>
                        <div class="col-sm-5">
                            <input type="password" class="form-control" name="current_password" autocomplete="current-password" required>
                        </div>
                    </div>
                    <div class="mb-2 row">
                        <label class="col-sm-3 col-form-label"><?php echo lng('New password') ?></label>
                        <div class="col-sm-5">
                            <input type="password" class="form-control" name="new_password" autocomplete="new-password" minlength="6" required>
                        </div>
                    </div>
                    <div class="mb-3 row">
                        <label class="col-sm-3 col-form-label"><?php echo lng('Confirm password') ?></label>
                        <div class="col-sm-5">
                            <input type="password" class="form-control" name="confirm_password" autocomplete="new-password" minlength="6" required>
                        </div>
                    </div>
                    <div class="mb-3 row">
                        <div class="col-sm-10">
                            <button type="submit" class="btn btn-warning"><i class="fa fa-key"></i> <?php echo lng('Change Password') ?></button>
                        </div>
                    </div>
                </form>
                <?php endif; ?>
            </div>
        </div>
    </div>
<?php
    fm_show_footer();
    exit;
}

if (isset($_GET['help'])) {
    fm_show_header(); // HEADER
    fm_show_nav_path(FM_PATH); // current path
    global $cfg, $lang;
?>

    <div class="col-md-8 offset-md-2 pt-3">
        <div class="card mb-2" data-bs-theme="<?php echo FM_THEME; ?>">
            <h6 class="card-header d-flex justify-content-between">
                <span><i class="fa fa-exclamation-circle"></i> <?php echo lng('Help') ?></span>
                <a href="?p=<?php echo FM_PATH ?>" class="text-danger"><i class="fa fa-times-circle-o"></i> <?php echo lng('Cancel') ?></a>
            </h6>
            <div class="card-body">
                <div class="row">
                    <div class="col-xs-12 col-sm-6">
                        <p>
                        <h3><a href="https://github.com/prasathmani/tinyfilemanager" target="_blank" class="app-v-title"> Tiny File Manager <?php echo VERSION; ?></a></h3>
                        </p>
                        <p>Author: PRAŚATH MANİ</p>
                        <p>Mail Us: <a href="mailto:ccpprogrammers@gmail.com">ccpprogrammers [at] gmail [dot] com</a> </p>
                    </div>
                    <div class="col-xs-12 col-sm-6">
                        <div class="card">
                            <ul class="list-group list-group-flush">
                                <li class="list-group-item"><a href="https://github.com/prasathmani/tinyfilemanager/wiki" target="_blank"><i class="fa fa-question-circle"></i> <?php echo lng('Help Documents') ?> </a> </li>
                                <li class="list-group-item"><a href="https://github.com/prasathmani/tinyfilemanager/issues" target="_blank"><i class="fa fa-bug"></i> <?php echo lng('Report Issue') ?></a></li>
                                <?php if (!FM_READONLY) { ?>
                                    <li class="list-group-item"><a href="javascript:show_new_pwd();"><i class="fa fa-lock"></i> <?php echo lng('Generate new password hash') ?></a></li>
                                <?php } ?>
                            </ul>
                        </div>
                    </div>
                </div>
                <div class="row js-new-pwd hidden mt-2">
                    <div class="col-12">
                        <form class="form-inline" onsubmit="return new_password_hash(this)" method="POST" action="">
                            <input type="hidden" name="type" value="pwdhash" aria-label="hidden" aria-hidden="true">
                            <div class="form-group mb-2">
                                <label for="staticEmail2"><?php echo lng('Generate new password hash') ?></label>
                            </div>
                            <div class="form-group mx-sm-3 mb-2">
                                <label for="inputPassword2" class="sr-only"><?php echo lng('Password') ?></label>
                                <input type="text" class="form-control btn-sm" id="inputPassword2" name="inputPassword2" placeholder="<?php echo lng('Password') ?>" required>
                            </div>
                            <button type="submit" class="btn btn-success btn-sm mb-2"><?php echo lng('Generate') ?></button>
                        </form>
                        <textarea class="form-control" rows="2" readonly id="js-pwd-result"></textarea>
                    </div>
                </div>
            </div>
        </div>
    </div>
<?php
    fm_show_footer();
    exit;
}

// file viewer
if (isset($_GET['view'])) {
    $file_view_context_service = new TFM_FileViewContextService(FM_ROOT_PATH, FM_PATH);
    $file_view_context = $file_view_context_service->build($_GET['view']);

    $file = $file_view_context['file'];
    $file_url = $file_view_context['file_url'];
    $file_path = $file_view_context['file_path'];
    $view_info = $file_view_context['view_info'];

    fm_show_header(); // HEADER
    fm_show_nav_path(FM_PATH); // current path

    $ext = $view_info['ext'];
    $mime_type = $view_info['mime_type'];
    $is_image_mime = $view_info['is_image_mime'];
    $filesize_raw = $view_info['filesize_raw'];
    $filesize = $view_info['filesize'];
    $is_zip = $view_info['is_zip'];
    $is_gzip = $view_info['is_gzip'];
    $is_image = $view_info['is_image'];
    $is_audio = $view_info['is_audio'];
    $is_video = $view_info['is_video'];
    $is_pdf = $view_info['is_pdf'];
    $is_text = $view_info['is_text'];
    $is_onlineViewer = $view_info['is_onlineViewer'];
    $view_title = $view_info['view_title'];
    $filenames = $view_info['filenames'];
    $content = $view_info['content'];
    require __DIR__ . '/src/renderers/file-viewer.php';
    fm_show_footer();
    exit;
}

// file editor
if (isset($_GET['edit']) && !FM_READONLY && !FM_UPLOAD_ONLY && FM_CAN_WRITE_IN_PATH) {
    $file_editor_context_service = new TFM_FileEditorContextService(FM_ROOT_PATH, FM_PATH);
    $editor_context = $file_editor_context_service->build($_GET['edit'], $_GET, $_POST);

    $file = $editor_context['file'];
    $editFile = $editor_context['editFile'];
    $file_url = $editor_context['file_url'];
    $file_path = $editor_context['file_path'];
    $isNormalEditor = $editor_context['isNormalEditor'];
    $ext = $editor_context['ext'];
    $mime_type = $editor_context['mime_type'];
    $filesize = $editor_context['filesize'];
    $is_text = $editor_context['is_text'];
    $content = $editor_context['content'];

    header('X-XSS-Protection:0');
    fm_show_header(); // HEADER
    fm_show_nav_path(FM_PATH); // current path
    require __DIR__ . '/src/renderers/file-editor.php';
    fm_show_footer();
    exit;
}

// chmod (not for Windows)
if (isset($_GET['chmod']) && !FM_READONLY && !FM_UPLOAD_ONLY && !FM_IS_WIN && FM_CAN_WRITE_IN_PATH) {
    $chmod_page_context_service = new TFM_ChmodPageContextService(FM_ROOT_PATH, FM_PATH);
    $chmod_context = $chmod_page_context_service->build($_GET['chmod']);

    $file = $chmod_context['file'];
    $file_url = $chmod_context['file_url'];
    $file_path = $chmod_context['file_path'];
    $mode = $chmod_context['mode'];

    fm_show_header(); // HEADER
    fm_show_nav_path(FM_PATH); // current path
?>
    <div class="path">
        <div class="card mb-2" data-bs-theme="<?php echo FM_THEME; ?>">
            <h6 class="card-header">
                <?php echo lng('ChangePermissions') ?>
            </h6>
            <div class="card-body">
                <p class="card-text">
                    <?php $display_path = fm_get_display_path($file_path); ?>
                    <?php echo $display_path['label']; ?>: <?php echo $display_path['path']; ?><br>
                </p>
                <form action="" method="post">
                    <input type="hidden" name="p" value="<?php echo fm_enc(FM_PATH) ?>">
                    <input type="hidden" name="chmod" value="<?php echo fm_enc($file) ?>">

                    <table class="table compact-table" data-bs-theme="<?php echo FM_THEME; ?>">
                        <tr>
                            <td></td>
                            <td><b><?php echo lng('Owner') ?></b></td>
                            <td><b><?php echo lng('Group') ?></b></td>
                            <td><b><?php echo lng('Other') ?></b></td>
                        </tr>
                        <tr>
                            <td style="text-align: right"><b><?php echo lng('Read') ?></b></td>
                            <td><label><input type="checkbox" name="ur" value="1" <?php echo ($mode & 00400) ? ' checked' : '' ?>></label></td>
                            <td><label><input type="checkbox" name="gr" value="1" <?php echo ($mode & 00040) ? ' checked' : '' ?>></label></td>
                            <td><label><input type="checkbox" name="or" value="1" <?php echo ($mode & 00004) ? ' checked' : '' ?>></label></td>
                        </tr>
                        <tr>
                            <td style="text-align: right"><b><?php echo lng('Write') ?></b></td>
                            <td><label><input type="checkbox" name="uw" value="1" <?php echo ($mode & 00200) ? ' checked' : '' ?>></label></td>
                            <td><label><input type="checkbox" name="gw" value="1" <?php echo ($mode & 00020) ? ' checked' : '' ?>></label></td>
                            <td><label><input type="checkbox" name="ow" value="1" <?php echo ($mode & 00002) ? ' checked' : '' ?>></label></td>
                        </tr>
                        <tr>
                            <td style="text-align: right"><b><?php echo lng('Execute') ?></b></td>
                            <td><label><input type="checkbox" name="ux" value="1" <?php echo ($mode & 00100) ? ' checked' : '' ?>></label></td>
                            <td><label><input type="checkbox" name="gx" value="1" <?php echo ($mode & 00010) ? ' checked' : '' ?>></label></td>
                            <td><label><input type="checkbox" name="ox" value="1" <?php echo ($mode & 00001) ? ' checked' : '' ?>></label></td>
                        </tr>
                    </table>

                    <p>
                        <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
                        <b><a href="?p=<?php echo urlencode(FM_PATH) ?>" class="btn btn-outline-primary"><i class="fa fa-times-circle"></i> <?php echo lng('Cancel') ?></a></b>&nbsp;
                        <button type="submit" class="btn btn-success"><i class="fa fa-check-circle"></i> <?php echo lng('Change') ?></button>
                    </p>
                </form>
            </div>
        </div>
    </div>
<?php
    fm_show_footer();
    exit;
}

// --- TINYFILEMANAGER MAIN ---
fm_show_header(); // HEADER
fm_show_nav_path(FM_PATH); // current path

// show alert messages
fm_show_message();

$num_files = count($files);
$num_folders = count($folders);
    require __DIR__ . '/src/renderers/main-page.php';
fm_show_footer();

// --- END HTML ---

// Functions

/**
 * Verify CSRF TOKEN and remove after certified
 * @param string $token
 * @return bool
 */
function verifyToken($token)
{
    if (hash_equals($_SESSION['token'], $token)) {
        return true;
    }
    return false;
}

/**
 * Build normalized relative preview target from current path and filename.
 * @param string $path
 * @param string $file
 * @return string
 */
function fm_preview_relative_target($path, $file)
{
    $path = fm_clean_path((string) $path);
    // Preserve '+' when file names come from directory entries and signed URLs.
    $file = rawurldecode((string) $file);
    $file = fm_clean_path($file, false);
    $file = str_replace('/', '', $file);
    if ($file === '') {
        return '';
    }
    return ltrim(($path !== '' ? $path . '/' : '') . $file, '/');
}

/**
 * Derive preview signing secret from runtime configuration.
 * @return string
 */
function fm_preview_secret()
{
    static $secret = null;
    if ($secret !== null) {
        return $secret;
    }

    global $root_path, $auth_users;
    $secret = hash('sha256', __FILE__ . '|' . (string) $root_path . '|' . json_encode($auth_users));
    return $secret;
}

/**
 * Sign preview target for time-limited public access.
 * @param string $relative_target
 * @param int $expires
 * @return string
 */
function fm_preview_signature($relative_target, $expires)
{
    return hash_hmac('sha256', (string) $expires . '|' . $relative_target, fm_preview_secret());
}

/**
 * Build signed preview query string.
 * @param string $path
 * @param string $file
 * @param int $ttl
 * @return string
 */
function fm_build_preview_query($path, $file, $ttl = 900)
{
    $path = fm_clean_path((string) $path);
    // Preserve '+' when file names come from directory entries and signed URLs.
    $raw_file = rawurldecode((string) $file);
    $file = str_replace('/', '', fm_clean_path($raw_file, false));
    $relative_target = fm_preview_relative_target($path, $file);

    $ttl = max(60, (int) $ttl);
    $expires = time() + $ttl;
    $sig = fm_preview_signature($relative_target, $expires);

    return 'p=' . urlencode($path) . '&preview=' . urlencode($file) . '&exp=' . $expires . '&sig=' . $sig;
}

/**
 * Verify signed preview request.
 * @param string $path
 * @param string $file
 * @param mixed $expires
 * @param string $sig
 * @return bool
 */
function fm_has_valid_preview_signature($path, $file, $expires, $sig)
{
    if (!is_numeric($expires) || !is_string($sig) || $sig === '') {
        return false;
    }

    $expires = (int) $expires;
    if ($expires < (time() - 30) || $expires > (time() + 86400)) {
        return false;
    }

    $relative_target = fm_preview_relative_target($path, $file);
    if ($relative_target === '') {
        return false;
    }

    return hash_equals(fm_preview_signature($relative_target, $expires), $sig);
}

/**
 * Delete  file or folder (recursively)
 * @param string $path
 * @return bool
 */
function fm_rdelete($path)
{
    if (is_link($path)) {
        return unlink($path);
    } elseif (is_dir($path)) {
        $objects = scandir($path);
        $ok = true;
        if (is_array($objects)) {
            foreach ($objects as $file) {
                if ($file != '.' && $file != '..') {
                    if (!fm_rdelete($path . '/' . $file)) {
                        $ok = false;
                    }
                }
            }
        }
        return ($ok) ? rmdir($path) : false;
    } elseif (is_file($path)) {
        return unlink($path);
    }
    return false;
}

/**
 * Recursive chmod
 * @param string $path
 * @param int $filemode
 * @param int $dirmode
 * @return bool
 * @todo Will use in mass chmod
 */
function fm_rchmod($path, $filemode, $dirmode)
{
    if (is_dir($path)) {
        if (!chmod($path, $dirmode)) {
            return false;
        }
        $objects = scandir($path);
        if (is_array($objects)) {
            foreach ($objects as $file) {
                if ($file != '.' && $file != '..') {
                    if (!fm_rchmod($path . '/' . $file, $filemode, $dirmode)) {
                        return false;
                    }
                }
            }
        }
        return true;
    } elseif (is_link($path)) {
        return true;
    } elseif (is_file($path)) {
        return chmod($path, $filemode);
    }
    return false;
}

/**
 * Check the file extension which is allowed or not
 * @param string $filename
 * @return bool
 */
function fm_is_valid_ext($filename)
{
    $allowed = (FM_FILE_EXTENSION) ? explode(',', FM_FILE_EXTENSION) : false;

    $ext = pathinfo($filename, PATHINFO_EXTENSION);
    $isFileAllowed = ($allowed) ? in_array($ext, $allowed) : true;

    return ($isFileAllowed) ? true : false;
}

/**
 * Safely rename
 * @param string $old
 * @param string $new
 * @return bool|null
 */
function fm_rename($old, $new)
{
    $isFileAllowed = fm_is_valid_ext($new);

    if (!is_dir($old)) {
        if (!$isFileAllowed) return false;
    }

    return (!file_exists($new) && file_exists($old)) ? rename($old, $new) : null;
}

/**
 * Copy file or folder (recursively).
 * @param string $path
 * @param string $dest
 * @param bool $upd Update files
 * @param bool $force Create folder with same names instead file
 * @return bool
 */
function fm_rcopy($path, $dest, $upd = true, $force = true)
{
    if (!is_dir($path) && !is_file($path)) {
        return false;
    }

    if (is_dir($path)) {
        if (!fm_mkdir($dest, $force)) {
            return false;
        }

        $objects = array_diff(scandir($path), ['.', '..']);

        foreach ($objects as $file) {
            if (!fm_rcopy("$path/$file", "$dest/$file", $upd, $force)) {
                return false;
            }
        }

        return true;
    }

    // Handle file copying
    return fm_copy($path, $dest, $upd);
}


/**
 * Safely create folder
 * @param string $dir
 * @param bool $force
 * @return bool
 */
function fm_mkdir($dir, $force)
{
    if (file_exists($dir)) {
        if (is_dir($dir)) {
            return $dir;
        } elseif (!$force) {
            return false;
        }
        unlink($dir);
    }
    return mkdir($dir, 0777, true);
}

/**
 * Safely copy file
 * @param string $f1
 * @param string $f2
 * @param bool $upd Indicates if file should be updated with new content
 * @return bool
 */
function fm_copy($f1, $f2, $upd)
{
    $time1 = filemtime($f1);
    if (file_exists($f2)) {
        $time2 = filemtime($f2);
        if ($time2 >= $time1 && $upd) {
            return false;
        }
    }
    $ok = copy($f1, $f2);
    if ($ok) {
        touch($f2, $time1);
    }
    return $ok;
}

/**
 * Get mime type
 * @param string $file_path
 * @return mixed|string
 */
function fm_get_mime_type($file_path)
{
    if (function_exists('finfo_open')) {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime = finfo_file($finfo, $file_path);
        finfo_close($finfo);
        return $mime;
    } elseif (function_exists('mime_content_type')) {
        return mime_content_type($file_path);
    } elseif (!stristr(ini_get('disable_functions'), 'shell_exec')) {
        $file = escapeshellarg($file_path);
        $mime = shell_exec('file -bi ' . $file);
        return $mime;
    } else {
        return '--';
    }
}

/**
 * Check whether MIME type is an image MIME.
 * @param mixed $mime_type
 * @return bool
 */
function fm_is_image_mime_type($mime_type)
{
    if (!is_string($mime_type) || $mime_type === '' || $mime_type === '--') {
        return false;
    }
    return strpos(strtolower($mime_type), 'image/') === 0;
}

/**
 * HTTP Redirect
 * @param string $url
 * @param int $code
 */
function fm_redirect($url, $code = 302)
{
    header('Location: ' . $url, true, $code);
    exit;
}

/**
 * Track active authenticated users for manager/admin footer badges.
 */
function fm_online_state_file()
{
    $dir = __DIR__ . '/.fm_usercfg';
    if (!@is_dir($dir)) {
        @mkdir($dir, 0755, true);
    }
    $htaccess = $dir . '/.htaccess';
    if (!@file_exists($htaccess)) {
        @file_put_contents($htaccess, "Order Deny,Allow\nDeny from all\n");
    }
    return $dir . '/online_users.json';
}

function fm_online_touch_user($username)
{
    if (!is_string($username) || $username === '') {
        return;
    }

    $file = fm_online_state_file();
    $now = time();
    $ttl = 900;

    $fh = @fopen($file, 'c+');
    if ($fh === false) {
        return;
    }

    if (!@flock($fh, LOCK_EX)) {
        @fclose($fh);
        return;
    }

    $raw = stream_get_contents($fh);
    $data = json_decode($raw ?: '{}', true);
    if (!is_array($data)) {
        $data = array();
    }

    foreach ($data as $user => $ts) {
        if (!is_numeric($ts) || ((int)$ts < ($now - $ttl))) {
            unset($data[$user]);
        }
    }

    $data[$username] = $now;
    ksort($data);

    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, json_encode($data));
    fflush($fh);
    flock($fh, LOCK_UN);
    fclose($fh);
}

function fm_online_remove_user($username)
{
    if (!is_string($username) || $username === '') {
        return;
    }

    $file = fm_online_state_file();
    $fh = @fopen($file, 'c+');
    if ($fh === false) {
        return;
    }

    if (!@flock($fh, LOCK_EX)) {
        @fclose($fh);
        return;
    }

    $raw = stream_get_contents($fh);
    $data = json_decode($raw ?: '{}', true);
    if (!is_array($data)) {
        $data = array();
    }

    unset($data[$username]);

    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, json_encode($data));
    fflush($fh);
    flock($fh, LOCK_UN);
    fclose($fh);
}

function fm_online_get_users()
{
    $file = fm_online_state_file();
    if (!@file_exists($file)) {
        return array();
    }

    $raw = @file_get_contents($file);
    $data = json_decode($raw ?: '{}', true);
    if (!is_array($data)) {
        return array();
    }

    $now = time();
    $ttl = 900;
    $users = array();
    foreach ($data as $user => $ts) {
        if (is_string($user) && $user !== '' && is_numeric($ts) && ((int)$ts >= ($now - $ttl))) {
            $users[] = $user;
        }
    }

    sort($users, SORT_NATURAL | SORT_FLAG_CASE);
    return $users;
}

/**
 * Write unexpected runtime error details to local errors.log file.
 * @param string $message
 * @return void
 */
function fm_log_error($message)
{
    $date = date('Y-m-d H:i:s');
    $user = isset($_SESSION[FM_SESSION_ID]['logged']) ? $_SESSION[FM_SESSION_ID]['logged'] : 'guest';
    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
    $log_line = '[' . $date . '] [' . $ip . '] [' . $user . '] ' . $message . PHP_EOL;
    @file_put_contents(__DIR__ . '/errors.log', $log_line, FILE_APPEND | LOCK_EX);
}

/**
 * Redirect user to login page on unexpected runtime failures.
 * @return void
 */
function fm_redirect_to_login_on_error()
{
    if (PHP_SAPI === 'cli') {
        exit(1);
    }

    if (session_status() === PHP_SESSION_ACTIVE) {
        unset($_SESSION[FM_SESSION_ID]['logged']);
        $_SESSION['status'] = array(
            'type' => 'error',
            'text' => 'Unexpected server error. Please login again.'
        );
    }

    $target = defined('FM_SELF_URL') ? FM_SELF_URL : (isset($_SERVER['PHP_SELF']) ? $_SERVER['PHP_SELF'] : '/');
    if (!headers_sent()) {
        header('Location: ' . $target, true, 302);
        exit;
    }

    echo '<script>window.location.href=' . json_encode($target) . ';</script>';
    exit;
}

/**
 * Handler for uncaught exceptions.
 * @param Throwable|Exception $exception
 * @return void
 */
function fm_unexpected_exception_handler($exception)
{
    fm_log_error('TinyFileManager unexpected exception: ' . $exception->getMessage());
    error_log('TinyFileManager unexpected exception: ' . $exception->getMessage());
    fm_redirect_to_login_on_error();
}

/**
 * Handler for fatal runtime errors.
 * @return void
 */
function fm_unexpected_shutdown_handler()
{
    $error = error_get_last();
    if (!$error) {
        return;
    }

    $fatal_error_types = array(E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR);
    if (in_array($error['type'], $fatal_error_types, true)) {
        fm_log_error('TinyFileManager fatal error: ' . $error['message'] . ' in ' . $error['file'] . ':' . $error['line']);
        error_log('TinyFileManager fatal error: ' . $error['message'] . ' in ' . $error['file'] . ':' . $error['line']);
        if (ob_get_length()) {
            @ob_clean();
        }
        fm_redirect_to_login_on_error();
    }
}

/**
 * Check if $path is equal to or inside $base path.
 * @param string $path
 * @param string $base
 * @return bool
 */
function fm_is_path_inside($path, $base)
{
    $path = rtrim(str_replace('\\', '/', (string)$path), '/');
    $base = rtrim(str_replace('\\', '/', (string)$base), '/');
    if ($path === '' || $base === '') {
        return false;
    }
    return $path === $base || strpos($path, $base . '/') === 0;
}

/**
 * Check whether the current user can access a path.
 * If $allow_parent is true, parent folders of allowed directories are also valid.
 * @param string $path
 * @param bool $allow_parent
 * @return bool
 */
function fm_user_can_access_path($path, $allow_parent = false)
{
    global $fm_user_allowed_dirs;

    if (empty($fm_user_allowed_dirs) || !is_array($fm_user_allowed_dirs)) {
        return true;
    }

    $path = rtrim(str_replace('\\', '/', (string)$path), '/');
    if ($path === '') {
        return false;
    }

    foreach ($fm_user_allowed_dirs as $allowed_path) {
        $allowed_path = rtrim(str_replace('\\', '/', (string)$allowed_path), '/');
        if ($allowed_path === '') {
            continue;
        }

        if (fm_is_path_inside($path, $allowed_path)) {
            return true;
        }
        if ($allow_parent && fm_is_path_inside($allowed_path, $path)) {
            return true;
        }
    }

    return false;
}

/**
 * Get first accessible relative path from assigned user directories.
 * @return string
 */
function fm_get_user_default_path()
{
    global $fm_user_allowed_dirs;

    if (empty($fm_user_allowed_dirs) || !is_array($fm_user_allowed_dirs)) {
        return '';
    }

    foreach ($fm_user_allowed_dirs as $allowed_path) {
        $allowed_path = rtrim(str_replace('\\', '/', (string)$allowed_path), '/');
        $root_path = rtrim(str_replace('\\', '/', FM_ROOT_PATH), '/');
        if (fm_is_path_inside($allowed_path, $root_path)) {
            $relative_path = ltrim(substr($allowed_path, strlen($root_path)), '/');
            return fm_clean_path($relative_path);
        }
    }

    return '';
}

/**
 * Path traversal prevention and clean the url
 * It replaces (consecutive) occurrences of / and \\ with whatever is in DIRECTORY_SEPARATOR, and processes /. and /.. fine.
 * @param $path
 * @return string
 */
function get_absolute_path($path)
{
    $path = str_replace(array('/', '\\'), DIRECTORY_SEPARATOR, $path);
    $parts = array_filter(explode(DIRECTORY_SEPARATOR, $path), 'strlen');
    $absolutes = array();
    foreach ($parts as $part) {
        if ('.' == $part) continue;
        if ('..' == $part) {
            array_pop($absolutes);
        } else {
            $absolutes[] = $part;
        }
    }
    return implode(DIRECTORY_SEPARATOR, $absolutes);
}

/**
 * Clean path
 * @param string $path
 * @return string
 */
function fm_clean_path($path, $trim = true)
{
    $path = $trim ? trim($path) : $path;
    $path = trim($path, '\\/');
    $path = str_replace(array('../', '..\\'), '', $path);
    $path =  get_absolute_path($path);
    if ($path == '..') {
        $path = '';
    }
    return str_replace('\\', '/', $path);
}

/**
 * Get parent path
 * @param string $path
 * @return bool|string
 */
function fm_get_parent_path($path)
{
    $path = fm_clean_path($path);
    if ($path != '') {
        $array = explode('/', $path);
        if (count($array) > 1) {
            $array = array_slice($array, 0, -1);
            return implode('/', $array);
        }
        return '';
    }
    return false;
}

function fm_get_display_path($file_path)
{
    global $path_display_mode, $root_path, $root_url;
    switch ($path_display_mode) {
        case 'relative':
            return array(
                'label' => 'Path',
                'path' => fm_enc(fm_convert_win(str_replace($root_path, '', $file_path)))
            );
        case 'host':
            $relative_path = str_replace($root_path, '', $file_path);
            return array(
                'label' => 'Host Path',
                'path' => fm_enc(fm_convert_win('/' . $root_url . '/' . ltrim(str_replace('\\', '/', $relative_path), '/')))
            );
        case 'full':
        default:
            return array(
                'label' => 'Full Path',
                'path' => fm_enc(fm_convert_win($file_path))
            );
    }
}

/**
 * Build absolute public file URL with encoded path segments.
 * @param string $path
 * @param string $file
 * @return string
 */
function fm_build_public_file_url($path, $file)
{
    $base = rtrim((string) FM_ROOT_URL, '/');
    $relative = trim((string) $path, '/');
    $file = (string) $file;

    $parts = array();
    if ($relative !== '') {
        foreach (explode('/', str_replace('\\', '/', $relative)) as $segment) {
            if ($segment !== '') {
                $parts[] = rawurlencode($segment);
            }
        }
    }

    if ($file !== '') {
        $parts[] = rawurlencode($file);
    }

    if (empty($parts)) {
        return $base;
    }

    return $base . '/' . implode('/', $parts);
}

/**
 * Check file is in exclude list
 * @param string $name The name of the file/folder
 * @param string $path The full path of the file/folder
 * @return bool
 */
function fm_is_exclude_items($name, $path)
{
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    if (isset($exclude_items) and sizeof($exclude_items)) {
        unset($exclude_items);
    }

    $exclude_items = FM_EXCLUDE_ITEMS;
    if (version_compare(PHP_VERSION, '7.0.0', '<')) {
        $exclude_items = unserialize($exclude_items);
    }
    if (!in_array($name, $exclude_items) && !in_array("*.$ext", $exclude_items) && !in_array($path, $exclude_items)) {
        return true;
    }
    return false;
}

/**
 * get language translations from json file
 * @param int $tr
 * @return array
 */
function fm_get_translations($tr)
{
    try {
        $content = @file_get_contents('translation.json');
        if ($content !== FALSE) {
            $lng = json_decode($content, TRUE);
            global $lang_list;
            foreach ($lng["language"] as $key => $value) {
                $code = $value["code"];
                $lang_list[$code] = $value["name"];
                if ($tr)
                    $tr[$code] = $value["translation"];
            }
            return $tr;
        }
    } catch (Exception $e) {
        echo $e;
    }
}

/**
 * @param string $file
 * Recover all file sizes larger than > 2GB.
 * Works on php 32bits and 64bits and supports linux
 * @return int|string
 */
function fm_get_size($file)
{
    static $iswin = null;
    static $isdarwin = null;
    static $exec_works = null;

    // Set static variables once
    if ($iswin === null) {
        $iswin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
        $isdarwin = strtoupper(PHP_OS) === 'DARWIN';
        $exec_works = function_exists('exec') && !ini_get('safe_mode') && @exec('echo EXEC') === 'EXEC';
    }

    // Attempt shell command if exec is available
    if ($exec_works) {
        $arg = escapeshellarg($file);
        $cmd = $iswin ? "for %F in (\"$file\") do @echo %~zF" : ($isdarwin ? "stat -f%z $arg" : "stat -c%s $arg");
        @exec($cmd, $output);

        if (!empty($output) && ctype_digit($size = trim(implode("\n", $output)))) {
            return $size;
        }
    }

    // Attempt Windows COM interface for Windows systems
    if ($iswin && class_exists('COM')) {
        try {
            $fsobj = new COM('Scripting.FileSystemObject');
            $f = $fsobj->GetFile(realpath($file));
            if (ctype_digit($size = $f->Size)) {
                return $size;
            }
        } catch (Exception $e) {
            // COM failed, fallback to filesize
        }
    }

    // Default to PHP's filesize function
    return filesize($file);
}


/**
 * Get nice filesize
 * @param int $size
 * @return string
 */
function fm_get_filesize($size)
{
    $size = (float) $size;
    $units = array('B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB');
    $power = ($size > 0) ? floor(log($size, 1024)) : 0;
    $power = ($power > (count($units) - 1)) ? (count($units) - 1) : $power;
    return sprintf('%s %s', round($size / pow(1024, $power), 2), $units[$power]);
}

/**
 * Get info about zip archive
 * @param string $path
 * @return array|bool
 */
function fm_get_zif_info($path, $ext)
{
    if ($ext == 'zip' && function_exists('zip_open')) {
        $arch = @zip_open($path);
        if ($arch) {
            $filenames = array();
            while ($zip_entry = @zip_read($arch)) {
                $zip_name = @zip_entry_name($zip_entry);
                $zip_folder = substr($zip_name, -1) == '/';
                $filenames[] = array(
                    'name' => $zip_name,
                    'filesize' => @zip_entry_filesize($zip_entry),
                    'compressed_size' => @zip_entry_compressedsize($zip_entry),
                    'folder' => $zip_folder
                    //'compression_method' => zip_entry_compressionmethod($zip_entry),
                );
            }
            @zip_close($arch);
            return $filenames;
        }
    } elseif ($ext == 'tar' && class_exists('PharData')) {
        $archive = new PharData($path);
        $filenames = array();
        foreach (new RecursiveIteratorIterator($archive) as $file) {
            $parent_info = $file->getPathInfo();
            $zip_name = str_replace("phar://" . $path, '', $file->getPathName());
            $zip_name = substr($zip_name, ($pos = strpos($zip_name, '/')) !== false ? $pos + 1 : 0);
            $zip_folder = $parent_info->getFileName();
            $zip_info = new SplFileInfo($file);
            $filenames[] = array(
                'name' => $zip_name,
                'filesize' => $zip_info->getSize(),
                'compressed_size' => $file->getCompressedSize(),
                'folder' => $zip_folder
            );
        }
        return $filenames;
    }
    return false;
}

/**
 * Encode html entities
 * @param string $text
 * @return string
 */
function fm_enc($text)
{
    return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
}

/**
 * Prevent XSS attacks
 * @param string $text
 * @return string
 */
function fm_isvalid_filename($text)
{
    return (strpbrk($text, '/?%*:|"<>') === FALSE) ? true : false;
}

/**
 * Save message in session
 * @param string $msg
 * @param string $status
 */
function fm_set_msg($msg, $status = 'ok')
{
    $_SESSION[FM_SESSION_ID]['message'] = $msg;
    $_SESSION[FM_SESSION_ID]['status'] = $status;
}

/**
 * Check if string is in UTF-8
 * @param string $string
 * @return int
 */
function fm_is_utf8($string)
{
    return preg_match('//u', $string);
}

/**
 * Convert file name to UTF-8 in Windows
 * @param string $filename
 * @return string
 */
function fm_convert_win($filename)
{
    if (FM_IS_WIN && function_exists('iconv')) {
        $filename = iconv(FM_ICONV_INPUT_ENC, 'UTF-8//IGNORE', $filename);
    }
    return $filename;
}

/**
 * @param $obj
 * @return array
 */
function fm_object_to_array($obj)
{
    if (!is_object($obj) && !is_array($obj)) {
        return $obj;
    }
    if (is_object($obj)) {
        $obj = get_object_vars($obj);
    }
    return array_map('fm_object_to_array', $obj);
}

/**
 * Get CSS classname for file
 * @param string $path
 * @return string
 */
function fm_get_file_icon_class($path)
{
    // get extension
    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));

    switch ($ext) {
        case 'ico':
        case 'gif':
        case 'jpg':
        case 'jpeg':
        case 'jpc':
        case 'jp2':
        case 'jpx':
        case 'xbm':
        case 'wbmp':
        case 'png':
        case 'bmp':
        case 'tif':
        case 'tiff':
        case 'webp':
        case 'avif':
        case 'svg':
            $img = 'fa fa-picture-o';
            break;
        case 'passwd':
        case 'ftpquota':
        case 'sql':
        case 'js':
        case 'ts':
        case 'jsx':
        case 'tsx':
        case 'hbs':
        case 'json':
        case 'sh':
        case 'config':
        case 'twig':
        case 'tpl':
        case 'md':
        case 'gitignore':
        case 'c':
        case 'cpp':
        case 'cs':
        case 'py':
        case 'rs':
        case 'map':
        case 'lock':
        case 'dtd':
        case 'ps1':
            $img = 'fa fa-file-code-o';
            break;
        case 'txt':
        case 'ini':
        case 'conf':
        case 'log':
        case 'htaccess':
        case 'yaml':
        case 'yml':
        case 'toml':
        case 'tmp':
        case 'top':
        case 'bot':
        case 'dat':
        case 'bak':
        case 'htpasswd':
        case 'pl':
            $img = 'fa fa-file-text-o';
            break;
        case 'css':
        case 'less':
        case 'sass':
        case 'scss':
            $img = 'fa fa-css3';
            break;
        case 'bz2':
        case 'tbz2':
        case 'tbz':
        case 'zip':
        case 'rar':
        case 'gz':
        case 'tgz':
        case 'tar':
        case '7z':
        case 'xz':
        case 'txz':
        case 'zst':
        case 'tzst':
            $img = 'fa fa-file-archive-o';
            break;
        case 'php':
        case 'php4':
        case 'php5':
        case 'phps':
        case 'phtml':
            $img = 'fa fa-code';
            break;
        case 'htm':
        case 'html':
        case 'shtml':
        case 'xhtml':
            $img = 'fa fa-html5';
            break;
        case 'xml':
        case 'xsl':
            $img = 'fa fa-file-excel-o';
            break;
        case 'wav':
        case 'mp3':
        case 'mp2':
        case 'm4a':
        case 'aac':
        case 'ogg':
        case 'oga':
        case 'wma':
        case 'mka':
        case 'flac':
        case 'ac3':
        case 'tds':
            $img = 'fa fa-music';
            break;
        case 'm3u':
        case 'm3u8':
        case 'pls':
        case 'cue':
        case 'xspf':
            $img = 'fa fa-headphones';
            break;
        case 'avi':
        case 'mpg':
        case 'mpeg':
        case 'mp4':
        case 'm4v':
        case 'flv':
        case 'f4v':
        case 'ogm':
        case 'ogv':
        case 'mov':
        case 'mkv':
        case '3gp':
        case 'asf':
        case 'wmv':
        case 'webm':
            $img = 'fa fa-file-video-o';
            break;
        case 'eml':
        case 'msg':
            $img = 'fa fa-envelope-o';
            break;
        case 'xls':
        case 'xlsx':
        case 'ods':
            $img = 'fa fa-file-excel-o';
            break;
        case 'csv':
            $img = 'fa fa-file-text-o';
            break;
        case 'bak':
        case 'swp':
            $img = 'fa fa-clipboard';
            break;
        case 'doc':
        case 'docx':
        case 'odt':
            $img = 'fa fa-file-word-o';
            break;
        case 'ppt':
        case 'pptx':
            $img = 'fa fa-file-powerpoint-o';
            break;
        case 'ttf':
        case 'ttc':
        case 'otf':
        case 'woff':
        case 'woff2':
        case 'eot':
        case 'fon':
            $img = 'fa fa-font';
            break;
        case 'pdf':
            $img = 'fa fa-file-pdf-o';
            break;
        case 'psd':
        case 'ai':
        case 'eps':
        case 'fla':
        case 'swf':
            $img = 'fa fa-file-image-o';
            break;
        case 'exe':
        case 'msi':
            $img = 'fa fa-file-o';
            break;
        case 'bat':
            $img = 'fa fa-terminal';
            break;
        default:
            $img = 'fa fa-info-circle';
    }

    return $img;
}

/**
 * Get image files extensions
 * @return array
 */
function fm_get_image_exts()
{
    return array('ico', 'gif', 'jpg', 'jpeg', 'jpc', 'jp2', 'jpx', 'xbm', 'wbmp', 'png', 'bmp', 'tif', 'tiff', 'psd', 'svg', 'webp', 'avif');
}

/**
 * Get video files extensions
 * @return array
 */
function fm_get_video_exts()
{
    return array('avi', 'webm', 'wmv', 'mp4', 'm4v', 'ogm', 'ogv', 'mov', 'mkv');
}

/**
 * Get audio files extensions
 * @return array
 */
function fm_get_audio_exts()
{
    return array('wav', 'mp3', 'ogg', 'm4a');
}

/**
 * Get text file extensions
 * @return array
 */
function fm_get_text_exts()
{
    return array(
        'txt',
        'css',
        'ini',
        'conf',
        'log',
        'htaccess',
        'passwd',
        'ftpquota',
        'sql',
        'js',
        'ts',
        'jsx',
        'tsx',
        'mjs',
        'json',
        'sh',
        'config',
        'php',
        'php4',
        'php5',
        'phps',
        'phtml',
        'htm',
        'html',
        'shtml',
        'xhtml',
        'xml',
        'xsl',
        'm3u',
        'm3u8',
        'pls',
        'cue',
        'bash',
        'vue',
        'eml',
        'msg',
        'csv',
        'bat',
        'twig',
        'tpl',
        'md',
        'gitignore',
        'less',
        'sass',
        'scss',
        'c',
        'cpp',
        'cs',
        'py',
        'go',
        'zsh',
        'swift',
        'map',
        'lock',
        'dtd',
        'svg',
        'asp',
        'aspx',
        'asx',
        'asmx',
        'ashx',
        'jsp',
        'jspx',
        'cgi',
        'dockerfile',
        'ruby',
        'yml',
        'yaml',
        'toml',
        'vhost',
        'scpt',
        'applescript',
        'csx',
        'cshtml',
        'c++',
        'coffee',
        'cfm',
        'rb',
        'graphql',
        'mustache',
        'jinja',
        'http',
        'handlebars',
        'java',
        'es',
        'es6',
        'markdown',
        'wiki',
        'tmp',
        'top',
        'bot',
        'dat',
        'bak',
        'htpasswd',
        'pl',
        'ps1'
    );
}

/**
 * Get mime types of text files
 * @return array
 */
function fm_get_text_mimes()
{
    return array(
        'application/xml',
        'application/javascript',
        'application/x-javascript',
        'image/svg+xml',
        'message/rfc822',
        'application/json',
    );
}

/**
 * Get file names of text files w/o extensions
 * @return array
 */
function fm_get_text_names()
{
    return array(
        'license',
        'readme',
        'authors',
        'contributors',
        'changelog',
    );
}

/**
 * Get online docs viewer supported files extensions
 * @return array
 */
function fm_get_onlineViewer_exts()
{
    return array('doc', 'docx', 'xls', 'xlsx', 'pdf', 'ppt', 'pptx', 'ai', 'psd', 'dxf', 'xps', 'rar', 'odt', 'ods');
}

/**
 * It returns the mime type of a file based on its extension.
 * @param extension The file extension of the file you want to get the mime type for.
 * @return string|string[] The mime type of the file.
 */
function fm_get_file_mimes($extension)
{
    $fileTypes['swf'] = 'application/x-shockwave-flash';
    $fileTypes['pdf'] = 'application/pdf';
    $fileTypes['exe'] = 'application/octet-stream';
    $fileTypes['zip'] = 'application/zip';
    $fileTypes['doc'] = 'application/msword';
    $fileTypes['xls'] = 'application/vnd.ms-excel';
    $fileTypes['ppt'] = 'application/vnd.ms-powerpoint';
    $fileTypes['gif'] = 'image/gif';
    $fileTypes['png'] = 'image/png';
    $fileTypes['jpeg'] = 'image/jpg';
    $fileTypes['jpg'] = 'image/jpg';
    $fileTypes['webp'] = 'image/webp';
    $fileTypes['avif'] = 'image/avif';
    $fileTypes['rar'] = 'application/rar';

    $fileTypes['ra'] = 'audio/x-pn-realaudio';
    $fileTypes['ram'] = 'audio/x-pn-realaudio';
    $fileTypes['ogg'] = 'audio/x-pn-realaudio';

    $fileTypes['wav'] = 'video/x-msvideo';
    $fileTypes['wmv'] = 'video/x-msvideo';
    $fileTypes['avi'] = 'video/x-msvideo';
    $fileTypes['asf'] = 'video/x-msvideo';
    $fileTypes['divx'] = 'video/x-msvideo';

    $fileTypes['mp3'] = 'audio/mpeg';
    $fileTypes['mp4'] = 'video/mp4';
    $fileTypes['mpeg'] = 'video/mpeg';
    $fileTypes['mpg'] = 'video/mpeg';
    $fileTypes['mpe'] = 'video/mpeg';
    $fileTypes['mov'] = 'video/quicktime';
    $fileTypes['swf'] = 'video/quicktime';
    $fileTypes['3gp'] = 'video/quicktime';
    $fileTypes['m4a'] = 'video/quicktime';
    $fileTypes['aac'] = 'video/quicktime';
    $fileTypes['m3u'] = 'video/quicktime';

    $fileTypes['php'] = ['application/x-php'];
    $fileTypes['html'] = ['text/html'];
    $fileTypes['txt'] = ['text/plain'];
    //Unknown mime-types should be 'application/octet-stream'
    if (empty($fileTypes[$extension])) {
        $fileTypes[$extension] = ['application/octet-stream'];
    }
    return $fileTypes[$extension];
}

/**
 * This function scans the files and folder recursively, and return matching files
 * @param string $dir
 * @param string $filter
 * @return array|null
 */
function scan($dir = '', $filter = '')
{
    $path = FM_ROOT_PATH . '/' . $dir;
    if ($path) {
        $ite = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path));
        $rii = new RegexIterator($ite, "/(" . $filter . ")/i");

        $files = array();
        foreach ($rii as $file) {
            if (!$file->isDir()) {
                if (!fm_user_can_access_path($file->getPathname(), false)) {
                    continue;
                }
                $fileName = $file->getFilename();
                $location = str_replace(FM_ROOT_PATH, '', $file->getPath());
                $files[] = array(
                    "name" => $fileName,
                    "type" => "file",
                    "path" => $location,
                );
            }
        }
        return $files;
    }
}

/**
 * Parameters: downloadFile(File Location, File Name,
 * max speed, is streaming
 * If streaming - videos will show as videos, images as images
 * instead of download prompt
 * https://stackoverflow.com/a/13821992/1164642
 */
function fm_download_file($fileLocation, $fileName, $chunkSize  = 1024)
{
    if (connection_status() != 0)
        return (false);
    $extension = pathinfo($fileName, PATHINFO_EXTENSION);

    $contentType = fm_get_file_mimes($extension);

    if (is_array($contentType)) {
        $contentType = implode(' ', $contentType);
    }

    $size = filesize($fileLocation);

    if ($size == 0) {
        fm_set_msg(lng('Zero byte file! Aborting download'), 'error');
        $FM_PATH = FM_PATH;
        fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));

        return (false);
    }

    @ini_set('magic_quotes_runtime', 0);
    $fp = fopen("$fileLocation", "rb");

    if ($fp === false) {
        fm_set_msg(lng('Cannot open file! Aborting download'), 'error');
        $FM_PATH = FM_PATH;
        fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
        return (false);
    }

    // headers
    header('Content-Description: File Transfer');
    header('Expires: 0');
    header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
    header('Pragma: public');
    header("Content-Transfer-Encoding: binary");
    header("Content-Type: $contentType");

    $contentDisposition = 'attachment';

    if (strstr($_SERVER['HTTP_USER_AGENT'], "MSIE")) {
        $fileName = preg_replace('/\./', '%2e', $fileName, substr_count($fileName, '.') - 1);
        header("Content-Disposition: $contentDisposition;filename=\"$fileName\"");
    } else {
        header("Content-Disposition: $contentDisposition;filename=\"$fileName\"");
    }

    header("Accept-Ranges: bytes");
    $range = 0;

    if (isset($_SERVER['HTTP_RANGE'])) {
        list($a, $range) = explode("=", $_SERVER['HTTP_RANGE']);
        str_replace($range, "-", $range);
        $size2 = $size - 1;
        $new_length = $size - $range;
        header("HTTP/1.1 206 Partial Content");
        header("Content-Length: $new_length");
        header("Content-Range: bytes $range$size2/$size");
    } else {
        $size2 = $size - 1;
        header("Content-Range: bytes 0-$size2/$size");
        header("Content-Length: " . $size);
    }
    $fileLocation = realpath($fileLocation);
    while (ob_get_level()) ob_end_clean();
    readfile($fileLocation);

    fclose($fp);

    return ((connection_status() == 0) and !connection_aborted());
}

/**
 * Save Configuration
 */
class FM_Config
{
    var $data;
    // Directory where per-user setting JSON files are stored.
    const USER_CFG_DIR = '.fm_usercfg';

    function __construct()
    {
        global $root_path, $root_url, $CONFIG;
        $fm_url = $root_url . $_SERVER["PHP_SELF"];
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
        if (is_array($data) && count($data)) $this->data = $data;
        else $this->save();

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
        if (!is_readable($path)) return false;
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

//--- Templates Functions ---

    /**
     * Show Header after login
     */
    function fm_show_header()
    {
        header("Content-Type: text/html; charset=utf-8");
        header("Expires: Sat, 26 Jul 1997 05:00:00 GMT");
        header("Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0");
        header("Pragma: no-cache");

        global $sticky_navbar, $favicon_path;
        $isStickyNavBar = $sticky_navbar ? 'navbar-fixed' : 'navbar-normal';
        $pwa_icon = LOGIN_LOGO_PATH ? LOGIN_LOGO_PATH : $favicon_path;
?>
    <!DOCTYPE html>
    <html data-bs-theme="<?php echo FM_THEME; ?>">

    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        <meta name="description" content="Web based File Manager in PHP, Manage your files efficiently and easily with Tiny File Manager">
        <meta name="author" content="CCP Programmers">
        <meta name="robots" content="noindex, nofollow">
        <meta name="googlebot" content="noindex">
        <meta name="theme-color" content="#1f6feb">
        <meta name="mobile-web-app-capable" content="yes">
        <meta name="apple-mobile-web-app-capable" content="yes">
        <meta name="apple-mobile-web-app-status-bar-style" content="default">
        <meta name="apple-mobile-web-app-title" content="<?php echo fm_enc(APP_TITLE); ?>">
        <link rel="manifest" href="<?php echo fm_enc(FM_SELF_URL . '?manifest=1'); ?>">
        <?php if ($favicon_path) {
            echo '<link rel="icon" href="' . fm_enc($favicon_path) . '" type="image/png">';
        } ?>
        <?php if ($pwa_icon) {
            echo '<link rel="apple-touch-icon" href="' . fm_enc($pwa_icon) . '">';
        } ?>
        <title><?php echo fm_enc(APP_TITLE) ?> | <?php echo (isset($_GET['view']) ? $_GET['view'] : ((isset($_GET['edit'])) ? $_GET['edit'] : "H3K")); ?></title>
        <?php print_external('pre-jsdelivr'); ?>
        <?php print_external('pre-cloudflare'); ?>
        <?php print_external('css-bootstrap'); ?>
        <?php print_external('css-font-awesome'); ?>
        <?php if (FM_USE_HIGHLIGHTJS && isset($_GET['view'])): ?>
            <?php print_external('css-highlightjs'); ?>
        <?php endif; ?>
        <script type="text/javascript">
            window.csrf = '<?php echo $_SESSION['token']; ?>';
        </script>
        <style>
            html {
                -moz-osx-font-smoothing: grayscale;
                -webkit-font-smoothing: antialiased;
                text-rendering: optimizeLegibility;
                height: 100%;
                scroll-behavior: smooth;
            }

            :root {
                --fm-body-bg: #f7f7f7;
                --fm-body-color: #222222;
                --fm-row-odd: #ffffff;
                --fm-row-even: #f3f4f6;
                --fm-row-hover: #e9f2ff;
            }

            html[data-bs-theme="dark"] {
                --fm-body-bg: #1c2429;
                --fm-body-color: #cfd8dc;
                --fm-row-odd: #1f282e;
                --fm-row-even: #263238;
                --fm-row-hover: #32424a;
            }

            *,
            *::before,
            *::after {
                box-sizing: border-box;
            }

            body {
                font-size: 15px;
                color: var(--fm-body-color);
                background: var(--fm-body-bg);
                transition: background-color .2s ease, color .2s ease;
            }

            body.navbar-fixed {
                /* margin-top set dynamically via JS to handle multi-line navbar on mobile */
            }

            a,
            a:hover,
            a:visited,
            a:focus {
                text-decoration: none !important;
            }

            .filename,
            td,
            th {
                white-space: nowrap
            }

            .navbar-brand {
                font-weight: bold;
            }

            .nav-item.avatar a {
                cursor: pointer;
                text-transform: capitalize;
            }

            .nav-item.avatar a>i {
                font-size: 15px;
            }

            .nav-item.avatar .dropdown-menu a {
                font-size: 13px;
            }

            #search-addon {
                font-size: 12px;
                border-right-width: 0;
            }

            .brl-0 {
                background: transparent;
                border-left: 0;
                border-top-left-radius: 0;
                border-bottom-left-radius: 0;
            }

            .brr-0 {
                border-top-right-radius: 0;
                border-bottom-right-radius: 0;
            }

            .bread-crumb {
                color: #cccccc;
                font-style: normal;
            }

            #main-table {
                transition: transform .25s cubic-bezier(0.4, 0.5, 0, 1), width 0s .25s;
            }

            #main-table .filename a {
                color: #222222;
            }

            .table td,
            .table th {
                vertical-align: middle !important;
            }

            .table .custom-checkbox-td .custom-control.custom-checkbox,
            .table .custom-checkbox-header .custom-control.custom-checkbox {
                min-width: 18px;
                display: flex;
                align-items: center;
                justify-content: center;
            }

            .table-sm td,
            .table-sm th {
                padding: .4rem;
            }

            .table-bordered td,
            .table-bordered th {
                border: 1px solid #f1f1f1;
            }

            .hidden {
                display: none
            }

            pre.with-hljs {
                padding: 0;
                overflow: hidden;
            }

            pre.with-hljs code {
                margin: 0;
                border: 0;
                overflow: scroll;
            }

            code.maxheight,
            pre.maxheight {
                max-height: 512px
            }

            .fa.fa-caret-right {
                font-size: 1.2em;
                margin: 0 4px;
                vertical-align: middle;
                color: #ececec
            }

            .fa.fa-home {
                font-size: 1.3em;
                vertical-align: bottom
            }

            .path {
                margin-bottom: 10px
            }

            form.dropzone {
                min-height: 200px;
                border: 2px dashed #007bff;
                line-height: 6rem;
            }

            .right {
                text-align: right
            }

            .center,
            .close,
            .login-form,
            .preview-img-container {
                text-align: center
            }

            .message {
                padding: 4px 7px;
                border: 1px solid #ddd;
                background-color: #fff
            }

            .message.ok {
                border-color: green;
                color: green
            }

            .message.error {
                border-color: red;
                color: red
            }

            .message.alert {
                border-color: orange;
                color: orange
            }

            .preview-img {
                max-width: 100%;
                max-height: 80vh;
                background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAAAKklEQVR42mL5//8/Azbw+PFjrOJMDCSCUQ3EABZc4S0rKzsaSvTTABBgAMyfCMsY4B9iAAAAAElFTkSuQmCC);
                cursor: zoom-in
            }

            input#preview-img-zoomCheck[type=checkbox] {
                display: none
            }

            input#preview-img-zoomCheck[type=checkbox]:checked~label>img {
                max-width: none;
                max-height: none;
                cursor: zoom-out
            }

            .inline-actions>a>i {
                font-size: 1em;
                margin-left: 5px;
                background: #3785c1;
                color: #fff;
                padding: 3px 4px;
                border-radius: 3px;
            }

            .preview-video {
                position: relative;
                max-width: 100%;
                height: 0;
                padding-bottom: 62.5%;
                margin-bottom: 10px
            }

            .preview-video video {
                position: absolute;
                width: 100%;
                height: 100%;
                left: 0;
                top: 0;
                background: #000
            }

            .compact-table {
                border: 0;
                width: auto
            }

            .compact-table td,
            .compact-table th {
                width: 100px;
                border: 0;
                text-align: center
            }

            .compact-table tr:hover td {
                background-color: #fff
            }

            .filename {
                max-width: 420px;
                overflow: hidden;
                text-overflow: ellipsis
            }

            .break-word {
                word-wrap: break-word;
                margin-left: 30px
            }

            .break-word.float-left a {
                color: #7d7d7d
            }

            .break-word+.float-right {
                padding-right: 30px;
                position: relative
            }

            .break-word+.float-right>a {
                color: #7d7d7d;
                font-size: 1.2em;
                margin-right: 4px
            }

            #editor {
                position: absolute;
                right: 15px;
                top: 100px;
                bottom: 15px;
                left: 15px
            }

            @media (max-width:481px) {
                #editor {
                    top: 150px;
                }
            }

            #normal-editor {
                border-radius: 3px;
                border-width: 2px;
                padding: 10px;
                outline: none;
            }

            .btn-2 {
                padding: 4px 10px;
                font-size: small;
            }

            li.file:before,
            li.folder:before {
                font: normal normal normal 14px/1 FontAwesome;
                content: "\f016";
                margin-right: 5px
            }

            li.folder:before {
                content: "\f114"
            }

            i.fa.fa-folder-o {
                color: #0157b3
            }

            i.fa.fa-picture-o {
                color: #26b99a
            }

            i.fa.fa-file-archive-o {
                color: #da7d7d
            }

            .btn-2 i.fa.fa-file-archive-o {
                color: inherit
            }

            i.fa.fa-css3 {
                color: #f36fa0
            }

            i.fa.fa-file-code-o {
                color: #007bff
            }

            i.fa.fa-code {
                color: #cc4b4c
            }

            i.fa.fa-file-text-o {
                color: #0096e6
            }

            i.fa.fa-html5 {
                color: #d75e72
            }

            i.fa.fa-file-excel-o {
                color: #09c55d
            }

            i.fa.fa-file-powerpoint-o {
                color: #f6712e
            }

            i.go-back {
                font-size: 1.2em;
                color: #007bff;
            }

            .main-nav {
                padding: 0.2rem 1rem;
                box-shadow: 0 4px 5px 0 rgba(0, 0, 0, .14), 0 1px 10px 0 rgba(0, 0, 0, .12), 0 2px 4px -1px rgba(0, 0, 0, .2)
            }

            .fm-mobile-quickbar {
                gap: 6px;
            }

            .fm-mobile-quickbar .btn {
                min-width: 42px;
                min-height: 42px;
                display: inline-flex;
                align-items: center;
                justify-content: center;
                padding: 0;
            }

            .dataTables_filter {
                display: none;
            }

            table.dataTable thead .sorting {
                cursor: pointer;
                background-repeat: no-repeat;
                background-position: center right;
                background-image: url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABMAAAATCAQAAADYWf5HAAAAkElEQVQoz7XQMQ5AQBCF4dWQSJxC5wwax1Cq1e7BAdxD5SL+Tq/QCM1oNiJidwox0355mXnG/DrEtIQ6azioNZQxI0ykPhTQIwhCR+BmBYtlK7kLJYwWCcJA9M4qdrZrd8pPjZWPtOqdRQy320YSV17OatFC4euts6z39GYMKRPCTKY9UnPQ6P+GtMRfGtPnBCiqhAeJPmkqAAAAAElFTkSuQmCC');
            }

            table.dataTable thead .sorting_asc {
                cursor: pointer;
                background-repeat: no-repeat;
                background-position: center right;
                background-image: url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABMAAAATCAYAAAByUDbMAAAAZ0lEQVQ4y2NgGLKgquEuFxBPAGI2ahhWCsS/gDibUoO0gPgxEP8H4ttArEyuQYxAPBdqEAxPBImTY5gjEL9DM+wTENuQahAvEO9DMwiGdwAxOymGJQLxTyD+jgWDxCMZRsEoGAVoAADeemwtPcZI2wAAAABJRU5ErkJggg==');
            }

            table.dataTable thead .sorting_desc {
                cursor: pointer;
                background-repeat: no-repeat;
                background-position: center right;
                background-image: url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABMAAAATCAYAAAByUDbMAAAAZUlEQVQ4y2NgGAWjYBSggaqGu5FA/BOIv2PBIPFEUgxjB+IdQPwfC94HxLykus4GiD+hGfQOiB3J8SojEE9EM2wuSJzcsFMG4ttQgx4DsRalkZENxL+AuJQaMcsGxBOAmGvopk8AVz1sLZgg0bsAAAAASUVORK5CYII=');
            }

            table.dataTable thead tr:first-child th.custom-checkbox-header:first-child {
                background-image: none;
            }

            .footer-action li {
                margin-bottom: 10px;
            }

            .app-v-title {
                font-size: 24px;
                font-weight: 300;
                letter-spacing: -.5px;
                text-transform: uppercase;
            }

            hr.custom-hr {
                border-top: 1px dashed #8c8b8b;
                border-bottom: 1px dashed #fff;
            }

            #snackbar {
                visibility: hidden;
                min-width: 250px;
                margin-left: -125px;
                background-color: #333;
                color: #fff;
                text-align: center;
                border-radius: 2px;
                padding: 16px;
                position: fixed;
                z-index: 1;
                left: 50%;
                bottom: 30px;
                font-size: 17px;
            }

            #snackbar.show {
                visibility: visible;
                -webkit-animation: fadein 0.5s, fadeout 0.5s 2.5s;
                animation: fadein 0.5s, fadeout 0.5s 2.5s;
            }

            @-webkit-keyframes fadein {
                from {
                    bottom: 0;
                    opacity: 0;
                }

                to {
                    bottom: 30px;
                    opacity: 1;
                }
            }

            @keyframes fadein {
                from {
                    bottom: 0;
                    opacity: 0;
                }

                to {
                    bottom: 30px;
                    opacity: 1;
                }
            }

            @-webkit-keyframes fadeout {
                from {
                    bottom: 30px;
                    opacity: 1;
                }

                to {
                    bottom: 0;
                    opacity: 0;
                }
            }

            @keyframes fadeout {
                from {
                    bottom: 30px;
                    opacity: 1;
                }

                to {
                    bottom: 0;
                    opacity: 0;
                }
            }

            #main-table span.badge {
                border-bottom: 2px solid #f8f9fa
            }

            #main-table span.badge:nth-child(1) {
                border-color: #df4227
            }

            #main-table span.badge:nth-child(2) {
                border-color: #f8b600
            }

            #main-table span.badge:nth-child(3) {
                border-color: #00bd60
            }

            #main-table span.badge:nth-child(4) {
                border-color: #4581ff
            }

            #main-table span.badge:nth-child(5) {
                border-color: #ac68fc
            }

            #main-table span.badge:nth-child(6) {
                border-color: #45c3d2
            }

            @media only screen and (min-device-width:768px) and (max-device-width:1024px) and (orientation:landscape) and (-webkit-min-device-pixel-ratio:2) {
                .navbar-collapse .col-xs-6 {
                    padding: 0;
                }
            }

            .btn.active.focus,
            .btn.active:focus,
            .btn.focus,
            .btn.focus:active,
            .btn:active:focus,
            .btn:focus {
                outline: 0 !important;
                outline-offset: 0 !important;
                background-image: none !important;
                -webkit-box-shadow: none !important;
                box-shadow: none !important
            }

            .lds-facebook {
                display: none;
                position: relative;
                width: 64px;
                height: 64px
            }

            .lds-facebook div,
            .lds-facebook.show-me {
                display: inline-block
            }

            .lds-facebook div {
                position: absolute;
                left: 6px;
                width: 13px;
                background: #007bff;
                animation: lds-facebook 1.2s cubic-bezier(0, .5, .5, 1) infinite
            }

            .lds-facebook div:nth-child(1) {
                left: 6px;
                animation-delay: -.24s
            }

            .lds-facebook div:nth-child(2) {
                left: 26px;
                animation-delay: -.12s
            }

            .lds-facebook div:nth-child(3) {
                left: 45px;
                animation-delay: 0s
            }

            @keyframes lds-facebook {
                0% {
                    top: 6px;
                    height: 51px
                }

                100%,
                50% {
                    top: 19px;
                    height: 26px
                }
            }

            ul#search-wrapper {
                padding-left: 0;
                border: 1px solid #ecececcc;
            }

            ul#search-wrapper li {
                list-style: none;
                padding: 5px;
                border-bottom: 1px solid #ecececcc;
            }

            ul#search-wrapper li:nth-child(odd) {
                background: #f9f9f9cc;
            }

            .c-preview-img {
                max-width: 300px;
            }

            .border-radius-0 {
                border-radius: 0;
            }

            .float-right {
                float: right;
            }

            .table-hover>tbody>tr:hover>td:first-child {
                border-left: 1px solid #1b77fd;
            }

            #main-table tbody tr:nth-child(odd)>td {
                background-color: var(--fm-row-odd);
            }

            #main-table tbody tr:nth-child(even)>td {
                background-color: var(--fm-row-even);
            }

            #main-table.table-hover>tbody>tr:hover>td {
                background-color: var(--fm-row-hover);
            }

            .filename>a>i {
                margin-right: 3px;
            }

            .fs-7 {
                font-size: 14px;
            }

            #fm-grid-view {
                margin-bottom: 12px;
            }

            .fm-grid {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
                gap: 12px;
            }

            .fm-grid-item {
                border: 1px solid #e8ecf2;
                border-radius: 10px;
                background: #fff;
                box-shadow: 0 1px 2px rgba(0, 0, 0, .04);
                overflow: hidden;
                transition: transform .12s ease, box-shadow .12s ease;
            }

            .fm-grid-item:hover {
                transform: translateY(-2px);
                box-shadow: 0 6px 18px rgba(0, 0, 0, .08);
            }

            .fm-grid-thumb {
                height: 122px;
                background: linear-gradient(120deg, #f7f9fc, #eef3f8);
                display: flex;
                align-items: center;
                justify-content: center;
                overflow: hidden;
                position: relative;
                transition: opacity .15s ease, background .15s ease;
                cursor: pointer;
            }

            .fm-grid-thumb:hover {
                opacity: 0.85;
                background: linear-gradient(120deg, #f0f4f9, #e8eef8);
            }

            .fm-grid-thumb img,
            .fm-grid-thumb video {
                width: 100%;
                height: 100%;
                object-fit: cover;
                display: block;
            }

            .fm-grid-thumb video {
                background: #0e1218;
            }

            .fm-grid-thumb i {
                font-size: 34px;
            }

            .fm-grid-pdf-badge {
                position: absolute;
                top: 6px;
                right: 6px;
                background: #ff3b30;
                color: white;
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 11px;
                font-weight: 600;
                text-transform: uppercase;
                z-index: 1;
            }

            .fm-grid-body {
                padding: 10px 12px 8px;
            }

            .fm-grid-name a {
                display: block;
                color: #1d2b3a;
                font-weight: 700;
                text-decoration: none;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
                cursor: pointer;
            }

            .fm-grid-name a:hover,
            .fm-grid-name a:focus {
                text-decoration: underline;
            }

            .fm-grid-name a.fm-grid-link-dir {
                color: #0a66c2;
                font-weight: 700;
            }

            .fm-grid-name a.fm-grid-link-file {
                color: #1d2b3a;
                font-weight: 600;
            }

            .fm-grid-item.fm-grid-parent .fm-grid-name a {
                color: #0066cc;
            }

            .fm-grid-item:not(.fm-grid-parent) .fm-grid-name a {
                color: #1d2b3a;
            }

            .theme-dark .fm-grid-item.fm-grid-parent .fm-grid-name a {
                color: #4da6ff;
            }

            .theme-dark .fm-grid-name a.fm-grid-link-dir {
                color: #6bb8ff;
            }

            .theme-dark .fm-grid-name a.fm-grid-link-file {
                color: #e2ecef;
            }

            .fm-grid-meta {
                margin-top: 6px;
                font-size: 12px;
                color: #7a8490;
                display: flex;
                justify-content: space-between;
                gap: 8px;
            }

            .fm-grid-path-row {
                margin-top: 6px;
                margin-bottom: 4px;
                font-size: 11px;
                color: #666;
                word-break: break-word;
            }

            .fm-grid-path {
                display: block;
                padding: 2px 4px;
                background: #f5f5f5;
                border-radius: 3px;
                font-family: monospace;
            }

            .fm-grid-actions {
                border-top: 1px solid #edf1f5;
                padding: 8px 10px;
                text-align: right;
            }

            .fm-grid-actions .inline-actions {
                white-space: nowrap;
            }

            .fm-grid-item.fm-grid-parent .fm-grid-thumb {
                background: linear-gradient(120deg, #eef6ff, #e5f1ff);
            }

            .theme-dark .fm-grid-item {
                background: #1f282e;
                border-color: #2f3b42;
                box-shadow: none;
            }

            .theme-dark .fm-grid-item:hover {
                box-shadow: 0 8px 18px rgba(0, 0, 0, .25);
            }

            .theme-dark .fm-grid-thumb {
                background: linear-gradient(120deg, #263238, #202a31);
            }

            .theme-dark .fm-grid-name a {
                color: #e2ecef;
            }

            .theme-dark .fm-grid-meta {
                color: #9fb0b7;
            }

            .theme-dark .fm-grid-actions {
                border-top-color: #2f3b42;
            }

            @media (max-width: 767.98px) {
                body {
                    padding-bottom: 76px;
                }

                .main-nav {
                    padding: 0.35rem 0.6rem;
                }

                .navbar-brand {
                    max-width: 44vw;
                    overflow: hidden;
                    text-overflow: ellipsis;
                    white-space: nowrap;
                }

                .navbar-collapse .col-xs-6 {
                    width: 100%;
                    max-width: 100%;
                    margin-bottom: 8px;
                }

                .navbar-nav .nav-link,
                .btn.btn-2,
                .inline-actions > a {
                    min-height: 44px;
                    display: inline-flex;
                    align-items: center;
                }

                #main-table td,
                #main-table th {
                    padding-top: .55rem;
                    padding-bottom: .55rem;
                }

                #fm-selection-bar {
                    position: fixed;
                    left: 8px;
                    right: 8px;
                    bottom: 8px;
                    z-index: 1040;
                    background: rgba(255, 255, 255, 0.96);
                    border: 1px solid #d9e0e8;
                    border-radius: 12px;
                    box-shadow: 0 8px 24px rgba(0, 0, 0, .16);
                    padding: 8px;
                    gap: 6px;
                    display: none;
                }

                body.theme-dark #fm-selection-bar {
                    background: rgba(27, 35, 40, 0.96);
                    border-color: #2f3b42;
                }

                #fm-selection-bar .btn {
                    flex: 1 1 calc(50% - 6px);
                    justify-content: center;
                }

                #fm-selection-bar #fm-selection-count {
                    flex: 1 0 100%;
                    justify-content: center;
                }
            }

            @media (max-width: 479.98px) {
                #main-table.fm-compact-mobile .fm-col-modified,
                #main-table.fm-compact-mobile .fm-col-perms,
                #main-table.fm-compact-mobile .fm-col-owner {
                    display: none;
                }

                #main-table.fm-compact-mobile .fm-col-size,
                #main-table.fm-compact-mobile .fm-col-actions {
                    white-space: nowrap;
                    width: 1%;
                }

                #main-table.fm-compact-mobile .inline-actions > a {
                    padding-left: .2rem;
                    padding-right: .2rem;
                }
            }
        </style>
        <?php
        if (FM_THEME == "dark"): ?>
            <style>
                :root {
                    --bs-bg-opacity: 1;
                    --bg-color: #f3daa6;
                    --bs-dark-rgb: 28, 36, 41 !important;
                    --bs-bg-opacity: 1;
                }

                body.theme-dark {
                    background-image: linear-gradient(90deg, #1c2429, #263238);
                    color: #CFD8DC;
                }

                .list-group .list-group-item {
                    background: #343a40;
                }

                .theme-dark .navbar-nav i,
                .navbar-nav .dropdown-toggle,
                .break-word {
                    color: #CFD8DC;
                }

                a,
                a:hover,
                a:visited,
                a:active,
                #main-table .filename a,
                i.fa.fa-folder-o,
                i.go-back {
                    color: var(--bg-color);
                }

                ul#search-wrapper li:nth-child(odd) {
                    background: #212a2f;
                }

                .theme-dark .btn-outline-primary {
                    color: #b8e59c;
                    border-color: #b8e59c;
                }

                .theme-dark .btn-outline-primary:hover,
                .theme-dark .btn-outline-primary:active {
                    background-color: #2d4121;
                }

                .theme-dark input.form-control {
                    background-color: #101518;
                    color: #CFD8DC;
                }

                .theme-dark .dropzone {
                    background: transparent;
                }

                .theme-dark .inline-actions>a>i {
                    background: #79755e;
                }

                .theme-dark .text-white {
                    color: #CFD8DC !important;
                }

                .theme-dark .table-bordered td,
                .table-bordered th {
                    border-color: #343434;
                }

                .theme-dark .table-bordered td .custom-control-input,
                .theme-dark .table-bordered th .custom-control-input {
                    opacity: 0.678;
                }

                .message {
                    background-color: #212529;
                }

                form.dropzone {
                    border-color: #79755e;
                }
            </style>
        <?php endif; ?>
    </head>

    <body class="<?php echo (FM_THEME == "dark") ? 'theme-dark' : ''; ?> <?php echo $isStickyNavBar; ?>">
        <div id="wrapper" class="container-fluid">
            <!-- New Item creation -->
            <div class="modal fade" id="createNewItem" tabindex="-1" role="dialog" data-bs-backdrop="static" data-bs-keyboard="false" aria-labelledby="newItemModalLabel" aria-hidden="true" data-bs-theme="<?php echo FM_THEME; ?>">
                <div class="modal-dialog" role="document">
                    <form class="modal-content" method="post">
                        <div class="modal-header">
                            <h5 class="modal-title" id="newItemModalLabel"><i class="fa fa-plus-square fa-fw"></i><?php echo lng('CreateNewItem') ?></h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <p><label for="newfile"><?php echo lng('ItemType') ?> </label></p>
                            <div class="form-check form-check-inline">
                                <input class="form-check-input" type="radio" name="newfile" id="customRadioInline1" name="newfile" value="file">
                                <label class="form-check-label" for="customRadioInline1"><?php echo lng('File') ?></label>
                            </div>
                            <div class="form-check form-check-inline">
                                <input class="form-check-input" type="radio" name="newfile" id="customRadioInline2" value="folder" checked>
                                <label class="form-check-label" for="customRadioInline2"><?php echo lng('Folder') ?></label>
                            </div>

                            <p class="mt-3"><label for="newfilename"><?php echo lng('ItemName') ?> </label></p>
                            <input type="text" name="newfilename" id="newfilename" value="" class="form-control" placeholder="<?php echo lng('Enter here...') ?>" required>
                        </div>
                        <div class="modal-footer">
                            <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
                            <button type="button" class="btn btn-outline-primary" data-bs-dismiss="modal"><i class="fa fa-times-circle"></i> <?php echo lng('Cancel') ?></button>
                            <button type="submit" class="btn btn-success"><i class="fa fa-check-circle"></i> <?php echo lng('CreateNow') ?></button>
                        </div>
                    </form>
                </div>
            </div>

            <!-- Advance Search Modal -->
            <div class="modal fade" id="searchModal" tabindex="-1" role="dialog" aria-labelledby="searchModalLabel" aria-hidden="true" data-bs-theme="<?php echo FM_THEME; ?>">
                <div class="modal-dialog modal-lg" role="document">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title col-10" id="searchModalLabel">
                                <div class="input-group mb-3">
                                    <input type="text" class="form-control" placeholder="<?php echo lng('Search') ?> <?php echo lng('a files') ?>" aria-label="<?php echo lng('Search') ?>" aria-describedby="search-addon3" id="advanced-search" autofocus required>
                                    <span class="input-group-text" id="search-addon3"><i class="fa fa-search"></i></span>
                                </div>
                            </h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <form action="" method="post">
                                <div class="lds-facebook">
                                    <div></div>
                                    <div></div>
                                    <div></div>
                                </div>
                                <ul id="search-wrapper">
                                    <p class="m-2"><?php echo lng('Search file in folder and subfolders...') ?></p>
                                </ul>
                            </form>
                        </div>
                    </div>
                </div>
            </div>

            <!--Rename Modal -->
            <div class="modal modal-alert" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" role="dialog" id="renameDailog" data-bs-theme="<?php echo FM_THEME; ?>">
                <div class="modal-dialog" role="document">
                    <form class="modal-content rounded-3 shadow" method="post" autocomplete="off">
                        <div class="modal-body p-4 text-center">
                            <h5 class="mb-3"><?php echo lng('Are you sure want to rename?') ?></h5>
                            <p class="mb-1">
                                <input type="text" name="rename_to" id="js-rename-to" class="form-control" placeholder="<?php echo lng('Enter new file name') ?>" required>
                                <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
                                <input type="hidden" name="rename_from" id="js-rename-from">
                            </p>
                        </div>
                        <div class="modal-footer flex-nowrap p-0">
                            <button type="button" class="btn btn-lg btn-link fs-6 text-decoration-none col-6 m-0 rounded-0 border-end" data-bs-dismiss="modal"><?php echo lng('Cancel') ?></button>
                            <button type="submit" class="btn btn-lg btn-link fs-6 text-decoration-none col-6 m-0 rounded-0"><strong><?php echo lng('Okay') ?></strong></button>
                        </div>
                    </form>
                </div>
            </div>

            <!-- Confirm Modal -->
            <script type="text/html" id="js-tpl-confirm">
                <div class="modal modal-alert confirmDailog" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" role="dialog" id="confirmDailog-<%this.id%>" data-bs-theme="<?php echo FM_THEME; ?>">
                    <div class="modal-dialog" role="document">
                        <form class="modal-content rounded-3 shadow" method="post" autocomplete="off" action="<%this.action%>">
                            <div class="modal-body p-4 text-center">
                                <h5 class="mb-2"><?php echo lng('Are you sure want to') ?> <%this.title%> ?</h5>
                                <p class="mb-1"><%this.content%></p>
                            </div>
                            <div class="modal-footer flex-nowrap p-0">
                                <button type="button" class="btn btn-lg btn-link fs-6 text-decoration-none col-6 m-0 rounded-0 border-end" data-bs-dismiss="modal"><?php echo lng('Cancel') ?></button>
                                <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
                                <button type="submit" class="btn btn-lg btn-link fs-6 text-decoration-none col-6 m-0 rounded-0" data-bs-dismiss="modal"><strong><?php echo lng('Okay') ?></strong></button>
                            </div>
                        </form>
                    </div>
                </div>
            </script>
        <?php
    }

    /**
     * Show page footer after login
     */
    function fm_show_footer()
    {
        ?>
        </div>
        <?php print_external('js-jquery'); ?>
        <?php print_external('js-bootstrap'); ?>
        <?php print_external('js-jquery-datatables'); ?>
        <?php if (FM_USE_HIGHLIGHTJS && isset($_GET['view'])): ?>
            <?php print_external('js-highlightjs'); ?>
            <script>
                hljs.highlightAll();
                var isHighlightingEnabled = true;
            </script>
        <?php endif; ?>
        <script>
            function template(html, options) {
                var re = /<\%([^\%>]+)?\%>/g,
                    reExp = /(^( )?(if|for|else|switch|case|break|{|}))(.*)?/g,
                    code = 'var r=[];\n',
                    cursor = 0,
                    match;
                var add = function(line, js) {
                    js ? (code += line.match(reExp) ? line + '\n' : 'r.push(' + line + ');\n') : (code += line != '' ? 'r.push("' + line.replace(/"/g, '\\"') + '");\n' : '');
                    return add
                }
                while (match = re.exec(html)) {
                    add(html.slice(cursor, match.index))(match[1], !0);
                    cursor = match.index + match[0].length
                }
                add(html.substr(cursor, html.length - cursor));
                code += 'return r.join("");';
                return new Function(code.replace(/[\r\t\n]/g, '')).apply(options)
            }

            function rename(e, t) {
                if (t) {
                    $("#js-rename-from").val(t);
                    $("#js-rename-to").val(t);
                    $("#renameDailog").modal('show');
                }
            }

            function change_checkboxes(e, t) {
                for (var n = e.length - 1; n >= 0; n--) e[n].checked = "boolean" == typeof t ? t : !e[n].checked;
                if (typeof window.fmUpdateSelectionBar === 'function') {
                    window.fmUpdateSelectionBar();
                }
            }

            function get_checkboxes() {
                for (var e = document.getElementsByName("file[]"), t = [], n = e.length - 1; n >= 0; n--)(e[n].type = "checkbox") && t.push(e[n]);
                return t
            }

            function select_all() {
                change_checkboxes(get_checkboxes(), !0)
            }

            function unselect_all() {
                change_checkboxes(get_checkboxes(), !1)
            }

            function invert_all() {
                change_checkboxes(get_checkboxes())
            }

            function checkbox_toggle() {
                var e = get_checkboxes();
                e.push(this), change_checkboxes(e)
            }

            // Create file backup with .bck
            function backup(e, t) {
                var n = new XMLHttpRequest,
                    a = "path=" + e + "&file=" + t + "&token=" + window.csrf + "&type=backup&ajax=true";
                return n.open("POST", "", !0), n.setRequestHeader("Content-type", "application/x-www-form-urlencoded"), n.onreadystatechange = function() {
                    4 == n.readyState && 200 == n.status && toast(n.responseText)
                }, n.send(a), !1
            }

            // Toast message
            function toast(txt) {
                var x = document.getElementById("snackbar");
                x.innerHTML = txt;
                x.className = "show";
                setTimeout(function() {
                    x.className = x.className.replace("show", "");
                }, 3000);
            }

            // Save file
            function edit_save(e, t) {
                var n = "ace" == t ? editor.getSession().getValue() : document.getElementById("normal-editor").value;
                if (typeof n !== 'undefined' && n !== null) {
                    if (true) {
                        var data = {
                            ajax: true,
                            content: n,
                            type: 'save',
                            token: window.csrf
                        };

                        $.ajax({
                            type: "POST",
                            url: window.location,
                            data: JSON.stringify(data),
                            contentType: "application/json; charset=utf-8",
                            success: function(mes) {
                                toast("Saved Successfully");
                                window.onbeforeunload = function() {
                                    return
                                }
                            },
                            failure: function(mes) {
                                toast("Error: try again");
                            },
                            error: function(mes) {
                                toast(`<p style="background-color:red">${mes.responseText}</p>`);
                            }
                        });
                    } else {
                        var a = document.createElement("form");
                        a.setAttribute("method", "POST"), a.setAttribute("action", "");
                        var o = document.createElement("textarea");
                        o.setAttribute("type", "textarea"), o.setAttribute("name", "savedata");
                        let cx = document.createElement("input");
                        cx.setAttribute("type", "hidden");
                        cx.setAttribute("name", "token");
                        cx.setAttribute("value", window.csrf);
                        var c = document.createTextNode(n);
                        o.appendChild(c), a.appendChild(o), a.appendChild(cx), document.body.appendChild(a), a.submit()
                    }
                }
            }

            function show_new_pwd() {
                $(".js-new-pwd").toggleClass('hidden');
            }

            // Save Settings
            function save_settings($this) {
                let form = $($this),
                    selectedTheme = form.find('select[name="js-theme-3"]').val() || 'light';

                // Apply instantly so the user can see the theme switch right away.
                document.documentElement.setAttribute('data-bs-theme', selectedTheme);
                $('body').toggleClass('theme-dark', selectedTheme === 'dark');

                $.ajax({
                    type: form.attr('method'),
                    url: form.attr('action'),
                    data: form.serialize() + "&token=" + window.csrf + "&ajax=" + true,
                    success: function(data) {
                        var response = data;
                        if (typeof data === 'string') {
                            try {
                                response = JSON.parse(data);
                            } catch (e) {
                                response = {
                                    success: false
                                };
                            }
                        }

                        if (response && response.success) {
                            toast('Settings saved successfully');
                            var url = new URL(window.location.href);
                            url.searchParams.delete('settings');
                            url.hash = '';
                            var nextUrl = url.pathname + (url.searchParams.toString() ? ('?' + url.searchParams.toString()) : '');
                            setTimeout(function() {
                                window.location.assign(nextUrl);
                            }, 450);
                        } else {
                            toast('Settings could not be saved. Check write permissions for config.php');
                        }
                    },
                    error: function() {
                        toast('Settings could not be saved. Check write permissions for config.php');
                    }
                });
                return false;
            }

            // Change password for logged-in user
            function change_password($this) {
                let form = $($this);
                $.ajax({
                    type: 'post',
                    url: '',
                    data: form.serialize() + '&token=' + window.csrf + '&ajax=true',
                    success: function(data) {
                        let response = data;
                        if (typeof data === 'string') {
                            try { response = JSON.parse(data); } catch(e) { response = {success:false,msg:'Unknown error'}; }
                        }
                        if (response && response.success) {
                            toast(response.msg || 'Password changed successfully');
                            form[0].reset();
                        } else {
                            toast((response && response.msg) ? response.msg : 'Password change failed');
                        }
                    },
                    error: function() { toast('Password change failed'); }
                });
                return false;
            }

            //Create new password hash
            function new_password_hash($this) {
                let form = $($this),
                    $pwd = $("#js-pwd-result");
                $pwd.val('');
                $.ajax({
                    type: form.attr('method'),
                    url: form.attr('action'),
                    data: form.serialize() + "&token=" + window.csrf + "&ajax=" + true,
                    success: function(data) {
                        if (data) {
                            $pwd.val(data);
                        }
                    }
                });
                return false;
            }

            // Upload files using URL @param {Object}
            function upload_from_url($this) {
                let form = $($this),
                    resultWrapper = $("div#js-url-upload__list");
                $.ajax({
                    type: form.attr('method'),
                    url: form.attr('action'),
                    data: form.serialize() + "&token=" + window.csrf + "&ajax=" + true,
                    beforeSend: function() {
                        form.find("input[name=uploadurl]").attr("disabled", "disabled");
                        form.find("button").hide();
                        form.find(".lds-facebook").addClass('show-me');
                    },
                    success: function(data) {
                        if (data) {
                            data = JSON.parse(data);
                            if (data.done) {
                                resultWrapper.append('<div class="alert alert-success row">Uploaded Successful: ' + data.done.name + '</div>');
                                form.find("input[name=uploadurl]").val('');
                            } else if (data['fail']) {
                                resultWrapper.append('<div class="alert alert-danger row">Error: ' + data.fail.message + '</div>');
                            }
                            form.find("input[name=uploadurl]").removeAttr("disabled");
                            form.find("button").show();
                            form.find(".lds-facebook").removeClass('show-me');
                        }
                    },
                    error: function(xhr) {
                        form.find("input[name=uploadurl]").removeAttr("disabled");
                        form.find("button").show();
                        form.find(".lds-facebook").removeClass('show-me');
                        console.error(xhr);
                    }
                });
                return false;
            }

            // Search template
            function search_template(data) {
                var response = "";
                $.each(data, function(key, val) {
                    response += `<li><a href="?p=${val.path}&view=${val.name}">${val.path}/${val.name}</a></li>`;
                });
                return response;
            }

            // Advance search
            function fm_search() {
                var searchTxt = $("input#advanced-search").val(),
                    searchWrapper = $("ul#search-wrapper"),
                    path = $("#js-search-modal").attr("href"),
                    _html = "",
                    $loader = $("div.lds-facebook");
                if (!!searchTxt && searchTxt.length > 2 && path) {
                    var data = {
                        ajax: true,
                        content: searchTxt,
                        path: path,
                        type: 'search',
                        token: window.csrf
                    };
                    $.ajax({
                        type: "POST",
                        url: window.location,
                        data: data,
                        beforeSend: function() {
                            searchWrapper.html('');
                            $loader.addClass('show-me');
                        },
                        success: function(data) {
                            $loader.removeClass('show-me');
                            data = JSON.parse(data);
                            if (data && data.length) {
                                _html = search_template(data);
                                searchWrapper.html(_html);
                            } else {
                                searchWrapper.html('<p class="m-2">No result found!<p>');
                            }
                        },
                        error: function(xhr) {
                            $loader.removeClass('show-me');
                            searchWrapper.html('<p class="m-2">ERROR: Try again later!</p>');
                        },
                        failure: function(mes) {
                            $loader.removeClass('show-me');
                            searchWrapper.html('<p class="m-2">ERROR: Try again later!</p>');
                        }
                    });
                } else {
                    searchWrapper.html("OOPS: minimum 3 characters required!");
                }
            }

            // action confirm dailog modal
            function confirmDailog(e, id = 0, title = "Action", content = "", action = null) {
                e.preventDefault();
                const tplObj = {
                    id,
                    title,
                    content: decodeURIComponent(content.replace(/\+/g, ' ')),
                    action
                };
                let tpl = $("#js-tpl-confirm").html();
                $(".modal.confirmDailog").remove();
                $('#wrapper').append(template(tpl, tplObj));
                const $confirmDailog = $("#confirmDailog-" + tplObj.id);
                $confirmDailog.modal('show');
                return false;
            }

            // on mouse hover image preview
            ! function(s) {
                s.previewImage = function(e) {
                    var o = s(document),
                        t = ".previewImage",
                        a = s.extend({
                            xOffset: 20,
                            yOffset: -20,
                            fadeIn: "fast",
                            css: {
                                padding: "5px",
                                border: "1px solid #cccccc",
                                "background-color": "#fff"
                            },
                            eventSelector: "[data-preview-image]",
                            dataKey: "previewImage",
                            overlayId: "preview-image-plugin-overlay"
                        }, e);
                    return o.off(t), o.on("mouseover" + t, a.eventSelector, function(e) {
                        s("p#" + a.overlayId).remove();
                        var o = s("<p>").attr("id", a.overlayId).css("position", "absolute").css("display", "none").append(s('<img class="c-preview-img">').attr("src", s(this).data(a.dataKey)));
                        a.css && o.css(a.css), s("body").append(o), o.css("top", e.pageY + a.yOffset + "px").css("left", e.pageX + a.xOffset + "px").fadeIn(a.fadeIn)
                    }), o.on("mouseout" + t, a.eventSelector, function() {
                        s("#" + a.overlayId).remove()
                    }), o.on("mousemove" + t, a.eventSelector, function(e) {
                        s("#" + a.overlayId).css("top", e.pageY + a.yOffset + "px").css("left", e.pageX + a.xOffset + "px")
                    }), this
                }, s.previewImage()
            }(jQuery);

            // Dom Ready Events
            $(document).ready(function() {
                // dataTable init
                var $table = $('#main-table'),
                    tableLng = $table.find('th').length,
                    _targets = (tableLng && tableLng == 7) ? [0, 4, 5, 6] : tableLng == 5 ? [0, 4] : [3];
                mainTable = $('#main-table').DataTable({
                    paging: false,
                    info: false,
                    order: [],
                    columnDefs: [{
                        targets: _targets,
                        orderable: false
                    }]
                });

                var storageKey = 'fm_view_mode',
                    $viewButtons = $('.js-view-mode'),
                    $tableWrap = $('.table-responsive').first(),
                    $grid = $('#fm-grid-view'),
                    fmIsManagerOrAdmin = <?php echo (FM_MANAGER || (!FM_READONLY && !FM_UPLOAD_ONLY)) ? 'true' : 'false'; ?>;

                function isMobileViewport() {
                    return window.matchMedia('(max-width: 767.98px)').matches;
                }

                function getViewMode() {
                    var savedMode = localStorage.getItem(storageKey);
                    if (savedMode) {
                        return savedMode;
                    }
                    return isMobileViewport() ? 'grid' : 'list';
                }

                function setViewMode(mode, persist) {
                    if (typeof persist === 'undefined') {
                        persist = true;
                    }
                    var gridMode = mode === 'grid';
                    $viewButtons.removeClass('active');
                    $viewButtons.filter('[data-view-mode="' + mode + '"]').addClass('active');
                    $tableWrap.toggleClass('hidden', gridMode);
                    $grid.toggleClass('hidden', !gridMode);
                    if (gridMode) {
                        renderGridView();
                    }
                    if (persist) {
                        localStorage.setItem(storageKey, mode);
                    }
                }

                function applyCompactMobileMode() {
                    var compact = window.matchMedia('(max-width: 479.98px)').matches;
                    $table.toggleClass('fm-compact-mobile', compact);
                }

                function renderGridView() {
                    var hasSelect = $('#main-table thead th').first().hasClass('custom-checkbox-header'),
                        rows = $('#main-table tbody tr'),
                        nameIndex = hasSelect ? 1 : 0,
                        sizeIndex = hasSelect ? 2 : 1,
                        modIndex = hasSelect ? 3 : 2,
                        cards = [];

                    rows.each(function() {
                        var $tr = $(this),
                            $tds = $tr.children('td');

                        if (!$tds.length) {
                            return;
                        }

                        var $nameCell = $tds.eq(nameIndex),
                            $nameLink = $nameCell.find('.filename a').first();

                        if (!$nameLink.length) {
                            return;
                        }

                        var title = $.trim($nameLink.text()),
                            href = $nameLink.attr('href') || '#',
                            hrefSafe = (href || '#').replace(/"/g, '&quot;'),
                            fullPath = $nameLink.attr('data-full-path') || '',
                            iconHtml = $nameCell.find('.filename i').first().prop('outerHTML') || '<i class="fa fa-file-o"></i>',
                            previewType = $nameLink.attr('data-preview-type') || '',
                            previewSrc = $nameLink.attr('data-preview-src') || '',
                            size = $.trim($tds.eq(sizeIndex).text()),
                            modified = $.trim($tds.eq(modIndex).text()),
                            actionsHtml = $tds.last().html() || '',
                            parentClass = title === '..' ? ' fm-grid-parent' : '',
                            isFile = href.indexOf('&view=') !== -1,
                            linkClass = isFile ? 'fm-grid-link-file' : 'fm-grid-link-dir',
                            thumbHtml = iconHtml,
                            badgeHtml = '',
                            pathDisplay = (fmIsManagerOrAdmin && fullPath) ? '<span class="fm-grid-path" title="' + fullPath.replace(/"/g, '&quot;') + '">' + fullPath + '</span>' : '';

                        if (previewType === 'image' && previewSrc) {
                            thumbHtml = '<img src="' + previewSrc + '" alt="' + title.replace(/"/g, '&quot;') + '">';
                        } else if (previewType === 'video' && previewSrc) {
                            thumbHtml = '<video src="' + previewSrc + '" muted preload="metadata" playsinline></video>';
                        } else if (previewType === 'pdf') {
                            badgeHtml = '<div class="fm-grid-pdf-badge">PDF</div>';
                        }


                        cards.push(
                            '<div class="fm-grid-item' + parentClass + '">' +
                            '<div class="fm-grid-thumb" data-href="' + hrefSafe + '">' +
                            thumbHtml +
                            badgeHtml +
                            '</div>' +
                            '<div class="fm-grid-body">' +
                            '<div class="fm-grid-name"><a href="' + hrefSafe + '" class="fm-grid-link ' + linkClass + '" title="' + title.replace(/"/g, '&quot;') + '">' + title + '</a></div>' +
                            (pathDisplay ? '<div class="fm-grid-path-row">' + pathDisplay + '</div>' : '') +
                            '<div class="fm-grid-meta"><span>' + size + '</span><span>' + modified + '</span></div>' +
                            '</div>' +
                            '<div class="fm-grid-actions"><div class="inline-actions">' + actionsHtml + '</div></div>' +
                            '</div>'
                        );
                    });

                    if (!cards.length) {
                        $grid.html('<div class="alert alert-light border mb-2"><?php echo addslashes(lng('Folder is empty')); ?></div>');
                        return;
                    }

                    $grid.html('<div class="fm-grid">' + cards.join('') + '</div>');
                }

                $viewButtons.on('click', function() {
                    setViewMode($(this).data('view-mode'), true);
                });

                $grid.off('click.fmgrid').on('click.fmgrid', '.fm-grid-thumb, .fm-grid-name', function(e) {
                    if ($(e.target).closest('a,button,input,label,form').length) {
                        return;
                    }

                    var $item = $(this).closest('.fm-grid-item'),
                        href = $(this).data('href') || $item.find('.fm-grid-link').attr('href');

                    if (href) {
                        window.location.href = href;
                    }
                });

                mainTable.on('draw', function() {
                    if (getViewMode() === 'grid') {
                        renderGridView();
                    }
                    if (typeof window.fmUpdateSelectionBar === 'function') {
                        window.fmUpdateSelectionBar();
                    }
                });

                function adjustNavbarOffset() {
                    if ($('body').hasClass('navbar-fixed')) {
                        var h = $('.main-nav.fixed-top').outerHeight(true) || 56;
                        $('body').css('margin-top', h + 'px');
                    }
                }

                setViewMode(getViewMode(), !!localStorage.getItem(storageKey));
                applyCompactMobileMode();
                adjustNavbarOffset();

                // Keep view mode in sync with viewport when no explicit preference exists.
                $(window).on('resize', function() {
                    if (!localStorage.getItem(storageKey)) {
                        setViewMode(getViewMode(), false);
                    }
                    applyCompactMobileMode();
                    adjustNavbarOffset();
                });

                var $selectionBar = $('#fm-selection-bar'),
                    $selectionCount = $('#fm-selection-count');

                window.fmUpdateSelectionBar = function() {
                    var selected = get_checkboxes().filter(function(item) {
                        return item.checked;
                    }).length;

                    $selectionCount.text('<?php echo addslashes(lng('Selected')); ?>: ' + selected);
                    $selectionCount.toggle(selected > 0);

                    if (isMobileViewport()) {
                        $selectionBar.css('display', selected > 0 ? 'flex' : 'none');
                    } else {
                        $selectionBar.css('display', '');
                    }
                };

                $(document).on('change', 'input[name="file[]"], #js-select-all-items', function() {
                    window.fmUpdateSelectionBar();
                });

                $('#js-mobile-focus-search').on('click', function(e) {
                    e.preventDefault();
                    var target = document.getElementById('navbarSupportedContent');
                    if (target && !target.classList.contains('show')) {
                        var bsCollapse = bootstrap.Collapse.getOrCreateInstance(target, {
                            toggle: false
                        });
                        bsCollapse.show();
                    }
                    setTimeout(function() {
                        var searchInput = document.getElementById('search-addon');
                        if (searchInput) {
                            searchInput.focus();
                        }
                    }, 160);
                });

                window.fmUpdateSelectionBar();

                // filter table
                $('#search-addon').on('keyup', function() {
                    mainTable.search(this.value).draw();
                });

                $("input#advanced-search").on('keyup', function(e) {
                    if (e.keyCode === 13) {
                        fm_search();
                    }
                });

                $('#search-addon3').on('click', function() {
                    fm_search();
                });

                //upload nav tabs
                $(".fm-upload-wrapper .card-header-tabs").on("click", 'a', function(e) {
                    e.preventDefault();
                    let target = $(this).data('target');
                    $(".fm-upload-wrapper .card-header-tabs a").removeClass('active');
                    $(this).addClass('active');
                    $(".fm-upload-wrapper .card-tabs-container").addClass('hidden');
                    $(target).removeClass('hidden');
                });
            });
        </script>

        <?php if (isset($_GET['edit']) && isset($_GET['env']) && FM_EDIT_FILE && !FM_READONLY):
            $ext = pathinfo($_GET["edit"], PATHINFO_EXTENSION);
            $ext =  $ext == "js" ? "javascript" :  $ext;
        ?>
            <?php print_external('js-ace'); ?>
            <script>
                var editor = ace.edit("editor");
                editor.getSession().setMode({
                    path: "ace/mode/<?php echo $ext; ?>",
                    inline: true
                });
                //editor.setTheme("ace/theme/twilight"); // Dark Theme
                editor.setShowPrintMargin(false); // Hide the vertical ruler
                function ace_commend(cmd) {
                    editor.commands.exec(cmd, editor);
                }
                editor.commands.addCommands([{
                    name: 'save',
                    bindKey: {
                        win: 'Ctrl-S',
                        mac: 'Command-S'
                    },
                    exec: function(editor) {
                        edit_save(this, 'ace');
                    }
                }]);

                function renderThemeMode() {
                    var $modeEl = $("select#js-ace-mode"),
                        $themeEl = $("select#js-ace-theme"),
                        $fontSizeEl = $("select#js-ace-fontSize"),
                        optionNode = function(type, arr) {
                            var $Option = "";
                            $.each(arr, function(i, val) {
                                $Option += "<option value='" + type + i + "'>" + val + "</option>";
                            });
                            return $Option;
                        },
                        _data = {
                            "aceTheme": {
                                "bright": {
                                    "chrome": "Chrome",
                                    "clouds": "Clouds",
                                    "crimson_editor": "Crimson Editor",
                                    "dawn": "Dawn",
                                    "dreamweaver": "Dreamweaver",
                                    "eclipse": "Eclipse",
                                    "github": "GitHub",
                                    "iplastic": "IPlastic",
                                    "solarized_light": "Solarized Light",
                                    "textmate": "TextMate",
                                    "tomorrow": "Tomorrow",
                                    "xcode": "XCode",
                                    "kuroir": "Kuroir",
                                    "katzenmilch": "KatzenMilch",
                                    "sqlserver": "SQL Server"
                                },
                                "dark": {
                                    "ambiance": "Ambiance",
                                    "chaos": "Chaos",
                                    "clouds_midnight": "Clouds Midnight",
                                    "dracula": "Dracula",
                                    "cobalt": "Cobalt",
                                    "gruvbox": "Gruvbox",
                                    "gob": "Green on Black",
                                    "idle_fingers": "idle Fingers",
                                    "kr_theme": "krTheme",
                                    "merbivore": "Merbivore",
                                    "merbivore_soft": "Merbivore Soft",
                                    "mono_industrial": "Mono Industrial",
                                    "monokai": "Monokai",
                                    "pastel_on_dark": "Pastel on dark",
                                    "solarized_dark": "Solarized Dark",
                                    "terminal": "Terminal",
                                    "tomorrow_night": "Tomorrow Night",
                                    "tomorrow_night_blue": "Tomorrow Night Blue",
                                    "tomorrow_night_bright": "Tomorrow Night Bright",
                                    "tomorrow_night_eighties": "Tomorrow Night 80s",
                                    "twilight": "Twilight",
                                    "vibrant_ink": "Vibrant Ink"
                                }
                            },
                            "aceMode": {
                                "javascript": "JavaScript",
                                "abap": "ABAP",
                                "abc": "ABC",
                                "actionscript": "ActionScript",
                                "ada": "ADA",
                                "apache_conf": "Apache Conf",
                                "asciidoc": "AsciiDoc",
                                "asl": "ASL",
                                "assembly_x86": "Assembly x86",
                                "autohotkey": "AutoHotKey",
                                "apex": "Apex",
                                "batchfile": "BatchFile",
                                "bro": "Bro",
                                "c_cpp": "C and C++",
                                "c9search": "C9Search",
                                "cirru": "Cirru",
                                "clojure": "Clojure",
                                "cobol": "Cobol",
                                "coffee": "CoffeeScript",
                                "coldfusion": "ColdFusion",
                                "csharp": "C#",
                                "csound_document": "Csound Document",
                                "csound_orchestra": "Csound",
                                "csound_score": "Csound Score",
                                "css": "CSS",
                                "curly": "Curly",
                                "d": "D",
                                "dart": "Dart",
                                "diff": "Diff",
                                "dockerfile": "Dockerfile",
                                "dot": "Dot",
                                "drools": "Drools",
                                "edifact": "Edifact",
                                "eiffel": "Eiffel",
                                "ejs": "EJS",
                                "elixir": "Elixir",
                                "elm": "Elm",
                                "erlang": "Erlang",
                                "forth": "Forth",
                                "fortran": "Fortran",
                                "fsharp": "FSharp",
                                "fsl": "FSL",
                                "ftl": "FreeMarker",
                                "gcode": "Gcode",
                                "gherkin": "Gherkin",
                                "gitignore": "Gitignore",
                                "glsl": "Glsl",
                                "gobstones": "Gobstones",
                                "golang": "Go",
                                "graphqlschema": "GraphQLSchema",
                                "groovy": "Groovy",
                                "haml": "HAML",
                                "handlebars": "Handlebars",
                                "haskell": "Haskell",
                                "haskell_cabal": "Haskell Cabal",
                                "haxe": "haXe",
                                "hjson": "Hjson",
                                "html": "HTML",
                                "html_elixir": "HTML (Elixir)",
                                "html_ruby": "HTML (Ruby)",
                                "ini": "INI",
                                "io": "Io",
                                "jack": "Jack",
                                "jade": "Jade",
                                "java": "Java",
                                "json": "JSON",
                                "jsoniq": "JSONiq",
                                "jsp": "JSP",
                                "jssm": "JSSM",
                                "jsx": "JSX",
                                "julia": "Julia",
                                "kotlin": "Kotlin",
                                "latex": "LaTeX",
                                "less": "LESS",
                                "liquid": "Liquid",
                                "lisp": "Lisp",
                                "livescript": "LiveScript",
                                "logiql": "LogiQL",
                                "lsl": "LSL",
                                "lua": "Lua",
                                "luapage": "LuaPage",
                                "lucene": "Lucene",
                                "makefile": "Makefile",
                                "markdown": "Markdown",
                                "mask": "Mask",
                                "matlab": "MATLAB",
                                "maze": "Maze",
                                "mel": "MEL",
                                "mixal": "MIXAL",
                                "mushcode": "MUSHCode",
                                "mysql": "MySQL",
                                "nix": "Nix",
                                "nsis": "NSIS",
                                "objectivec": "Objective-C",
                                "ocaml": "OCaml",
                                "pascal": "Pascal",
                                "perl": "Perl",
                                "perl6": "Perl 6",
                                "pgsql": "pgSQL",
                                "php_laravel_blade": "PHP (Blade Template)",
                                "php": "PHP",
                                "puppet": "Puppet",
                                "pig": "Pig",
                                "powershell": "Powershell",
                                "praat": "Praat",
                                "prolog": "Prolog",
                                "properties": "Properties",
                                "protobuf": "Protobuf",
                                "python": "Python",
                                "r": "R",
                                "razor": "Razor",
                                "rdoc": "RDoc",
                                "red": "Red",
                                "rhtml": "RHTML",
                                "rst": "RST",
                                "ruby": "Ruby",
                                "rust": "Rust",
                                "sass": "SASS",
                                "scad": "SCAD",
                                "scala": "Scala",
                                "scheme": "Scheme",
                                "scss": "SCSS",
                                "sh": "SH",
                                "sjs": "SJS",
                                "slim": "Slim",
                                "smarty": "Smarty",
                                "snippets": "snippets",
                                "soy_template": "Soy Template",
                                "space": "Space",
                                "sql": "SQL",
                                "sqlserver": "SQLServer",
                                "stylus": "Stylus",
                                "svg": "SVG",
                                "swift": "Swift",
                                "tcl": "Tcl",
                                "terraform": "Terraform",
                                "tex": "Tex",
                                "text": "Text",
                                "textile": "Textile",
                                "toml": "Toml",
                                "tsx": "TSX",
                                "twig": "Twig",
                                "typescript": "Typescript",
                                "vala": "Vala",
                                "vbscript": "VBScript",
                                "velocity": "Velocity",
                                "verilog": "Verilog",
                                "vhdl": "VHDL",
                                "visualforce": "Visualforce",
                                "wollok": "Wollok",
                                "xml": "XML",
                                "xquery": "XQuery",
                                "yaml": "YAML",
                                "django": "Django"
                            },
                            "fontSize": {
                                8: 8,
                                10: 10,
                                11: 11,
                                12: 12,
                                13: 13,
                                14: 14,
                                15: 15,
                                16: 16,
                                17: 17,
                                18: 18,
                                20: 20,
                                22: 22,
                                24: 24,
                                26: 26,
                                30: 30
                            }
                        };
                    if (_data && _data.aceMode) {
                        $modeEl.html(optionNode("ace/mode/", _data.aceMode));
                    }
                    if (_data && _data.aceTheme) {
                        var lightTheme = optionNode("ace/theme/", _data.aceTheme.bright),
                            darkTheme = optionNode("ace/theme/", _data.aceTheme.dark);
                        $themeEl.html("<optgroup label=\"Bright\">" + lightTheme + "</optgroup><optgroup label=\"Dark\">" + darkTheme + "</optgroup>");
                    }
                    if (_data && _data.fontSize) {
                        $fontSizeEl.html(optionNode("", _data.fontSize));
                    }
                    $modeEl.val(editor.getSession().$modeId);
                    $themeEl.val(editor.getTheme());
                    $(function() {
                        //set default font size in drop down
                        $fontSizeEl.val(12).change();
                    });
                }

                $(function() {
                    renderThemeMode();
                    $(".js-ace-toolbar").on("click", 'button', function(e) {
                        e.preventDefault();
                        let cmdValue = $(this).attr("data-cmd"),
                            editorOption = $(this).attr("data-option");
                        if (cmdValue && cmdValue != "none") {
                            ace_commend(cmdValue);
                        } else if (editorOption) {
                            if (editorOption == "fullscreen") {
                                (void 0 !== document.fullScreenElement && null === document.fullScreenElement || void 0 !== document.msFullscreenElement && null === document.msFullscreenElement || void 0 !== document.mozFullScreen && !document.mozFullScreen || void 0 !== document.webkitIsFullScreen && !document.webkitIsFullScreen) &&
                                (editor.container.requestFullScreen ? editor.container.requestFullScreen() : editor.container.mozRequestFullScreen ? editor.container.mozRequestFullScreen() : editor.container.webkitRequestFullScreen ? editor.container.webkitRequestFullScreen(Element.ALLOW_KEYBOARD_INPUT) : editor.container.msRequestFullscreen && editor.container.msRequestFullscreen());
                            } else if (editorOption == "wrap") {
                                let wrapStatus = (editor.getSession().getUseWrapMode()) ? false : true;
                                editor.getSession().setUseWrapMode(wrapStatus);
                            }
                        }
                    });

                    $("select#js-ace-mode, select#js-ace-theme, select#js-ace-fontSize").on("change", function(e) {
                        e.preventDefault();
                        let selectedValue = $(this).val(),
                            selectionType = $(this).attr("data-type");
                        if (selectedValue && selectionType == "mode") {
                            editor.getSession().setMode(selectedValue);
                        } else if (selectedValue && selectionType == "theme") {
                            editor.setTheme(selectedValue);
                        } else if (selectedValue && selectionType == "fontSize") {
                            editor.setFontSize(parseInt(selectedValue));
                        }
                    });
                });
            </script>
        <?php endif; ?>
        <div id="snackbar"></div>
    </body>

    </html>
<?php
    }

    /**
     * Language Translation System
     * @param string $txt
     * @return string
     */
    function lng($txt)
    {
        global $lang;

        // English Language
        $tr['en']['AppName']        = 'Tiny File Manager';
        $tr['en']['AppTitle']       = 'File Manager';
        $tr['en']['Login']          = 'Sign in';
        $tr['en']['Username']       = 'Username';
        $tr['en']['Password']       = 'Password';
        $tr['en']['Logout']         = 'Sign Out';
        $tr['en']['Move']           = 'Move';
        $tr['en']['Copy']           = 'Copy';
        $tr['en']['Save']           = 'Save';
        $tr['en']['SelectAll']      = 'Select all';
        $tr['en']['UnSelectAll']    = 'Unselect all';
        $tr['en']['File']           = 'File';
        $tr['en']['Back']           = 'Back';
        $tr['en']['Size']           = 'Size';
        $tr['en']['Perms']          = 'Perms';
        $tr['en']['Modified']       = 'Modified';
        $tr['en']['Owner']          = 'Owner';
        $tr['en']['Search']         = 'Search';
        $tr['en']['NewItem']        = 'New Item';
        $tr['en']['Folder']         = 'Folder';
        $tr['en']['Delete']         = 'Delete';
        $tr['en']['Rename']         = 'Rename';
        $tr['en']['CopyTo']         = 'Copy to';
        $tr['en']['DirectLink']     = 'Direct link';
        $tr['en']['UploadingFiles'] = 'Upload Files';
        $tr['en']['ChangePermissions']  = 'Change Permissions';
        $tr['en']['Copying']        = 'Copying';
        $tr['en']['CreateNewItem']  = 'Create New Item';
        $tr['en']['Name']           = 'Name';
        $tr['en']['AdvancedEditor'] = 'Advanced Editor';
        $tr['en']['Actions']        = 'Actions';
        $tr['en']['Folder is empty'] = 'Folder is empty';
        $tr['en']['Upload']         = 'Upload';
        $tr['en']['Cancel']         = 'Cancel';
        $tr['en']['InvertSelection'] = 'Invert Selection';
        $tr['en']['DestinationFolder']  = 'Destination Folder';
        $tr['en']['ItemType']       = 'Item Type';
        $tr['en']['ItemName']       = 'Item Name';
        $tr['en']['CreateNow']      = 'Create Now';
        $tr['en']['Download']       = 'Download';
        $tr['en']['Open']           = 'Open';
        $tr['en']['UnZip']          = 'UnZip';
        $tr['en']['UnZipToFolder']  = 'UnZip to folder';
        $tr['en']['Edit']           = 'Edit';
        $tr['en']['NormalEditor']   = 'Normal Editor';
        $tr['en']['BackUp']         = 'Back Up';
        $tr['en']['SourceFolder']   = 'Source Folder';
        $tr['en']['Files']          = 'Files';
        $tr['en']['Move']           = 'Move';
        $tr['en']['Change']         = 'Change';
        $tr['en']['Settings']       = 'Settings';
        $tr['en']['Language']       = 'Language';
        $tr['en']['ErrorReporting'] = 'Error Reporting';
        $tr['en']['ShowHiddenFiles'] = 'Show Hidden Files';
        $tr['en']['Help']           = 'Help';
        $tr['en']['Created']        = 'Created';
        $tr['en']['Help Documents'] = 'Help Documents';
        $tr['en']['Report Issue']   = 'Report Issue';
        $tr['en']['Generate']       = 'Generate';
        $tr['en']['FullSize']       = 'Full Size';
        $tr['en']['HideColumns']        = 'Hide Perms/Owner columns';
        $tr['en']['Online users']       = 'Online users';
        $tr['en']['Some internal options are available only for managers'] = 'Some internal options are available only for managers';
        $tr['en']['Change Password']    = 'Change Password';
        $tr['en']['Current password']   = 'Current password';
        $tr['en']['New password']       = 'New password';
        $tr['en']['Confirm password']   = 'Confirm password';
        $tr['en']['You are logged in'] = 'You are logged in';
        $tr['en']['Selected']          = 'Selected';
        $tr['en']['Nothing selected']  = 'Nothing selected';
        $tr['en']['Paths must be not equal']    = 'Paths must be not equal';
        $tr['en']['Renamed from']       = 'Renamed from';
        $tr['en']['Archive not unpacked'] = 'Archive not unpacked';
        $tr['en']['Deleted']            = 'Deleted';
        $tr['en']['Archive not created'] = 'Archive not created';
        $tr['en']['Copied from']        = 'Copied from';
        $tr['en']['Permissions changed'] = 'Permissions changed';
        $tr['en']['to']                 = 'to';
        $tr['en']['Saved Successfully'] = 'Saved Successfully';
        $tr['en']['not found!']         = 'not found!';
        $tr['en']['File Saved Successfully']    = 'File Saved Successfully';
        $tr['en']['Archive']            = 'Archive';
        $tr['en']['Permissions not changed']    = 'Permissions not changed';
        $tr['en']['Select folder']      = 'Select folder';
        $tr['en']['Source path not defined']    = 'Source path not defined';
        $tr['en']['already exists']     = 'already exists';
        $tr['en']['Error while moving from']    = 'Error while moving from';
        $tr['en']['Create archive?']    = 'Create archive?';
        $tr['en']['Invalid file or folder name']    = 'Invalid file or folder name';
        $tr['en']['Archive unpacked']   = 'Archive unpacked';
        $tr['en']['File extension is not allowed']  = 'File extension is not allowed';
        $tr['en']['Root path']          = 'Root path';
        $tr['en']['Error while renaming from']  = 'Error while renaming from';
        $tr['en']['File not found']     = 'File not found';
        $tr['en']['Error while deleting items'] = 'Error while deleting items';
        $tr['en']['Moved from']         = 'Moved from';
        $tr['en']['Generate new password hash'] = 'Generate new password hash';
        $tr['en']['Login failed. Invalid username or password'] = 'Login failed. Invalid username or password';
        $tr['en']['password_hash not supported, Upgrade PHP version'] = 'password_hash not supported, Upgrade PHP version';
        $tr['en']['Advanced Search']    = 'Advanced Search';
        $tr['en']['Error while copying from']    = 'Error while copying from';
        $tr['en']['Invalid characters in file name']                = 'Invalid characters in file name';
        $tr['en']['FILE EXTENSION IS NOT SUPPORTED']                = 'FILE EXTENSION IS NOT SUPPORTED';
        $tr['en']['Selected files and folder deleted']              = 'Selected files and folder deleted';
        $tr['en']['Error while fetching archive info']              = 'Error while fetching archive info';
        $tr['en']['Delete selected files and folders?']             = 'Delete selected files and folders?';
        $tr['en']['Search file in folder and subfolders...']        = 'Search file in folder and subfolders...';
        $tr['en']['Access denied. IP restriction applicable']       = 'Access denied. IP restriction applicable';
        $tr['en']['Invalid characters in file or folder name']      = 'Invalid characters in file or folder name';
        $tr['en']['Operations with archives are not available']     = 'Operations with archives are not available';
        $tr['en']['File or folder with this path already exists']   = 'File or folder with this path already exists';
        $tr['en']['Are you sure want to rename?']                   = 'Are you sure want to rename?';
        $tr['en']['Are you sure want to']                           = 'Are you sure want to';
        $tr['en']['Date Modified']                                  = 'Date Modified';
        $tr['en']['File size']                                      = 'File size';
        $tr['en']['MIME-type']                                      = 'MIME-type';
        $tr['en']['DownloadOriginal']                               = 'Download original';
        $tr['en']['OfficeLoadingDocument']                          = 'Loading document...';
        $tr['en']['OfficeLoadingSpreadsheet']                       = 'Loading spreadsheet...';
        $tr['en']['OfficeLoadError']                                = 'Loading failed';
        $tr['en']['OfficeRenderError']                              = 'Rendering failed';
        $tr['en']['OfficeLibraryLoadErrorDocx']                     = 'docx-preview library could not be loaded.';
        $tr['en']['OfficeLibraryLoadErrorXlsx']                     = 'SheetJS library could not be loaded.';

        $i18n = fm_get_translations($tr);
        $tr = $i18n ? $i18n : $tr;

        if (!strlen($lang)) $lang = 'en';
        if (isset($tr[$lang][$txt])) return fm_enc($tr[$lang][$txt]);
        else if (isset($tr['en'][$txt])) return fm_enc($tr['en'][$txt]);
        else return "$txt";
    }

?>
