<?php
//Default Configuration
$CONFIG = '{"lang":"zh-CN","error_reporting":false,"show_hidden":true,"hide_Cols":false,"theme":"light"}';
/*
#################################################################################################################
This is an OPTIONAL configuration file. rename this file into config.php to use this configuration 
The role of this file is to make updating of "tinyfilemanager.php" easier.
So you can:
-Feel free to remove completely this file and configure "tinyfilemanager.php" as a single file application.
or
-Put inside this file all the static configuration you want and forgot to configure "tinyfilemanager.php".
#################################################################################################################
*/

// Auth with login/password
// set true/false to enable/disable it
// Is independent from IP white- and blacklisting
$use_auth = true;

// Login user name and password
// Users: array('Username' => 'Password', 'Username2' => 'Password2', ...)
// Generate secure password hash - https://tinyfilemanager.github.io/docs/pwd.html
$auth_users = array(
    'admin' => '$2y$10$jx9DL2I3x3nS6wmGTTete.wlPNtIddwlvySXYS2zjoPRGyhinbf1W', //  admin@123 
    'user0' => '$2y$10$pk.6o4/CCS0kwaPp349hVeOKHPDSP871HQDzUuZbnG0On/3YbCh9C', // 12345
	'user1' => '$2y$10$Bgj/8tbeamSe452sPXSK5eweR5rjIA/6cJPvCX85tvN2BED2VjO3m', // 12345
	'user2' => '$2y$10$Ey26DNdAImdZ7MSvBUYNZ.Tym0BkZVm9RqnS/vzXn8VM5RejeWol.', // 12345
	'user3' => '$2y$10$ZDTPfCO2nUWGhpkuTVCsKehbUuqq.xZJZ7RBFILRkgCWrgKGzgXM.', // user3
	'user4' => '$2y$10$yDbhZeVYg9zMaZXDx7HTueVvmpMHNFp6Ru2GkSBWNJH0m03XVg0ES',// @
	'user5' => '$2y$10$m2wUB5Kx3E6a/.BZ3VMUte5LzoLDJDpxNQ7qhffjtA9wLp28Qa3xa' //30116511
);

// Readonly users
// e.g. array('users', 'guest', ...)
$readonly_users = array(
    'guest'
);

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
//$root_path = '';    //
$root_path = $_SERVER['DOCUMENT_ROOT'].'/nas';//'/'; //

// Root url for links in file manager.Relative to $http_host. Variants: '', 'path/to/subfolder'
// Will not working if $root_path will be outside of server document root
$root_url = '';

// Server hostname. Can set manually if wrong
$http_host = $_SERVER['HTTP_HOST'];

// user specific directories
// array('Username' => 'Directory path', 'Username2' => 'Directory path', ...)
$directories_users = 
array(
      'admin' => '/', 
      'user0' => '/mnt/mmcblk2p4', 
      'user1' =>  '/mnt/mmcblk2p4/user1',
      'user2' => '/mnt/mmcblk2p4/user1/user2',
      'user3' => '/mnt/mmcblk2p4/user1/user3', 
      'user4' => '/mnt/mmcblk2p4/user1/user4',
      'user5' => '/mnt/mmcblk2p4/user1/user5'
);  // array();

// input encoding for iconv
$iconv_input_encoding = 'UTF-8';

// date() format for file modification date
// Doc - https://www.php.net/manual/en/datetime.format.php
$datetime_format = 'd.m.y H:i:s';

// Allowed file extensions for create and rename files
// e.g. 'txt,html,css,js'
$allowed_file_extensions = '';

// Allowed file extensions for upload files
// e.g. 'gif,png,jpg,html,txt'
$allowed_upload_extensions = '';

// Favicon path. This can be either a full url to an .PNG image, or a path based on the document root.
// full path, e.g http://example.com/favicon.png
// local path, e.g images/icons/favicon.png
$favicon_path = '/nas/favicon.ico';

// Files and folders to excluded from listing
// e.g. array('myfile.html', 'personal-folder', '*.php', ...)
$exclude_items = array('');

// Online office Docs Viewer
// Availabe rules are 'google', 'microsoft' or false
// google => View documents using Google Docs Viewer
// microsoft => View documents using Microsoft Web Apps Viewer
// false => disable online doc viewer
$online_viewer = 'google';

// Sticky Nav bar
// true => enable sticky header
// false => disable sticky header
$sticky_navbar = true;

// Path display mode when viewing file information
// 'full' => show full path
// 'relative' => show path relative to root_path
// 'host' => show path on the host
$path_display_mode = 'full';

// max upload file size
$max_upload_size_bytes = 5000;

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

// **新增：是否信任反向代理的 IP 头 (例如 Cloudflare 或 Nginx)**
// false (默认/最安全)：只使用 REMOTE_ADDR，防止 IP 伪造。
// true (使用代理时)：允许读取 HTTP_X_FORWARDED_FOR 等头，获取真实客户端 IP。
$trust_proxy = false;

?>