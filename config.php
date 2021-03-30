<?php

/*
#################################################################################################################
This is an OPTIONAL configuration file.
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
    'recox' => '$2y$10$9WBeaacPPHQ9hrCErO.0p.zZFANR2hAaunMaivBSKWyFMzNRfBc9i', 
    'jopi' => '$2y$10$Fg6Dz8oH9fPoZ2jJan5tZuv6Z4Kp7avtQ9bDfrdRntXtPeiMAZyGO',
    'wyrox' => '$2y$10$hGwYApvN9TO8DHCnqM5rXeXeEJDMm5MD5Xa9l9T4SA47anEobs0By',
    'simp' => '$2y$10$gIHw2ybKo6mvsZ8Z/k3FzuYvNIV0DnOzihjbFlqgFEFpIl3dh4t4u',
    'haracin' => '$2y$10$1N9vyknVQcKlPZDXKjhUK.h7srnK.cjfgVj5O6Nrnt10yKrg5jqYK',
    'vancleff' => '$2y$10$pNkLwl4FWEeOmw2s5AwVKe7CpB3mfZTXM5TxMF6tJx8xGEEKbCEWi',
    'emancu' => '$2y$10$zvyW4i.058EtyqQXVOLRROu3f1sEfyi1/G8F71sSQu8paMkgaI5GS',
    'ronin' => '$2y$10$zvyW4i.058EtyqQXVOLRROu3f1sEfyi1/G8F71sSQu8paMkgaI5GS',
    'reyarb' => '$2y$10$4X3gqurnA7KmcybjbqWAOu31Ntg6mjB8q669IP/waEGtegISwpm3G',
    'MartinTrionfetti' => '$2y$10$GeoDYYo43edC9FmN2ZmygePg2J2l7YLYOGl9JBZztxdI/W5ROpPKu',
    'ronin' => '$2y$10$C0JNU8RK8GDp1OLOyFWuLOLa4B7/nqcYIhVf0rNyGcnGD7uQNE1SC',
    'emancu' => '$2y$10$YVgOfXhD3BfJT1LeCKqYMOl7.DWJXMJz2OK3.z6AW5meFO3jzGgMW'
);

//set application theme
//options - 'light' and 'dark'
$theme = 'dark';

// Readonly users
// e.g. array('users', 'guest', ...)
$readonly_users = array(
    'MartinTrionfetti', 'ronin', 'vancleff', 'emancu', 'jopi', 'wyrox', 'simp', 'haracin', 'reyarb', 'emancu'
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
$root_path = $_SERVER['DOCUMENT_ROOT'];

// Root url for links in file manager.Relative to $http_host. Variants: '', 'path/to/subfolder'
// Will not working if $root_path will be outside of server document root
$root_url = '';

// Server hostname. Can set manually if wrong
$http_host = $_SERVER['HTTP_HOST'];

// user specific directories
// array('Username' => 'Directory path', 'Username2' => 'Directory path', ...)
$directories_users = array();

// input encoding for iconv
$iconv_input_encoding = 'UTF-8';

// date() format for file modification date
// Doc - https://www.php.net/manual/en/function.date.php
$datetime_format = 'd.m.y H:i';

// Allowed file extensions for create and rename files
// e.g. 'txt,html,css,js'
$allowed_file_extensions = '';

// Allowed file extensions for upload files
// e.g. 'gif,png,jpg,html,txt'
$allowed_upload_extensions = '';

// Favicon path. This can be either a full url to an .PNG image, or a path based on the document root.
// full path, e.g http://example.com/favicon.png
// local path, e.g images/icons/favicon.png
$favicon_path = '?img=favicon';

// Files and folders to excluded from listing
// e.g. array('myfile.html', 'personal-folder', '*.php', ...)
$exclude_items = array();

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


// max upload file size
$max_upload_size_bytes = 2048;

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

?>
