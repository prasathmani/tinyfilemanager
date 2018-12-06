# Tiny File Manager


[![Live demo](https://img.shields.io/badge/Live-Demo-brightgreen.svg?style=flat-square)](https://tinyfilemanager.github.io/demo/)
[![Live demo](https://img.shields.io/badge/Help-Docs-lightgrey.svg?style=flat-square)](https://tinyfilemanager.github.io/)
[![GitHub Release](https://img.shields.io/github/release/qubyte/rubidium.svg?style=flat-square)](https://github.com/prasathmani/tinyfilemanager/releases)
 [![GitHub License](https://img.shields.io/github/license/prasathmani/tinyfilemanager.svg?style=flat-square)](https://github.com/prasathmani/tinyfilemanager/blob/master/LICENSE) 
[![Beerpay](https://beerpay.io/prasathmani/tinyfilemanager/badge.svg?style=flat-square)](https://beerpay.io/prasathmani/tinyfilemanager)
> It is a simple, fast and small file manager with single php file. It is also a web code editor. It'll run either online or locally, on Linux, Windows or Mac based platforms. The only requirement is to have PHP 5.5+ available.

## Demo
[Demo](https://tinyfilemanager.github.io/demo/)

 Login Details : admin/admin@123 | user/12345


## Documents
<a href="https://tinyfilemanager.github.io/" target="_blank">tinyfilemanager.github.io</a>
<hr>

<img src="screenshot.gif" alt="H3K | Tiny File Manager">

## Requirements

- PHP 5.5.0 or higher.
- [Zip extension](http://php.net/manual/en/book.zip.php) for zip and unzip actions.
- Fileinfo, iconv and mbstring extensions are strongly recommended.

## How to use

Download ZIP with latest version from master branch.

Just copy the tinyfilemanager.php to your webspace - thats all :)
You can also change the file name from "tinyfilemanager.php" to something else, you know what i meant for.

Default username/password: admin/admin@123 and user/12345.

Warning: Please set your own username and password in `$auth_users` before use. password is encrypted with <code>password_hash()</code>. to generate new password hash <a href="https://tinyfilemanager.github.io/docs/pwd.html" target="_blank">here</a>

To enable/disable authentication set `$use_auth` to true or false.

### Supported constants:

- `FM_ROOT_PATH` - default is `$_SERVER['DOCUMENT_ROOT']`
- `FM_ROOT_URL` - default is `'http(s)://site.domain/'`
- `FM_SELF_URL` - default is `'http(s)://site.domain/' . $_SERVER['PHP_SELF']`
- `FM_ICONV_INPUT_ENC` - default is `'CP1251'`
- `FM_USE_HIGHLIGHTJS` - default is `true`
- `FM_HIGHLIGHTJS_STYLE` - default is `'vs'`
- `FM_DATETIME_FORMAT` - default is `'d.m.y H:i'`
- `FM_EXTENSION` - default is `""` //upload files extensions


### :loudspeaker: Features 
<ul>
<li>:cd: Open Source, light and extremely simple</li>
<li>:iphone: Mobile friendly view for touch devices</li>
<li>:information_source: Basic features likes Create, Delete, Modify, View, Download, Copy and Move files </li>
<li>:arrow_double_up: Ajax Upload, Ability to drag & drop, multiple files upload and file extensions filter </li>
<li>:file_folder: Ability to create folders and files</li>
<li>:gift: Ability to compress, extract files (zip, tar)</li>
<li>:sunglasses: Support user permissions - based on session and each user root folder mapping</li>
<li>:floppy_disk: Copy direct file URL</li>
<li>:pencil2: Cloud9 IDE - Syntax highlighting for over 90+ languages, Over 35+ themes with your favorite programming style
</li>
<li>:page_facing_up: Google Drive viewer helps you preview PDF/DOC/XLS/PPT/etc. 25 MB can be previewed with the Google Drive viewer</li>
<li>:zap: Backup files</li>
<li>:mag_right: Search -  Search and Sorting using datatable js</li>
<li>:file_folder: Exclude folders from listing</li>
<li>:globe_with_meridians: Multi-language support (English, French, Italian, Russian)</li>
<li>:bangbang: lots more...</li>
</ul>

### <a name=license></a>License, Credit  

- Available under the [GNU license](https://github.com/prasathmani/tinyfilemanager/blob/master/LICENSE)
- Original concept and development by github.com/alexantr/filemanager
- CDN Used - jQuery, Bootstrap, Font Awesome, Highlight js, ace js, DropZone js, DataTable js
- To report a bug or request a feature, please file an [issue](https://github.com/prasathmani/tinyfilemanager/issues)
- We hope our tools will be helpful for you. If you find Tiny File Manager useful for your personal or commercial projects, Help me out for a couple of 
[![Beerpay](https://beerpay.io/prasathmani/tinyfilemanager/badge.svg?style=flat-square)](https://beerpay.io/prasathmani/tinyfilemanager)



