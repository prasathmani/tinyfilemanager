<?php
/**
 * TinyFileManager - Directory Listing Service
 * Incremental extraction for path/parent/listing context used by the UI.
 */

class TFM_DirectoryListingService {
    private $root_path;
    private $current_path;

    public function __construct($root_path, $current_path = '') {
        $this->root_path = rtrim((string) $root_path, '/\\');
        $this->current_path = (string) $current_path;
    }

    /**
     * Build listing context equivalent to legacy monolith variables.
     * @return array
     */
    public function buildContext() {
        $path = $this->root_path;
        if ($this->current_path != '') {
            $path .= '/' . $this->current_path;
        }

        if (!is_dir($path)) {
            fm_redirect(FM_SELF_URL . '?p=');
        }

        $parent = fm_get_parent_path($this->current_path);
        if ($parent !== false) {
            $parent_path = $this->root_path . ($parent !== '' ? '/' . $parent : '');
            if (!fm_user_can_access_path($parent_path, true)) {
                $parent = false;
            }
        }

        $objects = is_readable($path) ? scandir($path) : array();
        $folders = array();
        $files = array();
        $current_dir_name = array_slice(explode('/', $path), -1)[0];

        if (is_array($objects) && fm_is_exclude_items($current_dir_name, $path)) {
            foreach ($objects as $file) {
                if ($file == '.' || $file == '..') {
                    continue;
                }
                if (!FM_SHOW_HIDDEN && substr($file, 0, 1) === '.') {
                    continue;
                }
                $new_path = $path . '/' . $file;
                if (@is_file($new_path) && fm_is_exclude_items($file, $new_path) && fm_user_can_access_path($new_path, false)) {
                    $files[] = $file;
                } elseif (@is_dir($new_path) && $file != '.' && $file != '..' && fm_is_exclude_items($file, $new_path) && fm_user_can_access_path($new_path, true)) {
                    $folders[] = $file;
                }
            }
        }

        if (!empty($files)) {
            natcasesort($files);
        }
        if (!empty($folders)) {
            natcasesort($folders);
        }

        return array(
            'path' => $path,
            'parent' => $parent,
            'objects' => $objects,
            'folders' => $folders,
            'files' => $files,
            'current_path' => $current_dir_name,
        );
    }
}