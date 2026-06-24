<?php
/**
 * TinyFileManager - Chmod Page Context Service
 * Incremental extraction for chmod page validation and context assembly.
 */

class TFM_ChmodPageContextService {
    private $root_path;
    private $current_path;

    public function __construct($root_path, $current_path = '') {
        $this->root_path = rtrim((string) $root_path, '/\\');
        $this->current_path = (string) $current_path;
    }

    /**
     * Build validated chmod page context.
     * @param string $file_param
     * @return array
     */
    public function build($file_param) {
        $path = $this->root_path;
        if ($this->current_path != '') {
            $path .= '/' . $this->current_path;
        }

        $file = fm_clean_path($file_param);
        $file = str_replace('/', '', $file);
        if ($file == '' || (!is_file($path . '/' . $file) && !is_dir($path . '/' . $file))) {
            fm_set_msg(lng('File not found'), 'error');
            fm_redirect(FM_SELF_URL . '?p=' . urlencode($this->current_path));
        }

        $file_url = fm_build_public_file_url($this->current_path, $file);
        $file_path = $path . '/' . $file;
        $mode = fileperms($path . '/' . $file);

        return array(
            'file' => $file,
            'file_url' => $file_url,
            'file_path' => $file_path,
            'mode' => $mode,
        );
    }
}