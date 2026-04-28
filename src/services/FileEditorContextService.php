<?php
/**
 * TinyFileManager - File Editor Context Service
 * Incremental extraction for file editor validation/save/context assembly.
 */

class TFM_FileEditorContextService {
    private $root_path;
    private $current_path;

    public function __construct($root_path, $current_path = '') {
        $this->root_path = rtrim((string) $root_path, '/\\');
        $this->current_path = (string) $current_path;
    }

    /**
     * Build validated editor context.
     * @param string $file_param
     * @param array $get
     * @param array $post
     * @return array
     */
    public function build($file_param, $get, $post) {
        $path = $this->root_path;
        if ($this->current_path != '') {
            $path .= '/' . $this->current_path;
        }

        $file = fm_clean_path($file_param, false);
        $file = str_replace('/', '', $file);
        if ($file == '' || !is_file($path . '/' . $file) || !fm_is_exclude_items($file, $path . '/' . $file)) {
            fm_set_msg(lng('File not found'), 'error');
            fm_redirect(FM_SELF_URL . '?p=' . urlencode($this->current_path));
        }

        $file_url = fm_build_public_file_url($this->current_path, $file);
        $file_path = $path . '/' . $file;
        $editFile = ' : <i><b>' . $file . '</b></i>';

        $isNormalEditor = true;
        if (isset($get['env']) && $get['env'] == 'ace') {
            $isNormalEditor = false;
        }

        if (isset($post['savedata'])) {
            $writedata = $post['savedata'];
            $fd = fopen($file_path, 'w');
            @fwrite($fd, $writedata);
            fclose($fd);
            fm_set_msg(lng('File Saved Successfully'));
        }

        $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
        $mime_type = fm_get_mime_type($file_path);
        $filesize = filesize($file_path);
        $is_text = false;
        $content = '';

        if (in_array($ext, fm_get_text_exts()) || substr($mime_type, 0, 4) == 'text' || in_array($mime_type, fm_get_text_mimes())) {
            $is_text = true;
            $content = file_get_contents($file_path);
        }

        return array(
            'file' => $file,
            'editFile' => $editFile,
            'file_url' => $file_url,
            'file_path' => $file_path,
            'isNormalEditor' => $isNormalEditor,
            'ext' => $ext,
            'mime_type' => $mime_type,
            'filesize' => $filesize,
            'is_text' => $is_text,
            'content' => $content,
        );
    }
}