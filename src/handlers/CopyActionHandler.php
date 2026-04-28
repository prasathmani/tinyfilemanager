<?php
/**
 * TinyFileManager - Copy Action Handler
 * Incremental extraction for copy + mass copy actions.
 */

class TFM_CopyActionHandler {
    private $root_path;
    private $current_path;

    public function __construct($root_path, $current_path = '') {
        $this->root_path = rtrim((string) $root_path, '/\\');
        $this->current_path = (string) $current_path;
    }

    /**
     * Handle single copy/move/duplicate request.
     * Preserves legacy behavior and redirects back.
     * @param array $get
     * @return void
     */
    public function handleCopy($get) {
        $copy = urldecode($get['copy']);
        $copy = fm_clean_path($copy);

        if ($copy == '') {
            fm_set_msg(lng('Source path not defined'), 'error');
            fm_redirect(FM_SELF_URL . '?p=' . urlencode($this->current_path));
        }

        $from = $this->root_path . '/' . $copy;
        $dest = $this->basePath() . '/' . basename($from);

        $move = isset($get['move']);
        $move = fm_clean_path(urldecode($move));

        if ($from != $dest) {
            $msg_from = trim($this->current_path . '/' . basename($from), '/');
            if ($move) {
                $rename = fm_rename($from, $dest);
                if ($rename) {
                    fm_set_msg(sprintf(lng('Moved from') . ' <b>%s</b> ' . lng('to') . ' <b>%s</b>', fm_enc($copy), fm_enc($msg_from)));
                } elseif ($rename === null) {
                    fm_set_msg(lng('File or folder with this path already exists'), 'alert');
                } else {
                    fm_set_msg(sprintf(lng('Error while moving from') . ' <b>%s</b> ' . lng('to') . ' <b>%s</b>', fm_enc($copy), fm_enc($msg_from)), 'error');
                }
            } else {
                if (fm_rcopy($from, $dest)) {
                    fm_set_msg(sprintf(lng('Copied from') . ' <b>%s</b> ' . lng('to') . ' <b>%s</b>', fm_enc($copy), fm_enc($msg_from)));
                } else {
                    fm_set_msg(sprintf(lng('Error while copying from') . ' <b>%s</b> ' . lng('to') . ' <b>%s</b>', fm_enc($copy), fm_enc($msg_from)), 'error');
                }
            }
        } else {
            if (!$move) {
                $fn_parts = pathinfo($from);
                $extension_suffix = '';
                if (!is_dir($from)) {
                    $extension_suffix = '.' . $fn_parts['extension'];
                }

                $fn_duplicate = $fn_parts['dirname'] . '/' . $fn_parts['filename'] . '-' . date('YmdHis') . $extension_suffix;
                $loop_count = 0;
                $max_loop = 1000;

                while (file_exists($fn_duplicate) & $loop_count < $max_loop) {
                    $fn_parts = pathinfo($fn_duplicate);
                    $fn_duplicate = $fn_parts['dirname'] . '/' . $fn_parts['filename'] . '-copy' . $extension_suffix;
                    $loop_count++;
                }

                if (fm_rcopy($from, $fn_duplicate, false)) {
                    fm_set_msg(sprintf('Copied from <b>%s</b> to <b>%s</b>', fm_enc($copy), fm_enc($fn_duplicate)));
                } else {
                    fm_set_msg(sprintf('Error while copying from <b>%s</b> to <b>%s</b>', fm_enc($copy), fm_enc($fn_duplicate)), 'error');
                }
            } else {
                fm_set_msg(lng('Paths must be not equal'), 'alert');
            }
        }

        fm_redirect(FM_SELF_URL . '?p=' . urlencode($this->current_path));
    }

    /**
     * Handle mass copy/move request.
     * Preserves legacy behavior and redirects back.
     * @param array $post
     * @return void
     */
    public function handleMassCopy($post) {
        if (!verifyToken($post['token'])) {
            fm_set_msg(lng('Invalid Token.'), 'error');
            die('Invalid Token.');
        }

        $path = $this->basePath();

        $copy_to_path = $this->root_path;
        $copy_to = fm_clean_path($post['copy_to']);
        if ($copy_to != '') {
            $copy_to_path .= '/' . $copy_to;
        }

        if ($path == $copy_to_path) {
            fm_set_msg(lng('Paths must be not equal'), 'alert');
            fm_redirect(FM_SELF_URL . '?p=' . urlencode($this->current_path));
        }

        if (!is_dir($copy_to_path)) {
            if (!fm_mkdir($copy_to_path, true)) {
                fm_set_msg('Unable to create destination folder', 'error');
                fm_redirect(FM_SELF_URL . '?p=' . urlencode($this->current_path));
            }
        }

        $move = isset($post['move']);
        $errors = 0;
        $files = $post['file'];

        if (is_array($files) && count($files)) {
            foreach ($files as $f) {
                if ($f != '') {
                    $f = fm_clean_path($f);
                    $from = $path . '/' . $f;
                    $dest = $copy_to_path . '/' . $f;

                    if ($move) {
                        $rename = fm_rename($from, $dest);
                        if ($rename === false) {
                            $errors++;
                        }
                    } else {
                        if (!fm_rcopy($from, $dest)) {
                            $errors++;
                        }
                    }
                }
            }

            if ($errors == 0) {
                $msg = $move ? 'Selected files and folders moved' : 'Selected files and folders copied';
                fm_set_msg($msg);
            } else {
                $msg = $move ? 'Error while moving items' : 'Error while copying items';
                fm_set_msg($msg, 'error');
            }
        } else {
            fm_set_msg(lng('Nothing selected'), 'alert');
        }

        fm_redirect(FM_SELF_URL . '?p=' . urlencode($this->current_path));
    }

    private function basePath() {
        $path = $this->root_path;
        if ($this->current_path !== '') {
            $path .= '/' . $this->current_path;
        }
        return $path;
    }
}