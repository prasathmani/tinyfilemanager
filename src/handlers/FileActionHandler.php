<?php
/**
 * TinyFileManager - File Action Handler
 * Incremental extraction for delete + rename actions.
 */

class TFM_FileActionHandler {
    private $root_path;
    private $current_path;

    public function __construct($root_path, $current_path = '') {
        $this->root_path = rtrim((string) $root_path, '/\\');
        $this->current_path = (string) $current_path;
    }

    /**
     * Handle single file/folder delete request.
     * Preserves legacy behavior and redirects back.
     * @param array $get
     * @param array $post
     * @return void
     */
    public function handleDelete($get, $post) {
        $del = str_replace('/', '', fm_clean_path($get['del']));

        if ($del != '' && $del != '..' && $del != '.' && verifyToken($post['token'])) {
            $path = $this->basePath();
            $is_dir = is_dir($path . '/' . $del);

            // Audit log delete attempt
            if (class_exists('AuditLogger')) {
                $audit = new AuditLogger();
                $username = isset($_SESSION[FM_SESSION_ID]['logged']) ? $_SESSION[FM_SESSION_ID]['logged'] : 'unknown';
                $audit->log('file_delete_attempt', $username, ($is_dir ? 'DIR: ' : 'FILE: ') . $del);
            }

            if (fm_rdelete($path . '/' . $del)) {
                $msg = $is_dir ? lng('Folder') . ' <b>%s</b> ' . lng('Deleted') : lng('File') . ' <b>%s</b> ' . lng('Deleted');
                fm_set_msg(sprintf($msg, fm_enc($del)));
            } else {
                $msg = $is_dir ? lng('Folder') . ' <b>%s</b> ' . lng('not deleted') : lng('File') . ' <b>%s</b> ' . lng('not deleted');
                fm_set_msg(sprintf($msg, fm_enc($del)), 'error');
            }
        } else {
            fm_set_msg(lng('Invalid file or folder name'), 'error');
        }

        fm_redirect(FM_SELF_URL . '?p=' . urlencode($this->current_path));
    }

    /**
     * Handle file rename request.
     * Preserves legacy behavior and redirects back.
     * @param array $post
     * @return void
     */
    public function handleRename($post) {
        if (!verifyToken($post['token'])) {
            fm_set_msg('Invalid Token.', 'error');
            die('Invalid Token.');
        }

        // old name
        $old = urldecode($post['rename_from']);
        $old = fm_clean_path($old);
        $old = str_replace('/', '', $old);

        // new name
        $new = urldecode($post['rename_to']);
        $new = fm_clean_path(strip_tags($new));
        $new = str_replace('/', '', $new);

        // path
        $path = $this->basePath();

        // rename
        if (fm_isvalid_filename($new) && $old != '' && $new != '') {
            if (fm_rename($path . '/' . $old, $path . '/' . $new)) {
                fm_set_msg(sprintf(lng('Renamed from') . ' <b>%s</b> ' . lng('to') . ' <b>%s</b>', fm_enc($old), fm_enc($new)));
            } else {
                fm_set_msg(sprintf(lng('Error while renaming from') . ' <b>%s</b> ' . lng('to') . ' <b>%s</b>', fm_enc($old), fm_enc($new)), 'error');
            }
        } else {
            fm_set_msg(lng('Invalid characters in file name'), 'error');
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
