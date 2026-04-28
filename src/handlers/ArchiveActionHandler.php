<?php
/**
 * TinyFileManager - Archive Action Handler
 * Incremental extraction for archive pack + unpack actions.
 */

class TFM_ArchiveActionHandler {
    private $root_path;
    private $current_path;

    public function __construct($root_path, $current_path = '') {
        $this->root_path = rtrim((string) $root_path, '/\\');
        $this->current_path = (string) $current_path;
    }

    /**
     * Handle zip/tar archive creation.
     * Preserves legacy behavior and redirects back.
     * @param array $post
     * @return void
     */
    public function handlePack($post) {
        if (!verifyToken($post['token'])) {
            fm_set_msg(lng('Invalid Token.'), 'error');
            die('Invalid Token.');
        }

        $path = $this->basePath();
        $ext = isset($post['tar']) ? 'tar' : 'zip';

        if (($ext == 'zip' && !class_exists('ZipArchive')) || ($ext == 'tar' && !class_exists('PharData'))) {
            fm_set_msg(lng('Operations with archives are not available'), 'error');
            fm_redirect(FM_SELF_URL . '?p=' . urlencode($this->current_path));
        }

        $files = $post['file'];
        $sanitized_files = array();

        foreach ($files as $file) {
            array_push($sanitized_files, fm_clean_path($file));
        }

        $files = $sanitized_files;

        if (!empty($files)) {
            chdir($path);

            if (count($files) == 1) {
                $one_file = reset($files);
                $one_file = basename($one_file);
                $zipname = $one_file . '_' . date('ymd_His') . '.' . $ext;
            } else {
                $zipname = 'archive_' . date('ymd_His') . '.' . $ext;
            }

            if ($ext == 'zip') {
                $zipper = new FM_Zipper();
                $res = $zipper->create($zipname, $files);
            } elseif ($ext == 'tar') {
                $tar = new FM_Zipper_Tar();
                $res = $tar->create($zipname, $files);
            }

            if ($res) {
                fm_set_msg(sprintf(lng('Archive') . ' <b>%s</b> ' . lng('Created'), fm_enc($zipname)));
            } else {
                fm_set_msg(lng('Archive not created'), 'error');
            }
        } else {
            fm_set_msg(lng('Nothing selected'), 'alert');
        }

        fm_redirect(FM_SELF_URL . '?p=' . urlencode($this->current_path));
    }

    /**
     * Handle zip/tar archive unpack request.
     * Preserves legacy behavior and redirects back.
     * @param array $post
     * @return void
     */
    public function handleUnpack($post) {
        if (!verifyToken($post['token'])) {
            fm_set_msg(lng('Invalid Token.'), 'error');
            die('Invalid Token.');
        }

        $unzip = urldecode($post['unzip']);
        $unzip = fm_clean_path($unzip);
        $unzip = str_replace('/', '', $unzip);
        $isValid = false;
        $ext = '';

        $path = $this->basePath();

        if ($unzip != '' && is_file($path . '/' . $unzip)) {
            $zip_path = $path . '/' . $unzip;
            $ext = pathinfo($zip_path, PATHINFO_EXTENSION);
            $isValid = true;
        } else {
            fm_set_msg(lng('File not found'), 'error');
        }

        if (($ext == 'zip' && !class_exists('ZipArchive')) || ($ext == 'tar' && !class_exists('PharData'))) {
            fm_set_msg(lng('Operations with archives are not available'), 'error');
            fm_redirect(FM_SELF_URL . '?p=' . urlencode($this->current_path));
        }

        if ($isValid) {
            if (isset($post['tofolder'])) {
                $tofolder = pathinfo($zip_path, PATHINFO_FILENAME);
                if (fm_mkdir($path . '/' . $tofolder, true)) {
                    $path .= '/' . $tofolder;
                }
            }

            if ($ext == 'zip') {
                $zipper = new FM_Zipper();
                $res = $zipper->unzip($zip_path, $path);
            } elseif ($ext == 'tar') {
                try {
                    $gzipper = new PharData($zip_path);
                    if (@$gzipper->extractTo($path, null, true)) {
                        $res = true;
                    } else {
                        $res = false;
                    }
                } catch (Exception $e) {
                    $res = true;
                }
            }

            if ($res) {
                fm_set_msg(lng('Archive unpacked'));
            } else {
                fm_set_msg(lng('Archive not unpacked'), 'error');
            }
        } else {
            fm_set_msg(lng('File not found'), 'error');
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