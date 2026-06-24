<?php
/**
 * TinyFileManager - Download & Preview Handler
 * First extraction step from legacy monolith: keeps behavior intact.
 */

class TFM_DownloadPreviewHandler {
    private $root_path;
    private $current_path;

    public function __construct($root_path, $current_path = '') {
        $this->root_path = rtrim((string) $root_path, '/\\');
        $this->current_path = (string) $current_path;
    }

    /**
     * Handle download request.
     * @param array $get
     * @param array $post
     * @return bool
     */
    public function handleDownload($get, $post) {
        if (!isset($get['dl'], $post['token'])) {
            return false;
        }

        if (!verifyToken($post['token'])) {
            fm_set_msg('Invalid Token.', 'error');
            return true;
        }

        // Keep literal '+' in filenames; urldecode() would turn it into a space.
        $dl = rawurldecode((string) $get['dl']);
        $dl = fm_clean_path($dl);
        $dl = str_replace('/', '', $dl);

        $path = $this->basePath();
        if ($dl !== '' && is_file($path . '/' . $dl)) {
            if (session_status() === PHP_SESSION_ACTIVE) {
                session_write_close();
            }

            fm_download_file($path . '/' . $dl, $dl, 1024);
            return true;
        }

        fm_set_msg(lng('File not found'), 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode($this->current_path));
        return true;
    }

    /**
     * Handle inline preview request.
     * @param array $get
     * @return bool
     */
    public function handlePreview($get) {
        if (!isset($get['preview'])) {
            return false;
        }

        // Keep literal '+' in filenames; urldecode() would turn it into a space.
        $pv = rawurldecode((string) $get['preview']);
        $pv = fm_clean_path($pv);
        $pv = str_replace('/', '', $pv);

        $path = $this->basePath();
        $file_path = $path . '/' . $pv;

        if ($pv === '' || !is_file($file_path) || !fm_is_exclude_items($pv, $file_path)) {
            header('HTTP/1.1 404 Not Found');
            return true;
        }

        $content_type = fm_get_mime_type($file_path);
        $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
        $allowed_preview_exts = array_unique(array_merge(
            fm_get_image_exts(),
            fm_get_audio_exts(),
            fm_get_video_exts(),
            fm_get_onlineViewer_exts(),
            array('pdf')
        ));
        $is_image_mime = fm_is_image_mime_type($content_type);

        if (!in_array($ext, $allowed_preview_exts, true) && !$is_image_mime) {
            header('HTTP/1.1 403 Forbidden');
            return true;
        }

        if (!$content_type || $content_type === '--') {
            $fallback = array(
                'pdf' => 'application/pdf',
                'jpg' => 'image/jpeg',
                'jpeg' => 'image/jpeg',
                'png' => 'image/png',
                'gif' => 'image/gif',
                'svg' => 'image/svg+xml',
                'webp' => 'image/webp',
                'avif' => 'image/avif',
                'bmp' => 'image/bmp',
                'mp4' => 'video/mp4',
                'webm' => 'video/webm',
                'ogg' => 'video/ogg',
                'mov' => 'video/quicktime',
                'm4v' => 'video/x-m4v',
                'doc' => 'application/msword',
                'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'xls' => 'application/vnd.ms-excel',
                'xlsx' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                'ppt' => 'application/vnd.ms-powerpoint',
                'pptx' => 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
                'odt' => 'application/vnd.oasis.opendocument.text',
                'ods' => 'application/vnd.oasis.opendocument.spreadsheet',
                'xps' => 'application/oxps',
            );

            $content_type = isset($fallback[$ext]) ? $fallback[$ext] : 'application/octet-stream';
        }

        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }

        header('Content-Type: ' . $content_type);
        header('Content-Length: ' . filesize($file_path));
        header('Content-Disposition: inline; filename="' . basename($file_path) . '"');
        header('Cache-Control: private, max-age=300');
        readfile($file_path);

        return true;
    }

    private function basePath() {
        $path = $this->root_path;
        if ($this->current_path !== '') {
            $path .= '/' . $this->current_path;
        }
        return $path;
    }
}
