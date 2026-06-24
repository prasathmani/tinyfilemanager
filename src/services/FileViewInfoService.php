<?php
/**
 * TinyFileManager - File View Info Service
 * Incremental extraction for viewer metadata and type detection.
 */

class TFM_FileViewInfoService {
    /**
     * Build file-view metadata and content/type flags.
     * @param string $file_path
     * @return array
     */
    public function build($file_path) {
        $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
        $mime_type = fm_get_mime_type($file_path);
        $is_image_mime = fm_is_image_mime_type($mime_type);
        $filesize_raw = fm_get_size($file_path);
        $filesize = fm_get_filesize($filesize_raw);

        $is_zip = false;
        $is_gzip = false;
        $is_image = false;
        $is_audio = false;
        $is_video = false;
        $is_pdf = false;
        $is_text = false;
        $is_onlineViewer = false;

        $view_title = 'File';
        $filenames = false;
        $content = '';
        $online_viewer = strtolower(FM_DOC_VIEWER);

        if ($ext === 'pdf') {
            $is_pdf = true;
            $view_title = 'PDF';
        } elseif ($online_viewer && $online_viewer !== 'false' && in_array($ext, fm_get_onlineViewer_exts())) {
            $is_onlineViewer = true;
        } elseif ($ext == 'zip' || $ext == 'tar') {
            $is_zip = true;
            $view_title = 'Archive';
            $filenames = fm_get_zif_info($file_path, $ext);
        } elseif (in_array($ext, fm_get_image_exts()) || $is_image_mime) {
            $is_image = true;
            $view_title = 'Image';
        } elseif (in_array($ext, fm_get_audio_exts())) {
            $is_audio = true;
            $view_title = 'Audio';
        } elseif (in_array($ext, fm_get_video_exts())) {
            $is_video = true;
            $view_title = 'Video';
        } elseif (in_array($ext, fm_get_text_exts()) || substr($mime_type, 0, 4) == 'text' || in_array($mime_type, fm_get_text_mimes())) {
            $is_text = true;
            $content = file_get_contents($file_path);
        }

        return array(
            'ext' => $ext,
            'mime_type' => $mime_type,
            'is_image_mime' => $is_image_mime,
            'filesize_raw' => $filesize_raw,
            'filesize' => $filesize,
            'is_zip' => $is_zip,
            'is_gzip' => $is_gzip,
            'is_image' => $is_image,
            'is_audio' => $is_audio,
            'is_video' => $is_video,
            'is_pdf' => $is_pdf,
            'is_text' => $is_text,
            'is_onlineViewer' => $is_onlineViewer,
            'view_title' => $view_title,
            'filenames' => $filenames,
            'content' => $content,
        );
    }
}