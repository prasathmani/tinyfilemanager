<?php

/**
 * Check if $path is equal to or inside $base path.
 *
 * @param string $path
 * @param string $base
 * @return bool
 */
function fm_is_path_inside($path, $base)
{
    $path = rtrim(str_replace('\\', '/', (string) $path), '/');
    $base = rtrim(str_replace('\\', '/', (string) $base), '/');
    if ($path === '' || $base === '') {
        return false;
    }
    return $path === $base || strpos($path, $base . '/') === 0;
}

/**
 * Check whether the current user can access a path.
 * If $allow_parent is true, parent folders of allowed directories are also valid.
 *
 * @param string $path
 * @param bool $allow_parent
 * @return bool
 */
function fm_user_can_access_path($path, $allow_parent = false)
{
    global $fm_user_allowed_dirs;

    if (empty($fm_user_allowed_dirs) || !is_array($fm_user_allowed_dirs)) {
        return true;
    }

    $path = rtrim(str_replace('\\', '/', (string) $path), '/');
    if ($path === '') {
        return false;
    }

    foreach ($fm_user_allowed_dirs as $allowed_path) {
        $allowed_path = rtrim(str_replace('\\', '/', (string) $allowed_path), '/');
        if ($allowed_path === '') {
            continue;
        }

        if (fm_is_path_inside($path, $allowed_path)) {
            return true;
        }
        if ($allow_parent && fm_is_path_inside($allowed_path, $path)) {
            return true;
        }
    }

    return false;
}

/**
 * Get first accessible relative path from assigned user directories.
 *
 * @return string
 */
function fm_get_user_default_path()
{
    global $fm_user_allowed_dirs;

    if (empty($fm_user_allowed_dirs) || !is_array($fm_user_allowed_dirs)) {
        return '';
    }

    foreach ($fm_user_allowed_dirs as $allowed_path) {
        $allowed_path = rtrim(str_replace('\\', '/', (string) $allowed_path), '/');
        $root_path = rtrim(str_replace('\\', '/', FM_ROOT_PATH), '/');
        if (fm_is_path_inside($allowed_path, $root_path)) {
            $relative_path = ltrim(substr($allowed_path, strlen($root_path)), '/');
            return fm_clean_path($relative_path);
        }
    }

    return '';
}

/**
 * Path traversal prevention and clean the URL.
 * It replaces occurrences of / and \\ with DIRECTORY_SEPARATOR and resolves . and .. segments.
 *
 * @param string $path
 * @return string
 */
function get_absolute_path($path)
{
    $path = str_replace(array('/', '\\'), DIRECTORY_SEPARATOR, $path);
    $parts = array_filter(explode(DIRECTORY_SEPARATOR, $path), 'strlen');
    $absolutes = array();
    foreach ($parts as $part) {
        if ('.' == $part) {
            continue;
        }
        if ('..' == $part) {
            array_pop($absolutes);
        } else {
            $absolutes[] = $part;
        }
    }
    return implode(DIRECTORY_SEPARATOR, $absolutes);
}

/**
 * Clean path.
 *
 * @param string $path
 * @param bool $trim
 * @return string
 */
function fm_clean_path($path, $trim = true)
{
    $path = $trim ? trim($path) : $path;
    $path = trim($path, '\\/');
    $path = str_replace(array('../', '..\\'), '', $path);
    $path = get_absolute_path($path);
    if ($path == '..') {
        $path = '';
    }
    return str_replace('\\', '/', $path);
}

/**
 * Get parent path.
 *
 * @param string $path
 * @return bool|string
 */
function fm_get_parent_path($path)
{
    $path = fm_clean_path($path);
    if ($path != '') {
        $array = explode('/', $path);
        if (count($array) > 1) {
            $array = array_slice($array, 0, -1);
            return implode('/', $array);
        }
        return '';
    }
    return false;
}

/**
 * Build a user-facing display path label and value.
 *
 * @param string $file_path
 * @return array
 */
function fm_get_display_path($file_path)
{
    global $path_display_mode, $root_path, $root_url;
    switch ($path_display_mode) {
        case 'relative':
            return array(
                'label' => 'Path',
                'path' => fm_enc(fm_convert_win(str_replace($root_path, '', $file_path)))
            );
        case 'host':
            $relative_path = str_replace($root_path, '', $file_path);
            return array(
                'label' => 'Host Path',
                'path' => fm_enc(fm_convert_win('/' . $root_url . '/' . ltrim(str_replace('\\', '/', $relative_path), '/')))
            );
        case 'full':
        default:
            return array(
                'label' => 'Full Path',
                'path' => fm_enc(fm_convert_win($file_path))
            );
    }
}

/**
 * Build absolute public file URL with encoded path segments.
 *
 * @param string $path
 * @param string $file
 * @return string
 */
function fm_build_public_file_url($path, $file)
{
    $base = rtrim((string) FM_ROOT_URL, '/');
    $relative = trim((string) $path, '/');
    $file = (string) $file;

    $parts = array();
    if ($relative !== '') {
        foreach (explode('/', str_replace('\\', '/', $relative)) as $segment) {
            if ($segment !== '') {
                $parts[] = rawurlencode($segment);
            }
        }
    }

    if ($file !== '') {
        $parts[] = rawurlencode($file);
    }

    if (empty($parts)) {
        return $base;
    }

    return $base . '/' . implode('/', $parts);
}

/**
 * Check whether a file or folder should be included in listing.
 *
 * @param string $name
 * @param string $path
 * @return bool
 */
function fm_is_exclude_items($name, $path)
{
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    if (isset($exclude_items) and sizeof($exclude_items)) {
        unset($exclude_items);
    }

    $exclude_items = FM_EXCLUDE_ITEMS;
    if (version_compare(PHP_VERSION, '7.0.0', '<')) {
        $exclude_items = unserialize($exclude_items);
    }
    if (!in_array($name, $exclude_items) && !in_array('*.' . $ext, $exclude_items) && !in_array($path, $exclude_items)) {
        return true;
    }
    return false;
}