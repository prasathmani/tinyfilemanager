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
 * Get navigation home root relative to FM_ROOT_PATH.
 * For admin it is always FM_ROOT_PATH itself (empty relative path).
 * For regular users it prefers configured shared home root and falls back
 * to the legacy first allowed directory behavior.
 *
 * @return string
 */
function fm_get_navigation_home_root()
{
    if (defined('FM_IS_ADMIN') && FM_IS_ADMIN) {
        return '';
    }

    $configured_home = '';
    if (defined('FM_USER_HOME_ROOT')) {
        $configured_home = fm_clean_path((string) FM_USER_HOME_ROOT);
    }

    if ($configured_home !== '') {
        return $configured_home;
    }

    return fm_get_user_default_path();
}

/**
 * Check whether an absolute path is within the navigation home boundary.
 *
 * @param string $absolute_path
 * @return bool
 */
function fm_is_within_navigation_home($absolute_path)
{
    $absolute_path = rtrim(str_replace('\\', '/', (string) $absolute_path), '/');
    if ($absolute_path === '') {
        return false;
    }

    $home_relative = fm_get_navigation_home_root();
    if ($home_relative === '') {
        return true;
    }

    $root_path = rtrim(str_replace('\\', '/', (string) FM_ROOT_PATH), '/');
    if ($root_path === '') {
        return false;
    }

    $home_absolute = $root_path . '/' . ltrim($home_relative, '/');
    return fm_is_path_inside($absolute_path, $home_absolute);
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

/**
 * Build breadcrumb segments for navigation.
 * Returns array of segments with labels and paths for breadcrumb display.
 * The first segment is always "Home" (user's root), followed by parent path segments.
 * Returns empty array if user is at their root directory.
 *
 * @param string $current_path Relative path from root
 * @return array Array of breadcrumb segments with 'label', 'path', 'is_root' keys
 */
function fm_build_breadcrumb_segments($current_path)
{
    $current_path = fm_clean_path($current_path);
    $home_path = fm_get_navigation_home_root();

    if ($current_path === '' || $current_path === $home_path) {
        return array();
    }

    if ($home_path !== '' && strpos($current_path . '/', $home_path . '/') !== 0) {
        return array();
    }

    $relative_to_home = $home_path === ''
        ? $current_path
        : ltrim(substr($current_path, strlen($home_path)), '/');
    if ($relative_to_home === '') {
        return array();
    }

    $breadcrumbs = array();

    $breadcrumbs[] = array(
        'label' => lng('Home'),
        'path' => $home_path,
        'is_root' => true,
    );

    $segments = array_filter(explode('/', $relative_to_home), 'strlen');
    if (empty($segments)) {
        return $breadcrumbs;
    }

    $path_so_far = $home_path;
    $segment_count = count($segments);

    for ($i = 0; $i < $segment_count - 1; $i++) {
        $segment = $segments[$i];
        $path_so_far = trim($path_so_far . '/' . $segment, '/');

        $absolute_path = FM_ROOT_PATH . (FM_ROOT_PATH !== '' && $path_so_far !== '' ? '/' . $path_so_far : '');
        if (!fm_user_can_access_path($absolute_path, false)) {
            continue;
        }

        $breadcrumbs[] = array(
            'label' => fm_enc($segment),
            'path' => $path_so_far,
            'is_root' => false,
        );
    }

    return $breadcrumbs;
}