<?php

/*
 * Central request gate for state-changing Tiny File Manager routes.
 *
 * The route classifier deliberately keys only on fields that reach a
 * state-changing handler. Navigation-only GET parameters such as `copy` and
 * `chmod` are not mutations by themselves.
 */

function fm_mutation_route($get, $post, $files)
{
    $get = is_array($get) ? $get : array();
    $post = is_array($post) ? $post : array();
    $files = is_array($files) ? $files : array();

    if (isset($post['fm_usr'], $post['fm_pwd'])) {
        return 'login';
    }
    if (isset($post['logout']) || isset($get['logout'])) {
        return 'logout';
    }

    if (isset($post['ajax'], $post['type'])) {
        if ($post['type'] === 'save') {
            return 'ajax-save';
        }
        if ($post['type'] === 'backup') {
            return 'ajax-backup';
        }
        if ($post['type'] === 'settings') {
            return 'settings-save';
        }
    }
    if (isset($post['savedata'])) {
        return 'editor-form-save';
    }

    if (isset($get['del'])) {
        return 'delete';
    }
    if (isset($post['newfilename'], $post['newfile'])) {
        return 'create';
    }
    if (isset($post['copy'], $post['finish'])) {
        return 'single-copy-move';
    }
    if (isset($post['file'], $post['copy_to'], $post['finish'])) {
        return 'bulk-copy-move';
    }
    if (isset($post['rename_from'], $post['rename_to'])) {
        return 'rename';
    }
    if (!empty($files)) {
        return 'upload';
    }
    if (isset($post['group'], $post['delete'])) {
        return 'bulk-delete';
    }
    if (isset($post['group'])
        && (isset($post['zip']) || isset($post['tar']))) {
        return 'archive-create';
    }
    if (isset($post['unzip'])) {
        return 'archive-extract';
    }
    if (isset($post['chmod'])) {
        return 'permissions';
    }

    return null;
}

function fm_mutation_origin_is_valid($origin)
{
    if (!is_string($origin) || $origin === '' || trim($origin) !== $origin
        || preg_match('/[\x00-\x20\x7f]/', $origin)) {
        return false;
    }

    $parts = parse_url($origin);
    if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])
        || $parts['scheme'] !== 'https' || $parts['host'] === '') {
        return false;
    }
    foreach (array('user', 'pass', 'path', 'query', 'fragment') as $forbidden) {
        if (isset($parts[$forbidden])) {
            return false;
        }
    }
    if (isset($parts['port'])
        && (!is_int($parts['port']) || $parts['port'] < 1
            || $parts['port'] > 65535)) {
        return false;
    }

    $canonical = 'https://' . $parts['host'];
    if (isset($parts['port'])) {
        $canonical .= ':' . $parts['port'];
    }
    return hash_equals($canonical, $origin);
}

function fm_mutation_gate_evaluate($server, $get, $post, $files, $session,
    $required, $requiredOrigin)
{
    if (!is_bool($required)
        || ($required && (!is_string($requiredOrigin)
            || !fm_mutation_origin_is_valid($requiredOrigin)))) {
        return array(
            'allowed' => false,
            'status' => 503,
            'reason' => 'configuration',
            'route' => null,
        );
    }

    $route = fm_mutation_route($get, $post, $files);
    $server = is_array($server) ? $server : array();
    $method = isset($server['REQUEST_METHOD']) && is_string($server['REQUEST_METHOD'])
        ? $server['REQUEST_METHOD'] : '';
    if (!$required || ($route === null && $method !== 'POST')) {
        return array(
            'allowed' => true,
            'status' => 0,
            'reason' => '',
            'route' => $route,
        );
    }

    $post = is_array($post) ? $post : array();
    $session = is_array($session) ? $session : array();
    if ($method !== 'POST') {
        return array(
            'allowed' => false,
            'status' => 405,
            'reason' => 'method',
            'route' => $route,
        );
    }

    $actualOrigin = isset($server['HTTP_ORIGIN'])
        && is_string($server['HTTP_ORIGIN']) ? $server['HTTP_ORIGIN'] : '';
    if (!hash_equals($requiredOrigin, $actualOrigin)) {
        return array(
            'allowed' => false,
            'status' => 403,
            'reason' => 'origin',
            'route' => $route,
        );
    }

    $expectedToken = isset($session['token']) && is_string($session['token'])
        ? $session['token'] : '';
    $providedToken = isset($post['token']) && is_string($post['token'])
        ? $post['token'] : '';
    if ($expectedToken === '' || $providedToken === ''
        || !hash_equals($expectedToken, $providedToken)) {
        return array(
            'allowed' => false,
            'status' => 403,
            'reason' => 'csrf',
            'route' => $route,
        );
    }

    return array(
        'allowed' => true,
        'status' => 0,
        'reason' => '',
        'route' => $route,
    );
}

function fm_enforce_mutation_request($server, $get, $post, $files, $session,
    $required, $requiredOrigin)
{
    $decision = fm_mutation_gate_evaluate(
        $server, $get, $post, $files, $session, $required, $requiredOrigin);
    if ($decision['allowed']) {
        return;
    }

    if (!headers_sent()) {
        http_response_code($decision['status']);
        header('Cache-Control: no-store, max-age=0');
        header('Content-Type: text/plain; charset=UTF-8');
        header('X-Content-Type-Options: nosniff');
        if ($decision['status'] === 405) {
            header('Allow: POST');
        }
    }

    if ($decision['status'] === 503) {
        echo "The mutation-request policy is unavailable.\n";
    } else {
        echo "The mutation request was rejected.\n";
    }
    exit;
}
