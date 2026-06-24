<?php

/**
 * Recover from session start warnings by rotating the session id.
 *
 * @param int $code
 * @param string $msg
 * @param string $file
 * @param int $line
 * @return void
 */
function session_error_handling_function($code, $msg, $file, $line)
{
    if ($code == 2) {
        session_abort();
        session_id(session_create_id());
        @session_start();
    }
}

/**
 * Resolve the best client IP from proxy and direct headers.
 *
 * @return string
 */
function getClientIP()
{
    if (array_key_exists('HTTP_CF_CONNECTING_IP', $_SERVER)) {
        return $_SERVER['HTTP_CF_CONNECTING_IP'];
    }
    if (array_key_exists('HTTP_X_FORWARDED_FOR', $_SERVER)) {
        return $_SERVER['HTTP_X_FORWARDED_FOR'];
    }
    if (array_key_exists('REMOTE_ADDR', $_SERVER)) {
        return $_SERVER['REMOTE_ADDR'];
    }
    if (array_key_exists('HTTP_CLIENT_IP', $_SERVER)) {
        return $_SERVER['HTTP_CLIENT_IP'];
    }

    return '';
}