<?php

/**
 * Write unexpected runtime error details to local errors.log file.
 *
 * @param string $message
 * @return void
 */
function fm_log_error($message)
{
    $date = date('Y-m-d H:i:s');
    $user = isset($_SESSION[FM_SESSION_ID]['logged']) ? $_SESSION[FM_SESSION_ID]['logged'] : 'guest';
    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
    $log_line = '[' . $date . '] [' . $ip . '] [' . $user . '] ' . $message . PHP_EOL;
    @file_put_contents(__DIR__ . '/../errors.log', $log_line, FILE_APPEND | LOCK_EX);
}

/**
 * Redirect user to login page on unexpected runtime failures.
 *
 * @return void
 */
function fm_redirect_to_login_on_error()
{
    if (PHP_SAPI === 'cli') {
        exit(1);
    }

    if (session_status() === PHP_SESSION_ACTIVE) {
        unset($_SESSION[FM_SESSION_ID]['logged']);
        $_SESSION['status'] = array(
            'type' => 'error',
            'text' => 'Unexpected server error. Please login again.'
        );
    }

    $target = defined('FM_SELF_URL') ? FM_SELF_URL : (isset($_SERVER['PHP_SELF']) ? $_SERVER['PHP_SELF'] : '/');
    if (!headers_sent()) {
        header('Location: ' . $target, true, 302);
        exit;
    }

    echo '<script>window.location.href=' . json_encode($target) . ';</script>';
    exit;
}

/**
 * Handler for uncaught exceptions.
 *
 * @param Throwable|Exception $exception
 * @return void
 */
function fm_unexpected_exception_handler($exception)
{
    fm_log_error('TinyFileManager unexpected exception: ' . $exception->getMessage());
    error_log('TinyFileManager unexpected exception: ' . $exception->getMessage());
    fm_redirect_to_login_on_error();
}

/**
 * Handler for fatal runtime errors.
 *
 * @return void
 */
function fm_unexpected_shutdown_handler()
{
    $error = error_get_last();
    if (!$error) {
        return;
    }

    $fatal_error_types = array(E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR);
    if (in_array($error['type'], $fatal_error_types, true)) {
        fm_log_error('TinyFileManager fatal error: ' . $error['message'] . ' in ' . $error['file'] . ':' . $error['line']);
        error_log('TinyFileManager fatal error: ' . $error['message'] . ' in ' . $error['file'] . ':' . $error['line']);
        if (ob_get_length()) {
            @ob_clean();
        }
        fm_redirect_to_login_on_error();
    }
}