#!/usr/bin/env php
<?php

require_once dirname(__DIR__) . '/lib/fm_mutation_guard.php';

$checks = 0;

function mutation_check($condition, $message)
{
    global $checks;
    $checks++;
    if (!$condition) {
        fwrite(STDERR, "not ok $checks - $message\n");
        exit(1);
    }
    echo "ok $checks - $message\n";
}

function mutation_decision($method, $origin, $get, $post, $files, $token,
    $requiredOrigin)
{
    $server = array('REQUEST_METHOD' => $method);
    if ($origin !== null) {
        $server['HTTP_ORIGIN'] = $origin;
    }
    return fm_mutation_gate_evaluate(
        $server,
        $get,
        $post,
        $files,
        array('token' => $token),
        true,
        $requiredOrigin
    );
}

$token = str_repeat('a', 64);
$wrongToken = str_repeat('b', 64);
$origin = 'https://afs-auth.example.test:8444';

$routes = array(
    'login' => array(array(), array('fm_usr' => 'user', 'fm_pwd' => 'secret'), array()),
    'logout' => array(array(), array('logout' => '1'), array()),
    'ajax-save' => array(array(), array('ajax' => true, 'type' => 'save'), array()),
    'ajax-backup' => array(array(), array('ajax' => true, 'type' => 'backup'), array()),
    'settings-save' => array(array(), array('ajax' => true, 'type' => 'settings'), array()),
    'editor-form-save' => array(array(), array('savedata' => 'content'), array()),
    'delete' => array(array('del' => 'file.txt'), array(), array()),
    'create' => array(array(), array('newfilename' => 'file.txt', 'newfile' => 'file'), array()),
    'single-copy-move' => array(array(), array('copy' => 'file.txt', 'finish' => '1'), array()),
    'bulk-copy-move' => array(array(), array('file' => array('file.txt'), 'copy_to' => 'dest', 'finish' => '1'), array()),
    'rename' => array(array(), array('rename_from' => 'old.txt', 'rename_to' => 'new.txt'), array()),
    'upload' => array(array(), array(), array('file' => array('name' => 'upload.txt'))),
    'bulk-delete' => array(array(), array('group' => '1', 'delete' => 'Delete'), array()),
    'archive-create' => array(array(), array('group' => '1', 'tar' => 'tar'), array()),
    'archive-extract' => array(array(), array('unzip' => 'archive.zip'), array()),
    'permissions' => array(array(), array('chmod' => 'file.txt'), array()),
);

foreach ($routes as $expectedRoute => $request) {
    list($get, $post, $files) = $request;
    mutation_check(fm_mutation_route($get, $post, $files) === $expectedRoute,
        "$expectedRoute is centrally classified");

    $validPost = $post;
    $validPost['token'] = $token;
    $allowed = mutation_decision(
        'POST', $origin, $get, $validPost, $files, $token, $origin);
    mutation_check($allowed['allowed'] && $allowed['route'] === $expectedRoute,
        "$expectedRoute accepts exact method origin and CSRF state");

    $missingOrigin = mutation_decision(
        'POST', null, $get, $validPost, $files, $token, $origin);
    mutation_check(!$missingOrigin['allowed']
        && $missingOrigin['status'] === 403
        && $missingOrigin['reason'] === 'origin',
        "$expectedRoute rejects a missing Origin");

    $wrongOrigin = mutation_decision(
        'POST', 'https://wrong.example.test:8444',
        $get, $validPost, $files, $token, $origin);
    mutation_check(!$wrongOrigin['allowed']
        && $wrongOrigin['status'] === 403
        && $wrongOrigin['reason'] === 'origin',
        "$expectedRoute rejects a wrong Origin");

    $missingToken = mutation_decision(
        'POST', $origin, $get, $post, $files, $token, $origin);
    mutation_check(!$missingToken['allowed']
        && $missingToken['status'] === 403
        && $missingToken['reason'] === 'csrf',
        "$expectedRoute rejects a missing CSRF token");

    $badPost = $post;
    $badPost['token'] = $wrongToken;
    $wrongCsrf = mutation_decision(
        'POST', $origin, $get, $badPost, $files, $token, $origin);
    mutation_check(!$wrongCsrf['allowed']
        && $wrongCsrf['status'] === 403
        && $wrongCsrf['reason'] === 'csrf',
        "$expectedRoute rejects a wrong CSRF token");

    $getAttempt = mutation_decision(
        'GET', $origin, $get, $validPost, $files, $token, $origin);
    mutation_check(!$getAttempt['allowed']
        && $getAttempt['status'] === 405
        && $getAttempt['reason'] === 'method',
        "$expectedRoute rejects a GET mutation attempt");
}

$read = fm_mutation_gate_evaluate(
    array('REQUEST_METHOD' => 'GET'),
    array('raw' => 'file.txt'),
    array(),
    array(),
    array('token' => $token),
    true,
    $origin
);
mutation_check($read['allowed'] && $read['route'] === null,
    'ordinary GET reads do not require mutation credentials');

$globalPost = fm_mutation_gate_evaluate(
    array('REQUEST_METHOD' => 'POST', 'HTTP_ORIGIN' => $origin),
    array(),
    array('type' => 'pwdhash', 'token' => $token),
    array(),
    array('token' => $token),
    true,
    $origin
);
mutation_check($globalPost['allowed'] && $globalPost['route'] === null,
    'configured policy protects and admits an otherwise unclassified POST');

$globalPostMissingToken = fm_mutation_gate_evaluate(
    array('REQUEST_METHOD' => 'POST', 'HTTP_ORIGIN' => $origin),
    array(),
    array('type' => 'pwdhash'),
    array(),
    array('token' => $token),
    true,
    $origin
);
mutation_check(!$globalPostMissingToken['allowed']
    && $globalPostMissingToken['reason'] === 'csrf',
    'configured policy rejects an unclassified POST without CSRF state');

$coalescedOrigin = fm_mutation_gate_evaluate(
    array(
        'REQUEST_METHOD' => 'POST',
        'HTTP_ORIGIN' => $origin . ', https://wrong.example.test:8444',
    ),
    array(),
    array(
        'newfilename' => 'file.txt',
        'newfile' => 'file',
        'token' => $token,
    ),
    array(),
    array('token' => $token),
    true,
    $origin
);
mutation_check(!$coalescedOrigin['allowed']
    && $coalescedOrigin['status'] === 403
    && $coalescedOrigin['reason'] === 'origin',
    'a comma-coalesced duplicate Origin is rejected');

$disabled = fm_mutation_gate_evaluate(
    array('REQUEST_METHOD' => 'POST'),
    array(),
    array('newfilename' => 'file.txt', 'newfile' => 'file'),
    array(),
    array(),
    false,
    ''
);
mutation_check($disabled['allowed'],
    'the mutation gate remains backward-compatible when not configured');

$disabledWithUnusedOrigin = fm_mutation_gate_evaluate(
    array('REQUEST_METHOD' => 'POST'),
    array(),
    array('newfilename' => 'file.txt', 'newfile' => 'file'),
    array(),
    array(),
    false,
    null
);
mutation_check($disabledWithUnusedOrigin['allowed'],
    'disabled policy ignores an unused legacy origin value');

foreach (array(
    '',
    'http://afs-auth.example.test:8444',
    'https://afs-auth.example.test:0',
    'https://afs-auth.example.test:65536',
    'https://user@afs-auth.example.test:8444',
    'https://afs-auth.example.test:8444/path',
    "https://afs-auth.example.test:8444\n",
) as $invalidOrigin) {
    $invalid = fm_mutation_gate_evaluate(
        array('REQUEST_METHOD' => 'GET'),
        array(), array(), array(), array(), true, $invalidOrigin);
    mutation_check(!$invalid['allowed']
        && $invalid['status'] === 503
        && $invalid['reason'] === 'configuration',
        'an invalid configured mutation origin fails closed');
}

echo "PASS: $checks central mutation-request checks\n";
