<?php
/**
 * Generate ChatGPT project source descriptor for Joyee.
 *
 * This creates a Markdown file that can be uploaded manually
 * into a ChatGPT project as a source file.
 */

$root = dirname(__DIR__);

$configFile = $root . '/config.php';
$versionFile = $root . '/RELEASE_VERSION';
$outputFile = $root . '/chatgpt-source-joyee.md';

if (!is_file($configFile)) {
    fwrite(STDERR, "Missing config.php\n");
    exit(1);
}

require $configFile;

if (empty($machine_login_token)) {
    fwrite(STDERR, "Missing \$machine_login_token in config.php\n");
    exit(1);
}

$machineUser = isset($machine_login_user) && $machine_login_user !== ''
    ? $machine_login_user
    : 'joyee';

$version = 'neznama';
if (is_file($versionFile)) {
    $versionValue = trim((string) file_get_contents($versionFile));
    if ($versionValue !== '') {
        $version = $versionValue;
    }
}

$baseUrl = 'https://files.dremont.in/tinyfilemanager.php';
$linkUrl = $baseUrl . '?machine_token=' . rawurlencode($machine_login_token);

$workspacePath = 'Joyee';
if (isset($directories_users[$machineUser])) {
    $workspacePath = $directories_users[$machineUser];
    if (is_array($workspacePath)) {
        $workspacePath = implode(', ', $workspacePath);
    }
}

$generatedAt = date('c');

$content = <<<MD
# Joyee - ChatGPT Project Source

Tento subor sluzi ako zdrojovy manifest pre ChatGPT projekt.

## Ucel

Tento zdroj opisuje technicke pripojenie pouzivatela **Joyee** do sukromneho pracovneho priestoru TinyFileManager.

Joyee je technicky pouzivatel systemu, spravovany rovnakym permission modelom ako ostatni pouzivatelia.

## Link URL

Pouzi tento odkaz ako machine/session vstup:

{$linkUrl}

Po otvoreni odkazu sa ma vytvorit session pouzivatela:

{$machineUser}

Token sa ma po uspesnom prihlaseni odstranit z URL redirectom.

## Workspace

Pouzivatel:

{$machineUser}

Pracovny priestor:

{$workspacePath}

## Aktualna verzia

TinyFileManager build:

{$version}

## Pravidla

1. Joyee nesmie obchadzat existujuci permission model.
2. Joyee ma pracovat iba v priestore pridelenom pouzivatelovi {$machineUser}.
3. Korenovy adresar, prava a obmedzenia sa nastavuju cez Spravu pouzivatelov.
4. Machine login je iba iny sposob vytvorenia session, nie novy bezpecnostny model.
5. Pri rizikovych operaciach ma mat pouzivatel moznost schvalenia.
6. Tento subor je urceny pre sukromny pracovny projekt, nie verejnu distribuciu.

## Generovane

{$generatedAt}

MD;

file_put_contents($outputFile, $content);

echo "Generated: {$outputFile}\n";