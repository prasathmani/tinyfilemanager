<?php
// =============================================================================
// Tiny File Manager – externá konfigurácia
// Tento súbor prepíše predvolené hodnoty v tinyfilemanager.php.
// Upravujte IBA tento súbor, hlavný tinyfilemanager.php nechajte nedotknutý.
//
// Generovanie hashov hesiel: https://tinyfilemanager.github.io/docs/pwd.html
//   alebo v PHP: echo password_hash('moje_heslo', PASSWORD_BCRYPT);
// =============================================================================

// --- POUŽÍVATELIA A HESLÁ ---
// Formát: 'meno' => 'bcrypt_hash_hesla'
$auth_users = array(
    // Admin – plný prístup (upload, download, rename, copy, zip, delete)
    'admin'     => '$2y$10$MDkNAqrsNXnWDpWSUe9po.luFRyHwfktNXEcX0/cqKsnq9NJqPmIG', // Spdlhé

    // Manažéri – vidia a upravujú všetko, nemôžu mazať
    'rehak'  => '$2y$10$MDqH4vvwosCqjePZo60nHeucpxRrN30Vu/HNHjvW04wTnS.GgoiDG', //Rehak01
    'bilek'  => '$2y$10$aAkrv/JD3fD9Fq0UWZlkk.vCioO7UAlByO9H6jyfa7pyTdBSkJwPq', // Bilek01
    'znava'  => '$2y$10$255.N7QKQ/tgfFkcW6Wzwu7NimvvoOIn5Y0MqsRgb2e5jnbY0FDCS', // Znava01

    // Klienti – môžu nahrávať a sťahovať, len svoj priečinok
    'sano'   => '$2y$10$m9ONc6v2Cro9GvhcPunBLOzL4tjQmxj/d6uosb4fEF6gGc5SrHko6', //Sano01
    'kristian'   => '$2y$10$UGPcbNMYVQv5p66bhyvQeuH6..JmXmdkF7fdpOqdTwKAluBywKyDC',//Kristian01
    'fero'   => '$2y$10$teczMBSCU4mhIBoQSJBhSeMCrrNdY0LJxP1w51EMqIIK6XZsehDLy', //Fero01
    'marian'   => '$2y$10$1bqqSfV0RrNerti7upxoOui77TBWQZQTVnxHbvCxqjhQ.JTNvFzSG', //Marian01    

    // Dodávatelia – môžu len sťahovať/prezerať, len svoj priečinok
    'supplier1' => '$2y$10$Fg6Dz8oH9fPoZ2jJan5tZuv6Z4Kp7avtQ9bDfrdRntXtPeiMAZyGO',
    'supplier2' => '$2y$10$Fg6Dz8oH9fPoZ2jJan5tZuv6Z4Kp7avtQ9bDfrdRntXtPeiMAZyGO',
);

// --- ROLY ---

// Readonly: môžu len prezerať a sťahovať (žiadny zápis)
$readonly_users = array(
    // sem patrí napr. hosť alebo audítor
);

// Upload-only: môžu nahrávať + sťahovať, nemôžu mazať/editovať/premenovávať
$upload_only_users = array(
    'šaňo',
    'kristián',
    'marián',
    'fero',
);

// Manager: môžu všetko okrem mazania
$manager_users = array(
    'rehák',
    'bílek',
);

// --- IZOLOVANÉ PRIEČINKY / PROJEKTY ---
// Klienti a dodávatelia môžu mať prístup do jedného alebo viacerých projektových priečinkov.
// Manažéri a admin tu nemajú záznam – vidia celý root_path.
// Cesty musia existovať na disku a webserver musí mať práva na zápis.
$directories_users = array(
    'šaňo'   => __DIR__ . '/Mirko/BARMO',
    'kristián'   => __DIR__ . '/Mirko/BARMO',
    'supplier1' => __DIR__ . '/uploads/supplier1',
    'supplier2' => __DIR__ . '/uploads/supplier2',
    // Príklad používateľa s viacerými projektmi:
     'marián' => array(
         __DIR__ . '/Mirko/Nemocnica PP',
         __DIR__ . '/Mirko/free',
     ),
);

// --- VŠEOBECNÉ NASTAVENIA ---

// Koreňový priečinok pre admin a manažérov
$root_path = __DIR__ . '/Mirko';

// Maximálna veľkosť uploadu (~5 GB)
$max_upload_size_bytes = 5000000000;

// Povolené prípony pre upload (prázdne = všetky)
$allowed_upload_extensions = '';

// Predvolený jazyk a UI nastavenia
$CONFIG = '{"lang":"sk","error_reporting":false,"show_hidden":false,"hide_Cols":false,"theme":"light"}';

// Téma: 'light' alebo 'dark'
// $CONFIG = '{"lang":"en","error_reporting":false,"show_hidden":false,"hide_Cols":false,"theme":"dark"}';
