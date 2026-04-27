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
    'rehák'  => '$2y$10$WqbQGH1KGzPywYv6KEdJkuz7YWRxAJmIf8F5ESz8Zt50LFCPW7NPC', //Rehák01
    'bílek'  => '$2y$10$.u0a6jwDjrZGe5679SYqh.ipfrIhzqVn8GkpFzwwjwNsbh5WuXvaW', // Bílek01
    'znava'  => '$2y$10$255.N7QKQ/tgfFkcW6Wzwu7NimvvoOIn5Y0MqsRgb2e5jnbY0FDCS', // Znava01

    // Klienti – môžu nahrávať a sťahovať, len svoj priečinok
    'šaňo'   => '$2y$10$ttOoy.PKbGhypSnt7habEe1a1bh1ZVmr7je7Dc.WthEfzf3O.L74i', //Šaňo01
    'kristián'   => '$2y$10$yB9dlXQyrnVdl9dReexdPOG1xzMDVhNjFyjenHPXDW8TDuZ25jQ6W',
    'fero'   => '$2y$10$teczMBSCU4mhIBoQSJBhSeMCrrNdY0LJxP1w51EMqIIK6XZsehDLy',
    'marián'   => '$2y$10$ZDstCy90JIV1uwG2EMsgKOyZiLALBlVGDMvekN5lqWQn/M97CHrUu',

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
