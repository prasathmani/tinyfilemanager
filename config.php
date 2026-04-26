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
    'admin'     => '$2y$10$/K.hjNr84lLNDt8fTXjoI.DBp6PpeyoJ.mGwrrLuCZfAwfSAGqhOW',

    // Manažéri – vidia a upravujú všetko, nemôžu mazať
    'manager1'  => '$2y$10$Fg6Dz8oH9fPoZ2jJan5tZuv6Z4Kp7avtQ9bDfrdRntXtPeiMAZyGO',
    'manager2'  => '$2y$10$Fg6Dz8oH9fPoZ2jJan5tZuv6Z4Kp7avtQ9bDfrdRntXtPeiMAZyGO',

    // Klienti – môžu nahrávať a sťahovať, len svoj priečinok
    'client1'   => '$2y$10$Fg6Dz8oH9fPoZ2jJan5tZuv6Z4Kp7avtQ9bDfrdRntXtPeiMAZyGO',
    'client2'   => '$2y$10$Fg6Dz8oH9fPoZ2jJan5tZuv6Z4Kp7avtQ9bDfrdRntXtPeiMAZyGO',

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
    'client1',
    'client2',
    'supplier1',
    'supplier2',
);

// Manager: môžu všetko okrem mazania
$manager_users = array(
    'manager1',
    'manager2',
);

// --- IZOLOVANÉ PRIEČINKY / PROJEKTY ---
// Klienti a dodávatelia môžu mať prístup do jedného alebo viacerých projektových priečinkov.
// Manažéri a admin tu nemajú záznam – vidia celý root_path.
// Cesty musia existovať na disku a webserver musí mať práva na zápis.
$directories_users = array(
    'client1'   => __DIR__ . '/uploads/client1',
    'client2'   => __DIR__ . '/uploads/client2',
    'supplier1' => __DIR__ . '/uploads/supplier1',
    'supplier2' => __DIR__ . '/uploads/supplier2',
    // Príklad používateľa s viacerými projektmi:
     'client3' => array(
         __DIR__ . '/uploads/Nemocnica PP',
         __DIR__ . '/uploads/free',
     ),
);

// --- VŠEOBECNÉ NASTAVENIA ---

// Koreňový priečinok pre admin a manažérov
$root_path = __DIR__ . '/uploads';

// Maximálna veľkosť uploadu (~5 GB)
$max_upload_size_bytes = 5000000000;

// Povolené prípony pre upload (prázdne = všetky)
$allowed_upload_extensions = '';

// Predvolený jazyk a UI nastavenia
$CONFIG = '{"lang":"sk","error_reporting":false,"show_hidden":false,"hide_Cols":false,"theme":"light"}';

// Téma: 'light' alebo 'dark'
// $CONFIG = '{"lang":"en","error_reporting":false,"show_hidden":false,"hide_Cols":false,"theme":"dark"}';
