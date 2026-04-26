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
    'admin'     => '$2y$10$/K.hjNr84lLNDt8fTXjoI.DBp6PpeyoJ.mGwrrLuCZfAwfSAGqhOW', // heslo: admin@123

    // Manažéri – vidia a upravujú všetko, nemôžu mazať
    'manager1'  => '$2y$10$Fg6Dz8oH9fPoZ2jJan5tZuv6Z4Kp7avtQ9bDfrdRntXtPeiMAZyGO', // heslo: 12345
    'manager2'  => '$2y$10$Fg6Dz8oH9fPoZ2jJan5tZuv6Z4Kp7avtQ9bDfrdRntXtPeiMAZyGO', // heslo: 12345

    // Klienti – môžu nahrávať a sťahovať, len svoj priečinok
    'client1'   => '$2y$10$Fg6Dz8oH9fPoZ2jJan5tZuv6Z4Kp7avtQ9bDfrdRntXtPeiMAZyGO', // heslo: 12345
    'client2'   => '$2y$10$Fg6Dz8oH9fPoZ2jJan5tZuv6Z4Kp7avtQ9bDfrdRntXtPeiMAZyGO', // heslo: 12345

    // Dodávatelia – môžu len sťahovať/prezerať, len svoj priečinok
    'supplier1' => '$2y$10$Fg6Dz8oH9fPoZ2jJan5tZuv6Z4Kp7avtQ9bDfrdRntXtPeiMAZyGO', // heslo: 12345
    'supplier2' => '$2y$10$Fg6Dz8oH9fPoZ2jJan5tZuv6Z4Kp7avtQ9bDfrdRntXtPeiMAZyGO', // heslo: 12345
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

// --- IZOLOVANÉ PRIEČINKY ---
// Klienti a dodávatelia vidia LEN svoj priečinok.
// Manažéri a admin tu nemajú záznam – vidia celý root_path.
// Cesty musia existovať na disku a webserver musí mať práva na zápis.
$directories_users = array(
    'client1'   => '/var/www/html/uploads/client1',
    'client2'   => '/var/www/html/uploads/client2',
    'supplier1' => '/var/www/html/uploads/supplier1',
    'supplier2' => '/var/www/html/uploads/supplier2',
);

// --- VŠEOBECNÉ NASTAVENIA ---

// Koreňový priečinok pre admin a manažérov
$root_path = '/var/www/html/uploads';

// Maximálna veľkosť uploadu (~5 GB)
$max_upload_size_bytes = 5000000000;

// Povolené prípony pre upload (prázdne = všetky)
$allowed_upload_extensions = '';

// Predvolený jazyk a UI nastavenia
$CONFIG = '{"lang":"sk","error_reporting":false,"show_hidden":false,"hide_Cols":false,"theme":"light"}';

// Téma: 'light' alebo 'dark'
// $CONFIG = '{"lang":"en","error_reporting":false,"show_hidden":false,"hide_Cols":false,"theme":"dark"}';
