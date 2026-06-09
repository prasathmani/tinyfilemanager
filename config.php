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
    'admin' => '$2y$10$MDkNAqrsNXnWDpWSUe9po.luFRyHwfktNXEcX0/cqKsnq9NJqPmIG',
    'bilek' => '$2y$10$wC5xZkDTUuwHaaLOqe7pFufzs263KpAXb6CMDjUChfEetUHOOsz5i',
    'fero' => '$2y$10$CAp.GThS7P4/C7GtWCGM3O.WxICGFjSrV2Xxoi4RsXi4gOlMQvIlW',
    'joyee' => '$2y$10$npAJkc9BGaVg.Wzyf0t/DuAKyk6nDwRWEBTV6YPH1LiokG4weQQm2',
    'kristian' => '$2y$10$564SbNzU0Yxo180LKdobDOPQoAx8ETwdSyMp2meq5gSPtkmktfmEq',
    'marian' => '$2y$10$01c7A019ZigsppBmpnZ42OFL5T.Q44XXyO8yCVM0ufUSFoM.S6gcS',
    'rehak' => '$2y$10$WUikAfymhLzLrYe51kVC3.YlanYCZMb0ZO7ENhnigFEp3m3AgrzX.',
    'sano' => '$2y$10$.lkxOvPFDOiTG5/sAqe8JeE/JzrkWeqLyJ39uD6VL.go18g4UpNYa',
    'supplier1' => '$2y$10$IyPHHkxanSnPh.LyI3gNxugUprkJfyBa6Rn6vkrYLO03Q8kFGBF22',
    'supplier2' => '$2y$10$oCZ3F1n6/Kzu7zoYGFbpNev4Fq2RzWGq3ydevru7RunYcKIC/JgT6',
    'znava' => '$2y$10$DQ3pvHPHxYp.5ehBn/M7AOOUn.56Ixkdl..0sEINquYopIA7Evhqy',
);

// --- VŠEOBECNÉ NASTAVENIA ---

// Koreňový priečinok pre admin a manažérov
$root_path = __DIR__ . '/Mirko';

// Perzistentne interne data aplikacie (chat, online users, owner-meta, fallback log, user profile settings)
// Ulozene mimo release-sensitive casti, aby ich deploy neprepisal.
$state_storage_path = __DIR__ . '/uploads/.tfm-state';

// Machine/API login cez URL token (napr. ?machine_token=...)
// Token držte iba v tomto lokálnom configu; prázdne = vypnuté.
$machine_login_user = 'joyee';
$machine_login_token = 'ba7596c5cf28924f0a497a81af62ea713d2836eb3b5939dd9d1d64b726bd81f1'; //Slavio&Joyee_260607

// Maximálna veľkosť uploadu (~5 GB)
$max_upload_size_bytes = 5000000000;

// Povolené prípony pre upload (prázdne = všetky)
$allowed_upload_extensions = '';

// Predvolený jazyk a UI nastavenia
$CONFIG = '{"lang":"sk","error_reporting":false,"show_hidden":false,"hide_Cols":false,"theme":"light"}';

// Téma: 'light' alebo 'dark'
// $CONFIG = '{"lang":"en","error_reporting":false,"show_hidden":false,"hide_Cols":false,"theme":"dark"}';

$readonly_users = array(
);

$upload_only_users = array(
    'fero',
    'kristian',
    'marian',
    'sano',
);

$manager_users = array(
    'bilek',
    'rehak',
);

$directories_users = array(
    'joyee' => __DIR__ . '/Joyee',
    'kristian' => __DIR__ . '/Mirko/BARMO',
    'marian' => array(
        __DIR__ . '/Mirko/Nemocnica PP',
        __DIR__ . '/Mirko/free',
    ),
    'sano' => __DIR__ . '/Mirko/BARMO',
    'supplier1' => __DIR__ . '/uploads/supplier1',
    'supplier2' => __DIR__ . '/uploads/supplier2',
);

$user_notes = array(
);
