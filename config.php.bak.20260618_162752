<?php
// =============================================================================
// Tiny File Manager – externá konfigurácia
// Tento súbor prepíše predvolené hodnoty v tinyfilemanager.php.
// Upravujte IBA tento súbor, hlavný tinyfilemanager.php nechajte nedotknutý.
//
// Generovanie hashov hesiel: https://tinyfilemanager.github.io/docs/pwd.html
//   alebo v PHP: echo password_hash('moje_heslo', PASSWORD_BCRYPT);
// =============================================================================

// Globálne predvolené UI nastavenia (fallback pre používateľov bez vlastného profilu).
$CONFIG = '{"lang":"sk","error_reporting":false,"show_hidden":false,"hide_Cols":false,"theme":"light","list_density":"compact","fallback_logging":false}';

// --- POUŽÍVATELIA A HESLÁ ---
// Formát: 'meno' => 'bcrypt_hash_hesla'
$auth_users = array(
    'admin' => '$2y$10$MDkNAqrsNXnWDpWSUe9po.luFRyHwfktNXEcX0/cqKsnq9NJqPmIG',
    'bilek' => '$2y$10$wC5xZkDTUuwHaaLOqe7pFufzs263KpAXb6CMDjUChfEetUHOOsz5i',
    'chachula' => '$2y$10$aXrwD.R2BgClZAuGDkiwc.twb2UKgPWh7WxYVqdG9eYwP7C1cUUfW',
    'fero' => '$2y$10$CAp.GThS7P4/C7GtWCGM3O.WxICGFjSrV2Xxoi4RsXi4gOlMQvIlW',
    'joyee' => '$2y$10$npAJkc9BGaVg.Wzyf0t/DuAKyk6nDwRWEBTV6YPH1LiokG4weQQm2',
    'kicin' => '$2y$10$WiObQoB/OV.f46d7lIj9ZODXaaxWNGX4m3dUqPu9xWo.ijsruqpEG',
    'kristian' => '$2y$10$564SbNzU0Yxo180LKdobDOPQoAx8ETwdSyMp2meq5gSPtkmktfmEq',
    'marian' => '$2y$10$01c7A019ZigsppBmpnZ42OFL5T.Q44XXyO8yCVM0ufUSFoM.S6gcS',
    'rehak' => '$2y$10$WUikAfymhLzLrYe51kVC3.YlanYCZMb0ZO7ENhnigFEp3m3AgrzX.',
    'sano' => '$2y$10$.lkxOvPFDOiTG5/sAqe8JeE/JzrkWeqLyJ39uD6VL.go18g4UpNYa',
    'supplier1' => '$2y$10$IyPHHkxanSnPh.LyI3gNxugUprkJfyBa6Rn6vkrYLO03Q8kFGBF22',
    'supplier2' => '$2y$10$oCZ3F1n6/Kzu7zoYGFbpNev4Fq2RzWGq3ydevru7RunYcKIC/JgT6',
    'znava' => '$2y$10$DQ3pvHPHxYp.5ehBn/M7AOOUn.56Ixkdl..0sEINquYopIA7Evhqy',
);

$readonly_users = array(
    'chachula',
    'kicin',
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
    'znava',
);

$directories_users = array(
    'admin' => __DIR__ . '/Mirko/',
    'bilek' => __DIR__ . '/Mirko/',
    'chachula' => __DIR__ . '/Mirko/Nemocnica PP',
    'fero' => __DIR__ . '/Mirko/',
    'joyee' => __DIR__ . '/Joyee',
    'kicin' => __DIR__ . '/Mirko/Nemocnica PP',
    'kristian' => __DIR__ . '/Mirko/BARMO',
    'marian' => array(
        __DIR__ . '/Mirko/Nemocnica PP',
        __DIR__ . '/Mirko/free',
    ),
    'rehak' => __DIR__ . '/Mirko/',
    'sano' => __DIR__ . '/Mirko/BARMO',
    'supplier1' => __DIR__ . '/uploads/supplier1',
    'supplier2' => __DIR__ . '/uploads/supplier2',
    'znava' => __DIR__ . '/Mirko/',
);

$user_notes = array(
);
