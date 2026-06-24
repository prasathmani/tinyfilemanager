# Bezpečnosť a správa používateľov

Keďže TinyFileManager dokáže manipulovať so súbormi na serveri, je nevyhnutné aplikáciu správne zabezpečiť.

## Konfigurácia

Predvolené prihlasovacie údaje:

- admin/admin@123
- user/12345

**Upozornenie**: Pred použitím si nastav vlastné používateľské meno a heslo v `$auth_users`. Heslá sú šifrované pomocou `password_hash()`.

Zapnutie alebo vypnutie autentifikácie nastavíš cez `$use_auth` na `true` alebo `false`.

```php
// Auth with login/password
// set true/false to enable/disable it
// Is independent from IP white- and blacklisting
$use_auth = true;

// Login user name and password
// Users: array('Username' => 'Password', 'Username2' => 'Password2', ...)
// Generate secure password hash - https://tinyfilemanager.github.io/docs/pwd.html
$auth_users = array(
    'admin' => '$2y$10$/K.hjNr84lLNDt8fTXjoI.DBp6PpeyoJ.mGwrrLuCZfAwfSAGqhOW', //admin@123
    'user' => '$2y$10$Fg6Dz8oH9fPoZ2jJan5tZuv6Z4Kp7avtQ9bDfrdRntXtPeiMAZyGO', //12345
    'guest' => '$2y$10$a.DMI5sRjAnvhb.8rFAXY.XPSEO/eatVb4qCMmTc2YcxTDKp9xMyC' //guest
);
```

## Heslo

Heslá sa šifrujú pomocou `password_hash()`. Nový hash môžeš vygenerovať tu:
https://tinyfilemanager.github.io/docs/pwd.html

Ak sa hash nepodarí vygenerovať alebo narazíš na problém, použi generovanie priamo v TinyFileManageri cez:
`tinyfilemanager > Help > Generate new password hash`

Alternatívny generátor:
https://onlinephp.io/password-hash

Alebo môžeš nastaviť hash priamo cez `password_hash()`:

```php
$auth_users = array(
    'username' => password_hash('password here', PASSWORD_DEFAULT)
);
```

## Používatelia iba na čítanie

Používatelia s rolou readonly nemajú oprávnenie vytvárať, upravovať, mazať ani nahrávať súbory.

```php
// Readonly users
// e.g. array('users', 'guest', ...)
$readonly_users = array(
    'user',
    'guest'
);
```

## Adresáre špecifické pre používateľa

Keďže používatelia môžu nahrávať, sťahovať, mazať a meniť oprávnenia na väčšine súborov v prístupných priečinkoch, často je vhodné obmedziť ich len na konkrétne adresáre.

Takto vieš dať používateľovi prístup iba do jednej časti úložiska.

Obmedzený prístup je užitočný aj vtedy, keď chceš niekomu povoliť nahrávanie súborov, ale nechceš mu sprístupniť celý adresár.

```php
// user specific directories
// array('Username' => 'Directory path', 'Username2' => 'Directory path', ...)
$directories_users = array(
    'user' => 'root/user-folder',
    'guest' => 'root/guest/temp'
);
```
