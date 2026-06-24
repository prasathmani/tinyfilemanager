# FAQ

## Pri nahrávaní niektorých súborov dostávam chybu

Najčastejšie ide o limit veľkosti súboru.
Konfiguračná voľba `MAX_UPLOAD_SIZE` umožňuje nastaviť limit prenosu, ale serverové nastavenia v `php.ini` (`upload_max_filesize` a `post_max_size`) ho môžu prepísať.

## Oprávnenia súborov

Pozri vysvetlenie a odporúčania:
https://serverfault.com/questions/962790/php-script-and-correct-permissions-for-user-to-change-everything
