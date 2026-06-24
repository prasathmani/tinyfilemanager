# Vylúčenie súborov a priečinkov (Exclude Files & Folders)

Pomocou konfigurácie môžeš určiť súbory alebo adresáre, ktoré sa nemajú zobrazovať vo výpise.
Ak sa rovnaký názov súboru alebo priečinka nachádza na viacerých miestach, pravidlo vylúčenia sa uplatní na všetky zhody.

```php
// Files and folders to excluded from listing
// e.g. array('myfile.html', 'personal-folder', '*.php', ...)
$exclude_items = array(
    'my-folder',
    'secret-files',
    'tinyfilemanger.php',
    '*.php',
    '*.js'
);
```
