# Vloženie do iného skriptu (Embedding)

Správcu súborov môžeš vložiť do iného skriptu. Stačí definovať FM_EMBED a ďalšie potrebné konštanty.

```php
class SomeController
{
    public function actionIndex()
    {
        define('FM_EMBED', true);
        define('FM_SELF_URL', UrlHelper::currentUrl()); // must be set if URL to manager not equal PHP_SELF
        require 'path/to/tinyfilemanager.php';
    }
}
```

Alebo:

```php
define('FM_EMBED', true);
define('FM_SELF_URL', $_SERVER['PHP_SELF']);
require 'path/tinyfilemanager.php';
```
