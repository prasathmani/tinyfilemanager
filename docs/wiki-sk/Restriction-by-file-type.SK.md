# Obmedzenie podľa typu súboru (Restriction by file type)

Nahrávanie, vytváranie a premenovanie súborov je možné obmedziť podľa prípony,
podobnou logikou ako pri [Apache access control](http://httpd.apache.org/docs/2.2/howto/access.html).

- Povolené prípony pre nahrávanie sú definované v premennej `$allowed_upload_extensions`.
- Povolené prípony pre vytváranie a premenovanie sú definované v premennej `$allowed_file_extensions`.

```php
// Allowed file extensions for create and rename files
// e.g. 'txt,html,css,js'
$allowed_file_extensions = 'txt,html,js,css,scss';

// Allowed file extensions for upload files
// e.g. 'gif,png,jpg,html,txt'
$allowed_upload_extensions = 'jpg,jpeg,gif,txt,mp4';
```
