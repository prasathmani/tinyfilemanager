# Konfiguračné prepínače (Config Flags)

Prehľad najdôležitejších konfiguračných premenných:

- `$root_path` - predvolene `$_SERVER['DOCUMENT_ROOT']`
- `$root_url` - predvolene `'http(s)://site.domain/'`
- `$http_host` - predvolene `$_SERVER['HTTP_HOST']`
- `$global_readonly` - predvolene `false`; globálny režim iba na čítanie, aj keď nepoužívaš autentifikáciu
- `$iconv_input_encoding` - predvolene `'CP1251'`
- `$use_highlightjs` - predvolene `true`; zapína/vypína zvýraznenie kódu
- `$highlightjs_style` - predvolene `'vs'`
- `$datetime_format` - predvolene `'m/d/Y g:i A'`
- `$allowed_upload_extensions` - predvolene prázdne; povolené prípony pre nahrávanie, napr. `'jpg,png,pdf,gif,html,css,js'`
- `$allowed_file_extensions` - predvolene prázdne; povolené prípony pri vytváraní a premenovaní súborov, napr. `'html,css,js'`
- `$exclude_items` - predvolene prázdne; súbory a priečinky, ktoré sa nezobrazia vo výpise
- `$edit_files` - predvolene `true`; zapína editor ace.js (https://ace.c9.io/) na stránke zobrazenia
- `$sticky_navbar` - predvolene `true`; zapína/vypína fixný horný panel
- `$online_viewer` - predvolene `'google'`; dostupné voľby sú `'google'`, `'microsoft'` alebo `false`
- `$favicon_path` - predvolene prázdne; môže byť úplná URL na PNG alebo cesta od document root
- `MAX_UPLOAD_SIZE` - predvolene `5GB`
- `$ip_ruleset` - predvolene `OFF`
- `$state_storage_path` - predvolene vnútorný `.fm_usercfg`; odporúčané nastaviť na perzistentnú cestu mimo release balíka (napr. `uploads/.tfm-state`), aby chat/online/audit/metadata prežili deploy

## Poznámka

V pôvodnej wiki je položka `$allowed_upload_extensions` uvedená dvakrát pre dva rôzne účely. Pri konfigurácii skontroluj aktuálne správanie vo verzii, ktorú nasadzuješ.
