# Release Quick Help

## Najcastejsie pouzitie

- Patch release + commit + push:
  - `./release.sh patch --auto-push`
- Minor release + commit + push:
  - `./release.sh minor --auto-push`
- Major release + commit + push:
  - `./release.sh major --auto-push`
- Explicitna verzia + commit + push:
  - `./release.sh 2.10.06 --auto-push`

## Version argument

- `patch` -> `x.y.z` na `x.y.(z+1)`
- `minor` alebo `mini` -> `x.y.z` na `x.(y+1).0`
- `major` -> `x.y.z` na `(x+1).0.0`
- `X.Y.Z` -> pouzije sa explicitna verzia

## Dolezite prepinace

- `--auto-commit`:
  - spravi commit s `RELEASE_VERSION` a `releases/tinyfilemanager-<verzia>.zip`
- `--auto-push`:
  - automaticky zapne aj `--auto-commit`
  - pushne aktualnu vetvu na `origin`
- `--commit-message="..."`:
  - vlastna commit sprava
- `--include-local-config`:
  - do release prida lokalne configy, ak existuju (`api.config.php`, `joyee-bridge.config.php`)

## Priklady

- `./release.sh patch`
- `./release.sh patch --auto-commit`
- `./release.sh patch --auto-commit --commit-message="Release 2.10.06"`
- `./release.sh mini --auto-push`

## Pred release/deploy (runtime state)

- Over, ze `config.php` obsahuje perzistentnu cestu pre runtime data:
  - `$state_storage_path = __DIR__ . '/uploads/.tfm-state';`
- Spusti migraciu legacy state dat (bezpecny dry-run -> apply):
  - `php scripts/migrate-legacy-state.php`
  - `php scripts/migrate-legacy-state.php --apply`
- Skontroluj cielovy adresar:
  - `ls -la uploads/.tfm-state`

## Migracia konfiguracie do SQLite

- Prekopiruj runtime konfiguraciu aj UI predvolby do databazy:
  - `php scripts/migrate-config-to-db.php`
  - `php scripts/migrate-config-to-db.php --apply`
- Skript prenasa:
  - runtime config z `config.php` do `runtime_config/global`
  - globalne UI predvolby z `$CONFIG` do `ui_preferences/global`
  - stare profilove JSON nastavenia pouzivatelov do `ui_preferences/<username>`
- Po migracii uz budu nove ulozenia smerovat do SQLite config store, ale filesystem fallback zostane ako poistka.

## Bezpecny postup pred release (server je zdroj pravdy)

Ak sa na nasadenom serveri medzicasom menili konfiguracie alebo pouzivatelia v Sprave uzivatelov, pred release ich najprv stiahni zo servera do workspace a az potom vytvaraj release balik.

### Odporucany postup

1. Zisti aktualny stav na serveri a sprav si zalohu lokalnych configov:
  - `cp config.php config.php.bak.$(date +%Y%m%d_%H%M%S)`
  - `cp api.config.php api.config.php.bak.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true`
  - `cp joyee-bridge.config.php joyee-bridge.config.php.bak.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true`

2. Stiahni serverove konfiguracie do workspace cez `rsync` alebo `scp`:
  - `rsync -avz user@server:/var/www/html/config.php ./config.php`
  - `rsync -avz user@server:/var/www/html/api.config.php ./api.config.php 2>/dev/null || true`
  - `rsync -avz user@server:/var/www/html/joyee-bridge.config.php ./joyee-bridge.config.php 2>/dev/null || true`

3. Over rozdiely pred release:
  - `git diff -- config.php api.config.php joyee-bridge.config.php`

4. Ak su zmeny spravne, commitni ich a az potom pust release:
  - `./release.sh patch --auto-push`

### Poznamka

- `.gitignore` chraní len neversionované lokalne subory.
- Trackovany `config.php` sa do release prenesie iba vtedy, ked je skutocne aktualizovany vo workspace.
- Týmto je serverova konfiguracia zdroj pravdy a release ju neprepise naslepo.
