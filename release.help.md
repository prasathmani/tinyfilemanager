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
