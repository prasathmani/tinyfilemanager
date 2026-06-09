# Changelog

## [Unreleased]

### Added
- Added integrated read-only user administration page via `?admin_users=1`.
- Added admin-only modal framework for future New/Edit user actions.
- Added one-time migration helper `scripts/migrate-legacy-state.php` with `dry-run` and `--apply` modes.

### Changed
- User overview now lists access type, auth status, assigned directories and configuration notes.
- Access to the user administration page and navigation link is now restricted to the `admin` user only (not `manager_users`).
- Runtime state storage is now configurable via `$state_storage_path` in `config.php`.
- Internal runtime records (online users, chat DB, owner metadata, audit and fallback log, per-user settings) now use a persistent state directory.
- Authentication and online-user tracking were hardened to remove stale user markers when a session account changes.
- Documentation updated for release/deploy flow to include runtime-state migration and verification.

### Removed
- Removed operational dependency on app-local `.fm_usercfg` as the primary runtime state location.

### Notes
- User listing remains read-only; modal content is loaded only on admin action.
- No `config.php` write is performed in user administration phase.
