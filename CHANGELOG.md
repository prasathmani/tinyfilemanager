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
- Owner-map save now synchronizes runtime DB config to keep UI and persisted ownership state consistent after reload.
- Owner-map apply now preserves unchanged users when partial payloads are submitted, preventing accidental reset of owners to `admin`.
- Admin config loaders now read runtime DB scope for user-management arrays, so snapshot restore is reflected immediately in owner-map/admin views.
- Snapshot panel now explicitly indicates that rows are ordered newest-first.

### Removed
- Removed operational dependency on app-local `.fm_usercfg` as the primary runtime state location.

### Breaking changes
- Visual baseline is now aligned with the modern theme layer.
- Some legacy CSS override rules were narrowed or removed to reduce cascade conflicts.
- Custom theme overrides may need revalidation after deploy.

### Migration notes
- Back up `config.php`, `api.config.php`, custom assets, and local patches before deploy.
- Deploy the new release package and verify file ownership/permissions in the target environment.
- Clear browser cache and any reverse proxy or CDN cache.
- Run smoke tests for login/logout, theme switch, listing density, selection/bulk move, upload, rename, copy/move, delete, and file preview/editor.
- Verify path-boundary behavior for move/copy operations and confirm readonly/upload-only modes.
- Review PHP and web server logs after deploy and check browser console for front-end regressions.

### Notes
- User listing remains read-only; modal content is loaded only on admin action.
- No `config.php` write is performed in user administration phase.
