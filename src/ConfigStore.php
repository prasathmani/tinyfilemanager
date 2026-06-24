<?php

/**
 * SQLite-backed configuration store for app-wide and per-user settings.
 *
 * The store is intentionally generic so future configuration can move out of
 * config.php without changing the schema again.
 */

function fm_config_store_db_path()
{
    $dir = fm_runtime_state_dir();
    return $dir . '/config.sqlite';
}

function fm_config_store_normalize_scope_type($scopeType)
{
    $scopeType = strtolower(trim((string) $scopeType));
    if ($scopeType === '') {
        $scopeType = 'app';
    }
    return preg_replace('/[^a-z0-9_\-]/', '_', $scopeType);
}

function fm_config_store_normalize_scope_key($scopeKey)
{
    $scopeKey = trim((string) $scopeKey);
    return $scopeKey === '' ? 'global' : $scopeKey;
}

function fm_config_store_value_type($value)
{
    if ($value === null) {
        return 'null';
    }
    if (is_bool($value)) {
        return 'bool';
    }
    if (is_int($value)) {
        return 'int';
    }
    if (is_float($value)) {
        return 'float';
    }
    if (is_array($value)) {
        return 'array';
    }
    if (is_object($value)) {
        return 'object';
    }
    return 'string';
}

function fm_config_store_encode_value($value)
{
    if ($value === null) {
        return 'null';
    }

    $json = json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if (!is_string($json)) {
        return 'null';
    }

    return $json;
}

function fm_config_store_decode_value($json)
{
    $decoded = json_decode((string) $json, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        return null;
    }
    return $decoded;
}

function fm_config_store_json_hash($json)
{
    $json = (string) $json;
    return hash('sha256', $json);
}

function fm_config_store_db_init_schema(SQLite3 $db)
{
    $schema = array(
        'CREATE TABLE IF NOT EXISTS fm_config_scopes (
            scope_type TEXT NOT NULL,
            scope_key TEXT NOT NULL,
            display_name TEXT NOT NULL DEFAULT "",
            current_revision INTEGER NOT NULL DEFAULT 0,
            current_snapshot_id INTEGER NOT NULL DEFAULT 0,
            current_hash TEXT NOT NULL DEFAULT "",
            created_at INTEGER NOT NULL DEFAULT 0,
            created_by TEXT NOT NULL DEFAULT "",
            updated_at INTEGER NOT NULL DEFAULT 0,
            updated_by TEXT NOT NULL DEFAULT "",
            source TEXT NOT NULL DEFAULT "runtime",
            PRIMARY KEY (scope_type, scope_key)
        )',
        'CREATE TABLE IF NOT EXISTS fm_config_entries (
            scope_type TEXT NOT NULL,
            scope_key TEXT NOT NULL,
            config_key TEXT NOT NULL,
            value_json TEXT NOT NULL,
            value_type TEXT NOT NULL DEFAULT "string",
            is_sensitive INTEGER NOT NULL DEFAULT 0,
            source TEXT NOT NULL DEFAULT "runtime",
            revision INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL DEFAULT 0,
            created_by TEXT NOT NULL DEFAULT "",
            updated_at INTEGER NOT NULL DEFAULT 0,
            updated_by TEXT NOT NULL DEFAULT "",
            PRIMARY KEY (scope_type, scope_key, config_key)
        )',
        'CREATE INDEX IF NOT EXISTS idx_fm_config_entries_scope_updated ON fm_config_entries(scope_type, scope_key, updated_at)',
        'CREATE INDEX IF NOT EXISTS idx_fm_config_entries_scope_key ON fm_config_entries(scope_type, scope_key, config_key)',
        'CREATE TABLE IF NOT EXISTS fm_config_snapshots (
            snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scope_type TEXT NOT NULL,
            scope_key TEXT NOT NULL,
            snapshot_label TEXT NOT NULL DEFAULT "",
            snapshot_reason TEXT NOT NULL DEFAULT "",
            payload_json TEXT NOT NULL,
            payload_hash TEXT NOT NULL DEFAULT "",
            created_at INTEGER NOT NULL DEFAULT 0,
            created_by TEXT NOT NULL DEFAULT "",
            source TEXT NOT NULL DEFAULT "runtime",
            restored_from_snapshot_id INTEGER NOT NULL DEFAULT 0,
            revision INTEGER NOT NULL DEFAULT 0
        )',
        'CREATE INDEX IF NOT EXISTS idx_fm_config_snapshots_scope_created ON fm_config_snapshots(scope_type, scope_key, created_at)',
        'CREATE TABLE IF NOT EXISTS fm_config_backups (
            backup_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scope_type TEXT NOT NULL,
            scope_key TEXT NOT NULL,
            source_file TEXT NOT NULL DEFAULT "",
            backup_name TEXT NOT NULL DEFAULT "",
            backup_reason TEXT NOT NULL DEFAULT "",
            backup_json TEXT NOT NULL,
            backup_hash TEXT NOT NULL DEFAULT "",
            created_at INTEGER NOT NULL DEFAULT 0,
            created_by TEXT NOT NULL DEFAULT "",
            source TEXT NOT NULL DEFAULT "runtime"
        )',
        'CREATE INDEX IF NOT EXISTS idx_fm_config_backups_scope_created ON fm_config_backups(scope_type, scope_key, created_at)',
        'CREATE TABLE IF NOT EXISTS fm_config_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scope_type TEXT NOT NULL,
            scope_key TEXT NOT NULL,
            config_key TEXT NOT NULL DEFAULT "",
            event_type TEXT NOT NULL,
            old_value_json TEXT NOT NULL DEFAULT "",
            new_value_json TEXT NOT NULL DEFAULT "",
            created_at INTEGER NOT NULL DEFAULT 0,
            created_by TEXT NOT NULL DEFAULT "",
            source TEXT NOT NULL DEFAULT "runtime",
            message TEXT NOT NULL DEFAULT ""
        )',
        'CREATE INDEX IF NOT EXISTS idx_fm_config_events_scope_created ON fm_config_events(scope_type, scope_key, created_at)',
        'CREATE TABLE IF NOT EXISTS fm_config_migrations (
            migration_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scope_type TEXT NOT NULL,
            scope_key TEXT NOT NULL,
            migration_name TEXT NOT NULL,
            migration_state TEXT NOT NULL DEFAULT "done",
            created_at INTEGER NOT NULL DEFAULT 0,
            created_by TEXT NOT NULL DEFAULT "",
            source TEXT NOT NULL DEFAULT "runtime",
            notes TEXT NOT NULL DEFAULT ""
        )',
        'CREATE INDEX IF NOT EXISTS idx_fm_config_migrations_scope_created ON fm_config_migrations(scope_type, scope_key, created_at)',
    );

    foreach ($schema as $sql) {
        if (!$db->exec($sql)) {
            return false;
        }
    }

    return true;
}

function fm_config_store_db()
{
    static $db = null;
    if ($db instanceof SQLite3) {
        return $db;
    }

    if (!class_exists('SQLite3')) {
        return null;
    }

    try {
        $db = new SQLite3(fm_config_store_db_path());
        $db->busyTimeout(3000);
        if (!fm_config_store_db_init_schema($db)) {
            $db = null;
        }
    } catch (Exception $e) {
        $db = null;
    }

    return $db;
}

function fm_config_store_runtime_keys()
{
    return array(
        'use_auth',
        'machine_login_token',
        'machine_login_user',
        'auth_users',
        'readonly_users',
        'upload_only_users',
        'manager_users',
        'bulk_actions_disabled_users',
        'user_welcome_messages',
        'welcome_message_shown_users',
        'global_readonly',
        'directories_users',
        'user_manager_owners',
        'user_notes',
        'user_home_root',
        'use_highlightjs',
        'highlightjs_style',
        'edit_files',
        'default_timezone',
        'root_path',
        'root_url',
        'http_host',
        'iconv_input_encoding',
        'datetime_format',
        'path_display_mode',
        'allowed_file_extensions',
        'allowed_upload_extensions',
        'favicon_path',
        'exclude_items',
        'online_viewer',
        'docx_preview_mode',
        'sticky_navbar',
        'max_upload_size_bytes',
        'upload_chunk_size_bytes',
        'ip_ruleset',
        'ip_silent',
        'ip_whitelist',
        'ip_blacklist',
        'state_storage_path',
    );
}

function fm_config_store_apply_scope_to_globals($scopeType, $scopeKey, array $keys = array())
{
    $data = fm_config_store_load_scope($scopeType, $scopeKey);
    if (!is_array($data) || empty($data)) {
        return false;
    }

    if (empty($keys)) {
        $keys = array_keys($data);
    }

    foreach ($keys as $key) {
        $key = (string) $key;
        if ($key === '' || !array_key_exists($key, $data)) {
            continue;
        }
        $GLOBALS[$key] = $data[$key];
    }

    return $data;
}

function fm_config_store_load_scope($scopeType, $scopeKey)
{
    $db = fm_config_store_db();
    if (!$db) {
        return false;
    }

    $scopeType = fm_config_store_normalize_scope_type($scopeType);
    $scopeKey = fm_config_store_normalize_scope_key($scopeKey);

    $stmt = $db->prepare('SELECT config_key, value_json FROM fm_config_entries WHERE scope_type = :scope_type AND scope_key = :scope_key ORDER BY config_key ASC');
    if (!$stmt) {
        return false;
    }
    $stmt->bindValue(':scope_type', $scopeType, SQLITE3_TEXT);
    $stmt->bindValue(':scope_key', $scopeKey, SQLITE3_TEXT);
    $result = $stmt->execute();
    if (!$result) {
        return false;
    }

    $data = array();
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        if (!is_array($row) || !isset($row['config_key'])) {
            continue;
        }
        $data[(string) $row['config_key']] = fm_config_store_decode_value(isset($row['value_json']) ? $row['value_json'] : null);
    }
    $result->finalize();

    if (empty($data)) {
        return false;
    }

    return $data;
}

function fm_config_store_load_ui_preferences($username = 'global')
{
    return fm_config_store_load_scope('ui_preferences', $username);
}

function fm_config_store_save_ui_preferences($username, array $values, array $meta = array())
{
    return fm_config_store_save_scope('ui_preferences', $username, $values, $meta);
}

function fm_config_store_save_runtime_config(array $values, array $meta = array())
{
    return fm_config_store_save_scope('runtime_config', 'global', $values, $meta);
}

function fm_config_store_upsert_backup(SQLite3 $db, $scopeType, $scopeKey, array $meta, $payloadJson)
{
    $scopeType = fm_config_store_normalize_scope_type($scopeType);
    $scopeKey = fm_config_store_normalize_scope_key($scopeKey);
    $payloadJson = is_string($payloadJson) ? $payloadJson : '';

    $stmt = $db->prepare('INSERT INTO fm_config_backups
        (scope_type, scope_key, source_file, backup_name, backup_reason, backup_json, backup_hash, created_at, created_by, source)
        VALUES (:scope_type, :scope_key, :source_file, :backup_name, :backup_reason, :backup_json, :backup_hash, :created_at, :created_by, :source)');
    if (!$stmt) {
        return false;
    }

    $stmt->bindValue(':scope_type', $scopeType, SQLITE3_TEXT);
    $stmt->bindValue(':scope_key', $scopeKey, SQLITE3_TEXT);
    $stmt->bindValue(':source_file', isset($meta['source_file']) ? (string) $meta['source_file'] : '', SQLITE3_TEXT);
    $stmt->bindValue(':backup_name', isset($meta['backup_name']) ? (string) $meta['backup_name'] : '', SQLITE3_TEXT);
    $stmt->bindValue(':backup_reason', isset($meta['backup_reason']) ? (string) $meta['backup_reason'] : '', SQLITE3_TEXT);
    $stmt->bindValue(':backup_json', $payloadJson, SQLITE3_TEXT);
    $stmt->bindValue(':backup_hash', fm_config_store_json_hash($payloadJson), SQLITE3_TEXT);
    $stmt->bindValue(':created_at', isset($meta['created_at']) ? (int) $meta['created_at'] : time(), SQLITE3_INTEGER);
    $stmt->bindValue(':created_by', isset($meta['created_by']) ? (string) $meta['created_by'] : '', SQLITE3_TEXT);
    $stmt->bindValue(':source', isset($meta['source']) ? (string) $meta['source'] : 'runtime', SQLITE3_TEXT);

    $result = $stmt->execute();
    if ($result) {
        $result->finalize();
    }
    return $result !== false;
}

function fm_config_store_append_event(SQLite3 $db, $scopeType, $scopeKey, $eventType, $configKey, $oldValueJson, $newValueJson, array $meta = array())
{
    $scopeType = fm_config_store_normalize_scope_type($scopeType);
    $scopeKey = fm_config_store_normalize_scope_key($scopeKey);

    $stmt = $db->prepare('INSERT INTO fm_config_events
        (scope_type, scope_key, config_key, event_type, old_value_json, new_value_json, created_at, created_by, source, message)
        VALUES (:scope_type, :scope_key, :config_key, :event_type, :old_value_json, :new_value_json, :created_at, :created_by, :source, :message)');
    if (!$stmt) {
        return false;
    }

    $stmt->bindValue(':scope_type', $scopeType, SQLITE3_TEXT);
    $stmt->bindValue(':scope_key', $scopeKey, SQLITE3_TEXT);
    $stmt->bindValue(':config_key', (string) $configKey, SQLITE3_TEXT);
    $stmt->bindValue(':event_type', (string) $eventType, SQLITE3_TEXT);
    $stmt->bindValue(':old_value_json', (string) $oldValueJson, SQLITE3_TEXT);
    $stmt->bindValue(':new_value_json', (string) $newValueJson, SQLITE3_TEXT);
    $stmt->bindValue(':created_at', isset($meta['created_at']) ? (int) $meta['created_at'] : time(), SQLITE3_INTEGER);
    $stmt->bindValue(':created_by', isset($meta['created_by']) ? (string) $meta['created_by'] : '', SQLITE3_TEXT);
    $stmt->bindValue(':source', isset($meta['source']) ? (string) $meta['source'] : 'runtime', SQLITE3_TEXT);
    $stmt->bindValue(':message', isset($meta['message']) ? (string) $meta['message'] : '', SQLITE3_TEXT);

    $result = $stmt->execute();
    if ($result) {
        $result->finalize();
    }
    return $result !== false;
}

function fm_config_store_save_scope($scopeType, $scopeKey, array $values, array $meta = array())
{
    $db = fm_config_store_db();
    if (!$db) {
        return array('ok' => false, 'error' => 'Config database is not available.');
    }

    $scopeType = fm_config_store_normalize_scope_type($scopeType);
    $scopeKey = fm_config_store_normalize_scope_key($scopeKey);
    $createdBy = isset($meta['created_by']) ? (string) $meta['created_by'] : '';
    $updatedBy = isset($meta['updated_by']) ? (string) $meta['updated_by'] : $createdBy;
    $source = isset($meta['source']) ? (string) $meta['source'] : 'runtime';
    $label = isset($meta['label']) ? (string) $meta['label'] : '';
    $reason = isset($meta['reason']) ? (string) $meta['reason'] : '';
    $snapshotReason = isset($meta['snapshot_reason']) ? (string) $meta['snapshot_reason'] : $reason;
    $snapshotLabel = isset($meta['snapshot_label']) ? (string) $meta['snapshot_label'] : $label;
    $now = isset($meta['created_at']) ? (int) $meta['created_at'] : time();
    $restoredFromSnapshotId = isset($meta['restored_from_snapshot_id']) ? (int) $meta['restored_from_snapshot_id'] : 0;
    $payloadJson = json_encode($values, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if (!is_string($payloadJson)) {
        $payloadJson = '{}';
    }
    $payloadHash = fm_config_store_json_hash($payloadJson);

    $existingScope = null;
    $scopeStmt = $db->prepare('SELECT scope_type, scope_key, current_revision, current_snapshot_id, current_hash FROM fm_config_scopes WHERE scope_type = :scope_type AND scope_key = :scope_key LIMIT 1');
    if ($scopeStmt) {
        $scopeStmt->bindValue(':scope_type', $scopeType, SQLITE3_TEXT);
        $scopeStmt->bindValue(':scope_key', $scopeKey, SQLITE3_TEXT);
        $scopeResult = $scopeStmt->execute();
        if ($scopeResult) {
            $existingScope = $scopeResult->fetchArray(SQLITE3_ASSOC);
            $scopeResult->finalize();
        }
    }

    $currentRevision = 1;
    if (is_array($existingScope) && isset($existingScope['current_revision'])) {
        $currentRevision = max(1, (int) $existingScope['current_revision'] + 1);
        if ($restoredFromSnapshotId <= 0) {
            $restoredFromSnapshotId = isset($existingScope['current_snapshot_id']) ? (int) $existingScope['current_snapshot_id'] : 0;
        }
    }

    if (!$db->exec('BEGIN IMMEDIATE')) {
        return array('ok' => false, 'error' => 'Failed to start config transaction.');
    }

    try {
        $deleteEntries = $db->prepare('DELETE FROM fm_config_entries WHERE scope_type = :scope_type AND scope_key = :scope_key');
        if (!$deleteEntries) {
            throw new Exception('Failed to prepare config entry cleanup.');
        }
        $deleteEntries->bindValue(':scope_type', $scopeType, SQLITE3_TEXT);
        $deleteEntries->bindValue(':scope_key', $scopeKey, SQLITE3_TEXT);
        if (!$deleteEntries->execute()) {
            throw new Exception('Failed to clear previous config entries.');
        }

        $insertEntry = $db->prepare('INSERT INTO fm_config_entries
            (scope_type, scope_key, config_key, value_json, value_type, is_sensitive, source, revision, created_at, created_by, updated_at, updated_by)
            VALUES (:scope_type, :scope_key, :config_key, :value_json, :value_type, :is_sensitive, :source, :revision, :created_at, :created_by, :updated_at, :updated_by)');
        if (!$insertEntry) {
            throw new Exception('Failed to prepare config entry insert.');
        }

        foreach ($values as $key => $value) {
            $configKey = (string) $key;
            if ($configKey === '') {
                continue;
            }

            $valueJson = fm_config_store_encode_value($value);
            $valueType = fm_config_store_value_type($value);
            $insertEntry->bindValue(':scope_type', $scopeType, SQLITE3_TEXT);
            $insertEntry->bindValue(':scope_key', $scopeKey, SQLITE3_TEXT);
            $insertEntry->bindValue(':config_key', $configKey, SQLITE3_TEXT);
            $insertEntry->bindValue(':value_json', $valueJson, SQLITE3_TEXT);
            $insertEntry->bindValue(':value_type', $valueType, SQLITE3_TEXT);
            $insertEntry->bindValue(':is_sensitive', !empty($meta['sensitive_keys']) && in_array($configKey, (array) $meta['sensitive_keys'], true) ? 1 : 0, SQLITE3_INTEGER);
            $insertEntry->bindValue(':source', $source, SQLITE3_TEXT);
            $insertEntry->bindValue(':revision', $currentRevision, SQLITE3_INTEGER);
            $insertEntry->bindValue(':created_at', $now, SQLITE3_INTEGER);
            $insertEntry->bindValue(':created_by', $createdBy, SQLITE3_TEXT);
            $insertEntry->bindValue(':updated_at', $now, SQLITE3_INTEGER);
            $insertEntry->bindValue(':updated_by', $updatedBy, SQLITE3_TEXT);
            if (!$insertEntry->execute()) {
                throw new Exception('Failed to insert config entry: ' . $configKey);
            }
        }

        $deleteSnapshots = $db->prepare('SELECT snapshot_id FROM fm_config_snapshots WHERE scope_type = :scope_type AND scope_key = :scope_key ORDER BY snapshot_id DESC LIMIT 1');
        $previousSnapshotId = 0;
        if ($deleteSnapshots) {
            $deleteSnapshots->bindValue(':scope_type', $scopeType, SQLITE3_TEXT);
            $deleteSnapshots->bindValue(':scope_key', $scopeKey, SQLITE3_TEXT);
            $snapshotResult = $deleteSnapshots->execute();
            if ($snapshotResult) {
                $snapshotRow = $snapshotResult->fetchArray(SQLITE3_ASSOC);
                $snapshotResult->finalize();
                if (is_array($snapshotRow) && isset($snapshotRow['snapshot_id'])) {
                    $previousSnapshotId = (int) $snapshotRow['snapshot_id'];
                }
            }
        }

        $insertSnapshot = $db->prepare('INSERT INTO fm_config_snapshots
            (scope_type, scope_key, snapshot_label, snapshot_reason, payload_json, payload_hash, created_at, created_by, source, restored_from_snapshot_id, revision)
            VALUES (:scope_type, :scope_key, :snapshot_label, :snapshot_reason, :payload_json, :payload_hash, :created_at, :created_by, :source, :restored_from_snapshot_id, :revision)');
        if (!$insertSnapshot) {
            throw new Exception('Failed to prepare snapshot insert.');
        }
        $insertSnapshot->bindValue(':scope_type', $scopeType, SQLITE3_TEXT);
        $insertSnapshot->bindValue(':scope_key', $scopeKey, SQLITE3_TEXT);
        $insertSnapshot->bindValue(':snapshot_label', $snapshotLabel, SQLITE3_TEXT);
        $insertSnapshot->bindValue(':snapshot_reason', $snapshotReason, SQLITE3_TEXT);
        $insertSnapshot->bindValue(':payload_json', $payloadJson, SQLITE3_TEXT);
        $insertSnapshot->bindValue(':payload_hash', $payloadHash, SQLITE3_TEXT);
        $insertSnapshot->bindValue(':created_at', $now, SQLITE3_INTEGER);
        $insertSnapshot->bindValue(':created_by', $createdBy, SQLITE3_TEXT);
        $insertSnapshot->bindValue(':source', $source, SQLITE3_TEXT);
        $insertSnapshot->bindValue(':restored_from_snapshot_id', $restoredFromSnapshotId, SQLITE3_INTEGER);
        $insertSnapshot->bindValue(':revision', $currentRevision, SQLITE3_INTEGER);
        if (!$insertSnapshot->execute()) {
            throw new Exception('Failed to insert config snapshot.');
        }

        $snapshotId = (int) $db->lastInsertRowID();

        $upsertScope = $db->prepare('INSERT OR REPLACE INTO fm_config_scopes
            (scope_type, scope_key, display_name, current_revision, current_snapshot_id, current_hash, created_at, created_by, updated_at, updated_by, source)
            VALUES (:scope_type, :scope_key, :display_name, :current_revision, :current_snapshot_id, :current_hash, :created_at, :created_by, :updated_at, :updated_by, :source)');
        if (!$upsertScope) {
            throw new Exception('Failed to prepare scope metadata upsert.');
        }
        $upsertScope->bindValue(':scope_type', $scopeType, SQLITE3_TEXT);
        $upsertScope->bindValue(':scope_key', $scopeKey, SQLITE3_TEXT);
        $upsertScope->bindValue(':display_name', $label, SQLITE3_TEXT);
        $upsertScope->bindValue(':current_revision', $currentRevision, SQLITE3_INTEGER);
        $upsertScope->bindValue(':current_snapshot_id', $snapshotId, SQLITE3_INTEGER);
        $upsertScope->bindValue(':current_hash', $payloadHash, SQLITE3_TEXT);
        $upsertScope->bindValue(':created_at', $now, SQLITE3_INTEGER);
        $upsertScope->bindValue(':created_by', $createdBy, SQLITE3_TEXT);
        $upsertScope->bindValue(':updated_at', $now, SQLITE3_INTEGER);
        $upsertScope->bindValue(':updated_by', $updatedBy, SQLITE3_TEXT);
        $upsertScope->bindValue(':source', $source, SQLITE3_TEXT);
        if (!$upsertScope->execute()) {
            throw new Exception('Failed to update scope metadata.');
        }

        if (!empty($meta['source_file']) || !empty($meta['backup_name'])) {
            if (!fm_config_store_upsert_backup($db, $scopeType, $scopeKey, array(
                'source_file' => isset($meta['source_file']) ? (string) $meta['source_file'] : '',
                'backup_name' => isset($meta['backup_name']) ? (string) $meta['backup_name'] : '',
                'backup_reason' => $snapshotReason,
                'created_at' => $now,
                'created_by' => $createdBy,
                'source' => $source,
            ), $payloadJson)) {
                throw new Exception('Failed to insert config backup.');
            }
        }

        if (!fm_config_store_append_event($db, $scopeType, $scopeKey, 'save_scope', '', '', '', array(
            'created_at' => $now,
            'created_by' => $createdBy,
            'source' => $source,
            'message' => $reason,
        ))) {
            throw new Exception('Failed to insert config event.');
        }

        if (!$db->exec('COMMIT')) {
            throw new Exception('Failed to commit config transaction.');
        }

        return array(
            'ok' => true,
            'scope_type' => $scopeType,
            'scope_key' => $scopeKey,
            'revision' => $currentRevision,
            'snapshot_id' => $snapshotId,
            'hash' => $payloadHash,
        );
    } catch (Exception $e) {
        $db->exec('ROLLBACK');
        return array('ok' => false, 'error' => $e->getMessage());
    }
}

function fm_config_store_list_snapshots($scopeType = '', $scopeKey = '', $limit = 20)
{
    $db = fm_config_store_db();
    if (!$db) {
        return array();
    }

    $scopeType = trim((string) $scopeType);
    $scopeKey = trim((string) $scopeKey);
    $limit = (int) $limit;
    if ($limit < 1) {
        $limit = 1;
    }
    if ($limit > 100) {
        $limit = 100;
    }

    $sql = 'SELECT snapshot_id, scope_type, scope_key, snapshot_label, snapshot_reason, payload_json, payload_hash, created_at, created_by, source, restored_from_snapshot_id, revision FROM fm_config_snapshots';
    $where = array();
    if ($scopeType !== '') {
        $where[] = 'scope_type = :scope_type';
    }
    if ($scopeKey !== '') {
        $where[] = 'scope_key = :scope_key';
    }
    if (!empty($where)) {
        $sql .= ' WHERE ' . implode(' AND ', $where);
    }
    $sql .= ' ORDER BY snapshot_id DESC LIMIT :limit';

    $stmt = $db->prepare($sql);
    if (!$stmt) {
        return array();
    }
    if ($scopeType !== '') {
        $stmt->bindValue(':scope_type', $scopeType, SQLITE3_TEXT);
    }
    if ($scopeKey !== '') {
        $stmt->bindValue(':scope_key', $scopeKey, SQLITE3_TEXT);
    }
    $stmt->bindValue(':limit', $limit, SQLITE3_INTEGER);

    $result = $stmt->execute();
    if (!$result) {
        return array();
    }

    $rows = array();
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        if (is_array($row)) {
            $rows[] = $row;
        }
    }
    $result->finalize();
    return $rows;
}

function fm_config_store_get_snapshot($snapshotId)
{
    $db = fm_config_store_db();
    if (!$db) {
        return false;
    }

    $snapshotId = (int) $snapshotId;
    if ($snapshotId < 1) {
        return false;
    }

    $stmt = $db->prepare('SELECT snapshot_id, scope_type, scope_key, snapshot_label, snapshot_reason, payload_json, payload_hash, created_at, created_by, source, restored_from_snapshot_id, revision FROM fm_config_snapshots WHERE snapshot_id = :snapshot_id LIMIT 1');
    if (!$stmt) {
        return false;
    }
    $stmt->bindValue(':snapshot_id', $snapshotId, SQLITE3_INTEGER);
    $result = $stmt->execute();
    if (!$result) {
        return false;
    }
    $row = $result->fetchArray(SQLITE3_ASSOC);
    $result->finalize();
    return is_array($row) ? $row : false;
}

function fm_config_store_restore_snapshot($snapshotId, array $meta = array())
{
    $snapshot = fm_config_store_get_snapshot($snapshotId);
    if (!is_array($snapshot)) {
        return array('ok' => false, 'error' => 'Snapshot not found.');
    }

    $payload = json_decode(isset($snapshot['payload_json']) ? (string) $snapshot['payload_json'] : '', true);
    if (!is_array($payload)) {
        return array('ok' => false, 'error' => 'Snapshot payload is invalid.');
    }

    $meta = array_merge(array(
        'label' => isset($snapshot['snapshot_label']) ? (string) $snapshot['snapshot_label'] : '',
        'reason' => 'restore_snapshot',
        'source' => 'restore',
        'created_by' => isset($meta['created_by']) ? (string) $meta['created_by'] : '',
        'updated_by' => isset($meta['updated_by']) ? (string) $meta['updated_by'] : '',
        'created_at' => time(),
        'snapshot_label' => isset($snapshot['snapshot_label']) ? (string) $snapshot['snapshot_label'] : '',
        'snapshot_reason' => 'Restored from snapshot #' . (int) $snapshot['snapshot_id'],
        'restored_from_snapshot_id' => (int) $snapshot['snapshot_id'],
    ), $meta);

    return fm_config_store_save_scope(
        isset($snapshot['scope_type']) ? (string) $snapshot['scope_type'] : 'ui_preferences',
        isset($snapshot['scope_key']) ? (string) $snapshot['scope_key'] : 'global',
        $payload,
        $meta
    );
}

