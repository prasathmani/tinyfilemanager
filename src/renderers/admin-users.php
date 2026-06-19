<?php
// Read-only user administration overview renderer
// Does not call fm_show_header/footer/exit/session_start

// Defensive: ensure all user arrays exist and are arrays
$auth_users = isset($auth_users) && is_array($auth_users) ? $auth_users : array();
$readonly_users = isset($readonly_users) && is_array($readonly_users) ? $readonly_users : array();
$upload_only_users = isset($upload_only_users) && is_array($upload_only_users) ? $upload_only_users : array();
$manager_users = isset($manager_users) && is_array($manager_users) ? $manager_users : array();
$directories_users = isset($directories_users) && is_array($directories_users) ? $directories_users : array();
$user_manager_owners = isset($user_manager_owners) && is_array($user_manager_owners) ? $user_manager_owners : array();
$is_admin_actor = defined('FM_IS_ADMIN') && FM_IS_ADMIN;
$is_manager_actor = !$is_admin_actor && defined('FM_MANAGER') && FM_MANAGER;
$logged_user = isset($_SESSION[FM_SESSION_ID]['logged']) ? (string) $_SESSION[FM_SESSION_ID]['logged'] : '';
$audit_events = $is_admin_actor && function_exists('fm_admin_read_audit_events') ? fm_admin_read_audit_events(50) : array();
$config_snapshots_enabled = $is_admin_actor && function_exists('fm_config_store_list_snapshots');
$config_file_path = dirname(__DIR__, 2) . '/config.php';
$config_is_writable = is_file($config_file_path) && is_writable($config_file_path);
$fm_admin_return_path = isset($_GET['p']) ? (string) $_GET['p'] : (defined('FM_PATH') ? (string) FM_PATH : '');
$admin_close_label = (isset($lang) && $lang === 'sk') ? 'Zatvoriť' : 'Cancel';
$admin_ajax_token = isset($_SESSION['token']) ? (string) $_SESSION['token'] : '';
$owner_map_choices = array_values(array_unique(array_merge(array('admin'), array_map('strval', $manager_users))));

// Union of all usernames
$usernames = array();
$usernames = array_merge(
    array_keys($auth_users),
    $readonly_users,
    $upload_only_users,
    $manager_users,
    array_keys($directories_users)
);

$usernames = array_unique(array_filter($usernames, 'strlen'));

if (function_exists('fm_admin_normalize_user_manager_owners')) {
    $user_manager_owners = fm_admin_normalize_user_manager_owners($user_manager_owners, $manager_users, $auth_users);
}

if ($is_manager_actor && function_exists('fm_admin_manager_can_manage_user')) {
    $usernames = array_values(array_filter($usernames, function ($u) use ($logged_user, $manager_users, $user_manager_owners) {
        return fm_admin_manager_can_manage_user($logged_user, $u, $manager_users, $user_manager_owners);
    }));
}

sort($usernames, SORT_NATURAL | SORT_FLAG_CASE);

// Escaping helper
if (!function_exists('fm_enc')) {
    function fm_enc($v) { return htmlspecialchars($v, ENT_QUOTES, 'UTF-8'); }
}

function user_type($u, $auth_users, $readonly_users, $upload_only_users, $manager_users, $directories_users) {
    if (in_array($u, $manager_users)) return 'manager';
    if (in_array($u, $upload_only_users)) return 'upload only';
    if (in_array($u, $readonly_users)) return 'read only';
    if (array_key_exists($u, $auth_users)) return 'standard';
    if (array_key_exists($u, $directories_users)) return 'directory mapped';
    return 'unknown';
}

function user_dirs($u, $directories_users) {
    if (!array_key_exists($u, $directories_users)) return 'globálny / podľa hlavnej konfigurácie';
    $dirs = $directories_users[$u];
    if (is_array($dirs)) {
        $out = array();
        foreach ($dirs as $d) {
            $out[] = fm_enc($d);
        }
        return implode('<br>', $out);
    } else {
        return fm_enc($dirs);
    }
}

function user_status($u, $auth_users, $readonly_users, $upload_only_users, $manager_users, $directories_users) {
    $has_pwd = array_key_exists($u, $auth_users);
    $type = user_type($u, $auth_users, $readonly_users, $upload_only_users, $manager_users, $directories_users);
    if ($has_pwd && $type !== 'unknown') return 'OK';
    if (!$has_pwd && ($type !== 'unknown' && $type !== 'directory mapped')) return 'Chýba heslo v auth_users';
    if ($has_pwd && $type === 'standard') return 'Má heslo, ale nemá špecifickú rolu';
    if (!$has_pwd && $type === 'directory mapped') return 'Má adresár, ale nemá heslo';
    return 'N/A';
}

function user_owner_label($u, $user_manager_owners, $manager_users) {
    if (!function_exists('fm_admin_get_user_manager_owner')) {
        return 'admin';
    }
    return fm_admin_get_user_manager_owner($u, $user_manager_owners, $manager_users);
}

?>

<div class="container mt-4">
    <h2>Správa používateľov</h2>
    <p class="text-muted">Prehľad a správa používateľov z aktuálnej konfigurácie.</p>
    <?php if (!$config_is_writable): ?>
        <div class="alert alert-warning">
            <strong>Upozornenie:</strong> Súbor <code>config.php</code> nie je zapisovateľný.
            Operácie New/Edit/Delete sa neuložia, kým web server nezíska právo zápisu.
        </div>
    <?php endif; ?>
    <div class="mb-3 d-flex flex-wrap gap-2">
        <button type="button" class="btn btn-success" data-admin-user-action="new">New user</button>
        <?php if ($is_admin_actor): ?>
            <button type="button" class="btn btn-outline-primary" id="owner-map-preview-btn">Zobraziť mapu zodpovednosti</button>
            <button type="button" class="btn btn-outline-warning" id="owner-map-apply-btn">Uložiť upravenú mapu</button>
            <button type="button" class="btn btn-outline-success" id="owner-map-oneclick-btn">Náhľad + Uložiť + Obnoviť</button>
            <button type="button" class="btn btn-outline-dark" id="config-snapshots-refresh-btn">Snapshoty konfigurácií</button>
        <?php endif; ?>
        <a href="?p=<?php echo urlencode($fm_admin_return_path); ?>" class="btn btn-outline-secondary">
            <i class="fa fa-times-circle" aria-hidden="true"></i>
            <?php echo fm_enc($admin_close_label); ?>
        </a>
    </div>

    <?php if ($is_admin_actor): ?>
        <div class="card mb-3" id="config-snapshots-card" style="display:none;">
            <div class="card-header d-flex flex-wrap justify-content-between align-items-center gap-2">
                <strong>Snapshoty konfigurácií</strong>
                <button type="button" class="btn btn-sm btn-outline-secondary" id="config-snapshots-refresh-inline-btn">Obnoviť zoznam</button>
            </div>
            <div class="card-body">
                <div id="config-snapshots-status" class="text-muted mb-3">Načítavam snapshoty konfigurácií...</div>
                <div class="table-responsive mb-4">
                    <table class="table table-sm table-bordered table-striped align-middle mb-0" id="config-snapshots-runtime-table" style="display:none;">
                        <thead class="table-light">
                            <tr>
                                <th>Snapshot</th>
                                <th>Rev.</th>
                                <th>Vytvorené</th>
                                <th>Kým</th>
                                <th>Hash</th>
                                <th>Akcia</th>
                            </tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
                <div class="table-responsive">
                    <table class="table table-sm table-bordered table-striped align-middle mb-0" id="config-snapshots-ui-table" style="display:none;">
                        <thead class="table-light">
                            <tr>
                                <th>Snapshot</th>
                                <th>Rev.</th>
                                <th>Vytvorené</th>
                                <th>Kým</th>
                                <th>Hash</th>
                                <th>Akcia</th>
                            </tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="card mb-3" id="owner-map-card" style="display:none;">
            <div class="card-header d-flex flex-wrap justify-content-between align-items-center gap-2">
                <strong>Mapa zodpovednosti (owner map)</strong>
                <div class="d-flex flex-wrap align-items-center gap-3">
                    <div class="form-check m-0">
                        <input class="form-check-input" type="checkbox" id="owner-map-rebuild">
                        <label class="form-check-label" for="owner-map-rebuild">Prepísať aj existujúce owner priradenia (rebuild)</label>
                    </div>
                    <div class="form-check m-0">
                        <input class="form-check-input" type="checkbox" id="owner-map-only-changes">
                        <label class="form-check-label" for="owner-map-only-changes">Len riadky so zmenou</label>
                    </div>
                    <button type="button" class="btn btn-sm btn-outline-secondary" id="owner-map-export-json-btn">Export JSON</button>
                </div>
            </div>
            <div class="card-body p-0">
                <div id="owner-map-status" class="p-3 text-muted">Klikni na "Zobraziť mapu zodpovednosti" pre náhľad a úpravu vlastníctva.</div>
                <div class="table-responsive">
                    <table class="table table-sm table-bordered table-striped mb-0 align-middle" id="owner-map-table" style="display:none;">
                        <thead class="table-light">
                            <tr>
                                <th>Používateľ</th>
                                <th>Aktuálny owner</th>
                                <th>Nový owner</th>
                                <th>Stav</th>
                                <th>Dôvod</th>
                            </tr>
                        </thead>
                        <tbody id="owner-map-body"></tbody>
                    </table>
                </div>
            </div>
        </div>
    <?php endif; ?>
    <div class="table-responsive">
        <table class="table table-bordered table-striped table-sm align-middle">
            <thead class="table-light">
                <tr>
                    <th>Používateľ</th>
                    <th>Typ prístupu</th>
                    <th>Heslo v konfigurácii</th>
                    <th>Priradené adresáre</th>
                    <th>Stav / poznámka</th>
                    <th>Zodpovednosť</th>
                    <th>Akcia</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($usernames as $u): ?>
                <?php
                    $can_edit_user = !$is_manager_actor
                        || (function_exists('fm_admin_manager_can_manage_user') && fm_admin_manager_can_manage_user($logged_user, $u, $manager_users, $user_manager_owners));
                ?>
                <tr>
                    <td><?php echo fm_enc($u); ?></td>
                    <td><?php echo fm_enc(user_type($u, $auth_users, $readonly_users, $upload_only_users, $manager_users, $directories_users)); ?></td>
                    <td><?php echo array_key_exists($u, $auth_users) ? 'áno' : 'nie'; ?></td>
                    <td><?php echo user_dirs($u, $directories_users); ?></td>
                    <td><?php echo fm_enc(user_status($u, $auth_users, $readonly_users, $upload_only_users, $manager_users, $directories_users)); ?></td>
                    <td><?php echo fm_enc(user_owner_label($u, $user_manager_owners, $manager_users)); ?></td>
                    <td>
                        <?php if ($can_edit_user): ?>
                            <button type="button" class="btn btn-sm btn-primary" data-admin-user-action="edit" data-username="<?php echo fm_enc($u); ?>">Edit</button>
                        <?php else: ?>
                            <span class="text-muted small">Bez oprávnenia</span>
                        <?php endif; ?>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <?php if (!$is_admin_actor): ?>
        <div class="alert alert-info mt-3">
            Manažér môže vytvárať, upravovať a mazať iba používateľov, ktorí sú priradení pod jeho zodpovednosť.
        </div>
    <?php endif; ?>

    <?php if ($is_admin_actor): ?>
    <div class="card mt-4">
        <div class="card-header">
            <strong>Audit</strong> <span class="text-muted">(posledných <?php echo count($audit_events); ?> záznamov)</span>
        </div>
        <div class="card-body p-0">
            <?php if (empty($audit_events)): ?>
                <div class="p-3 text-muted">Zatiaľ nie sú dostupné žiadne audit záznamy.</div>
            <?php else: ?>
                <div class="p-3 border-bottom bg-light-subtle">
                    <div class="row g-2 align-items-end">
                        <div class="col-sm-4 col-md-3">
                            <label for="audit-filter-action" class="form-label mb-1">Akcia</label>
                            <select id="audit-filter-action" class="form-select form-select-sm">
                                <option value="">Všetky</option>
                                <option value="user_save">user_save</option>
                                <option value="user_delete">user_delete</option>
                            </select>
                        </div>
                        <div class="col-sm-8 col-md-5">
                            <label for="audit-filter-text" class="form-label mb-1">Hľadať</label>
                            <input id="audit-filter-text" type="text" class="form-control form-control-sm" placeholder="meno, IP, meta...">
                        </div>
                        <div class="col-md-4 text-md-end">
                            <div class="d-flex gap-2 justify-content-md-end">
                                <button type="button" id="audit-filter-clear" class="btn btn-sm btn-outline-secondary">Vyčistiť filtre</button>
                                <button type="button" id="audit-export-csv" class="btn btn-sm btn-outline-primary">Export CSV</button>
                            </div>
                            <small id="audit-filter-count" class="text-muted d-block mt-1"></small>
                        </div>
                    </div>
                </div>
                <div class="table-responsive">
                    <table class="table table-sm table-bordered table-striped mb-0 align-middle">
                        <thead class="table-light">
                            <tr>
                                <th>Čas</th>
                                <th>Akcia</th>
                                <th>Kto</th>
                                <th>Cieľový používateľ</th>
                                <th>IP</th>
                                <th>Meta</th>
                            </tr>
                        </thead>
                        <tbody id="audit-table-body">
                            <?php foreach ($audit_events as $ev): ?>
                                <?php
                                $ev_ts = isset($ev['ts']) ? (string) $ev['ts'] : '';
                                $ev_action = isset($ev['action']) ? (string) $ev['action'] : '';
                                $ev_actor = isset($ev['actor']) ? (string) $ev['actor'] : '';
                                $ev_target = isset($ev['target']) ? (string) $ev['target'] : '';
                                $ev_ip = isset($ev['ip']) ? (string) $ev['ip'] : '';
                                $ev_meta = isset($ev['meta']) && is_array($ev['meta']) ? $ev['meta'] : array();
                                $ev_meta_text = '';
                                if (!empty($ev_meta)) {
                                    $meta_parts = array();
                                    foreach ($ev_meta as $mk => $mv) {
                                        if (is_bool($mv)) {
                                            $mv = $mv ? 'true' : 'false';
                                        } elseif (is_array($mv)) {
                                            $mv = json_encode($mv, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                                        }
                                        $meta_parts[] = (string) $mk . '=' . (string) $mv;
                                    }
                                    $ev_meta_text = implode('; ', $meta_parts);
                                }
                                ?>
                                <tr data-audit-action="<?php echo fm_enc($ev_action); ?>" data-audit-search="<?php echo fm_enc(strtolower($ev_ts . ' ' . $ev_action . ' ' . $ev_actor . ' ' . $ev_target . ' ' . $ev_ip . ' ' . $ev_meta_text)); ?>">
                                    <td><?php echo fm_enc($ev_ts); ?></td>
                                    <td><?php echo fm_enc($ev_action); ?></td>
                                    <td><?php echo fm_enc($ev_actor); ?></td>
                                    <td><?php echo fm_enc($ev_target); ?></td>
                                    <td><?php echo fm_enc($ev_ip); ?></td>
                                    <td><?php echo fm_enc($ev_meta_text); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </div>
    </div>
    <?php endif; ?>

    <div id="admin-user-modal-container"></div>
        <script>
        document.addEventListener('DOMContentLoaded', function () {
            var ownerMapChoices = <?php echo json_encode($owner_map_choices, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES); ?>;

            function forEachNode(list, cb) {
                if (!list || typeof cb !== 'function') {
                    return;
                }
                for (var i = 0; i < list.length; i++) {
                    cb(list[i], i);
                }
            }

            function hasClass(el, className) {
                if (!el || !className) {
                    return false;
                }
                if (el.classList && typeof el.classList.contains === 'function') {
                    return el.classList.contains(className);
                }
                var cls = ' ' + String(el.className || '') + ' ';
                return cls.indexOf(' ' + className + ' ') !== -1;
            }

            function findByIdOrAncestorId(startEl, targetId) {
                var el = startEl;
                while (el && el !== document) {
                    if (el.id === targetId) {
                        return el;
                    }
                    el = el.parentNode;
                }
                return null;
            }

            function executeInjectedScripts(rootEl) {
                if (!rootEl) {
                    return;
                }
                var scripts = rootEl.querySelectorAll('script');
                forEachNode(scripts, function (oldScript) {
                    var newScript = document.createElement('script');
                    if (oldScript.src) {
                        newScript.src = oldScript.src;
                    } else {
                        newScript.textContent = oldScript.textContent;
                    }
                    oldScript.parentNode.replaceChild(newScript, oldScript);
                });
            }

            var auditAction = document.getElementById('audit-filter-action');
            var auditText = document.getElementById('audit-filter-text');
            var auditCount = document.getElementById('audit-filter-count');
            var auditClear = document.getElementById('audit-filter-clear');
            var auditExport = document.getElementById('audit-export-csv');
            var auditRows = document.querySelectorAll('#audit-table-body tr');

            function applyAuditFilters() {
                if (!auditRows || !auditRows.length) {
                    return;
                }
                var actionVal = auditAction ? String(auditAction.value || '') : '';
                var textVal = auditText ? String(auditText.value || '').trim().toLowerCase() : '';
                var shown = 0;

                forEachNode(auditRows, function (row) {
                    var rowAction = row.getAttribute('data-audit-action') || '';
                    var rowSearch = row.getAttribute('data-audit-search') || '';
                    var matchAction = !actionVal || rowAction === actionVal;
                    var matchText = !textVal || rowSearch.indexOf(textVal) !== -1;
                    var visible = matchAction && matchText;
                    row.style.display = visible ? '' : 'none';
                    if (visible) {
                        shown++;
                    }
                });

                if (auditCount) {
                    auditCount.textContent = 'Zobrazené: ' + shown + ' / ' + auditRows.length;
                }
            }

            if (auditAction) {
                auditAction.addEventListener('change', applyAuditFilters);
            }
            if (auditText) {
                auditText.addEventListener('input', applyAuditFilters);
            }
            if (auditClear) {
                auditClear.addEventListener('click', function () {
                    if (auditAction) {
                        auditAction.value = '';
                    }
                    if (auditText) {
                        auditText.value = '';
                    }
                    applyAuditFilters();
                });
            }

            if (auditExport) {
                auditExport.addEventListener('click', function () {
                    if (!auditRows || !auditRows.length) {
                        return;
                    }

                    function csvEscape(value) {
                        var s = String(value == null ? '' : value);
                        return '"' + s.replace(/"/g, '""') + '"';
                    }

                    var header = ['Cas', 'Akcia', 'Kto', 'Cielovy pouzivatel', 'IP', 'Meta'];
                    var lines = [header.map(csvEscape).join(',')];

                    forEachNode(auditRows, function (row) {
                        if (row.style.display === 'none') {
                            return;
                        }
                        var cells = row.querySelectorAll('td');
                        if (!cells || cells.length < 6) {
                            return;
                        }
                        var rowData = [];
                        for (var i = 0; i < 6; i++) {
                            rowData.push(csvEscape(cells[i].textContent || ''));
                        }
                        lines.push(rowData.join(','));
                    });

                    if (lines.length <= 1) {
                        return;
                    }

                    var csv = lines.join('\n');
                    var blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
                    var url = URL.createObjectURL(blob);
                    var a = document.createElement('a');
                    var now = new Date();
                    var stamp = now.getFullYear().toString()
                        + String(now.getMonth() + 1).padStart(2, '0')
                        + String(now.getDate()).padStart(2, '0')
                        + '_'
                        + String(now.getHours()).padStart(2, '0')
                        + String(now.getMinutes()).padStart(2, '0')
                        + String(now.getSeconds()).padStart(2, '0');
                    a.href = url;
                    a.download = 'admin_audit_' + stamp + '.csv';
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                });
            }
            applyAuditFilters();

            var container = document.getElementById('admin-user-modal-container');
            if (!container) {
                console.error('Missing modal container: #admin-user-modal-container');
                return;
            }

            var ownerMapCard = document.getElementById('owner-map-card');
            var ownerMapPreviewBtn = document.getElementById('owner-map-preview-btn');
            var ownerMapApplyBtn = document.getElementById('owner-map-apply-btn');
            var ownerMapOneclickBtn = document.getElementById('owner-map-oneclick-btn');
            var configSnapshotsRefreshBtn = document.getElementById('config-snapshots-refresh-btn');
            var configSnapshotsRefreshInlineBtn = document.getElementById('config-snapshots-refresh-inline-btn');
            var configSnapshotsCard = document.getElementById('config-snapshots-card');
            var configSnapshotsStatus = document.getElementById('config-snapshots-status');
            var configSnapshotsRuntimeTable = document.getElementById('config-snapshots-runtime-table');
            var configSnapshotsUiTable = document.getElementById('config-snapshots-ui-table');
            var ownerMapRebuild = document.getElementById('owner-map-rebuild');
            var ownerMapOnlyChanges = document.getElementById('owner-map-only-changes');
            var ownerMapExportJsonBtn = document.getElementById('owner-map-export-json-btn');
            var ownerMapStatus = document.getElementById('owner-map-status');
            var ownerMapTable = document.getElementById('owner-map-table');
            var ownerMapBody = document.getElementById('owner-map-body');
            var ownerMapLastRows = [];
            var configSnapshotsEnabled = <?php echo $config_snapshots_enabled ? 'true' : 'false'; ?>;
            var configSnapshotToken = '<?php echo fm_enc($admin_ajax_token); ?>';

            function normalizeOwnerValue(value) {
                var normalized = String(value == null ? '' : value).trim();
                for (var i = 0; i < ownerMapChoices.length; i++) {
                    if (String(ownerMapChoices[i]) === normalized) {
                        return normalized;
                    }
                }
                return 'admin';
            }

            function escapeHtml(value) {
                return String(value == null ? '' : value)
                    .replace(/&/g, '&amp;')
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;')
                    .replace(/"/g, '&quot;')
                    .replace(/'/g, '&#39;');
            }

            function formatSnapshotTime(ts) {
                var numericTs = Number(ts || 0);
                if (!numericTs) {
                    return '-';
                }

                try {
                    return new Date(numericTs * 1000).toLocaleString();
                } catch (e) {
                    return '-';
                }
            }

            function renderOwnerMapRows(rows) {
                if (!ownerMapBody || !ownerMapTable) {
                    return;
                }

                ownerMapLastRows = Array.isArray(rows) ? rows.slice() : [];
                var onlyChanges = !!(ownerMapOnlyChanges && ownerMapOnlyChanges.checked);
                var visibleRows = onlyChanges
                    ? ownerMapLastRows.filter(function (row) { return !!row.changed; })
                    : ownerMapLastRows;

                var html = '';
                forEachNode(visibleRows, function (row) {
                    var changed = !!row.changed;
                    var username = String(row.username || '');
                    var newOwner = normalizeOwnerValue(row.new_owner || 'admin');
                    var ownerOptions = '';
                    forEachNode(ownerMapChoices, function (choice) {
                        var selected = String(choice) === newOwner ? ' selected' : '';
                        ownerOptions += '<option value="' + escapeHtml(choice) + '"' + selected + '>' + escapeHtml(choice) + '</option>';
                    });
                    html += '<tr>'
                        + '<td>' + escapeHtml(username) + '</td>'
                        + '<td>' + escapeHtml(row.current_owner || '-') + '</td>'
                        + '<td>'
                        + '<select class="form-select form-select-sm owner-map-owner-select" data-owner-username="' + escapeHtml(username) + '">' + ownerOptions + '</select>'
                        + '<button type="button" class="btn btn-link btn-sm p-0 mt-1" data-admin-user-action="edit" data-username="' + escapeHtml(username) + '">Upraviť používateľa</button>'
                        + '</td>'
                        + '<td>' + (changed ? '<span class="badge text-bg-warning">zmena</span>' : '<span class="badge text-bg-light border">bez zmeny</span>') + '</td>'
                        + '<td><small>' + escapeHtml(row.reason || '') + '</small></td>'
                        + '</tr>';
                });

                ownerMapBody.innerHTML = html;
                ownerMapTable.style.display = visibleRows && visibleRows.length ? '' : 'none';
            }

            function renderConfigSnapshotRows(tableEl, rows, scopeLabel) {
                if (!tableEl) {
                    return;
                }

                var tbody = tableEl.querySelector('tbody');
                if (!tbody) {
                    return;
                }

                var html = '';
                forEachNode(Array.isArray(rows) ? rows : [], function (row) {
                    var snapshotId = Number(row.snapshot_id || 0);
                    html += '<tr>'
                        + '<td>' + escapeHtml(String(row.snapshot_label || scopeLabel || 'snapshot')) + '</td>'
                        + '<td>' + escapeHtml(String(row.revision || '-')) + '</td>'
                        + '<td>' + escapeHtml(formatSnapshotTime(row.created_at || 0)) + '</td>'
                        + '<td>' + escapeHtml(String(row.created_by || '-')) + '</td>'
                        + '<td><code>' + escapeHtml(String(row.payload_hash || '').substring(0, 12)) + '</code></td>'
                        + '<td><button type="button" class="btn btn-sm btn-danger" data-config-restore-snapshot="' + snapshotId + '">Obnoviť</button></td>'
                        + '</tr>';
                });

                tbody.innerHTML = html;
                tableEl.style.display = html ? '' : 'none';
            }

            function refreshConfigSnapshots() {
                if (!configSnapshotsCard || !configSnapshotsStatus) {
                    return;
                }

                configSnapshotsCard.style.display = '';
                configSnapshotsStatus.textContent = 'Načítavam snapshoty konfigurácií...';

                var url = window.location.pathname + '?p=' + encodeURIComponent(getCurrentPath()) + '&admin_config_snapshots=1';
                fetch(url, {
                    method: 'GET',
                    headers: { 'X-Requested-With': 'XMLHttpRequest' },
                    credentials: 'same-origin'
                })
                    .then(function (resp) {
                        return resp.json().catch(function () {
                            return { ok: false, error: 'Unexpected server response' };
                        });
                    })
                    .then(function (payload) {
                        if (!payload || !payload.ok || !payload.data) {
                            throw new Error((payload && payload.error) ? payload.error : 'Snapshot list failed.');
                        }

                        var runtimeRows = Array.isArray(payload.data.runtime_config) ? payload.data.runtime_config : [];
                        var uiRows = Array.isArray(payload.data.ui_preferences) ? payload.data.ui_preferences : [];
                        renderConfigSnapshotRows(configSnapshotsRuntimeTable, runtimeRows, 'runtime_config');
                        renderConfigSnapshotRows(configSnapshotsUiTable, uiRows, 'ui_preferences');
                        configSnapshotsStatus.textContent = 'Snapshoty načítané. Runtime: ' + runtimeRows.length + ', UI: ' + uiRows.length + '.';
                    })
                    .catch(function (err) {
                        configSnapshotsStatus.textContent = 'Chyba: ' + String(err && err.message ? err.message : err);
                    });
            }

            function restoreConfigSnapshot(snapshotId) {
                var id = Number(snapshotId || 0);
                if (!id) {
                    return;
                }

                if (!window.confirm('Naozaj chceš obnoviť tento snapshot konfigurácie?')) {
                    return;
                }

                if (configSnapshotsStatus) {
                    configSnapshotsStatus.textContent = 'Obnovujem snapshot #' + id + '...';
                }

                var fd = new FormData();
                fd.append('token', configSnapshotToken);
                fd.append('snapshot_id', String(id));

                var url = window.location.pathname + '?p=' + encodeURIComponent(getCurrentPath()) + '&admin_config_snapshots=1';
                fetch(url, {
                    method: 'POST',
                    body: fd,
                    headers: { 'X-Requested-With': 'XMLHttpRequest' },
                    credentials: 'same-origin'
                })
                    .then(function (resp) {
                        return resp.json().catch(function () {
                            return { ok: false, error: 'Unexpected server response' };
                        });
                    })
                    .then(function (payload) {
                        if (!payload || !payload.ok) {
                            throw new Error((payload && payload.error) ? payload.error : 'Restore failed.');
                        }

                        if (configSnapshotsStatus) {
                            configSnapshotsStatus.textContent = 'Snapshot obnovený.';
                        }
                        window.location.reload();
                    })
                    .catch(function (err) {
                        if (configSnapshotsStatus) {
                            configSnapshotsStatus.textContent = 'Chyba: ' + String(err && err.message ? err.message : err);
                        }
                    });
            }

            function buildOwnerMapJson(rows) {
                var map = {};
                forEachNode(rows, function (row) {
                    var username = String(row && row.username ? row.username : '').trim();
                    var owner = normalizeOwnerValue(row && row.new_owner ? row.new_owner : 'admin');
                    if (!username || !owner) {
                        return;
                    }
                    map[username] = owner;
                });
                return map;
            }

            function syncOwnerMapModelFromDom() {
                if (!ownerMapBody || !ownerMapLastRows || !ownerMapLastRows.length) {
                    return;
                }

                var selects = ownerMapBody.querySelectorAll('.owner-map-owner-select');
                forEachNode(selects, function (selectEl) {
                    var username = selectEl.getAttribute('data-owner-username') || '';
                    var newOwner = normalizeOwnerValue(selectEl.value);
                    if (!username) {
                        return;
                    }

                    for (var i = 0; i < ownerMapLastRows.length; i++) {
                        if (String(ownerMapLastRows[i].username || '') === username) {
                            ownerMapLastRows[i].new_owner = newOwner;
                            ownerMapLastRows[i].changed = String(ownerMapLastRows[i].current_owner || '-') !== newOwner;
                            break;
                        }
                    }
                });
            }

            function downloadTextFile(filename, content, mimeType) {
                var blob = new Blob([content], { type: mimeType || 'text/plain;charset=utf-8;' });
                var url = URL.createObjectURL(blob);
                var a = document.createElement('a');
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            }

            function ownerMapRequest(apply) {
                if (!ownerMapCard || !ownerMapStatus) {
                    return;
                }

                var rebuild = ownerMapRebuild && ownerMapRebuild.checked ? '1' : '0';
                var path = getCurrentPath();
                ownerMapCard.style.display = '';
                ownerMapStatus.textContent = apply ? 'Aplikujem mapovanie...' : 'Načítavam mapu...';

                var url = window.location.pathname + '?p=' + encodeURIComponent(path) + '&admin_users_owner_map=1&rebuild=' + encodeURIComponent(rebuild);
                var fetchOptions = {
                    method: apply ? 'POST' : 'GET',
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    credentials: 'same-origin'
                };

                if (apply) {
                    syncOwnerMapModelFromDom();
                    var fd = new FormData();
                    fd.append('token', '<?php echo fm_enc($admin_ajax_token); ?>');
                    fd.append('rebuild', rebuild);
                    fd.append('owners_json', JSON.stringify(buildOwnerMapJson(ownerMapLastRows)));
                    fetchOptions.body = fd;
                }

                return fetch(url, fetchOptions)
                    .then(function (resp) {
                        return resp.json().catch(function () {
                            return { ok: false, error: 'Unexpected server response' };
                        });
                    })
                    .then(function (payload) {
                        if (!payload || !payload.ok || !payload.data) {
                            throw new Error((payload && payload.error) ? payload.error : 'Owner map request failed.');
                        }

                        var rows = Array.isArray(payload.data.rows) ? payload.data.rows : [];
                        var summary = payload.data.summary || {};
                        renderOwnerMapRows(rows);

                        var changed = Number(summary.changed || 0);
                        var total = Number(summary.users_total || 0);
                        ownerMapStatus.textContent = (apply ? 'Mapovanie uložené. ' : 'Náhľad mapy. ')
                            + 'Používatelia: ' + total + ', zmeny: ' + changed + '.';

                        if (apply) {
                            window.setTimeout(function () {
                                window.location.reload();
                            }, 350);
                        }
                    })
                    .catch(function (err) {
                        ownerMapStatus.textContent = 'Chyba: ' + String(err && err.message ? err.message : err);
                        if (ownerMapTable) {
                            ownerMapTable.style.display = 'none';
                        }
                    });
            }

            if (ownerMapPreviewBtn) {
                ownerMapPreviewBtn.addEventListener('click', function () {
                    ownerMapRequest(false);
                });
            }

            if (configSnapshotsRefreshBtn) {
                configSnapshotsRefreshBtn.addEventListener('click', refreshConfigSnapshots);
            }

            if (configSnapshotsRefreshInlineBtn) {
                configSnapshotsRefreshInlineBtn.addEventListener('click', refreshConfigSnapshots);
            }

            if (ownerMapOnlyChanges) {
                ownerMapOnlyChanges.addEventListener('change', function () {
                    syncOwnerMapModelFromDom();
                    renderOwnerMapRows(ownerMapLastRows);
                });
            }

            if (ownerMapExportJsonBtn) {
                ownerMapExportJsonBtn.addEventListener('click', function () {
                    syncOwnerMapModelFromDom();
                    if (!ownerMapLastRows || !ownerMapLastRows.length) {
                        ownerMapStatus.textContent = 'Najprv načítaj mapu cez náhľad.';
                        return;
                    }

                    var map = buildOwnerMapJson(ownerMapLastRows);
                    var json = JSON.stringify(map, null, 2) + '\n';
                    var now = new Date();
                    var stamp = now.getFullYear().toString()
                        + String(now.getMonth() + 1).padStart(2, '0')
                        + String(now.getDate()).padStart(2, '0')
                        + '_'
                        + String(now.getHours()).padStart(2, '0')
                        + String(now.getMinutes()).padStart(2, '0')
                        + String(now.getSeconds()).padStart(2, '0');
                    downloadTextFile('manager-assignments_' + stamp + '.json', json, 'application/json;charset=utf-8;');
                });
            }

            if (ownerMapApplyBtn) {
                ownerMapApplyBtn.addEventListener('click', function () {
                    if (!window.confirm('Naozaj chceš uložiť ručne upravenú mapu ownerov?')) {
                        return;
                    }
                    syncOwnerMapModelFromDom();
                    ownerMapRequest(true);
                });
            }

            if (ownerMapOneclickBtn) {
                ownerMapOneclickBtn.addEventListener('click', function () {
                    if (!window.confirm('Spustiť postup Náhľad → Uložiť → Obnoviť?')) {
                        return;
                    }

                    ownerMapRequest(false)
                        .then(function () {
                            syncOwnerMapModelFromDom();
                            var changedCount = 0;
                            forEachNode(ownerMapLastRows, function (row) {
                                if (row && row.changed) {
                                    changedCount++;
                                }
                            });

                            if (changedCount === 0) {
                                ownerMapStatus.textContent = 'Náhľad hotový. Žiadne zmeny na aplikovanie.';
                                return;
                            }

                            return ownerMapRequest(true);
                        })
                        .catch(function (err) {
                            ownerMapStatus.textContent = 'Chyba one-click: ' + String(err && err.message ? err.message : err);
                        });
                });
            }

            if (ownerMapBody) {
                ownerMapBody.addEventListener('change', function (e) {
                    var target = e.target || null;
                    if (!target || !target.classList || !target.classList.contains('owner-map-owner-select')) {
                        return;
                    }
                    syncOwnerMapModelFromDom();
                    renderOwnerMapRows(ownerMapLastRows);
                });
            }

            document.addEventListener('click', function (e) {
                var target = e.target;
                if (!target || typeof target.closest !== 'function') {
                    return;
                }

                var restoreBtn = target.closest('[data-config-restore-snapshot]');
                if (!restoreBtn) {
                    return;
                }

                e.preventDefault();
                restoreConfigSnapshot(restoreBtn.getAttribute('data-config-restore-snapshot'));
            });

            if (configSnapshotsEnabled && configSnapshotsCard) {
                refreshConfigSnapshots();
            }

            function showModalError(message) {
                var err = document.getElementById('admin-user-modal-error');
                if (!err) {
                    return;
                }
                err.textContent = message || 'Operation failed.';
                err.classList.remove('d-none');
            }

            function clearModalError() {
                var err = document.getElementById('admin-user-modal-error');
                if (!err) {
                    return;
                }
                err.textContent = '';
                err.classList.add('d-none');
            }

            function getCurrentPath() {
                try {
                    if (typeof URL === 'function') {
                        var url = new URL(window.location.href);
                        if (url.searchParams && typeof url.searchParams.get === 'function') {
                            return url.searchParams.get('p') || '';
                        }
                    }
                } catch (e) {
                }

                var query = String(window.location.search || '');
                if (query.indexOf('?') === 0) {
                    query = query.substring(1);
                }
                if (!query) {
                    return '';
                }
                var parts = query.split('&');
                for (var i = 0; i < parts.length; i++) {
                    var kv = parts[i].split('=');
                    if (decodeURIComponent(kv[0] || '') === 'p') {
                        return decodeURIComponent((kv[1] || '').replace(/\+/g, ' '));
                    }
                }
                return '';
            }

            document.addEventListener('submit', function (e) {
                var form = e.target;
                if (!form || form.id !== 'admin-user-modal-form') {
                    return;
                }

                e.preventDefault();
                clearModalError();

                var fd = new FormData(form);
                var pwd = String(fd.get('password') || '');
                var pwd2 = String(fd.get('password2') || '');
                if (pwd !== pwd2) {
                    showModalError('Passwords do not match.');
                    return;
                }

                var saveUrl = window.location.pathname + '?p=' + encodeURIComponent(getCurrentPath()) + '&admin_users_save=1';
                fetch(saveUrl, {
                    method: 'POST',
                    body: fd,
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    credentials: 'same-origin'
                })
                    .then(function (resp) {
                        return resp.json().catch(function () {
                            return { ok: false, error: 'Unexpected server response' };
                        });
                    })
                    .then(function (data) {
                        if (!data || !data.ok) {
                            showModalError((data && data.error) ? data.error : 'Save failed.');
                            return;
                        }
                        window.location.reload();
                    })
                    .catch(function () {
                        showModalError('Save request failed.');
                    });
            });

            document.addEventListener('click', function (e) {
                var btn = e.target;
                if (!btn) {
                    return;
                }

                var deleteBtn = findByIdOrAncestorId(btn, 'admin-user-delete-btn');
                if (!deleteBtn) {
                    return;
                }

                e.preventDefault();
                clearModalError();

                var usernameInput = document.getElementById('admin-username');
                var tokenInput = document.querySelector('#admin-user-modal-form input[name="token"]');
                var username = usernameInput ? String(usernameInput.value || '') : '';
                var token = tokenInput ? String(tokenInput.value || '') : '';
                if (!username || !token) {
                    showModalError('Missing username or token.');
                    return;
                }

                if (!window.confirm('Naozaj chceš vymazať užívateľa "' + username + '"?')) {
                    return;
                }

                var fd = new FormData();
                fd.append('username', username);
                fd.append('token', token);

                var deleteUrl = window.location.pathname + '?p=' + encodeURIComponent(getCurrentPath()) + '&admin_users_delete=1';
                fetch(deleteUrl, {
                    method: 'POST',
                    body: fd,
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    credentials: 'same-origin'
                })
                    .then(function (resp) {
                        return resp.json().catch(function () {
                            return { ok: false, error: 'Unexpected server response' };
                        });
                    })
                    .then(function (data) {
                        if (!data || !data.ok) {
                            showModalError((data && data.error) ? data.error : 'Delete failed.');
                            return;
                        }
                        window.location.reload();
                    })
                    .catch(function () {
                        showModalError('Delete request failed.');
                    });
            });

            function handleModalAction(btn) {
                if (!btn) {
                    return;
                }
                var action = btn.getAttribute('data-admin-user-action');
                var username = btn.getAttribute('data-username') || '';
                var path = getCurrentPath();
                var params = new URLSearchParams();
                params.set('p', path);
                if (action === 'new') {
                    params.set('admin_users_modal', 'new');
                } else if (action === 'edit') {
                    params.set('admin_users_modal', 'edit');
                    params.set('user', username);
                } else {
                    console.error('Unknown admin-user action:', action);
                    return;
                }
                var url = window.location.pathname + '?' + params.toString();
                fetch(url, { credentials: 'same-origin' })
                    .then(function (resp) {
                        if (!resp.ok) throw new Error('Failed to fetch modal: ' + resp.status);
                        return resp.text();
                    })
                    .then(function (html) {
                        if (!html) {
                            console.error('Empty modal response');
                            return;
                        }
                        container.innerHTML = html;
                        executeInjectedScripts(container);
                        var modalEl = document.getElementById('adminUserModal');
                        if (!modalEl) {
                            console.error('Missing adminUserModal element in response');
                            return;
                        }
                        if (typeof bootstrap === 'undefined' || typeof bootstrap.Modal !== 'function') {
                            console.error('Bootstrap modal API is not available.');
                            return;
                        }
                        var modal = new bootstrap.Modal(modalEl);
                        modal.show();
                    })
                    .catch(function (err) {
                        console.error('Failed to load admin user modal:', err);
                    });
            }

            document.addEventListener('click', function (e) {
                var target = e.target;
                if (!target || typeof target.closest !== 'function') {
                    return;
                }

                var actionBtn = target.closest('[data-admin-user-action]');
                if (!actionBtn) {
                    return;
                }

                e.preventDefault();
                handleModalAction(actionBtn);
            });
        });
        </script>
