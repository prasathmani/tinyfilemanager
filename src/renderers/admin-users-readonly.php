<?php
// Read-only user administration overview renderer
// Does not call fm_show_header/footer/exit/session_start

// Defensive: ensure all user arrays exist and are arrays
$auth_users = isset($auth_users) && is_array($auth_users) ? $auth_users : array();
$readonly_users = isset($readonly_users) && is_array($readonly_users) ? $readonly_users : array();
$upload_only_users = isset($upload_only_users) && is_array($upload_only_users) ? $upload_only_users : array();
$manager_users = isset($manager_users) && is_array($manager_users) ? $manager_users : array();
$directories_users = isset($directories_users) && is_array($directories_users) ? $directories_users : array();
$audit_events = function_exists('fm_admin_read_audit_events') ? fm_admin_read_audit_events(50) : array();
$config_file_path = dirname(__DIR__, 2) . '/config.php';
$config_is_writable = is_file($config_file_path) && is_writable($config_file_path);

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
    <div class="mb-3">
        <button type="button" class="btn btn-success" data-admin-user-action="new">New user</button>
    </div>
    <div class="table-responsive">
        <table class="table table-bordered table-striped table-sm align-middle">
            <thead class="table-light">
                <tr>
                    <th>Používateľ</th>
                    <th>Typ prístupu</th>
                    <th>Heslo v konfigurácii</th>
                    <th>Priradené adresáre</th>
                    <th>Stav / poznámka</th>
                    <th>Akcia</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($usernames as $u): ?>
                <tr>
                    <td><?php echo fm_enc($u); ?></td>
                    <td><?php echo fm_enc(user_type($u, $auth_users, $readonly_users, $upload_only_users, $manager_users, $directories_users)); ?></td>
                    <td><?php echo array_key_exists($u, $auth_users) ? 'áno' : 'nie'; ?></td>
                    <td><?php echo user_dirs($u, $directories_users); ?></td>
                    <td><?php echo fm_enc(user_status($u, $auth_users, $readonly_users, $upload_only_users, $manager_users, $directories_users)); ?></td>
                    <td>
                        <button type="button" class="btn btn-sm btn-primary" data-admin-user-action="edit" data-username="<?php echo fm_enc($u); ?>">Edit</button>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>

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

    <div id="admin-user-modal-container"></div>
        <script>
        document.addEventListener('DOMContentLoaded', function () {
            function executeInjectedScripts(rootEl) {
                if (!rootEl) {
                    return;
                }
                var scripts = rootEl.querySelectorAll('script');
                scripts.forEach(function (oldScript) {
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

                auditRows.forEach(function (row) {
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

                    auditRows.forEach(function (row) {
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
                var url = new URL(window.location.href);
                return url.searchParams.get('p') || '';
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

                var deleteBtn = btn.closest ? btn.closest('#admin-user-delete-btn') : null;
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

            function handleModalAction(e) {
                var btn = e.currentTarget;
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
            var buttons = document.querySelectorAll('[data-admin-user-action]');
            buttons.forEach(function (btn) {
                btn.addEventListener('click', handleModalAction);
            });
        });
        </script>
