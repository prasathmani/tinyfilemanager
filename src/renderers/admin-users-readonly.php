<?php
// Read-only user administration overview renderer
// Does not call fm_show_header/footer/exit/session_start

// Defensive: ensure all user arrays exist and are arrays
$auth_users = isset($auth_users) && is_array($auth_users) ? $auth_users : array();
$readonly_users = isset($readonly_users) && is_array($readonly_users) ? $readonly_users : array();
$upload_only_users = isset($upload_only_users) && is_array($upload_only_users) ? $upload_only_users : array();
$manager_users = isset($manager_users) && is_array($manager_users) ? $manager_users : array();
$directories_users = isset($directories_users) && is_array($directories_users) ? $directories_users : array();

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
    <p class="text-muted">Read-only prehľad používateľov z aktuálnej konfigurácie. Úpravy budú doplnené v ďalšej etape.</p>
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
    <div id="admin-user-modal-container"></div>
</div>
<script>
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
    <p class="text-muted">Read-only prehľad používateľov z aktuálnej konfigurácie. Úpravy budú doplnené v ďalšej etape.</p>
    <div class="table-responsive">
        <table class="table table-bordered table-striped table-sm align-middle">
            <thead class="table-light">
                <tr>
                    <th>Používateľ</th>
                    <th>Typ prístupu</th>
                    <th>Heslo v konfigurácii</th>
                    <th>Priradené adresáre</th>
                    <th>Stav / poznámka</th>
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
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>
