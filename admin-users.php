<?php
// admin-users.php: Administračná stránka pre správu užívateľov a ich oprávnení

// Definuj FM_SESSION_ID a inicializuj session ako v tinyfilemanager.php
if (!defined('FM_SESSION_ID')) {
    define('FM_SESSION_ID', 'filemanager');
}
session_name(FM_SESSION_ID);
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once __DIR__ . '/src/bootstrap.php';
require_once __DIR__ . '/src/FM_Config.php';

session_start();

// Kontrola, či je prihlásený administrátor
if (!isset($_SESSION[FM_SESSION_ID]['logged']) || !isset($_SESSION[FM_SESSION_ID]['is_admin']) || !$_SESSION[FM_SESSION_ID]['is_admin']) {
    header('Location: index.php');
    exit;
}

$config = new FM_Config();
$users = $config->getUsers(); // Očakáva sa, že FM_Config má metódu getUsers()

?>
<!DOCTYPE html>
<html lang="sk">
<head>
    <meta charset="UTF-8">
    <title>Správa užívateľov | DREMONT</title>
    <link rel="stylesheet" href="src/assets/css/fm-navbar-fix.css">
    <!-- Nepoužívame hlavný JS ani jQuery, aby nevznikali JS chyby -->
    <style>
        .admin-table { width: 100%; border-collapse: collapse; margin-top: 2rem; }
        .admin-table th, .admin-table td { border: 1px solid #ccc; padding: 8px; }
        .admin-table th { background: #f0f0f0; }
        .admin-actions { display: flex; gap: 8px; }
    </style>
</head>
<body>
    <h1>Správa užívateľov</h1>
    <table class="admin-table">
        <thead>
            <tr>
                <th>Používateľ</th>
                <th>Oprávnenia</th>
                <th>Povolené priečinky</th>
                <th>Akcie</th>
            </tr>
        </thead>
        <tbody>
        <?php foreach ($users as $user => $info): ?>
            <tr>
                <td><?= htmlspecialchars($user) ?></td>
                <td><?= htmlspecialchars($info['role'] ?? 'user') ?></td>
                <td><?= htmlspecialchars(implode(', ', $info['folders'] ?? [])) ?></td>
                <td class="admin-actions">
                    <a href="?edit=<?= urlencode($user) ?>">Upraviť</a>
                    <a href="?delete=<?= urlencode($user) ?>" onclick="return confirm('Naozaj zmazať užívateľa?')">Zmazať</a>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <p><a href="#" onclick="showUserModal();return false;">Pridať nového užívateľa</a></p>

    <!-- Modálny formulár pre pridanie/úpravu užívateľa -->
    <div id="userModal" style="display:none;position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.3);z-index:9999;align-items:center;justify-content:center;">
        <div style="background:#fff;padding:2rem;max-width:400px;margin:auto;border-radius:8px;box-shadow:0 2px 8px #0002;position:relative;">
            <h2 id="modalTitle">Pridať užívateľa</h2>
            <form method="post" id="userForm">
                <input type="hidden" name="action" value="save_user">
                <div style="margin-bottom:1em;">
                    <label>Používateľské meno:<br><input type="text" name="username" id="username" required></label>
                </div>
                <div style="margin-bottom:1em;">
                    <label>Heslo:<br><input type="password" name="password" id="password" required></label>
                </div>
                <div style="margin-bottom:1em;">
                    <label>Rola:<br>
                        <select name="role" id="role">
                            <option value="user">Používateľ</option>
                            <option value="manager">Manažér</option>
                            <option value="admin">Admin</option>
                        </select>
                    </label>
                </div>
                <div style="margin-bottom:1em;">
                    <label>Povolené priečinky (oddelené čiarkou):<br><input type="text" name="folders" id="folders"></label>
                </div>
                <div style="text-align:right;">
                    <button type="button" onclick="hideUserModal()">Zrušiť</button>
                    <button type="submit">Uložiť</button>
                </div>
            </form>
            <button onclick="hideUserModal()" style="position:absolute;top:8px;right:8px;background:none;border:none;font-size:1.5em;">&times;</button>
        </div>
    </div>
    <script>
    function showUserModal() {
        document.getElementById('userModal').style.display = 'flex';
        document.getElementById('userForm').reset();
        document.getElementById('modalTitle').innerText = 'Pridať užívateľa';
    }
    function hideUserModal() {
        document.getElementById('userModal').style.display = 'none';
    }
    </script>

<?php
// Spracovanie formulára na pridanie/úpravu užívateľa
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'save_user') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $role = $_POST['role'] ?? 'user';
    $folders = array_map('trim', explode(',', $_POST['folders'] ?? ''));
    if ($username && $password) {
        $hash = password_hash($password, PASSWORD_DEFAULT);
        // Načítať config.php
        $config_path = __DIR__ . '/config.php';
        $config_code = file_get_contents($config_path);
        // Pridať/aktualizovať užívateľa v $auth_users
        $pattern = '/\$auth_users\s*=\s*array\((.*?)\);/s';
        if (preg_match($pattern, $config_code, $matches)) {
            $users_code = trim($matches[1]);
            // Odstrániť existujúci záznam pre užívateľa
            $users_code = preg_replace("/'" . preg_quote($username, '/') . "'\s*=>\s*'[^']*',?/", '', $users_code);
            // Pridať nový záznam
            $users_code = rtrim($users_code, ",\n\r ");
            if ($users_code !== '') $users_code .= ",\n    ";
            $users_code .= "'" . addslashes($username) . "' => '" . addslashes($hash) . "'";
            $new_code = preg_replace($pattern, "\$auth_users = array(\n    $users_code\n);", $config_code);
            file_put_contents($config_path, $new_code);
        }
        // TODO: Uložiť rolu a priečinky do config.php podľa štruktúry
        echo '<script>alert("Užívateľ uložený.");window.location.href=window.location.pathname;</script>';
        exit;
    }
}
?>
</body>
</html>
