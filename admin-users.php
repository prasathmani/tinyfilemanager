<?php
// admin-users.php: Administračná stránka pre správu užívateľov a ich oprávnení
require_once __DIR__ . '/../src/bootstrap.php';
require_once __DIR__ . '/../src/FM_Config.php';

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
    <p><a href="?add">Pridať nového užívateľa</a></p>
</body>
</html>
