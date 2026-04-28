<?php
// src/renderers/layout.php
// Univerzálna šablóna pre všetky stránky

function render_layout($params = []) {
    $title = $params['title'] ?? 'TinyFileManager';
    $content = $params['content'] ?? '';
    $extra_head = $params['extra_head'] ?? '';
    $body_class = $params['body_class'] ?? '';
    ?>
<!DOCTYPE html>
<html lang="sk">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($title) ?></title>
    <link rel="stylesheet" href="/src/assets/css/fm-navbar-fix.css">
    <link rel="stylesheet" href="/src/assets/css/fm-grid.css">
    <!-- Ďalšie globálne CSS -->
    <?= $extra_head ?>
    <style>
        body { margin:0; }
        .fm-navbar { position:fixed; top:0; left:0; width:100vw; z-index:1000; background:#222; color:#fff; height:48px; display:flex; align-items:center; padding:0 1.5rem; box-shadow:0 2px 8px #0002; }
        .fm-navbar h1 { font-size:1.2em; margin:0; flex:1; }
        .fm-content { padding-top:56px; min-height:calc(100vh - 56px); }
        .fm-footer { background:#f0f0f0; color:#888; text-align:center; padding:1em 0; font-size:0.95em; }
    </style>
</head>
<body class="<?= htmlspecialchars($body_class) ?>">
    <div class="fm-navbar">
        <h1>TinyFileManager</h1>
        <!-- Tu môžeš pridať menu, logo, odkazy, atď. -->
    </div>
    <div class="fm-content">
        <?= $content ?>
    </div>
    <div class="fm-footer">
        &copy; <?= date('Y') ?> TinyFileManager &ndash; <a href="https://github.com/prasathmani/tinyfilemanager" target="_blank">GitHub</a>
    </div>
</body>
</html>
<?php
}
