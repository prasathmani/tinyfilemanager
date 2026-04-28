<?php

/**
 * It prints the css/js files into html.
 *
 * @param string $key
 * @return void
 */
function print_external($key)
{
    global $external;

    if (!array_key_exists($key, $external)) {
        echo "<!-- EXTERNAL: MISSING KEY $key -->";
        return;
    }

    echo "$external[$key]";
}

/**
 * Show nav block.
 *
 * @param string $path
 * @return void
 */
function fm_show_nav_path($path)
{
    global $lang, $sticky_navbar, $editFile;
    $isStickyNavBar = $sticky_navbar ? 'fixed-top' : '';
?>
    <nav class="navbar navbar-expand-lg mb-4 main-nav <?php echo $isStickyNavBar ?> bg-body-tertiary" data-bs-theme="<?php echo FM_THEME; ?>">
        <a class="navbar-brand"><a href="https://dremont.sk">
            <img src="https://dremont.sk/wp-content/uploads/2024/04/logo-DREMONTMA_3_11_10izak-e1714296077460.png" alt="DREMONT logo" style="height:32px;vertical-align:middle;margin-right:8px;"></a>
            <?php echo lng('AppTitle') ?>
        </a>
        <div class="fm-mobile-quickbar d-flex d-lg-none ms-auto me-2">
            <a class="btn btn-sm btn-outline-primary" href="#" id="js-mobile-focus-search" aria-label="<?php echo lng('Search') ?>" title="<?php echo lng('Search') ?>"><i class="fa fa-search" aria-hidden="true"></i></a>
            <?php if ((!FM_READONLY || FM_UPLOAD_ONLY) && FM_CAN_WRITE_IN_PATH): ?>
                <a class="btn btn-sm btn-outline-primary" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;upload" aria-label="<?php echo lng('Upload') ?>" title="<?php echo lng('Upload') ?>"><i class="fa fa-cloud-upload" aria-hidden="true"></i></a>
            <?php endif; ?>
            <?php if ((FM_USE_AUTH && !empty($_SESSION[FM_SESSION_ID]['logged'])) || !FM_READONLY): ?>
                <a class="btn btn-sm btn-outline-primary" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;settings=1" aria-label="<?php echo lng('Settings') ?>" title="<?php echo lng('Settings') ?>"><i class="fa fa-cog" aria-hidden="true"></i></a>
            <?php endif; ?>
        </div>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarSupportedContent">

            <?php
            $path = fm_clean_path($path);
            $root_url = "<a href='?p='><i class='fa fa-home' aria-hidden='true' title='" . FM_ROOT_PATH . "'></i></a>";
            $sep = '<i class="bread-crumb"> / </i>';
            if ($path != '') {
                $exploded = explode('/', $path);
                $count = count($exploded);
                $array = array();
                $parent = '';
                for ($i = 0; $i < $count; $i++) {
                    $parent = trim($parent . '/' . $exploded[$i], '/');
                    $parent_enc = urlencode($parent);
                    $array[] = "<a href='?p={$parent_enc}'>" . fm_enc(fm_convert_win($exploded[$i])) . "</a>";
                }
                $root_url .= $sep . implode($sep, $array);
            }
            echo '<div class="col-xs-6 col-sm-5">' . $root_url . $editFile . '</div>';
            ?>

            <div class="col-xs-6 col-sm-7">
                <ul class="navbar-nav justify-content-end" data-bs-theme="<?php echo FM_THEME; ?>">
                    <li class="nav-item mr-2">
                        <div class="input-group input-group-sm mr-1" style="margin-top:4px;">
                            <input type="text" class="form-control" placeholder="<?php echo lng('Search') ?>" aria-label="<?php echo lng('Search') ?>" aria-describedby="search-addon2" id="search-addon">
                            <div class="input-group-append">
                                <span class="input-group-text brl-0 brr-0" id="search-addon2"><i class="fa fa-search"></i></span>
                            </div>
                            <div class="input-group-append btn-group">
                                <span class="input-group-text dropdown-toggle brl-0" data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false"></span>
                                <div class="dropdown-menu dropdown-menu-right">
                                    <a class="dropdown-item" href="<?php echo $path2 = $path ? $path : '.'; ?>" id="js-search-modal" data-bs-toggle="modal" data-bs-target="#searchModal"><?php echo lng('Advanced Search') ?></a>
                                </div>
                            </div>
                        </div>
                    </li>
                    <?php if ((!FM_READONLY || FM_UPLOAD_ONLY) && FM_CAN_WRITE_IN_PATH): ?>
                        <li class="nav-item">
                            <a title="<?php echo lng('Upload') ?>" class="nav-link" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;upload"><i class="fa fa-cloud-upload" aria-hidden="true"></i> <?php echo lng('Upload') ?></a>
                        </li>
                        <?php if (!FM_UPLOAD_ONLY): ?>
                        <li class="nav-item">
                            <a title="<?php echo lng('NewItem') ?>" class="nav-link" href="#createNewItem" data-bs-toggle="modal" data-bs-target="#createNewItem"><i class="fa fa-plus-square"></i> <?php echo lng('NewItem') ?></a>
                        </li>
                        <?php endif; ?>
                    <?php endif; ?>
                    <?php if (FM_USE_AUTH && !empty($_SESSION[FM_SESSION_ID]['logged'])): ?>
                        <?php
                        // Zobraziť admin odkaz len pre admina
                        $current_user = isset($_SESSION[FM_SESSION_ID]['logged']) ? $_SESSION[FM_SESSION_ID]['logged'] : '';
                        if ($current_user === 'admin') : ?>
                            <li class="nav-item">
                                <a title="Správa používateľov" class="nav-link" href="?p=<?php echo urlencode(FM_PATH); ?>&amp;admin_users=1"><i class="fa fa-users-cog"></i> Správa používateľov</a>
                            </li>
                        <?php endif; ?>
                        <li class="nav-item avatar dropdown">
                            <a class="nav-link dropdown-toggle" id="navbarDropdownMenuLink-5" data-bs-toggle="dropdown" aria-expanded="false">
                                <i class="fa fa-user-circle"></i>
                                <span class="ms-1"><?php echo fm_enc($_SESSION[FM_SESSION_ID]['logged']); ?></span>
                            </a>
                            <div class="dropdown-menu dropdown-menu-end text-small shadow" aria-labelledby="navbarDropdownMenuLink-5" data-bs-theme="<?php echo FM_THEME; ?>">
                                <a title="<?php echo lng('Settings') ?>" class="dropdown-item nav-link" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;settings=1"><i class="fa fa-cog" aria-hidden="true"></i> <?php echo lng('Settings') ?></a>
                                <a title="<?php echo lng('Help') ?>" class="dropdown-item nav-link" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;help=2"><i class="fa fa-exclamation-circle" aria-hidden="true"></i> <?php echo lng('Help') ?></a>
                                <a title="<?php echo lng('Logout') ?>" class="dropdown-item nav-link" href="?logout=1"><i class="fa fa-sign-out" aria-hidden="true"></i> <?php echo lng('Logout') ?></a>
                            </div>
                        </li>
                    <?php elseif (!FM_READONLY): ?>
                        <li class="nav-item">
                            <a title="<?php echo lng('Settings') ?>" class="dropdown-item nav-link" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;settings=1"><i class="fa fa-cog" aria-hidden="true"></i> <?php echo lng('Settings') ?></a>
                        </li>
                    <?php endif; ?>
                </ul>
            </div>
        </div>
    </nav>
<?php
}

/**
 * Show alert message from session.
 *
 * @return void
 */
function fm_show_message()
{
    if (isset($_SESSION[FM_SESSION_ID]['message'])) {
        $class = isset($_SESSION[FM_SESSION_ID]['status']) ? $_SESSION[FM_SESSION_ID]['status'] : 'ok';
        echo '<p class="message ' . $class . '">' . $_SESSION[FM_SESSION_ID]['message'] . '</p>';
        unset($_SESSION[FM_SESSION_ID]['message']);
        unset($_SESSION[FM_SESSION_ID]['status']);
    }
}

/**
 * Show page header in Login Form.
 *
 * @return void
 */
function fm_show_header_login()
{
    header("Content-Type: text/html; charset=utf-8");
    header("Expires: Sat, 26 Jul 1997 05:00:00 GMT");
    header("Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0");
    header("Pragma: no-cache");

    global $favicon_path;
    $pwa_icon = LOGIN_LOGO_PATH ? LOGIN_LOGO_PATH : $favicon_path;
?>
    <!DOCTYPE html>
    <html lang="en" data-bs-theme="<?php echo (FM_THEME == "dark") ? 'dark' : 'light' ?>">

    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        <meta name="description" content="Web based File Manager in PHP, Manage your files efficiently and easily with Tiny File Manager">
        <meta name="author" content="CCP Programmers">
        <meta name="robots" content="noindex, nofollow">
        <meta name="googlebot" content="noindex">
        <meta name="theme-color" content="#1f6feb">
        <meta name="mobile-web-app-capable" content="yes">
        <meta name="apple-mobile-web-app-capable" content="yes">
        <meta name="apple-mobile-web-app-status-bar-style" content="default">
        <meta name="apple-mobile-web-app-title" content="<?php echo fm_enc(APP_TITLE); ?>">
        <link rel="manifest" href="<?php echo fm_enc(FM_SELF_URL . '?manifest=1'); ?>">
        <?php if ($favicon_path) {
            echo '<link rel="icon" href="' . fm_enc($favicon_path) . '" type="image/png">';
        } ?>
        <?php if ($pwa_icon) {
            echo '<link rel="apple-touch-icon" href="' . fm_enc($pwa_icon) . '">';
        } ?>
        <title><?php echo fm_enc(APP_TITLE) ?></title>
        <?php print_external('pre-jsdelivr'); ?>
        <?php print_external('css-bootstrap'); ?>
        <link rel="stylesheet" href="src/assets/css/fm-navbar-fix.css?v=<?php echo rawurlencode((string) VERSION); ?>">
        <style>
            body.fm-login-page {
                background-color: #f7f9fb;
                font-size: 14px;
                background-color: #f7f9fb;
                background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 304 304' width='304' height='304'%3E%3Cpath fill='%23e2e9f1' fill-opacity='0.4' d='M44.1 224a5 5 0 1 1 0 2H0v-2h44.1zm160 48a5 5 0 1 1 0 2H82v-2h122.1zm57.8-46a5 5 0 1 1 0-2H304v2h-42.1zm0 16a5 5 0 1 1 0-2H304v2h-42.1zm6.2-114a5 5 0 1 1 0 2h-86.2a5 5 0 1 1 0-2h86.2zm-256-48a5 5 0 1 1 0 2H0v-2h12.1zm185.8 34a5 5 0 1 1 0-2h86.2a5 5 0 1 1 0 2h-86.2zM258 12.1a5 5 0 1 1-2 0V0h2v12.1zm-64 208a5 5 0 1 1-2 0v-54.2a5 5 0 1 1 2 0v54.2zm48-198.2V80h62v2h-64V21.9a5 5 0 1 1 2 0zm16 16V64h46v2h-48V37.9a5 5 0 1 1 2 0zm-128 96V208h16v12.1a5 5 0 1 1-2 0V210h-16v-76.1a5 5 0 1 1 2 0zm-5.9-21.9a5 5 0 1 1 0 2H114v48H85.9a5 5 0 1 1 0-2H112v-48h12.1zm-6.2 130a5 5 0 1 1 0-2H176v-74.1a5 5 0 1 1 2 0V242h-60.1zm-16-64a5 5 0 1 1 0-2H114v48h10.1a5 5 0 1 1 0 2H112v-48h-10.1zM66 284.1a5 5 0 1 1-2 0V274H50v30h-2v-32h18v12.1zM236.1 176a5 5 0 1 1 0 2H226v94h48v32h-2v-30h-48v-98h12.1zm25.8-30a5 5 0 1 1 0-2H274v44.1a5 5 0 1 1-2 0V146h-10.1zm-64 96a5 5 0 1 1 0-2H208v-80h16v-14h-42.1a5 5 0 1 1 0-2H226v18h-16v80h-12.1zm86.2-210a5 5 0 1 1 0 2H272V0h2v32h10.1zM98 101.9V146H53.9a5 5 0 1 1 0-2H96v-42.1a5 5 0 1 1 2 0zM53.9 34a5 5 0 1 1 0-2H80V0h2v34H53.9zm60.1 3.9V66H82v64H69.9a5 5 0 1 1 0-2H80V64h32V37.9a5 5 0 1 1 2 0zM101.9 82a5 5 0 1 1 0-2H128V37.9a5 5 0 1 1 2 0V82h-28.1zm16-64a5 5 0 1 1 0-2H146v44.1a5 5 0 1 1-2 0V18h-26.1zm102.2 270a5 5 0 1 1 0 2H98v14h-2v-16h124.1zM242 149.9V160h16v34h-16v62h48v48h-2v-46h-48v-66h16v-30h-16v-12.1a5 5 0 1 1 2 0zM53.9 18a5 5 0 1 1 0-2H64V2H48V0h18v18H53.9zm112 32a5 5 0 1 1 0-2H192V0h50v2h-48v48h-28.1zm-48-48a5 5 0 0 1-9.8-2h2.07a3 3 0 1 0 5.66 0H178v34h-18V21.9a5 5 0 1 1 2 0V32h14V2h-58.1zm0 96a5 5 0 1 1 0-2H137l32-32h39V21.9a5 5 0 1 1 2 0V66h-40.17l-32 32H117.9zm28.1 90.1a5 5 0 1 1-2 0v-76.51L175.59 80H224V21.9a5 5 0 1 1 2 0V82h-49.59L146 112.41v75.69zm16 32a5 5 0 1 1-2 0v-99.51L184.59 96H300.1a5 5 0 0 1 3.9-3.9v2.07a3 3 0 0 0 0 5.66v2.07a5 5 0 0 1-3.9-3.9H185.41L162 121.41v98.69zm-144-64a5 5 0 1 1-2 0v-3.51l48-48V48h32V0h2v50H66v55.41l-48 48v2.69zM50 53.9v43.51l-48 48V208h26.1a5 5 0 1 1 0 2H0v-65.41l48-48V53.9a5 5 0 1 1 2 0zm-16 16V89.41l-34 34v-2.82l32-32V69.9a5 5 0 1 1 2 0zM12.1 32a5 5 0 1 1 0 2H9.41L0 43.41V40.6L8.59 32h3.51zm265.8 18a5 5 0 1 1 0-2h18.69l7.41-7.41v2.82L297.41 50H277.9zm-16 160a5 5 0 1 1 0-2H288v-71.41l16-16v2.82l-14 14V210h-28.1zm-208 32a5 5 0 1 1 0-2H64v-22.59L40.59 194H21.9a5 5 0 1 1 0-2H41.41L66 216.59V242H53.9zm150.2 14a5 5 0 1 1 0 2H96v-56.6L56.6 162H37.9a5 5 0 1 1 0-2h19.5L98 200.6V256h106.1zm-150.2 2a5 5 0 1 1 0-2H80v-46.59L48.59 178H21.9a5 5 0 1 1 0-2H49.41L82 208.59V258H53.9zM34 39.8v1.61L9.41 66H0v-2h8.59L32 40.59V0h2v39.8zM2 300.1a5 5 0 0 1 3.9 3.9H3.83A3 3 0 0 0 0 302.17V256h18v48h-2v-46H2v42.1zM34 241v63h-2v-62H0v-2h34v1zM17 18H0v-2h16V0h2v18h-1zm273-2h14v2h-16V0h2v16zm-32 273v15h-2v-14h-14v14h-2v-16h18v1zM0 92.1A5.02 5.02 0 0 1 6 97a5 5 0 0 1-6 4.9v-2.07a3 3 0 1 0 0-5.66V92.1zM80 272h2v32h-2v-32zm37.9 32h-2.07a3 3 0 0 0-5.66 0h-2.07a5 5 0 0 1 9.8 0zM5.9 0A5.02 5.02 0 0 1 0 5.9V3.83A3 3 0 0 0 3.83 0H5.9zm294.2 0h2.07A3 3 0 0 0 304 3.83V5.9a5 5 0 0 1-3.9-5.9zm3.9 300.1v2.07a3 3 0 0 0-1.83 1.83h-2.07a5 5 0 0 1 3.9-3.9zM97 100a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0-16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-48 32a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm32 48a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-16 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm32-16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0-32a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16 32a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm32 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0-16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-16-64a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16 0a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16 96a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16-144a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0 32a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16-32a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16-16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-96 0a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16-32a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm96 0a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-16-64a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16-16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-32 0a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0-16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-16 0a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-16 0a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-16 0a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM49 36a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-32 0a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm32 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM33 68a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16-48a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0 240a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16 32a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-16-64a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-16-32a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm80-176a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16 0a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-16-16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm32 48a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16-16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0-32a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm112 176a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-16 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM17 180a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0-32a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16 0a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM17 84a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm32 64a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16-16a3 3 0 1 0 0-6 3 3 0 0 0 0 6z'%3E%3C/path%3E%3C/svg%3E");
            }

            .fm-login-page .brand {
                width: 180px;
                overflow: hidden;
                margin: 0 auto;
                position: relative;
                z-index: 1
            }

            .fm-login-page .brand img {
                width: 100%;
                height: auto;
                display: block;
                border-radius: 6px;
            }

            .fm-login-page .card-wrapper {
                width: 360px;
            }

            .fm-login-page .card {
                border-color: transparent;
                box-shadow: 0 4px 8px rgba(0, 0, 0, .05)
            }

            .fm-login-page .card-title {
                margin-bottom: 1.5rem;
                font-size: 24px;
                font-weight: 400;
            }

            .fm-login-page .company-subtitle {
                margin-top: -10px;
                margin-bottom: 8px;
                font-size: 13px;
                font-weight: 600;
                letter-spacing: .4px;
                color: #2f3f4f;
                text-transform: uppercase;
            }

            .fm-login-page .form-control {
                border-width: 2.3px
            }

            .fm-login-page .form-group label {
                width: 100%
            }

            .fm-login-page .btn.btn-block {
                padding: 12px 10px
            }

            .fm-login-page .footer {
                margin: 20px 0;
                color: #888;
                text-align: center
            }

            @media screen and (max-width:425px) {
                .fm-login-page .card-wrapper {
                    width: 90%;
                    margin: 0 auto;
                    margin-top: 10%;
                }
            }

            @media screen and (max-width:320px) {
                .fm-login-page .card.fat {
                    padding: 0
                }

                .fm-login-page .card.fat .card-body {
                    padding: 15px
                }
            }

            .message {
                padding: 4px 7px;
                border: 1px solid #051280;
                background-color: #b6bdf7
                margin-top: 72px; /* výška lišty + medzera */
                position: relative;
                z-index: 1;
                width: 66%;
                margin-left: auto;
                margin-right: auto;
            }

            .message.ok {
                border-color: green;
                color: green
            }

            .message.error {
                border-color: red;
                color: red
            }

            .message.alert {
                border-color: orange;
                color: orange
            }

            body.fm-login-page.theme-dark {
                background-color: #2f2a2a;
            }

            .theme-dark .form-control {
                color: #fff;
                background-color: #403e3e;
            }

            .theme-dark .company-subtitle {
                color: #cfd8dc;
            }

            .h-100vh {
                min-height: 100vh;
            }
        </style>
    </head>

    <body class="fm-login-page <?php echo (FM_THEME == "dark") ? 'theme-dark' : ''; ?>">
        <div id="wrapper" class="container-fluid">

        <?php
}

/**
 * Show page footer in Login Form.
 *
 * @return void
 */
function fm_show_footer_login()
{
    ?>
        </div>
        <?php print_external('js-jquery'); ?>
        <?php print_external('js-bootstrap'); ?>
    </body>

    </html>

<?php
}

/**
 * Build the accepted upload extension list for Dropzone.
 *
 * @return string
 */
function getUploadExt()
{
    $extArr = explode(',', FM_UPLOAD_EXTENSION);
    if (FM_UPLOAD_EXTENSION && $extArr) {
        array_walk($extArr, function (&$x) {
            $x = '.' . $x;
        });
        return implode(',', $extArr);
    }

    return '';
}

/**
 * Return the selected attribute for the active language option.
 *
 * @param string $languageCode
 * @return string
 */
function getSelected($languageCode)
{
    global $lang;
    return ($lang == $languageCode) ? 'selected' : '';
}