<?php $all_files_size = 0; ?>
<form action="" method="post" class="pt-3 fm-shell">
    <input type="hidden" name="p" value="<?php echo fm_enc(FM_PATH) ?>">
    <input type="hidden" name="group" value="1">
    <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
    <div class="fm-listing-toolbar mb-3">
        <div class="fm-listing-toolbar__meta">
            <span class="badge text-bg-light fm-toolbar-badge"><?php echo lng('File') ?>: <?php echo (int) $num_files; ?></span>
            <span class="badge text-bg-light fm-toolbar-badge"><?php echo lng('Folder') ?>: <?php echo (int) $num_folders; ?></span>
            <span class="badge text-bg-light fm-toolbar-badge"><?php echo lng('FullSize') ?>: <?php echo fm_get_filesize($all_files_size); ?></span>
        </div>
        <div class="btn-group btn-group-sm fm-view-switch" role="group" aria-label="<?php echo lng('View mode'); ?>">
            <button type="button" class="btn btn-outline-primary js-view-mode active" data-view-mode="list">
                <i class="fa fa-list" aria-hidden="true"></i> <?php echo lng('Zoznam'); ?>
            </button>
            <button type="button" class="btn btn-outline-primary js-view-mode" data-view-mode="grid">
                <i class="fa fa-th-large" aria-hidden="true"></i> <?php echo lng('Mriežka'); ?>
            </button>
        </div>
        <?php if (!FM_IS_WIN && !$hide_Cols): ?>
            <div class="fm-owner-filter-wrap">
                <label for="fm-owner-source-filter" class="fm-owner-filter-label"><?php echo lng('Vlastnik:'); ?></label>
                <select id="fm-owner-source-filter" class="form-select form-select-sm fm-owner-filter" aria-label="<?php echo lng('Filter owner source'); ?>">
                    <option value="all"><?php echo lng('Vsetko'); ?></option>
                    <option value="app">App</option>
                    <option value="system">System</option>
                </select>
                <span class="badge text-bg-light fm-owner-source-count" id="fm-owner-count-app" data-owner-filter-target="app" tabindex="0" role="button" title="Pocet App owner poloziek (klik pre filter)">App: 0</span>
                <span class="badge text-bg-light fm-owner-source-count" id="fm-owner-count-system" data-owner-filter-target="system" tabindex="0" role="button" title="Pocet System owner poloziek (klik pre filter)">System: 0</span>
            </div>
        <?php endif; ?>
    </div>
    <div class="fm-explorer-layout">
        <?php
        $fm_navigation_home = fm_get_navigation_home_root();
        $fm_tree_current_path = fm_clean_path((string) FM_PATH);
        if ($fm_tree_current_path === '' && $fm_navigation_home !== '') {
            $fm_tree_current_path = $fm_navigation_home;
        }
        $fm_tree_revision = function_exists('fm_search_index_get_tree_revision')
            ? (int) fm_search_index_get_tree_revision()
            : 0;
        $fm_on_navigation_home = fm_is_navigation_home($fm_tree_current_path);
        $fm_tree_ancestors = fm_get_navigation_ancestor_paths($fm_tree_current_path);
        $fm_tree_root_children = fm_get_visible_child_directories($fm_navigation_home);
        $fm_tree_root_has_children = !empty($fm_tree_root_children);
        $fm_sidebar_path_raw = '/' . ltrim((string) $fm_tree_current_path, '/');
        if ($fm_on_navigation_home) {
            $fm_sidebar_path_raw = fm_get_navigation_home_label();
        } elseif ($fm_navigation_home !== '' && strpos(($fm_tree_current_path . '/'), ($fm_navigation_home . '/')) === 0) {
            $fm_relative_sidebar = ltrim(substr((string) $fm_tree_current_path, strlen($fm_navigation_home)), '/');
            $fm_sidebar_path_raw = fm_get_navigation_home_label() . ($fm_relative_sidebar !== '' ? ' / ' . $fm_relative_sidebar : '');
        }
        $fm_sidebar_path_title = fm_enc($fm_sidebar_path_raw);
        $fm_sidebar_path_text = str_replace('/', '/<wbr>', $fm_sidebar_path_title);
        ?>
        <aside class="fm-folder-sidebar" aria-label="<?php echo lng('Folders'); ?>">
            <div class="fm-folder-sidebar__title"><?php echo lng('Folders'); ?></div>
            <div class="fm-folder-sidebar__path" title="<?php echo $fm_sidebar_path_title; ?>">
                <i class="fa fa-folder-open-o" aria-hidden="true"></i>
                <span><?php echo $fm_sidebar_path_text; ?></span>
            </div>
            <div class="fm-folder-sidebar__list" role="navigation" aria-label="<?php echo lng('Folders'); ?>">
                <div
                    class="fm-folder-tree"
                    id="fm-folder-tree"
                    role="tree"
                    aria-label="<?php echo lng('Folders'); ?>"
                    data-home-path="<?php echo fm_enc($fm_navigation_home); ?>"
                    data-current-path="<?php echo fm_enc($fm_tree_current_path); ?>"
                >
                    <?php
                    $fm_root_expanded = $fm_tree_root_has_children ? 'true' : 'false';
                    ?>
                    <div class="fm-tree-node<?php echo $fm_on_navigation_home ? ' is-active' : ''; ?><?php echo $fm_tree_root_has_children ? ' is-expanded' : ''; ?>" role="treeitem" aria-level="1" aria-expanded="<?php echo $fm_root_expanded; ?>" aria-selected="<?php echo $fm_on_navigation_home ? 'true' : 'false'; ?>" data-path="<?php echo fm_enc($fm_navigation_home); ?>">
                        <button
                            type="button"
                            class="fm-tree-toggle<?php echo !$fm_tree_root_has_children ? ' is-leaf' : ''; ?>"
                            data-path="<?php echo fm_enc($fm_navigation_home); ?>"
                            aria-label="<?php echo fm_enc($fm_tree_root_has_children ? lng('Collapse') : lng('No subfolders')); ?>"
                            aria-expanded="<?php echo $fm_root_expanded; ?>"
                            <?php echo !$fm_tree_root_has_children ? 'disabled' : ''; ?>
                        >
                            <i class="fa fa-caret-right" aria-hidden="true"></i>
                        </button>
                        <a
                            class="fm-tree-label<?php echo $fm_on_navigation_home ? ' is-active' : ''; ?>"
                            href="?p=<?php echo urlencode($fm_navigation_home); ?>"
                            data-path="<?php echo fm_enc($fm_navigation_home); ?>"
                            role="treeitem"
                            aria-selected="<?php echo $fm_on_navigation_home ? 'true' : 'false'; ?>"
                        >
                            <i class="fa fa-home" aria-hidden="true"></i>
                            <span><?php echo fm_enc(fm_get_navigation_home_label()); ?></span>
                        </a>
                    </div>
                    <div class="fm-tree-children" data-parent-path="<?php echo fm_enc($fm_navigation_home); ?>" <?php echo $fm_tree_root_has_children ? '' : 'hidden'; ?>>
                        <?php foreach ($fm_tree_root_children as $tree_child): ?>
                            <?php
                            $tree_child_name = isset($tree_child['name']) ? (string) $tree_child['name'] : '';
                            $tree_child_path = isset($tree_child['path']) ? fm_clean_path((string) $tree_child['path']) : '';
                            $tree_child_has_children = !empty($tree_child['has_children']);
                            $tree_child_is_active = ($fm_tree_current_path === $tree_child_path);
                            $tree_child_is_expanded = $tree_child_has_children && in_array($tree_child_path, $fm_tree_ancestors, true);
                            ?>
                            <div class="fm-tree-node fm-tree-node--depth-2<?php echo $tree_child_is_active ? ' is-active' : ''; ?><?php echo $tree_child_is_expanded ? ' is-expanded' : ''; ?>" role="treeitem" aria-level="2" aria-expanded="<?php echo $tree_child_has_children ? ($tree_child_is_expanded ? 'true' : 'false') : 'false'; ?>" aria-selected="<?php echo $tree_child_is_active ? 'true' : 'false'; ?>" data-path="<?php echo fm_enc($tree_child_path); ?>">
                                <button
                                    type="button"
                                    class="fm-tree-toggle<?php echo !$tree_child_has_children ? ' is-leaf' : ''; ?>"
                                    data-path="<?php echo fm_enc($tree_child_path); ?>"
                                    aria-label="<?php echo fm_enc($tree_child_has_children ? ($tree_child_is_expanded ? lng('Collapse') : lng('Expand')) : lng('No subfolders')); ?>"
                                    aria-expanded="<?php echo $tree_child_has_children ? ($tree_child_is_expanded ? 'true' : 'false') : 'false'; ?>"
                                    <?php echo !$tree_child_has_children ? 'disabled' : ''; ?>
                                >
                                    <i class="fa fa-caret-right" aria-hidden="true"></i>
                                </button>
                                <a class="fm-tree-label<?php echo $tree_child_is_active ? ' is-active' : ''; ?>" href="?p=<?php echo urlencode($tree_child_path); ?>" data-path="<?php echo fm_enc($tree_child_path); ?>" role="treeitem" aria-selected="<?php echo $tree_child_is_active ? 'true' : 'false'; ?>">
                                    <i class="fa fa-folder-o" aria-hidden="true"></i>
                                    <span><?php echo fm_convert_win(fm_enc($tree_child_name)); ?></span>
                                </a>
                            </div>
                            <div class="fm-tree-children" data-parent-path="<?php echo fm_enc($tree_child_path); ?>" <?php echo $tree_child_is_expanded ? '' : 'hidden'; ?>></div>
                        <?php endforeach; ?>
                    </div>
                </div>
                <script type="application/json" id="fm-folder-tree-config"><?php echo json_encode(array(
                    'csrfToken' => $_SESSION['token'],
                    'homePath' => $fm_navigation_home,
                    'currentPath' => $fm_tree_current_path,
                    'treeRevision' => $fm_tree_revision,
                    'ancestorPaths' => $fm_tree_ancestors,
                    'endpoint' => FM_SELF_URL . '?p=' . urlencode($fm_tree_current_path),
                    'texts' => array(
                        'expand' => lng('Expand'),
                        'collapse' => lng('Collapse'),
                        'loading' => lng('Loading…'),
                        'noSubfolders' => lng('No subfolders'),
                        'loadError' => lng('Failed to load folders'),
                    ),
                ), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); ?></script>
            </div>
        </aside>
        <div class="fm-sidebar-resizer" id="fm-sidebar-resizer" role="separator" aria-orientation="vertical" aria-label="Resize folders panel" tabindex="0"></div>
        <div class="fm-explorer-main">
            <div class="table-responsive fm-table-wrap fm-list-clean-wrap">
                <table class="table table-hover table-sm align-middle fm-modern-table fm-list-clean" id="main-table" data-bs-theme="<?php echo FM_THEME; ?>">
            <thead class="thead-white">
                <tr>
                    <?php if (!FM_READONLY && !FM_UPLOAD_ONLY && FM_CAN_WRITE_IN_PATH): ?>
                        <th style="width:3%" class="custom-checkbox-header">
                            <div class="custom-control custom-checkbox">
                                <input type="checkbox" class="custom-control-input" id="js-select-all-items" onclick="checkbox_toggle()">
                                <label class="custom-control-label" for="js-select-all-items"></label>
                            </div>
                        </th><?php endif; ?>
                    <th class="fm-col-name"><?php echo lng('Name') ?></th>
                    <th class="fm-col-size"><?php echo lng('Size') ?></th>
                    <th class="fm-col-modified"><?php echo lng('Modified') ?></th>
                    <?php if (!FM_IS_WIN && !$hide_Cols): ?>
                        <th class="fm-col-perms"><?php echo lng('Perms') ?></th>
                        <th class="fm-col-owner"><?php echo lng('Owner') ?></th><?php endif; ?>
                    <th class="fm-col-actions"><?php echo lng('Actions') ?></th>
                </tr>
            </thead>
            <?php
            if ($parent !== false && !fm_is_navigation_home(FM_PATH)) {
                $breadcrumbs = fm_build_breadcrumb_segments(FM_PATH);
            ?>
                <tr class="fm-parent-row"><?php if (!FM_READONLY && !FM_UPLOAD_ONLY && FM_CAN_WRITE_IN_PATH): ?>
                        <td class="nosort"></td><?php endif; ?>
                    <td class="border-0 fm-col-name" data-sort>
                        <?php if (!empty($breadcrumbs)): ?>
                            <a href="?p=<?php echo urlencode($parent); ?>" class="fm-parent-nav-link fm-breadcrumb-back" title="<?php echo lng('Back'); ?>">
                                <span class="fm-parent-nav-icon" aria-hidden="true"><i class="fa fa-arrow-left"></i></span>
                                <span class="fm-parent-nav-text"><?php echo lng('Back'); ?></span>
                                <span class="fm-breadcrumb-content">
                                    <?php foreach ($breadcrumbs as $index => $crumb): ?>
                                        <?php if ($index > 0): ?>
                                            <span class="fm-breadcrumb-sep"> / </span>
                                        <?php endif; ?>
                                        <a href="?p=<?php echo urlencode($crumb['path']); ?>" class="fm-breadcrumb-link" title="<?php echo fm_enc($crumb['label']); ?>" onclick="event.stopPropagation();">
                                            <?php echo $crumb['label']; ?>
                                        </a>
                                    <?php endforeach; ?>
                                </span>
                            </a>
                        <?php else: ?>
                            <a href="?p=<?php echo urlencode($parent) ?>" class="fm-parent-nav-link" title="<?php echo lng('Back'); ?>">
                                <span class="fm-parent-nav-icon" aria-hidden="true"><i class="fa fa-arrow-left"></i></span>
                                <span class="fm-parent-nav-text"><?php echo lng('Back'); ?></span>
                            </a>
                        <?php endif; ?>
                    </td>
                    <td class="border-0 fm-col-size" data-order></td>
                    <td class="border-0 fm-col-modified" data-order></td>
                    <?php if (!FM_IS_WIN && !$hide_Cols) { ?>
                        <td class="border-0 fm-col-perms"></td>
                        <td class="border-0 fm-col-owner"></td>
                    <?php } ?>
                    <td class="border-0 fm-col-actions"></td>
                </tr>
            <?php
            }

            $fmBuildActionNote = static function ($meta, $fallbackModified, $isDirectory = false) {
                $label = 'Bez app zaznamu';
                $title = 'Bez zaznamu o poslednom app ukone';

                if (is_array($meta)) {
                    $lastActionRaw = isset($meta['last_action']) ? strtolower(trim((string) $meta['last_action'])) : '';

                    if ($lastActionRaw !== '') {
                        if (function_exists('fm_owner_meta_action_label')) {
                            $label = fm_owner_meta_action_label($lastActionRaw, $isDirectory);
                        } else {
                            $label = ucfirst(str_replace('_', ' ', $lastActionRaw));
                        }
                    } else {
                        $label = 'Uprava';
                    }

                    $updatedBy = isset($meta['updated_by']) ? trim((string) $meta['updated_by']) : '';
                    $updatedAt = isset($meta['updated_at']) && is_numeric($meta['updated_at']) ? (int) $meta['updated_at'] : 0;

                    if ($updatedBy !== '' && strtolower($updatedBy) !== 'system') {
                        $label .= ' · ' . $updatedBy;
                    }

                    if ($updatedAt > 0) {
                        $label .= ' · ' . date('d.m.Y H:i', $updatedAt);
                    }

                    $title = $label;
                    if ($updatedAt > 0) {
                        $title .= ' @ ' . date(FM_DATETIME_FORMAT, $updatedAt);
                    }
                } elseif ($fallbackModified !== '') {
                    $label = 'System · ' . (string) $fallbackModified;
                    $title = 'Posledna systemova zmena podla mtime: ' . (string) $fallbackModified;
                }

                return array('label' => $label, 'title' => $title);
            };

            $ii = 3399;
            foreach ($folders as $f) {
                $is_link = is_link($path . '/' . $f);
                $img = $is_link ? 'icon-link_folder' : 'fa fa-folder-o';
                $modif_raw = filemtime($path . '/' . $f);
                $modif = date(FM_DATETIME_FORMAT, $modif_raw);
                $date_sorting = strtotime(date("F d Y H:i:s.", $modif_raw));
                $filesize_raw = "";
                $filesize = lng('Folder');
                $perms = substr(decoct(fileperms($path . '/' . $f)), -4);
                $owner = array('name' => '?');
                $group = array('name' => '?');
                if (function_exists('posix_getpwuid') && function_exists('posix_getgrgid')) {
                    try {
                        $owner_id = fileowner($path . '/' . $f);
                        if ($owner_id != 0) {
                            $owner_info = posix_getpwuid($owner_id);
                            if ($owner_info) {
                                $owner =  $owner_info;
                            }
                        }
                        $group_id = filegroup($path . '/' . $f);
                        $group_info = posix_getgrgid($group_id);
                        if ($group_info) {
                            $group =  $group_info;
                        }
                    } catch (Exception $e) {
                        error_log("exception:" . $e->getMessage());
                    }
                }
            ?>
                <tr>
                    <?php if (!FM_READONLY && !FM_UPLOAD_ONLY && FM_CAN_WRITE_IN_PATH): ?>
                        <td class="custom-checkbox-td">
                            <div class="custom-control custom-checkbox">
                                <input type="checkbox" class="custom-control-input" id="<?php echo $ii ?>" name="file[]" value="<?php echo fm_enc($f) ?>">
                                <label class="custom-control-label" for="<?php echo $ii ?>"></label>
                            </div>
                        </td>
                    <?php endif; ?>
                    <td class="fm-col-name" data-sort=<?php echo fm_convert_win(fm_enc($f)) ?>>
                        <div class="filename">
                            <a href="?p=<?php echo urlencode(trim(FM_PATH . '/' . $f, '/')) ?>"><i class="<?php echo $img ?>"></i> <?php echo fm_convert_win(fm_enc($f)) ?></a>
                            <?php echo ($is_link ? ' &rarr; <i>' . readlink($path . '/' . $f) . '</i>' : '') ?>
                        </div>
                    </td>
                    <td class="fm-col-size" data-order="a-<?php echo str_pad($filesize_raw, 18, "0", STR_PAD_LEFT); ?>">
                        <?php echo $filesize; ?>
                    </td>
                    <td class="fm-col-modified" data-order="a-<?php echo $date_sorting; ?>"><?php echo $modif ?></td>
                    <?php if (!FM_IS_WIN && !$hide_Cols) { ?>
                        <?php
                        $ownerName = isset($owner['name']) ? (string) $owner['name'] : '?';
                        $groupName = isset($group['name']) ? (string) $group['name'] : '?';
                        $ownerTitle = $ownerName . ':' . $groupName;
                        $hasAppOwner = false;
                        $ownerSource = 'system';
                        $lastEditorName = '';
                        $lastEditorTitle = '';
                        $appOwnerMeta = function_exists('fm_owner_meta_get') ? fm_owner_meta_get($path . '/' . $f) : null;
                        if (is_array($appOwnerMeta)) {
                            $appCreatedBy = isset($appOwnerMeta['created_by']) ? trim((string) $appOwnerMeta['created_by']) : '';
                            $appUpdatedBy = isset($appOwnerMeta['updated_by']) ? trim((string) $appOwnerMeta['updated_by']) : '';
                            $ownerSource = isset($appOwnerMeta['owner_source']) ? strtolower(trim((string) $appOwnerMeta['owner_source'])) : '';
                            if ($ownerSource !== 'app' && $ownerSource !== 'system') {
                                $ownerSource = ($appCreatedBy !== '' && strtolower($appCreatedBy) !== 'system') ? 'app' : 'system';
                            }
                            if ($ownerSource === 'app' && $appCreatedBy !== '') {
                                $hasAppOwner = true;
                                $ownerName = $appCreatedBy;
                                $ownerLabel = $appCreatedBy;
                                $ownerTitle = 'App owner: ' . $appCreatedBy;
                                if ($appUpdatedBy !== '' && $appUpdatedBy !== $appCreatedBy) {
                                    $ownerTitle .= ' | Last update: ' . $appUpdatedBy;
                                }
                            } elseif ($ownerSource === 'system' && $appUpdatedBy !== '' && strtolower($appUpdatedBy) !== 'system') {
                                $lastEditorName = $appUpdatedBy;
                                $lastEditorTitle = 'Last update: ' . $appUpdatedBy;
                            }
                        }
                        $ownerLabel = $ownerName;
                        if (!$hasAppOwner) {
                            if (!empty($owner['gecos'])) {
                                $ownerGecos = trim((string) $owner['gecos']);
                                if ($ownerGecos !== '') {
                                    $ownerLabel = $ownerGecos;
                                }
                            }
                            if (preg_match('/^u[0-9]{5,}$/', $ownerLabel)) {
                                $ownerLabel = 'System';
                            }
                        }
                        $canChatWithOwner = FM_USE_AUTH
                            && !empty($_SESSION[FM_SESSION_ID]['logged'])
                            && isset($auth_users)
                            && is_array($auth_users)
                            && isset($auth_users[$ownerName]);
                        $isSelfOwnerBadge = !empty($_SESSION[FM_SESSION_ID]['logged']) && $_SESSION[FM_SESSION_ID]['logged'] === $ownerName;
                        $canChatWithLastEditor = FM_USE_AUTH
                            && !empty($_SESSION[FM_SESSION_ID]['logged'])
                            && $lastEditorName !== ''
                            && isset($auth_users)
                            && is_array($auth_users)
                            && isset($auth_users[$lastEditorName]);
                        $isSelfLastEditorBadge = !empty($_SESSION[FM_SESSION_ID]['logged']) && $_SESSION[FM_SESSION_ID]['logged'] === $lastEditorName;
                        $actionNote = $fmBuildActionNote($appOwnerMeta, $modif, true);
                        ?>
                        <td class="fm-col-perms"><?php echo $perms ?></td>
                        <td class="fm-col-owner" data-owner-source="<?php echo $ownerSource === 'app' ? 'app' : 'system'; ?>">
                            <div class="fm-owner-stack">
                                <button
                                    type="button"
                                    class="badge border-0 fm-user-chat-badge fm-owner-badge <?php echo ($canChatWithOwner && !$isSelfOwnerBadge) ? 'text-bg-secondary' : 'text-bg-light'; ?>"
                                    data-chat-user="<?php echo ($canChatWithOwner && !$isSelfOwnerBadge) ? fm_enc($ownerName) : ''; ?>"
                                    title="<?php echo fm_enc($ownerTitle); ?>"
                                    <?php echo (!$canChatWithOwner || $isSelfOwnerBadge) ? 'disabled' : ''; ?>
                                >
                                    <i class="fa fa-user" aria-hidden="true"></i>
                                    <span><?php echo fm_enc($ownerLabel); ?></span>
                                </button>
                                <?php if ($lastEditorName !== ''): ?>
                                    <button
                                        type="button"
                                        class="badge border-0 fm-user-chat-badge fm-owner-badge fm-owner-last-editor-badge <?php echo ($canChatWithLastEditor && !$isSelfLastEditorBadge) ? 'text-bg-secondary' : 'text-bg-light'; ?>"
                                        data-chat-user="<?php echo ($canChatWithLastEditor && !$isSelfLastEditorBadge) ? fm_enc($lastEditorName) : ''; ?>"
                                        title="<?php echo fm_enc($lastEditorTitle); ?>"
                                        <?php echo (!$canChatWithLastEditor || $isSelfLastEditorBadge) ? 'disabled' : ''; ?>
                                    >
                                        <i class="fa fa-pencil" aria-hidden="true"></i>
                                        <span><?php echo fm_enc($lastEditorName); ?></span>
                                    </button>
                                <?php endif; ?>
                            </div>
                        </td>
                    <?php } ?>
                    <td class="fm-col-actions">
                        <div class="fm-action-note" title="<?php echo fm_enc($actionNote['title']); ?>">
                            <i class="fa fa-history" aria-hidden="true"></i>
                            <span><?php echo fm_enc($actionNote['label']); ?></span>
                        </div>
                        <div class="inline-actions">
                            <?php if (!FM_READONLY && !FM_UPLOAD_ONLY && FM_CAN_WRITE_IN_PATH): ?>
                                <?php if (!FM_MANAGER): ?>
                                <a title="<?php echo lng('Delete') ?>" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;del=<?php echo urlencode($f) ?>" onclick="confirmDailog(event, '1028','<?php echo lng('Delete') . ' ' . lng('Folder'); ?>','<?php echo urlencode($f) ?>', this.href);"> <i class="fa fa-trash-o" aria-hidden="true"></i></a>
                                <?php endif; ?>
                                <a title="<?php echo lng('Rename') ?>" href="#" onclick="rename('<?php echo fm_enc(addslashes(FM_PATH)) ?>', '<?php echo fm_enc(addslashes($f)) ?>');return false;"><i class="fa fa-pencil-square-o" aria-hidden="true"></i></a>
                                <a title="<?php echo lng('CopyTo') ?>..." href="?p=<?php echo urlencode(FM_PATH) ?>&amp;copy=<?php echo urlencode(trim(FM_PATH . '/' . $f, '/')) ?>"><i class="fa fa-files-o" aria-hidden="true"></i></a>
                            <?php endif; ?>
                            <a title="<?php echo lng('DirectLink') ?>" href="?p=<?php echo urlencode(trim(FM_PATH . '/' . $f, '/')) ?>" target="_blank"><i class="fa fa-link" aria-hidden="true"></i></a>
                        </div>
                    </td>
                </tr>
            <?php
                flush();
                $ii++;
            }
            // End foreach folders
            $ik = 8002;
            foreach ($files as $f) {
                $is_link = is_link($path . '/' . $f);
                $img = $is_link ? 'fa fa-file-text-o' : fm_get_file_icon_class($path . '/' . $f);
                $modif_raw = filemtime($path . '/' . $f);
                $modif = date(FM_DATETIME_FORMAT, $modif_raw);
                $date_sorting = strtotime(date("F d Y H:i:s.", $modif_raw));
                $filesize_raw = fm_get_size($path . '/' . $f);
                $filesize = fm_get_filesize($filesize_raw);
                $filelink = '?p=' . urlencode(FM_PATH) . '&amp;view=' . urlencode($f);
                $all_files_size += $filesize_raw;
                $perms = substr(decoct(fileperms($path . '/' . $f)), -4);
                $owner = array('name' => '?');
                $group = array('name' => '?');
                if (function_exists('posix_getpwuid') && function_exists('posix_getgrgid')) {
                    try {
                        $owner_id = fileowner($path . '/' . $f);
                        if ($owner_id != 0) {
                            $owner_info = posix_getpwuid($owner_id);
                            if ($owner_info) {
                                $owner =  $owner_info;
                            }
                        }
                        $group_id = filegroup($path . '/' . $f);
                        $group_info = posix_getgrgid($group_id);
                        if ($group_info) {
                            $group =  $group_info;
                        }
                    } catch (Exception $e) {
                        error_log("exception:" . $e->getMessage());
                    }
                }
            ?>
                <tr>
                    <?php if (!FM_READONLY && !FM_UPLOAD_ONLY && FM_CAN_WRITE_IN_PATH): ?>
                        <td class="custom-checkbox-td">
                            <div class="custom-control custom-checkbox">
                                <input type="checkbox" class="custom-control-input" id="<?php echo $ik ?>" name="file[]" value="<?php echo fm_enc($f) ?>">
                                <label class="custom-control-label" for="<?php echo $ik ?>"></label>
                            </div>
                        </td><?php endif; ?>
                    <td class="fm-col-name" data-sort=<?php echo fm_enc($f) ?>>
                        <div class="filename">
                            <?php
                            $ext_lower = strtolower(pathinfo($f, PATHINFO_EXTENSION));
                            $previewUrl = fm_enc(FM_SELF_PATH . '?' . fm_build_preview_query(FM_PATH, $f));
                            $item_mime = fm_get_mime_type($path . '/' . $f);
                            $previewType = '';
                            $isPdf = false;
                            if (in_array($ext_lower, array('gif', 'jpg', 'jpeg', 'png', 'bmp', 'ico', 'svg', 'webp', 'avif')) || fm_is_image_mime_type($item_mime)) {
                                $previewType = 'image';
                            } elseif (in_array($ext_lower, array('mp4', 'webm', 'ogg', 'mov', 'm4v'))) {
                                $previewType = 'video';
                            } elseif ($ext_lower === 'pdf') {
                                $isPdf = true;
                            }
                            ?>
                            <a href="<?php echo $filelink ?>" data-full-path="<?php echo fm_enc(trim(FM_PATH . '/' . $f, '/')); ?>" <?php echo $previewType ? 'data-preview-type="' . $previewType . '" data-preview-src="' . $previewUrl . '"' : ''; ?> <?php echo $isPdf ? 'data-preview-type="pdf"' : ''; ?> <?php echo $previewType === 'image' ? 'data-preview-image="' . $previewUrl . '"' : ''; ?> title="<?php echo fm_enc($f) ?>">
                                <i class="<?php echo $img ?>"></i> <?php echo fm_convert_win(fm_enc($f)) ?>
                            </a>
                            <?php echo ($is_link ? ' &rarr; <i>' . readlink($path . '/' . $f) . '</i>' : '') ?>
                        </div>
                    </td>
                    <td class="fm-col-size" data-order="b-<?php echo str_pad($filesize_raw, 18, "0", STR_PAD_LEFT); ?>"><span title="<?php printf('%s bytes', $filesize_raw) ?>">
                            <?php echo $filesize; ?>
                        </span></td>
                    <td class="fm-col-modified" data-order="b-<?php echo $date_sorting; ?>"><?php echo $modif ?></td>
                    <?php if (!FM_IS_WIN && !$hide_Cols): ?>
                        <?php
                        $ownerName = isset($owner['name']) ? (string) $owner['name'] : '?';
                        $groupName = isset($group['name']) ? (string) $group['name'] : '?';
                        $ownerTitle = $ownerName . ':' . $groupName;
                        $hasAppOwner = false;
                        $ownerSource = 'system';
                        $lastEditorName = '';
                        $lastEditorTitle = '';
                        $appOwnerMeta = function_exists('fm_owner_meta_get') ? fm_owner_meta_get($path . '/' . $f) : null;
                        if (is_array($appOwnerMeta)) {
                            $appCreatedBy = isset($appOwnerMeta['created_by']) ? trim((string) $appOwnerMeta['created_by']) : '';
                            $appUpdatedBy = isset($appOwnerMeta['updated_by']) ? trim((string) $appOwnerMeta['updated_by']) : '';
                            $ownerSource = isset($appOwnerMeta['owner_source']) ? strtolower(trim((string) $appOwnerMeta['owner_source'])) : '';
                            if ($ownerSource !== 'app' && $ownerSource !== 'system') {
                                $ownerSource = ($appCreatedBy !== '' && strtolower($appCreatedBy) !== 'system') ? 'app' : 'system';
                            }
                            if ($ownerSource === 'app' && $appCreatedBy !== '') {
                                $hasAppOwner = true;
                                $ownerName = $appCreatedBy;
                                $ownerLabel = $appCreatedBy;
                                $ownerTitle = 'App owner: ' . $appCreatedBy;
                                if ($appUpdatedBy !== '' && $appUpdatedBy !== $appCreatedBy) {
                                    $ownerTitle .= ' | Last update: ' . $appUpdatedBy;
                                }
                            } elseif ($ownerSource === 'system' && $appUpdatedBy !== '' && strtolower($appUpdatedBy) !== 'system') {
                                $lastEditorName = $appUpdatedBy;
                                $lastEditorTitle = 'Last update: ' . $appUpdatedBy;
                            }
                        }
                        $ownerLabel = $ownerName;
                        if (!$hasAppOwner) {
                            if (!empty($owner['gecos'])) {
                                $ownerGecos = trim((string) $owner['gecos']);
                                if ($ownerGecos !== '') {
                                    $ownerLabel = $ownerGecos;
                                }
                            }
                            if (preg_match('/^u[0-9]{5,}$/', $ownerLabel)) {
                                $ownerLabel = 'System';
                            }
                        }
                        $canChatWithOwner = FM_USE_AUTH
                            && !empty($_SESSION[FM_SESSION_ID]['logged'])
                            && isset($auth_users)
                            && is_array($auth_users)
                            && isset($auth_users[$ownerName]);
                        $isSelfOwnerBadge = !empty($_SESSION[FM_SESSION_ID]['logged']) && $_SESSION[FM_SESSION_ID]['logged'] === $ownerName;
                        $canChatWithLastEditor = FM_USE_AUTH
                            && !empty($_SESSION[FM_SESSION_ID]['logged'])
                            && $lastEditorName !== ''
                            && isset($auth_users)
                            && is_array($auth_users)
                            && isset($auth_users[$lastEditorName]);
                        $isSelfLastEditorBadge = !empty($_SESSION[FM_SESSION_ID]['logged']) && $_SESSION[FM_SESSION_ID]['logged'] === $lastEditorName;
                        $actionNote = $fmBuildActionNote($appOwnerMeta, $modif, false);
                        ?>
                        <td class="fm-col-perms"><?php if (!FM_READONLY): ?><a title="<?php echo 'Change Permissions' ?>" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;chmod=<?php echo urlencode($f) ?>"><?php echo $perms ?></a><?php else: ?><?php echo $perms ?><?php endif; ?>
                        </td>
                        <td class="fm-col-owner" data-owner-source="<?php echo $ownerSource === 'app' ? 'app' : 'system'; ?>">
                            <div class="fm-owner-stack">
                                <button
                                    type="button"
                                    class="badge border-0 fm-user-chat-badge fm-owner-badge <?php echo ($canChatWithOwner && !$isSelfOwnerBadge) ? 'text-bg-secondary' : 'text-bg-light'; ?>"
                                    data-chat-user="<?php echo ($canChatWithOwner && !$isSelfOwnerBadge) ? fm_enc($ownerName) : ''; ?>"
                                    title="<?php echo fm_enc($ownerTitle); ?>"
                                    <?php echo (!$canChatWithOwner || $isSelfOwnerBadge) ? 'disabled' : ''; ?>
                                >
                                    <i class="fa fa-user" aria-hidden="true"></i>
                                    <span><?php echo fm_enc($ownerLabel); ?></span>
                                </button>
                                <?php if ($lastEditorName !== ''): ?>
                                    <button
                                        type="button"
                                        class="badge border-0 fm-user-chat-badge fm-owner-badge fm-owner-last-editor-badge <?php echo ($canChatWithLastEditor && !$isSelfLastEditorBadge) ? 'text-bg-secondary' : 'text-bg-light'; ?>"
                                        data-chat-user="<?php echo ($canChatWithLastEditor && !$isSelfLastEditorBadge) ? fm_enc($lastEditorName) : ''; ?>"
                                        title="<?php echo fm_enc($lastEditorTitle); ?>"
                                        <?php echo (!$canChatWithLastEditor || $isSelfLastEditorBadge) ? 'disabled' : ''; ?>
                                    >
                                        <i class="fa fa-pencil" aria-hidden="true"></i>
                                        <span><?php echo fm_enc($lastEditorName); ?></span>
                                    </button>
                                <?php endif; ?>
                            </div>
                        </td>
                    <?php endif; ?>
                    <td class="fm-col-actions">
                        <div class="fm-action-note" title="<?php echo fm_enc($actionNote['title']); ?>">
                            <i class="fa fa-history" aria-hidden="true"></i>
                            <span><?php echo fm_enc($actionNote['label']); ?></span>
                        </div>
                        <div class="inline-actions">
                            <?php if (!FM_READONLY && !FM_UPLOAD_ONLY && FM_CAN_WRITE_IN_PATH): ?>
                                <?php if (!FM_MANAGER): ?>
                                <a title="<?php echo lng('Delete') ?>" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;del=<?php echo urlencode($f) ?>" onclick="confirmDailog(event, 1209, '<?php echo lng('Delete') . ' ' . lng('File'); ?>','<?php echo urlencode($f); ?>', this.href);"> <i class="fa fa-trash-o"></i></a>
                                <?php endif; ?>
                                <a title="<?php echo lng('Rename') ?>" href="#" onclick="rename('<?php echo fm_enc(addslashes(FM_PATH)) ?>', '<?php echo fm_enc(addslashes($f)) ?>');return false;"><i class="fa fa-pencil-square-o"></i></a>
                                <a title="<?php echo lng('CopyTo') ?>..."
                                    href="?p=<?php echo urlencode(FM_PATH) ?>&amp;copy=<?php echo urlencode(trim(FM_PATH . '/' . $f, '/')) ?>"><i class="fa fa-files-o"></i></a>
                            <?php endif; ?>
                            <a title="<?php echo lng('DirectLink') ?>" href="<?php echo fm_enc(FM_ROOT_URL . (FM_PATH != '' ? '/' . FM_PATH : '') . '/' . $f) ?>" target="_blank"><i class="fa fa-link"></i></a>
                            <a title="<?php echo lng('Download') ?>" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;dl=<?php echo urlencode($f) ?>" onclick="confirmDailog(event, 1211, '<?php echo lng('Download'); ?>','<?php echo urlencode($f); ?>', this.href);"><i class="fa fa-download"></i></a>
                        </div>
                    </td>
                </tr>
            <?php
                flush();
                $ik++;
            }
            // Close the foreach for $files

            if (empty($folders) && empty($files)) { ?>
                <tfoot>
                    <tr>
                        <?php if (!FM_READONLY && !FM_UPLOAD_ONLY && FM_CAN_WRITE_IN_PATH): ?><td></td><?php endif; ?>
                        <td><em><?php echo lng('Folder is empty') ?></em></td>
                        <td></td>
                        <td></td>
                        <?php if (!FM_IS_WIN && !$hide_Cols): ?><td></td><td></td><?php endif; ?>
                        <td></td>
                    </tr>
                </tfoot>
            <?php
            } else { ?>
                <tfoot>
                    <tr>
                        <?php if (!FM_READONLY && !FM_UPLOAD_ONLY && FM_CAN_WRITE_IN_PATH): ?><td></td><?php endif; ?>
                        <td class="gray fs-7">
                            <?php echo lng('FullSize') . ': <span class="badge text-bg-light border-radius-0">' . fm_get_filesize($all_files_size) . '</span>' ?>
                            <?php echo lng('File') . ': <span class="badge text-bg-light border-radius-0">' . $num_files . '</span>' ?>
                            <?php echo lng('Folder') . ': <span class="badge text-bg-light border-radius-0">' . $num_folders . '</span>' ?>
                        </td>
                        <td></td>
                        <td></td>
                        <?php if (!FM_IS_WIN && !$hide_Cols): ?><td></td><td></td><?php endif; ?>
                        <td></td>
                    </tr>
                </tfoot>
            <?php } ?>
                </table>
            </div>
            <div id="fm-grid-view" class="hidden"></div>
        </div>
    </div>

    <div class="row fm-footer-tools-row">
        <?php
        $footerLoggedUser = (FM_USE_AUTH && !empty($_SESSION[FM_SESSION_ID]['logged'])) ? $_SESSION[FM_SESSION_ID]['logged'] : '';
        $fm_bulk_toolbar_visible = defined('FM_BULK_ACTIONS_ENABLED') ? (bool) FM_BULK_ACTIONS_ENABLED : (!FM_READONLY && !FM_UPLOAD_ONLY && FM_CAN_WRITE_IN_PATH);
        $fm_bulk_can_modify = !FM_READONLY && !FM_UPLOAD_ONLY && FM_CAN_WRITE_IN_PATH;
        $fm_bulk_can_delete = $fm_bulk_can_modify && !FM_MANAGER;
        // Chat availability is role-agnostic: every logged-in user can communicate.
        $footerShowUserBadges = !empty($footerLoggedUser);
        $footerChatPeers = $footerShowUserBadges
            ? fm_chat_get_visible_peers(
                $footerLoggedUser,
                isset($auth_users) && is_array($auth_users) ? $auth_users : array(),
                isset($directories_users) && is_array($directories_users) ? $directories_users : array(),
                FM_ROOT_PATH,
                FM_USER_HOME_ROOT,
                isset($manager_users) && is_array($manager_users) ? $manager_users : array(),
                isset($user_manager_owners) && is_array($user_manager_owners) ? $user_manager_owners : array()
            )
            : array();
        $footerOnlineUsers = $footerShowUserBadges ? fm_online_get_users() : array();
        if (!empty($footerOnlineUsers) && !empty($footerChatPeers)) {
            $footerOnlineUsers = array_values(array_intersect($footerOnlineUsers, $footerChatPeers));
        }
        $footerReleaseVersion = fm_get_release_version();
        if ($footerReleaseVersion === '' || $footerReleaseVersion === 'dev') {
            $footerReleaseVersion = (string) VERSION;
        }
        $footerBuildLabel = 'tinyfilemanager DREMONT v' . $footerReleaseVersion;
        $footerCopyrightYear = (int) date('Y');
        $footerCopyrightLabel = '©' . $footerCopyrightYear . ' slapiar';
        if ($footerShowUserBadges && empty($footerOnlineUsers)) {
            $footerOnlineUsers = array($footerLoggedUser);
        }
        ?>
        <?php if ($fm_bulk_toolbar_visible): ?>
            <div class="fm-footer-actions-col">
                <div class="fm-mobile-bulk-header">
                    <strong>Hromadné akcie</strong>
                    <button type="button" class="btn-close btn-close-sm" data-fm-bulk-close aria-label="Close"></button>
                </div>
                <div class="fm-bulk-toolbar-wrapper d-none d-md-block">
                    <small class="text-muted fm-bulk-toolbar-label">Lišta hromadných akcií</small>
                    <div id="fm-selection-bar" class="btn-group flex-wrap" data-toggle="buttons" role="toolbar">
                    <span id="fm-selection-count" class="btn btn-small btn-outline-secondary btn-2 pe-none" style="display:none;">0</span>
                    <a href="#/select-all" class="btn btn-small btn-outline-primary btn-2" onclick="select_all();return false;"><i class="fa fa-check-square"></i> <?php echo lng('SelectAll') ?> </a>
                    <a href="#/unselect-all" class="btn btn-small btn-outline-primary btn-2" onclick="unselect_all();return false;"><i class="fa fa-window-close"></i> <?php echo lng('UnSelectAll') ?> </a>
                    <a href="#/invert-all" class="btn btn-small btn-outline-primary btn-2" onclick="invert_all();return false;"><i class="fa fa-th-list"></i> <?php echo lng('InvertSelection') ?> </a>
                    <input type="submit" class="hidden" name="download_selected" id="a-download-selected" value="download_selected">
                    <a href="javascript:document.getElementById('a-download-selected').click();" class="btn btn-small btn-outline-primary btn-2"><i class="fa fa-download"></i> <?php echo lng('Download') ?> ZIP</a>
                    <?php if ($fm_bulk_can_delete): ?>
                    <input type="submit" class="hidden" name="delete" id="a-delete" value="Delete" onclick="return confirm('<?php echo lng('Delete selected files and folders?'); ?>')">
                    <a href="javascript:document.getElementById('a-delete').click();" class="btn btn-small btn-outline-primary btn-2"><i class="fa fa-trash"></i> <?php echo lng('Delete') ?> </a>
                    <?php endif; ?>
                    <?php if ($fm_bulk_can_modify): ?>
                    <input type="submit" class="hidden" name="zip" id="a-zip" value="zip" onclick="return confirm('<?php echo lng('Create archive?'); ?>')">
                    <a href="javascript:document.getElementById('a-zip').click();" class="btn btn-small btn-outline-primary btn-2"><i class="fa fa-file-archive-o"></i> <?php echo lng('Zip') ?> </a>
                    <input type="submit" class="hidden" name="tar" id="a-tar" value="tar" onclick="return confirm('<?php echo lng('Create archive?'); ?>')">
                    <a href="javascript:document.getElementById('a-tar').click();" class="btn btn-small btn-outline-primary btn-2"><i class="fa fa-file-archive-o"></i> <?php echo lng('Tar') ?> </a>
                    <input type="hidden" id="fm-bulk-move-flag" value="1">
                    <input type="submit" class="hidden" name="copy" id="a-copy" value="Copy">
                    <a href="javascript:(function(){var f=document.getElementById('fm-bulk-move-flag');if(f){f.removeAttribute('name');}document.getElementById('a-copy').click();})();" class="btn btn-small btn-outline-primary btn-2"><i class="fa fa-files-o"></i> <?php echo lng('Copy') ?> </a>
                    <a href="javascript:(function(){var f=document.getElementById('fm-bulk-move-flag');if(f){f.setAttribute('name','move');}document.getElementById('a-copy').click();})();" class="btn btn-small btn-outline-primary btn-2"><i class="fa fa-arrows"></i> <?php echo lng('Move') ?> </a>
                    <?php endif; ?>
                    </div>
                </div>
            </div>
            <div class="fm-footer-online-col">
                <?php if ($footerShowUserBadges): ?>
                    <div class="d-flex gap-2 align-items-center flex-wrap justify-content-sm-end justify-content-start fm-online-users-wrap">
                        <button type="button" class="badge border-0 text-bg-primary fm-mobile-bulk-launcher" data-fm-bulk-open title="Hromadné akcie" aria-label="Hromadné akcie" aria-expanded="false">
                            <i class="fa fa-sliders" aria-hidden="true"></i>
                            <span class="fm-mobile-bulk-launcher__count" style="display:none;">0</span>
                        </button>
                        <span class="badge text-bg-light border"><?php echo lng('Online users') ?>: <?php echo count($footerOnlineUsers); ?></span>
                        <?php if ($footerLoggedUser === 'admin'): ?>
                            <button
                                type="button"
                                class="badge border-0 text-bg-danger js-reset-runtime-state"
                            >
                                <?php echo lng('Reset runtime state'); ?>
                            </button>
                        <?php endif; ?>
                        <button type="button" class="badge text-bg-warning border fm-chat-unread-badge" style="display:none;" data-chat-open-unread>
                            <?php echo lng('Unread'); ?>: <span class="fm-chat-unread-count">0</span>
                        </button>
                        <?php if (!empty($footerChatPeers)): ?>
                            <div class="input-group input-group-sm fm-chat-peer-picker">
                                <select class="form-select form-select-sm" data-chat-peer-select aria-label="Vyber používateľa pre správu">
                                    <option value="">Komu odkaz?</option>
                                    <?php foreach ($footerChatPeers as $chatPeer): ?>
                                        <option value="<?php echo fm_enc($chatPeer); ?>"><?php echo fm_enc($chatPeer); ?></option>
                                    <?php endforeach; ?>
                                </select>
                                <button type="button" class="btn btn-outline-primary" data-chat-open-peer>Napísať</button>
                            </div>
                        <?php endif; ?>
                        <?php foreach ($footerOnlineUsers as $onlineUser): ?>
                            <button
                                type="button"
                                class="badge border-0 fm-user-chat-badge <?php echo ($onlineUser === $footerLoggedUser) ? 'text-bg-primary' : 'text-bg-secondary'; ?>"
                                data-chat-user="<?php echo fm_enc($onlineUser); ?>"
                                <?php echo ($onlineUser === $footerLoggedUser) ? 'disabled' : ''; ?>
                            >
                                <?php echo fm_enc($onlineUser); ?>
                            </button>
                        <?php endforeach; ?>
                        <a href="https://tinyfilemanager.github.io" target="_blank" class="text-muted ms-sm-2" style="font-size: 0.67em;"><?php echo fm_enc($footerBuildLabel); ?></a>
                        <span class="text-muted ms-sm-2 fm-footer-copyright" style="font-size: 0.75em; font-weight: 300;"><?php echo fm_enc($footerCopyrightLabel); ?> · <a href="<?php echo fm_enc(FM_ROOT_URL . '/LICENSE'); ?>" target="_blank" class="text-muted">GNU GPL v3.0</a> · Made with the open source community · <a href="https://github.com/slapiar" target="_blank" class="text-muted">slapiar</a></span>
                    </div>
                <?php else: ?>
                    <div class="d-flex flex-column align-items-sm-end align-items-start gap-1 w-100">
                        <button type="button" class="badge border-0 text-bg-primary fm-mobile-bulk-launcher" data-fm-bulk-open title="Hromadné akcie" aria-label="Hromadné akcie" aria-expanded="false">
                            <i class="fa fa-sliders" aria-hidden="true"></i>
                            <span class="fm-mobile-bulk-launcher__count" style="display:none;">0</span>
                        </button>
                        <a href="https://tinyfilemanager.github.io" target="_blank" class="text-muted" style="font-size: 0.67em;"><?php echo fm_enc($footerBuildLabel); ?></a>
                        <span class="text-muted fm-footer-copyright" style="font-size: 0.75em; font-weight: 300;"><?php echo fm_enc($footerCopyrightLabel); ?> · <a href="<?php echo fm_enc(FM_ROOT_URL . '/LICENSE'); ?>" target="_blank" class="text-muted">GNU GPL v3.0</a> · Made with the open source community · <a href="https://github.com/slapiar" target="_blank" class="text-muted">slapiar</a></span>
                    </div>
                <?php endif; ?>
            </div>
        <?php else: ?>
            <div class="col-12">
                <?php if ($footerShowUserBadges): ?>
                    <div class="float-right d-flex gap-2 align-items-center flex-wrap">
                        <span class="badge text-bg-light border"><?php echo lng('Online users') ?>: <?php echo count($footerOnlineUsers); ?></span>
                        <?php if ($footerLoggedUser === 'admin'): ?>
                            <button
                                type="button"
                                class="badge border-0 text-bg-danger js-reset-runtime-state"
                            >
                                <?php echo lng('Reset runtime state'); ?>
                            </button>
                        <?php endif; ?>
                        <button type="button" class="badge text-bg-warning border fm-chat-unread-badge" style="display:none;" data-chat-open-unread>
                            <?php echo lng('Unread'); ?>: <span class="fm-chat-unread-count">0</span>
                        </button>
                        <?php if (!empty($footerChatPeers)): ?>
                            <div class="input-group input-group-sm fm-chat-peer-picker">
                                <select class="form-select form-select-sm" data-chat-peer-select aria-label="Vyber používateľa pre správu">
                                    <option value="">Komu odkaz?</option>
                                    <?php foreach ($footerChatPeers as $chatPeer): ?>
                                        <option value="<?php echo fm_enc($chatPeer); ?>"><?php echo fm_enc($chatPeer); ?></option>
                                    <?php endforeach; ?>
                                </select>
                                <button type="button" class="btn btn-outline-primary" data-chat-open-peer>Napísať</button>
                            </div>
                        <?php endif; ?>
                        <?php foreach ($footerOnlineUsers as $onlineUser): ?>
                            <button
                                type="button"
                                class="badge border-0 fm-user-chat-badge <?php echo ($onlineUser === $footerLoggedUser) ? 'text-bg-primary' : 'text-bg-secondary'; ?>"
                                data-chat-user="<?php echo fm_enc($onlineUser); ?>"
                                <?php echo ($onlineUser === $footerLoggedUser) ? 'disabled' : ''; ?>
                            >
                                <?php echo fm_enc($onlineUser); ?>
                            </button>
                        <?php endforeach; ?>
                        <a href="https://tinyfilemanager.github.io" target="_blank" class="text-muted ms-sm-2" style="font-size: 0.67em;"><?php echo fm_enc($footerBuildLabel); ?></a>
                        <span class="text-muted ms-sm-2 fm-footer-copyright" style="font-size: 0.75em; font-weight: 300;"><?php echo fm_enc($footerCopyrightLabel); ?> · <a href="<?php echo fm_enc(FM_ROOT_URL . '/LICENSE'); ?>" target="_blank" class="text-muted">GNU GPL v3.0</a> · Made with the open source community · <a href="https://github.com/slapiar" target="_blank" class="text-muted">slapiar</a></span>
                    </div>
                <?php else: ?>
                    <div class="d-flex flex-column align-items-sm-end align-items-start gap-1">
                        <a href="https://tinyfilemanager.github.io" target="_blank" class="text-muted" style="font-size: 0.67em;"><?php echo fm_enc($footerBuildLabel); ?></a>
                        <span class="text-muted fm-footer-copyright" style="font-size: 0.75em; font-weight: 300;"><?php echo fm_enc($footerCopyrightLabel); ?> · <a href="<?php echo fm_enc(FM_ROOT_URL . '/LICENSE'); ?>" target="_blank" class="text-muted">GNU GPL v3.0</a> · Made with the open source community · <a href="https://github.com/slapiar" target="_blank" class="text-muted">slapiar</a></span>
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>
    <?php if ($fm_bulk_toolbar_visible): ?>
        <button type="button" id="fm-mobile-bulk-backdrop" class="fm-mobile-bulk-backdrop" data-fm-bulk-close aria-hidden="true" tabindex="-1"></button>
    <?php endif; ?>
</form>

<div id="fm-context-menu" class="fm-context-menu hidden" role="menu" aria-hidden="true">
    <div class="fm-context-menu__title">Context menu</div>
    <div class="fm-context-menu__meta" data-context-menu-meta>Empty space</div>
    <div class="fm-context-menu__items">
        <button type="button" class="fm-context-menu__item" data-context-menu-item="primary"><i class="fa fa-folder-open-o fm-context-menu__icon" aria-hidden="true"></i><span class="fm-context-menu__item-label">Open</span></button>
        <button type="button" class="fm-context-menu__item" data-context-menu-item="secondary"><i class="fa fa-pencil-square-o fm-context-menu__icon" aria-hidden="true"></i><span class="fm-context-menu__item-label">Rename</span></button>
        <button type="button" class="fm-context-menu__item" data-context-menu-item="third"><i class="fa fa-files-o fm-context-menu__icon" aria-hidden="true"></i><span class="fm-context-menu__item-label">Copy</span></button>
    </div>
</div>

<script src="src/assets/js/fm-folder-tree.js?v=<?php echo VERSION; ?>"></script>

<script>
    (function () {
        var resetButtons = document.querySelectorAll('.js-reset-runtime-state');
        if (!resetButtons.length) {
            return;
        }

        var token = <?php echo json_encode($_SESSION['token']); ?>;
        var requestInFlight = false;

        function setBusyState(isBusy) {
            for (var i = 0; i < resetButtons.length; i++) {
                resetButtons[i].disabled = isBusy;
                if (isBusy) {
                    resetButtons[i].setAttribute('aria-busy', 'true');
                } else {
                    resetButtons[i].removeAttribute('aria-busy');
                }
            }
        }

        function onResetClick(event) {
            event.preventDefault();
            if (requestInFlight) {
                return;
            }

            if (!window.confirm('Resetovat cache a vsetky pripojenia?')) {
                return;
            }

            requestInFlight = true;
            setBusyState(true);

            var body = new URLSearchParams();
            body.append('ajax', '1');
            body.append('type', 'reset_runtime_state');
            body.append('token', token);

            fetch(window.location.href, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
                },
                body: body.toString(),
                credentials: 'same-origin'
            }).then(function (response) {
                return response.json();
            }).then(function (payload) {
                if (!payload || payload.success !== true) {
                    throw new Error((payload && payload.msg) ? payload.msg : 'Reset zlyhal.');
                }
                window.location.reload();
            }).catch(function (error) {
                window.alert(error && error.message ? error.message : 'Reset zlyhal.');
            }).finally(function () {
                requestInFlight = false;
                setBusyState(false);
            });
        }

        for (var i = 0; i < resetButtons.length; i++) {
            resetButtons[i].addEventListener('click', onResetClick);
        }
    })();
</script>

<style>
    .fm-explorer-layout {
        --fm-explorer-font-size: .82rem;
        --fm-explorer-row-height: 34px;
        --fm-explorer-header-height: 34px;
        --fm-tree-font-size: .62rem;
        --fm-tree-indent-size: .83rem;
        --fm-tree-toggle-size: 1.1rem;
        --fm-sidebar-width: 250px;
        display: flex;
        align-items: stretch;
        gap: 12px;
        margin-bottom: 10px;
    }

    .fm-folder-sidebar {
        width: var(--fm-sidebar-width);
        min-width: 220px;
        border: 1px solid rgba(120, 130, 150, 0.35);
        border-radius: 12px;
        background: var(--fmx-surface, #f9fafb);
        display: flex;
        flex-direction: column;
        overflow: hidden;
        max-height: 72vh;
    }

    .fm-sidebar-resizer {
        width: 10px;
        align-self: stretch;
        cursor: col-resize;
        position: relative;
        border-radius: 8px;
        touch-action: none;
        user-select: none;
        background: transparent;
        flex: 0 0 auto;
    }

    .fm-sidebar-resizer::before {
        content: '';
        position: absolute;
        top: 10px;
        bottom: 10px;
        left: 50%;
        width: 2px;
        transform: translateX(-50%);
        background: rgba(120, 130, 150, 0.42);
        border-radius: 999px;
    }

    .fm-explorer-layout.is-resizing {
        user-select: none;
        cursor: col-resize;
    }

    .fm-explorer-layout.is-resizing * {
        cursor: col-resize !important;
    }

    .fm-folder-sidebar__title {
        min-height: var(--fm-explorer-header-height);
        padding: .35rem .7rem;
        font-weight: 600;
        font-size: var(--fm-tree-font-size);
        line-height: 1.2;
        display: flex;
        align-items: center;
        border-bottom: 1px solid rgba(120, 130, 150, 0.25);
        letter-spacing: .01em;
    }

    .fm-folder-sidebar__path {
        display: flex;
        align-items: flex-start;
        gap: .45rem;
        min-height: var(--fm-explorer-row-height);
        padding: .35rem .7rem;
        color: rgba(33, 37, 41, .74);
        border-bottom: 1px solid rgba(120, 130, 150, 0.2);
        font-size: var(--fm-tree-font-size);
        line-height: 1.25;
        white-space: normal;
        overflow: visible;
        text-overflow: clip;
    }

    .fm-folder-sidebar__path i {
        margin-top: .1rem;
        flex: 0 0 auto;
    }

    .fm-folder-sidebar__path span {
        flex: 1 1 auto;
        min-width: 0;
        white-space: normal;
        overflow-wrap: break-word;
        word-break: normal;
    }

    .fm-folder-sidebar__list {
        padding: .4rem;
        overflow: auto;
        overflow-x: auto;
    }

    .fm-folder-tree {
        display: block;
        min-width: 0;
    }

    .fm-context-menu {
        position: fixed;
        z-index: 1090;
        min-width: 210px;
        padding: .55rem;
        border: 1px solid var(--fmx-border);
        border-radius: 12px;
        background: var(--fmx-surface);
        box-shadow: 0 16px 38px rgba(15, 23, 42, 0.22);
    }

    .fm-context-menu__title {
        font-size: .72rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: .06em;
        color: var(--fmx-subtle);
        margin-bottom: .35rem;
    }

    .fm-context-menu__meta {
        font-size: .82rem;
        font-weight: 600;
        margin-bottom: .45rem;
        color: var(--fmx-text);
    }

    .fm-context-menu__items {
        display: grid;
        gap: .35rem;
    }

    .fm-context-menu__item {
        width: 100%;
        display: flex;
        align-items: center;
        gap: .55rem;
        border: 1px solid var(--fmx-border);
        border-radius: 10px;
        background: transparent;
        color: var(--fmx-text);
        padding: .45rem .65rem;
        text-align: left;
        font-size: .82rem;
        cursor: not-allowed;
        opacity: .72;
    }

    .fm-context-menu__icon {
        width: 1.15rem;
        text-align: center;
        color: var(--fmx-accent);
        flex: 0 0 auto;
    }

    .fm-tree-node {
        display: flex;
        align-items: center;
        gap: .15rem;
        min-height: var(--fm-explorer-row-height);
        border-radius: 8px;
        padding: .1rem .15rem;
    }

    .fm-tree-node--depth-2 {
        margin-left: 0;
    }

    .fm-tree-node.is-active {
        background: rgba(13, 110, 253, 0.1);
    }

    .fm-tree-node.is-loading .fm-tree-label {
        opacity: .65;
    }

    .fm-tree-toggle {
        width: var(--fm-tree-toggle-size);
        height: var(--fm-tree-toggle-size);
        border: 0;
        border-radius: 6px;
        background: transparent;
        color: inherit;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        flex: 0 0 auto;
        cursor: pointer;
    }

    .fm-tree-toggle .fa {
        transition: transform .14s ease;
    }

    .fm-tree-node.is-expanded > .fm-tree-toggle .fa {
        transform: rotate(90deg);
    }

    .fm-tree-toggle.is-leaf {
        cursor: default;
        opacity: .35;
    }

    .fm-tree-toggle:focus-visible,
    .fm-tree-label:focus-visible {
        outline: 2px solid rgba(13, 110, 253, 0.55);
        outline-offset: 1px;
    }

    .fm-tree-label {
        display: inline-flex;
        align-items: center;
        gap: .34rem;
        min-height: 1.45rem;
        flex: 1 1 auto;
        min-width: 0;
        padding: .15rem .25rem;
        border-radius: 8px;
        color: inherit;
        text-decoration: none;
        font-size: var(--fm-tree-font-size);
        line-height: 1.2;
    }

    .fm-tree-label:hover,
    .fm-tree-label:focus-visible {
        background: rgba(13, 110, 253, 0.1);
        color: inherit;
        text-decoration: none;
    }

    .fm-tree-label span {
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }

    .fm-tree-label.is-active {
        font-weight: 700;
    }

    .fm-tree-children {
        margin-left: var(--fm-tree-indent-size);
        border-left: 1px dashed rgba(120, 130, 150, 0.35);
        padding-left: .22rem;
    }

    .fm-tree-empty {
        font-size: .78rem;
        color: rgba(33, 37, 41, .62);
        padding: .35rem .4rem .45rem 1.8rem;
    }

    .fm-tree-error {
        border: 0;
        background: transparent;
        color: #c98017;
        font-size: .78rem;
        text-align: left;
        padding: .35rem .4rem .45rem 1.8rem;
        width: 100%;
    }

    html[data-bs-theme="dark"] .fm-tree-node.is-active {
        background: rgba(110, 162, 255, 0.18);
    }

    html[data-bs-theme="dark"] .fm-tree-label:hover,
    html[data-bs-theme="dark"] .fm-tree-label:focus-visible {
        background: rgba(110, 162, 255, 0.16);
    }

    html[data-bs-theme="dark"] .fm-tree-empty {
        color: rgba(220, 229, 241, .68);
    }

    .fm-explorer-main {
        flex: 1 1 auto;
        min-width: 0;
    }

    .fm-explorer-main #main-table.fm-modern-table thead th,
    .fm-explorer-main #main-table.fm-modern-table tbody td {
        min-height: var(--fm-explorer-row-height);
        font-size: var(--fm-explorer-font-size);
        line-height: 1.2;
    }

    .fm-footer-tools-row {
        display: flex;
        flex-wrap: wrap;
        align-items: flex-start;
        row-gap: .5rem;
    }

    .fm-footer-actions-col {
        flex: 1 1 58%;
        min-width: 320px;
    }

    .fm-footer-online-col {
        flex: 1 1 42%;
        min-width: 300px;
        display: flex;
        justify-content: flex-end;
        align-items: center;
    }

    .fm-online-users-wrap {
        width: 100%;
    }

    .fm-mobile-bulk-launcher,
    .fm-mobile-bulk-backdrop,
    .fm-mobile-bulk-header {
        display: none;
    }

    .fm-mobile-bulk-launcher {
        position: relative;
        min-width: 36px;
        min-height: 28px;
        align-items: center;
        justify-content: center;
        gap: .2rem;
        cursor: pointer;
    }

    .fm-mobile-bulk-launcher__count {
        position: absolute;
        top: -6px;
        right: -6px;
        min-width: 17px;
        height: 17px;
        border-radius: 999px;
        background: #dc3545;
        color: #fff;
        font-size: .66rem;
        line-height: 17px;
        text-align: center;
        padding: 0 4px;
    }

    @media (max-width: 991.98px) {
        .fm-explorer-layout {
            flex-direction: column;
        }

        .fm-folder-sidebar {
            width: 100%;
            min-width: 0;
            max-height: none;
        }

        .fm-sidebar-resizer {
            display: none;
        }

        .fm-folder-sidebar__list {
            max-height: 180px;
        }

        .fm-footer-tools-row {
            flex-wrap: wrap;
            align-items: flex-start;
            column-gap: .5rem;
            row-gap: .45rem;
            overflow: visible;
            padding-bottom: .2rem;
        }

        .fm-footer-actions-col {
            position: fixed;
            left: 10px;
            right: 10px;
            bottom: 12px;
            z-index: 1056;
            min-width: 0;
            max-width: none;
            background: rgba(255, 255, 255, 0.98);
            border: 1px solid rgba(120, 130, 150, 0.33);
            border-radius: 14px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, .22);
            padding: .62rem;
            transform: translateY(calc(100% + 20px));
            opacity: 0;
            pointer-events: none;
            transition: transform .18s ease, opacity .18s ease;
        }

        html[data-bs-theme="dark"] .fm-footer-actions-col {
            background: rgba(31, 35, 40, 0.98);
            border-color: rgba(255, 255, 255, 0.16);
        }

        .fm-footer-actions-col.is-open {
            transform: translateY(0);
            opacity: 1;
            pointer-events: auto;
        }

        .fm-mobile-bulk-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: .45rem;
            font-size: .88rem;
        }

        .fm-mobile-bulk-backdrop {
            display: block;
            position: fixed;
            inset: 0;
            border: 0;
            background: rgba(0, 0, 0, .22);
            z-index: 1055;
            opacity: 0;
            pointer-events: none;
            transition: opacity .18s ease;
        }

        .fm-mobile-bulk-backdrop.is-visible {
            opacity: 1;
            pointer-events: auto;
        }

        .fm-mobile-bulk-launcher {
            display: inline-flex;
        }

        .fm-footer-tools-row #fm-selection-bar {
            display: flex;
            flex-wrap: wrap;
            min-width: 0;
            overflow: visible;
            white-space: normal;
            width: 100%;
            padding: 0;
            gap: .38rem;
        }

        .fm-footer-online-col {
            flex: 1 1 100%;
            min-width: 0;
            max-width: none;
            justify-content: flex-start;
        }

        .fm-footer-tools-row #fm-selection-bar .btn.btn-2,
        .fm-footer-tools-row #fm-selection-bar #fm-selection-count {
            flex: 0 0 auto;
            min-height: 34px;
            padding-top: 0.2rem;
            padding-bottom: 0.2rem;
        }

        .fm-online-users-wrap {
            display: flex;
            flex-wrap: wrap !important;
            overflow: visible;
            white-space: normal;
            justify-content: flex-start;
            width: 100%;
            gap: .35rem !important;
            padding-bottom: 2px;
        }

        .fm-online-users-wrap .badge,
        .fm-online-users-wrap .fm-user-chat-badge,
        .fm-online-users-wrap .js-reset-runtime-state {
            flex: 0 0 auto;
        }

        .fm-online-users-wrap::-webkit-scrollbar,
        .fm-footer-tools-row::-webkit-scrollbar {
            height: 5px;
        }

        .fm-online-users-wrap::-webkit-scrollbar-thumb,
        .fm-footer-tools-row::-webkit-scrollbar-thumb {
            background: rgba(120, 130, 150, 0.45);
            border-radius: 999px;
        }

        .fm-online-users-wrap::-webkit-scrollbar-track,
        .fm-footer-tools-row::-webkit-scrollbar-track {
            background: transparent;
        }
    }

    @media (max-width: 575.98px) {
        .fm-footer-online-col {
            min-width: 0;
            max-width: 100%;
        }

        .fm-footer-tools-row #fm-selection-bar .btn.btn-2,
        .fm-footer-tools-row #fm-selection-bar #fm-selection-count {
            min-height: 32px;
            font-size: .78rem;
        }

        .fm-online-users-wrap .badge,
        .fm-online-users-wrap .fm-user-chat-badge,
        .fm-online-users-wrap .js-reset-runtime-state {
            font-size: .72rem;
        }
    }
</style>

<script>
    (function () {
        var explorerLayoutEl = document.querySelector('.fm-explorer-layout');
        var sidebarEl = document.querySelector('.fm-folder-sidebar');
        var sidebarResizerEl = document.getElementById('fm-sidebar-resizer');
        var SIDEBAR_STORAGE_KEY = 'fm.sidebar.width';
        var SIDEBAR_MIN_WIDTH = 190;
        var SIDEBAR_MAX_RATIO = 0.58;
        var mediumViewportQuery = window.matchMedia ? window.matchMedia('(max-width: 991.98px)') : null;
        var sidebarDragging = false;

        var filterEl = document.getElementById('fm-owner-source-filter');
        var tableEl = document.getElementById('main-table');
        var tableWrapEl = document.querySelector('.fm-table-wrap');
        var gridViewEl = document.getElementById('fm-grid-view');
        var viewButtons = document.querySelectorAll('.js-view-mode');
        var countAppEl = document.getElementById('fm-owner-count-app');
        var countSystemEl = document.getElementById('fm-owner-count-system');
        var countBadgeEls = document.querySelectorAll('.fm-owner-source-count[data-owner-filter-target]');
        var selectionCountEl = document.getElementById('fm-selection-count');
        var bulkPanelEl = document.querySelector('.fm-footer-actions-col');
        var bulkOpenButtonEl = document.querySelector('[data-fm-bulk-open]');
        var bulkBackdropEl = document.getElementById('fm-mobile-bulk-backdrop');
        var bulkCloseButtonEls = document.querySelectorAll('[data-fm-bulk-close]');
        var mobileBulkCountEl = document.querySelector('.fm-mobile-bulk-launcher__count');
        var canCreateNewItem = <?php echo (!FM_READONLY && !FM_UPLOAD_ONLY && FM_CAN_WRITE_IN_PATH) ? 'true' : 'false'; ?>;
        if (!tableEl) {
            return;
        }

        var currentViewMode = 'list';
        var floatingPanelEl = null;
        var floatingPanelTitleEl = null;
        var floatingPanelActionsEl = null;
        var activeFloatingRow = null;
        var contextMenuEl = document.getElementById('fm-context-menu');
        var contextMenuMetaEl = contextMenuEl ? contextMenuEl.querySelector('[data-context-menu-meta]') : null;
        var contextMenuItemEls = contextMenuEl ? contextMenuEl.querySelectorAll('[data-context-menu-item]') : [];
        var hoverShowTimer = null;
        var hoverHideTimer = null;
        var HOVER_SHOW_DELAY_MS = 120;
        var HOVER_HIDE_DELAY_MS = 180;

        var dataTableFilterInstalled = false;

        function isMobileBulkViewport() {
            return !!(window.matchMedia && window.matchMedia('(max-width: 991.98px)').matches);
        }

        function getSelectedItemsCount() {
            var checked = tableEl.querySelectorAll('input[name="file[]"]:checked');
            return checked ? checked.length : 0;
        }

        function closeMobileBulkPanel() {
            if (!bulkPanelEl) {
                return;
            }

            bulkPanelEl.classList.remove('is-open');
            if (bulkBackdropEl) {
                bulkBackdropEl.classList.remove('is-visible');
            }
            if (bulkOpenButtonEl) {
                bulkOpenButtonEl.setAttribute('aria-expanded', 'false');
            }
        }

        function openMobileBulkPanel() {
            if (!bulkPanelEl || !isMobileBulkViewport()) {
                return;
            }

            bulkPanelEl.classList.add('is-open');
            if (bulkBackdropEl) {
                bulkBackdropEl.classList.add('is-visible');
            }
            if (bulkOpenButtonEl) {
                bulkOpenButtonEl.setAttribute('aria-expanded', 'true');
            }
        }

        function updateSelectionBarState() {
            var selectedCount = getSelectedItemsCount();

            if (selectionCountEl) {
                selectionCountEl.textContent = String(selectedCount);
                selectionCountEl.style.display = selectedCount > 0 ? '' : 'none';
            }

            if (mobileBulkCountEl) {
                mobileBulkCountEl.textContent = String(selectedCount);
                mobileBulkCountEl.style.display = selectedCount > 0 ? '' : 'none';
            }
        }

        window.fmUpdateSelectionBar = updateSelectionBarState;

        function getSidebarMaxWidth() {
            if (!explorerLayoutEl) {
                return 520;
            }

            var layoutWidth = explorerLayoutEl.getBoundingClientRect().width;
            if (!layoutWidth || layoutWidth <= 0) {
                return 520;
            }

            return Math.max(SIDEBAR_MIN_WIDTH + 30, Math.round(layoutWidth * SIDEBAR_MAX_RATIO));
        }

        function clampSidebarWidth(width) {
            var numeric = Number(width);
            if (!isFinite(numeric)) {
                return SIDEBAR_MIN_WIDTH;
            }

            var min = SIDEBAR_MIN_WIDTH;
            var max = getSidebarMaxWidth();
            if (numeric < min) {
                return min;
            }
            if (numeric > max) {
                return max;
            }
            return Math.round(numeric);
        }

        function applySidebarWidth(width, persist) {
            if (!sidebarEl || (mediumViewportQuery && mediumViewportQuery.matches)) {
                return;
            }

            var clamped = clampSidebarWidth(width);
            sidebarEl.style.width = clamped + 'px';
            sidebarEl.style.minWidth = clamped + 'px';
            sidebarEl.style.maxWidth = clamped + 'px';

            if (persist) {
                try {
                    window.localStorage.setItem(SIDEBAR_STORAGE_KEY, String(clamped));
                } catch (e) {
                    // ignore storage errors
                }
            }
        }

        function resetSidebarWidthForSmallScreens() {
            if (!sidebarEl) {
                return;
            }

            sidebarEl.style.width = '';
            sidebarEl.style.minWidth = '';
            sidebarEl.style.maxWidth = '';
        }

        function loadStoredSidebarWidth() {
            if (!sidebarEl || (mediumViewportQuery && mediumViewportQuery.matches)) {
                return;
            }

            try {
                var raw = window.localStorage.getItem(SIDEBAR_STORAGE_KEY);
                if (raw !== null && raw !== '') {
                    applySidebarWidth(raw, false);
                }
            } catch (e) {
                // ignore storage errors
            }
        }

        function setupSidebarResizer() {
            if (!sidebarEl || !sidebarResizerEl || !explorerLayoutEl || !window.PointerEvent) {
                return;
            }

            function onPointerMove(event) {
                if (!sidebarDragging) {
                    return;
                }

                var layoutRect = explorerLayoutEl.getBoundingClientRect();
                var desiredWidth = event.clientX - layoutRect.left;
                applySidebarWidth(desiredWidth, false);
            }

            function stopDrag(event) {
                if (!sidebarDragging) {
                    return;
                }

                sidebarDragging = false;
                explorerLayoutEl.classList.remove('is-resizing');
                if (event && sidebarResizerEl.releasePointerCapture) {
                    try {
                        sidebarResizerEl.releasePointerCapture(event.pointerId);
                    } catch (e) {
                        // ignore release errors
                    }
                }

                var width = sidebarEl.getBoundingClientRect().width;
                applySidebarWidth(width, true);
            }

            sidebarResizerEl.addEventListener('pointerdown', function (event) {
                if (mediumViewportQuery && mediumViewportQuery.matches) {
                    return;
                }

                event.preventDefault();
                sidebarDragging = true;
                explorerLayoutEl.classList.add('is-resizing');
                if (sidebarResizerEl.setPointerCapture) {
                    sidebarResizerEl.setPointerCapture(event.pointerId);
                }
            });

            sidebarResizerEl.addEventListener('pointermove', onPointerMove);
            sidebarResizerEl.addEventListener('pointerup', stopDrag);
            sidebarResizerEl.addEventListener('pointercancel', stopDrag);
            sidebarResizerEl.addEventListener('lostpointercapture', stopDrag);

            if (mediumViewportQuery) {
                var handleViewportChange = function () {
                    if (mediumViewportQuery.matches) {
                        resetSidebarWidthForSmallScreens();
                    } else {
                        loadStoredSidebarWidth();
                    }
                };

                if (typeof mediumViewportQuery.addEventListener === 'function') {
                    mediumViewportQuery.addEventListener('change', handleViewportChange);
                } else if (typeof mediumViewportQuery.addListener === 'function') {
                    mediumViewportQuery.addListener(handleViewportChange);
                }
            }

            window.addEventListener('resize', function () {
                if (mediumViewportQuery && mediumViewportQuery.matches) {
                    return;
                }

                var currentWidth = sidebarEl.getBoundingClientRect().width;
                applySidebarWidth(currentWidth, false);
            });

            loadStoredSidebarWidth();
        }

        function getSelectedSource() {
            return (filterEl.value || 'all').toLowerCase();
        }

        function rowMatchesFilter(row) {
            if (!filterEl) {
                return true;
            }
            var selected = getSelectedSource();
            if (selected === 'all') {
                return true;
            }

            var ownerCell = row.querySelector('td.fm-col-owner[data-owner-source]');
            if (!ownerCell) {
                return true;
            }

            return String(ownerCell.getAttribute('data-owner-source') || 'system').toLowerCase() === selected;
        }

        function applyPlainFilter() {
            var rows = tableEl.querySelectorAll('tbody tr');
            rows.forEach(function (row) {
                if (row.classList.contains('fm-parent-row')) {
                    row.style.display = '';
                    return;
                }
                row.style.display = rowMatchesFilter(row) ? '' : 'none';
            });
        }

        function refreshOwnerSourceCounts() {
            if (!countAppEl && !countSystemEl) {
                return;
            }
            var appCount = 0;
            var systemCount = 0;
            var ownerCells = tableEl.querySelectorAll('tbody td.fm-col-owner[data-owner-source]');

            ownerCells.forEach(function (cell) {
                var src = String(cell.getAttribute('data-owner-source') || 'system').toLowerCase();
                if (src === 'app') {
                    appCount++;
                } else {
                    systemCount++;
                }
            });

            if (countAppEl) {
                countAppEl.textContent = 'App: ' + appCount;
            }
            if (countSystemEl) {
                countSystemEl.textContent = 'System: ' + systemCount;
            }

            var selected = filterEl ? getSelectedSource() : 'all';
            countBadgeEls.forEach(function (el) {
                var target = String(el.getAttribute('data-owner-filter-target') || '').toLowerCase();
                if (target && target === selected) {
                    el.classList.add('is-active');
                } else {
                    el.classList.remove('is-active');
                }
            });
        }

        function ensureDataTableFilter() {
            if (!(window.jQuery && window.jQuery.fn && window.jQuery.fn.dataTable && window.jQuery.fn.dataTable.ext && window.jQuery.fn.dataTable.ext.search)) {
                return false;
            }

            if (!dataTableFilterInstalled) {
                window.jQuery.fn.dataTable.ext.search.push(function (settings, data, dataIndex) {
                    if (!settings || !settings.nTable || settings.nTable.id !== 'main-table') {
                        return true;
                    }

                    var api = new window.jQuery.fn.dataTable.Api(settings);
                    var rowNode = api.row(dataIndex).node();
                    if (!rowNode) {
                        return true;
                    }

                    if (rowNode.classList && rowNode.classList.contains('fm-parent-row')) {
                        return true;
                    }

                    return rowMatchesFilter(rowNode);
                });
                dataTableFilterInstalled = true;
            }

            if (window.mainTable && typeof window.mainTable.draw === 'function') {
                window.mainTable.draw();
                return true;
            }

            if (window.jQuery.fn.dataTable.isDataTable('#main-table')) {
                window.mainTable = window.jQuery('#main-table').DataTable();
                window.mainTable.draw();
                return true;
            }

            return false;
        }

        function applyFilter() {
            var dataTableApplied = false;
            if (filterEl) {
                dataTableApplied = ensureDataTableFilter();
            }
            if (!dataTableApplied) {
                applyPlainFilter();
            }
            refreshOwnerSourceCounts();
            if (currentViewMode === 'grid') {
                renderGridFromVisibleRows();
            }
        }

        function htmlEscape(value) {
            return String(value || '')
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        function hideContextMenu() {
            if (!contextMenuEl) {
                return;
            }
            contextMenuEl.classList.add('hidden');
            contextMenuEl.setAttribute('aria-hidden', 'true');
        }

        function getContextMenuModel(menuType) {
            if (menuType === 'folder') {
                return {
                    label: 'Folder',
                    items: [
                        { label: 'Open folder', action: 'open', icon: 'fa-folder-open-o' },
                        { label: 'Rename', action: 'rename', icon: 'fa-pencil-square-o' },
                        { label: 'Copy', action: 'copy', icon: 'fa-files-o' }
                    ]
                };
            }

            if (menuType === 'file') {
                return {
                    label: 'File',
                    items: [
                        { label: 'Open file', action: 'open', icon: 'fa-file-o' },
                        { label: 'Rename', action: 'rename', icon: 'fa-pencil-square-o' },
                        { label: 'Copy', action: 'copy', icon: 'fa-files-o' }
                    ]
                };
            }

            return {
                label: 'Empty space',
                items: [
                    { label: 'Upload', action: 'upload', icon: 'fa-cloud-upload' },
                    { label: 'New item', action: 'newItem', icon: 'fa-plus-square' },
                    { label: 'Refresh', action: 'refresh', icon: 'fa-refresh' }
                ]
            };
        }

        function showContextMenu(menuType, label, href, x, y) {
            if (!contextMenuEl) {
                return;
            }

            var model = getContextMenuModel(menuType || 'empty');
            contextMenuMetaEl.textContent = (label || model.label || 'Empty space') + ' • ' + (menuType || 'empty');
            contextMenuEl.dataset.contextMenuType = menuType || 'empty';
            contextMenuEl.dataset.contextMenuHref = href || '';
            contextMenuEl.dataset.contextMenuPath = '';
            contextMenuEl.dataset.contextMenuName = '';

            if (menuType === 'folder' && href) {
                var folderPath = '';
                try {
                    var folderUrl = new URL(href, window.location.href);
                    folderPath = folderUrl.searchParams.get('p') || '';
                } catch (e) {
                }
                contextMenuEl.dataset.contextMenuPath = folderPath;
                contextMenuEl.dataset.contextMenuName = label || '';
            } else if (menuType === 'file' && href) {
                contextMenuEl.dataset.contextMenuPath = href;
                contextMenuEl.dataset.contextMenuName = label || '';
            } else {
                var currentPathInput = document.querySelector('input[name="p"]');
                contextMenuEl.dataset.contextMenuPath = currentPathInput ? String(currentPathInput.value || '') : '';
            }

            contextMenuEl.style.left = Math.max(8, x) + 'px';
            contextMenuEl.style.top = Math.max(8, y) + 'px';
            contextMenuItemEls.forEach(function (itemEl, index) {
                var itemLabelEl = itemEl.querySelector('.fm-context-menu__item-label');
                var iconEl = itemEl.querySelector('.fm-context-menu__icon');
                var itemData = model.items[index] || { label: '', action: '' };
                if (!itemLabelEl) {
                    return;
                }
                itemLabelEl.textContent = itemData.label || '';
                if (iconEl) {
                    iconEl.className = 'fa fm-context-menu__icon ' + (itemData.icon || 'fa-circle-o');
                }
                itemEl.disabled = false;
                itemEl.dataset.contextMenuAction = itemData.action || '';
            });
            contextMenuEl.classList.remove('hidden');
            contextMenuEl.setAttribute('aria-hidden', 'false');
        }

        function detectContextMenuTarget(target) {
            var menuType = 'empty';
            var label = 'Empty space';

            if (!target || !target.closest) {
                return { type: menuType, label: label };
            }

            var treeLabel = target.closest('.fm-tree-label');
            if (treeLabel) {
                menuType = 'folder';
                label = treeLabel.textContent.trim() || 'Folder';
                return { type: menuType, label: label, href: treeLabel.getAttribute('href') || '' };
            }

            var row = target.closest('tbody tr');
            if (row && !row.classList.contains('fm-parent-row')) {
                var folderIcon = row.querySelector('td.fm-col-name i.fa-folder-o, td.fm-col-name i.icon-link_folder');
                var nameCell = row.querySelector('td.fm-col-name .filename a');
                var fullPath = nameCell ? (nameCell.getAttribute('data-full-path') || '') : '';
                label = nameCell ? (nameCell.textContent || '').trim() : 'Item';
                if (folderIcon) {
                    menuType = 'folder';
                } else {
                    menuType = 'file';
                }
                return { type: menuType, label: label || (menuType === 'folder' ? 'Folder' : 'File'), href: nameCell ? (nameCell.getAttribute('href') || '') : '', fullPath: fullPath };
            }

            return { type: menuType, label: label, href: '' };
        }

        function getBaseName(path) {
            var clean = String(path || '').replace(/^\/+|\/+$/g, '');
            if (!clean) {
                return '';
            }
            var parts = clean.split('/');
            return parts.pop() || '';
        }

        function getParentPath(path) {
            var clean = String(path || '').replace(/^\/+|\/+$/g, '');
            if (!clean || clean.indexOf('/') === -1) {
                return '';
            }
            return clean.split('/').slice(0, -1).join('/');
        }

        function collectVisibleRows() {
            var rows = tableEl.querySelectorAll('tbody tr');
            var items = [];
            rows.forEach(function (row) {
                if (row.classList.contains('fm-parent-row')) {
                    return;
                }

                if (!rowMatchesFilter(row)) {
                    return;
                }

                var display = window.getComputedStyle(row).display;
                if (display === 'none') {
                    return;
                }

                var nameCell = row.querySelector('td.fm-col-name .filename');
                if (!nameCell) {
                    return;
                }

                var nameLink = nameCell.querySelector('a');
                if (!nameLink) {
                    return;
                }

                var iconEl = nameLink.querySelector('i');
                var sizeCell = row.querySelector('td.fm-col-size');
                var modCell = row.querySelector('td.fm-col-modified');
                var ownerCell = row.querySelector('td.fm-col-owner');
                var actionsWrap = row.querySelector('td.fm-col-actions .inline-actions');
                var ownerSource = ownerCell ? String(ownerCell.getAttribute('data-owner-source') || 'system').toLowerCase() : 'system';

                items.push({
                    nameHtml: nameLink.outerHTML,
                    iconClass: iconEl ? iconEl.className : 'fa fa-file-o',
                    sizeText: sizeCell ? (sizeCell.textContent || '').trim() : '',
                    modText: modCell ? (modCell.textContent || '').trim() : '',
                    ownerHtml: ownerCell ? ownerCell.innerHTML : '',
                    ownerSource: ownerSource,
                    actionsHtml: actionsWrap ? actionsWrap.innerHTML : '',
                });
            });
            return items;
        }

        function renderGridFromVisibleRows() {
            if (!gridViewEl) {
                return;
            }

            var items = collectVisibleRows();
            if (!items.length) {
                gridViewEl.innerHTML = '<div class="alert alert-light border mb-0">Ziadne polozky pre aktualny filter.</div>';
                return;
            }

            var cards = items.map(function (item) {
                var ownerSourceBadge = item.ownerSource === 'app' ? '<span class="badge text-bg-primary">App</span>' : '<span class="badge text-bg-secondary">System</span>';
                return '<div class="card fm-grid-item">'
                    + '<div class="fm-grid-thumb"><i class="' + htmlEscape(item.iconClass) + '"></i></div>'
                    + '<div class="fm-grid-body">'
                    + '<div class="fm-grid-name">' + item.nameHtml + '</div>'
                    + '<div class="fm-grid-meta"><span>' + htmlEscape(item.sizeText) + '</span><span>' + htmlEscape(item.modText) + '</span></div>'
                    + '<div class="d-flex align-items-center justify-content-between mt-2"><div class="small">' + item.ownerHtml + '</div>' + ownerSourceBadge + '</div>'
                    + '</div>'
                    + '<div class="fm-grid-actions"><div class="inline-actions">' + item.actionsHtml + '</div></div>'
                    + '</div>';
            }).join('');

            gridViewEl.innerHTML = '<div class="fm-grid">' + cards + '</div>';
        }

        function openCreateNewItemModal() {
            if (!canCreateNewItem) {
                return;
            }

            var modalEl = document.getElementById('createNewItem');
            if (!modalEl) {
                return;
            }

            if (window.bootstrap && window.bootstrap.Modal) {
                window.bootstrap.Modal.getOrCreateInstance(modalEl).show();
                return;
            }

            if (window.jQuery && window.jQuery.fn && typeof window.jQuery.fn.modal === 'function') {
                window.jQuery(modalEl).modal('show');
            }
        }

        function ensureFloatingPanel() {
            if (floatingPanelEl) {
                return;
            }

            floatingPanelEl = document.createElement('div');
            floatingPanelEl.id = 'fm-row-actions-float';
            floatingPanelEl.className = 'fm-row-actions-float hidden';
            floatingPanelEl.innerHTML = ''
                + '<div class="fm-row-actions-float__header">'
                + '  <span class="fm-row-actions-float__title"></span>'
                + '  <button type="button" class="btn btn-sm btn-outline-primary fm-row-actions-float__new" title="<?php echo fm_enc(lng('NewItem')); ?>" aria-label="<?php echo fm_enc(lng('NewItem')); ?>"><i class="fa fa-plus-square" aria-hidden="true"></i></button>'
                + '  <button type="button" class="btn-close btn-close-sm fm-row-actions-float__close" aria-label="Close"></button>'
                + '</div>'
                + '<div class="inline-actions fm-row-actions-float__actions"></div>';

            document.body.appendChild(floatingPanelEl);
            floatingPanelTitleEl = floatingPanelEl.querySelector('.fm-row-actions-float__title');
            floatingPanelActionsEl = floatingPanelEl.querySelector('.fm-row-actions-float__actions');

            var closeBtn = floatingPanelEl.querySelector('.fm-row-actions-float__close');
            var newBtn = floatingPanelEl.querySelector('.fm-row-actions-float__new');
            if (newBtn) {
                if (!canCreateNewItem) {
                    newBtn.classList.add('hidden');
                    newBtn.setAttribute('disabled', 'disabled');
                } else {
                    newBtn.addEventListener('click', function () {
                        openCreateNewItemModal();
                    });
                }
            }
            if (closeBtn) {
                closeBtn.addEventListener('click', function () {
                    hideFloatingPanel();
                });
            }

            floatingPanelEl.addEventListener('mouseenter', function () {
                if (hoverHideTimer) {
                    window.clearTimeout(hoverHideTimer);
                    hoverHideTimer = null;
                }
            });

            floatingPanelEl.addEventListener('mouseleave', function () {
                if (currentViewMode === 'list' && !isNarrowViewport()) {
                    scheduleHideFloatingPanel();
                }
            });
        }

        function hideFloatingPanel() {
            if (!floatingPanelEl) {
                return;
            }
            floatingPanelEl.classList.add('hidden');
            activeFloatingRow = null;
        }

        function scheduleShowFloatingPanel(row) {
            if (hoverHideTimer) {
                window.clearTimeout(hoverHideTimer);
                hoverHideTimer = null;
            }
            if (hoverShowTimer) {
                window.clearTimeout(hoverShowTimer);
            }
            hoverShowTimer = window.setTimeout(function () {
                showFloatingActionsForRow(row);
                hoverShowTimer = null;
            }, HOVER_SHOW_DELAY_MS);
        }

        function scheduleHideFloatingPanel() {
            if (hoverShowTimer) {
                window.clearTimeout(hoverShowTimer);
                hoverShowTimer = null;
            }
            if (hoverHideTimer) {
                window.clearTimeout(hoverHideTimer);
            }
            hoverHideTimer = window.setTimeout(function () {
                hideFloatingPanel();
                hoverHideTimer = null;
            }, HOVER_HIDE_DELAY_MS);
        }

        function isNarrowViewport() {
            return window.matchMedia && window.matchMedia('(max-width: 767.98px)').matches;
        }

        function positionFloatingPanel(row) {
            if (!floatingPanelEl || !row) {
                return;
            }

            if (isNarrowViewport()) {
                floatingPanelEl.style.top = 'auto';
                floatingPanelEl.style.bottom = '12px';
                floatingPanelEl.style.right = '10px';
                return;
            }

            var rect = row.getBoundingClientRect();
            var panelRect = floatingPanelEl.getBoundingClientRect();
            var top = window.scrollY + rect.top + (rect.height / 2) - (panelRect.height / 2);
            var minTop = window.scrollY + 10;
            var maxTop = window.scrollY + window.innerHeight - panelRect.height - 10;
            if (top < minTop) {
                top = minTop;
            }
            if (top > maxTop) {
                top = maxTop;
            }

            floatingPanelEl.style.top = Math.round(top) + 'px';
            floatingPanelEl.style.bottom = 'auto';
            floatingPanelEl.style.right = '12px';
        }

        function showFloatingActionsForRow(row) {
            if (currentViewMode !== 'list' || !row || row.classList.contains('fm-parent-row')) {
                return;
            }

            var actionWrap = row.querySelector('td.fm-col-actions .inline-actions');
            if (!actionWrap || !floatingPanelActionsEl || !floatingPanelTitleEl) {
                return;
            }

            var titleEl = row.querySelector('td.fm-col-name .filename a');
            var titleText = titleEl ? (titleEl.textContent || '').trim() : 'Akcie';
            floatingPanelTitleEl.textContent = titleText;
            floatingPanelActionsEl.innerHTML = actionWrap.innerHTML;
            floatingPanelEl.classList.remove('hidden');
            activeFloatingRow = row;
            positionFloatingPanel(row);
        }

        function bindFloatingRowActions() {
            ensureFloatingPanel();

            tableEl.addEventListener('mouseover', function (event) {
                if (currentViewMode !== 'list' || isNarrowViewport()) {
                    return;
                }
                var row = event.target.closest('tbody tr');
                if (!row || row === activeFloatingRow) {
                    return;
                }
                scheduleShowFloatingPanel(row);
            });

            tableEl.addEventListener('click', function (event) {
                if (currentViewMode !== 'list' || !isNarrowViewport()) {
                    return;
                }

                if (event.target.closest('a,button,input,label')) {
                    return;
                }

                var row = event.target.closest('tbody tr');
                if (!row || row.classList.contains('fm-parent-row')) {
                    return;
                }

                showFloatingActionsForRow(row);
            });

            if (tableWrapEl) {
                tableWrapEl.addEventListener('mouseenter', function () {
                    if (hoverHideTimer) {
                        window.clearTimeout(hoverHideTimer);
                        hoverHideTimer = null;
                    }
                });

                tableWrapEl.addEventListener('mouseleave', function () {
                    if (!isNarrowViewport()) {
                        scheduleHideFloatingPanel();
                    }
                });
            }

            window.addEventListener('scroll', function () {
                if (floatingPanelEl && !floatingPanelEl.classList.contains('hidden') && activeFloatingRow) {
                    positionFloatingPanel(activeFloatingRow);
                }
            }, { passive: true });

            window.addEventListener('resize', function () {
                if (floatingPanelEl && !floatingPanelEl.classList.contains('hidden') && activeFloatingRow) {
                    positionFloatingPanel(activeFloatingRow);
                }
            });
        }

        function bindContextMenu() {
            if (!contextMenuEl) {
                return;
            }

            document.addEventListener('click', function () {
                hideContextMenu();
            });

            contextMenuEl.addEventListener('click', function (event) {
                var button = event.target && event.target.closest ? event.target.closest('[data-context-menu-action]') : null;
                if (!button || button.disabled) {
                    return;
                }

                var action = button.getAttribute('data-context-menu-action') || '';
                var menuType = contextMenuEl.dataset.contextMenuType || 'empty';
                var href = contextMenuEl.dataset.contextMenuHref || '';
                var path = contextMenuEl.dataset.contextMenuPath || '';
                var name = contextMenuEl.dataset.contextMenuName || '';
                hideContextMenu();

                if (action === 'open' && href) {
                    window.location.href = href;
                    return;
                }

                if (action === 'rename' && path) {
                    var renameBasePath = getParentPath(path);
                    var renameName = name || getBaseName(path);
                    if (renameName && typeof rename === 'function') {
                        rename(renameBasePath, renameName);
                    }
                    return;
                }

                if (action === 'copy' && path) {
                    var currentCopyPathInput = document.querySelector('input[name="p"]');
                    var currentCopyPath = currentCopyPathInput ? String(currentCopyPathInput.value || '') : '';
                    window.location.href = '?p=' + encodeURIComponent(currentCopyPath) + '&copy=' + encodeURIComponent(path);
                    return;
                }

                if (action === 'upload' && menuType === 'empty') {
                    window.location.href = '?p=' + encodeURIComponent(path) + '&upload';
                    return;
                }

                if (action === 'newItem' && menuType === 'empty') {
                    openCreateNewItemModal();
                    return;
                }

                if (action === 'refresh' && menuType === 'empty') {
                    window.location.reload();
                }
            });

            document.addEventListener('contextmenu', function (event) {
                var shell = event.target && event.target.closest ? event.target.closest('.fm-shell, .fm-explorer-layout, #main-table, .fm-folder-sidebar') : null;
                if (!shell) {
                    hideContextMenu();
                    return;
                }

                event.preventDefault();
                var detected = detectContextMenuTarget(event.target);
                var actionHref = detected.href || detected.fullPath || '';
                showContextMenu(detected.type, detected.label, actionHref, event.clientX, event.clientY);
            });
        }

        function setViewMode(mode) {
            currentViewMode = mode === 'grid' ? 'grid' : 'list';

            viewButtons.forEach(function (btn) {
                var btnMode = String(btn.getAttribute('data-view-mode') || 'list');
                var active = btnMode === currentViewMode;
                btn.classList.toggle('active', active);
            });

            if (tableWrapEl) {
                tableWrapEl.classList.toggle('hidden', currentViewMode === 'grid');
            }
            if (gridViewEl) {
                gridViewEl.classList.toggle('hidden', currentViewMode !== 'grid');
            }

            document.body.classList.toggle('fm-list-mode', currentViewMode === 'list');
            document.body.classList.toggle('fm-grid-mode', currentViewMode === 'grid');

            if (currentViewMode === 'grid') {
                if (hoverShowTimer) {
                    window.clearTimeout(hoverShowTimer);
                    hoverShowTimer = null;
                }
                if (hoverHideTimer) {
                    window.clearTimeout(hoverHideTimer);
                    hoverHideTimer = null;
                }
                hideFloatingPanel();
                renderGridFromVisibleRows();
            }
        }

        if (filterEl) {
            filterEl.addEventListener('change', applyFilter);
        }
        countBadgeEls.forEach(function (badge) {
            function applyTargetFilter() {
                var target = String(badge.getAttribute('data-owner-filter-target') || '').toLowerCase();
                if (!target || !filterEl) {
                    return;
                }
                filterEl.value = target;
                applyFilter();
            }

            badge.addEventListener('click', applyTargetFilter);
            badge.addEventListener('keydown', function (event) {
                if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    applyTargetFilter();
                }
            });
        });
        viewButtons.forEach(function (btn) {
            btn.addEventListener('click', function () {
                var mode = String(btn.getAttribute('data-view-mode') || 'list');
                setViewMode(mode);
            });
        });
        setupSidebarResizer();
        bindFloatingRowActions();
        bindContextMenu();

        if (bulkOpenButtonEl) {
            bulkOpenButtonEl.addEventListener('click', function () {
                if (bulkPanelEl && bulkPanelEl.classList.contains('is-open')) {
                    closeMobileBulkPanel();
                } else {
                    openMobileBulkPanel();
                }
            });
        }

        bulkCloseButtonEls.forEach(function (button) {
            button.addEventListener('click', function () {
                closeMobileBulkPanel();
            });
        });

        if (bulkPanelEl) {
            bulkPanelEl.addEventListener('click', function (event) {
                if (!isMobileBulkViewport()) {
                    return;
                }

                if (event.target && event.target.closest && event.target.closest('#fm-selection-bar a')) {
                    window.setTimeout(closeMobileBulkPanel, 120);
                }
            });
        }

        document.addEventListener('keydown', function (event) {
            if (event.key === 'Escape') {
                closeMobileBulkPanel();
            }
        });

        window.addEventListener('resize', function () {
            if (!isMobileBulkViewport()) {
                closeMobileBulkPanel();
            }
        });

        tableEl.addEventListener('change', function (event) {
            if (event.target && event.target.matches && event.target.matches('input[name="file[]"]')) {
                updateSelectionBarState();
            }
        });

        updateSelectionBarState();
        refreshOwnerSourceCounts();
        window.setTimeout(function () {
            applyFilter();
            setViewMode('list');
            updateSelectionBarState();
        }, 0);
    })();
</script>

<?php if ($footerShowUserBadges): ?>
    <style>
        .fm-user-chat-badge.fm-chat-ringing {
            background-color: #dc3545 !important;
            color: #fff !important;
            animation: fm-chat-ring-blink 0.85s steps(2, jump-none) infinite;
        }

        .fm-chat-history {
            background: var(--bs-body-bg);
            color: var(--bs-body-color);
        }

        .fm-chat-bubble {
            border: 1px solid transparent;
            max-width: 75%;
        }

        .fm-chat-bubble--mine {
            background: var(--bs-primary);
            color: #fff;
        }

        .fm-chat-bubble--theirs {
            background: var(--bs-body-bg);
            color: var(--bs-body-color);
            border-color: rgba(120, 130, 150, 0.28);
        }

        .fm-chat-unread-list .list-group-item {
            background: var(--bs-body-bg);
            color: var(--bs-body-color);
            border-color: rgba(120, 130, 150, 0.22);
        }

        .fm-chat-unread-list .list-group-item:hover,
        .fm-chat-unread-list .list-group-item:focus {
            background: rgba(13, 110, 253, 0.08);
            color: var(--bs-body-color);
        }

        .fm-chat-peer-picker {
            min-width: 220px;
            max-width: 320px;
        }

        .fm-chat-peer-picker .form-select,
        .fm-chat-peer-picker .btn {
            font-size: .78rem;
            min-height: 28px;
        }

        html[data-bs-theme="dark"] .fm-chat-modal .modal-content,
        html[data-bs-theme="dark"] .fm-chat-unread-modal .modal-content {
            background: #1f2328;
            color: #e7edf5;
            border-color: rgba(255, 255, 255, 0.12);
        }

        html[data-bs-theme="dark"] .fm-chat-modal .modal-header,
        html[data-bs-theme="dark"] .fm-chat-modal .modal-footer,
        html[data-bs-theme="dark"] .fm-chat-unread-modal .modal-header {
            border-color: rgba(255, 255, 255, 0.12);
        }

        html[data-bs-theme="dark"] .fm-chat-history {
            background: #1f2328;
            color: #e7edf5;
        }

        html[data-bs-theme="dark"] .fm-chat-bubble--theirs {
            background: #2a3037;
            color: #e7edf5;
            border-color: rgba(255, 255, 255, 0.12);
        }

        html[data-bs-theme="dark"] .fm-chat-bubble--mine {
            background: #0d6efd;
            color: #fff;
        }

        html[data-bs-theme="dark"] .fm-chat-unread-list .list-group-item {
            background: #1f2328;
            color: #e7edf5;
            border-color: rgba(255, 255, 255, 0.12);
        }

        html[data-bs-theme="dark"] .fm-chat-unread-list .list-group-item:hover,
        html[data-bs-theme="dark"] .fm-chat-unread-list .list-group-item:focus {
            background: rgba(110, 162, 255, 0.16);
            color: #e7edf5;
        }

        @keyframes fm-chat-ring-blink {
            50% {
                opacity: 0.35;
            }
        }
    </style>

    <div class="modal fade fm-chat-modal" id="fm-chat-modal" tabindex="-1" aria-labelledby="fm-chat-modal-label" aria-hidden="true">
        <div class="modal-dialog modal-dialog-scrollable modal-lg modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="fm-chat-modal-label">Chat</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body p-0">
                    <div id="fm-chat-history" class="p-3 fm-chat-history" style="max-height: 420px; overflow-y: auto;"></div>
                </div>
                <div class="modal-footer">
                    <form id="fm-chat-form" class="w-100 d-flex gap-2 m-0">
                        <input type="text" id="fm-chat-input" class="form-control" maxlength="2000" placeholder="Write a message..." autocomplete="off">
                        <button type="submit" class="btn btn-primary">Send</button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <div class="modal fade fm-chat-unread-modal" id="fm-chat-unread-modal" tabindex="-1" aria-labelledby="fm-chat-unread-modal-label" aria-hidden="true">
        <div class="modal-dialog modal-dialog-scrollable modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="fm-chat-unread-modal-label"><?php echo lng('Unread'); ?></h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body p-0">
                    <div id="fm-chat-unread-list" class="list-group list-group-flush fm-chat-unread-list"></div>
                </div>
            </div>
        </div>
    </div>

    <script>
        (function () {
            var currentUser = <?php echo json_encode($footerLoggedUser); ?>;
            if (!currentUser) {
                return;
            }

            var modalEl = document.getElementById('fm-chat-modal');
            var historyEl = document.getElementById('fm-chat-history');
            var formEl = document.getElementById('fm-chat-form');
            var inputEl = document.getElementById('fm-chat-input');
            var titleEl = document.getElementById('fm-chat-modal-label');
            var unreadListModalEl = document.getElementById('fm-chat-unread-modal');
            var unreadListEl = document.getElementById('fm-chat-unread-list');
            var tokenEl = document.querySelector('input[name="token"]');
            var badges = document.querySelectorAll('.fm-user-chat-badge[data-chat-user]');
            var unreadCountEls = document.querySelectorAll('.fm-chat-unread-count');
            var unreadBadgeEls = document.querySelectorAll('.fm-chat-unread-badge');
            var peerPickerButtons = document.querySelectorAll('[data-chat-open-peer]');

            if (!modalEl || !historyEl || !formEl || !inputEl || !titleEl || !tokenEl) {
                return;
            }

            var modal = null;
            var unreadListModal = null;
            var state = {
                peer: '',
                timer: null,
                inboxTimer: null,
                inboxInitialized: false,
                lastIncomingBySender: {},
                unreadInboxItems: {},
                unreadBySender: {},
                lastReadBySender: {},
            };

            var readStateStorageKey = 'tfm-chat-read:' + currentUser;

            var badgeByUser = {};
            badges.forEach(function (badge) {
                var u = badge.getAttribute('data-chat-user') || '';
                if (u) {
                    badgeByUser[u] = badge;
                }
            });

            function loadReadState() {
                try {
                    var raw = window.localStorage ? window.localStorage.getItem(readStateStorageKey) : '';
                    if (!raw) {
                        return;
                    }
                    var data = JSON.parse(raw);
                    if (data && typeof data === 'object') {
                        state.lastReadBySender = data;
                    }
                } catch (e) {
                }
            }

            function saveReadState() {
                try {
                    if (window.localStorage) {
                        window.localStorage.setItem(readStateStorageKey, JSON.stringify(state.lastReadBySender));
                    }
                } catch (e) {
                }
            }

            function setUnreadCount(total) {
                unreadCountEls.forEach(function (el) {
                    el.textContent = String(total);
                });
                unreadBadgeEls.forEach(function (el) {
                    el.style.display = total > 0 ? '' : 'none';
                });
            }

            function recomputeUnreadCount() {
                var total = 0;
                Object.keys(state.unreadBySender).forEach(function (sender) {
                    var count = Number(state.unreadBySender[sender] || 0);
                    if (count > 0) {
                        total += count;
                    }
                });
                setUnreadCount(total);
            }

            function markSenderRead(sender, id) {
                if (!sender || !id) {
                    return;
                }
                var readId = Number(state.lastReadBySender[sender] || 0);
                if (id > readId) {
                    state.lastReadBySender[sender] = id;
                    saveReadState();
                }

                if (state.unreadInboxItems[sender]) {
                    state.unreadInboxItems[sender].unread_count = 0;
                }
                delete state.unreadBySender[sender];
                recomputeUnreadCount();
            }

            function chatMarkRead(peer, lastId) {
                if (!peer) {
                    return Promise.resolve(false);
                }

                var url = new URL(window.location.href);
                url.searchParams.set('chat_action', 'mark_read');

                var body = new URLSearchParams();
                body.set('with', peer);
                body.set('token', tokenEl.value || '');
                if (lastId && Number(lastId) > 0) {
                    body.set('last_id', String(Number(lastId)));
                }

                return fetch(url.toString(), {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
                    },
                    credentials: 'same-origin',
                    body: body.toString()
                }).then(function (response) {
                    return response.json();
                }).then(function (payload) {
                    return !!(payload && payload.ok === true);
                }).catch(function () {
                    return false;
                });
            }

            function markBadgeRinging(user, ring) {
                if (!user || !badgeByUser[user]) {
                    return;
                }
                badgeByUser[user].classList[ring ? 'add' : 'remove']('fm-chat-ringing');
            }

            function showModal() {
                var hasBootstrap5Modal = !!(window.bootstrap && window.bootstrap.Modal);
                var hasJQueryModal = !!(window.jQuery && window.jQuery.fn && window.jQuery.fn.modal);

                if (hasBootstrap5Modal) {
                    if (!modal) {
                        modal = new window.bootstrap.Modal(modalEl);
                    }
                    modal.show();
                    return;
                }

                if (hasJQueryModal) {
                    window.jQuery(modalEl).modal('show');
                    return;
                }

                // Last-resort fallback when Bootstrap JS is not available.
                modalEl.style.display = 'block';
                modalEl.classList.add('show');
                modalEl.removeAttribute('aria-hidden');
            }

            function bindModalHidden(handler) {
                if (modalEl.addEventListener) {
                    modalEl.addEventListener('hidden.bs.modal', handler);
                }
                if (window.jQuery && window.jQuery.fn && window.jQuery.fn.modal) {
                    window.jQuery(modalEl).on('hidden.bs.modal', handler);
                }
            }

            function bindFallbackClose() {
                var closeEls = modalEl.querySelectorAll('[data-bs-dismiss="modal"], .btn-close');
                closeEls.forEach(function (closeEl) {
                    closeEl.addEventListener('click', function () {
                        modalEl.classList.remove('show');
                        modalEl.style.display = 'none';
                        modalEl.setAttribute('aria-hidden', 'true');
                        stopPolling();
                        clearPeerNotification(state.peer);
                        state.peer = '';
                        formEl.reset();
                    });
                });
            }

            function openChatWithPeer(peer) {
                if (!peer || peer === currentUser) {
                    return;
                }

                state.peer = peer;
                clearPeerNotification(peer);
                titleEl.textContent = 'Chat with ' + peer;
                historyEl.innerHTML = '<div class="text-muted small p-2">Loading...</div>';
                showModal();
                chatFetch();
                startPolling();
            }

            function renderUnreadInboxList() {
                if (!unreadListEl) {
                    return;
                }

                var rows = Object.keys(state.unreadInboxItems).map(function (sender) {
                    var item = state.unreadInboxItems[sender] || {};
                    var unreadCount = Number(item.unread_count || 0);
                    if (unreadCount <= 0) {
                        return null;
                    }

                    return {
                        sender: sender,
                        unreadCount: unreadCount,
                        id: Number(item.id || 0),
                        message: String(item.message || ''),
                        createdAt: Number(item.created_at || 0)
                    };
                }).filter(function (item) {
                    return !!item;
                }).sort(function (a, b) {
                    return b.createdAt - a.createdAt;
                });

                if (!rows.length) {
                    unreadListEl.innerHTML = '<div class="text-muted small p-3"><?php echo fm_enc(lng('Unread')); ?>: 0</div>';
                    return;
                }

                var html = rows.map(function (row) {
                    return '<button type="button" class="list-group-item list-group-item-action d-flex justify-content-between align-items-start" data-chat-unread-peer="' + esc(row.sender) + '">'
                        + '<div class="me-2">'
                        + '<div class="fw-semibold">' + esc(row.sender) + '</div>'
                        + '<div class="small text-muted text-truncate" style="max-width: 330px;">' + esc(row.message) + '</div>'
                        + '<div class="small text-muted">' + esc(formatTime(row.createdAt)) + '</div>'
                        + '</div>'
                        + '<span class="badge text-bg-warning rounded-pill">' + String(row.unreadCount) + '</span>'
                        + '</button>';
                }).join('');

                unreadListEl.innerHTML = html;
                unreadListEl.querySelectorAll('[data-chat-unread-peer]').forEach(function (buttonEl) {
                    buttonEl.addEventListener('click', function () {
                        var peer = buttonEl.getAttribute('data-chat-unread-peer') || '';
                        if (!peer) {
                            return;
                        }

                        if (unreadListModal && typeof unreadListModal.hide === 'function') {
                            unreadListModal.hide();
                        } else if (window.jQuery && window.jQuery.fn && window.jQuery.fn.modal && unreadListModalEl) {
                            window.jQuery(unreadListModalEl).modal('hide');
                        } else if (unreadListModalEl) {
                            unreadListModalEl.classList.remove('show');
                            unreadListModalEl.style.display = 'none';
                            unreadListModalEl.setAttribute('aria-hidden', 'true');
                        }

                        openChatWithPeer(peer);
                    });
                });
            }

            function showUnreadListModal() {
                if (!unreadListModalEl || !unreadListEl) {
                    return;
                }

                renderUnreadInboxList();

                if (window.bootstrap && window.bootstrap.Modal) {
                    if (!unreadListModal) {
                        unreadListModal = new window.bootstrap.Modal(unreadListModalEl);
                    }
                    unreadListModal.show();
                    return;
                }

                if (window.jQuery && window.jQuery.fn && window.jQuery.fn.modal) {
                    window.jQuery(unreadListModalEl).modal('show');
                    return;
                }

                unreadListModalEl.style.display = 'block';
                unreadListModalEl.classList.add('show');
                unreadListModalEl.removeAttribute('aria-hidden');
            }

            function esc(value) {
                return String(value)
                    .replace(/&/g, '&amp;')
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;')
                    .replace(/"/g, '&quot;')
                    .replace(/'/g, '&#39;');
            }

            function formatTime(ts) {
                if (!ts) {
                    return '';
                }
                return new Date(ts * 1000).toLocaleString();
            }

            function renderMessages(messages) {
                if (!Array.isArray(messages) || messages.length === 0) {
                    historyEl.innerHTML = '<div class="text-muted small p-2"><?php echo addslashes(lng('No messages yet.')); ?></div>';
                    return;
                }

                var html = messages.map(function (msg) {
                    var mine = msg.sender === currentUser;
                    var align = mine ? 'justify-content-end' : 'justify-content-start';
                    var bubble = mine ? 'fm-chat-bubble fm-chat-bubble--mine' : 'fm-chat-bubble fm-chat-bubble--theirs';
                    return '<div class="d-flex ' + align + ' mb-2">'
                        + '<div class="rounded px-3 py-2 ' + bubble + '" style="max-width: 75%;">'
                        + '<div class="small fw-semibold mb-1">' + esc(msg.sender || '') + '</div>'
                        + '<div>' + esc(msg.message || '') + '</div>'
                        + '<div class="small opacity-75 mt-1">' + esc(formatTime(msg.created_at || 0)) + '</div>'
                        + '</div>'
                        + '</div>';
                }).join('');

                historyEl.innerHTML = html;
                historyEl.scrollTop = historyEl.scrollHeight;
            }

            function chatFetch() {
                if (!state.peer) {
                    return;
                }

                var url = new URL(window.location.href);
                url.searchParams.set('chat_action', 'fetch');
                url.searchParams.set('with', state.peer);

                fetch(url.toString(), {
                    credentials: 'same-origin'
                })
                    .then(function (response) { return response.json(); })
                    .then(function (payload) {
                        if (!payload || payload.ok !== true || !payload.data) {
                            return;
                        }
                        var messages = payload.data.messages || [];
                        renderMessages(messages);

                        var maxIncomingId = 0;
                        messages.forEach(function (msg) {
                            if ((msg.sender || '') === state.peer) {
                                var mid = Number(msg.id || 0);
                                if (mid > maxIncomingId) {
                                    maxIncomingId = mid;
                                }
                            }
                        });
                        if (maxIncomingId > 0) {
                            markSenderRead(state.peer, maxIncomingId);
                        }
                    })
                    .catch(function () {
                    });
            }

            function chatSend(message) {
                var url = new URL(window.location.href);
                url.searchParams.set('chat_action', 'send');

                var body = new URLSearchParams();
                body.set('to', state.peer);
                body.set('message', message);
                body.set('token', tokenEl.value || '');

                return fetch(url.toString(), {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
                    },
                    credentials: 'same-origin',
                    body: body.toString()
                })
                    .then(function (response) { return response.json(); })
                    .then(function (payload) {
                        if (payload && payload.ok && payload.data) {
                            renderMessages(payload.data.messages || []);
                            return true;
                        }
                        return false;
                    })
                    .catch(function () {
                        return false;
                    });
            }

            function startPolling() {
                if (state.timer) {
                    window.clearInterval(state.timer);
                }
                state.timer = window.setInterval(chatFetch, 5000);
            }

            function stopPolling() {
                if (state.timer) {
                    window.clearInterval(state.timer);
                    state.timer = null;
                }
            }

            function pollInbox() {
                var url = new URL(window.location.href);
                url.searchParams.set('chat_action', 'inbox');

                fetch(url.toString(), {
                    credentials: 'same-origin'
                })
                    .then(function (response) { return response.json(); })
                    .then(function (payload) {
                        if (!payload || payload.ok !== true || !payload.data || !Array.isArray(payload.data.inbox)) {
                            return;
                        }

                        var inbox = payload.data.inbox;
                        state.unreadInboxItems = {};
                        var seenSenders = {};
                        var shouldAutoOpenSender = '';
                        inbox.forEach(function (item) {
                            var sender = item && item.sender ? String(item.sender) : '';
                            var id = item && item.id ? Number(item.id) : 0;
                            var unreadCount = item && item.unread_count ? Number(item.unread_count) : 0;
                            if (!sender || !id || sender === currentUser) {
                                return;
                            }

                            seenSenders[sender] = true;
                            state.unreadInboxItems[sender] = {
                                id: id,
                                sender: sender,
                                message: item && item.message ? String(item.message) : '',
                                created_at: item && item.created_at ? Number(item.created_at) : 0,
                                unread_count: unreadCount,
                            };

                            var prev = Number(state.lastIncomingBySender[sender] || 0);
                            if (id > prev) {
                                state.lastIncomingBySender[sender] = id;

                                if (state.peer === sender) {
                                    chatFetch();
                                    markBadgeRinging(sender, false);
                                    markSenderRead(sender, id);
                                } else {
                                    if (unreadCount > 0 && state.inboxInitialized && !state.peer && !shouldAutoOpenSender) {
                                        shouldAutoOpenSender = sender;
                                    }
                                }
                            }

                            if (state.peer !== sender) {
                                if (unreadCount > 0) {
                                    state.unreadBySender[sender] = unreadCount;
                                    markBadgeRinging(sender, true);
                                } else {
                                    delete state.unreadBySender[sender];
                                    markBadgeRinging(sender, false);
                                }
                            }
                        });

                        Object.keys(state.unreadBySender).forEach(function (sender) {
                            if (!seenSenders[sender]) {
                                delete state.unreadBySender[sender];
                                markBadgeRinging(sender, false);
                            }
                        });

                        state.inboxInitialized = true;
                        recomputeUnreadCount();

                        if (shouldAutoOpenSender) {
                            openChatWithPeer(shouldAutoOpenSender);
                        }
                    })
                    .catch(function () {
                    });
            }

            function startInboxPolling() {
                if (state.inboxTimer) {
                    window.clearInterval(state.inboxTimer);
                }
                pollInbox();
                state.inboxTimer = window.setInterval(pollInbox, 4000);
            }

            function clearPeerNotification(peer) {
                if (!peer) {
                    return;
                }
                markBadgeRinging(peer, false);
                var lastIncoming = Number(state.lastIncomingBySender[peer] || 0);
                if (lastIncoming > 0) {
                    markSenderRead(peer, lastIncoming);
                    chatMarkRead(peer, lastIncoming);
                }
            }

            badges.forEach(function (badge) {
                badge.addEventListener('click', function () {
                    var peer = badge.getAttribute('data-chat-user') || '';
                    openChatWithPeer(peer);
                });
            });

            unreadBadgeEls.forEach(function (badgeEl) {
                badgeEl.addEventListener('click', function () {
                    showUnreadListModal();
                });
            });

            peerPickerButtons.forEach(function (buttonEl) {
                buttonEl.addEventListener('click', function () {
                    var picker = buttonEl.closest('.fm-chat-peer-picker');
                    if (!picker) {
                        return;
                    }

                    var selectEl = picker.querySelector('[data-chat-peer-select]');
                    var peer = selectEl ? String(selectEl.value || '') : '';
                    if (!peer) {
                        return;
                    }

                    openChatWithPeer(peer);
                });
            });

            bindModalHidden(function () {
                stopPolling();
                clearPeerNotification(state.peer);
                state.peer = '';
                formEl.reset();
            });

            bindFallbackClose();

            formEl.addEventListener('submit', function (event) {
                event.preventDefault();
                var message = (inputEl.value || '').trim();
                if (!message || !state.peer) {
                    return;
                }

                chatSend(message).then(function (ok) {
                    if (ok) {
                        clearPeerNotification(state.peer);
                        inputEl.value = '';
                        inputEl.focus();
                    }
                });
            });

            loadReadState();
            setUnreadCount(0);
            startInboxPolling();
        })();
    </script>
<?php endif; ?>

<?php
