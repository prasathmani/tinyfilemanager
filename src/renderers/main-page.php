<?php $all_files_size = 0; ?>
<script src="src/assets/js/navbar-padding-fix.js?v=<?php echo rawurlencode((string) VERSION); ?>"></script>
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
        <div class="btn-group btn-group-sm fm-view-switch" role="group" aria-label="View mode">
            <button type="button" class="btn btn-outline-primary js-view-mode active" data-view-mode="list">
                <i class="fa fa-list" aria-hidden="true"></i> Zoznam
            </button>
            <button type="button" class="btn btn-outline-primary js-view-mode" data-view-mode="grid">
                <i class="fa fa-th-large" aria-hidden="true"></i> Mriežka
            </button>
        </div>
    </div>
    <div class="table-responsive fm-table-wrap">
        <table class="table table-bordered table-hover table-sm align-middle fm-modern-table" id="main-table" data-bs-theme="<?php echo FM_THEME; ?>">
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
            if ($parent !== false) {
            ?>
                <tr class="fm-parent-row"><?php if (!FM_READONLY && !FM_UPLOAD_ONLY && FM_CAN_WRITE_IN_PATH): ?>
                        <td class="nosort"></td><?php endif; ?>
                    <td class="border-0 fm-col-name" data-sort><a href="?p=<?php echo urlencode($parent) ?>"><i class="fa fa-chevron-circle-left go-back"></i> ..</a></td>
                    <td class="border-0 fm-col-size" data-order></td>
                    <td class="border-0 fm-col-modified" data-order></td>
                    <td class="border-0 fm-col-actions"></td>
                    <?php if (!FM_IS_WIN && !$hide_Cols) { ?>
                        <td class="border-0 fm-col-perms"></td>
                        <td class="border-0 fm-col-owner"></td>
                    <?php } ?>
                </tr>
            <?php
            }
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
                        <td class="fm-col-perms"><?php echo $perms ?></td>
                        <td class="fm-col-owner">
                            <span class="fm-owner-badge" title="<?php echo fm_enc($owner['name'] . ':' . $group['name']); ?>">
                                <i class="fa fa-user" aria-hidden="true"></i>
                                <span><?php echo fm_enc($owner['name']); ?></span>
                            </span>
                        </td>
                    <?php } ?>
                    <td class="inline-actions fm-col-actions">
                        <?php if (!FM_READONLY && !FM_UPLOAD_ONLY && FM_CAN_WRITE_IN_PATH): ?>
                            <?php if (!FM_MANAGER): ?>
                            <a title="<?php echo lng('Delete') ?>" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;del=<?php echo urlencode($f) ?>" onclick="confirmDailog(event, '1028','<?php echo lng('Delete') . ' ' . lng('Folder'); ?>','<?php echo urlencode($f) ?>', this.href);"> <i class="fa fa-trash-o" aria-hidden="true"></i></a>
                            <?php endif; ?>
                            <a title="<?php echo lng('Rename') ?>" href="#" onclick="rename('<?php echo fm_enc(addslashes(FM_PATH)) ?>', '<?php echo fm_enc(addslashes($f)) ?>');return false;"><i class="fa fa-pencil-square-o" aria-hidden="true"></i></a>
                            <a title="<?php echo lng('CopyTo') ?>..." href="?p=&amp;copy=<?php echo urlencode(trim(FM_PATH . '/' . $f, '/')) ?>"><i class="fa fa-files-o" aria-hidden="true"></i></a>
                        <?php endif; ?>
                        <a title="<?php echo lng('DirectLink') ?>" href="<?php echo fm_enc(FM_ROOT_URL . (FM_PATH != '' ? '/' . FM_PATH : '') . '/' . $f . '/') ?>" target="_blank"><i class="fa fa-link" aria-hidden="true"></i></a>
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
                        <td class="fm-col-perms"><?php if (!FM_READONLY): ?><a title="<?php echo 'Change Permissions' ?>" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;chmod=<?php echo urlencode($f) ?>"><?php echo $perms ?></a><?php else: ?><?php echo $perms ?><?php endif; ?>
                        </td>
                        <td class="fm-col-owner">
                            <span class="fm-owner-badge" title="<?php echo fm_enc($owner['name'] . ':' . $group['name']); ?>">
                                <i class="fa fa-user" aria-hidden="true"></i>
                                <span><?php echo fm_enc($owner['name']); ?></span>
                            </span>
                        </td>
                    <?php endif; ?>
                    <td class="inline-actions fm-col-actions">
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
                    </td>
                </tr>
            <?php
                flush();
                $ik++;
            }
            // Close the foreach for $files

            if (empty($folders) && empty($files)) { ?>
                <tfoot>
                    <tr><?php if (!FM_READONLY): ?>
                            <td></td><?php endif; ?>
                        <td colspan="<?php echo (!FM_IS_WIN && !$hide_Cols) ? '6' : '4' ?>"><em><?php echo lng('Folder is empty') ?></em></td>
                    </tr>
                </tfoot>
            <?php
            } else { ?>
                <tfoot>
                    <tr>
                        <td class="gray fs-7" colspan="<?php echo (!FM_IS_WIN && !$hide_Cols) ? ((FM_READONLY || FM_UPLOAD_ONLY) ? '6' : '7') : ((FM_READONLY || FM_UPLOAD_ONLY) ? '4' : '5') ?>">
                            <?php echo lng('FullSize') . ': <span class="badge text-bg-light border-radius-0">' . fm_get_filesize($all_files_size) . '</span>' ?>
                            <?php echo lng('File') . ': <span class="badge text-bg-light border-radius-0">' . $num_files . '</span>' ?>
                            <?php echo lng('Folder') . ': <span class="badge text-bg-light border-radius-0">' . $num_folders . '</span>' ?>
                        </td>
                    </tr>
                </tfoot>
            <?php } ?>
        </table>
    </div>
    <div id="fm-grid-view" class="hidden"></div>

    <div class="row">
        <?php
        $footerLoggedUser = (FM_USE_AUTH && !empty($_SESSION[FM_SESSION_ID]['logged'])) ? $_SESSION[FM_SESSION_ID]['logged'] : '';
        $footerShowUserBadges = !empty($footerLoggedUser) && (FM_MANAGER || (!FM_READONLY && !FM_UPLOAD_ONLY));
        $footerOnlineUsers = $footerShowUserBadges ? fm_online_get_users() : array();
        if ($footerShowUserBadges && empty($footerOnlineUsers)) {
            $footerOnlineUsers = array($footerLoggedUser);
        }
        ?>
        <?php if (!FM_READONLY && !FM_UPLOAD_ONLY && FM_CAN_WRITE_IN_PATH): ?>
            <div class="col-xs-12 col-sm-9">
                <div id="fm-selection-bar" class="btn-group flex-wrap" data-toggle="buttons" role="toolbar">
                    <span id="fm-selection-count" class="btn btn-small btn-outline-secondary btn-2 pe-none" style="display:none;">0</span>
                    <a href="#/select-all" class="btn btn-small btn-outline-primary btn-2" onclick="select_all();return false;"><i class="fa fa-check-square"></i> <?php echo lng('SelectAll') ?> </a>
                    <a href="#/unselect-all" class="btn btn-small btn-outline-primary btn-2" onclick="unselect_all();return false;"><i class="fa fa-window-close"></i> <?php echo lng('UnSelectAll') ?> </a>
                    <a href="#/invert-all" class="btn btn-small btn-outline-primary btn-2" onclick="invert_all();return false;"><i class="fa fa-th-list"></i> <?php echo lng('InvertSelection') ?> </a>
                    <?php if (!FM_MANAGER): ?>
                    <input type="submit" class="hidden" name="delete" id="a-delete" value="Delete" onclick="return confirm('<?php echo lng('Delete selected files and folders?'); ?>')">
                    <a href="javascript:document.getElementById('a-delete').click();" class="btn btn-small btn-outline-primary btn-2"><i class="fa fa-trash"></i> <?php echo lng('Delete') ?> </a>
                    <?php endif; ?>
                    <input type="submit" class="hidden" name="zip" id="a-zip" value="zip" onclick="return confirm('<?php echo lng('Create archive?'); ?>')">
                    <a href="javascript:document.getElementById('a-zip').click();" class="btn btn-small btn-outline-primary btn-2"><i class="fa fa-file-archive-o"></i> <?php echo lng('Zip') ?> </a>
                    <input type="submit" class="hidden" name="tar" id="a-tar" value="tar" onclick="return confirm('<?php echo lng('Create archive?'); ?>')">
                    <a href="javascript:document.getElementById('a-tar').click();" class="btn btn-small btn-outline-primary btn-2"><i class="fa fa-file-archive-o"></i> <?php echo lng('Tar') ?> </a>
                    <input type="submit" class="hidden" name="copy" id="a-copy" value="Copy">
                    <a href="javascript:document.getElementById('a-copy').click();" class="btn btn-small btn-outline-primary btn-2"><i class="fa fa-files-o"></i> <?php echo lng('Copy') ?> </a>
                </div>
            </div>
            <div class="col-3 d-none d-sm-block">
                <?php if ($footerShowUserBadges): ?>
                    <div class="float-right d-flex gap-2 align-items-center flex-wrap justify-content-end">
                        <span class="badge text-bg-light border"><?php echo lng('Online users') ?>: <?php echo count($footerOnlineUsers); ?></span>
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
                    </div>
                <?php else: ?>
                    <a href="https://tinyfilemanager.github.io" target="_blank" class="float-right text-muted">Tiny File Manager <?php echo VERSION; ?></a>
                <?php endif; ?>
            </div>
        <?php else: ?>
            <div class="col-12">
                <?php if ($footerShowUserBadges): ?>
                    <div class="float-right d-flex gap-2 align-items-center flex-wrap">
                        <span class="badge text-bg-light border"><?php echo lng('Online users') ?>: <?php echo count($footerOnlineUsers); ?></span>
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
                    </div>
                <?php else: ?>
                    <a href="https://tinyfilemanager.github.io" target="_blank" class="float-right text-muted">Tiny File Manager <?php echo VERSION; ?></a>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>
</form>

<?php if ($footerShowUserBadges): ?>
    <style>
        .fm-user-chat-badge.fm-chat-ringing {
            background-color: #dc3545 !important;
            color: #fff !important;
            animation: fm-chat-ring-blink 0.85s steps(2, jump-none) infinite;
        }

        @keyframes fm-chat-ring-blink {
            50% {
                opacity: 0.35;
            }
        }
    </style>

    <div class="modal fade" id="fm-chat-modal" tabindex="-1" aria-labelledby="fm-chat-modal-label" aria-hidden="true">
        <div class="modal-dialog modal-dialog-scrollable modal-lg modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="fm-chat-modal-label">Chat</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body p-0">
                    <div id="fm-chat-history" class="p-3" style="max-height: 420px; overflow-y: auto;"></div>
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
            var tokenEl = document.querySelector('input[name="token"]');
            var badges = document.querySelectorAll('.fm-user-chat-badge[data-chat-user]');

            if (!modalEl || !historyEl || !formEl || !inputEl || !titleEl || !tokenEl) {
                return;
            }

            var modal = null;
            var state = {
                peer: '',
                timer: null,
                inboxTimer: null,
                inboxInitialized: false,
                lastIncomingBySender: {},
            };

            var badgeByUser = {};
            badges.forEach(function (badge) {
                var u = badge.getAttribute('data-chat-user') || '';
                if (u) {
                    badgeByUser[u] = badge;
                }
            });

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
                        state.peer = '';
                        formEl.reset();
                    });
                });
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
                    historyEl.innerHTML = '<div class="text-muted small p-2">No messages yet.</div>';
                    return;
                }

                var html = messages.map(function (msg) {
                    var mine = msg.sender === currentUser;
                    var align = mine ? 'justify-content-end' : 'justify-content-start';
                    var bubble = mine ? 'bg-primary text-white' : 'bg-light border';
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
                        renderMessages(payload.data.messages || []);
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
                        var shouldAutoOpenSender = '';
                        inbox.forEach(function (item) {
                            var sender = item && item.sender ? String(item.sender) : '';
                            var id = item && item.id ? Number(item.id) : 0;
                            if (!sender || !id || sender === currentUser) {
                                return;
                            }

                            var prev = Number(state.lastIncomingBySender[sender] || 0);
                            if (!state.inboxInitialized) {
                                state.lastIncomingBySender[sender] = id;
                                return;
                            }

                            if (id > prev) {
                                state.lastIncomingBySender[sender] = id;

                                if (state.peer === sender) {
                                    chatFetch();
                                    markBadgeRinging(sender, false);
                                } else {
                                    markBadgeRinging(sender, true);
                                    if (!state.peer && !shouldAutoOpenSender) {
                                        shouldAutoOpenSender = sender;
                                    }
                                }
                            }
                        });

                        state.inboxInitialized = true;

                        if (shouldAutoOpenSender) {
                            state.peer = shouldAutoOpenSender;
                            titleEl.textContent = 'Chat with ' + shouldAutoOpenSender;
                            historyEl.innerHTML = '<div class="text-muted small p-2">Loading...</div>';
                            showModal();
                            chatFetch();
                            startPolling();
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
            }

            badges.forEach(function (badge) {
                badge.addEventListener('click', function () {
                    var peer = badge.getAttribute('data-chat-user') || '';
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
                });
            });

            bindModalHidden(function () {
                stopPolling();
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

            startInboxPolling();
        })();
    </script>
<?php endif; ?>

<?php
