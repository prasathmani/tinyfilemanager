
    <div class="row">
        <div class="col-12">
            <ul class="list-group w-50 my-3" data-bs-theme="<?php echo FM_THEME; ?>">
                <li class="list-group-item active" aria-current="true"><strong><?php echo lng($view_title) ?>:</strong> <?php echo fm_enc(fm_convert_win($file)) ?></li>
                <?php $display_path = fm_get_display_path($file_path); ?>
                <li class="list-group-item"><strong><?php echo $display_path['label']; ?>:</strong> <?php echo $display_path['path']; ?></li>
                <li class="list-group-item"><strong><?php echo lng('Date Modified') ?>:</strong> <?php echo date(FM_DATETIME_FORMAT, filemtime($file_path)); ?></li>
                <li class="list-group-item"><strong><?php echo lng('File size') ?>:</strong> <?php echo ($filesize_raw <= 1000) ? "$filesize_raw bytes" : $filesize; ?></li>
                <li class="list-group-item"><strong><?php echo lng('MIME-type') ?>:</strong> <?php echo $mime_type ?></li>
                <?php
                if (($is_zip || $is_gzip) && $filenames !== false) {
                    $total_files = 0;
                    $total_comp = 0;
                    $total_uncomp = 0;
                    foreach ($filenames as $fn) {
                        if (!$fn['folder']) {
                            $total_files++;
                        }
                        $total_comp += $fn['compressed_size'];
                        $total_uncomp += $fn['filesize'];
                    }
                ?>
                    <li class="list-group-item"><?php echo lng('Files in archive') ?>: <?php echo $total_files ?></li>
                    <li class="list-group-item"><?php echo lng('Total size') ?>: <?php echo fm_get_filesize($total_uncomp) ?></li>
                    <li class="list-group-item"> <?php echo lng('Size in archive') ?>: <?php echo fm_get_filesize($total_comp) ?></li>
                    <li class="list-group-item"><?php echo lng('Compression') ?>: <?php echo round(($total_comp / max($total_uncomp, 1)) * 100) ?>%</li>
                <?php
                }
                if ($is_image) {
                    $image_size = getimagesize($file_path);
                    echo '<li class="list-group-item"><strong>' . lng('Image size') . ':</strong> ' . (isset($image_size[0]) ? $image_size[0] : '0') . ' x ' . (isset($image_size[1]) ? $image_size[1] : '0') . '</li>';
                }
                if ($is_text) {
                    $is_utf8 = fm_is_utf8($content);
                    if (function_exists('iconv')) {
                        if (!$is_utf8) {
                            $content = iconv(FM_ICONV_INPUT_ENC, 'UTF-8//IGNORE', $content);
                        }
                    }
                    echo '<li class="list-group-item"><strong>' . lng('Charset') . ':</strong> ' . ($is_utf8 ? 'utf-8' : '8 bit') . '</li>';
                }
                ?>
            </ul>
            <div class="btn-group btn-group-sm flex-wrap" role="group">
                <form method="post" class="d-inline mb-0 btn btn-outline-primary" action="?p=<?php echo urlencode(FM_PATH) ?>&amp;dl=<?php echo urlencode($file) ?>">
                    <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
                    <button type="submit" class="btn btn-link btn-sm text-decoration-none fw-bold p-0"><i class="fa fa-cloud-download"></i> <?php echo lng('Download') ?></button> &nbsp;
                </form>
                <?php if (!FM_READONLY && !FM_UPLOAD_ONLY && FM_CAN_WRITE_IN_PATH): ?>
                    <?php if (!FM_MANAGER): ?>
                    <a class="fw-bold btn btn-outline-primary" title="<?php echo lng('Delete') ?>" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;del=<?php echo urlencode($file) ?>" onclick="confirmDailog(event, 1209, '<?php echo lng('Delete') . ' ' . lng('File'); ?>','<?php echo urlencode($file); ?>', this.href);"> <i class="fa fa-trash"></i> Delete</a>
                    <?php endif; ?>
                <?php endif; ?>
                <a class="fw-bold btn btn-outline-primary" href="<?php echo fm_enc($file_url) ?>" target="_blank"><i class="fa fa-external-link-square"></i> <?php echo lng('Open') ?></a></b>
                <?php
                if (!FM_READONLY && !FM_UPLOAD_ONLY && FM_CAN_WRITE_IN_PATH && ($is_zip || $is_gzip) && $filenames !== false) {
                    $zip_name = pathinfo($file_path, PATHINFO_FILENAME);
                ?>
                    <form method="post" class="d-inline btn btn-outline-primary mb-0">
                        <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
                        <input type="hidden" name="unzip" value="<?php echo urlencode($file); ?>">
                        <button type="submit" class="btn btn-link text-decoration-none fw-bold p-0 border-0" style="font-size: 14px;"><i class="fa fa-check-circle"></i> <?php echo lng('UnZip') ?></button>
                    </form>
                    <form method="post" class="d-inline btn btn-outline-primary mb-0">
                        <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
                        <input type="hidden" name="unzip" value="<?php echo urlencode($file); ?>">
                        <input type="hidden" name="tofolder" value="1">
                        <button type="submit" class="btn btn-link text-decoration-none fw-bold p-0" style="font-size: 14px;" title="UnZip to <?php echo fm_enc($zip_name) ?>"><i class="fa fa-check-circle"></i> <?php echo lng('UnZipToFolder') ?></button>
                    </form>
                <?php
                }
                if ($is_text && !FM_READONLY && !FM_UPLOAD_ONLY && FM_CAN_WRITE_IN_PATH) {
                ?>
                    <a class="fw-bold btn btn-outline-primary" href="?p=<?php echo urlencode(trim(FM_PATH)) ?>&amp;edit=<?php echo urlencode($file) ?>" class="edit-file">
                        <i class="fa fa-pencil-square"></i> <?php echo lng('Edit') ?>
                    </a>
                    <a class="fw-bold btn btn-outline-primary" href="?p=<?php echo urlencode(trim(FM_PATH)) ?>&amp;edit=<?php echo urlencode($file) ?>&env=ace"
                        class="edit-file"><i class="fa fa-pencil-square"></i> <?php echo lng('AdvancedEditor') ?>
                    </a>
                <?php } ?>
                <a class="fw-bold btn btn-outline-primary" href="?p=<?php echo urlencode(FM_PATH) ?>"><i class="fa fa-chevron-circle-left go-back"></i> <?php echo lng('Back') ?></a>
            </div>
            <div class="row mt-3">
                <?php
                if ($is_pdf) {
                    $pdf_preview_url = FM_SELF_PATH . '?' . fm_build_preview_query(FM_PATH, $file);
                    echo '<iframe src="' . fm_enc($pdf_preview_url) . '" frameborder="no" style="width:100%;min-height:640px"></iframe>';
                } elseif ($is_onlineViewer) {
                    $local_preview_url = FM_SELF_PATH . '?' . fm_build_preview_query(FM_PATH, $file, 1800);
                    $local_preview_url_json = json_encode($local_preview_url);
                    $office_txt_download_original = lng('DownloadOriginal');
                    $office_txt_loading_doc = json_encode(lng('OfficeLoadingDocument'));
                    $office_txt_loading_sheet = json_encode(lng('OfficeLoadingSpreadsheet'));
                    $office_txt_load_error = json_encode(lng('OfficeLoadError'));
                    $office_txt_render_error = json_encode(lng('OfficeRenderError'));
                    $office_txt_lib_docx_error = json_encode(lng('OfficeLibraryLoadErrorDocx'));
                    $office_txt_lib_xlsx_error = json_encode(lng('OfficeLibraryLoadErrorXlsx'));

                    $word_exts  = array('doc', 'docx');
                    $excel_exts = array('xls', 'xlsx', 'xlsm', 'xlsb');

                    echo '<div class="mb-2">'
                        . '<form method="post" class="d-inline" action="?p=' . urlencode(FM_PATH) . '&amp;dl=' . urlencode($file) . '">'
                        . '<input type="hidden" name="token" value="' . $_SESSION['token'] . '">'
                        . '<button type="submit" class="btn btn-sm btn-outline-primary"><i class="fa fa-cloud-download"></i> ' . $office_txt_download_original . '</button>'
                        . '</form>'
                        . '</div>';

                    if (in_array($ext, $word_exts, true)) {
                        echo '<div id="office-viewer-wrap" style="width:100%;min-height:520px;border:1px solid #dee2e6;border-radius:4px;overflow:auto;background:#fff;padding:8px;">'
                            . '<div id="office-viewer-msg" style="padding:20px;color:#6c757d;">' . lng('OfficeLoadingDocument') . '</div>'
                            . '</div>';
                        echo '<script>'
                            . 'document.addEventListener("DOMContentLoaded",function(){'
                            .   'var wrap=document.getElementById("office-viewer-wrap");'
                            .   'var msg=document.getElementById("office-viewer-msg");'
                            .   'var url=' . $local_preview_url_json . ';'
                            .   'var txtLoadErr=' . $office_txt_load_error . ';'
                            .   'var txtRenderErr=' . $office_txt_render_error . ';'
                            .   'var txtLibErr=' . $office_txt_lib_docx_error . ';'
                            .   'function run(){'
                            .     'fetch(url,{credentials:"same-origin"})'
                            .       '.then(function(r){return r.arrayBuffer();})'
                            .       '.then(function(buf){'
                            .         'msg.remove();'
                            .         'if(typeof docx!=="undefined" && typeof docx.renderAsync==="function"){'
                            .           'docx.renderAsync(buf,wrap,null,{className:"docx-render",inWrapper:false})'
                            .             '.catch(function(e){wrap.innerHTML="<p style=\'padding:16px;color:red;\'>"+txtRenderErr+": "+e+"</p>";});'
                            .         '}else{wrap.innerHTML="<p style=\'padding:16px;color:red;\'>"+txtLibErr+"</p>";}'
                            .       '})'
                            .       '.catch(function(e){msg.textContent=txtLoadErr+": "+e;});'
                            .   '}'
                            .   'if(typeof docx!=="undefined" && typeof docx.renderAsync==="function"){run();}'
                            .   'else{'
                            .     'var s=document.createElement("script");'
                            .     's.src="https://cdn.jsdelivr.net/npm/docx-preview@0.3.6/dist/docx-preview.min.js";'
                            .     's.onload=run;'
                            .     's.onerror=function(){msg.textContent=txtLibErr;};'
                            .     'document.head.appendChild(s);'
                            .   '}'
                            . '});'
                            . '</script>';
                    } elseif (in_array($ext, $excel_exts, true)) {
                        echo '<div style="width:100%;border:1px solid #dee2e6;border-radius:4px;background:#fff;">'
                            . '<div id="xlsx-sheet-tabs" style="display:flex;flex-wrap:wrap;gap:4px;padding:6px 8px;border-bottom:1px solid #dee2e6;background:#f8f9fa;"></div>'
                            . '<div id="xlsx-table-wrap" style="overflow:auto;max-height:560px;padding:4px 8px;">'
                            . '<p id="office-viewer-msg" style="padding:20px;color:#6c757d;">' . lng('OfficeLoadingSpreadsheet') . '</p>'
                            . '</div>'
                            . '</div>';
                        echo '<script>'
                            . 'document.addEventListener("DOMContentLoaded",function(){'
                            .   'var url=' . $local_preview_url_json . ';'
                            .   'var msg=document.getElementById("office-viewer-msg");'
                            .   'var tableWrap=document.getElementById("xlsx-table-wrap");'
                            .   'var tabsEl=document.getElementById("xlsx-sheet-tabs");'
                            .   'var wb=null;'
                            .   'var txtLoadErr=' . $office_txt_load_error . ';'
                            .   'var txtLibErr=' . $office_txt_lib_xlsx_error . ';'
                            .   'function renderSheet(name){'
                            .     'var ws=wb.Sheets[name];'
                            .     'var html=XLSX.utils.sheet_to_html(ws,{editable:false});'
                            .     'tableWrap.innerHTML="<div style=\"font-size:13px;\">"+html+"</div>";'
                            .     'tableWrap.querySelectorAll("table").forEach(function(t){'
                            .       't.classList.add("table","table-bordered","table-sm");'
                            .       't.style.cssText="min-width:100%;white-space:nowrap;";'
                            .     '});'
                            .   '}'
                            .   'function buildTabs(){'
                            .     'wb.SheetNames.forEach(function(name,i){'
                            .       'var btn=document.createElement("button");'
                            .       'btn.textContent=name;'
                            .       'btn.className="btn btn-sm "+(i===0?"btn-primary":"btn-outline-secondary");'
                            .       'btn.onclick=function(){'
                            .         'tabsEl.querySelectorAll("button").forEach(function(b){b.className="btn btn-sm btn-outline-secondary";});'
                            .         'btn.className="btn btn-sm btn-primary";'
                            .         'renderSheet(name);'
                            .       '};'
                            .       'tabsEl.appendChild(btn);'
                            .     '});'
                            .   '}'
                            .   'function run(){'
                            .     'fetch(url,{credentials:"same-origin"})'
                            .       '.then(function(r){return r.arrayBuffer();})'
                            .       '.then(function(buf){'
                            .         'wb=XLSX.read(new Uint8Array(buf),{type:"array"});'
                            .         'buildTabs();'
                            .         'renderSheet(wb.SheetNames[0]);'
                            .       '})'
                            .       '.catch(function(e){msg.textContent=txtLoadErr+": "+e;});'
                            .   '}'
                            .   'if(typeof XLSX!=="undefined"){run();}'
                            .   'else{'
                            .     'var s=document.createElement("script");'
                            .     's.src="https://cdn.sheetjs.com/xlsx-0.20.3/package/dist/xlsx.full.min.js";'
                            .     's.onload=run;'
                            .     's.onerror=function(){msg.textContent=txtLibErr;};'
                            .     'document.head.appendChild(s);'
                            .   '}'
                            . '});'
                            . '</script>';
                    } else {
                        $office_preview_url = $file_url;
                        if (!preg_match('#^https?://#i', $office_preview_url)) {
                            $office_preview_url = FM_SELF_URL . '?' . fm_build_preview_query(FM_PATH, $file, 1800);
                        }
                        $google_src = 'https://docs.google.com/viewer?embedded=true&hl=en&url=' . rawurlencode($office_preview_url);
                        echo '<iframe src="' . fm_enc($google_src) . '" frameborder="no" style="width:100%;min-height:460px"></iframe>';
                    }
                } elseif ($is_zip) {
                    if ($filenames !== false) {
                        echo '<code class="maxheight">';
                        foreach ($filenames as $fn) {
                            if ($fn['folder']) {
                                echo '<b>' . fm_enc($fn['name']) . '</b><br>';
                            } else {
                                echo $fn['name'] . ' (' . fm_get_filesize($fn['filesize']) . ')<br>';
                            }
                        }
                        echo '</code>';
                    } else {
                        echo '<p>' . lng('Error while fetching archive info') . '</p>';
                    }
                } elseif ($is_image) {
                    $preview_url = FM_SELF_PATH . '?' . fm_build_preview_query(FM_PATH, $file);
                    echo '<p><input type="checkbox" id="preview-img-zoomCheck"><label for="preview-img-zoomCheck"><img src="' . fm_enc($preview_url) . '" alt="image" class="preview-img"></label></p>';
                } elseif ($is_audio) {
                    $preview_url = FM_SELF_PATH . '?' . fm_build_preview_query(FM_PATH, $file);
                    echo '<p><audio src="' . fm_enc($preview_url) . '" controls preload="metadata"></audio></p>';
                } elseif ($is_video) {
                    $preview_url = FM_SELF_PATH . '?' . fm_build_preview_query(FM_PATH, $file);
                    echo '<div class="preview-video"><video src="' . fm_enc($preview_url) . '" width="640" height="360" controls preload="metadata"></video></div>';
                } elseif ($is_text) {
                    if (FM_USE_HIGHLIGHTJS) {
                        $hljs_classes = array(
                            'shtml' => 'xml',
                            'htaccess' => 'apache',
                            'phtml' => 'php',
                            'lock' => 'json',
                            'svg' => 'xml',
                        );
                        $hljs_class = isset($hljs_classes[$ext]) ? 'lang-' . $hljs_classes[$ext] : 'lang-' . $ext;
                        if (empty($ext) || in_array(strtolower($file), fm_get_text_names()) || preg_match('#\.min\.(css|js)$#i', $file)) {
                            $hljs_class = 'nohighlight';
                        }
                        $content = '<pre class="with-hljs"><code class="' . $hljs_class . '">' . fm_enc($content) . '</code></pre>';
                    } elseif (in_array($ext, array('php', 'php4', 'php5', 'phtml', 'phps'))) {
                        $content = highlight_string($content, true);
                    } else {
                        $content = '<pre>' . fm_enc($content) . '</pre>';
                    }
                    echo $content;
                }
                ?>
            </div>
        </div>
    </div>
<?php