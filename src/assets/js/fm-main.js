(function () {
  function readJsonConfig(id) {
    var el = document.getElementById(id);
    if (!el) {
      return {};
    }
    try {
      return JSON.parse(el.textContent || '{}');
    } catch (e) {
      return {};
    }
  }

  var config = readJsonConfig('fm-runtime-config');
  window.csrf = config.csrfToken || window.csrf || '';

  if (config.highlightCurrentView && typeof window.hljs !== 'undefined' && typeof window.hljs.highlightAll === 'function') {
    window.hljs.highlightAll();
    window.isHighlightingEnabled = true;
  }

  function template(html, options) {
    var re = /<\%([^\%>]+)?\%>/g;
    var reExp = /(^(()?(if|for|else|switch|case|break|{|}))(.*)?)/g;
    var code = 'var r=[];\n';
    var cursor = 0;
    var match;

    var add = function (line, js) {
      if (js) {
        code += line.match(reExp) ? line + '\n' : 'r.push(' + line + ');\n';
      } else {
        code += line !== '' ? 'r.push("' + line.replace(/"/g, '\\"') + '");\n' : '';
      }
      return add;
    };

    while ((match = re.exec(html))) {
      add(html.slice(cursor, match.index))(match[1], true);
      cursor = match.index + match[0].length;
    }

    add(html.substr(cursor, html.length - cursor));
    code += 'return r.join("");';
    return new Function(code.replace(/[\r\t\n]/g, '')).apply(options || {});
  }

  function renameItem(e, t) {
    if (t) {
      $('#js-rename-from').val(t);
      $('#js-rename-to').val(t);
      $('#renameDailog').modal('show');
    }
  }

  function getCheckboxes() {
    var e = document.getElementsByName('file[]');
    var t = [];
    for (var n = e.length - 1; n >= 0; n--) {
      (e[n].type = 'checkbox') && t.push(e[n]);
    }
    return t;
  }

  function changeCheckboxes(e, t) {
    for (var n = e.length - 1; n >= 0; n--) {
      e[n].checked = typeof t === 'boolean' ? t : !e[n].checked;
    }
    if (typeof window.fmUpdateSelectionBar === 'function') {
      window.fmUpdateSelectionBar();
    }
  }

  function selectAll() {
    changeCheckboxes(getCheckboxes(), true);
  }

  function unselectAll() {
    changeCheckboxes(getCheckboxes(), false);
  }

  function invertAll() {
    changeCheckboxes(getCheckboxes());
  }

  function checkboxToggle() {
    var e = getCheckboxes();
    e.push(this);
    changeCheckboxes(e);
  }

  function toast(txt) {
    var x = document.getElementById('snackbar');
    if (!x) {
      return;
    }
    x.innerHTML = txt;
    x.className = 'show';
    setTimeout(function () {
      x.className = x.className.replace('show', '');
    }, 3000);
  }

  function backup(path, file) {
    var xhr = new XMLHttpRequest();
    var payload = 'path=' + path + '&file=' + file + '&token=' + window.csrf + '&type=backup&ajax=true';
    xhr.open('POST', '', true);
    xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
    xhr.onreadystatechange = function () {
      if (xhr.readyState === 4 && xhr.status === 200) {
        toast(xhr.responseText);
      }
    };
    xhr.send(payload);
    return false;
  }

  function editSave(e, t) {
    var n = t === 'ace' ? window.editor.getSession().getValue() : document.getElementById('normal-editor').value;
    if (typeof n !== 'undefined' && n !== null) {
      var data = {
        ajax: true,
        content: n,
        type: 'save',
        token: window.csrf
      };

      $.ajax({
        type: 'POST',
        url: window.location,
        data: JSON.stringify(data),
        contentType: 'application/json; charset=utf-8',
        success: function () {
          toast('Saved Successfully');
          window.onbeforeunload = function () {
            return;
          };
        },
        failure: function () {
          toast('Error: try again');
        },
        error: function (mes) {
          toast('<p style="background-color:red">' + mes.responseText + '</p>');
        }
      });
    }
  }

  function showNewPwd() {
    $('.js-new-pwd').toggleClass('hidden');
  }

  function saveSettings(el) {
    var form = $(el);
    var selectedTheme = form.find('select[name="js-theme-3"]').val() || 'light';

    document.documentElement.setAttribute('data-bs-theme', selectedTheme);
    $('body').toggleClass('theme-dark', selectedTheme === 'dark');

    $.ajax({
      type: form.attr('method'),
      url: form.attr('action'),
      data: form.serialize() + '&token=' + window.csrf + '&ajax=true',
      success: function (data) {
        var response = data;
        if (typeof data === 'string') {
          try {
            response = JSON.parse(data);
          } catch (e) {
            response = { success: false };
          }
        }

        if (response && response.success) {
          toast('Settings saved successfully');
          var url = new URL(window.location.href);
          url.searchParams.delete('settings');
          url.hash = '';
          var nextUrl = url.pathname + (url.searchParams.toString() ? '?' + url.searchParams.toString() : '');
          setTimeout(function () {
            window.location.assign(nextUrl);
          }, 450);
        } else {
          toast('Settings could not be saved. Check write permissions for config.php');
        }
      },
      error: function () {
        toast('Settings could not be saved. Check write permissions for config.php');
      }
    });

    return false;
  }

  function changePassword(el) {
    var form = $(el);
    $.ajax({
      type: 'post',
      url: '',
      data: form.serialize() + '&token=' + window.csrf + '&ajax=true',
      success: function (data) {
        var response = data;
        if (typeof data === 'string') {
          try {
            response = JSON.parse(data);
          } catch (e) {
            response = { success: false, msg: 'Unknown error' };
          }
        }
        if (response && response.success) {
          toast(response.msg || 'Password changed successfully');
          form[0].reset();
        } else {
          toast(response && response.msg ? response.msg : 'Password change failed');
        }
      },
      error: function () {
        toast('Password change failed');
      }
    });
    return false;
  }

  function newPasswordHash(el) {
    var form = $(el);
    var pwd = $('#js-pwd-result');
    pwd.val('');
    $.ajax({
      type: form.attr('method'),
      url: form.attr('action'),
      data: form.serialize() + '&token=' + window.csrf + '&ajax=true',
      success: function (data) {
        if (data) {
          pwd.val(data);
        }
      }
    });
    return false;
  }

  function uploadFromUrl(el) {
    var form = $(el);
    var resultWrapper = $('div#js-url-upload__list');
    $.ajax({
      type: form.attr('method'),
      url: form.attr('action'),
      data: form.serialize() + '&token=' + window.csrf + '&ajax=true',
      beforeSend: function () {
        form.find('input[name=uploadurl]').attr('disabled', 'disabled');
        form.find('button').hide();
        form.find('.lds-facebook').addClass('show-me');
      },
      success: function (data) {
        if (data) {
          data = JSON.parse(data);
          if (data.done) {
            resultWrapper.append('<div class="alert alert-success row">Uploaded Successful: ' + data.done.name + '</div>');
            form.find('input[name=uploadurl]').val('');
          } else if (data.fail) {
            resultWrapper.append('<div class="alert alert-danger row">Error: ' + data.fail.message + '</div>');
          }
          form.find('input[name=uploadurl]').removeAttr('disabled');
          form.find('button').show();
          form.find('.lds-facebook').removeClass('show-me');
        }
      },
      error: function (xhr) {
        form.find('input[name=uploadurl]').removeAttr('disabled');
        form.find('button').show();
        form.find('.lds-facebook').removeClass('show-me');
        console.error(xhr);
      }
    });
    return false;
  }

  function searchTemplate(data) {
    var response = '';
    $.each(data, function (key, val) {
      response += '<li><a href="?p=' + val.path + '&view=' + val.name + '">' + val.path + '/' + val.name + '</a></li>';
    });
    return response;
  }

  function fmSearch() {
    var searchTxt = $('input#advanced-search').val();
    var searchWrapper = $('ul#search-wrapper');
    var path = $('#js-search-modal').attr('href');
    var html = '';
    var loader = $('div.lds-facebook');

    if (!!searchTxt && searchTxt.length > 2 && path) {
      var data = {
        ajax: true,
        content: searchTxt,
        path: path,
        type: 'search',
        token: window.csrf
      };

      $.ajax({
        type: 'POST',
        url: window.location,
        data: data,
        beforeSend: function () {
          searchWrapper.html('');
          loader.addClass('show-me');
        },
        success: function (payload) {
          loader.removeClass('show-me');
          payload = JSON.parse(payload);
          if (payload && payload.length) {
            html = searchTemplate(payload);
            searchWrapper.html(html);
          } else {
            searchWrapper.html('<p class="m-2">No result found!<p>');
          }
        },
        error: function () {
          loader.removeClass('show-me');
          searchWrapper.html('<p class="m-2">ERROR: Try again later!</p>');
        },
        failure: function () {
          loader.removeClass('show-me');
          searchWrapper.html('<p class="m-2">ERROR: Try again later!</p>');
        }
      });
    } else {
      searchWrapper.html('OOPS: minimum 3 characters required!');
    }
  }

  function confirmDialog(e, id, title, content, action) {
    if (typeof id === 'undefined') id = 0;
    if (typeof title === 'undefined') title = 'Action';
    if (typeof content === 'undefined') content = '';
    if (typeof action === 'undefined') action = null;

    e.preventDefault();
    var tplObj = {
      id: id,
      title: title,
      content: decodeURIComponent(String(content).replace(/\+/g, ' ')),
      action: action
    };

    var tpl = $('#js-tpl-confirm').html();
    $('.modal.confirmDailog').remove();
    $('#wrapper').append(template(tpl, tplObj));
    var confirmDailog = $('#confirmDailog-' + tplObj.id);
    confirmDailog.modal('show');
    return false;
  }

  !(function (s) {
    s.previewImage = function (e) {
      var o = s(document),
        t = '.previewImage',
        a = s.extend(
          {
            xOffset: 20,
            yOffset: -20,
            fadeIn: 'fast',
            css: {
              padding: '5px',
              border: '1px solid #cccccc',
              'background-color': '#fff'
            },
            eventSelector: '[data-preview-image]',
            dataKey: 'previewImage',
            overlayId: 'preview-image-plugin-overlay'
          },
          e
        );
      return (
        o.off(t),
        o.on('mouseover' + t, a.eventSelector, function (ev) {
          s('p#' + a.overlayId).remove();
          var node = s('<p>')
            .attr('id', a.overlayId)
            .css('position', 'absolute')
            .css('display', 'none')
            .append(s('<img class="c-preview-img">').attr('src', s(this).data(a.dataKey)));
          a.css && node.css(a.css);
          s('body').append(node);
          node.css('top', ev.pageY + a.yOffset + 'px').css('left', ev.pageX + a.xOffset + 'px').fadeIn(a.fadeIn);
        }),
        o.on('mouseout' + t, a.eventSelector, function () {
          s('#' + a.overlayId).remove();
        }),
        o.on('mousemove' + t, a.eventSelector, function (ev) {
          s('#' + a.overlayId).css('top', ev.pageY + a.yOffset + 'px').css('left', ev.pageX + a.xOffset + 'px');
        }),
        this
      );
    };
    s.previewImage();
  })(jQuery);



  function initMainTableDataTable() {
    var table = $('#main-table');
    if (!table.length) return;
    var tableLng = table.find('th').length;
    var targets = tableLng && tableLng == 7 ? [0, 4, 5, 6] : tableLng == 5 ? [0, 4] : [3];
    if ($.fn.DataTable.isDataTable(table)) {
      table.DataTable().destroy();
    }
    window.mainTable = table.DataTable({
      paging: false,
      info: false,
      order: [],
      columnDefs: [{
        targets: targets,
        orderable: false
      }]
    });
  }

  $(document).ready(function () {
    initMainTableDataTable();

    var storageKey = 'fm_view_mode';
    var viewButtons = $('.js-view-mode');
    var tableWrap = $('.table-responsive').first();
    var grid = $('#fm-grid-view');
    var fmIsManagerOrAdmin = !!config.isManagerOrAdmin;

    function isMobileViewport() {
      return window.matchMedia('(max-width: 767.98px)').matches;
    }

    function getViewMode() {
      var savedMode = localStorage.getItem(storageKey);
      if (savedMode) {
        return savedMode;
      }
      return isMobileViewport() ? 'grid' : 'list';
    }

    function setViewMode(mode, persist) {
      if (typeof persist === 'undefined') {
        persist = true;
      }
      var gridMode = mode === 'grid';
      viewButtons.removeClass('active');
      viewButtons.filter('[data-view-mode="' + mode + '"]').addClass('active');
      tableWrap.toggleClass('hidden', gridMode);
      grid.toggleClass('hidden', !gridMode);
      if (gridMode) {
        renderGridView();
      }
      if (persist) {
        localStorage.setItem(storageKey, mode);
      }
    }

    function applyCompactMobileMode() {
      var compact = window.matchMedia('(max-width: 479.98px)').matches;
      table.toggleClass('fm-compact-mobile', compact);
    }

    function renderGridView() {
      var hasSelect = $('#main-table thead th').first().hasClass('custom-checkbox-header');
      var rows = $('#main-table tbody tr');
      var nameIndex = hasSelect ? 1 : 0;
      var sizeIndex = hasSelect ? 2 : 1;
      var modIndex = hasSelect ? 3 : 2;
      var cards = [];

      rows.each(function () {
        var tr = $(this);
        var tds = tr.children('td');

        if (!tds.length) {
          return;
        }

        var nameCell = tds.eq(nameIndex);
        var nameLink = nameCell.find('.filename a').first();

        if (!nameLink.length) {
          return;
        }

        var title = $.trim(nameLink.text());
        var href = nameLink.attr('href') || '#';
        var hrefSafe = (href || '#').replace(/"/g, '&quot;');
        var fullPath = nameLink.attr('data-full-path') || '';
        var iconHtml = nameCell.find('.filename i').first().prop('outerHTML') || '<i class="fa fa-file-o"></i>';
        var previewType = nameLink.attr('data-preview-type') || '';
        var previewSrc = nameLink.attr('data-preview-src') || '';
        var size = $.trim(tds.eq(sizeIndex).text());
        var modified = $.trim(tds.eq(modIndex).text());
        var actionsHtml = tds.last().html() || '';
        var parentClass = title === '..' ? ' fm-grid-parent' : '';
        var isFile = href.indexOf('&view=') !== -1;
        var linkClass = isFile ? 'fm-grid-link-file' : 'fm-grid-link-dir';
        var thumbHtml = iconHtml;
        var badgeHtml = '';
        var pathDisplay =
          fmIsManagerOrAdmin && fullPath
            ? '<span class="fm-grid-path" title="' + fullPath.replace(/"/g, '&quot;') + '">' + fullPath + '</span>'
            : '';

        if (previewType === 'image' && previewSrc) {
          thumbHtml = '<img src="' + previewSrc + '" alt="' + title.replace(/"/g, '&quot;') + '">';
        } else if (previewType === 'video' && previewSrc) {
          thumbHtml = '<video src="' + previewSrc + '" muted preload="metadata" playsinline></video>';
        } else if (previewType === 'pdf') {
          badgeHtml = '<div class="fm-grid-pdf-badge">PDF</div>';
        }

        cards.push(
          '<div class="fm-grid-item' +
            parentClass +
            '">' +
            '<div class="fm-grid-thumb" data-href="' +
            hrefSafe +
            '">' +
            thumbHtml +
            badgeHtml +
            '</div>' +
            '<div class="fm-grid-body">' +
            '<div class="fm-grid-name"><a href="' +
            hrefSafe +
            '" class="fm-grid-link ' +
            linkClass +
            '" title="' +
            title.replace(/"/g, '&quot;') +
            '">' +
            title +
            '</a></div>' +
            (pathDisplay ? '<div class="fm-grid-path-row">' + pathDisplay + '</div>' : '') +
            '<div class="fm-grid-meta"><span>' +
            size +
            '</span><span>' +
            modified +
            '</span></div>' +
            '</div>' +
            '<div class="fm-grid-actions"><div class="inline-actions">' +
            actionsHtml +
            '</div></div>' +
            '</div>'
        );
      });

      if (!cards.length) {
        grid.html('<div class="alert alert-light border mb-2">' + (config.folderEmptyText || 'Folder is empty') + '</div>');
        return;
      }

      grid.html('<div class="fm-grid">' + cards.join('') + '</div>');
    }

    viewButtons.on('click', function () {
      setViewMode($(this).data('view-mode'), true);
    });

    grid.off('click.fmgrid').on('click.fmgrid', '.fm-grid-thumb, .fm-grid-name', function (e) {
      if ($(e.target).closest('a,button,input,label,form').length) {
        return;
      }

      var item = $(this).closest('.fm-grid-item');
      var href = $(this).data('href') || item.find('.fm-grid-link').attr('href');

      if (href) {
        window.location.href = href;
      }
    });

    window.mainTable.on('draw', function () {
      if (getViewMode() === 'grid') {
        renderGridView();
      }
      if (typeof window.fmUpdateSelectionBar === 'function') {
        window.fmUpdateSelectionBar();
      }
    });

    function adjustNavbarOffset() {
      if ($('body').hasClass('navbar-fixed')) {
        var h = $('.main-nav.fixed-top').outerHeight(true) || 56;
        $('body').css('margin-top', h + 'px');
      }
    }

    setViewMode(getViewMode(), !!localStorage.getItem(storageKey));
    applyCompactMobileMode();
    adjustNavbarOffset();

    $(window).on('resize', function () {
      if (!localStorage.getItem(storageKey)) {
        setViewMode(getViewMode(), false);
      }
      applyCompactMobileMode();
      adjustNavbarOffset();
    });

    var selectionBar = $('#fm-selection-bar');
    var selectionCount = $('#fm-selection-count');

    window.fmUpdateSelectionBar = function () {
      var selected = getCheckboxes().filter(function (item) {
        return item.checked;
      }).length;

      selectionCount.text((config.selectedLabel || 'Selected') + ': ' + selected);
      selectionCount.toggle(selected > 0);

      if (isMobileViewport()) {
        selectionBar.css('display', selected > 0 ? 'flex' : 'none');
      } else {
        selectionBar.css('display', '');
      }
    };

    $(document).on('change', 'input[name="file[]"], #js-select-all-items', function () {
      window.fmUpdateSelectionBar();
    });

    $('#js-mobile-focus-search').on('click', function (e) {
      e.preventDefault();
      var target = document.getElementById('navbarSupportedContent');
      if (target && !target.classList.contains('show')) {
        var bsCollapse = bootstrap.Collapse.getOrCreateInstance(target, {
          toggle: false
        });
        bsCollapse.show();
      }
      setTimeout(function () {
        var searchInput = document.getElementById('search-addon');
        if (searchInput) {
          searchInput.focus();
        }
      }, 160);
    });

    window.fmUpdateSelectionBar();

    $('#search-addon').on('keyup', function () {
      window.mainTable.search(this.value).draw();
    });

    $('input#advanced-search').on('keyup', function (e) {
      if (e.keyCode === 13) {
        fmSearch();
      }
    });

    $('#search-addon3').on('click', function () {
      fmSearch();
    });

    $('.fm-upload-wrapper .card-header-tabs').on('click', 'a', function (e) {
      e.preventDefault();
      var target = $(this).data('target');
      $('.fm-upload-wrapper .card-header-tabs a').removeClass('active');
      $(this).addClass('active');
      $('.fm-upload-wrapper .card-tabs-container').addClass('hidden');
      $(target).removeClass('hidden');
    });
  });

  window.rename = renameItem;
  window.change_checkboxes = changeCheckboxes;
  window.get_checkboxes = getCheckboxes;
  window.select_all = selectAll;
  window.unselect_all = unselectAll;
  window.invert_all = invertAll;
  window.checkbox_toggle = checkboxToggle;
  window.backup = backup;
  window.toast = toast;
  window.edit_save = editSave;
  window.show_new_pwd = showNewPwd;
  window.save_settings = saveSettings;
  window.change_password = changePassword;
  window.new_password_hash = newPasswordHash;
  window.upload_from_url = uploadFromUrl;
  window.search_template = searchTemplate;
  window.fm_search = fmSearch;
  window.confirmDailog = confirmDialog;
})();
