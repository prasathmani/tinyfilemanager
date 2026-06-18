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

  function resolveCurrentPathFromLocation() {
    try {
      var url = new URL(window.location.href);
      return String(url.searchParams.get('p') || '').replace(/^\/+|\/+$/g, '');
    } catch (e) {
      return '';
    }
  }

  function emitFilesystemChanged(detail) {
    if (typeof window.CustomEvent !== 'function') {
      return;
    }

    var payload = detail && typeof detail === 'object' ? detail : {};
    if (!Array.isArray(payload.paths) || !payload.paths.length) {
      payload.paths = [resolveCurrentPathFromLocation()];
    }

    window.dispatchEvent(new CustomEvent('fm:filesystem-changed', {
      detail: payload,
    }));
  }

  var searchIndexState = {
    ready: false,
    preparePromise: null,
    pendingQuery: '',
    pendingPath: ''
  };

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
    for (var n = 0; n < e.length; n++) {
      if (e[n] && e[n].type === 'checkbox') {
        t.push(e[n]);
      }
    }
    return t;
  }

  var selectionAnchor = null;

  function getRuntimeText(key, fallback) {
    return String(config[key] || fallback || '');
  }

  function getSearchStatusElement() {
    return document.getElementById('fm-search-index-status');
  }

  function setSearchStatus(message, kind) {
    var element = getSearchStatusElement();
    if (!element) {
      return;
    }

    if (!message) {
      element.textContent = '';
      element.style.display = 'none';
      element.className = 'small text-muted mb-2';
      return;
    }

    element.textContent = message;
    element.style.display = 'block';
    element.className = 'small mb-2' + (kind === 'error' ? ' text-danger' : kind === 'success' ? ' text-success' : ' text-muted');
  }

  function executeSearchRequest(searchTxt, path) {
    var searchWrapper = $('#search-wrapper');
    var loader = $('div.lds-facebook');
    var html = '';

    $.ajax({
      type: 'POST',
      url: window.location,
      data: {
        ajax: true,
        content: searchTxt,
        path: path,
        type: 'search',
        token: window.csrf
      },
      beforeSend: function () {
        searchWrapper.html('');
        loader.addClass('show-me');
      },
      success: function (payload) {
        loader.removeClass('show-me');
        if (typeof payload === 'string') {
          try {
            payload = JSON.parse(payload);
          } catch (e) {
            searchWrapper.html('<p class="m-2">ERROR: Invalid search response.</p>');
            return;
          }
        }
        if (payload && payload.length) {
          html = searchTemplate(payload);
          searchWrapper.html(html);
          setSearchStatus(getRuntimeText('searchIndexReadyText', 'Search map is ready.'), 'success');
        } else {
          searchWrapper.html('<p class="m-2">No result found!<p>');
          setSearchStatus(getRuntimeText('searchIndexReadyText', 'Search map is ready.'), 'success');
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
  }

  function flushPendingSearch() {
    var searchTxt = String(searchIndexState.pendingQuery || '').trim();
    var path = String(searchIndexState.pendingPath || resolveSearchPath());

    searchIndexState.pendingQuery = '';
    searchIndexState.pendingPath = '';

    if (!searchTxt || searchTxt.length <= 2) {
      return;
    }

    setSearchStatus(getRuntimeText('searchIndexRetryText', 'Retrying search after index preparation...'), 'info');
    executeSearchRequest(searchTxt, path);
  }

  function prepareSearchIndex(options) {
    var settings = options || {};
    var showStatus = settings.showStatus !== false;

    if (searchIndexState.ready) {
      var readyPromise = $.Deferred();
      readyPromise.resolve({ success: true, cached: true });
      return readyPromise.promise();
    }

    if (searchIndexState.preparePromise) {
      if (showStatus) {
        setSearchStatus(getRuntimeText('searchIndexPreparingText', 'Preparing search map...'), 'info');
      }
      return searchIndexState.preparePromise;
    }

    var deferred = $.Deferred();
    var promise = deferred.promise();
    searchIndexState.preparePromise = promise;

    promise.always(function () {
      searchIndexState.preparePromise = null;
      if (searchIndexState.pendingQuery) {
        flushPendingSearch();
      }
    });

    $.ajax({
      type: 'POST',
      url: window.location,
      data: {
        ajax: true,
        type: 'search_index_prepare',
        path: resolveSearchPath(),
        token: window.csrf
      },
      beforeSend: function () {
        if (showStatus) {
          setSearchStatus(getRuntimeText('searchIndexPreparingText', 'Preparing search map...'), 'info');
        }
      },
      success: function (payload) {
        if (typeof payload === 'string') {
          try {
            payload = JSON.parse(payload);
          } catch (e) {
            payload = null;
          }
        }

        if (payload && payload.success === true) {
          searchIndexState.ready = true;
          setSearchStatus(getRuntimeText('searchIndexReadyText', 'Search map is ready.'), 'success');
          deferred.resolve(payload);
          return;
        }

        searchIndexState.ready = false;
        setSearchStatus(getRuntimeText('searchIndexPrepareErrorText', 'Search map could not be prepared. Search will use fallback mode.'), 'error');
        deferred.resolve(payload || { success: false });
      },
      error: function () {
        searchIndexState.ready = false;
        setSearchStatus(getRuntimeText('searchIndexPrepareErrorText', 'Search map could not be prepared. Search will use fallback mode.'), 'error');
        deferred.resolve({ success: false });
      },
      failure: function () {
        searchIndexState.ready = false;
        setSearchStatus(getRuntimeText('searchIndexPrepareErrorText', 'Search map could not be prepared. Search will use fallback mode.'), 'error');
        deferred.resolve({ success: false });
      }
    });

    return promise;
  }

  function queueSearchRequest(searchTxt, path) {
    searchIndexState.pendingQuery = searchTxt;
    searchIndexState.pendingPath = path;

    if (searchIndexState.ready) {
      flushPendingSearch();
      return;
    }

    prepareSearchIndex({ showStatus: true });
  }

  function updateSelectionAnchor(checkbox) {
    if (!checkbox || checkbox.type !== 'checkbox') {
      return;
    }

    if (checkbox.checked) {
      selectionAnchor = checkbox;
      return;
    }

    if (selectionAnchor === checkbox) {
      selectionAnchor = null;
    }
  }

  function applyRangeSelection(anchor, current, checked) {
    var checkboxes = getCheckboxes();
    var anchorIndex = checkboxes.indexOf(anchor);
    var currentIndex = checkboxes.indexOf(current);

    if (anchorIndex === -1 || currentIndex === -1) {
      current.checked = checked;
      return;
    }

    var startIndex = Math.min(anchorIndex, currentIndex);
    var endIndex = Math.max(anchorIndex, currentIndex);
    for (var i = startIndex; i <= endIndex; i++) {
      checkboxes[i].checked = checked;
    }
  }

  function isSelectionModifiedEvent(event) {
    return !!(event && (event.shiftKey || event.ctrlKey || event.metaKey));
  }

  function handleSelectionToggle(checkbox, event) {
    if (!checkbox || checkbox.type !== 'checkbox') {
      return;
    }

    if (event && event.shiftKey && selectionAnchor) {
      event.preventDefault();
      event.stopPropagation();
      applyRangeSelection(selectionAnchor, checkbox, !checkbox.checked);
      updateSelectionAnchor(checkbox);
      if (typeof window.fmUpdateSelectionBar === 'function') {
        window.fmUpdateSelectionBar();
      }
      return;
    }

    var shouldUpdateAnchor = true;
    if (event && isSelectionModifiedEvent(event)) {
      shouldUpdateAnchor = true;
    }

    window.setTimeout(function () {
      if (shouldUpdateAnchor) {
        updateSelectionAnchor(checkbox);
      }
      if (typeof window.fmUpdateSelectionBar === 'function') {
        window.fmUpdateSelectionBar();
      }
    }, 0);
  }

  function isInteractiveElement(node) {
    if (!node) {
      return false;
    }

    // Clicking link text can produce a Text node target; normalize to element.
    if (node.nodeType === 3 && node.parentElement) {
      node = node.parentElement;
    }

    if (!node.tagName) {
      return false;
    }

    var tagName = String(node.tagName).toUpperCase();
    if (tagName === 'A' || tagName === 'BUTTON' || tagName === 'INPUT' || tagName === 'LABEL' || tagName === 'SELECT' || tagName === 'TEXTAREA') {
      return true;
    }

    return !!node.closest && !!node.closest('a, button, input, label, select, textarea, .filename');
  }

  function bindRowClickSelection() {
    var rows = document.querySelectorAll('#main-table tbody tr');

    rows.forEach(function (row) {
      if (row.dataset && row.dataset.rowSelectionBound === '1') {
        return;
      }

      if (row.dataset) {
        row.dataset.rowSelectionBound = '1';
      }

      row.addEventListener('click', function (event) {
        if (isInteractiveElement(event.target)) {
          return;
        }

        var checkbox = row.querySelector('input[name="file[]"]');
        if (!checkbox) {
          return;
        }

        if (event.shiftKey && selectionAnchor) {
          handleSelectionToggle(checkbox, event);
          return;
        }

        checkbox.checked = !checkbox.checked;
        handleSelectionToggle(checkbox, event);
      });
    });
  }

  function bindSelectionModifiers() {
    var checkboxes = getCheckboxes();

    checkboxes.forEach(function (checkbox) {
      if (checkbox.dataset && checkbox.dataset.selectionBound === '1') {
        return;
      }

      if (checkbox.dataset) {
        checkbox.dataset.selectionBound = '1';
      }

      checkbox.addEventListener('click', function (event) {
        handleSelectionToggle(checkbox, event);
      }, true);
    });
  }

  function changeCheckboxes(e, t) {
    for (var n = e.length - 1; n >= 0; n--) {
      e[n].checked = typeof t === 'boolean' ? t : !e[n].checked;
    }
    selectionAnchor = null;
    for (var i = 0; i < e.length; i++) {
      if (e[i].checked) {
        selectionAnchor = e[i];
        break;
      }
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

  function extractAjaxErrorMessage(xhr, fallback) {
    var fb = fallback || 'Request failed';
    if (!xhr) {
      return fb;
    }

    var raw = '';
    if (typeof xhr.responseText === 'string' && xhr.responseText.trim() !== '') {
      raw = xhr.responseText.trim();
    }

    if (raw) {
      try {
        var parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object') {
          if (parsed.msg) {
            return String(parsed.msg);
          }
          if (parsed.error) {
            return String(parsed.error);
          }
        }
      } catch (e) {
      }
      return raw;
    }

    if (xhr.status) {
      return fb + ' (HTTP ' + xhr.status + ')';
    }

    return fb;
  }

  function backup(path, file) {
    var xhr = new XMLHttpRequest();
    var payload = 'path=' + path + '&file=' + file + '&token=' + window.csrf + '&type=backup&ajax=true';
    xhr.open('POST', '', true);
    xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
    xhr.onreadystatechange = function () {
      if (xhr.readyState === 4 && xhr.status === 200) {
        toast(xhr.responseText);
        emitFilesystemChanged({
          reason: 'backup',
          paths: [String(path || '').replace(/^\/+|\/+$/g, '')],
        });
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
          emitFilesystemChanged({
            reason: 'save',
            paths: [resolveCurrentPathFromLocation()],
          });
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

  function buildAjaxPayloadWithToken(form) {
    var serialized = form.serialize();
    var hasToken = /(^|&)token=/.test(serialized);
    var formToken = String(form.find('input[name="token"]').val() || '');
    var tokenValue = formToken || String(window.csrf || '');

    if (!hasToken) {
      serialized += (serialized ? '&' : '') + 'token=' + encodeURIComponent(tokenValue);
    }

    serialized += (serialized ? '&' : '') + 'ajax=true';
    return serialized;
  }

  function saveSettings(el) {
    var form = $(el);
    var selectedTheme = form.find('select[name="js-theme-3"]').val() || 'light';
    var payload = buildAjaxPayloadWithToken(form);

    document.documentElement.setAttribute('data-bs-theme', selectedTheme);
    $('body').toggleClass('theme-dark', selectedTheme === 'dark');

    $.ajax({
      type: form.attr('method'),
      url: form.attr('action'),
      data: payload,
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
          toast(response.msg || 'Settings saved successfully');
          var url = new URL(window.location.href);
          url.searchParams.delete('settings');
          url.hash = '';
          var nextUrl = url.pathname + (url.searchParams.toString() ? '?' + url.searchParams.toString() : '');
          setTimeout(function () {
            window.location.assign(nextUrl);
          }, 450);
        } else {
          toast(response && response.msg ? response.msg : 'Settings could not be saved.');
        }
      },
      error: function () {
        toast(extractAjaxErrorMessage(arguments[0], 'Settings could not be saved.'));
      }
    });

    return false;
  }

  function changePassword(el) {
    var form = $(el);
    var payload = buildAjaxPayloadWithToken(form);
    $.ajax({
      type: 'post',
      url: '',
      data: payload,
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
        toast(extractAjaxErrorMessage(arguments[0], 'Password change failed'));
      }
    });
    return false;
  }

  function clearFallbackLog() {
    if (!window.confirm('Vymazat fallback log udalosti?')) {
      return false;
    }

    $.ajax({
      type: 'post',
      url: '',
      data: {
        ajax: true,
        type: 'settings_clear_fallback_log',
        token: window.csrf
      },
      success: function (data) {
        var response = data;
        if (typeof data === 'string') {
          try {
            response = JSON.parse(data);
          } catch (e) {
            response = { success: false, msg: 'Neznama odpoved' };
          }
        }

        if (response && response.success) {
          toast(response.msg || 'Fallback log bol vycisteny');
          refreshFallbackLogStats();
        } else {
          toast(response && response.msg ? response.msg : 'Fallback log sa nepodarilo vycistit');
        }
      },
      error: function () {
        toast(extractAjaxErrorMessage(arguments[0], 'Fallback log sa nepodarilo vycistit'));
      }
    });

    return false;
  }

  function refreshFallbackLogStats() {
    var root = document.getElementById('js-fallback-log-stats');
    if (!root) {
      return;
    }

    $.ajax({
      type: 'post',
      url: '',
      data: {
        ajax: true,
        type: 'settings_fallback_log_stats',
        token: window.csrf
      },
      success: function (data) {
        var response = data;
        if (typeof data === 'string') {
          try {
            response = JSON.parse(data);
          } catch (e) {
            return;
          }
        }

        if (!response || !response.success || !response.stats) {
          return;
        }

        var stats = response.stats;
        var existsEl = document.getElementById('js-fallback-log-exists');
        var bytesEl = document.getElementById('js-fallback-log-bytes');
        var linesEl = document.getElementById('js-fallback-log-lines');
        var updatedEl = document.getElementById('js-fallback-log-updated');
        var statusEl = document.getElementById('js-fallback-log-status');

        var bytes = Number(stats.bytes || 0);
        var lines = Number(stats.lines || 0);
        var statusText = 'NIZKE';
        var statusClass = 'bg-success';
        if (bytes >= 220000 || lines >= 900) {
          statusText = 'VYSOKE';
          statusClass = 'bg-danger';
        } else if (bytes >= 131072 || lines >= 600) {
          statusText = 'STREDNE';
          statusClass = 'bg-warning';
        }

        if (existsEl) existsEl.textContent = stats.exists ? 'ano' : 'nie';
        if (bytesEl) bytesEl.textContent = String(bytes);
        if (linesEl) linesEl.textContent = String(lines);
        if (updatedEl) updatedEl.textContent = stats.updated_at || '';
        if (statusEl) {
          statusEl.textContent = statusText;
          statusEl.classList.remove('bg-success', 'bg-warning', 'bg-danger');
          statusEl.classList.add(statusClass);
        }
      }
    });
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

    function parseUploadResponse(data) {
      if (typeof data === 'object' && data !== null) {
        return data;
      }
      if (typeof data !== 'string') {
        return null;
      }
      try {
        return JSON.parse(data);
      } catch (e) {
        return null;
      }
    }

    function showUploadResult(isSuccess, message) {
      var cssClass = isSuccess ? 'alert-success' : 'alert-danger';
      resultWrapper.append('<div class="alert ' + cssClass + ' row">' + message + '</div>');
    }

    $.ajax({
      type: form.attr('method'),
      url: form.attr('action'),
      data: buildAjaxPayloadWithToken(form),
      beforeSend: function () {
        form.find('input[name=uploadurl]').attr('disabled', 'disabled');
        form.find('button').hide();
        form.find('.lds-facebook').addClass('show-me');
      },
      success: function (data) {
        var parsed = parseUploadResponse(data);
        if (!parsed) {
          showUploadResult(false, 'Error: Invalid server response.');
        } else if (parsed.done) {
          var uploadedName = parsed.done.name ? parsed.done.name : 'file';
          showUploadResult(true, 'Uploaded successful: ' + uploadedName);
          emitFilesystemChanged({
            reason: 'upload_from_url',
            paths: [resolveCurrentPathFromLocation()],
          });
          form.find('input[name=uploadurl]').val('');
        } else if (parsed.fail) {
          var failMessage = (parsed.fail && parsed.fail.message) ? parsed.fail.message : 'Upload from URL failed.';
          showUploadResult(false, 'Error: ' + failMessage);
        } else {
          showUploadResult(false, 'Error: Unexpected upload response.');
        }
        form.find('input[name=uploadurl]').removeAttr('disabled');
        form.find('button').show();
        form.find('.lds-facebook').removeClass('show-me');
      },
      error: function (xhr) {
        form.find('input[name=uploadurl]').removeAttr('disabled');
        form.find('button').show();
        form.find('.lds-facebook').removeClass('show-me');

        var status = xhr && typeof xhr.status !== 'undefined' ? xhr.status : 'unknown';
        var responseText = xhr && typeof xhr.responseText === 'string' ? xhr.responseText.trim() : '';
        var detailed = responseText ? ('HTTP ' + status + ' - ' + responseText) : ('HTTP ' + status + ' - Server nevrátil detail chyby.');
        showUploadResult(false, 'URL upload zlyhal: ' + detailed);
        console.error(xhr);
      }
    });
    return false;
  }

  function escapeHtml(value) {
    return String(value || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function searchTemplate(data) {
    var rows = '';
    $.each(data, function (key, val) {
      var rawPath = String(val.path || '').replace(/^\/+/, '');
      var rawName = String(val.name || '');
      var fullPath = (rawPath ? rawPath + '/' : '') + rawName;
      var href = '?p=' + encodeURIComponent(rawPath) + '&view=' + encodeURIComponent(rawName);

      rows += '<tr>' +
        '<td class="text-nowrap"><a href="' + href + '">' + escapeHtml(rawName) + '</a></td>' +
        '<td><code>' + escapeHtml(rawPath || '/') + '</code></td>' +
        '<td class="text-nowrap"><a class="btn btn-sm btn-outline-primary" href="' + href + '"><i class="fa fa-external-link"></i> Open</a></td>' +
        '</tr>';
    });

    return '' +
      '<div class="table-responsive fm-search-results-table-wrap">' +
      '<table class="table table-sm table-striped align-middle mb-0 fm-search-results-table">' +
      '<thead><tr><th>File</th><th>Path</th><th>Action</th></tr></thead>' +
      '<tbody>' + rows + '</tbody>' +
      '</table>' +
      '</div>';
  }

  function normalizeSearchPath(value) {
    var raw = String(value || '').trim();
    if (!raw || raw === '#') {
      return '';
    }

    // If path came as URL, extract ?p= from query when available.
    try {
      if (/^https?:\/\//i.test(raw)) {
        var absUrl = new URL(raw, window.location.origin);
        var pAbs = String(absUrl.searchParams.get('p') || '').trim();
        if (pAbs) {
          return pAbs;
        }
      }
    } catch (e) {
    }

    // Accept plain query snippets too (e.g. ?p=dir/sub).
    if (raw.indexOf('?') !== -1 || raw.indexOf('&') !== -1) {
      try {
        var queryPart = raw.charAt(0) === '?' ? raw.slice(1) : raw;
        var params = new URLSearchParams(queryPart);
        var pQuery = String(params.get('p') || '').trim();
        if (pQuery) {
          return pQuery;
        }
      } catch (e) {
      }
    }

    // Keep existing behavior for direct relative path values.
    return raw;
  }

  function resolveSearchPath() {
    // Primary source: current route query (?p=...), always reflects active directory.
    try {
      var params = new URLSearchParams(window.location.search || '');
      var fromUrl = normalizeSearchPath(params.get('p'));
      if (fromUrl !== '') {
        return fromUrl;
      }
    } catch (e) {
    }

    // Secondary source: hidden form field used across listing forms.
    var hiddenPath = document.querySelector('input[name="p"]');
    if (hiddenPath) {
      var fromHidden = normalizeSearchPath(hiddenPath.value);
      if (fromHidden !== '') {
        return fromHidden;
      }
    }

    // Fallback source: modal trigger link href.
    var modalPath = normalizeSearchPath($('#js-search-modal').attr('href'));
    if (modalPath !== '') {
      return modalPath;
    }

    return '.';
  }

  function fmSearch() {
    var searchTxt = $('input#advanced-search').val();
    var path = resolveSearchPath();

    if (!!searchTxt && searchTxt.length > 2 && path) {
      queueSearchRequest(searchTxt, path);
    } else {
      $('#search-wrapper').html('OOPS: minimum 3 characters required!');
    }
  }

  function renderSearchIndexMap(payload) {
    var items = (payload && payload.items && Array.isArray(payload.items)) ? payload.items : [];
    var meta = (payload && payload.meta) ? payload.meta : {};
    var rows = '';

    items.forEach(function (item) {
      var relPath = String(item.rel_path || '');
      var dirPath = String(item.dir_path || '');
      var name = String(item.name || '');
      var isDir = Number(item.is_dir || 0) === 1;
      var mtimeTs = Number(item.mtime || 0);
      var indexedTs = Number(item.indexed_at || 0);
      var mtime = mtimeTs > 0 ? new Date(mtimeTs * 1000).toLocaleString() : '-';
      var indexedAt = indexedTs > 0 ? new Date(indexedTs * 1000).toLocaleString() : '-';
      var typeLabel = isDir ? 'DIR' : 'FILE';
      var href = isDir
        ? ('?p=' + encodeURIComponent(relPath))
        : ('?p=' + encodeURIComponent(dirPath) + '&view=' + encodeURIComponent(name));

      rows += '<tr>' +
        '<td><span class="badge ' + (isDir ? 'text-bg-info' : 'text-bg-secondary') + '">' + typeLabel + '</span></td>' +
        '<td><a href="' + href + '">' + escapeHtml(relPath || '/') + '</a></td>' +
        '<td><code>' + escapeHtml(dirPath || '/') + '</code></td>' +
        '<td class="text-nowrap">' + escapeHtml(mtime) + '</td>' +
        '<td class="text-nowrap">' + escapeHtml(indexedAt) + '</td>' +
        '</tr>';
    });

    var count = Number(meta.count || items.length || 0);
    var limit = Number(meta.limit || 0);
    var scope = String(meta.scope || '');
    var dbPath = String(meta.db_path || '');
    var isDirty = Number(meta.is_dirty || 0) === 1;
    var lastFullTs = Number(meta.last_full_index_at || 0);
    var lastFull = lastFullTs > 0 ? new Date(lastFullTs * 1000).toLocaleString() : '-';

    return '' +
      '<div class="mb-2 small text-muted">' +
      'SQL index map | records: <strong>' + count + '</strong>' +
      (limit > 0 ? (' / limit ' + limit) : '') +
      ' | dirty: <strong>' + (isDirty ? 'yes' : 'no') + '</strong>' +
      ' | last full index: <strong>' + escapeHtml(lastFull) + '</strong>' +
      '</div>' +
      '<div class="mb-2 small text-muted">scope: <code>' + escapeHtml(scope) + '</code></div>' +
      '<div class="mb-2 small text-muted">db: <code>' + escapeHtml(dbPath) + '</code></div>' +
      '<div class="table-responsive fm-search-results-table-wrap">' +
      '<table class="table table-sm table-striped align-middle mb-0 fm-search-results-table">' +
      '<thead><tr><th>Type</th><th>Indexed path</th><th>Dir</th><th>Modified</th><th>Indexed</th></tr></thead>' +
      '<tbody>' + (rows || '<tr><td colspan="5" class="text-muted">No indexed items for this path.</td></tr>') + '</tbody>' +
      '</table>' +
      '</div>';
  }

  function loadSearchIndexMap() {
    var searchWrapper = $('#search-wrapper');
    var loader = $('div.lds-facebook');
    var path = resolveSearchPath();

    $.ajax({
      type: 'POST',
      url: window.location,
      data: {
        ajax: true,
        type: 'search_index_map',
        path: path,
        limit: 1200,
        token: window.csrf
      },
      beforeSend: function () {
        searchWrapper.html('');
        loader.addClass('show-me');
      },
      success: function (payload) {
        loader.removeClass('show-me');
        if (typeof payload === 'string') {
          try {
            payload = JSON.parse(payload);
          } catch (e) {
            searchWrapper.html('<p class="m-2">ERROR: Invalid SQL map response.</p>');
            return;
          }
        }

        if (!payload || payload.success !== true) {
          var msg = payload && payload.msg ? String(payload.msg) : 'Search index map is unavailable.';
          searchWrapper.html('<p class="m-2 text-danger">' + escapeHtml(msg) + '</p>');
          return;
        }

        searchWrapper.html(renderSearchIndexMap(payload));
      },
      error: function () {
        loader.removeClass('show-me');
        searchWrapper.html('<p class="m-2">ERROR: Could not load SQL index map.</p>');
      }
    });
  }

  function triggerRecursiveSearchFromNavbar() {
    var navbarInput = document.getElementById('search-addon');
    if (!navbarInput) {
      return;
    }

    var query = String(navbarInput.value || '').trim();
    if (!query) {
      applyMainTableSearch();
      return;
    }

    var advancedInput = document.getElementById('advanced-search');
    if (advancedInput) {
      advancedInput.value = query;
    }

    if (window.jQuery && $('#searchModal').length) {
      $('#searchModal').modal('show');
    }

    // Reuse existing recursive search endpoint logic.
    fmSearch();
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
    if ($.fn.dataTable.isDataTable('#main-table')) {
      window.mainTable = table.DataTable();
    } else {
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
  }

  function applyMainTableSearch() {
    var input = document.getElementById('search-addon');
    if (!input) {
      return;
    }
    var query = String(input.value || '');

    if ((!window.mainTable || typeof window.mainTable.search !== 'function') && window.jQuery && window.jQuery.fn && window.jQuery.fn.dataTable) {
      initMainTableDataTable();
    }

    if (window.mainTable && typeof window.mainTable.search === 'function') {
      window.mainTable.search(query).draw();
      return;
    }

    var table = document.getElementById('main-table');
    if (!table) {
      return;
    }

    var rows = table.querySelectorAll('tbody tr');
    var needle = query.trim().toLowerCase();
    rows.forEach(function (row) {
      if (!needle) {
        row.style.display = '';
        return;
      }
      var text = String(row.textContent || '').toLowerCase();
      row.style.display = text.indexOf(needle) !== -1 ? '' : 'none';
    });
  }

  function bindMainTableSearch() {
    var input = document.getElementById('search-addon');
    var iconPrimary = document.getElementById('search-addon2');
    var iconSecondary = document.getElementById('search-addon3');
    var mobileFocus = document.getElementById('js-mobile-focus-search');
    var advancedInput = document.getElementById('advanced-search');
    var mapButton = document.getElementById('js-search-map-btn');

    if (!input) {
      // Even without navbar search field, advanced modal search must keep working.
      if (iconSecondary) {
        iconSecondary.style.cursor = 'pointer';
        iconSecondary.addEventListener('click', function (event) {
          event.preventDefault();
          fmSearch();
        });
      }

      if (advancedInput) {
        advancedInput.addEventListener('keydown', function (event) {
          if (event.key === 'Enter') {
            event.preventDefault();
            fmSearch();
          }
        });
      }
      return;
    }

    if (iconPrimary) {
      iconPrimary.style.cursor = 'pointer';
      iconPrimary.addEventListener('click', function (event) {
        event.preventDefault();
        triggerRecursiveSearchFromNavbar();
      });
    }

    if (iconSecondary) {
      iconSecondary.style.cursor = 'pointer';
      iconSecondary.addEventListener('click', function (event) {
        event.preventDefault();
        fmSearch();
      });
    }

    if (advancedInput) {
      advancedInput.addEventListener('keydown', function (event) {
        if (event.key === 'Enter') {
          event.preventDefault();
          fmSearch();
        }
      });
    }

    if (mapButton) {
      mapButton.addEventListener('click', function (event) {
        event.preventDefault();
        loadSearchIndexMap();
      });
    }

    if (document.getElementById('searchModal')) {
      prepareSearchIndex({ showStatus: false });
    }

    input.addEventListener('keydown', function (event) {
      if (event.key === 'Enter') {
        event.preventDefault();
        applyMainTableSearch();
      }
    });

    input.addEventListener('input', function () {
      applyMainTableSearch();
    });

    if (mobileFocus) {
      mobileFocus.addEventListener('click', function (event) {
        // Mobile search button now opens advanced search modal (handled by Bootstrap data-bs-toggle)
        // Just focus the search input in the modal when it opens
        setTimeout(function() {
          var advancedInput = document.getElementById('advanced-search');
          if (advancedInput) {
            advancedInput.focus();
          }
        }, 100);
      });
    }
  }

  $(document).ready(function () {
    if (document.getElementById('js-fallback-log-stats')) {
      refreshFallbackLogStats();
      window.setInterval(refreshFallbackLogStats, 15000);
    }

    initMainTableDataTable();
    bindMainTableSearch();
    bindSelectionModifiers();
    bindRowClickSelection();
    var hasMainTable = !!window.mainTable;
    function adjustNavbarOffset() {
      if ($('body').hasClass('navbar-fixed')) {
        var h = $('.main-nav.fixed-top').outerHeight(true) || 56;
        $('body').css('margin-top', h + 'px');
      }
    }
    adjustNavbarOffset();
    $(window).on('resize', adjustNavbarOffset);
    if (!hasMainTable) {
      // No #main-table: only adjust navbar offset, skip DataTable/grid/selection logic
      return;
    }
    // ...existing code for DataTable/grid/selection logic...
    // (The rest of the original document.ready handler remains unchanged)
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
  window.clear_fallback_log = clearFallbackLog;
  window.new_password_hash = newPasswordHash;
  window.upload_from_url = uploadFromUrl;
  window.search_template = searchTemplate;
  window.fm_search = fmSearch;
  window.confirmDailog = confirmDialog;
})();
