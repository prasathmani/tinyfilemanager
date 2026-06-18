(function () {
  function initFolderTree() {
    var treeElement = document.getElementById('fm-folder-tree');
    var configElement = document.getElementById('fm-folder-tree-config');
    if (!treeElement || !configElement) {
      return;
    }

    var config = {};
    try {
      config = JSON.parse(configElement.textContent || '{}');
    } catch (e) {
      return;
    }

    var loadedPaths = new Set();
    var ancestorPaths = Array.isArray(config.ancestorPaths) ? config.ancestorPaths : [];
    var currentPath = String(config.currentPath || '');
    var homePath = String(config.homePath || '');
    var endpoint = String(config.endpoint || window.location.href);
    var csrfToken = String(config.csrfToken || '');
    var texts = config.texts || {};
    var lastKnownRevision = Number(config.treeRevision || 0);
    var revisionPollMs = 8000;
    var revisionPollTimer = null;
    var revisionRequestInFlight = false;

    window.fmFolderTreeRequestCount = 0;

    function text(key, fallback) {
      var value = texts[key];
      if (typeof value === 'string' && value !== '') {
        return value;
      }
      return fallback;
    }

    function getCurrentToken() {
      var tokenInput = document.querySelector('input[name="token"]');
      if (tokenInput && typeof tokenInput.value === 'string' && tokenInput.value !== '') {
        return tokenInput.value;
      }
      return csrfToken;
    }

    function findNode(path) {
      var nodes = treeElement.querySelectorAll('.fm-tree-node');
      for (var i = 0; i < nodes.length; i++) {
        if ((nodes[i].dataset.path || '') === path) {
          return nodes[i];
        }
      }
      return null;
    }

    function findChildrenContainer(path) {
      var containers = treeElement.querySelectorAll('.fm-tree-children');
      for (var i = 0; i < containers.length; i++) {
        if ((containers[i].dataset.parentPath || '') === path) {
          return containers[i];
        }
      }
      return null;
    }

    function getNodeLevel(path) {
      if (path === homePath) {
        return 1;
      }

      var relative = path;
      if (homePath !== '' && (path + '/').indexOf(homePath + '/') === 0) {
        relative = path.slice(homePath.length);
        relative = relative.replace(/^\/+/, '');
      }

      if (!relative) {
        return 1;
      }

      return relative.split('/').filter(Boolean).length + 1;
    }

    function setExpandedState(node, expanded) {
      if (!node) {
        return;
      }

      var toggle = node.querySelector('.fm-tree-toggle');
      var path = node.dataset.path || '';
      var childrenContainer = findChildrenContainer(path);
      var hasChildren = toggle && !toggle.disabled;

      if (!hasChildren) {
        node.classList.remove('is-expanded');
        node.setAttribute('aria-expanded', 'false');
        return;
      }

      node.classList.toggle('is-expanded', expanded);
      node.setAttribute('aria-expanded', expanded ? 'true' : 'false');
      toggle.setAttribute('aria-expanded', expanded ? 'true' : 'false');
      toggle.setAttribute('aria-label', expanded ? text('collapse', 'Collapse') : text('expand', 'Expand'));
      if (childrenContainer) {
        childrenContainer.hidden = !expanded;
      }
    }

    function createTreeNode(child) {
      var path = String(child.path || '');
      var name = String(child.name || '');
      var hasChildren = !!child.has_children;
      var level = getNodeLevel(path);
      var isActive = path === currentPath;
      var isExpanded = hasChildren && ancestorPaths.indexOf(path) !== -1;

      var node = document.createElement('div');
      node.className = 'fm-tree-node' + (isActive ? ' is-active' : '') + (isExpanded ? ' is-expanded' : '') + ' fm-tree-node--depth-' + level;
      node.setAttribute('role', 'treeitem');
      node.setAttribute('aria-level', String(level));
      node.setAttribute('aria-expanded', hasChildren ? (isExpanded ? 'true' : 'false') : 'false');
      node.setAttribute('aria-selected', isActive ? 'true' : 'false');
      node.dataset.path = path;

      var toggle = document.createElement('button');
      toggle.type = 'button';
      toggle.className = 'fm-tree-toggle' + (!hasChildren ? ' is-leaf' : '');
      toggle.dataset.path = path;
      toggle.setAttribute('aria-expanded', hasChildren ? (isExpanded ? 'true' : 'false') : 'false');
      toggle.setAttribute('aria-label', hasChildren ? (isExpanded ? text('collapse', 'Collapse') : text('expand', 'Expand')) : text('noSubfolders', 'No subfolders'));
      if (!hasChildren) {
        toggle.disabled = true;
      }

      var caret = document.createElement('i');
      caret.className = 'fa fa-caret-right';
      caret.setAttribute('aria-hidden', 'true');
      toggle.appendChild(caret);

      var link = document.createElement('a');
      link.className = 'fm-tree-label' + (isActive ? ' is-active' : '');
      link.href = '?p=' + encodeURIComponent(path);
      link.dataset.path = path;
      link.setAttribute('role', 'treeitem');
      link.setAttribute('aria-selected', isActive ? 'true' : 'false');

      var icon = document.createElement('i');
      icon.className = 'fa fa-folder-o';
      icon.setAttribute('aria-hidden', 'true');

      var title = document.createElement('span');
      title.textContent = name;

      link.appendChild(icon);
      link.appendChild(title);

      node.appendChild(toggle);
      node.appendChild(link);

      var children = document.createElement('div');
      children.className = 'fm-tree-children';
      children.dataset.parentPath = path;
      children.hidden = !isExpanded;

      return {
        node: node,
        children: children,
        expandAfterRender: isExpanded,
        path: path,
      };
    }

    function renderChildren(parentPath, childrenList) {
      var childrenContainer = findChildrenContainer(parentPath);
      if (!childrenContainer) {
        return;
      }

      childrenContainer.innerHTML = '';

      if (!childrenList.length) {
        var empty = document.createElement('div');
        empty.className = 'fm-tree-empty';
        empty.textContent = text('noSubfolders', 'No subfolders');
        childrenContainer.appendChild(empty);
        return;
      }

      var pendingExpand = [];
      childrenList.forEach(function (child) {
        var rendered = createTreeNode(child);
        childrenContainer.appendChild(rendered.node);
        childrenContainer.appendChild(rendered.children);
        if (rendered.expandAfterRender) {
          pendingExpand.push(rendered.path);
        }
      });

      pendingExpand.forEach(function (path) {
        ensureChildrenLoaded(path, true);
      });
    }

    function setLoadingState(path, loading) {
      var node = findNode(path);
      if (!node) {
        return;
      }
      node.classList.toggle('is-loading', loading);
    }

    function buildTreeRequest(payload) {
      var formData = new URLSearchParams();
      var requestToken = getCurrentToken();
      var requestPath = currentPath || homePath || '';
      formData.append('ajax', '1');
      formData.append('p', requestPath);
      formData.append('token', requestToken);

      Object.keys(payload || {}).forEach(function (key) {
        formData.append(String(key), String(payload[key]));
      });

      return fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
          'Accept': 'application/json',
          'X-Requested-With': 'XMLHttpRequest',
        },
        credentials: 'same-origin',
        body: formData.toString(),
      })
        .then(function (response) {
          return response.text().then(function (bodyText) {
            return {
              ok: response.ok,
              status: response.status,
              bodyText: bodyText,
            };
          });
        })
        .then(function (result) {
          if (!result.ok) {
            throw new Error('HTTP_' + result.status);
          }

          try {
            return JSON.parse(result.bodyText || '{}');
          } catch (parseError) {
            throw new Error('NON_JSON_RESPONSE');
          }
        });
    }

    function ensureChildrenLoaded(path, forceOpen, attempt) {
      attempt = typeof attempt === 'number' ? attempt : 0;

      var childrenContainer = findChildrenContainer(path);
      if (!childrenContainer) {
        return Promise.resolve(false);
      }

      if (loadedPaths.has(path)) {
        if (forceOpen) {
          setExpandedState(findNode(path), true);
        }
        return Promise.resolve(true);
      }

      setLoadingState(path, true);
      window.fmFolderTreeRequestCount += 1;

      return buildTreeRequest({
        type: 'folder_tree_children',
        path: path,
      })
        .then(function (payload) {
          if (!payload || payload.success !== true || !Array.isArray(payload.children)) {
            throw new Error(text('loadError', 'Failed to load folders'));
          }

          if (typeof payload.revision === 'number' && payload.revision >= 0) {
            lastKnownRevision = payload.revision;
          }

          renderChildren(path, payload.children);
          loadedPaths.add(path);
          if (forceOpen) {
            setExpandedState(findNode(path), true);
          }

          return true;
        })
        .catch(function () {
          if (attempt < 1) {
            return ensureChildrenLoaded(path, forceOpen, attempt + 1);
          }

          childrenContainer.innerHTML = '';
          var error = document.createElement('button');
          error.type = 'button';
          error.className = 'fm-tree-error';
          error.textContent = text('loadError', 'Failed to load folders');
          error.addEventListener('click', function () {
            loadedPaths.delete(path);
            ensureChildrenLoaded(path, true, 0);
          });
          childrenContainer.appendChild(error);
          setExpandedState(findNode(path), true);
          return false;
        })
        .finally(function () {
          setLoadingState(path, false);
        });
    }

    function requestTreeRevision() {
      if (revisionRequestInFlight) {
        return Promise.resolve(lastKnownRevision);
      }

      revisionRequestInFlight = true;
      return buildTreeRequest({ type: 'folder_tree_revision' })
        .then(function (payload) {
          if (payload && payload.success === true && typeof payload.revision === 'number') {
            return payload.revision;
          }
          return lastKnownRevision;
        })
        .catch(function () {
          return lastKnownRevision;
        })
        .finally(function () {
          revisionRequestInFlight = false;
        });
    }

    function collectExpandedPaths() {
      var paths = [];
      var nodes = treeElement.querySelectorAll('.fm-tree-node.is-expanded');
      nodes.forEach(function (node) {
        var path = String(node.dataset.path || '');
        if (path !== '') {
          paths.push(path);
        }
      });

      if (homePath !== '' && paths.indexOf(homePath) === -1) {
        paths.unshift(homePath);
      }

      paths.sort(function (a, b) {
        return getNodeLevel(a) - getNodeLevel(b);
      });

      return paths;
    }

    function getParentPath(path) {
      path = String(path || '').replace(/^\/+|\/+$/g, '');
      if (!path) {
        return homePath;
      }

      var idx = path.lastIndexOf('/');
      if (idx === -1) {
        return homePath;
      }

      var parent = path.slice(0, idx);
      if (homePath !== '' && (parent + '/').indexOf(homePath + '/') !== 0 && parent !== homePath) {
        return homePath;
      }
      return parent;
    }

    function invalidatePathAndAncestors(path) {
      var cursor = String(path || '').replace(/^\/+|\/+$/g, '');
      var seen = {};

      while (cursor !== '' && !seen[cursor]) {
        seen[cursor] = true;
        loadedPaths.delete(cursor);
        cursor = getParentPath(cursor);
      }

      if (homePath !== '') {
        loadedPaths.delete(homePath);
      }
    }

    function refreshExpandedBranches(changedPaths) {
      if (Array.isArray(changedPaths) && changedPaths.length) {
        changedPaths.forEach(function (path) {
          invalidatePathAndAncestors(path);
        });
      } else {
        loadedPaths.clear();
      }

      var expandedPaths = collectExpandedPaths();
      if (!expandedPaths.length) {
        expandedPaths = [homePath];
      }

      var sequence = Promise.resolve(true);
      expandedPaths.forEach(function (path) {
        sequence = sequence.then(function () {
          return ensureChildrenLoaded(path, true, 0);
        });
      });

      return sequence;
    }

    function handleFilesystemChangedEvent(detail) {
      var changedPaths = [];
      if (detail && Array.isArray(detail.paths)) {
        changedPaths = detail.paths.map(function (value) {
          return String(value || '').replace(/^\/+|\/+$/g, '');
        }).filter(Boolean);
      }

      var revision = detail && typeof detail.revision === 'number' ? detail.revision : null;
      if (revision !== null && revision <= lastKnownRevision && !detail.forceRefresh) {
        return;
      }

      if (revision !== null) {
        lastKnownRevision = revision;
      }

      refreshExpandedBranches(changedPaths);
    }

    function checkRevisionAndRefresh() {
      return requestTreeRevision().then(function (revision) {
        if (typeof revision !== 'number') {
          return;
        }
        if (revision > lastKnownRevision) {
          var event;
          try {
            event = new CustomEvent('fm:filesystem-changed', {
              detail: {
                revision: revision,
                reason: 'revision_poll',
                forceRefresh: true,
              },
            });
          } catch (e) {
            return;
          }
          window.dispatchEvent(event);
          return;
        }
        lastKnownRevision = revision;
      });
    }

    function startRevisionPolling() {
      if (revisionPollTimer || document.hidden) {
        return;
      }

      revisionPollTimer = window.setInterval(function () {
        checkRevisionAndRefresh();
      }, revisionPollMs);
    }

    function stopRevisionPolling() {
      if (!revisionPollTimer) {
        return;
      }

      window.clearInterval(revisionPollTimer);
      revisionPollTimer = null;
    }

    function toggleNode(path) {
      var node = findNode(path);
      if (!node) {
        return;
      }
      var expanded = node.classList.contains('is-expanded');
      if (expanded) {
        setExpandedState(node, false);
        return;
      }

      ensureChildrenLoaded(path, true);
    }

    function bindTreeHandlers() {
      treeElement.addEventListener('click', function (event) {
        var toggle = event.target.closest('.fm-tree-toggle');
        if (!toggle || !treeElement.contains(toggle)) {
          return;
        }

        event.preventDefault();
        event.stopPropagation();

        if (toggle.disabled) {
          return;
        }

        var path = String(toggle.dataset.path || '');
        toggleNode(path);
      });

      treeElement.addEventListener('keydown', function (event) {
        var toggle = event.target.closest('.fm-tree-toggle');
        if (!toggle || !treeElement.contains(toggle)) {
          return;
        }

        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          toggle.click();
        }
      });
    }

    function markInitiallyLoaded() {
      var containers = treeElement.querySelectorAll('.fm-tree-children');
      containers.forEach(function (container) {
        if (container.childElementCount > 0) {
          loadedPaths.add(container.dataset.parentPath || '');
        }
      });
    }

    function fmGetParentPathClient(path) {
      return getParentPath(path);
    }

    function expandAncestors() {
      if (!ancestorPaths.length) {
        return;
      }

      var chain = ancestorPaths.slice(1);
      var sequence = Promise.resolve(true);
      chain.forEach(function (path) {
        sequence = sequence.then(function () {
          var parentPath = fmGetParentPathClient(path);
          var parentNode = findNode(parentPath);
          if (parentNode) {
            setExpandedState(parentNode, true);
          }
          return ensureChildrenLoaded(parentPath, true).then(function () {
            var node = findNode(path);
            if (node && !node.classList.contains('is-active') && path === currentPath) {
              node.classList.add('is-active');
            }
            return true;
          });
        });
      });
    }

    bindTreeHandlers();
    window.addEventListener('fm:filesystem-changed', function (event) {
      handleFilesystemChangedEvent(event ? event.detail : null);
    });

    document.addEventListener('visibilitychange', function () {
      if (document.hidden) {
        stopRevisionPolling();
        return;
      }

      startRevisionPolling();
      checkRevisionAndRefresh();
    });

    markInitiallyLoaded();
    if (homePath !== '' || findNode('')) {
      loadedPaths.add(homePath);
    }
    expandAncestors();
    startRevisionPolling();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initFolderTree);
    return;
  }

  initFolderTree();
})();
