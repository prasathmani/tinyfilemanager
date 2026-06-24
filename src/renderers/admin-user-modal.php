<?php
// Admin user modal renderer for New/Edit user
// Does not call fm_show_header/footer/exit/session_start
// Only generates modal HTML for AJAX load

if (!isset($modal_mode)) $modal_mode = 'new';
if (!isset($modal_username)) $modal_username = '';
if (!isset($modal_token)) $modal_token = '';
if (!isset($modal_access_type)) $modal_access_type = 'standard';
if (!isset($modal_directories)) $modal_directories = '';
if (!isset($modal_note)) $modal_note = '';
if (!isset($modal_welcome_message)) $modal_welcome_message = '';
if (!isset($modal_bulk_actions_enabled)) $modal_bulk_actions_enabled = true;
if (!isset($modal_manager_users) || !is_array($modal_manager_users)) $modal_manager_users = array();
if (!isset($modal_manager_owner)) $modal_manager_owner = 'admin';
if (!isset($modal_is_manager_actor)) $modal_is_manager_actor = false;

$readonly = $modal_mode === 'edit' ? 'readonly' : '';
$now = date('Y-m-d\TH:i');
$title = $modal_mode === 'edit' ? lng('Edit user') : lng('New user');
$username_value = htmlspecialchars($modal_username, ENT_QUOTES, 'UTF-8');
$directories_value = htmlspecialchars($modal_directories, ENT_QUOTES, 'UTF-8');
$note_value = htmlspecialchars($modal_note, ENT_QUOTES, 'UTF-8');
$default_welcome_message = 'Ahoj {username}, vitaj v Správcovi súborov. Ak budeš potrebovať pomoc, ozvi sa prosím adminovi.';
$welcome_message_raw = (string) $modal_welcome_message;
if ($modal_mode !== 'edit' && trim($welcome_message_raw) === '') {
  $welcome_message_raw = $default_welcome_message;
}
$welcome_message_value = htmlspecialchars($welcome_message_raw, ENT_QUOTES, 'UTF-8');
$modal_cancel_label = (isset($lang) && $lang === 'sk') ? 'Zatvoriť' : 'Cancel';
$can_assign_manager_owner = !$modal_is_manager_actor;

?>
<div class="modal fade" id="adminUserModal" tabindex="-1" aria-labelledby="adminUserModalLabel" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="adminUserModalLabel"><?php echo $title; ?></h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <form id="admin-user-modal-form" method="post" action="<?php echo htmlspecialchars(FM_SELF_URL . '?p=' . urlencode(FM_PATH) . '&admin_users_save=1', ENT_QUOTES, 'UTF-8'); ?>" autocomplete="off">
        <div class="modal-body">
          <div id="admin-user-modal-error" class="alert alert-danger d-none" role="alert"></div>
          <div class="mb-3">
            <label for="admin-username" class="form-label"><?php echo lng('Username'); ?></label>
            <input type="text" class="form-control" id="admin-username" name="username" value="<?php echo $username_value; ?>" <?php echo $readonly; ?> required>
          </div>
          <div class="mb-3">
            <label for="admin-password" class="form-label"><?php echo lng('Password'); ?></label>
            <input type="password" class="form-control" id="admin-password" name="password" autocomplete="new-password">
          </div>
          <div class="mb-3">
            <label for="admin-password2" class="form-label"><?php echo lng('Confirm password'); ?></label>
            <input type="password" class="form-control" id="admin-password2" name="password2" autocomplete="new-password">
          </div>
          <div class="mb-3">
            <label for="admin-access-type" class="form-label"><?php echo lng('Access type'); ?></label>
            <select class="form-select" id="admin-access-type" name="access_type">
              <option value="standard" <?php echo $modal_access_type === 'standard' ? 'selected' : ''; ?>><?php echo lng('Standard'); ?></option>
              <option value="read only" <?php echo $modal_access_type === 'read only' ? 'selected' : ''; ?>><?php echo lng('Read only'); ?></option>
              <option value="upload only" <?php echo $modal_access_type === 'upload only' ? 'selected' : ''; ?>><?php echo lng('Upload only'); ?></option>
              <?php if (!$modal_is_manager_actor): ?>
                <option value="manager" <?php echo $modal_access_type === 'manager' ? 'selected' : ''; ?>><?php echo lng('Manager'); ?></option>
              <?php endif; ?>
            </select>
          </div>
          <?php if ($can_assign_manager_owner): ?>
          <div class="mb-3">
            <label for="admin-manager-owner" class="form-label">Zodpovedný manažér</label>
            <select class="form-select" id="admin-manager-owner" name="manager_owner">
              <option value="admin" <?php echo $modal_manager_owner === 'admin' ? 'selected' : ''; ?>>admin</option>
              <?php foreach ($modal_manager_users as $manager_name): ?>
                <option value="<?php echo htmlspecialchars((string) $manager_name, ENT_QUOTES, 'UTF-8'); ?>" <?php echo $modal_manager_owner === (string) $manager_name ? 'selected' : ''; ?>><?php echo htmlspecialchars((string) $manager_name, ENT_QUOTES, 'UTF-8'); ?></option>
              <?php endforeach; ?>
            </select>
            <div class="form-text">Pre používateľov (nie manažérov) vyberte, kto za účet zodpovedá.</div>
          </div>
          <?php else: ?>
            <input type="hidden" name="manager_owner" value="<?php echo htmlspecialchars((string) $modal_manager_owner, ENT_QUOTES, 'UTF-8'); ?>">
          <?php endif; ?>
          <div class="mb-3">
            <label for="admin-dirs" class="form-label"><?php echo lng('Assigned directories'); ?> <span class="text-danger">*</span></label>
            <textarea class="form-control" id="admin-dirs" name="directories" rows="3" required><?php echo $directories_value; ?></textarea>
            <div class="form-text"><?php echo lng('Directory field cannot be empty.'); ?> <button type="button" class="btn btn-link btn-sm p-0 ms-1" id="admin-dirs-default"><?php echo lng('Nastaviť predvolený'); ?></button></div>
          </div>
          <div class="mb-3 form-check">
            <input type="checkbox" class="form-check-input" id="admin-bulk-actions-enabled" name="bulk_actions_enabled" value="1" <?php echo $modal_bulk_actions_enabled ? 'checked' : ''; ?>>
            <label class="form-check-label" for="admin-bulk-actions-enabled">Povoliť lištu hromadných akcií</label>
          </div>
          <div class="mb-3">
            <label for="admin-date" class="form-label">Dátum vloženia / zmeny</label>
            <input type="datetime-local" class="form-control" id="admin-date" name="date" value="<?php echo $now; ?>" readonly>
          </div>
          <div class="mb-3">
            <label for="admin-note" class="form-label">Poznámka</label>
            <textarea class="form-control" id="admin-note" name="note" rows="3"><?php echo $note_value; ?></textarea>
          </div>
          <div class="mb-3">
            <label for="admin-welcome-message" class="form-label">Uvítacia správa (prvé prihlásenie)</label>
            <textarea class="form-control" id="admin-welcome-message" name="welcome_message" rows="3" placeholder="Ahoj {username}, vitaj v Správcovi súborov."><?php echo $welcome_message_value; ?></textarea>
            <div class="form-text">Zástupné meno používateľa: {username}. Správa sa odošle iba raz po prvom prihlásení (okrem admina).</div>
          </div>
          <input type="hidden" name="mode" value="<?php echo htmlspecialchars($modal_mode, ENT_QUOTES, 'UTF-8'); ?>">
          <input type="hidden" name="token" value="<?php echo htmlspecialchars($modal_token, ENT_QUOTES, 'UTF-8'); ?>">
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-secondary" data-bs-dismiss="modal"><?php echo fm_enc($modal_cancel_label); ?></button>
          <button type="submit" class="btn btn-primary"><?php echo lng('Save'); ?></button>
          <?php if ($modal_mode === 'edit'): ?>
          <button type="button" class="btn btn-danger ms-2" id="admin-user-delete-btn"><?php echo lng('Delete'); ?></button>
          <?php endif; ?>
        </div>
      </form>
    </div>
  </div>
</div>
<script>
(function() {
  var form = document.getElementById('admin-user-modal-form');
  var errorBox = document.getElementById('admin-user-modal-error');
  var dirsField = document.getElementById('admin-dirs');
  var dirsDefaultBtn = document.getElementById('admin-dirs-default');
  var defaultDir = <?php echo json_encode(isset($modal_default_directory) ? (string) $modal_default_directory : '', JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); ?>;

  if (dirsDefaultBtn && dirsField) {
    dirsDefaultBtn.addEventListener('click', function() {
      if (dirsField.value.trim() === '') {
        dirsField.value = defaultDir;
      }
    });
  }

  function showError(message) {
    if (!errorBox) return;
    errorBox.textContent = message || 'Unable to save user.';
    errorBox.classList.remove('d-none');
  }

  function clearError() {
    if (!errorBox) return;
    errorBox.textContent = '';
    errorBox.classList.add('d-none');
  }

  function currentPath() {
    try {
      var url = new URL(window.location.href);
      return url.searchParams.get('p') || '';
    } catch (e) {
      return '';
    }
  }

  if (form) {
    form.onsubmit = function(e) {
      e.preventDefault();
      clearError();
      var fd = new FormData(form);
      var pwd = String(fd.get('password') || '');
      var pwd2 = String(fd.get('password2') || '');
      var dirs = String(fd.get('directories') || '').trim();
      if (dirs === '') {
        if (dirsField) {
          dirsField.value = defaultDir;
          fd.set('directories', defaultDir);
          dirs = defaultDir;
        }
        if (dirs === '') {
          showError('<?php echo addslashes(lng('Directory field cannot be empty.')); ?>');
          if (dirsField) dirsField.focus();
          return;
        }
      }
      if (pwd !== pwd2) {
        showError('<?php echo addslashes(lng('Passwords do not match.')); ?>');
        return;
      }

      var saveUrl = window.location.pathname + '?p=' + encodeURIComponent(currentPath()) + '&admin_users_save=1';
      fetch(saveUrl, {
        method: 'POST',
        body: fd,
        headers: {
          'X-Requested-With': 'XMLHttpRequest'
        },
        credentials: 'same-origin'
      })
        .then(function(resp) {
          return resp.json().catch(function() { return { ok: false, error: '<?php echo addslashes(lng('Unexpected server response')); ?>' }; });
        })
        .then(function(data) {
          if (!data || !data.ok) {
            showError((data && data.error) ? data.error : '<?php echo addslashes(lng('Save failed.')); ?>');
            return;
          }
          window.location.reload();
        })
        .catch(function() {
          showError('<?php echo addslashes(lng('Save request failed.')); ?>');
        });
    };
  }
  var deleteBtn = document.getElementById('admin-user-delete-btn');
  if (deleteBtn) {
    deleteBtn.addEventListener('click', function() {
      var username = document.getElementById('admin-username').value;
      var confirmBox = document.createElement('div');
      confirmBox.className = 'modal fade';
      confirmBox.id = 'admin-user-delete-confirm';
      confirmBox.tabIndex = -1;
      confirmBox.innerHTML = '<div class="modal-dialog">'
        + '<div class="modal-content">'
        + '<div class="modal-header">'
        + '<h5 class="modal-title"><?php echo addslashes(lng('Potvrdenie vymazania')); ?></h5>'
        + '<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>'
        + '</div>'
        + '<div class="modal-body"><?php echo addslashes(lng('Naozaj chceš vymazať užívateľa')); ?> <strong>' + String(username).replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</strong>?</div>'
        + '<div class="modal-footer">'
        + '<button type="button" class="btn btn-secondary" data-bs-dismiss="modal" id="admin-user-delete-no"><?php echo addslashes(lng('No')); ?></button>'
        + '<button type="button" class="btn btn-danger" id="admin-user-delete-yes"><?php echo addslashes(lng('Yes')); ?></button>'
        + '</div>'
        + '</div>'
        + '</div>';
      document.body.appendChild(confirmBox);
      var bsModal = new bootstrap.Modal(confirmBox);
      bsModal.show();
      confirmBox.addEventListener('hidden.bs.modal', function() {
        confirmBox.remove();
      });
      confirmBox.querySelector('#admin-user-delete-no').addEventListener('click', function() {
        bsModal.hide();
      });
      confirmBox.querySelector('#admin-user-delete-yes').addEventListener('click', function() {
        var formData = new FormData();
        formData.append('username', username);
        formData.append('token', '<?php echo htmlspecialchars($modal_token, ENT_QUOTES, 'UTF-8'); ?>');

        fetch(window.location.pathname + '?p=' + encodeURIComponent(currentPath()) + '&admin_users_delete=1', {
          method: 'POST',
          body: formData,
          headers: {
            'X-Requested-With': 'XMLHttpRequest'
          },
          credentials: 'same-origin'
        })
          .then(function(resp) {
            return resp.json().catch(function() { return { ok: false, error: '<?php echo addslashes(lng('Unexpected server response')); ?>' }; });
          })
          .then(function(data) {
            if (!data || !data.ok) {
              showError((data && data.error) ? data.error : '<?php echo addslashes(lng('Delete failed.')); ?>');
              bsModal.hide();
              return;
            }
            window.location.reload();
          })
          .catch(function() {
            showError('<?php echo addslashes(lng('Delete request failed.')); ?>');
            bsModal.hide();
          });
      });
    });
  }
})();
</script>
