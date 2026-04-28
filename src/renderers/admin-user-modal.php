<?php
// Admin user modal renderer for New/Edit user
// Does not call fm_show_header/footer/exit/session_start
// Only generates modal HTML for AJAX load

if (!isset($modal_mode)) $modal_mode = 'new';
if (!isset($modal_username)) $modal_username = '';
if (!isset($modal_token)) $modal_token = '';

$readonly = $modal_mode === 'edit' ? 'readonly' : '';
$now = date('Y-m-d\TH:i');
$title = $modal_mode === 'edit' ? 'Edit user' : 'New user';
$username_value = htmlspecialchars($modal_username, ENT_QUOTES, 'UTF-8');

?>
<div class="modal fade" id="adminUserModal" tabindex="-1" aria-labelledby="adminUserModalLabel" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="adminUserModalLabel"><?php echo $title; ?></h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <form id="admin-user-modal-form" autocomplete="off">
        <div class="modal-body">
          <div class="mb-3">
            <label for="admin-username" class="form-label">Username</label>
            <input type="text" class="form-control" id="admin-username" name="username" value="<?php echo $username_value; ?>" <?php echo $readonly; ?> required>
          </div>
          <div class="mb-3">
            <label for="admin-password" class="form-label">Password</label>
            <input type="password" class="form-control" id="admin-password" name="password" autocomplete="new-password">
          </div>
          <div class="mb-3">
            <label for="admin-password2" class="form-label">Confirm password</label>
            <input type="password" class="form-control" id="admin-password2" name="password2" autocomplete="new-password">
          </div>
          <div class="mb-3">
            <label for="admin-access-type" class="form-label">Access type</label>
            <select class="form-select" id="admin-access-type" name="access_type">
              <option value="standard">Standard</option>
              <option value="read only">Read only</option>
              <option value="upload only">Upload only</option>
              <option value="manager">Manager</option>
            </select>
          </div>
          <div class="mb-3">
            <label for="admin-dirs" class="form-label">Assigned directories</label>
            <textarea class="form-control" id="admin-dirs" name="directories" rows="2"></textarea>
          </div>
          <div class="mb-3">
            <label for="admin-date" class="form-label">Dátum vloženia / zmeny</label>
            <input type="datetime-local" class="form-control" id="admin-date" name="date" value="<?php echo $now; ?>" readonly>
          </div>
          <div class="mb-3">
            <label for="admin-note" class="form-label">Poznámka</label>
            <textarea class="form-control" id="admin-note" name="note" rows="3"></textarea>
          </div>
          <input type="hidden" name="token" value="<?php echo htmlspecialchars($modal_token, ENT_QUOTES, 'UTF-8'); ?>">
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
          <button type="submit" class="btn btn-primary">Save</button>
          <?php if ($modal_mode === 'edit'): ?>
          <button type="button" class="btn btn-danger ms-2" id="admin-user-delete-btn">Zmazať</button>
          <?php endif; ?>
        </div>
      </form>
    </div>
  </div>
</div>
<script>
(function() {
  var form = document.getElementById('admin-user-modal-form');
  if (form) {
    form.onsubmit = function(e) {
      e.preventDefault();
      alert('Saving users will be implemented in the next phase.');
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
        + '<h5 class="modal-title">Potvrdenie vymazania</h5>'
        + '<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>'
        + '</div>'
        + '<div class="modal-body">Naozaj chceš vymazať užívateľa <strong>' + String(username).replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</strong>?</div>'
        + '<div class="modal-footer">'
        + '<button type="button" class="btn btn-secondary" data-bs-dismiss="modal" id="admin-user-delete-no">No</button>'
        + '<button type="button" class="btn btn-danger" id="admin-user-delete-yes">Yes</button>'
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
        alert('Delete handler will be implemented in the next phase.');
        bsModal.hide();
      });
    });
  }
})();
</script>
