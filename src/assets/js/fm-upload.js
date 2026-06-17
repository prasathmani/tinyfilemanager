(function () {
  function readJsonConfig(id) {
    var el = document.getElementById(id);
    if (!el) {
      return null;
    }
    try {
      return JSON.parse(el.textContent || '{}');
    } catch (e) {
      return null;
    }
  }

  function parseDropzoneResponse(response) {
    if (response && typeof response === 'object') {
      return response;
    }
    if (typeof response !== 'string' || response.trim() === '') {
      return null;
    }
    try {
      return JSON.parse(response);
    } catch (e) {
      return null;
    }
  }

  function extractHttpError(response, xhr) {
    var status = (xhr && typeof xhr.status !== 'undefined') ? xhr.status : 'unknown';
    var body = '';

    if (typeof response === 'string') {
      body = response;
    } else if (response && typeof response === 'object') {
      if (typeof response.info === 'string') {
        body = response.info;
      } else if (typeof response.message === 'string') {
        body = response.message;
      } else {
        try {
          body = JSON.stringify(response);
        } catch (e) {
          body = '';
        }
      }
    }

    if (!body && xhr && typeof xhr.responseText === 'string') {
      body = xhr.responseText;
    }

    return 'HTTP ' + status + (body ? ' - ' + body : '');
  }

  var config = readJsonConfig('fm-upload-config');
  if (!config || typeof window.Dropzone === 'undefined' || !window.Dropzone.options) {
    return;
  }

  window.Dropzone.options.fileUploader = {
    chunking: true,
    chunkSize: config.chunkSize,
    forceChunking: true,
    retryChunks: true,
    retryChunksLimit: 3,
    parallelUploads: 1,
    parallelChunkUploads: false,
    timeout: 120000,
    maxFilesize: Number(config.maxFileSize) / (1024 * 1024),
    acceptedFiles: config.acceptedFiles || '',
    init: function () {
      this.on('sending', function (file, xhr) {
        var path = file.fullPath ? file.fullPath : file.name;
        var uploadDirInput = document.getElementById('upload_dir');
        var fullPathInput = document.getElementById('fullpath');
        if (uploadDirInput && !uploadDirInput.value) {
          uploadDirInput.value = (typeof window.fm_path === 'string') ? window.fm_path : '';
        }
        if (fullPathInput) {
          fullPathInput.value = path;
        }
        xhr.ontimeout = function () {
          if (typeof window.toast === 'function') {
            window.toast('Error: Server Timeout');
          }
        };
      })
        .on('success', function (file, response) {
          var parsed = parseDropzoneResponse(response);
          if (!parsed) {
            file.status = window.Dropzone.ERROR;
            this.emit('error', file, 'Invalid JSON response from server');
            return;
          }

          if (parsed.status === 'success') {
            if (parsed.code === 'SUCCESS' && typeof window.toast === 'function') {
              window.toast('Súbor bol uložený.');
            }
            return;
          }

          var message = (typeof parsed.info === 'string' && parsed.info.trim() !== '')
            ? parsed.info
            : 'Upload failed.';
          file.status = window.Dropzone.ERROR;
          this.emit('error', file, message);
        })
        .on('error', function (file, response, xhr) {
          var message = extractHttpError(response, xhr);
          if (typeof window.toast === 'function') {
            window.toast(message);
          }
        });
    }
  };
})();
