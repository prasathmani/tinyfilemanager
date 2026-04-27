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
    maxFilesize: String(config.maxFileSize),
    acceptedFiles: config.acceptedFiles || '',
    init: function () {
      this.on('sending', function (file, xhr) {
        var path = file.fullPath ? file.fullPath : file.name;
        var fullPathInput = document.getElementById('fullpath');
        if (fullPathInput) {
          fullPathInput.value = path;
        }
        xhr.ontimeout = function () {
          if (typeof window.toast === 'function') {
            window.toast('Error: Server Timeout');
          }
        };
      })
        .on('success', function (res) {
          try {
            var response = JSON.parse(res.xhr.response);
            if (response.status === 'error' && typeof window.toast === 'function') {
              window.toast(response.info);
            }
          } catch (e) {
            if (typeof window.toast === 'function') {
              window.toast('Error: Invalid JSON response');
            }
          }
        })
        .on('error', function (file, response) {
          if (typeof window.toast === 'function') {
            window.toast(response);
          }
        });
    }
  };
})();
