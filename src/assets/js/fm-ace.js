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

  var cfg = readJsonConfig('fm-ace-config');
  if (!cfg || typeof window.ace === 'undefined') {
    return;
  }

  var root = document.getElementById('editor');
  if (!root) {
    return;
  }

  window.editor = ace.edit('editor');
  window.editor.getSession().setMode({
    path: 'ace/mode/' + (cfg.initialMode || 'text'),
    inline: true
  });
  window.editor.setShowPrintMargin(false);

  function aceCommand(cmd) {
    window.editor.commands.exec(cmd, window.editor);
  }

  window.editor.commands.addCommands([
    {
      name: 'save',
      bindKey: {
        win: 'Ctrl-S',
        mac: 'Command-S'
      },
      exec: function () {
        if (typeof window.edit_save === 'function') {
          window.edit_save(this, 'ace');
        }
      }
    }
  ]);

  function optionNode(type, arr) {
    var option = '';
    $.each(arr, function (i, val) {
      option += "<option value='" + type + i + "'>" + val + '</option>';
    });
    return option;
  }

  function renderThemeMode() {
    var modeEl = $('select#js-ace-mode');
    var themeEl = $('select#js-ace-theme');
    var fontSizeEl = $('select#js-ace-fontSize');

    var modelist = ace.require('ace/ext/modelist');
    var themelist = ace.require('ace/ext/themelist');
    var modeOptions = {};
    var brightThemeOptions = {};
    var darkThemeOptions = {};

    if (modelist && modelist.modes && modelist.modes.length) {
      $.each(modelist.modes, function (_, mode) {
        if (mode && mode.name) {
          modeOptions[mode.name] = mode.caption || mode.name;
        }
      });
      modeEl.html(optionNode('ace/mode/', modeOptions));
    }

    if (themelist && themelist.themesByName) {
      $.each(themelist.themesByName, function (name, theme) {
        if (!theme) {
          return;
        }
        if (theme.isDark) {
          darkThemeOptions[name] = theme.caption || name;
        } else {
          brightThemeOptions[name] = theme.caption || name;
        }
      });

      var lightTheme = optionNode('ace/theme/', brightThemeOptions);
      var darkTheme = optionNode('ace/theme/', darkThemeOptions);
      themeEl.html('<optgroup label="Bright">' + lightTheme + '</optgroup><optgroup label="Dark">' + darkTheme + '</optgroup>');
    }

    fontSizeEl.html(optionNode('', {
      8: 8,
      10: 10,
      11: 11,
      12: 12,
      13: 13,
      14: 14,
      15: 15,
      16: 16,
      17: 17,
      18: 18,
      20: 20,
      22: 22,
      24: 24,
      26: 26,
      30: 30
    }));

    modeEl.val(window.editor.getSession().$modeId);
    themeEl.val(window.editor.getTheme());
    fontSizeEl.val(12).change();
  }

  window.renderThemeMode = renderThemeMode;

  $(function () {
    renderThemeMode();

    $('.js-ace-toolbar').on('click', 'button', function (e) {
      e.preventDefault();
      var cmdValue = $(this).attr('data-cmd');
      var editorOption = $(this).attr('data-option');

      if (cmdValue && cmdValue !== 'none') {
        aceCommand(cmdValue);
      } else if (editorOption) {
        if (editorOption === 'fullscreen') {
          if (
            (typeof document.fullScreenElement !== 'undefined' && document.fullScreenElement === null) ||
            (typeof document.msFullscreenElement !== 'undefined' && document.msFullscreenElement === null) ||
            (typeof document.mozFullScreen !== 'undefined' && !document.mozFullScreen) ||
            (typeof document.webkitIsFullScreen !== 'undefined' && !document.webkitIsFullScreen)
          ) {
            if (window.editor.container.requestFullScreen) {
              window.editor.container.requestFullScreen();
            } else if (window.editor.container.mozRequestFullScreen) {
              window.editor.container.mozRequestFullScreen();
            } else if (window.editor.container.webkitRequestFullScreen) {
              window.editor.container.webkitRequestFullScreen(Element.ALLOW_KEYBOARD_INPUT);
            } else if (window.editor.container.msRequestFullscreen) {
              window.editor.container.msRequestFullscreen();
            }
          }
        } else if (editorOption === 'wrap') {
          var wrapStatus = window.editor.getSession().getUseWrapMode() ? false : true;
          window.editor.getSession().setUseWrapMode(wrapStatus);
        }
      }
    });

    $('select#js-ace-mode, select#js-ace-theme, select#js-ace-fontSize').on('change', function (e) {
      e.preventDefault();
      var selectedValue = $(this).val();
      var selectionType = $(this).attr('data-type');

      if (selectedValue && selectionType === 'mode') {
        window.editor.getSession().setMode(selectedValue);
      } else if (selectedValue && selectionType === 'theme') {
        window.editor.setTheme(selectedValue);
      } else if (selectedValue && selectionType === 'fontSize') {
        window.editor.setFontSize(parseInt(selectedValue, 10));
      }
    });
  });
})();
