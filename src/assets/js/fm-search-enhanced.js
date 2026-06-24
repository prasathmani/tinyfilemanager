// Enhanced search functionality with debugging and better UX
// Add this to fm-main.js or wrap it in a document.ready block

(function() {
  'use strict';

  // Debug logging - remove in production
  var DEBUG = true;
  function debugLog(msg, data) {
    if (!DEBUG) return;
    console.log('[FM-SEARCH] ' + msg, data || '');
  }

  debugLog('Search module loaded');

  // Make sure the search input exists
  var searchInput = document.getElementById('search-addon');
  var searchButton = document.getElementById('search-addon2');
  var advancedSearchBtn = document.getElementById('js-search-modal');

  debugLog('Search input found:', !!searchInput);
  debugLog('Search button found:', !!searchButton);
  debugLog('Advanced search btn found:', !!advancedSearchBtn);

  // Enhanced applyMainTableSearch with better feedback
  function enhancedApplyMainTableSearch() {
    if (!searchInput) {
      debugLog('Search input not found!');
      return;
    }

    var query = String(searchInput.value || '').trim();
    debugLog('Search query:', query);

    var table = document.getElementById('main-table');
    if (!table) {
      debugLog('Main table not found!');
      return;
    }

    var rows = table.querySelectorAll('tbody tr');
    debugLog('Table rows found:', rows.length);

    if (!query) {
      // Show all rows
      rows.forEach(function(row) {
        row.style.display = '';
        row.classList.remove('fm-search-no-match');
      });
      debugLog('Cleared search filter');
      updateSearchIndicator(0, rows.length);
      return;
    }

    var needle = query.toLowerCase();
    var matchCount = 0;
    var totalVisible = 0;

    rows.forEach(function(row) {
      var text = String(row.textContent || '').toLowerCase();
      var isMatch = text.indexOf(needle) !== -1;
      
      row.style.display = isMatch ? '' : 'none';
      row.classList.toggle('fm-search-no-match', !isMatch);
      
      if (isMatch) {
        matchCount++;
        totalVisible++;
      }
    });

    debugLog('Matches found:', matchCount);
    updateSearchIndicator(matchCount, rows.length);
  }

  // Visual feedback for search results
  function updateSearchIndicator(matches, total) {
    var indicator = document.getElementById('fm-search-indicator');
    if (!indicator && matches > 0) {
      // Create indicator if it doesn't exist
      var badge = document.createElement('small');
      badge.id = 'fm-search-indicator';
      badge.className = 'badge bg-info ms-2';
      badge.style.fontSize = '0.75rem';
      if (searchInput && searchInput.parentElement) {
        searchInput.parentElement.appendChild(badge);
      }
      indicator = badge;
    }

    if (indicator) {
      if (matches === 0 && String(searchInput.value || '').trim()) {
        indicator.textContent = 'Nenájdené';
        indicator.className = 'badge bg-danger ms-2';
      } else if (matches > 0) {
        indicator.textContent = matches + ' nájdené';
        indicator.className = 'badge bg-success ms-2';
      } else {
        indicator.style.display = 'none';
      }
    }
  }

  // Hook into existing search binding
  if (window.bindMainTableSearch) {
    var originalBind = window.bindMainTableSearch;
    window.bindMainTableSearch = function() {
      originalBind.call(this);
      
      // Add our enhancements
      if (searchInput) {
        debugLog('Enhancing search input event listeners');
        
        // Listen for input changes
        searchInput.addEventListener('input', function() {
          debugLog('Input event triggered');
          enhancedApplyMainTableSearch();
        });

        // Listen for keydown (Enter to search)
        searchInput.addEventListener('keydown', function(e) {
          if (e.key === 'Enter') {
            e.preventDefault();
            debugLog('Enter key pressed');
            enhancedApplyMainTableSearch();
          }
        });
      }

      // Enhance search button
      if (searchButton) {
        searchButton.addEventListener('click', function(e) {
          e.preventDefault();
          debugLog('Search button clicked');
          
          // Decide whether to do table filter or modal search based on query length
          var query = String(searchInput.value || '').trim();
          if (query.length >= 3) {
            // Use modal search for longer queries
            if (typeof triggerRecursiveSearchFromNavbar === 'function') {
              triggerRecursiveSearchFromNavbar();
            } else {
              enhancedApplyMainTableSearch();
            }
          } else if (query.length > 0) {
            // Just filter the table for short queries
            enhancedApplyMainTableSearch();
          }
        });
      }
    };
  }

  // On document ready, enhance search
  document.addEventListener('DOMContentLoaded', function() {
    debugLog('DOMContentLoaded event');
    
    // Wait for main page to load
    setTimeout(function() {
      if (searchInput) {
        debugLog('Initializing search enhancements');
        enhancedApplyMainTableSearch();
      }
    }, 100);
  });

  // Expose for testing
  window.fm_search_debug = {
    test: function() {
      debugLog('=== SEARCH DIAGNOSTICS ===');
      debugLog('Input element:', !!searchInput);
      debugLog('Search button:', !!searchButton);
      debugLog('Table element:', !!document.getElementById('main-table'));
      debugLog('Table rows:', document.getElementById('main-table') ? 
               document.getElementById('main-table').querySelectorAll('tbody tr').length : 0);
      return 'Diagnostics logged to console';
    },
    search: enhancedApplyMainTableSearch,
    debugToggle: function() { DEBUG = !DEBUG; return 'Debug: ' + (DEBUG ? 'ON' : 'OFF'); }
  };

  debugLog('Search module initialized. Type window.fm_search_debug.test() to diagnose.');

})();
