/* =============================================================
   Sidebar Toggle
   ============================================================= */
function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('open');
    document.getElementById('sidebarOverlay').classList.toggle('active');
}

/* =============================================================
   Toast Notification System
   ============================================================= */
function showToast(message, type, duration) {
    type = type || 'info';
    duration = duration || 4000;
    var container = document.getElementById('toast-container');
    var toast = document.createElement('div');
    toast.className = 'toast toast-' + type;

    var icons = { success: '\u2713', error: '\u2717', info: '\u24D8' };

    var iconSpan = document.createElement('span');
    iconSpan.className = 'toast-icon';
    iconSpan.textContent = icons[type] || icons.info;

    var bodySpan = document.createElement('span');
    bodySpan.className = 'toast-body';
    bodySpan.textContent = message;

    var dismissBtn = document.createElement('button');
    dismissBtn.className = 'toast-dismiss';
    dismissBtn.setAttribute('aria-label', 'Dismiss');
    dismissBtn.innerHTML = '&times;';
    dismissBtn.onclick = function() { dismissToast(toast); };

    toast.appendChild(iconSpan);
    toast.appendChild(bodySpan);
    toast.appendChild(dismissBtn);

    container.appendChild(toast);

    setTimeout(function() {
        dismissToast(toast);
    }, duration);
}

function dismissToast(el) {
    if (!el || el.classList.contains('removing')) return;
    el.classList.add('removing');
    setTimeout(function() { el.remove(); }, 300);
}

/* HTMX error handler: show error toast */
document.addEventListener('htmx:responseError', function(evt) {
    var status = evt.detail.xhr ? evt.detail.xhr.status : 'unknown';
    showToast('Request failed (HTTP ' + status + '). Please try again.', 'error');
});

document.addEventListener('htmx:sendError', function() {
    showToast('Network error. Check your connection.', 'error');
});

/* HTMX after-swap: show subtle success for exec commands */
document.addEventListener('htmx:afterSwap', function(evt) {
    if (evt.detail.target && evt.detail.target.id === 'exec-history') {
        /* Auto-scroll terminal to bottom */
        var el = evt.detail.target;
        el.scrollTop = el.scrollHeight;

        /* Check if the last result was blocked */
        var results = el.querySelectorAll('.exec-blocked-msg');
        if (results.length > 0) {
            var lastResult = el.lastElementChild;
            if (lastResult && lastResult.querySelector('.exec-blocked-msg')) {
                showToast('Command blocked by security policy', 'error', 3000);
            }
        }
    }
});

/* =============================================================
   Copy to Clipboard
   ============================================================= */
function copyToClipboard(text, btn) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function() {
            onCopySuccess(btn);
        }).catch(function() {
            fallbackCopy(text, btn);
        });
    } else {
        fallbackCopy(text, btn);
    }
}

function fallbackCopy(text, btn) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try {
        document.execCommand('copy');
        onCopySuccess(btn);
    } catch (e) {
        showToast('Failed to copy to clipboard', 'error');
    }
    document.body.removeChild(ta);
}

function onCopySuccess(btn) {
    if (btn) {
        var original = btn.innerHTML;
        btn.classList.add('copied');
        btn.textContent = 'Copied!';
        setTimeout(function() {
            btn.classList.remove('copied');
            btn.innerHTML = original;
        }, 1500);
    }
    showToast('Copied to clipboard', 'success', 2000);
}

/* =============================================================
   Search / Filter Table
   ============================================================= */
function filterTable(value) {
    var term = value.toLowerCase().trim();
    var rows = document.querySelectorAll('#sandbox-table-wrapper .data-table tbody tr');
    rows.forEach(function(row) {
        var text = row.textContent.toLowerCase();
        row.style.display = text.indexOf(term) !== -1 ? '' : 'none';
    });
}

/* =============================================================
   Confirmation Dialog
   ============================================================= */
var confirmResolve = null;

function openConfirmDialog(sandboxName, form) {
    var dialog = document.getElementById('confirm-dialog');
    var msg = document.getElementById('confirm-dialog-message');
    msg.textContent = '';
    var pre = document.createTextNode('Stop sandbox ');
    var strong = document.createElement('strong');
    strong.textContent = sandboxName;
    var post = document.createTextNode('? Running processes will be terminated.');
    msg.appendChild(pre);
    msg.appendChild(strong);
    msg.appendChild(post);
    dialog.classList.add('open');
    dialog._form = form;
    document.getElementById('confirm-cancel-btn').focus();
}

function closeConfirmDialog(confirmed) {
    var dialog = document.getElementById('confirm-dialog');
    dialog.classList.remove('open');
    if (confirmed && dialog._form) {
        dialog._form._confirmed = true;
        dialog._form.requestSubmit ? dialog._form.requestSubmit() : dialog._form.submit();
    }
    dialog._form = null;
}

function confirmStop(form, sandboxName) {
    if (form._confirmed) {
        form._confirmed = false;
        return true;
    }
    openConfirmDialog(sandboxName, form);
    return false;
}

/* =============================================================
   Keyboard Shortcuts Modal
   ============================================================= */
function toggleShortcutsModal() {
    document.getElementById('shortcuts-modal').classList.toggle('open');
}

/* =============================================================
   Keyboard Shortcuts
   ============================================================= */
document.addEventListener('keydown', function(e) {
    /* Skip if user is typing in an input/textarea/select */
    var tag = e.target.tagName;
    var isInput = (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || e.target.isContentEditable);

    /* Escape always works */
    if (e.key === 'Escape') {
        document.getElementById('sidebar').classList.remove('open');
        document.getElementById('sidebarOverlay').classList.remove('active');
        document.getElementById('shortcuts-modal').classList.remove('open');
        var dlg = document.getElementById('confirm-dialog');
        if (dlg.classList.contains('open')) { closeConfirmDialog(false); }
        if (isInput) { e.target.blur(); }
        return;
    }

    if (isInput) return;

    /* ? -> show shortcuts */
    if (e.key === '?' && !e.ctrlKey && !e.metaKey) {
        e.preventDefault();
        toggleShortcutsModal();
        return;
    }

    /* c -> toggle create wizard */
    if (e.key === 'c' && !e.ctrlKey && !e.metaKey) {
        var newBtn = document.getElementById('new-sandbox-btn');
        if (newBtn && typeof window.showCreateWizard === 'function') {
            e.preventDefault();
            window.showCreateWizard();
        }
        return;
    }

    /* / -> focus exec command input */
    if (e.key === '/' && !e.ctrlKey && !e.metaKey) {
        var execInput = document.getElementById('exec-command');
        if (execInput) { e.preventDefault(); execInput.focus(); }
        return;
    }
});

/* =============================================================
   Create Sandbox Form Loading State
   ============================================================= */
document.addEventListener('DOMContentLoaded', function() {
    var createForms = document.querySelectorAll('form[action*="sandbox/create"]');
    createForms.forEach(function(form) {
        form.addEventListener('submit', function() {
            var btn = form.querySelector('button[type="submit"]');
            if (btn && !btn.disabled) {
                btn.classList.add('btn-creating');
                btn.disabled = true;
            }
        });
    });

    /* Auto-dismiss success/info flash messages after 5 seconds */
    var flashMessages = document.querySelectorAll('.flash-success, .flash-info');
    flashMessages.forEach(function(msg) {
        setTimeout(function() {
            if (msg.parentElement) {
                msg.classList.add('flash-removing');
                setTimeout(function() { msg.remove(); }, 300);
            }
        }, 5000);
    });
});

/* =============================================================
   Terminal Command History (localStorage)
   ============================================================= */
(function() {
    var HISTORY_KEY = 'lasso_cmd_history';
    var MAX_HISTORY = 50;
    var historyIndex = -1;
    var tempInput = '';

    function getHistory() {
        try { return JSON.parse(localStorage.getItem(HISTORY_KEY)) || []; }
        catch(e) { return []; }
    }

    function addToHistory(cmd) {
        if (!cmd || !cmd.trim()) return;
        var history = getHistory();
        /* Remove duplicate if it exists */
        var idx = history.indexOf(cmd);
        if (idx !== -1) { history.splice(idx, 1); }
        history.push(cmd);
        if (history.length > MAX_HISTORY) { history.shift(); }
        try { localStorage.setItem(HISTORY_KEY, JSON.stringify(history)); } catch(e) {}
    }

    document.addEventListener('DOMContentLoaded', function() {
        var execInput = document.getElementById('exec-command');
        if (!execInput) return;

        /* Save command on form submit */
        var execForm = execInput.closest('form');
        if (execForm) {
            execForm.addEventListener('submit', function() {
                addToHistory(execInput.value);
                historyIndex = -1;
                tempInput = '';
            });
        }

        /* Arrow key navigation */
        execInput.addEventListener('keydown', function(e) {
            var history = getHistory();
            if (history.length === 0) return;

            if (e.key === 'ArrowUp') {
                e.preventDefault();
                if (historyIndex === -1) {
                    tempInput = execInput.value;
                    historyIndex = history.length - 1;
                } else if (historyIndex > 0) {
                    historyIndex--;
                }
                execInput.value = history[historyIndex];
            } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                if (historyIndex === -1) return;
                if (historyIndex < history.length - 1) {
                    historyIndex++;
                    execInput.value = history[historyIndex];
                } else {
                    historyIndex = -1;
                    execInput.value = tempInput;
                }
            }
        });
    });
})();

/* =============================================================
   Skeleton Loading for HTMX Sandbox Table
   ============================================================= */
document.addEventListener('htmx:beforeRequest', function(evt) {
    var wrapper = document.getElementById('sandbox-table-wrapper');
    if (wrapper && wrapper.contains(evt.detail.elt)) {
        wrapper.classList.add('skeleton-loading');
    }
});
document.addEventListener('htmx:afterSwap', function(evt) {
    var wrapper = document.getElementById('sandbox-table-wrapper');
    if (wrapper) {
        wrapper.classList.remove('skeleton-loading');
    }
});
(function() {
    var _browserTargetInput = null;
    var _browserCurrentPath = '';

    function openBrowser(inputId) {
        _browserTargetInput = document.getElementById(inputId);
        var startPath = _browserTargetInput ? _browserTargetInput.value : '';
        _browserCurrentPath = startPath;
        document.getElementById('dir-browser-modal').style.display = 'flex';
        loadBookmarks();
        loadDir(startPath);
    }

    function loadBookmarks() {
        fetch('/browse-dirs?bookmarks=1')
            .then(function(r) { return r.json(); })
            .then(function(data) {
                var el = document.getElementById('dir-browser-bookmarks');
                if (!data.bookmarks) { el.style.display = 'none'; return; }
                el.style.display = 'flex';
                el.innerHTML = data.bookmarks.map(function(b) {
                    return '<button type="button" class="dir-bookmark" data-dirpath="' +
                        b.path.replace(/"/g, '&quot;') + '">' +
                        b.icon + ' ' + b.name + '</button>';
                }).join('');
                el.querySelectorAll('.dir-bookmark').forEach(function(btn) {
                    btn.addEventListener('click', function() {
                        loadDir(this.getAttribute('data-dirpath'));
                    });
                });
            })
            .catch(function() {});
    }

    function closeBrowser() {
        document.getElementById('dir-browser-modal').style.display = 'none';
    }

    function selectCurrentDir() {
        if (_browserTargetInput && _browserCurrentPath) {
            _browserTargetInput.value = _browserCurrentPath;
            // Trigger input event so any listeners pick up the change
            _browserTargetInput.dispatchEvent(new Event('input', { bubbles: true }));
        }
        closeBrowser();
    }

    function loadDir(path) {
        var listEl = document.getElementById('dir-browser-list');
        listEl.innerHTML = '<p style="color:var(--text-tertiary);padding:var(--sp-3);">Loading...</p>';

        fetch('/browse-dirs?path=' + encodeURIComponent(path))
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (data.error) {
                    listEl.innerHTML = '<p style="color:var(--color-error);padding:var(--sp-3);">' + escapeHtml(data.error) + '</p>';
                    return;
                }
                _browserCurrentPath = data.path;
                document.getElementById('dir-browser-path').textContent = data.path || 'Drives';

                var html = '';
                if (data.parent !== undefined && data.parent !== null && data.parent !== '') {
                    html += '<div class="dir-item dir-up" tabindex="0" role="button" data-dirpath="' + escapeAttr(data.parent) + '">&#8593; Parent directory</div>';
                } else if (data.path && navigator.platform && navigator.platform.indexOf('Win') !== -1) {
                    // On Windows, allow going back to drive list from a root drive
                    html += '<div class="dir-item dir-up" tabindex="0" role="button" data-dirpath="">&#8593; Drive list</div>';
                }
                data.entries.forEach(function(e) {
                    var icon = e.type === 'drive' ? '&#128190;' : '&#128193;';
                    html += '<div class="dir-item" tabindex="0" role="button" data-dirpath="' + escapeAttr(e.path) + '">' +
                        '<span class="dir-item-icon">' + icon + '</span> ' + escapeHtml(e.name) + '</div>';
                });
                if (data.entries.length === 0) {
                    html += '<p style="color:var(--text-tertiary);padding:var(--sp-3);">No subdirectories</p>';
                }
                listEl.innerHTML = html;

                // Attach click and keyboard handlers
                listEl.querySelectorAll('.dir-item').forEach(function(item) {
                    item.addEventListener('click', function() {
                        loadDir(this.getAttribute('data-dirpath'));
                    });
                    item.addEventListener('keydown', function(e) {
                        if (e.key === 'Enter') {
                            e.preventDefault();
                            loadDir(this.getAttribute('data-dirpath'));
                        }
                    });
                });
            })
            .catch(function() {
                listEl.innerHTML = '<p style="color:var(--color-error);padding:var(--sp-3);">Failed to load directory</p>';
            });
    }

    function escapeHtml(str) {
        var div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function escapeAttr(str) {
        return str.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    // Close modal on Escape
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') closeBrowser();
    });

    // Close modal on backdrop click
    document.getElementById('dir-browser-modal').addEventListener('click', function(e) {
        if (e.target === this) closeBrowser();
    });

    // Expose to global scope
    window.openBrowser = openBrowser;
    window.closeBrowser = closeBrowser;
    window.selectCurrentDir = selectCurrentDir;
})();
