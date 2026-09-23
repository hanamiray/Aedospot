// static/theme-toggle.js

// ── THEME TOGGLE FUNCTIONS ──
function toggleTheme() {
    const isLight = document.body.classList.contains('light-theme');
    
    if (isLight) {
        document.body.classList.remove('light-theme');
        localStorage.setItem('theme', 'dark');
        updateThemeUI('dark');
    } else {
        document.body.classList.add('light-theme');
        localStorage.setItem('theme', 'light');
        updateThemeUI('light');
    }
}

function updateThemeUI(theme) {
    const isLight = theme === 'light';
    
    // Update all theme toggle elements
    document.querySelectorAll('.theme-toggle, .theme-toggle-input, #themeToggle, #sidebarThemeToggle').forEach(el => {
        if (el.type === 'checkbox') {
            el.checked = isLight;
        } else if (el.classList.contains('theme-toggle')) {
            el.textContent = isLight ? '☀️' : '🌙';
        }
    });
    
    // Update labels
    document.querySelectorAll('.theme-label').forEach(el => {
        el.textContent = isLight ? 'Current: Light Mode' : 'Current: Dark Mode';
    });
    document.querySelectorAll('.theme-desc').forEach(el => {
        el.textContent = isLight ? 'Light theme with green accents.' : 'Dark theme with green accents.';
    });
    
    // Update sidebar icon
    document.querySelectorAll('.theme-toggle-sidebar .theme-icon').forEach(el => {
        el.textContent = isLight ? '☀️' : '🌙';
    });
}

function loadThemePreference() {
    const saved = localStorage.getItem('theme');
    const prefersLight = window.matchMedia('(prefers-color-scheme: light)').matches;
    
    let theme = saved || (prefersLight ? 'light' : 'dark');
    
    if (theme === 'light') {
        document.body.classList.add('light-theme');
    } else {
        document.body.classList.remove('light-theme');
    }
    
    updateThemeUI(theme);
}

function saveThemePreference() {
    const isLight = document.body.classList.contains('light-theme');
    localStorage.setItem('theme', isLight ? 'light' : 'dark');
    
    if (typeof showToast === 'function') {
        showToast(isLight ? '☀️ Light theme activated!' : '🌙 Dark theme activated!');
    }
}

function resetThemePreference() {
    document.body.classList.remove('light-theme');
    localStorage.setItem('theme', 'dark');
    updateThemeUI('dark');
    
    document.querySelectorAll('.theme-toggle-input, #themeToggle, #sidebarThemeToggle').forEach(el => {
        if (el.type === 'checkbox') el.checked = false;
    });
    document.querySelectorAll('.theme-toggle').forEach(el => {
        el.textContent = '🌙';
    });
    
    if (typeof showToast === 'function') {
        showToast('Theme reset to dark mode.');
    }
}

function toggleThemeFromSidebar() {
    toggleTheme();
    const settingsToggle = document.getElementById('themeToggle');
    if (settingsToggle) {
        settingsToggle.checked = document.body.classList.contains('light-theme');
    }
}

// ── INITIALIZE ──
document.addEventListener('DOMContentLoaded', function() {
    loadThemePreference();
    
    // Setup theme toggle listeners
    document.querySelectorAll('.theme-toggle, .theme-toggle-input, #themeToggle, #sidebarThemeToggle').forEach(el => {
        if (el.type === 'checkbox') {
            el.addEventListener('change', function() {
                toggleTheme();
                // Sync other toggles
                document.querySelectorAll('.theme-toggle-input, #themeToggle, #sidebarThemeToggle').forEach(other => {
                    if (other !== this && other.type === 'checkbox') {
                        other.checked = this.checked;
                    }
                });
            });
        } else if (el.classList.contains('theme-toggle')) {
            el.addEventListener('click', function() {
                toggleTheme();
                const isLight = document.body.classList.contains('light-theme');
                document.querySelectorAll('.theme-toggle-input, #themeToggle, #sidebarThemeToggle').forEach(other => {
                    if (other.type === 'checkbox') {
                        other.checked = isLight;
                    }
                });
            });
        }
    });
});

// ── EXPOSE GLOBALLY ──
window.toggleTheme = toggleTheme;
window.loadThemePreference = loadThemePreference;
window.saveThemePreference = saveThemePreference;
window.resetThemePreference = resetThemePreference;
window.toggleThemeFromSidebar = toggleThemeFromSidebar;
window.updateThemeUI = updateThemeUI;