import React from 'react';

const themes = [
  { id: 'slate', name: 'Slate', color: '#64748b' },
  { id: 'snow', name: 'Snow', color: '#ffffff' },
];

export default function ThemeSwitcher({ currentTheme, onThemeChange, compact = false }) {
  return (
    <div className={`theme-switcher${compact ? " theme-switcher-compact" : ""}`}>
      <div className="theme-options">
        {themes.map((theme) => (
          <button
            key={theme.id}
            type="button"
            className={`theme-option ${currentTheme === theme.id ? 'active' : ''}`}
            onClick={() => onThemeChange(theme.id)}
            aria-label={`Switch to ${theme.name} theme`}
            aria-pressed={currentTheme === theme.id}
          >
            <span 
              className="theme-preview-dot" 
              style={{ backgroundColor: theme.color }}
            />
            <span className="theme-name">{theme.name}</span>
          </button>
        ))}
      </div>
    </div>
  );
}
