import { Sun, Moon } from 'lucide-react';
import { useTheme } from '../context/ThemeContext.jsx';

// variant="icon" — boxed icon button (standalone pages: Login, Register, ...)
// variant="row"  — full-width ghost row with label, matching nav/logout items (Sidebar footer)
export default function ThemeToggle({ style = {}, variant = 'icon', rail = false }) {
  const { theme, toggleTheme } = useTheme();
  const isDark = theme === 'dark';
  const label = isDark ? 'Thème clair' : 'Thème sombre';

  if (variant === 'row') {
    return (
      <button
        onClick={toggleTheme}
        title={rail ? label : undefined}
        aria-label="Changer de thème"
        style={{
          width: '100%', display: 'flex', alignItems: 'center', gap: 12,
          justifyContent: rail ? 'center' : 'flex-start',
          padding: '10px 12px', borderRadius: 8,
          background: 'none', border: 'none',
          color: 'var(--text-secondary)', fontSize: 14, cursor: 'pointer',
          transition: 'color 0.18s',
          ...style,
        }}
      >
        {isDark ? <Sun size={18} /> : <Moon size={18} />} {!rail && label}
      </button>
    );
  }

  return (
    <button
      onClick={toggleTheme}
      title={isDark ? 'Passer en thème clair' : 'Passer en thème sombre'}
      aria-label="Changer de thème"
      style={{
        width: 36, height: 36, borderRadius: 10,
        border: '1px solid var(--border-color)',
        background: 'var(--bg-card)',
        color: isDark ? '#EAB308' : '#3B82F6',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        cursor: 'pointer', flexShrink: 0,
        boxShadow: 'var(--shadow-xs)',
        ...style,
      }}
    >
      {isDark ? <Sun size={17} /> : <Moon size={17} />}
    </button>
  );
}
