import { Sun, Moon } from 'lucide-react';
import { useTheme } from '../context/ThemeContext.jsx';

export default function ThemeToggle({ style = {} }) {
  const { theme, toggleTheme } = useTheme();
  const isDark = theme === 'dark';

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
