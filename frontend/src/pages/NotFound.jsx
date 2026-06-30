import { Link } from 'react-router-dom'
import ThemeToggle from '../components/ThemeToggle'

export default function NotFound() {
  return (
    <div style={{
      minHeight: '100vh',
      background: 'var(--bg-primary)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: 24,
      color: 'var(--text-primary)',
      position: 'relative',
    }}>
      <ThemeToggle style={{ position: 'absolute', top: 20, right: 20 }} />
      <div style={{
        width: 'min(720px, 100%)',
        background: 'var(--bg-card)',
        border: '1px solid var(--border-color)',
        borderRadius: 16,
        padding: 28,
        boxShadow: 'var(--shadow-lg)',
      }}>
        <div style={{
          display: 'flex',
          gap: 16,
          alignItems: 'center',
          marginBottom: 12,
        }}>
          <div style={{
            width: 52,
            height: 52,
            borderRadius: 14,
            background: 'rgba(239,68,68,0.12)',
            border: '1px solid rgba(239,68,68,0.35)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontWeight: 900,
            fontSize: 20,
          }}>
            404
          </div>
          <div>
            <h1 style={{ margin: 0, fontSize: 22, fontWeight: 900 }}>Page introuvable</h1>
            <p style={{ margin: '6px 0 0', color: 'var(--text-secondary)', fontSize: 13 }}>
              La page demandée n’existe pas.
            </p>
          </div>
        </div>

        <div style={{
          marginTop: 18,
          color: 'var(--text-secondary)',
          fontSize: 13,
          lineHeight: 1.6,
        }}>
        </div>

      </div>
    </div>
  )
}

