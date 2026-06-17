import { Link } from 'react-router-dom'

export default function NotFound() {
  return (
    <div style={{
      minHeight: '100vh',
      background: '#0A0E1A',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: 24,
      color: '#F8FAFC',
    }}>
      <div style={{
        width: 'min(720px, 100%)',
        background: '#0F1629',
        border: '1px solid #1E2D4F',
        borderRadius: 16,
        padding: 28,
        boxShadow: '0 25px 50px rgba(0,0,0,0.5)',
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
            <p style={{ margin: '6px 0 0', color: '#94A3B8', fontSize: 13 }}>
              La page demandée n’existe pas.
            </p>
          </div>
        </div>

        <div style={{
          marginTop: 18,
          color: '#94A3B8',
          fontSize: 13,
          lineHeight: 1.6,
        }}>
        </div>

      </div>
    </div>
  )
}

