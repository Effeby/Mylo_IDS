import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Eye, EyeOff } from 'lucide-react'
import { login } from '../api/mylo'


export default function Login() {
  const [show, setShow]   = useState(false)
  const [form, setForm]   = useState({ user: '', pass: '' })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  const handleLogin = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await login(form.user, form.pass)
      //navigate('/monitor')
      navigate('/dashboard')  // au lieu de navigate('/monitor')
    } catch (err) {
      setError(err.response?.data?.error || 'Identifiants incorrects')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      minHeight: '100vh', background: '#0A0E1A',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div style={{
        position: 'absolute', inset: 0,
        backgroundImage: 'radial-gradient(circle at 1px 1px, #1E2D4F 1px, transparent 0)',
        backgroundSize: '40px 40px', opacity: 0.4,
      }} />

      <div style={{
        position: 'relative', width: 400, padding: 40,
        background: '#0F1629', borderRadius: 20,
        border: '1px solid #1E2D4F',
        boxShadow: '0 25px 50px rgba(0,0,0,0.5)',
      }}>
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <div style={{
            width: 64, height: 64, borderRadius: 16, margin: '0 auto 16px',
            background: 'linear-gradient(135deg, #3B82F6, #1E40AF)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Shield size={32} color="#fff" />
          </div>
          <h1 style={{ color: '#F8FAFC', fontSize: 24, fontWeight: 800, margin: 0 }}>Mylo IDS</h1>
          <p style={{ color: '#94A3B8', fontSize: 13, margin: '6px 0 0' }}>SecureBank Security Center</p>
        </div>

        <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div>
            <label style={{ color: '#94A3B8', fontSize: 12, fontWeight: 600, display: 'block', marginBottom: 6 }}>
              IDENTIFIANT
            </label>
            <input
              value={form.user}
              onChange={e => setForm({ ...form, user: e.target.value })}
              placeholder="admin"
              autoComplete="username"
              style={{
                width: '100%', padding: '12px 16px', borderRadius: 8, fontSize: 14,
                background: '#0A0E1A', border: '1px solid #1E2D4F',
                color: '#F8FAFC', outline: 'none', boxSizing: 'border-box',
              }}
            />
          </div>

          <div>
            <label style={{ color: '#94A3B8', fontSize: 12, fontWeight: 600, display: 'block', marginBottom: 6 }}>
              MOT DE PASSE
            </label>
            <div style={{ position: 'relative' }}>
              <input
                type={show ? 'text' : 'password'}
                value={form.pass}
                onChange={e => setForm({ ...form, pass: e.target.value })}
                placeholder="••••••••"
                autoComplete="current-password"
                style={{
                  width: '100%', padding: '12px 44px 12px 16px', borderRadius: 8, fontSize: 14,
                  background: '#0A0E1A', border: '1px solid #1E2D4F',
                  color: '#F8FAFC', outline: 'none', boxSizing: 'border-box',
                }}
              />
              <button type="button" onClick={() => setShow(!show)} style={{
                position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)',
                background: 'none', border: 'none', color: '#94A3B8', cursor: 'pointer',
              }}>
                {show ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          {error && (
            <div style={{
              padding: '10px 14px', borderRadius: 8, fontSize: 13,
              background: 'rgba(239,68,68,0.1)', border: '1px solid #EF4444',
              color: '#EF4444',
            }}>
              ⚠️ {error}
            </div>
          )}

          <button type="submit" disabled={loading} style={{
            padding: '13px', borderRadius: 8, fontSize: 14, fontWeight: 700,
            background: loading ? '#1E2D4F' : 'linear-gradient(135deg, #3B82F6, #1E40AF)',
            border: 'none', color: '#fff', cursor: loading ? 'not-allowed' : 'pointer', marginTop: 8,
          }}>
            {loading ? 'Connexion...' : 'Accéder au Dashboard'}
          </button>
        </form>

        <p style={{ color: '#475569', fontSize: 11, textAlign: 'center', marginTop: 24 }}>
          Système de détection d'intrusion — SecureBank © 2025
        </p>
      </div>
    </div>
  )
}