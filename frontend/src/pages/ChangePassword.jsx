import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Eye, EyeOff } from 'lucide-react'
import { changeMyPassword } from '../api/mylo'
import ThemeToggle from '../components/ThemeToggle'

export default function ChangePassword() {
  const navigate = useNavigate()
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [show, setShow] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [tempAuth, setTempAuth] = useState(null)

  useEffect(() => {
    const stored = sessionStorage.getItem('mylo_temp_auth')
    if (!stored) {
      navigate('/')
      return
    }
    try {
      setTempAuth(JSON.parse(stored))
    } catch {
      sessionStorage.removeItem('mylo_temp_auth')
      navigate('/')
    }
  }, [navigate])

  const submit = async (e) => {
    e.preventDefault()
    setError('')

    if (!password.trim() || !confirm.trim()) {
      setError('Veuillez saisir un nouveau mot de passe et sa confirmation.')
      return
    }
    if (password !== confirm) {
      setError('Les mots de passe ne correspondent pas.')
      return
    }
    if (password.length < 8) {
      setError('Le mot de passe doit contenir au moins 8 caractères.')
      return
    }
    if (!tempAuth?.access) {
      navigate('/')
      return
    }

    setLoading(true)
    try {
      const updatedUser = await changeMyPassword(password, '', tempAuth.access)
      localStorage.setItem('mylo_access', tempAuth.access)
      localStorage.setItem('mylo_refresh', tempAuth.refresh)
      localStorage.setItem('mylo_user', JSON.stringify(updatedUser))

      if (updatedUser?.organisation?.is_setup_done === false) {
        navigate('/onboarding')
      } else if (updatedUser?.totp_enabled) {
        navigate('/totp-verify')
      } else {
        sessionStorage.removeItem('mylo_temp_auth')
        navigate('/dashboard')
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Impossible de changer le mot de passe.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24, position: 'relative' }}>
      <ThemeToggle style={{ position: 'absolute', top: 20, right: 20 }} />
      <div style={{ width: '100%', maxWidth: 480, padding: 'clamp(18px, 6vw, 32px)', borderRadius: 20, background: 'var(--bg-card)', border: '1px solid var(--border-color)', boxSizing: 'border-box' }}>
        <div style={{ textAlign: 'center', marginBottom: 28 }}>
          <div style={{ width: 64, height: 64, margin: '0 auto 16px', borderRadius: 18, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'linear-gradient(135deg, #3B82F6, #1E40AF)' }}>
            <Shield size={28} color="#fff" />
          </div>
          <h1 style={{ margin: 0, fontSize: 26, fontWeight: 800, color: 'var(--text-primary)' }}>
            Changer votre mot de passe
          </h1>
          <p style={{ marginTop: 12, color: 'var(--text-secondary)', fontSize: 14 }}>
            Pour des raisons de sécurité, vous devez définir un nouveau mot de passe avant de continuer.
          </p>
        </div>

        <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          <div>
            <label style={{ display: 'block', marginBottom: 8, fontSize: 12, color: 'var(--text-secondary)', fontWeight: 700 }}>Nouveau mot de passe</label>
            <div style={{ position: 'relative' }}>
              <input
                type={show ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                autoComplete="new-password"
                style={{ width: '100%', padding: '13px 44px 13px 16px', borderRadius: 12, background: 'var(--bg-primary)', border: '1px solid var(--border-color)', color: 'var(--text-primary)', fontSize: 16 }}
              />
              <button type="button" onClick={() => setShow(!show)} style={{ position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}>
                {show ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
          </div>

          <div>
            <label style={{ display: 'block', marginBottom: 8, fontSize: 12, color: 'var(--text-secondary)', fontWeight: 700 }}>Confirmer le mot de passe</label>
            <input
              type={show ? 'text' : 'password'}
              value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                placeholder="••••••••"
                autoComplete="new-password"
                style={{ width: '100%', padding: '13px 16px', borderRadius: 12, background: 'var(--bg-primary)', border: '1px solid var(--border-color)', color: 'var(--text-primary)', fontSize: 16 }}
            />
          </div>

          {error && (
            <div style={{ padding: '12px 14px', borderRadius: 10, background: 'rgba(239,68,68,0.12)', border: '1px solid rgba(239,68,68,0.25)', color: '#F87171', fontSize: 13 }}>
              ⚠️ {error}
            </div>
          )}

          <button type="submit" disabled={loading} style={{ width: '100%', padding: '14px 18px', borderRadius: 12, border: 'none', background: '#3B82F6', color: '#fff', fontWeight: 700, cursor: loading ? 'not-allowed' : 'pointer' }}>
            {loading ? 'Validation...' : 'Définir mon nouveau mot de passe'}
          </button>
        </form>

        <div style={{ marginTop: 22, color: 'var(--text-tertiary)', fontSize: 13, textAlign: 'center' }}>
          Votre nouveau mot de passe doit contenir au moins 8 caractères.
        </div>
      </div>
    </div>
  )
}
