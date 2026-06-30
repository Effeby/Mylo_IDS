import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Key } from 'lucide-react'
import { verifyTotpWithToken, getUser } from '../api/mylo'
import ThemeToggle from '../components/ThemeToggle'

export default function VerifyTOTP() {
  const navigate = useNavigate()
  const [code, setCode] = useState('')
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
    if (!code.trim()) {
      return setError('Veuillez saisir le code à 6 chiffres.')
    }
    if (!tempAuth?.access) {
      return navigate('/')
    }
    setLoading(true)
    try {
      const data = await verifyTotpWithToken(code.trim(), tempAuth.access)
      localStorage.setItem('mylo_access', data.access)
      localStorage.setItem('mylo_refresh', data.refresh)
      localStorage.setItem('mylo_user', JSON.stringify(data.user || tempAuth.user || getUser() || {}))
      sessionStorage.removeItem('mylo_temp_auth')
      navigate('/dashboard')
    } catch (err) {
      setError(err.response?.data?.error || 'Code incorrect ou expiré.')
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
            <Key size={28} color="#fff" />
          </div>
          <h1 style={{ margin: 0, fontSize: 26, fontWeight: 800, color: 'var(--text-primary)' }}>
            Confirmez votre code TOTP
          </h1>
          <p style={{ marginTop: 12, color: 'var(--text-secondary)', fontSize: 14 }}>
            Saisissez le code à 6 chiffres généré par votre application d'authentification.
          </p>
        </div>

        <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          <div>
            <label style={{ display: 'block', marginBottom: 8, fontSize: 12, color: 'var(--text-secondary)', fontWeight: 700 }}>Code à 6 chiffres</label>
            <input
              value={code}
              onChange={e => setCode(e.target.value)}
              placeholder="000000"
              maxLength={6}
              autoComplete="one-time-code"
              style={{ width: '100%', padding: '13px 16px', borderRadius: 12, background: 'var(--bg-primary)', border: '1px solid var(--border-color)', color: 'var(--text-primary)', fontSize: 16, letterSpacing: '0.2em' }}
            />
          </div>

          {error && (
            <div style={{ padding: '12px 14px', borderRadius: 10, background: 'rgba(239,68,68,0.12)', border: '1px solid rgba(239,68,68,0.25)', color: '#F87171', fontSize: 13 }}>
              ⚠️ {error}
            </div>
          )}

          <button type="submit" disabled={loading} style={{ width: '100%', padding: '14px 18px', borderRadius: 12, border: 'none', background: '#3B82F6', color: '#fff', fontWeight: 700, cursor: loading ? 'not-allowed' : 'pointer' }}>
            {loading ? 'Vérification...' : 'Valider et entrer'}
          </button>
        </form>

        <div style={{ marginTop: 22, color: 'var(--text-tertiary)', fontSize: 13, textAlign: 'center' }}>
          Si le code n'est plus valide, patientez quelques secondes puis récupérez un nouveau code dans votre application.
        </div>
      </div>
    </div>
  )
}
