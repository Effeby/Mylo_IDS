import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, QrCode, CheckCircle } from 'lucide-react'
import { getTotpSetup, activateTotp, getUser } from '../api/mylo'
import ThemeToggle from '../components/ThemeToggle'

export default function SetupTOTP() {
  const navigate = useNavigate()
  const [qrCode, setQrCode] = useState('')
  const [secret, setSecret] = useState('')
  const [code, setCode] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [loadingSetup, setLoadingSetup] = useState(true)
  const [totpEnabled, setTotpEnabled] = useState(false)

  useEffect(() => {
    const fetchSetup = async () => {
      try {
        const data = await getTotpSetup()
        setQrCode(data.qr_code)
        setSecret(data.secret)
        setTotpEnabled(data.totp_enabled === true)
      } catch (err) {
        setError('Impossible de charger le QR code. Réessayez plus tard.')
      } finally {
        setLoadingSetup(false)
      }
    }
    fetchSetup()
  }, [])

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    if (!code.trim()) {
      return setError('Veuillez saisir le code à 6 chiffres.')
    }
    setLoading(true)
    try {
      await activateTotp(code.trim())
      const user = getUser() || {}
      user.totp_enabled = true
      localStorage.setItem('mylo_user', JSON.stringify(user))
      navigate('/dashboard')
    } catch (err) {
      setError(err.response?.data?.error || 'Code invalide, réessayez.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24, position: 'relative' }}>
      <ThemeToggle style={{ position: 'absolute', top: 20, right: 20 }} />
      <div style={{ width: '100%', maxWidth: 520, padding: 'clamp(18px, 6vw, 32px)', borderRadius: 20, background: 'var(--bg-card)', border: '1px solid var(--border-color)', boxSizing: 'border-box' }}>
        <div style={{ textAlign: 'center', marginBottom: 28 }}>
          <div style={{ width: 64, height: 64, margin: '0 auto 16px', borderRadius: 18, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'linear-gradient(135deg, #3B82F6, #1E40AF)' }}>
            <Shield size={28} color="#fff" />
          </div>
          <h1 style={{ margin: 0, fontSize: 26, fontWeight: 800, color: 'var(--text-primary)' }}>
            Configurez votre authentificateur
          </h1>
          <p style={{ margin: '12px auto 0', color: 'var(--text-secondary)', maxWidth: 420, fontSize: 14 }}>
            Scannez ce QR code avec Google Authenticator ou Authy puis confirmez avec le code à 6 chiffres.
          </p>
        </div>

        {loadingSetup ? (
          <div style={{ color: 'var(--text-secondary)', textAlign: 'center' }}>Chargement du QR code...</div>
        ) : totpEnabled ? (
          <div style={{ textAlign: 'center', color: 'var(--text-primary)' }}>
            <CheckCircle size={48} color="#22C55E" />
            <p style={{ marginTop: 16, fontSize: 15 }}>L'authentification à deux facteurs est déjà activée.</p>
            <button onClick={() => navigate('/dashboard')} style={{ marginTop: 20, padding: '12px 24px', borderRadius: 10, border: 'none', background: '#3B82F6', color: '#fff', cursor: 'pointer', fontWeight: 700 }}>Retour au dashboard</button>
          </div>
        ) : (
          <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
            <div style={{ textAlign: 'center' }}>
              <div style={{ display: 'inline-block', padding: 18, borderRadius: 24, background: 'var(--bg-primary)', border: '1px solid var(--border-color)' }}>
                {qrCode ? (
                  <img src={qrCode} alt="QR Code TOTP" style={{ width: 240, maxWidth: '100%', height: 'auto', display: 'block' }} />
                ) : (
                  <div style={{ width: 240, maxWidth: '100%', height: 240, display: 'grid', placeItems: 'center', color: 'var(--text-tertiary)', background: 'var(--bg-elevated)', borderRadius: 16 }}>QR code indisponible</div>
                )}
              </div>
            </div>

            <div style={{ padding: 18, borderRadius: 14, border: '1px solid var(--border-color)', background: 'var(--bg-elevated)' }}>
              <div style={{ color: 'var(--text-secondary)', fontSize: 12, textTransform: 'uppercase', fontWeight: 700, marginBottom: 10 }}>Secret TOTP</div>
              <div style={{ color: 'var(--text-primary)', fontFamily: 'monospace', wordBreak: 'break-all' }}>{secret}</div>
              <div style={{ marginTop: 10, color: 'var(--text-tertiary)', fontSize: 12 }}>
                Si le QR code ne s'affiche pas, copiez ce secret manuellement dans votre application d'authentification.
              </div>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: 12, color: 'var(--text-secondary)', fontWeight: 700, marginBottom: 8 }}>Code à 6 chiffres</label>
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
              {loading ? 'Validation...' : 'Confirmer et accéder'}
            </button>
          </form>
        )}
      </div>
    </div>
  )
}
