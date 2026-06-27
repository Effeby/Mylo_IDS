import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { Shield, Eye, EyeOff, Building2, User, Mail, Lock, Phone, Globe } from 'lucide-react'

const DJANGO_URL = import.meta.env.VITE_DJANGO_URL || 'https://mylo-ids.site'

const SECTORS = [
  { value: 'banking',    label: 'Banque / Finance' },
  { value: 'health',     label: 'Santé' },
  { value: 'industry',   label: 'Industrie' },
  { value: 'government', label: 'Gouvernement' },
  { value: 'education',  label: 'Éducation' },
  { value: 'telecom',    label: 'Télécommunications' },
  { value: 'retail',     label: 'Commerce / Distribution' },
  { value: 'other',      label: 'Autre' },
]

const S = {
  page:  { minHeight: '100vh', background: '#070B14', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24 },
  card:  { width: '100%', maxWidth: 520, background: '#0F1629', border: '1px solid #1E2D4F', borderRadius: 16, padding: 40 },
  input: { width: '100%', padding: '11px 14px 11px 40px', borderRadius: 8, background: '#0A0E1A', border: '1px solid #1E2D4F', color: '#F8FAFC', fontSize: 14, outline: 'none', boxSizing: 'border-box' },
  label: { fontSize: 12, color: '#94A3B8', fontWeight: 600, marginBottom: 6, display: 'block', letterSpacing: '0.05em' },
  field: { marginBottom: 16, position: 'relative' },
  icon:  { position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: '#475569', pointerEvents: 'none' },
}

function Field({ label, icon: Icon, children }) {
  return (
    <div style={S.field}>
      {label && <label style={S.label}>{label}</label>}
      <div style={{ position: 'relative' }}>
        {Icon && <Icon size={15} style={{ ...S.icon, top: label ? '50%' : '50%' }} />}
        {children}
      </div>
    </div>
  )
}

export default function Register() {
  const navigate = useNavigate()
  const [loading, setLoading] = useState(false)
  const [error,   setError]   = useState('')
  const [showPwd, setShowPwd] = useState(false)

  const [form, setForm] = useState({
    // Compte admin
    first_name: '', last_name: '', username: '',
    email: '', password: '', confirm_password: '',
    // Organisation
    org_name: '', org_email: '', sector: 'other',
  })

  const set = (k, v) => setForm(p => ({...p, [k]: v}))

  const submit = async () => {
    setError('')

    // Validation
    if (!form.first_name || !form.last_name)
      return setError('Le prénom et le nom sont requis')
    if (!form.username)
      return setError('Le nom d\'utilisateur est requis')
    if (!form.email)
      return setError('L\'email est requis')
    if (form.password.length < 8)
      return setError('Le mot de passe doit contenir au moins 8 caractères')
    if (form.password !== form.confirm_password)
      return setError('Les mots de passe ne correspondent pas')
    if (!form.org_name)
      return setError('Le nom de l\'organisation est requis')

    setLoading(true)
    try {
const userEmail = form.email.trim()
        const orgEmail  = form.org_email.trim() || userEmail

        const res = await fetch(`${DJANGO_URL}/api/auth/register/`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            first_name: form.first_name,
            last_name:  form.last_name,
            username:   form.username,
            email:      userEmail,
            password:   form.password,
            org_name:   form.org_name,
            org_email:  orgEmail,
          sector:     form.sector,
        }),
      })

      const data = await res.json()
      if (!res.ok) return setError(data.error || 'Erreur lors de l\'inscription')

      // Stocker le token et le user
      localStorage.setItem('mylo_access',  data.access)
      localStorage.setItem('mylo_refresh', data.refresh)
      localStorage.setItem('mylo_user',    JSON.stringify(data.user))

      // Rediriger vers le wizard (is_setup_done = false)
      navigate('/onboarding')

    } catch(e) {
      setError('Impossible de contacter le serveur')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={S.page}>
      <div style={S.card}>

        {/* Header */}
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <div style={{
            width: 56, height: 56, borderRadius: 14,
            background: 'linear-gradient(135deg, #3B82F6, #1E40AF)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            margin: '0 auto 16px',
          }}>
            <Shield size={28} color="#fff" />
          </div>
          <h1 style={{ margin: '0 0 6px', fontSize: 24, fontWeight: 800 }}>
            Créer votre espace Mylo IPS
          </h1>
          <p style={{ margin: 0, color: '#64748B', fontSize: 14 }}>
            Configurez votre système de prévention d'intrusions
          </p>
        </div>

        {/* Section Compte */}
        <div style={{ fontSize: 11, color: '#3B82F6', fontWeight: 700, letterSpacing: '0.08em', marginBottom: 14 }}>
          VOTRE COMPTE ADMINISTRATEUR
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <Field label="PRÉNOM" icon={User}>
            <input style={S.input} placeholder="Jean"
              value={form.first_name} onChange={e => set('first_name', e.target.value)} />
          </Field>
          <Field label="NOM" icon={User}>
            <input style={S.input} placeholder="Dupont"
              value={form.last_name} onChange={e => set('last_name', e.target.value)} />
          </Field>
        </div>

        <Field label="NOM D'UTILISATEUR" icon={User}>
          <input style={S.input} placeholder="jean.dupont"
            value={form.username} onChange={e => set('username', e.target.value)} />
        </Field>

        <Field label="EMAIL" icon={Mail}>
          <input style={S.input} type="email" placeholder="jean@entreprise.com"
            value={form.email} onChange={e => set('email', e.target.value)} />
        </Field>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <Field label="MOT DE PASSE" icon={Lock}>
            <input style={S.input} type={showPwd ? 'text' : 'password'} placeholder="Min. 8 caractères"
              value={form.password} onChange={e => set('password', e.target.value)} />
          </Field>
          <Field label="CONFIRMER" icon={Lock}>
            <input style={S.input} type={showPwd ? 'text' : 'password'} placeholder="Répéter"
              value={form.confirm_password} onChange={e => set('confirm_password', e.target.value)} />
          </Field>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 20, cursor: 'pointer' }}
          onClick={() => setShowPwd(p => !p)}>
          {showPwd ? <EyeOff size={14} color="#475569" /> : <Eye size={14} color="#475569" />}
          <span style={{ fontSize: 12, color: '#475569' }}>
            {showPwd ? 'Masquer' : 'Afficher'} le mot de passe
          </span>
        </div>

        {/* Divider */}
        <div style={{ borderTop: '1px solid #1E2D4F', margin: '4px 0 20px' }} />

        {/* Section Organisation */}
        <div style={{ fontSize: 11, color: '#22C55E', fontWeight: 700, letterSpacing: '0.08em', marginBottom: 14 }}>
          VOTRE ORGANISATION
        </div>

        <Field label="NOM DE L'ORGANISATION *" icon={Building2}>
          <input style={S.input} placeholder="Ex: Acme Corp, SecureBank CI..."
            value={form.org_name} onChange={e => set('org_name', e.target.value)} />
        </Field>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <Field label="EMAIL ORGANISATION" icon={Mail}>
            <input style={S.input} type="email" placeholder="contact@entreprise.com"
              value={form.org_email} onChange={e => set('org_email', e.target.value)} />
          </Field>
          <Field label="SECTEUR">
            <select style={{ ...S.input, paddingLeft: 14 }} value={form.sector} onChange={e => set('sector', e.target.value)}>
              {SECTORS.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
            </select>
          </Field>
        </div>

        {/* Erreur */}
        {error && (
          <div style={{ padding: '10px 14px', borderRadius: 8, background: 'rgba(239,68,68,0.1)', border: '1px solid #EF444440', color: '#EF4444', fontSize: 13, marginBottom: 16 }}>
            ⚠️ {error}
          </div>
        )}

        {/* Bouton */}
        <button onClick={submit} disabled={loading} style={{
          width: '100%', padding: '13px', borderRadius: 8, border: 'none',
          background: loading ? '#1E3A6E' : 'linear-gradient(135deg, #3B82F6, #1E40AF)',
          color: '#fff', fontWeight: 700, fontSize: 15,
          cursor: loading ? 'not-allowed' : 'pointer',
          marginBottom: 16,
        }}>
          {loading ? 'Création en cours...' : 'Créer mon espace Mylo IPS →'}
        </button>

        {/* Lien login */}
        <div style={{ textAlign: 'center', fontSize: 13, color: '#475569' }}>
          Vous avez déjà un compte ?{' '}
          <Link to="/" style={{ color: '#3B82F6', textDecoration: 'none', fontWeight: 600 }}>
            Se connecter
          </Link>
        </div>

      </div>
    </div>
  )
}