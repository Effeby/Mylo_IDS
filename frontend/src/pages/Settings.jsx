import { useState, useEffect } from 'react'
import { Save, RefreshCw, Shield, Zap, Brain, Bell, AlertTriangle, Building2, Users, Plus, Trash2, Edit2, X, Check, Lock, Unlock } from 'lucide-react'

const DJANGO_URL = import.meta.env.VITE_DJANGO_URL || 'http://localhost:8001'

const ATTACK_COLORS = {
  DoS: '#EF4444', DDoS: '#DC2626', Probe: '#EAB308', R2L: '#F97316',
  U2R: '#A855F7', BruteForce: '#EC4899', WebAttack: '#14B8A6',
  Botnet: '#F43F5E', Infiltration: '#8B5CF6',
}

const SECTORS = [
  { value: 'banking', label: 'Banque / Finance' },
  { value: 'health', label: 'Santé' },
  { value: 'industry', label: 'Industrie' },
  { value: 'government', label: 'Gouvernement' },
  { value: 'education', label: 'Éducation' },
  { value: 'telecom', label: 'Télécommunications' },
  { value: 'retail', label: 'Commerce / Distribution' },
  { value: 'other', label: 'Autre' },
]

const ROLES = [
  { value: 'org_admin',   label: 'Administrateur',  level: 4 },
  { value: 'soc_manager', label: 'Manager SOC',     level: 3 },
  { value: 'soc_analyst', label: 'Analyste SOC',    level: 2 },
  { value: 'viewer',      label: 'Observateur',     level: 1 },
]

const ROLE_COLORS = {
  org_admin:   '#EF4444',
  soc_manager: '#F97316',
  soc_analyst: '#3B82F6',
  viewer:      '#64748B',
}

async function apiFetch(path, options = {}) {
  const token = localStorage.getItem('mylo_access')
  const res = await fetch(`${DJANGO_URL}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    ...options,
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}

// ─── Composants UI ────────────────────────────────────────────────────────────
function Section({ icon: Icon, title, color = '#3B82F6', children }) {
  return (
    <div style={{ background: '#0F1629', border: '1px solid #1E2D4F', borderRadius: 12, padding: 24, marginBottom: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20 }}>
        <div style={{ width: 34, height: 34, borderRadius: 8, background: `${color}20`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Icon size={16} color={color} />
        </div>
        <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: '#F8FAFC' }}>{title}</h3>
      </div>
      {children}
    </div>
  )
}

function Toggle({ label, desc, value, onChange }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 0', borderBottom: '1px solid #0A0E1A' }}>
      <div>
        <div style={{ fontSize: 13, color: '#F8FAFC', fontWeight: 500 }}>{label}</div>
        {desc && <div style={{ fontSize: 11, color: '#475569', marginTop: 2 }}>{desc}</div>}
      </div>
      <button onClick={() => onChange(!value)} style={{
        width: 44, height: 24, borderRadius: 12, border: 'none',
        background: value ? '#3B82F6' : '#1E2D4F',
        cursor: 'pointer', position: 'relative', transition: 'background 0.2s', flexShrink: 0,
      }}>
        <div style={{ width: 18, height: 18, borderRadius: '50%', background: '#fff', position: 'absolute', top: 3, left: value ? 23 : 3, transition: 'left 0.2s' }} />
      </button>
    </div>
  )
}

function Slider({ label, desc, value, min, max, step = 0.01, onChange, color = '#3B82F6', format }) {
  const pct = ((value - min) / (max - min)) * 100
  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
        <div>
          <span style={{ fontSize: 13, color: '#F8FAFC', fontWeight: 500 }}>{label}</span>
          {desc && <span style={{ fontSize: 11, color: '#475569', marginLeft: 8 }}>{desc}</span>}
        </div>
        <span style={{ fontSize: 13, fontWeight: 700, color, fontFamily: 'monospace', background: `${color}15`, padding: '2px 8px', borderRadius: 6 }}>
          {format ? format(value) : value}
        </span>
      </div>
      <div style={{ position: 'relative', height: 6, background: '#1E2D4F', borderRadius: 3 }}>
        <div style={{ position: 'absolute', left: 0, top: 0, height: '100%', width: `${pct}%`, background: color, borderRadius: 3 }} />
        <input type="range" min={min} max={max} step={step} value={value}
          onChange={e => onChange(parseFloat(e.target.value))}
          style={{ position: 'absolute', inset: 0, opacity: 0, width: '100%', cursor: 'pointer', margin: 0 }} />
      </div>
    </div>
  )
}

function Input({ label, desc, value, onChange, type = 'text', placeholder }) {
  return (
    <div style={{ marginBottom: 14 }}>
      <label style={{ fontSize: 12, color: '#64748B', fontWeight: 600, display: 'block', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.04em' }}>{label}</label>
      {desc && <div style={{ fontSize: 11, color: '#475569', marginBottom: 6 }}>{desc}</div>}
      <input type={type} value={value} placeholder={placeholder} onChange={e => onChange(e.target.value)}
        style={{ width: '100%', padding: '9px 12px', borderRadius: 8, fontSize: 13, background: '#0A0E1A', border: '1px solid #1E2D4F', color: '#F8FAFC', outline: 'none', boxSizing: 'border-box' }} />
    </div>
  )
}

// ─── Modal ajout membre ───────────────────────────────────────────────────────
function AddMemberModal({ onClose, onAdd }) {
  const [form, setForm] = useState({ username: '', first_name: '', last_name: '', email: '', role: 'soc_analyst', poste: '', password: '' })
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)
  const set = (k, v) => setForm(p => ({...p, [k]: v}))

  const submit = async () => {
    if (!form.username || !form.password) return setError('Username et mot de passe requis')
    setSaving(true)
    try {
      const data = await apiFetch('/api/auth/users/', { method: 'POST', body: JSON.stringify({
        ...form,
        habilitation_level: ROLES.find(r => r.value === form.role)?.level || 2,
      })})
      onAdd(data)
      onClose()
    } catch(e) {
      setError('Erreur lors de la création')
    } finally { setSaving(false) }
  }

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', zIndex: 2000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ background: '#0F1629', border: '1px solid #1E2D4F', borderRadius: 16, padding: 32, width: 500, maxHeight: '90vh', overflowY: 'auto' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
          <h3 style={{ margin: 0, fontSize: 16, fontWeight: 700 }}>Ajouter un membre</h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#94A3B8', cursor: 'pointer' }}><X size={18} /></button>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <Input label="Prénom" value={form.first_name} onChange={v => set('first_name', v)} placeholder="Jean" />
          <Input label="Nom" value={form.last_name} onChange={v => set('last_name', v)} placeholder="Dupont" />
        </div>
        <Input label="Nom d'utilisateur *" value={form.username} onChange={v => set('username', v)} placeholder="jean.dupont" />
        <Input label="Email" type="email" value={form.email} onChange={v => set('email', v)} placeholder="jean@entreprise.com" />
        <Input label="Poste" value={form.poste} onChange={v => set('poste', v)} placeholder="Analyste SOC Senior" />
        <div style={{ marginBottom: 14 }}>
          <label style={{ fontSize: 12, color: '#64748B', fontWeight: 600, display: 'block', marginBottom: 6, textTransform: 'uppercase' }}>RÔLE</label>
          <select value={form.role} onChange={e => set('role', e.target.value)}
            style={{ width: '100%', padding: '9px 12px', borderRadius: 8, fontSize: 13, background: '#0A0E1A', border: '1px solid #1E2D4F', color: '#F8FAFC', outline: 'none' }}>
            {ROLES.map(r => <option key={r.value} value={r.value}>{r.label} — Niveau {r.level}</option>)}
          </select>
        </div>
        <Input label="Mot de passe provisoire *" type="password" value={form.password} onChange={v => set('password', v)} placeholder="Min. 8 caractères" />
        {error && <div style={{ color: '#EF4444', fontSize: 12, marginBottom: 12 }}>⚠️ {error}</div>}
        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
          <button onClick={onClose} style={{ padding: '9px 18px', borderRadius: 8, border: '1px solid #1E2D4F', background: 'transparent', color: '#94A3B8', cursor: 'pointer' }}>Annuler</button>
          <button onClick={submit} disabled={saving} style={{ padding: '9px 18px', borderRadius: 8, border: 'none', background: '#3B82F6', color: '#fff', cursor: 'pointer', fontWeight: 700 }}>
            {saving ? 'Création...' : 'Créer le membre'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Modal édition membre ────────────────────────────────────────────────────
function EditMemberModal({ member, onClose, onSave }) {
  const [form, setForm] = useState({
    first_name: member.fullname?.split(' ')[0] || '',
    last_name:  member.fullname?.split(' ').slice(1).join(' ') || '',
    email:      member.email || '',
    role:       member.role || 'soc_analyst',
    poste:      member.poste || '',
    is_active:  member.is_active !== false,
  })
  const [error,  setError]  = useState('')
  const [saving, setSaving] = useState(false)
  const set = (k, v) => setForm(p => ({...p, [k]: v}))

  const submit = async () => {
    setSaving(true)
    try {
      const data = await apiFetch(`/api/auth/users/${member.id}/`, {
        method: 'PATCH',
        body: JSON.stringify({
          ...form,
          habilitation_level: ROLES.find(r => r.value === form.role)?.level || 2,
        }),
      })
      onSave(data)
      onClose()
    } catch(e) { setError('Erreur lors de la modification') }
    finally { setSaving(false) }
  }

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', zIndex: 2000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ background: '#0F1629', border: '1px solid #1E2D4F', borderRadius: 16, padding: 32, width: 480 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
          <h3 style={{ margin: 0, fontSize: 16, fontWeight: 700 }}>Modifier {member.fullname || member.username}</h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#94A3B8', cursor: 'pointer' }}><X size={18} /></button>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <Input label="Prénom"     value={form.first_name} onChange={v => set('first_name', v)} />
          <Input label="Nom"        value={form.last_name}  onChange={v => set('last_name', v)} />
        </div>
        <Input label="Email" type="email" value={form.email} onChange={v => set('email', v)} />
        <Input label="Poste" value={form.poste} onChange={v => set('poste', v)} placeholder="Ex: Analyste SOC Senior" />
        <div style={{ marginBottom: 14 }}>
          <label style={{ fontSize: 12, color: '#64748B', fontWeight: 600, display: 'block', marginBottom: 6, textTransform: 'uppercase' }}>RÔLE</label>
          <select value={form.role} onChange={e => set('role', e.target.value)}
            style={{ width: '100%', padding: '9px 12px', borderRadius: 8, fontSize: 13, background: '#0A0E1A', border: '1px solid #1E2D4F', color: '#F8FAFC', outline: 'none' }}>
            {ROLES.map(r => <option key={r.value} value={r.value}>{r.label} — Niveau {r.level}</option>)}
          </select>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 0', marginBottom: 16 }}>
          <span style={{ fontSize: 13, color: '#F8FAFC' }}>Compte actif</span>
          <button onClick={() => set('is_active', !form.is_active)} style={{
            width: 44, height: 24, borderRadius: 12, border: 'none',
            background: form.is_active ? '#3B82F6' : '#1E2D4F', cursor: 'pointer', position: 'relative',
          }}>
            <div style={{ width: 18, height: 18, borderRadius: '50%', background: '#fff', position: 'absolute', top: 3, left: form.is_active ? 23 : 3, transition: 'left 0.2s' }} />
          </button>
        </div>
        {error && <div style={{ color: '#EF4444', fontSize: 12, marginBottom: 12 }}>⚠️ {error}</div>}
        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
          <button onClick={onClose} style={{ padding: '9px 18px', borderRadius: 8, border: '1px solid #1E2D4F', background: 'transparent', color: '#94A3B8', cursor: 'pointer' }}>Annuler</button>
          <button onClick={submit} disabled={saving} style={{ padding: '9px 18px', borderRadius: 8, border: 'none', background: '#3B82F6', color: '#fff', cursor: 'pointer', fontWeight: 700 }}>
            {saving ? 'Sauvegarde...' : 'Enregistrer'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Page principale ──────────────────────────────────────────────────────────
export default function Settings() {
  const [cfg,     setCfg]     = useState(null)
  const [org,     setOrg]     = useState(null)
  const [members, setMembers] = useState([])
  const [assets,  setAssets]  = useState([])
  const [assetsExpanded, setAssetsExpanded] = useState(true)
  const [editingAssetId, setEditingAssetId] = useState(null)
  const [editingAssetName, setEditingAssetName] = useState('')
  const [loading, setLoading] = useState(true)
  const [saving,  setSaving]  = useState(false)
  const [saved,   setSaved]   = useState(false)
  const [error,   setError]   = useState(null)
  const [discovering, setDiscovering] = useState(false)
  const [arpTarget, setArpTarget] = useState('')
  const [showAddMember,    setShowAddMember]    = useState(false)
  const [editMember,      setEditMember]      = useState(null)
  const [toast,        setToast]        = useState(null)
  const [wazuhStatus,  setWazuhStatus]  = useState({ checking: true, connected: false, message: 'Chargement...' })

  const showToast = (msg, type = 'success') => {
    setToast({ msg, type })
    setTimeout(() => setToast(null), 3000)
  }

  const loadWazuhStatus = async () => {
    setWazuhStatus({ checking: true, connected: false, message: 'Vérification en cours...' })
    try {
      const status = await apiFetch('/api/alerts/wazuh-status/')
      setWazuhStatus({
        checking: false,
        connected: status.connected === true,
        message: status.message || 'Connexion Wazuh OK',
        wazuh_url: status.wazuh_url,
        alert_count: status.alert_count,
        last_check_at: status.last_check_at,
      })
    } catch (e) {
      setWazuhStatus({
        checking: false,
        connected: false,
        message: 'Impossible de contacter Wazuh',
        wazuh_url: null,
        alert_count: 0,
        last_check_at: null,
      })
    }
  }

  // Récupérer le user depuis localStorage pour les permissions
  const currentUser = (() => { try { return JSON.parse(localStorage.getItem('mylo_user') || '{}') } catch { return {} } })()
  const canManageUsers = currentUser?.permissions?.can_manage_users
  const canConfigureIDS = currentUser?.permissions?.can_configure_ids

  const load = async () => {
    setLoading(true)
    setError(null)
    try {
      const [cfgData, orgData, membersData, assetsData] = await Promise.all([
        apiFetch('/api/alerts/settings/'),
        apiFetch('/api/auth/organisation/'),
        canManageUsers ? apiFetch('/api/auth/users/') : Promise.resolve([]),
        (canManageUsers || canConfigureIDS) ? apiFetch('/api/alerts/assets/') : Promise.resolve([]),
      ])
      setCfg(cfgData)
      setOrg(orgData)
      setMembers(membersData)
      setAssets(assetsData)
    } catch(e) {
      setError('Impossible de charger les paramètres')
    } finally {
      setLoading(false)
    }
    loadWazuhStatus()
  }

  useEffect(() => { load() }, [])

  const set    = (key, val) => setCfg(prev => ({ ...prev, [key]: val }))
  const setOrgField = (key, val) => setOrg(prev => ({ ...prev, [key]: val }))
  const setThreshold = (cls, val) => setCfg(prev => ({ ...prev, thresholds: { ...prev.thresholds, [cls]: val } }))

  const updateAsset = async (assetId, data) => {
    try {
      await apiFetch(`/api/alerts/assets/${assetId}/`, { method: 'PATCH', body: JSON.stringify(data) })
      setAssets(prev => prev.map(a => a.id === assetId ? { ...a, ...data } : a))
      showToast('Actif mis à jour')
    } catch {
      showToast('Erreur lors de la mise à jour de l’actif', 'error')
    }
  }

  const saveAssetName = async (assetId) => {
    if (!editingAssetName.trim()) {
      setEditingAssetId(null)
      return
    }
    await updateAsset(assetId, { name: editingAssetName.trim() })
    setEditingAssetId(null)
  }

  const discoverAssets = async () => {
    setDiscovering(true)
    try {
      const body = arpTarget ? { target_ip: arpTarget } : {}
      const data = await apiFetch('/api/alerts/assets/discover/', { method: 'POST', body: JSON.stringify(body) })
      setAssets(data)
      showToast('Découverte des actifs terminée')
    } catch {
      showToast('Erreur lors de la découverte des actifs', 'error')
    } finally {
      setDiscovering(false)
    }
  }

  const save = async () => {
    setSaving(true)
    setError(null)
    try {
      await Promise.all([
        apiFetch('/api/alerts/settings/', { method: 'PUT', body: JSON.stringify(cfg) }),
        canManageUsers ? apiFetch('/api/auth/organisation/', { method: 'PUT', body: JSON.stringify(org) }) : Promise.resolve(),
      ])
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch {
      setError('Erreur lors de la sauvegarde')
    } finally {
      setSaving(false)
    }
  }

  const deleteMember = async (userId) => {
    if (!window.confirm('Supprimer cet utilisateur ?')) return
    try {
      await apiFetch(`/api/auth/users/${userId}/`, { method: 'DELETE' })
      setMembers(p => p.filter(m => m.id !== userId))
    } catch { setError('Erreur lors de la suppression') }
  }

  const toggleMemberLock = async (member) => {
    const newLocked = !member.is_locked
    setMembers(p => p.map(m => m.id === member.id ? {...m, is_locked: newLocked} : m))
    try {
      const updated = await apiFetch(`/api/auth/users/${member.id}/`, {
        method: 'PATCH',
        body: JSON.stringify({ is_locked: newLocked }),
      })
      setMembers(p => p.map(m => m.id === updated.id ? updated : m))
      showToast(newLocked
        ? `${member.fullname || member.username} verrouillé — ne peut plus se connecter`
        : `${member.fullname || member.username} déverrouillé — peut se connecter`)
    } catch {
      setMembers(p => p.map(m => m.id === member.id ? {...m, is_locked: member.is_locked} : m))
      showToast('Erreur lors du verrouillage', 'error')
    }
  }

  const resetMemberTotp = async (member) => {
    if (!window.confirm(`Réinitialiser TOTP pour ${member.fullname || member.username} ?`)) return
    try {
      await apiFetch(`/api/auth/totp/reset/${member.id}/`, { method: 'POST' })
      setMembers(p => p.map(m => m.id === member.id ? { ...m, totp_enabled: false } : m))
      showToast(`TOTP réinitialisé pour ${member.fullname || member.username}`)
    } catch {
      showToast('Erreur lors de la réinitialisation TOTP', 'error')
    }
  }

  if (loading) return <div style={{ padding: 32, color: '#94A3B8' }}>Chargement...</div>
  if (error && !cfg) return <div style={{ padding: 32, color: '#EF4444' }}>{error}</div>

  return (
    <div style={{ padding: 32, color: '#F8FAFC', maxWidth: 860 }}>

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 28 }}>
        <div>
          <h1 style={{ margin: '0 0 6px', fontSize: 22, fontWeight: 800 }}>Paramètres</h1>
          <p style={{ margin: 0, color: '#94A3B8', fontSize: 13 }}>
            Configuration de Mylo IPS
            {cfg?.updated_at && <span style={{ marginLeft: 12, color: '#334155' }}>· Mis à jour {new Date(cfg.updated_at).toLocaleString('fr-FR')}{cfg.updated_by && ` par ${cfg.updated_by}`}</span>}
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button onClick={load} style={{ padding: '9px 16px', borderRadius: 8, border: '1px solid #1E2D4F', background: 'transparent', color: '#94A3B8', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
            <RefreshCw size={14} /> Réinitialiser
          </button>
          <button onClick={save} disabled={saving} style={{ padding: '9px 20px', borderRadius: 8, border: 'none', background: saved ? '#22C55E' : saving ? '#1E3A6E' : '#3B82F6', color: '#fff', cursor: saving ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', gap: 6, fontSize: 13, fontWeight: 700 }}>
            <Save size={14} />{saved ? '✓ Sauvegardé !' : saving ? 'Sauvegarde...' : 'Sauvegarder'}
          </button>
        </div>
      </div>

      {error && <div style={{ padding: '10px 16px', borderRadius: 8, marginBottom: 16, background: 'rgba(239,68,68,0.1)', border: '1px solid #EF4444', color: '#EF4444', fontSize: 13 }}>⚠️ {error}</div>}

      <Section icon={Shield} title="Wazuh" color="#8B5CF6">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 16, alignItems: 'center' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <span style={{ width: 10, height: 10, borderRadius: '50%', background: wazuhStatus.connected ? '#22C55E' : '#F97316' }} />
              <span style={{ fontSize: 13, fontWeight: 700, color: '#F8FAFC' }}>
                {wazuhStatus.connected ? 'Connecté à Wazuh' : 'Wazuh non connecté'}
              </span>
            </div>
            <div style={{ fontSize: 12, color: '#94A3B8', marginBottom: 6 }}>
              {wazuhStatus.message}
            </div>
            {wazuhStatus.wazuh_url && (
              <div style={{ fontSize: 12, color: '#94A3B8' }}>Manager : {wazuhStatus.wazuh_url}</div>
            )}
            <div style={{ fontSize: 12, color: '#94A3B8', marginTop: 6 }}>
              Alerte(s) récupérées : {wazuhStatus.alert_count ?? '—'}
            </div>
            {wazuhStatus.last_check_at && (
              <div style={{ fontSize: 12, color: '#94A3B8', marginTop: 4 }}>
                Vérifié le {new Date(wazuhStatus.last_check_at).toLocaleString('fr-FR')}
              </div>
            )}
          </div>
          <button onClick={loadWazuhStatus} disabled={wazuhStatus.checking}
            style={{ padding: '10px 16px', borderRadius: 8, border: '1px solid #1E2D4F', background: wazuhStatus.checking ? '#1E2D4F' : '#3B82F6', color: '#fff', cursor: wazuhStatus.checking ? 'not-allowed' : 'pointer', minWidth: 160 }}>
            {wazuhStatus.checking ? 'Vérification...' : 'Vérifier Wazuh'}
          </button>
        </div>
      </Section>

      {/* ── Organisation ── */}
      {org && canManageUsers && (
        <Section icon={Building2} title="Organisation" color="#22C55E">
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <Input label="Nom de l'organisation" value={org.name || ''} onChange={v => setOrgField('name', v)} placeholder="Acme Corp" />
            <Input label="Email de contact" type="email" value={org.email || ''} onChange={v => setOrgField('email', v)} placeholder="soc@entreprise.com" />
            <Input label="Téléphone" value={org.phone || ''} onChange={v => setOrgField('phone', v)} placeholder="+225 00 00 00 00" />
            <Input label="Site web" value={org.website || ''} onChange={v => setOrgField('website', v)} placeholder="https://entreprise.com" />
          </div>
          <div style={{ marginBottom: 14 }}>
            <label style={{ fontSize: 12, color: '#64748B', fontWeight: 600, display: 'block', marginBottom: 6, textTransform: 'uppercase' }}>SECTEUR D'ACTIVITÉ</label>
            <select value={org.sector || 'other'} onChange={e => setOrgField('sector', e.target.value)}
              style={{ width: '100%', padding: '9px 12px', borderRadius: 8, fontSize: 13, background: '#0A0E1A', border: '1px solid #1E2D4F', color: '#F8FAFC', outline: 'none' }}>
              {SECTORS.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
            </select>
          </div>
          {/* Infos lecture seule */}
          <div style={{ display: 'flex', gap: 16, padding: '10px 0', borderTop: '1px solid #1E2D4F', marginTop: 8 }}>
            {[
              { label: 'Plan', value: org.plan?.toUpperCase() },
              { label: 'Membres', value: org.members_count },
              { label: 'Créé le', value: org.created_at ? new Date(org.created_at).toLocaleDateString('fr-FR') : '—' },
            ].map(({ label, value }) => (
              <div key={label}>
                <div style={{ fontSize: 11, color: '#475569' }}>{label}</div>
                <div style={{ fontSize: 13, fontWeight: 700, color: '#94A3B8' }}>{value}</div>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* ── Équipe SOC ── */}
      {canManageUsers && (
        <Section icon={Users} title="Équipe SOC" color="#A855F7">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 16 }}>
            {members.map(m => (
              <div key={m.id} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '12px 16px', borderRadius: 10, background: '#0A0E1A', border: '1px solid #1E2D4F' }}>
                {/* Avatar initiales */}
                <div style={{ width: 36, height: 36, borderRadius: '50%', background: `${ROLE_COLORS[m.role] || '#3B82F6'}20`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: 13, color: ROLE_COLORS[m.role] || '#3B82F6', flexShrink: 0 }}>
                  {(m.fullname || m.username)[0].toUpperCase()}
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 600, fontSize: 13, color: '#F8FAFC' }}>{m.fullname || m.username}</div>
                  <div style={{ fontSize: 11, color: '#475569' }}>{m.poste || m.email || '—'}</div>
                </div>
                {/* Badge rôle */}
                <span style={{ fontSize: 11, fontWeight: 700, padding: '3px 10px', borderRadius: 20, background: `${ROLE_COLORS[m.role]}20`, color: ROLE_COLORS[m.role] || '#94A3B8', whiteSpace: 'nowrap' }}>
                  {m.role_display || m.role} · N{m.habilitation_level}
                </span>
                {/* Badge statut */}
                {m.is_locked && (
                  <span style={{ fontSize: 11, padding: '3px 8px', borderRadius: 20, background: 'rgba(239,68,68,0.1)', color: '#EF4444', display: 'flex', alignItems: 'center', gap: 4 }}>
                    <Lock size={10} /> Verrouillé
                  </span>
                )}
                {/* Actions */}
                <div style={{ display: 'flex', gap: 6 }}>
                  <button onClick={() => setEditMember(m)} title="Modifier"
                    style={{ background: 'none', border: '1px solid #1E2D4F', color: '#3B82F6', cursor: 'pointer', padding: '4px 8px', borderRadius: 6 }}>
                    <Edit2 size={13} />
                  </button>
                  <button onClick={() => toggleMemberLock(m)}
                    title={m.is_locked ? 'Cliquer pour déverrouiller' : 'Cliquer pour verrouiller'}
                    style={{
                      background: m.is_locked ? 'rgba(239,68,68,0.1)' : 'none',
                      border: `1px solid ${m.is_locked ? '#EF4444' : '#1E2D4F'}`,
                      color: m.is_locked ? '#EF4444' : '#64748B',
                      cursor: 'pointer', padding: '4px 8px', borderRadius: 6,
                      display: 'flex', alignItems: 'center', transition: 'all 0.2s',
                    }}>
                    {m.is_locked ? <Lock size={13} /> : <Unlock size={13} />}
                  </button>
                  {canConfigureIDS && (
                    <button onClick={() => resetMemberTotp(m)} title="Réinitialiser TOTP"
                      style={{ background: 'none', border: '1px solid #1E2D4F', color: '#64748B', cursor: 'pointer', padding: '4px 8px', borderRadius: 6 }}>
                      <RefreshCw size={13} />
                    </button>
                  )}
                  {m.id !== currentUser.id && (
                    <button onClick={() => deleteMember(m.id)} title="Supprimer"
                      style={{ background: 'none', border: '1px solid #1E2D4F', color: '#EF4444', cursor: 'pointer', padding: '4px 8px', borderRadius: 6 }}>
                      <Trash2 size={13} />
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
          <button onClick={() => setShowAddMember(true)} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 16px', borderRadius: 8, border: '1px dashed #1E2D4F', background: 'transparent', color: '#64748B', cursor: 'pointer', fontSize: 13, width: '100%', justifyContent: 'center' }}>
            <Plus size={16} /> Ajouter un membre
          </button>
        </Section>
      )}

      {/* ── Détection ── */}
      {canConfigureIDS && cfg && (
        <Section icon={Shield} title="Détection" color="#3B82F6">
          <Slider label="Seuil binaire (Normal / Attaque)" desc="Probabilité minimale pour déclarer une attaque"
            value={cfg.binary_threshold} min={0.1} max={0.9} step={0.01}
            onChange={v => set('binary_threshold', v)} format={v => `${(v * 100).toFixed(0)}%`} color="#3B82F6" />
          <Slider label="Confiance alerte 'Nouvelle'" desc="En dessous → statut 'À vérifier'"
            value={cfg.confidence_alert} min={0.1} max={0.99} step={0.01}
            onChange={v => set('confidence_alert', v)} format={v => `${(v * 100).toFixed(0)}%`} color="#EAB308" />
        </Section>
      )}

      {/* ── Thresholds ── */}
      {canConfigureIDS && cfg && (
        <Section icon={Zap} title="Seuils par classe d'attaque" color="#A855F7">
          <p style={{ fontSize: 12, color: '#475569', marginTop: 0, marginBottom: 16 }}>
            Plus le seuil est bas, plus Mylo est sensible pour cette classe.
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 32px' }}>
            {Object.entries(cfg.thresholds || {}).map(([cls, val]) => (
              <Slider key={cls} label={cls} value={val} min={0.05} max={0.95} step={0.01}
                onChange={v => setThreshold(cls, v)} format={v => `${(v * 100).toFixed(0)}%`}
                color={ATTACK_COLORS[cls] || '#94A3B8'} />
            ))}
          </div>
        </Section>
      )}

      {/* ── Blocage automatique ── */}
      {canConfigureIDS && cfg && (
        <Section icon={AlertTriangle} title="Blocage automatique" color="#EF4444">
          <Toggle label="Blocage automatique activé" desc="Bloque automatiquement les IP dont le score dépasse le seuil"
            value={cfg.auto_block_enabled} onChange={v => set('auto_block_enabled', v)} />
          <div style={{ marginTop: 16 }}>
            <Slider label="Seuil de blocage automatique" value={cfg.auto_block_threshold} min={0.5} max={0.99} step={0.01}
              onChange={v => set('auto_block_threshold', v)} format={v => `${(v * 100).toFixed(0)}%`} color="#EF4444" />
            <Slider label="Durée du blocage" value={cfg.auto_block_duration} min={300} max={86400} step={300}
              onChange={v => set('auto_block_duration', v)}
              format={v => { const h = Math.floor(v/3600); const m = Math.floor((v%3600)/60); return h > 0 ? `${h}h${m > 0 ? m+'m':''}` : `${m}m` }}
              color="#F97316" />
          </div>
        </Section>
      )}

      {/* ── River ── */}
      {canConfigureIDS && cfg && (
        <Section icon={Brain} title="Apprentissage en ligne (River)" color="#22C55E">
          <Toggle label="River activé" desc="Mylo apprend en continu depuis le trafic réel"
            value={cfg.river_enabled} onChange={v => set('river_enabled', v)} />
          <div style={{ marginTop: 16 }}>
            <Slider label="Seuil d'apprentissage River" desc="Confiance minimum pour que River apprenne automatiquement"
              value={cfg.river_learn_threshold} min={0.3} max={0.99} step={0.01}
              onChange={v => set('river_learn_threshold', v)} format={v => `${(v * 100).toFixed(0)}%`} color="#22C55E" />
          </div>
        </Section>
      )}

      {/* ── Notifications ── */}
      {cfg && (
  <Section icon={Bell} title="Notifications" color="#F97316">
    <Toggle
      label="Notifications activées"
      value={cfg.notif_enabled}
      onChange={v => set('notif_enabled', v)}
    />

    {cfg.notif_enabled && (
      <div style={{ marginTop: 16 }}>

        {/* Sévérité minimale globale */}
        <div style={{ marginBottom: 20 }}>
          <label style={{ fontSize: 12, color: '#64748B', fontWeight: 600, display: 'block', marginBottom: 8, textTransform: 'uppercase' }}>
            Sévérité minimale pour notifier
          </label>
          <div style={{ display: 'flex', gap: 8 }}>
            {['CRITICAL', 'HIGH', 'MEDIUM'].map(s => (
              <button key={s} onClick={() => set('notif_min_severity', s)} style={{
                padding: '6px 14px', borderRadius: 6, fontSize: 12, fontWeight: 600,
                border: `1px solid ${cfg.notif_min_severity === s ? '#3B82F6' : '#1E2D4F'}`,
                background: cfg.notif_min_severity === s ? 'rgba(59,130,246,0.15)' : 'transparent',
                color: cfg.notif_min_severity === s ? '#3B82F6' : '#64748B', cursor: 'pointer',
              }}>{s}</button>
            ))}
          </div>
        </div>

        {/* Telegram */}
        <div style={{ padding: 16, borderRadius: 10, background: '#0A0E1A', border: '1px solid #1E2D4F', marginBottom: 14 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 18 }}>✈️</span>
              <div>
                <div style={{ fontSize: 13, fontWeight: 700, color: '#F8FAFC' }}>Telegram</div>
                <div style={{ fontSize: 11, color: '#475569' }}>Alertes instantanées via bot Telegram</div>
              </div>
            </div>
            <button onClick={() => set('notif_telegram_enabled', !cfg.notif_telegram_enabled)} style={{
              width: 44, height: 24, borderRadius: 12, border: 'none',
              background: cfg.notif_telegram_enabled ? '#3B82F6' : '#1E2D4F',
              cursor: 'pointer', position: 'relative',
            }}>
              <div style={{ width: 18, height: 18, borderRadius: '50%', background: '#fff', position: 'absolute', top: 3, left: cfg.notif_telegram_enabled ? 23 : 3, transition: 'left 0.2s' }} />
            </button>
          </div>
          {cfg.notif_telegram_enabled && (
            <>
              <Input label="Token Bot Telegram" value={cfg.notif_telegram_token || ''} placeholder="1234567890:AAF..." onChange={v => set('notif_telegram_token', v)} />
              <Input label="Chat ID" value={cfg.notif_telegram_chat || ''} placeholder="-100123456789" onChange={v => set('notif_telegram_chat', v)} />
            </>
          )}
        </div>

        {/* Email */}
        <div style={{ padding: 16, borderRadius: 10, background: '#0A0E1A', border: '1px solid #1E2D4F' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 18 }}>📧</span>
              <div>
                <div style={{ fontSize: 13, fontWeight: 700, color: '#F8FAFC' }}>Email</div>
                <div style={{ fontSize: 11, color: '#475569' }}>Rapport d'alerte par email · Par défaut : HIGH et CRITICAL</div>
              </div>
            </div>
            <button onClick={() => set('notif_email_enabled', !cfg.notif_email_enabled)} style={{
              width: 44, height: 24, borderRadius: 12, border: 'none',
              background: cfg.notif_email_enabled ? '#3B82F6' : '#1E2D4F',
              cursor: 'pointer', position: 'relative',
            }}>
              <div style={{ width: 18, height: 18, borderRadius: '50%', background: '#fff', position: 'absolute', top: 3, left: cfg.notif_email_enabled ? 23 : 3, transition: 'left 0.2s' }} />
            </button>
          </div>
          {cfg.notif_email_enabled && (
            <>
              <Input
                label="Email destinataire SOC"
                type="email"
                value={cfg.notif_email_address || ''}
                placeholder="soc@votre-entreprise.com"
                onChange={v => set('notif_email_address', v)}
              />
              <div style={{ marginBottom: 8 }}>
                <label style={{ fontSize: 12, color: '#64748B', fontWeight: 600, display: 'block', marginBottom: 6, textTransform: 'uppercase' }}>
                  Sévérité minimale (email)
                </label>
                <div style={{ display: 'flex', gap: 8 }}>
                  {['CRITICAL', 'HIGH', 'MEDIUM'].map(s => (
                    <button key={s} onClick={() => set('notif_email_min_severity', s)} style={{
                      padding: '5px 12px', borderRadius: 6, fontSize: 11, fontWeight: 600,
                      border: `1px solid ${cfg.notif_email_min_severity === s ? '#F97316' : '#1E2D4F'}`,
                      background: cfg.notif_email_min_severity === s ? 'rgba(249,115,22,0.15)' : 'transparent',
                      color: cfg.notif_email_min_severity === s ? '#F97316' : '#64748B', cursor: 'pointer',
                    }}>{s}</button>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>

      </div>
    )}
  </Section>
)}

      {(canManageUsers || canConfigureIDS) && (
        <Section icon={Shield} title={`Inventaire des actifs${assets.length > 0 ? ` (${assets.length})` : ''}`} color="#3B82F6">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <div>
              <div style={{ fontSize: 13, color: '#F8FAFC', fontWeight: 600 }}>Découverte automatique des équipements</div>
              <div style={{ fontSize: 11, color: '#64748B' }}>Rechercher les IP et hôtes connus dans les flux et les logs.</div>
            </div>
            <button onClick={discoverAssets} disabled={discovering} style={{ padding: '9px 16px', borderRadius: 8, border: '1px solid #1E2D4F', background: discovering ? '#1E3A6E' : 'transparent', color: '#94A3B8', cursor: discovering ? 'not-allowed' : 'pointer', fontSize: 13 }}>
              {discovering ? 'Découverte...' : 'Découvrir les actifs'}
            </button>
          </div>
          <div style={{ display: 'grid', gap: 10, marginBottom: 16 }}>
            <label style={{ fontSize: 12, color: '#94A3B8', fontWeight: 600 }}>Plage ARP / CIDR</label>
            <input
              value={arpTarget}
              onChange={e => setArpTarget(e.target.value)}
              placeholder="Ex: 192.168.1.0/24"
              style={{ width: '100%', padding: '10px 14px', borderRadius: 8, background: '#0A0E1A', border: '1px solid #1E2D4F', color: '#F8FAFC', fontSize: 13 }}
            />
            <div style={{ fontSize: 11, color: '#64748B' }}>
              Si vous avez un CIDR local valide, ajoutez-le pour utiliser le scan ARP. Sinon, Mylo tente la découverte passive sur les flux et logs existants.
            </div>
          </div>

          {/* Bouton retractable si >= 5 actifs */}
          {assets.length >= 5 && (
            <button
              onClick={() => setAssetsExpanded(p => !p)}
              style={{
                display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12,
                padding: '8px 12px', borderRadius: 8, background: '#1E2D4F', border: 'none',
                color: '#94A3B8', cursor: 'pointer', fontSize: 12, fontWeight: 600,
              }}
            >
              <span style={{ transform: assetsExpanded ? 'rotate(90deg)' : 'rotate(0deg)', transition: 'transform 0.2s' }}>▶</span>
              {assetsExpanded ? 'Masquer' : 'Afficher'} {assets.length} actifs détectés
            </button>
          )}

          {(assetsExpanded || assets.length < 5) && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 12 }}>
            {assets.length === 0 && (
              <div style={{ padding: 16, borderRadius: 12, background: '#0A0E1A', color: '#94A3B8' }}>
                Aucune ressource détectée. Appuyez sur « Découvrir les actifs » pour scanner les IP connues.
              </div>
            )}
            {assets.map(asset => (
              <div key={asset.id} style={{ padding: 16, borderRadius: 12, border: `1px solid ${asset.is_authorized ? '#1E2D4F' : '#EF444440'}`, background: '#0A0E1A' }}>
                
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                  <div style={{ flex: 1 }}>
                    {/* Nom editable */}
                    {editingAssetId === asset.id ? (
                      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                        <input
                          type="text"
                          value={editingAssetName}
                          onChange={e => setEditingAssetName(e.target.value)}
                          onKeyDown={e => e.key === 'Enter' && saveAssetName(asset.id)}
                          onBlur={() => saveAssetName(asset.id)}
                          autoFocus
                          style={{
                            flex: 1, padding: '4px 8px', borderRadius: 6, fontSize: 13, fontWeight: 700,
                            background: '#0A0E1A', border: '1px solid #3B82F6', color: '#F8FAFC',
                          }}
                        />
                        <button onClick={() => saveAssetName(asset.id)} style={{ background: 'none', border: 'none', color: '#22C55E', cursor: 'pointer' }}><Check size={14} /></button>
                        <button onClick={() => setEditingAssetId(null)} style={{ background: 'none', border: 'none', color: '#EF4444', cursor: 'pointer' }}><X size={14} /></button>
                      </div>
                    ) : (
                      <div
                        onClick={() => { setEditingAssetId(asset.id); setEditingAssetName(asset.name || asset.label || '') }}
                        style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6 }}
                        title="Cliquer pour modifier le nom"
                      >
                        <div style={{ fontWeight: 700, color: '#F8FAFC' }}>{asset.name || asset.label || asset.ip_address}</div>
                        <Edit2 size={12} color="#64748B" />
                      </div>
                    )}
                    <div style={{ fontSize: 11, color: '#64748B' }}>
                      {asset.ip_address} · {asset.mac_address || 'MAC inconnue'} · {asset.os_type || 'OS inconnu'}
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    {/* Criticité 1-4 */}
                    <span style={{
                      padding: '3px 10px', borderRadius: 20, fontSize: 11, fontWeight: 700,
                      background: asset.criticality === 4 ? 'rgba(239,68,68,0.15)' :
                                  asset.criticality === 3 ? 'rgba(249,115,22,0.15)' :
                                  asset.criticality === 2 ? 'rgba(234,179,8,0.15)' : 'rgba(34,197,94,0.15)',
                      color: asset.criticality === 4 ? '#EF4444' :
                            asset.criticality === 3 ? '#F97316' :
                            asset.criticality === 2 ? '#EAB308' : '#22C55E',
                    }}>
                      Criticité {asset.criticality}/4 — {asset.criticality_label}
                    </span>
                    {/* Shadow IT */}
                    {!asset.is_authorized && (
                      <span style={{ padding: '3px 10px', borderRadius: 20, fontSize: 11, fontWeight: 700, background: 'rgba(239,68,68,0.15)', color: '#EF4444' }}>
                        ⚠ Non autorisé
                      </span>
                    )}
                  </div>
                </div>

                {/* Ports détectés */}
                {asset.open_ports?.length > 0 && (
                  <div style={{ marginBottom: 10 }}>
                    <div style={{ fontSize: 11, color: '#475569', marginBottom: 4 }}>PORTS OUVERTS</div>
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                      {asset.open_ports.map(port => (
                        <span key={port} style={{ padding: '2px 8px', borderRadius: 6, fontSize: 11, background: '#1E2D4F', color: '#94A3B8', fontFamily: 'monospace' }}>
                          :{port} {asset.services?.[port] ? `(${asset.services[port]})` : ''}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Actions */}
                <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                  <button
                    onClick={() => updateAsset(asset.id, { is_authorized: !asset.is_authorized })}
                    style={{
                      padding: '6px 14px', borderRadius: 8, fontSize: 12, fontWeight: 600,
                      border: `1px solid ${asset.is_authorized ? '#22C55E' : '#EF4444'}`,
                      background: asset.is_authorized ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)',
                      color: asset.is_authorized ? '#22C55E' : '#EF4444', cursor: 'pointer',
                    }}
                  >
                    {asset.is_authorized ? '✓ Autorisé' : '⚠ Marquer comme autorisé'}
                  </button>
                  {/* Criticité manuelle */}
                  <select
                    value={asset.criticality}
                    onChange={e => updateAsset(asset.id, { criticality: parseInt(e.target.value) })}
                    style={{ padding: '6px 12px', borderRadius: 8, fontSize: 12, background: '#0A0E1A', border: '1px solid #1E2D4F', color: '#F8FAFC' }}
                  >
                    <option value={1}>1 — Basse</option>
                    <option value={2}>2 — Moyenne</option>
                    <option value={3}>3 — Haute</option>
                    <option value={4}>4 — Critique</option>
                  </select>
                </div>
              </div>
            ))}
            </div>
          )}
        </Section>
      )}

      {/* Bouton save bas */}
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 8 }}>
        <button onClick={save} disabled={saving} style={{ padding: '11px 28px', borderRadius: 8, border: 'none', background: saved ? '#22C55E' : '#3B82F6', color: '#fff', cursor: 'pointer', fontWeight: 700, fontSize: 14, display: 'flex', alignItems: 'center', gap: 8 }}>
          <Save size={16} />{saved ? '✓ Sauvegardé !' : 'Sauvegarder les paramètres'}
        </button>
      </div>

      {/* Modal ajout membre */}
      {showAddMember && (
        <AddMemberModal
          onClose={() => setShowAddMember(false)}
          onAdd={member => setMembers(p => [...p, member])}
        />
      )}
      {/* Toast notification */}
      {toast && (
        <div style={{
          position: 'fixed', bottom: 24, left: '50%', transform: 'translateX(-50%)',
          zIndex: 3000, padding: '12px 24px', borderRadius: 10,
          background: toast.type === 'error' ? '#EF4444' : '#22C55E',
          color: '#fff', fontSize: 13, fontWeight: 600,
          boxShadow: '0 8px 24px rgba(0,0,0,0.4)',
          animation: 'fadeIn 0.2s ease',
        }}>
          {toast.type === 'error' ? '✗' : '✓'} {toast.msg}
        </div>
      )}

      {/* Modal édition membre */}
      {editMember && (
        <EditMemberModal
          member={editMember}
          onClose={() => setEditMember(null)}
          onSave={updated => {
            setMembers(p => p.map(m => m.id === updated.id ? updated : m))
            setEditMember(null)
          }}
        />
      )}
    <style>{`@keyframes fadeIn { from { opacity:0; transform:translateX(-50%) translateY(10px) } to { opacity:1; transform:translateX(-50%) translateY(0) } }`}</style>
    </div>
  )
}