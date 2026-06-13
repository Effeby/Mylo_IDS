import { useState, useEffect } from 'react'
import { Shield, RefreshCw, ChevronDown } from 'lucide-react'

const DJANGO_URL = import.meta.env.VITE_DJANGO_URL || 'http://localhost:8001'

const ACTION_COLORS = {
  login:'#22C55E', logout:'#64748B', login_failed:'#EF4444',
  alert_status_update:'#3B82F6', alert_feedback:'#A855F7',
  ip_block:'#EF4444', ip_unblock:'#22C55E', ip_whitelist:'#22C55E',
  settings_update:'#F97316', user_create:'#3B82F6', user_update:'#EAB308',
  user_delete:'#EF4444', report_generate:'#14B8A6',
  org_update:'#F97316', onboarding_complete:'#22C55E',
}

const ACTION_ICONS = {
  login:'🔑', logout:'🚪', login_failed:'⛔',
  alert_status_update:'🔔', alert_feedback:'🧠',
  ip_block:'🚫', ip_unblock:'✅', ip_whitelist:'✅',
  settings_update:'⚙️', user_create:'👤', user_update:'✏️', user_delete:'🗑️',
  report_generate:'📄', org_update:'🏢', onboarding_complete:'🎉',
}

async function apiFetch(path) {
  const token = localStorage.getItem('mylo_access')
  const res = await fetch(`${DJANGO_URL}${path}`, {
    headers: { Authorization: `Bearer ${token}` }
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}

export default function AuditLog() {
  const [logs,     setLogs]     = useState([])
  const [loading,  setLoading]  = useState(true)
  const [error,    setError]    = useState('')
  const [filter,   setFilter]   = useState({ action: '', limit: 100 })
  const [expanded, setExpanded] = useState(null)

  const currentUser = (() => { try { return JSON.parse(localStorage.getItem('mylo_user') || '{}') } catch { return {} } })()
  const canView = (currentUser?.habilitation_level || 0) >= 3

  const load = async () => {
    setLoading(true)
    setError('')
    try {
      let url = `/api/auth/audit/?limit=${filter.limit}`
      if (filter.action) url += `&action=${filter.action}`
      const data = await apiFetch(url)
      const sortedLogs = Array.isArray(data) ? [...data].sort((a, b) => {
        const priority = action => (action === 'ip_block' || action === 'ip_unblock') ? 0 : 1
        const pa = priority(a.action)
        const pb = priority(b.action)
        if (pa !== pb) return pa - pb
        return new Date(b.timestamp) - new Date(a.timestamp)
      }) : []
      setLogs(sortedLogs)
    } catch(e) { setError('Impossible de charger les logs') }
    finally { setLoading(false) }
  }

  useEffect(() => { if (canView) load() }, [filter.limit, filter.action])

  if (!canView) return (
    <div style={{ padding: 32, color: '#F8FAFC', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '60vh', gap: 16 }}>
      <Shield size={48} color="#EF4444" />
      <h2 style={{ margin: 0 }}>Accès refusé</h2>
      <p style={{ color: '#64748B', margin: 0 }}>Réservé aux Managers SOC et Administrateurs.</p>
    </div>
  )

  const stats = {
    total:  logs.length,
    failed: logs.filter(l => !l.success).length,
    blocks: logs.filter(l => l.action === 'ip_block').length,
    logins: logs.filter(l => l.action === 'login').length,
  }

  return (
    <div style={{ padding: 32, color: '#F8FAFC' }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ width: 42, height: 42, borderRadius: 10, background: 'linear-gradient(135deg,#F97316,#EA580C)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Shield size={22} color="#fff" />
          </div>
          <div>
            <h1 style={{ margin: 0, fontSize: 22, fontWeight: 800 }}>Journal d'Audit</h1>
            <p style={{ margin: 0, color: '#94A3B8', fontSize: 13 }}>Traçabilité des actions — qui, quoi, quand, d'où</p>
          </div>
        </div>
        <button onClick={load} disabled={loading} style={{ padding: '8px 16px', borderRadius: 8, border: '1px solid #1E2D4F', background: 'transparent', color: '#94A3B8', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
          <RefreshCw size={14} /> Actualiser
        </button>
      </div>

      {/* KPIs */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 12, marginBottom: 20 }}>
        {[
          { label: 'Total actions', value: stats.total,  color: '#3B82F6' },
          { label: 'Connexions',    value: stats.logins,  color: '#22C55E' },
          { label: 'IP bloquées',   value: stats.blocks,  color: '#EF4444' },
          { label: 'Échecs',        value: stats.failed,  color: '#F97316' },
        ].map(({ label, value, color }) => (
          <div key={label} style={{ background: '#0F1629', border: '1px solid #1E2D4F', borderRadius: 10, padding: '14px 18px' }}>
            <div style={{ fontSize: 24, fontWeight: 800, color }}>{value}</div>
            <div style={{ fontSize: 12, color: '#64748B' }}>{label}</div>
          </div>
        ))}
      </div>

      {/* Filtres */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 16 }}>
        <select value={filter.action} onChange={e => setFilter(p => ({...p, action: e.target.value}))}
          style={{ padding: '8px 12px', borderRadius: 8, background: '#0F1629', border: '1px solid #1E2D4F', color: '#F8FAFC', fontSize: 13 }}>
          <option value="">Toutes les actions</option>
          <option value="login">Connexions</option>
          <option value="login_failed">Échecs connexion</option>
          <option value="ip_block">Blocages IP</option>
          <option value="ip_unblock">Déblocages IP</option>
          <option value="settings_update">Modifications paramètres</option>
          <option value="user_create">Créations utilisateur</option>
          <option value="user_delete">Suppressions utilisateur</option>
          <option value="alert_feedback">Feedbacks River</option>
        </select>
        <select value={filter.limit} onChange={e => setFilter(p => ({...p, limit: parseInt(e.target.value)}))}
          style={{ padding: '8px 12px', borderRadius: 8, background: '#0F1629', border: '1px solid #1E2D4F', color: '#F8FAFC', fontSize: 13 }}>
          {[50,100,200,500].map(n => <option key={n} value={n}>{n} entrées</option>)}
        </select>
      </div>

      {error && <div style={{ padding: '10px 14px', borderRadius: 8, background: 'rgba(239,68,68,0.1)', color: '#EF4444', fontSize: 13, marginBottom: 12 }}>⚠️ {error}</div>}

      {/* Table */}
      <div style={{ background: '#0F1629', border: '1px solid #1E2D4F', borderRadius: 12, overflow: 'hidden' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '150px 130px 1fr 280px 130px 110px 40px', padding: '12px 20px', borderBottom: '1px solid #1E2D4F', fontSize: 11, color: '#475569', fontWeight: 700, letterSpacing: '0.05em' }}>
          <span>HORODATAGE</span><span>UTILISATEUR</span><span>ACTION</span><span>DESCRIPTION</span><span>IP SOURCE</span><span>STATUT</span><span></span>
        </div>

        {loading ? (
          <div style={{ padding: 32, textAlign: 'center', color: '#475569' }}>Chargement...</div>
        ) : logs.length === 0 ? (
          <div style={{ padding: 32, textAlign: 'center', color: '#475569' }}>Aucun log trouvé</div>
        ) : logs.map((log, i) => {
          const color  = ACTION_COLORS[log.action] || '#94A3B8'
          const icon   = ACTION_ICONS[log.action]  || '📋'
          const isOpen = expanded === log.id
          return (
            <div key={log.id}>
              <div onClick={() => setExpanded(isOpen ? null : log.id)}
                style={{ display: 'grid', gridTemplateColumns: '150px 130px 1fr 280px 130px 110px 40px', padding: '13px 20px', borderBottom: '1px solid #0A0E1A', cursor: 'pointer', background: isOpen ? 'rgba(59,130,246,0.04)' : i%2===0 ? 'transparent' : 'rgba(255,255,255,0.01)' }}>
                <div style={{ fontSize: 12, color: '#64748B' }}>
                  <div>{new Date(log.timestamp).toLocaleDateString('fr-FR')}</div>
                  <div style={{ fontFamily: 'monospace' }}>{new Date(log.timestamp).toLocaleTimeString('fr-FR')}</div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <div style={{ width: 24, height: 24, borderRadius: '50%', background: '#1E2D4F', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, fontWeight: 700, color: '#94A3B8' }}>
                    {(log.user || '?')[0].toUpperCase()}
                  </div>
                  <span style={{ fontSize: 12, color: '#F8FAFC', fontWeight: 500 }}>{log.user || '—'}</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontSize: 14 }}>{icon}</span>
                  <div>
                    <div style={{ fontSize: 12, fontWeight: 600, color }}>{log.action_display}</div>
                  </div>
                </div>
                <div style={{ fontSize: 12, color: '#94A3B8', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={log.description || ''}>
                  {log.description || '—'}
                </div>
                <div style={{ fontSize: 12, fontFamily: 'monospace', color: '#94A3B8' }}>{log.ip_address || '—'}</div>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '3px 10px', borderRadius: 20, background: log.success ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)', color: log.success ? '#22C55E' : '#EF4444', height: 'fit-content' }}>
                  {log.success ? '✓ Succès' : '✗ Échec'}
                </span>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <ChevronDown size={14} color="#475569" style={{ transform: isOpen ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s' }} />
                </div>
              </div>
              {isOpen && (
                <div style={{ padding: '16px 20px', background: '#0A0E1A', borderBottom: '1px solid #1E2D4F' }}>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 16 }}>
                    {[['Organisation',log.organisation||'—'],['Méthode HTTP',log.method||'—'],['Endpoint',log.endpoint||'—'],['Code HTTP',log.status_code||'—'],['Type objet',log.object_type||'—'],['Objet',log.object_repr||'—'],['Description',log.description||'—']].map(([label,value]) => (
                      <div key={label}>
                        <div style={{ fontSize: 10, color: '#475569', fontWeight: 700, marginBottom: 3, textTransform: 'uppercase' }}>{label}</div>
                        <div style={{ fontSize: 12, color: '#94A3B8', wordBreak: 'break-all' }}>{value}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}