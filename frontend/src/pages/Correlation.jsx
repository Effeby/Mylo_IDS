import { useState, useEffect } from 'react'
import { Link2, RefreshCw, ChevronDown, CheckCircle, AlertTriangle } from 'lucide-react'

const DJANGO_URL = import.meta.env.VITE_DJANGO_URL || 'https://mylo-ids.site'

async function apiFetch(path, options = {}) {
  const token = localStorage.getItem('mylo_access')
  const res = await fetch(`${DJANGO_URL}${path}`, {
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    ...options,
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}

const RISK_COLORS = {
  CRITICAL: '#EF4444', HIGH: '#F97316', MEDIUM: '#EAB308', LOW: '#22C55E'
}
const RISK_BG = {
  CRITICAL: 'rgba(239,68,68,0.1)', HIGH: 'rgba(249,115,22,0.1)',
  MEDIUM: 'rgba(234,179,8,0.1)', LOW: 'rgba(34,197,94,0.1)'
}
const SCENARIO_ICONS = {
  recon_exploit:     '🎯',
  recon_dos:         '💥',
  brute_exploit:     '🔓',
  persistence:       '👻',
  lateral_movement:  '↔️',
  data_exfiltration: '📤',
  multi_vector:      '🌊',
  coordinated:       '⚡',
  unknown:           '❓',
}

function formatDuration(seconds) {
  if (seconds < 60)  return `${Math.round(seconds)}s`
  if (seconds < 3600) return `${Math.round(seconds/60)}min`
  return `${Math.round(seconds/3600)}h`
}

export default function Correlation() {
  const [stats,    setStats]    = useState(null)
  const [correls,  setCorrels]  = useState([])
  const [loading,  setLoading]  = useState(true)
  const [expanded, setExpanded] = useState(null)
  const [detail,   setDetail]   = useState({})
  const [showAll,  setShowAll]  = useState(false)

  const load = async () => {
    setLoading(true)
    try {
      const [s, c] = await Promise.all([
        apiFetch('/api/alerts/correlations/stats/'),
        apiFetch(`/api/alerts/correlations/?active=${!showAll}&limit=100`),
      ])
      setStats(s)
      setCorrels(c)
    } catch(e) { console.error(e) }
    finally { setLoading(false) }
  }

  useEffect(() => { load() }, [showAll])

  const loadDetail = async (id) => {
    if (detail[id]) return
    try {
      const d = await apiFetch(`/api/alerts/correlations/${id}/`)
      setDetail(p => ({...p, [id]: d}))
    } catch(e) {}
  }

  const resolve = async (id) => {
    if (!window.confirm('Marquer cette corrélation comme résolue ?')) return
    try {
      await apiFetch(`/api/alerts/correlations/${id}/`, {
        method: 'PATCH',
        body: JSON.stringify({ resolve: true }),
      })
      setCorrels(p => p.filter(c => c.id !== id))
    } catch(e) {}
  }

  return (
    <div style={{ padding: 32, color: '#F8FAFC' }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ width: 42, height: 42, borderRadius: 10, background: 'linear-gradient(135deg,#EF4444,#B91C1C)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Link2 size={22} color="#fff" />
          </div>
          <div>
            <h1 style={{ margin: 0, fontSize: 22, fontWeight: 800 }}>Corrélation d'Alertes</h1>
            <p style={{ margin: 0, color: '#94A3B8', fontSize: 13 }}>
              Détection de scénarios d'attaque · Prédiction de la prochaine étape
            </p>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button onClick={() => setShowAll(p => !p)} style={{
            padding: '8px 14px', borderRadius: 8,
            border: `1px solid ${showAll ? '#3B82F6' : '#1E2D4F'}`,
            background: showAll ? 'rgba(59,130,246,0.1)' : 'transparent',
            color: showAll ? '#3B82F6' : '#64748B', cursor: 'pointer', fontSize: 13,
          }}>
            {showAll ? 'Toutes' : 'Actives seulement'}
          </button>
          <button onClick={load} disabled={loading} style={{ padding: '8px 16px', borderRadius: 8, border: '1px solid #1E2D4F', background: 'transparent', color: '#94A3B8', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
            <RefreshCw size={14} /> Actualiser
          </button>
        </div>
      </div>

      {/* KPIs */}
      {stats && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 12, marginBottom: 24 }}>
          {[
            { label: 'Total scénarios',    value: stats.total,    color: '#3B82F6' },
            { label: 'Actifs',             value: stats.active,   color: '#F97316' },
            { label: 'Critiques actifs',   value: stats.critical, color: '#EF4444' },
            { label: 'IPs impliquées',     value: stats.top_ips?.length || 0, color: '#A855F7' },
          ].map(({ label, value, color }) => (
            <div key={label} style={{ background: '#0F1629', border: '1px solid #1E2D4F', borderRadius: 10, padding: '14px 18px' }}>
              <div style={{ fontSize: 24, fontWeight: 800, color }}>{value}</div>
              <div style={{ fontSize: 12, color: '#64748B' }}>{label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Explication */}
      <div style={{ padding: '12px 16px', borderRadius: 8, background: 'rgba(239,68,68,0.05)', border: '1px solid #EF444420', marginBottom: 20, fontSize: 12, color: '#94A3B8' }}>
        <strong style={{ color: '#EF4444' }}>Comment ça marche</strong> — Mylo analyse les alertes des
        <strong style={{ color: '#F8FAFC' }}> 10 dernières minutes </strong>
        par IP source. Quand une séquence connue est détectée (ex: Probe → BruteForce), un scénario est créé avec la
        <strong style={{ color: '#F8FAFC' }}> prochaine étape probable </strong>et l'action recommandée.
      </div>

      {/* Scénarios connus */}
      <details style={{ marginBottom: 20 }}>
        <summary style={{ fontSize: 12, color: '#3B82F6', cursor: 'pointer', padding: '8px 0', userSelect: 'none' }}>
          📚 Scénarios d'attaque reconnus par Mylo
        </summary>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 8, marginTop: 10 }}>
          {[
            { seq: 'Probe → BruteForce', risk: 'CRITICAL', label: 'Recon → Exploit' },
            { seq: 'Probe → DoS/DDoS',   risk: 'CRITICAL', label: 'Recon → DoS' },
            { seq: 'BruteForce → R2L',   risk: 'CRITICAL', label: 'Force → Accès' },
            { seq: 'BruteForce → U2R',   risk: 'CRITICAL', label: 'Force → Root' },
            { seq: 'DoS → BruteForce',   risk: 'HIGH',     label: 'Diversion' },
            { seq: 'Probe → WebAttack',  risk: 'HIGH',     label: 'Scan Web' },
            { seq: 'Infiltration → Botnet', risk: 'CRITICAL', label: 'Compromission' },
            { seq: '3+ types différents', risk: 'HIGH',    label: 'Multi-vecteurs' },
          ].map(s => (
            <div key={s.seq} style={{ padding: '8px 12px', borderRadius: 8, background: RISK_BG[s.risk], border: `1px solid ${RISK_COLORS[s.risk]}30` }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: RISK_COLORS[s.risk], marginBottom: 2 }}>{s.label} · {s.risk}</div>
              <div style={{ fontSize: 11, color: '#94A3B8', fontFamily: 'monospace' }}>{s.seq}</div>
            </div>
          ))}
        </div>
      </details>

      {/* Liste des corrélations */}
      {loading ? (
        <div style={{ padding: 32, textAlign: 'center', color: '#475569' }}>Chargement...</div>
      ) : correls.length === 0 ? (
        <div style={{ padding: 48, textAlign: 'center', color: '#475569', background: '#0F1629', borderRadius: 12, border: '1px solid #1E2D4F' }}>
          <Link2 size={40} style={{ opacity: 0.3, marginBottom: 12 }} />
          <p style={{ margin: 0 }}>Aucun scénario d'attaque détecté</p>
          <p style={{ margin: '6px 0 0', fontSize: 12 }}>Les scénarios apparaissent quand des attaques séquentielles sont détectées depuis la même IP</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {correls.map(c => {
            const color  = RISK_COLORS[c.risk_level]
            const isOpen = expanded === c.id
            const d      = detail[c.id]

            return (
              <div key={c.id} style={{ background: '#0F1629', border: `1px solid ${c.risk_level === 'CRITICAL' ? '#EF444440' : '#1E2D4F'}`, borderRadius: 12, overflow: 'hidden' }}>

                {/* En-tête de la corrélation */}
                <div onClick={() => { setExpanded(isOpen ? null : c.id); loadDetail(c.id) }}
                  style={{ padding: '16px 20px', cursor: 'pointer', display: 'flex', alignItems: 'flex-start', gap: 14,
                    background: c.risk_level === 'CRITICAL' ? 'rgba(239,68,68,0.04)' : 'transparent',
                    borderLeft: `4px solid ${color}`,
                  }}>

                  {/* Icône scénario */}
                  <div style={{ fontSize: 28, lineHeight: 1, flexShrink: 0 }}>
                    {SCENARIO_ICONS[c.scenario_type] || '⚡'}
                  </div>

                  <div style={{ flex: 1, minWidth: 0 }}>
                    {/* Titre + badges */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6, flexWrap: 'wrap' }}>
                      <span style={{ fontSize: 15, fontWeight: 800, color: '#F8FAFC' }}>{c.scenario_label}</span>
                      <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 10px', borderRadius: 20, background: RISK_BG[c.risk_level], color }}>
                        {c.risk_level}
                      </span>
                      {c.is_active && (
                        <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 20, background: 'rgba(239,68,68,0.15)', color: '#EF4444', fontWeight: 700 }}>
                          ● EN COURS
                        </span>
                      )}
                      <span style={{ fontSize: 11, color: '#475569' }}>
                        {c.confidence * 100 | 0}% confiance
                      </span>
                    </div>

                    {/* Séquence d'attaque */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8, flexWrap: 'wrap' }}>
                      {c.attack_types.slice(-6).map((t, i) => (
                        <span key={i} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                          <span style={{ fontSize: 12, padding: '2px 10px', borderRadius: 20, background: '#1E2D4F', color: '#94A3B8', fontWeight: 600 }}>{t}</span>
                          {i < c.attack_types.slice(-6).length - 1 && <span style={{ color: '#475569', fontSize: 14 }}>→</span>}
                        </span>
                      ))}
                    </div>

                    {/* Description */}
                    <p style={{ margin: '0 0 8px', fontSize: 13, color: '#94A3B8' }}>{c.description}</p>

                    {/* Prochaine étape */}
                    {c.next_step_prediction && (
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 12px', borderRadius: 6, background: 'rgba(239,68,68,0.08)', border: '1px solid #EF444430' }}>
                        <span style={{ fontSize: 12 }}>🔮</span>
                        <span style={{ fontSize: 12, color: '#FCA5A5', fontWeight: 600 }}>Prochaine étape probable : {c.next_step_prediction}</span>
                      </div>
                    )}
                  </div>

                  {/* Méta droite */}
                  <div style={{ textAlign: 'right', flexShrink: 0 }}>
                    <div style={{ fontSize: 12, color: '#94A3B8', fontFamily: 'monospace', marginBottom: 4 }}>{c.src_ip}</div>
                    <div style={{ fontSize: 11, color: '#475569' }}>{c.alert_count} alertes · {formatDuration(c.duration_seconds)}</div>
                    <div style={{ fontSize: 11, color: '#475569', marginTop: 2 }}>
                      {new Date(c.first_alert_at).toLocaleTimeString('fr-FR')}
                    </div>
                    <ChevronDown size={14} color="#475569" style={{ marginTop: 8, transform: isOpen ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s' }} />
                  </div>
                </div>

                {/* Détail expandé */}
                {isOpen && (
                  <div style={{ padding: '16px 20px', background: '#0A0E1A', borderTop: '1px solid #1E2D4F' }}>

                    {/* Action recommandée */}
                    <div style={{ padding: '10px 14px', borderRadius: 8, background: 'rgba(249,115,22,0.08)', border: '1px solid #F9731620', marginBottom: 16 }}>
                      <div style={{ fontSize: 11, color: '#F97316', fontWeight: 700, marginBottom: 4 }}>💡 ACTION RECOMMANDÉE</div>
                      <div style={{ fontSize: 13, color: '#FED7AA' }}>{c.recommended_action}</div>
                    </div>

                    {/* Timeline des alertes */}
                    {d?.alerts && (
                      <div>
                        <div style={{ fontSize: 11, color: '#475569', fontWeight: 700, marginBottom: 10, textTransform: 'uppercase' }}>
                          Timeline des alertes ({d.alerts.length})
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                          {d.alerts.map((a, i) => (
                            <div key={a.id} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                              <div style={{ width: 8, height: 8, borderRadius: '50%', background: RISK_COLORS[a.severity] || '#94A3B8', flexShrink: 0 }} />
                              <span style={{ fontSize: 11, color: '#475569', fontFamily: 'monospace', minWidth: 70 }}>
                                {new Date(a.detected_at).toLocaleTimeString('fr-FR')}
                              </span>
                              <span style={{ fontSize: 12, fontWeight: 600, color: '#F8FAFC' }}>{a.attack_type}</span>
                              <span style={{ fontSize: 11, color: '#64748B' }}>· {a.severity}</span>
                              {i < d.alerts.length - 1 && (
                                <span style={{ fontSize: 10, color: '#334155', marginLeft: 4 }}>
                                  +{Math.round((new Date(d.alerts[i+1].detected_at) - new Date(a.detected_at))/1000)}s →
                                </span>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Bouton résoudre */}
                    {c.is_active && (
                      <button onClick={() => resolve(c.id)} style={{ marginTop: 16, display: 'flex', alignItems: 'center', gap: 6, padding: '8px 16px', borderRadius: 8, border: '1px solid #22C55E40', background: 'rgba(34,197,94,0.08)', color: '#22C55E', cursor: 'pointer', fontSize: 12, fontWeight: 600 }}>
                        <CheckCircle size={14} /> Marquer comme résolu
                      </button>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}