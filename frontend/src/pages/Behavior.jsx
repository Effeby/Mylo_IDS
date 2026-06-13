import { useState, useEffect } from 'react'
import { Brain, RefreshCw, AlertTriangle, Shield, Activity, ChevronDown, Trash2 } from 'lucide-react'

const DJANGO_URL = import.meta.env.VITE_DJANGO_URL || 'http://localhost:8001'

async function apiFetch(path, options = {}) {
  const token = localStorage.getItem('mylo_access')
  const res = await fetch(`${DJANGO_URL}${path}`, {
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    ...options,
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}

const SCORE_COLOR = (score) => {
  if (score >= 7) return '#EF4444'
  if (score >= 5) return '#F97316'
  if (score >= 3) return '#EAB308'
  return '#22C55E'
}

const SCORE_LABEL = (score) => {
  if (score >= 7) return 'Critique'
  if (score >= 5) return 'Élevé'
  if (score >= 3) return 'Suspect'
  return 'Normal'
}

const ANOMALY_LABELS = {
  volume_anormal:       '📊 Volume anormal',
  port_inhabituel:      '🔌 Port inhabituel',
  protocole_inhabituel: '🔄 Protocole inhabituel',
  destination_inconnue: '🌐 Destination inconnue',
  duree_anormale:       '⏱️ Durée anormale',
}

export default function Behavior() {
  const [stats,     setStats]     = useState(null)
  const [baselines, setBaselines] = useState([])
  const [loading,   setLoading]   = useState(true)
  const [filter,    setFilter]    = useState({ suspicious: false, internal: false })
  const [expanded,  setExpanded]  = useState(null)
  const [detail,    setDetail]    = useState({})

  const load = async () => {
    setLoading(true)
    try {
      let url = '/api/alerts/baselines/?limit=100'
      if (filter.suspicious) url += '&suspicious=true'
      if (filter.internal)   url += '&internal=true'
      const [s, b] = await Promise.all([
        apiFetch('/api/alerts/baselines/stats/'),
        apiFetch(url),
      ])
      setStats(s)
      setBaselines(b)
    } catch(e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [filter])

  const loadDetail = async (ip) => {
    if (detail[ip]) return
    try {
      const d = await apiFetch(`/api/alerts/baselines/${ip}/`)
      setDetail(p => ({...p, [ip]: d}))
    } catch(e) {}
  }

  const resetBaseline = async (ip) => {
    if (!window.confirm(`Réinitialiser la baseline de ${ip} ?`)) return
    try {
      await apiFetch(`/api/alerts/baselines/${ip}/`, { method: 'DELETE' })
      setBaselines(p => p.filter(b => b.ip_address !== ip))
      setDetail(p => { const n = {...p}; delete n[ip]; return n })
    } catch(e) {}
  }

  const toggleExpand = (ip) => {
    const wasOpen = expanded === ip
    setExpanded(wasOpen ? null : ip)
    if (!wasOpen) loadDetail(ip)
  }

  return (
    <div style={{ padding: 32, color: '#F8FAFC' }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ width: 42, height: 42, borderRadius: 10, background: 'linear-gradient(135deg,#A855F7,#7C3AED)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Brain size={22} color="#fff" />
          </div>
          <div>
            <h1 style={{ margin: 0, fontSize: 22, fontWeight: 800 }}>Analyse Comportementale</h1>
            <p style={{ margin: 0, color: '#94A3B8', fontSize: 13 }}>
              Profils IP · Détection d'anomalies · Z-score en temps réel
            </p>
          </div>
        </div>
        <button onClick={load} disabled={loading} style={{ padding: '8px 16px', borderRadius: 8, border: '1px solid #1E2D4F', background: 'transparent', color: '#94A3B8', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
          <RefreshCw size={14} /> Actualiser
        </button>
      </div>

      {/* KPIs */}
      {stats && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 12, marginBottom: 24 }}>
          {[
            { label: 'IPs profilées',    value: stats.total_ips,       color: '#3B82F6' },
            { label: 'Suspectes',        value: stats.suspicious_ips,   color: '#EF4444' },
            { label: 'Baselines prêtes', value: stats.baselines_ready,  color: '#22C55E' },
            { label: 'IPs internes',     value: stats.internal_ips,     color: '#F97316' },
            { label: 'Score max',        value: stats.max_anomaly_score, color: SCORE_COLOR(stats.max_anomaly_score) },
          ].map(({ label, value, color }) => (
            <div key={label} style={{ background: '#0F1629', border: '1px solid #1E2D4F', borderRadius: 10, padding: '14px 18px' }}>
              <div style={{ fontSize: 24, fontWeight: 800, color }}>{value}</div>
              <div style={{ fontSize: 12, color: '#64748B' }}>{label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Explication */}
      <div style={{ padding: '12px 16px', borderRadius: 8, background: 'rgba(168,85,247,0.06)', border: '1px solid #A855F720', marginBottom: 20, fontSize: 12, color: '#94A3B8' }}>
        <strong style={{ color: '#A855F7' }}>Comment ça marche</strong> — Mylo apprend le comportement normal de chaque IP (volume, ports, protocoles, destinations).
        Après <strong style={{ color: '#F8FAFC' }}>20 flux minimum</strong>, la baseline est établie et Mylo détecte les écarts via Z-score.
        Un score &gt; 3 = suspect · &gt; 5 = élevé · &gt; 7 = critique.
      </div>

      {/* Filtres */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 16 }}>
        <button onClick={() => setFilter(p => ({...p, suspicious: !p.suspicious}))} style={{
          padding: '7px 14px', borderRadius: 8, border: `1px solid ${filter.suspicious ? '#EF4444' : '#1E2D4F'}`,
          background: filter.suspicious ? 'rgba(239,68,68,0.1)' : 'transparent',
          color: filter.suspicious ? '#EF4444' : '#64748B', cursor: 'pointer', fontSize: 13, fontWeight: 600,
        }}>
          🚨 Suspectes seulement
        </button>
        <button onClick={() => setFilter(p => ({...p, internal: !p.internal}))} style={{
          padding: '7px 14px', borderRadius: 8, border: `1px solid ${filter.internal ? '#F97316' : '#1E2D4F'}`,
          background: filter.internal ? 'rgba(249,115,22,0.1)' : 'transparent',
          color: filter.internal ? '#F97316' : '#64748B', cursor: 'pointer', fontSize: 13, fontWeight: 600,
        }}>
          🏠 IPs internes seulement
        </button>
      </div>

      {/* Table */}
      <div style={{ background: '#0F1629', border: '1px solid #1E2D4F', borderRadius: 12, overflow: 'hidden' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '160px 100px 120px 100px 100px 120px 80px 40px', padding: '12px 20px', borderBottom: '1px solid #1E2D4F', fontSize: 11, color: '#475569', fontWeight: 700, letterSpacing: '0.05em' }}>
          <span>IP</span><span>TYPE</span><span>SCORE</span><span>FLUX</span><span>ATTAQUES</span><span>DERNIÈRE ANOMALIE</span><span>BASELINE</span><span></span>
        </div>

        {loading ? (
          <div style={{ padding: 32, textAlign: 'center', color: '#475569' }}>Chargement des profils...</div>
        ) : baselines.length === 0 ? (
          <div style={{ padding: 48, textAlign: 'center', color: '#475569' }}>
            <Brain size={40} style={{ opacity: 0.3, marginBottom: 12 }} />
            <p style={{ margin: 0 }}>Aucun profil IP — en attente de trafic réseau</p>
            <p style={{ margin: '6px 0 0', fontSize: 12 }}>Les profils se construisent automatiquement dès que capture.py reçoit du trafic</p>
          </div>
        ) : baselines.map((b, i) => {
          const color    = SCORE_COLOR(b.anomaly_score)
          const isOpen   = expanded === b.ip_address
          const d        = detail[b.ip_address]

          return (
            <div key={b.ip_address}>
              <div onClick={() => toggleExpand(b.ip_address)}
                style={{ display: 'grid', gridTemplateColumns: '160px 100px 120px 100px 100px 120px 80px 40px', padding: '13px 20px', borderBottom: '1px solid #0A0E1A', cursor: 'pointer',
                  background: b.is_suspicious ? 'rgba(239,68,68,0.03)' : isOpen ? 'rgba(59,130,246,0.04)' : i%2===0 ? 'transparent' : 'rgba(255,255,255,0.01)',
                  borderLeft: b.is_suspicious ? '3px solid #EF4444' : '3px solid transparent',
                }}>
                {/* IP */}
                <div>
                  <div style={{ fontFamily: 'monospace', fontSize: 13, fontWeight: 700, color: '#F8FAFC' }}>{b.ip_address}</div>
                  {b.is_suspicious && <div style={{ fontSize: 10, color: '#EF4444' }}>⚠ SUSPECTE</div>}
                </div>

                {/* Type */}
                <span style={{ fontSize: 11, padding: '3px 8px', borderRadius: 20, background: b.is_internal ? 'rgba(249,115,22,0.1)' : 'rgba(100,116,139,0.1)', color: b.is_internal ? '#F97316' : '#94A3B8', height: 'fit-content' }}>
                  {b.is_internal ? '🏠 Interne' : '🌐 Externe'}
                </span>

                {/* Score */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <div style={{ flex: 1, height: 6, background: '#1E2D4F', borderRadius: 3, overflow: 'hidden' }}>
                    <div style={{ height: '100%', width: `${b.anomaly_score * 10}%`, background: color, borderRadius: 3, transition: 'width 0.3s' }} />
                  </div>
                  <span style={{ fontSize: 12, fontWeight: 700, color, fontFamily: 'monospace', minWidth: 24 }}>{b.anomaly_score.toFixed(1)}</span>
                </div>

                {/* Flux */}
                <div style={{ fontSize: 13, color: '#94A3B8' }}>{b.total_flows.toLocaleString()}</div>

                {/* Attaques */}
                <div style={{ fontSize: 13, color: b.attack_count > 0 ? '#EF4444' : '#94A3B8', fontWeight: b.attack_count > 0 ? 700 : 400 }}>
                  {b.attack_count > 0 ? `⚠ ${b.attack_count}` : '—'}
                </div>

                {/* Dernière anomalie */}
                <div style={{ fontSize: 11, color: '#64748B' }}>
                  {b.last_anomaly_type ? (ANOMALY_LABELS[b.last_anomaly_type] || b.last_anomaly_type) : '—'}
                </div>

                {/* Baseline */}
                <span style={{ fontSize: 11, padding: '2px 8px', borderRadius: 20, background: b.baseline_established ? 'rgba(34,197,94,0.1)' : 'rgba(100,116,139,0.1)', color: b.baseline_established ? '#22C55E' : '#64748B', height: 'fit-content' }}>
                  {b.baseline_established ? '✓ Prête' : `⏳ ${b.total_flows}/20`}
                </span>

                <ChevronDown size={14} color="#475569" style={{ transform: isOpen ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s', alignSelf: 'center' }} />
              </div>

              {/* Détail expandé */}
              {isOpen && (
                <div style={{ padding: '20px', background: '#0A0E1A', borderBottom: '1px solid #1E2D4F' }}>
                  {!d ? (
                    <div style={{ color: '#475569', fontSize: 13 }}>Chargement...</div>
                  ) : (
                    <div>
                      {/* Stats comportementales */}
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 16, marginBottom: 16 }}>
                        {[
                          ['Bytes/flux moyen', `${d.avg_bytes_per_flow?.toLocaleString()} B`],
                          ['Durée moyenne',    `${d.avg_duration?.toFixed(3)} s`],
                          ['Total bytes',      `${(d.total_bytes/1024).toFixed(1)} KB`],
                          ['Écart-type bytes', `${d.std_bytes_per_flow?.toLocaleString()} B`],
                        ].map(([label, value]) => (
                          <div key={label} style={{ background: '#0F1629', padding: '10px 14px', borderRadius: 8 }}>
                            <div style={{ fontSize: 10, color: '#475569', fontWeight: 700, marginBottom: 4, textTransform: 'uppercase' }}>{label}</div>
                            <div style={{ fontSize: 14, fontWeight: 700, color: '#F8FAFC', fontFamily: 'monospace' }}>{value}</div>
                          </div>
                        ))}
                      </div>

                      {/* Ports typiques */}
                      {d.typical_ports?.length > 0 && (
                        <div style={{ marginBottom: 12 }}>
                          <div style={{ fontSize: 11, color: '#475569', fontWeight: 700, marginBottom: 6, textTransform: 'uppercase' }}>Ports habituels</div>
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                            {d.typical_ports.slice(0,15).map(p => (
                              <span key={p} style={{ fontSize: 12, padding: '2px 10px', borderRadius: 20, background: '#1E2D4F', color: '#94A3B8', fontFamily: 'monospace' }}>:{p}</span>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Protocoles */}
                      {Object.keys(d.typical_protocols || {}).length > 0 && (
                        <div style={{ marginBottom: 12 }}>
                          <div style={{ fontSize: 11, color: '#475569', fontWeight: 700, marginBottom: 6, textTransform: 'uppercase' }}>Répartition protocoles</div>
                          <div style={{ display: 'flex', gap: 10 }}>
                            {Object.entries(d.typical_protocols).map(([proto, ratio]) => (
                              <div key={proto} style={{ textAlign: 'center' }}>
                                <div style={{ fontSize: 13, fontWeight: 700, color: '#3B82F6' }}>{(ratio*100).toFixed(0)}%</div>
                                <div style={{ fontSize: 11, color: '#64748B' }}>{proto}</div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Actions */}
                      <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                        <button onClick={() => resetBaseline(b.ip_address)} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '7px 14px', borderRadius: 8, border: '1px solid #1E2D4F', background: 'transparent', color: '#64748B', cursor: 'pointer', fontSize: 12 }}>
                          <Trash2 size={13} /> Réinitialiser la baseline
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}