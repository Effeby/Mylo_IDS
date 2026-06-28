import { useState, useEffect, useRef } from 'react'
import { useLocation } from 'react-router-dom'
import { Bell, RefreshCw, Filter, CheckCircle, XCircle, AlertTriangle, Calendar, X, RotateCcw, Shield } from 'lucide-react'
import { getAlerts, updateAlertStatus, blockIP, getOrganisationName } from '../api/mylo'
import AlertBadge from '../components/AlertBadge'

const FASTAPI_URL = import.meta.env.VITE_FASTAPI_URL || 'https://mylo-ids.site/api/ml'
const DJANGO_URL  = import.meta.env.VITE_DJANGO_URL  || 'https://mylo-ids.site'

const TYPES = ['', 'DoS', 'DDoS', 'Probe', 'R2L', 'U2R', 'BruteForce', 'WebAttack', 'Botnet', 'Infiltration']

const STATUS_DISPLAY = {
  new:            { label: 'Nouvelle',     color: '#EF4444' },
  under_review:   { label: 'À vérifier',   color: '#F97316' },
  investigating:  { label: 'En cours',     color: '#EAB308' },
  confirmed:      { label: 'Confirmée',    color: '#EF4444' },
  resolved:       { label: 'Résolue',      color: '#22C55E' },
  false_positive: { label: 'Faux positif', color: '#64748B' },
  ignored:        { label: 'Ignorée',      color: '#475569' },
  normal:         { label: 'Normal',       color: '#22C55E' },
}

function formatDate(isoStr) {
  const dt      = new Date(isoStr)
  const now     = new Date()
  const sameYear = now.getFullYear() === dt.getFullYear()
  const date = dt.toLocaleDateString('fr-FR', {
    day: '2-digit', month: '2-digit',
    ...(sameYear ? {} : { year: '2-digit' })
  })
  const time = dt.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  return { line1: date, line2: time }
}

export default function Alerts() {
  const location = useLocation()
  const [alerts, setAlerts]       = useState([])
  const [loading, setLoading]     = useState(false)
  const [selected, setSelected]   = useState(null)
  const [riverFeedback, setRiverFeedback] = useState(null)

  // ── Attack Replay ─────────────────────────────────────────────────
  const [replaying,    setReplaying]    = useState(false)
  const [replayResult, setReplayResult] = useState(null)

  const handleReplay = async (alert) => {
    if (!alert.features || Object.keys(alert.features).length === 0) return
    setReplaying(true)
    setReplayResult(null)
    try {
      const token = localStorage.getItem('mylo_access')
      // Renvoyer les features à FastAPI directement pour une nouvelle prédiction
      const res = await fetch(`${FASTAPI_URL}/predict`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(alert.features),
      })
      const result = await res.json()
      setReplayResult({
        original:  { type: alert.attack_type, confidence: alert.binary_confidence, severity: alert.severity },
        replayed:  {
          type:       result.attack_type,
          confidence: result.binary_confidence,
          severity:   result.severity || alert.severity,
          is_attack:  result.is_attack,
        },
        improved: result.attack_type !== alert.attack_type ||
                  Math.abs(result.binary_confidence - alert.binary_confidence) > 0.05,
      })
    } catch(e) {
      setReplayResult({ error: 'FastAPI non disponible — vérifie que le service tourne sur :8000' })
    } finally {
      setReplaying(false)
    }
  }

  const lastAlertIdRef = useRef(0)

  const playAlertSound = (severity = 'HIGH') => {
    try {
      const files = {
        CRITICAL: '/sounds/alert-critical.wav',
        HIGH:     '/sounds/alert-high.wav',
        MEDIUM:   '/sounds/alert-medium.wav',
      }
      const audio = new Audio(files[severity] || files['HIGH'])
      audio.volume = 0.7
      audio.play().catch(() => {
        const ctx = new (window.AudioContext || window.webkitAudioContext)()
        ;[0, 0.15, 0.30].forEach(delay => {
          const osc  = ctx.createOscillator()
          const gain = ctx.createGain()
          osc.connect(gain); gain.connect(ctx.destination)
          osc.frequency.value = severity === 'CRITICAL' ? 1100 : 880
          osc.type = 'sine'
          gain.gain.setValueAtTime(0.3, ctx.currentTime + delay)
          gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + delay + 0.12)
          osc.start(ctx.currentTime + delay)
          osc.stop(ctx.currentTime + delay + 0.12)
        })
      })
    } catch(e) {}
  }

  useEffect(() => {
    let initialized = false
    const checkNewAttacks = async () => {
      try {
        const data = await getAlerts({ limit: 10 })
        const list = data.results || data
        if (list.length === 0) return
        const latestId = list[0].id
        if (!initialized) {
          lastAlertIdRef.current = latestId
          initialized = true
          return
        }
        const newAttacks = list.filter(a =>
          a.id > lastAlertIdRef.current &&
          a.is_attack &&
          ['HIGH', 'CRITICAL', 'MEDIUM'].includes(a.severity)
        )
        if (newAttacks.length > 0) {
          const worst = newAttacks.sort((a, b) => {
            const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2 }
            return (order[a.severity] || 3) - (order[b.severity] || 3)
          })[0]
          playAlertSound(worst.severity)
          lastAlertIdRef.current = latestId
        } else {
          lastAlertIdRef.current = latestId
        }
      } catch(e) {}
    }
    checkNewAttacks()
    const interval = setInterval(checkNewAttacks, 3000)
    return () => clearInterval(interval)
  }, [])

  const [filterType,      setFilterType]      = useState('')
  const [filterIP,        setFilterIP]        = useState('')
  const [filterStatus,    setFilterStatus]    = useState('')
  const [filterSource,    setFilterSource]    = useState('')
  const [filterDateFrom,  setFilterDateFrom]  = useState('')
  const [filterDateTo,    setFilterDateTo]    = useState('')
  const [filterTimeFrom,  setFilterTimeFrom]  = useState('')
  const [filterTimeTo,    setFilterTimeTo]    = useState('')
  const [showDateFilters, setShowDateFilters] = useState(false)

  useEffect(() => {
    const params = new URLSearchParams(location.search)
    const s  = params.get('status')
    const ip = params.get('ip')
    if (s)  setFilterStatus(s)
    if (ip) { setFilterIP(ip); load(ip) }
  }, [location.search])

  const load = async (overrideIP) => {
    setLoading(true)
    try {
      const params = { limit: 500 }
      if (filterType)             params.attack_type = filterType
      if (overrideIP || filterIP) params.ip          = overrideIP || filterIP
      if (filterStatus)           params.status      = filterStatus
      if (filterSource)           params.source      = filterSource
      if (filterDateFrom)         params.date_from   = filterDateFrom
      if (filterDateTo)           params.date_to     = filterDateTo
      const data = await getAlerts(params)
      setAlerts(data.results || data)
    } catch(e) { console.error(e) }
    finally { setLoading(false) }
  }

  useEffect(() => { load() }, [filterType, filterStatus, filterSource, filterDateFrom, filterDateTo])

  const filteredAlerts = alerts.filter(a => {
    const dt = new Date(a.detected_at)
    const localDate    = dt.getFullYear() + '-' + String(dt.getMonth()+1).padStart(2,'0') + '-' + String(dt.getDate()).padStart(2,'0')
    const localMinutes = dt.getHours() * 60 + dt.getMinutes()
    if (filterDateFrom && localDate < filterDateFrom) return false
    if (filterDateTo   && localDate > filterDateTo)   return false
    if (filterTimeFrom) { const [h,m] = filterTimeFrom.split(':').map(Number); if (localMinutes < h*60+m) return false }
    if (filterTimeTo)   { const [h,m] = filterTimeTo.split(':').map(Number);   if (localMinutes > h*60+m) return false }
    return true
  })

  const resetFilters = () => {
    setFilterType(''); setFilterIP(''); setFilterStatus('')
    setFilterSource('')
    setFilterDateFrom(''); setFilterDateTo('')
    setFilterTimeFrom(''); setFilterTimeTo('')
    window.history.replaceState({}, '', '/alerts')
  }

  const hasActiveFilters = filterType || filterIP || filterStatus ||
    filterSource || filterDateFrom || filterDateTo || filterTimeFrom || filterTimeTo

  const handleBlock = async (ip) => {
    try { await blockIP(ip, 'Bloqué depuis la page alertes'); alert('Bloqué : ' + ip) }
    catch { alert('Erreur lors du blocage') }
  }

  const handleStatus = async (id, newStatus) => {
    try {
      await updateAlertStatus(id, newStatus)
      setAlerts(prev => prev.map(a => a.id === id ? { ...a, status: newStatus } : a))
      if (selected?.id === id) setSelected(prev => ({ ...prev, status: newStatus }))
      if (newStatus === 'false_positive') {
        setRiverFeedback('River a appris : faux positif → Normal')
        setTimeout(() => setRiverFeedback(null), 4000)
      } else if (newStatus === 'confirmed') {
        setRiverFeedback('River a appris : attaque confirmée')
        setTimeout(() => setRiverFeedback(null), 4000)
      }
    } catch(e) { console.error(e) }
  }

  const Chip = ({ label, onRemove }) => (
    <span style={{
      display:'inline-flex', alignItems:'center', gap:4,
      padding:'3px 10px', borderRadius:20, fontSize:11, fontWeight:600,
      background:'rgba(59,130,246,0.15)', border:'1px solid #3B82F6', color:'#3B82F6',
    }}>
      {label}
      <button onClick={onRemove} style={{ background:'none',border:'none',color:'#3B82F6',cursor:'pointer',padding:0 }}>×</button>
    </span>
  )

  return (
    <div className="mylo-page" style={{ color:'#F8FAFC', position:'relative' }}>

      {riverFeedback && (
        <div className="mylo-floating" style={{
          position:'fixed', bottom:32, left:'50%', transform:'translateX(-50%)',
          background:'#1E3A5F', border:'1px solid #3B82F6', borderRadius:10,
          padding:'12px 24px', color:'#93C5FD', fontSize:13, fontWeight:600,
          zIndex:9999, boxShadow:'0 4px 24px rgba(0,0,0,0.4)',
        }}>🧠 {riverFeedback}</div>
      )}

      {/* Header */}
      <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:20, flexWrap:'wrap', gap:12 }}>
        <div>
          <h1 style={{ margin:0, fontSize:22, fontWeight:800 }}>Alertes</h1>
          <p style={{ margin:'4px 0 0', color:'#94A3B8', fontSize:13 }}>
            {filteredAlerts.length} alerte{filteredAlerts.length !== 1 ? 's' : ''}
            {hasActiveFilters ? ' (filtrées)' : ` — ${getOrganisationName()}`}
          </p>
        </div>
        <button onClick={load} style={{
          padding:'8px 16px', borderRadius:8, border:'1px solid #1E2D4F',
          background:'transparent', color:'#94A3B8', cursor:'pointer',
          display:'flex', alignItems:'center', gap:6, fontSize:13,
        }}>
          <RefreshCw size={14} /> Actualiser
        </button>
      </div>

      {/* Filtres */}
      <div style={{ display:'flex', gap:10, marginBottom:10, flexWrap:'wrap', alignItems:'center' }}>
        <select value={filterType} onChange={e => setFilterType(e.target.value)} style={{
          padding:'8px 12px', borderRadius:8, background:'#0F1629',
          border:'1px solid #1E2D4F', color:'#F8FAFC', fontSize:13,
        }}>
          {TYPES.map(t => <option key={t} value={t}>{t || 'Tous les types'}</option>)}
        </select>
        <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)} style={{
          padding:'8px 12px', borderRadius:8, background:'#0F1629',
          border:`1px solid ${filterStatus ? '#EF4444' : '#1E2D4F'}`,
          color: filterStatus ? '#EF4444' : '#F8FAFC', fontSize:13,
        }}>
          <option value="">Tous les statuts</option>
          <option value="new">Nouvelles</option>
          <option value="under_review">À vérifier</option>
          <option value="investigating">En cours</option>
          <option value="confirmed">Confirmées</option>
          <option value="resolved">Résolues</option>
          <option value="false_positive">Faux positifs</option>
        </select>
        <select value={filterSource} onChange={e => setFilterSource(e.target.value)} style={{
          padding:'8px 12px', borderRadius:8, background:'#0F1629',
          border:`1px solid ${filterSource ? '#3B82F6' : '#1E2D4F'}`,
          color: filterSource ? '#3B82F6' : '#F8FAFC', fontSize:13,
        }}>
          <option value="">Toutes sources</option>
          <option value="scapy">Scapy (capture)</option>
          <option value="wazuh">Wazuh (SIEM)</option>
        </select>
        <input value={filterIP} onChange={e => setFilterIP(e.target.value)}
          placeholder="Filtrer par IP..." onKeyDown={e => e.key === 'Enter' && load()}
          style={{ padding:'8px 14px', borderRadius:8, background:'#0F1629', border:'1px solid #1E2D4F', color:'#F8FAFC', fontSize:13, outline:'none', flex:'1 1 160px', maxWidth:220, minWidth:0 }} />
        <button onClick={load} style={{ padding:'8px 14px', borderRadius:8, background:'#3B82F6', border:'none', color:'#fff', cursor:'pointer' }}>
          <Filter size={14} />
        </button>
        <button onClick={() => setShowDateFilters(v => !v)} style={{
          padding:'8px 14px', borderRadius:8,
          background: showDateFilters ? 'rgba(59,130,246,0.15)' : 'transparent',
          border:`1px solid ${showDateFilters ? '#3B82F6' : '#1E2D4F'}`,
          color: showDateFilters ? '#3B82F6' : '#94A3B8',
          cursor:'pointer', display:'flex', alignItems:'center', gap:6, fontSize:12,
        }}>
          <Calendar size={13} /> Date / Heure
        </button>
        {hasActiveFilters && (
          <button onClick={resetFilters} style={{
            padding:'8px 14px', borderRadius:8, background:'transparent',
            border:'1px solid #1E2D4F', color:'#94A3B8', cursor:'pointer', fontSize:12,
            display:'flex', alignItems:'center', gap:5,
          }}><X size={12} /> Réinitialiser</button>
        )}
      </div>

      {showDateFilters && (
        <div style={{ display:'flex', gap:12, marginBottom:12, flexWrap:'wrap', padding:'12px 16px', background:'#0F1629', border:'1px solid #1E2D4F', borderRadius:10, alignItems:'center' }}>
          <div style={{ display:'flex', alignItems:'center', gap:8 }}>
            <span style={{ color:'#64748B', fontSize:12, whiteSpace:'nowrap' }}>Du</span>
            <input type="date" value={filterDateFrom} onChange={e => setFilterDateFrom(e.target.value)} style={{ padding:'6px 10px', borderRadius:6, background:'#0A0E1A', border:'1px solid #1E2D4F', color:'#F8FAFC', fontSize:12, outline:'none' }} />
            <input type="time" value={filterTimeFrom} onChange={e => setFilterTimeFrom(e.target.value)} style={{ padding:'6px 10px', borderRadius:6, background:'#0A0E1A', border:'1px solid #1E2D4F', color:'#F8FAFC', fontSize:12, outline:'none' }} />
          </div>
          <div style={{ display:'flex', alignItems:'center', gap:8 }}>
            <span style={{ color:'#64748B', fontSize:12, whiteSpace:'nowrap' }}>Au</span>
            <input type="date" value={filterDateTo} onChange={e => setFilterDateTo(e.target.value)} style={{ padding:'6px 10px', borderRadius:6, background:'#0A0E1A', border:'1px solid #1E2D4F', color:'#F8FAFC', fontSize:12, outline:'none' }} />
            <input type="time" value={filterTimeTo} onChange={e => setFilterTimeTo(e.target.value)} style={{ padding:'6px 10px', borderRadius:6, background:'#0A0E1A', border:'1px solid #1E2D4F', color:'#F8FAFC', fontSize:12, outline:'none' }} />
          </div>
          <span style={{ color:'#475569', fontSize:11 }}>{filteredAlerts.length} résultat{filteredAlerts.length !== 1 ? 's' : ''}</span>
        </div>
      )}

      {hasActiveFilters && (
        <div style={{ display:'flex', gap:6, flexWrap:'wrap', marginBottom:12 }}>
          {filterType     && <Chip label={`Type: ${filterType}`}      onRemove={() => setFilterType('')} />}
          {filterStatus   && <Chip label={`Statut: ${STATUS_DISPLAY[filterStatus]?.label || filterStatus}`} onRemove={() => setFilterStatus('')} />}
          {filterIP       && <Chip label={`IP: ${filterIP}`}          onRemove={() => setFilterIP('')} />}
          {filterSource   && <Chip label={`Source: ${filterSource}`}  onRemove={() => setFilterSource('')} />}
          {filterDateFrom && <Chip label={`Depuis: ${filterDateFrom}`} onRemove={() => setFilterDateFrom('')} />}
          {filterDateTo   && <Chip label={`Au: ${filterDateTo}`}       onRemove={() => setFilterDateTo('')} />}
          {filterTimeFrom && <Chip label={`Heure ≥ ${filterTimeFrom}`} onRemove={() => setFilterTimeFrom('')} />}
          {filterTimeTo   && <Chip label={`Heure ≤ ${filterTimeTo}`}   onRemove={() => setFilterTimeTo('')} />}
        </div>
      )}

      {/* Table */}
      <div className="mylo-table-scroll" style={{ background:'#0F1629', border:'1px solid #1E2D4F', borderRadius:12 }}>
        <div style={{ minWidth:980 }}>
        <div style={{
          display:'grid', gridTemplateColumns:'140px 1fr 1fr 1fr 90px 1fr 1fr 130px',
          padding:'12px 20px', borderBottom:'1px solid #1E2D4F',
          color:'#475569', fontSize:11, fontWeight:700, letterSpacing:'0.05em',
        }}>
          <span>DATE / HEURE</span><span>IP SOURCE</span><span>TYPE</span>
          <span>SÉVÉRITÉ</span><span>BYTES</span><span>CONFIANCE</span><span>STATUT</span><span>ACTION</span>
        </div>
        {loading ? (
          <div style={{ padding:40, textAlign:'center', color:'#475569' }}>Chargement...</div>
        ) : filteredAlerts.length === 0 ? (
          <div style={{ padding:40, textAlign:'center', color:'#475569' }}>
            <Bell size={32} style={{ marginBottom:8, opacity:0.5 }} />
            <p style={{ margin:0 }}>Aucune alerte trouvée</p>
            {hasActiveFilters && (
              <button onClick={resetFilters} style={{ marginTop:12, padding:'6px 14px', borderRadius:6, background:'transparent', border:'1px solid #1E2D4F', color:'#94A3B8', cursor:'pointer', fontSize:12 }}>Effacer les filtres</button>
            )}
          </div>
        ) : filteredAlerts.map(a => {
          const s = STATUS_DISPLAY[a.status] || STATUS_DISPLAY.new
          return (
            <div key={a.id} onClick={() => { setSelected(a); setReplayResult(null) }} style={{
              display:'grid', gridTemplateColumns:'140px 1fr 1fr 1fr 90px 1fr 1fr 130px',
              padding:'12px 20px', borderBottom:'1px solid #0A0E1A',
              fontSize:13, alignItems:'center', cursor:'pointer',
              background: selected?.id === a.id ? 'rgba(59,130,246,0.08)' : a.status === 'new' ? 'rgba(239,68,68,0.03)' : 'transparent',
              transition:'background 0.15s',
            }}>
              <span style={{ color:'#94A3B8', fontFamily:'monospace', fontSize:11 }}>
                {(() => { const f = formatDate(a.detected_at); return (
                  <>{f.line1 && <div style={{ color:'#F8FAFC', fontWeight:500 }}>{f.line1}</div>}<div style={{ color:'#94A3B8' }}>{f.line2}</div></>
                )})()}
              </span>
              <span style={{ color:'#64748B', fontFamily:'monospace', fontSize:11, display:'flex', alignItems:'center', gap:8 }}>
                <span>{a.src_ip || '—'}</span>
                <span style={{ fontSize:11, padding:'2px 6px', borderRadius:8, display:'inline-flex', alignItems:'center', gap:6, background: a.source === 'wazuh' ? 'rgba(124,58,237,0.12)' : 'rgba(99,102,241,0.08)', color: a.source === 'wazuh' ? '#7C3AED' : '#6366F1', border: '1px solid rgba(255,255,255,0.02)' }} title={a.source || 'scapy'}>
                  {a.source === 'wazuh' ? <Shield size={12} color="#7C3AED" /> : <svg width="12" height="12" viewBox="0 0 8 8" style={{borderRadius:6, display:'block'}}><circle cx="4" cy="4" r="4" fill="#6366F1"/></svg>}
                  <span style={{ lineHeight:1 }}>{a.source || 'scapy'}</span>
                </span>
              </span>
              <span style={{ color:'#F8FAFC', fontWeight:600 }}>{a.attack_type}</span>
              <AlertBadge severity={a.severity} />
              <span style={{ color:'#64748B', fontFamily:'monospace', fontSize:11 }}>
                {a.src_bytes > 0 ? (a.src_bytes > 1024 ? `${(a.src_bytes/1024).toFixed(1)}K` : `${a.src_bytes}B`) : '—'}
              </span>
              <span style={{ color:'#94A3B8', fontFamily:'monospace' }}>{(a.attack_confidence * 100).toFixed(1)}%</span>
              <span style={{ fontSize:11, fontWeight:600, color:s.color }}>{s.label}</span>
              <button onClick={e => { e.stopPropagation(); handleBlock(a.src_ip) }} style={{
                padding:'4px 10px', borderRadius:6, fontSize:11, fontWeight:600,
                background:'rgba(239,68,68,0.15)', border:'1px solid #EF4444',
                color:'#EF4444', cursor:'pointer',
              }}>🔴 Bloquer</button>
            </div>
          )
        })}
        </div>
      </div>

      {/* Panneau détail */}
      {selected && (
        <div className="mylo-panel" style={{
          position:'fixed', top:0, right:0, bottom:0, width:'min(440px, 100vw)',
          background:'#0A0E1A', borderLeft:'1px solid #1E2D4F',
          padding:28, overflowY:'auto', zIndex:100,
        }}>
          <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:24 }}>
            <h2 style={{ margin:0, fontSize:16, fontWeight:800 }}>Alerte #{selected.id}</h2>
            <button onClick={() => setSelected(null)} style={{ background:'none',border:'none',color:'#94A3B8',cursor:'pointer',fontSize:20 }}>✕</button>
          </div>
          <div style={{
            padding:'10px 14px', borderRadius:8, marginBottom:20,
            background:`${(STATUS_DISPLAY[selected.status]||STATUS_DISPLAY.new).color}15`,
            border:`1px solid ${(STATUS_DISPLAY[selected.status]||STATUS_DISPLAY.new).color}40`,
            color:(STATUS_DISPLAY[selected.status]||STATUS_DISPLAY.new).color,
            fontSize:12, fontWeight:700,
          }}>
            Statut : {(STATUS_DISPLAY[selected.status]||STATUS_DISPLAY.new).label}
          </div>

          <Section title="Réseau">
            <Row label="IP Source"        value={selected.src_ip}   mono />
            <Row label="IP Destination"   value={selected.dst_ip}   mono />
            <Row label="Protocole"        value={selected.protocol || '—'} />
            <Row label="Port Source"      value={selected.src_port > 0 ? selected.src_port : '—'} />
            <Row label="Port Destination" value={selected.dst_port > 0 ? selected.dst_port : '—'} />
            <Row label="Src Bytes"        value={selected.src_bytes > 0 ? `${selected.src_bytes} B` : '—'} />
            <Row label="Dst Bytes"        value={selected.dst_bytes > 0 ? `${selected.dst_bytes} B` : '—'} />
            <Row label="Total trafic"     value={selected.src_bytes + selected.dst_bytes > 0 ? `${selected.src_bytes + selected.dst_bytes} B` : '—'} />
            <Row label="Durée"            value={selected.duration > 0 ? `${selected.duration.toFixed(3)}s` : '< 1s'} />
          </Section>

          <Section title="Statistiques réseau">
            <Row label="Fréquence"       value={selected.features?.count !== undefined ? `${selected.features.count} conn/2s` : '—'} />
            <Row label="Nb services"     value={selected.features?.srv_count ?? '—'} />
            <Row label="Taux erreur SYN" value={selected.features?.serror_rate !== undefined ? `${(selected.features.serror_rate*100).toFixed(1)}%` : '—'} />
            <Row label="Taux erreur RST" value={selected.features?.rerror_rate !== undefined ? `${(selected.features.rerror_rate*100).toFixed(1)}%` : '—'} />
            <Row label="Même service"    value={selected.features?.same_srv_rate !== undefined ? `${(selected.features.same_srv_rate*100).toFixed(1)}%` : '—'} />
            <Row label="Diff services"   value={selected.features?.diff_srv_rate !== undefined ? `${(selected.features.diff_srv_rate*100).toFixed(1)}%` : '—'} />
            <Row label="Bytes/paquet"    value={selected.features?.bytes_per_packet !== undefined ? `${selected.features.bytes_per_packet.toFixed(1)} B` : '—'} />
            <Row label="Ratio bytes"     value={selected.features?.bytes_ratio !== undefined ? selected.features.bytes_ratio.toFixed(2) : '—'} />
            <Row label="Connecté"        value={selected.features?.logged_in === 1 ? '✅ Oui' : selected.features?.logged_in === 0 ? '❌ Non' : '—'} />
          </Section>

          <Section title="Prédiction ML">
            <Row label="Classe"            value={selected.attack_type} />
            <Row label="Sévérité"          value={selected.severity} />
            <Row label="Confiance binaire" value={`${(selected.binary_confidence*100).toFixed(2)}%`} />
            <Row label={`Confiance "${selected.attack_type}"`} value={`${(selected.attack_confidence*100).toFixed(2)}%`} />
          </Section>

          {selected.features?.anomaly_detail && (
            <Section title="Anomalie comportementale">
              <Row label="Type"   value={selected.features.anomaly_type || '—'} />
              <Row label="Détail" value={selected.features.anomaly_detail || '—'} />
              {Array.isArray(selected.features.anomalies) && selected.features.anomalies.length > 0 && (
                <div style={{ display:'grid', gap:8, marginTop:8 }}>
                  {selected.features.anomalies.map((a, idx) => (
                    <div key={idx} style={{ padding:'10px', borderRadius:10, background:'#0F1629', border:'1px solid #1E2D4F' }}>
                      <div style={{ fontSize:12, fontWeight:700, color:'#F8FAFC' }}>{a.type || `Anomalie ${idx + 1}`}</div>
                      <div style={{ fontSize:12, color:'#94A3B8', marginTop:4 }}>{a.detail || JSON.stringify(a)}</div>
                      {a.z_score !== undefined && <div style={{ fontSize:11, color:'#64748B', marginTop:4 }}>Z-score: {a.z_score}</div>}
                      {a.severity && <div style={{ fontSize:11, color:'#64748B' }}>Sévérité: {a.severity}</div>}
                    </div>
                  ))}
                </div>
              )}
            </Section>
          )}

          {/* ── ATTACK REPLAY ─────────────────────────────────────── */}
          <Section title="Attack Replay — Rejouer avec le modèle actuel">
            <p style={{ color:'#64748B', fontSize:12, margin:'0 0 12px' }}>
              Rejoue les features de cette alerte dans XGBoost pour voir si le modèle a évolué depuis River.
            </p>
            <button
              onClick={() => handleReplay(selected)}
              disabled={replaying || !selected.features || Object.keys(selected.features).length === 0}
              style={{
                width:'100%', padding:'10px 14px', borderRadius:8, fontSize:13, fontWeight:700,
                background: replaying ? 'rgba(59,130,246,0.05)' : 'rgba(59,130,246,0.15)',
                border:'1px solid #3B82F6', color:'#3B82F6',
                cursor: replaying ? 'not-allowed' : 'pointer',
                display:'flex', alignItems:'center', justifyContent:'center', gap:8,
              }}
            >
              <RotateCcw size={15} style={{ animation: replaying ? 'spin 1s linear infinite' : 'none' }} />
              {replaying ? 'Analyse en cours...' : '▶ Rejouer cette alerte'}
            </button>

            {/* Résultat du replay */}
            {replayResult && !replayResult.error && (
              <div style={{ marginTop:12, padding:'14px', borderRadius:8, background:'#0F1629', border:'1px solid #1E2D4F' }}>
                <div style={{ fontSize:11, color:'#475569', fontWeight:700, marginBottom:10, letterSpacing:'0.05em' }}>
                  RÉSULTAT DU REPLAY
                </div>
                <div className="mylo-grid-2" style={{ gap:8 }}>
                  {/* Original */}
                  <div style={{ padding:'10px', borderRadius:6, background:'rgba(100,116,139,0.1)', border:'1px solid #1E2D4F' }}>
                    <div style={{ fontSize:10, color:'#475569', marginBottom:6, fontWeight:700 }}>ORIGINAL</div>
                    <div style={{ fontSize:14, fontWeight:800, color:'#94A3B8' }}>{replayResult.original.type}</div>
                    <div style={{ fontSize:11, color:'#64748B', marginTop:2 }}>{(replayResult.original.confidence*100).toFixed(1)}% confiance</div>
                  </div>
                  {/* Replay */}
                  <div style={{
                    padding:'10px', borderRadius:6,
                    background: replayResult.improved ? 'rgba(59,130,246,0.1)' : 'rgba(34,197,94,0.1)',
                    border:`1px solid ${replayResult.improved ? '#3B82F6' : '#22C55E'}`,
                  }}>
                    <div style={{ fontSize:10, color: replayResult.improved ? '#3B82F6' : '#22C55E', marginBottom:6, fontWeight:700 }}>
                      MODÈLE ACTUEL {replayResult.improved ? '⚡ CHANGÉ' : '✓ STABLE'}
                    </div>
                    <div style={{ fontSize:14, fontWeight:800, color: replayResult.replayed.is_attack ? '#EF4444' : '#22C55E' }}>
                      {replayResult.replayed.type}
                    </div>
                    <div style={{ fontSize:11, color:'#64748B', marginTop:2 }}>{(replayResult.replayed.confidence*100).toFixed(1)}% confiance</div>
                  </div>
                </div>
                {replayResult.improved && (
                  <div style={{ marginTop:8, padding:'8px 12px', borderRadius:6, background:'rgba(59,130,246,0.08)', border:'1px solid #3B82F6', fontSize:11, color:'#93C5FD' }}>
                    🧠 Le modèle a évolué depuis cette alerte — River a amélioré la détection !
                  </div>
                )}
                {!replayResult.improved && (
                  <div style={{ marginTop:8, padding:'8px 12px', borderRadius:6, background:'rgba(34,197,94,0.08)', border:'1px solid #22C55E', fontSize:11, color:'#86EFAC' }}>
                    ✓ Prédiction stable — le modèle reste cohérent sur ce pattern.
                  </div>
                )}
              </div>
            )}

            {replayResult?.error && (
              <div style={{ marginTop:10, padding:'10px 14px', borderRadius:8, background:'rgba(239,68,68,0.1)', border:'1px solid #EF4444', color:'#EF4444', fontSize:12 }}>
                ❌ {replayResult.error}
              </div>
            )}
          </Section>

          {selected.features && Object.keys(selected.features).length > 0 && (
            <Section title="Features ML">
              {Object.entries(selected.features).slice(0, 10).map(([k, v]) => (
                <Row key={k} label={k} value={typeof v === 'number' ? v.toFixed(4) : v} mono />
              ))}
            </Section>
          )}

          <Section title="Feedback pour River (apprentissage)">
            <p style={{ color:'#64748B', fontSize:12, margin:'0 0 12px' }}>Ton feedback entraîne River à mieux détecter.</p>
            <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
              <button onClick={() => handleStatus(selected.id, 'false_positive')} style={{
                padding:'10px 14px', borderRadius:8, fontSize:13, fontWeight:700,
                background:'rgba(100,116,139,0.15)', border:'1px solid #64748B',
                color:'#94A3B8', cursor:'pointer', display:'flex', alignItems:'center', gap:8,
              }}><XCircle size={15} /> Faux positif — River apprend "Normal"</button>
              <button onClick={() => handleStatus(selected.id, 'confirmed')} style={{
                padding:'10px 14px', borderRadius:8, fontSize:13, fontWeight:700,
                background:'rgba(239,68,68,0.15)', border:'1px solid #EF4444',
                color:'#EF4444', cursor:'pointer', display:'flex', alignItems:'center', gap:8,
              }}><CheckCircle size={15} /> Confirmer attaque — River apprend "{selected.attack_type}"</button>
              <button onClick={() => handleStatus(selected.id, 'investigating')} style={{
                padding:'10px 14px', borderRadius:8, fontSize:13, fontWeight:700,
                background:'rgba(234,179,8,0.15)', border:'1px solid #EAB308',
                color:'#EAB308', cursor:'pointer', display:'flex', alignItems:'center', gap:8,
              }}><AlertTriangle size={15} /> En cours d'investigation</button>
            </div>
          </Section>

          <button onClick={() => handleBlock(selected.src_ip)} style={{
            width:'100%', padding:'12px', borderRadius:8, marginTop:8,
            background:'rgba(239,68,68,0.15)', border:'1px solid #EF4444',
            color:'#EF4444', fontWeight:700, cursor:'pointer', fontSize:13,
          }}>🔴 Blacklister {selected.src_ip}</button>

          <style>{`@keyframes spin { from { transform: rotate(0deg) } to { transform: rotate(360deg) } }`}</style>
        </div>
      )}
    </div>
  )
}

function Section({ title, children }) {
  return (
    <div style={{ marginBottom:24 }}>
      <div style={{ fontSize:11, color:'#475569', fontWeight:700, marginBottom:10, letterSpacing:'0.05em' }}>
        {title.toUpperCase()}
      </div>
      <div style={{ display:'flex', flexDirection:'column', gap:8 }}>{children}</div>
    </div>
  )
}

function Row({ label, value, mono }) {
  const renderValue = () => {
    if (value === null || value === undefined) return '—'
    if (typeof value === 'number' || typeof value === 'string') return value
    if (typeof value === 'boolean') return value ? 'true' : 'false'
    if (Array.isArray(value)) return value.join(', ')
    try {
      return JSON.stringify(value)
    } catch {
      return String(value)
    }
  }

  return (
    <div style={{ display:'flex', justifyContent:'space-between', fontSize:13 }}>
      <span style={{ color:'#64748B' }}>{label}</span>
      <span style={{ color:'#F8FAFC', fontFamily: mono ? 'monospace' : 'inherit', fontSize: mono ? 12 : 13 }}>
        {renderValue()}
      </span>
    </div>
  )
}