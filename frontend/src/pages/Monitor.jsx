import { useState, useMemo } from 'react'
import { Activity, Wifi, AlertTriangle, CheckCircle, Search, Filter, Ban, X, Shield } from 'lucide-react'
import { useMonitor } from '../context/MonitorContext'
import AlertBadge from '../components/AlertBadge'
import { blockIP, getOrganisationName } from '../api/mylo'

const ATTACK_TYPES = ['Tous', 'DoS', 'DDoS', 'Probe', 'R2L', 'U2R', 'BruteForce', 'WebAttack', 'Botnet', 'Infiltration', 'Normal']

const COLORS = {
  Normal:       '#22C55E',
  DoS:          '#EF4444',
  DDoS:         '#DC2626',
  Probe:        '#EAB308',
  R2L:          '#F97316',
  U2R:          '#A855F7',
  BruteForce:   '#EC4899',
  WebAttack:    '#14B8A6',
  Botnet:       '#F43F5E',
  Infiltration: '#8B5CF6',
}


// Affiche toujours date + heure — année uniquement si différente de l'année en cours
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

export default function Monitor() {
  const { results, running, stats, captureOk, start, stop } = useMonitor()

  // ─── Filtres ──────────────────────────────────────────────────────
  const [search,     setSearch]     = useState('')
  const [typeFilter, setTypeFilter] = useState('Tous')
  const [onlyAttacks, setOnlyAttacks] = useState(false)

  // ─── Blocage IP ───────────────────────────────────────────────────
  const [blocking,   setBlocking]   = useState(null)   // IP en cours
  const [blocked,    setBlocked]    = useState(new Set())
  const [blockMsg,   setBlockMsg]   = useState(null)

  const handleBlock = async (ip) => {
    if (!ip || blocked.has(ip)) return
    setBlocking(ip)
    try {
      await blockIP(ip, 'Bloqué depuis Monitor temps réel')
      setBlocked(prev => new Set([...prev, ip]))
      setBlockMsg({ ip, ok: true })
    } catch {
      setBlockMsg({ ip, ok: false })
    } finally {
      setBlocking(null)
      setTimeout(() => setBlockMsg(null), 3000)
    }
  }

  // ─── Données filtrées ─────────────────────────────────────────────
  const filtered = useMemo(() => {
    return results.filter(r => {
      if (onlyAttacks && !r.is_attack) return false
      if (typeFilter !== 'Tous' && r.attack_type !== typeFilter) return false
      if (search) {
        const q = search.toLowerCase()
        return (
          (r.src_ip || '').includes(q) ||
          (r.dst_ip || '').includes(q) ||
          (r.attack_type || '').toLowerCase().includes(q)
        )
      }
      return true
    })
  }, [results, search, typeFilter, onlyAttacks])

  return (
    <div className="mylo-page" style={{ color: '#F8FAFC' }}>

      {/* ── Header ── */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 28, flexWrap: 'wrap', gap: 16 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 22, fontWeight: 800 }}>Moniteur en direct</h1>
          <p style={{ margin: '4px 0 0', color: '#94A3B8', fontSize: 13 }}>
            Analyse du trafic réseau en temps réel — {getOrganisationName()}
          </p>
        </div>
        <button onClick={running ? stop : start} style={{
          padding: '10px 24px', borderRadius: 8, fontWeight: 700, fontSize: 14,
          border: 'none', cursor: 'pointer',
          background: running ? '#EF4444' : '#22C55E',
          color: '#fff', display: 'flex', alignItems: 'center', gap: 8,
        }}>
          {running ? '⏹ Arrêter' : '▶ Démarrer'}
        </button>
      </div>

      {/* ── KPI Cards ── */}
      <div className="mylo-grid-cards" style={{ gap: 16, marginBottom: 24 }}>
        {[
          { label: 'Total analysé', value: stats.total,   icon: Wifi,         color: '#3B82F6' },
          { label: 'Alertes',      value: stats.attacks, icon: AlertTriangle, color: '#EF4444' },
          { label: 'Normal',        value: stats.normal,  icon: CheckCircle,   color: '#22C55E' },
          {
            label: 'Taux d\'attaque',
            value: stats.total > 0 ? `${((stats.attacks / stats.total) * 100).toFixed(1)}%` : '—',
            icon: Activity, color: '#F97316',
          },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} style={{
            background: '#0F1629', border: '1px solid #1E2D4F', borderRadius: 12, padding: 20,
            display: 'flex', alignItems: 'center', gap: 16,
          }}>
            <div style={{
              width: 44, height: 44, borderRadius: 10,
              background: `${color}20`, display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <Icon size={22} color={color} />
            </div>
            <div>
              <div style={{ fontSize: 26, fontWeight: 800, color }}>{value}</div>
              <div style={{ fontSize: 12, color: '#94A3B8' }}>{label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* ── Status bar ── */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16, fontSize: 13,
        color: !running ? '#94A3B8' : captureOk === false ? '#EF4444' : '#22C55E',
      }}>
        <div style={{
          width: 8, height: 8, borderRadius: '50%',
          background: !running ? '#475569' : captureOk === false ? '#EF4444' : '#22C55E',
          animation: running && captureOk !== false ? 'pulse 2s infinite' : 'none',
        }} />
        {!running
          ? 'Moniteur arrêté — lance capture.py en admin puis clique Démarrer'
          : captureOk === false
          ? '⚠ Aucun trafic reçu — vérifie que capture.py tourne en admin'
          : `Analyse en cours... ${filtered.length} événement${filtered.length > 1 ? 's' : ''} affiché${filtered.length > 1 ? 's' : ''}`}
      </div>

      {/* ── Toast blocage IP ── */}
      {blockMsg && (
        <div style={{
          position: 'fixed', top: 24, right: 24, zIndex: 9999,
          padding: '12px 20px', borderRadius: 10, fontSize: 13, fontWeight: 600,
          background: blockMsg.ok ? 'rgba(34,197,94,0.15)' : 'rgba(239,68,68,0.15)',
          border: `1px solid ${blockMsg.ok ? '#22C55E' : '#EF4444'}`,
          color: blockMsg.ok ? '#22C55E' : '#EF4444',
        }}>
          {blockMsg.ok ? `✅ ${blockMsg.ip} bloquée` : `❌ Erreur blocage ${blockMsg.ip}`}
        </div>
      )}

      {/* ── Filtres ── */}
      <div style={{
        display: 'flex', gap: 12, marginBottom: 16, alignItems: 'center', flexWrap: 'wrap',
      }}>
        {/* Recherche IP */}
        <div style={{ position: 'relative', flex: 1, minWidth: 200 }}>
          <Search size={14} style={{
            position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)',
            color: '#475569',
          }} />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Rechercher IP ou type..."
            style={{
              width: '100%', padding: '9px 12px 9px 34px',
              background: '#0F1629', border: '1px solid #1E2D4F',
              borderRadius: 8, color: '#F8FAFC', fontSize: 13, outline: 'none',
              boxSizing: 'border-box',
            }}
          />
          {search && (
            <button onClick={() => setSearch('')} style={{
              position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)',
              background: 'none', border: 'none', color: '#475569', cursor: 'pointer', padding: 0,
            }}>
              <X size={14} />
            </button>
          )}
        </div>

        {/* Filtre type */}
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {ATTACK_TYPES.map(t => (
            <button key={t} onClick={() => setTypeFilter(t)} style={{
              padding: '6px 12px', borderRadius: 20, fontSize: 11, fontWeight: 600,
              border: `1px solid ${typeFilter === t ? (COLORS[t] || '#3B82F6') : '#1E2D4F'}`,
              background: typeFilter === t ? `${(COLORS[t] || '#3B82F6')}20` : 'transparent',
              color: typeFilter === t ? (COLORS[t] || '#3B82F6') : '#64748B',
              cursor: 'pointer', whiteSpace: 'nowrap',
            }}>
              {t}
            </button>
          ))}
        </div>

        {/* Toggle attaques seulement */}
        <button onClick={() => setOnlyAttacks(v => !v)} style={{
          padding: '7px 14px', borderRadius: 8, fontSize: 12, fontWeight: 600,
          border: `1px solid ${onlyAttacks ? '#EF4444' : '#1E2D4F'}`,
          background: onlyAttacks ? 'rgba(239,68,68,0.1)' : 'transparent',
          color: onlyAttacks ? '#EF4444' : '#64748B',
          cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6,
          whiteSpace: 'nowrap',
        }}>
          <Filter size={12} />
          Alertes seulement
        </button>
      </div>

      {/* ── Table ── */}
      <div className="mylo-table-scroll" style={{ background: '#0F1629', border: '1px solid #1E2D4F', borderRadius: 12 }}>
        <div style={{ minWidth: 880 }}>

        {/* Header table */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '100px 1fr 1fr 130px 110px 100px 100px',
          padding: '12px 20px', borderBottom: '1px solid #1E2D4F',
          color: '#475569', fontSize: 11, fontWeight: 700, letterSpacing: '0.06em',
        }}>
          <span>DATE/HEURE</span>
          <span>IP SOURCE</span>
          <span>IP DESTINATION</span>
          <span>TYPE</span>
          <span>SÉVÉRITÉ</span>
          <span>CONFIANCE</span>
          <span>ACTION</span>
        </div>

        {/* Lignes */}
        {filtered.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', color: '#475569' }}>
            <Activity size={32} style={{ marginBottom: 8, opacity: 0.4 }} />
            <p style={{ margin: 0, fontSize: 14 }}>
              {!running
                ? 'Lance le moniteur pour analyser le trafic'
                : search || typeFilter !== 'Tous' || onlyAttacks
                ? 'Aucun résultat pour ces filtres'
                : 'En attente du trafic de capture.py...'}
            </p>
            {running && !search && typeFilter === 'Tous' && (
              <p style={{ margin: '8px 0 0', fontSize: 12, color: '#334155' }}>
                Lance <code style={{ color: '#60A5FA' }}>python ml/capture.py</code> en PowerShell admin
              </p>
            )}
          </div>
        ) : (
          filtered.map(r => {
            const typeColor = COLORS[r.attack_type] || '#94A3B8'
            const isBlocked = blocked.has(r.src_ip)
            return (
              <div key={r.id} style={{
                display: 'grid',
                gridTemplateColumns: '100px 1fr 1fr 130px 110px 100px 100px',
                padding: '11px 20px', borderBottom: '1px solid #0A0E1A',
                fontSize: 13, alignItems: 'center',
                background: r.is_attack
                  ? 'rgba(239,68,68,0.03)'
                  : 'transparent',
                transition: 'background 0.2s',
              }}>
                {/* Heure */}
                <div style={{ fontFamily: 'monospace', fontSize: 11 }}>
                  {(() => { const f = formatDate(r.detected_at); return (
                    <>
                      {f.line1 && <div style={{ color: '#F8FAFC', fontWeight: 500 }}>{f.line1}</div>}
                      <div style={{ color: '#94A3B8' }}>{f.line2}</div>
                    </>
                  )})()}
                </div>

                {/* IP Source */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  {r.is_attack && (
                    <div style={{
                      width: 6, height: 6, borderRadius: '50%',
                      background: typeColor, flexShrink: 0,
                    }} />
                  )}
                  <div style={{ display:'flex', alignItems:'center', gap:8 }}>
                    <span style={{
                      fontFamily: 'monospace', fontSize: 12,
                      color: r.is_attack ? '#F8FAFC' : '#64748B',
                    }}>{r.src_ip || '—'}</span>
                    <span style={{ fontSize:11, padding:'2px 6px', borderRadius:8, display:'inline-flex', alignItems:'center', gap:6, background: r.source === 'wazuh' ? 'rgba(124,58,237,0.12)' : 'rgba(99,102,241,0.08)', color: r.source === 'wazuh' ? '#7C3AED' : '#6366F1' }} title={r.source || 'scapy'}>
                      {r.source === 'wazuh' ? <Shield size={12} color="#7C3AED" /> : <svg width="12" height="12" viewBox="0 0 8 8" style={{borderRadius:6, display:'block'}}><circle cx="4" cy="4" r="4" fill="#6366F1"/></svg>}
                      <span style={{ lineHeight:1 }}>{r.source || 'scapy'}</span>
                    </span>
                  </div>
                </div>

                {/* IP Destination */}
                <span style={{ fontFamily: 'monospace', fontSize: 12, color: '#64748B' }}>
                  {r.dst_ip || '—'}
                </span>

                {/* Type */}
                <span style={{
                  color: typeColor, fontWeight: 600, fontSize: 12,
                  display: 'flex', alignItems: 'center', gap: 4,
                }}>
                  {r.attack_type === 'Behavioral' ? (
                    <span style={{ color: '#A855F7' }}>
                      Anomalie <span style={{ fontSize: 10, color: '#64748B' }}>⬡ Comportemental</span>
                    </span>
                  ) : r.attack_type}
                </span>

                {/* Sévérité */}
                <AlertBadge severity={r.severity} />

                {/* Confiance */}
                <span style={{ fontFamily: 'monospace', fontSize: 12, color: '#94A3B8' }}>
                  {r.is_attack
                    ? `${(r.binary_confidence * 100).toFixed(1)}%`
                    : `${(r.attack_confidence * 100).toFixed(1)}%`}
                </span>

                {/* Action — Bloquer IP */}
                {r.is_attack && r.src_ip ? (
                  <button
                    onClick={() => handleBlock(r.src_ip)}
                    disabled={blocking === r.src_ip || isBlocked}
                    title={isBlocked ? 'IP déjà bloquée' : `Bloquer ${r.src_ip}`}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 5,
                      padding: '4px 10px', borderRadius: 6, fontSize: 11, fontWeight: 600,
                      border: `1px solid ${isBlocked ? '#22C55E' : '#EF4444'}`,
                      background: isBlocked
                        ? 'rgba(34,197,94,0.1)'
                        : blocking === r.src_ip
                        ? 'rgba(239,68,68,0.05)'
                        : 'rgba(239,68,68,0.1)',
                      color: isBlocked ? '#22C55E' : '#EF4444',
                      cursor: isBlocked || blocking === r.src_ip ? 'not-allowed' : 'pointer',
                      transition: 'all 0.2s',
                    }}
                  >
                    <Ban size={11} />
                    {isBlocked ? 'Bloquée' : blocking === r.src_ip ? '...' : 'Bloquer'}
                  </button>
                ) : (
                  <span style={{ color: '#1E2D4F', fontSize: 11 }}>—</span>
                )}
              </div>
            )
          })
        )}
        </div>
      </div>

      {/* Résumé filtres */}
      {(search || typeFilter !== 'Tous' || onlyAttacks) && results.length > 0 && (
        <div style={{ marginTop: 12, fontSize: 12, color: '#475569', textAlign: 'right' }}>
          {filtered.length} / {results.length} événements affichés
          <button onClick={() => { setSearch(''); setTypeFilter('Tous'); setOnlyAttacks(false) }}
            style={{
              marginLeft: 12, color: '#3B82F6', background: 'none',
              border: 'none', cursor: 'pointer', fontSize: 12,
            }}>
            Réinitialiser les filtres
          </button>
        </div>
      )}
    </div>
  )
}