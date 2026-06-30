import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { PieChart, Pie, Cell, BarChart, Bar, LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend } from 'recharts'
import { getAlertStats, getRiverStatus } from '../api/mylo'
import { Brain, RefreshCw, FileDown, FileText } from 'lucide-react'

const COLORS = {
  Normal:      '#22C55E',
  DoS:         '#EF4444',
  DDoS:        '#DC2626',
  Probe:       '#EAB308',
  R2L:         '#F97316',
  U2R:         '#A855F7',
  BruteForce:  '#EC4899',
  WebAttack:   '#14B8A6',
  Botnet:      '#F43F5E',
  Infiltration:'#8B5CF6',
}

export default function Stats() {
  const [stats, setStats]     = useState(null)
  const [timeline, setTimeline] = useState([])
  const [tlTypes, setTlTypes]   = useState([])
  const [river, setRiver]     = useState(null)
  const [loading, setLoading] = useState(true)
  const navigate    = useNavigate()
  const [generating, setGenerating] = useState(false)

  const downloadPDF = async () => {
    setGenerating(true)
    try {
      const token = localStorage.getItem('mylo_access')
      const res = await fetch('https://mylo-ids.site/api/reports/pdf/', {
        headers: { Authorization: `Bearer ${token}` }
      })
      if (!res.ok) throw new Error('Erreur génération PDF')
      const blob = await res.blob()
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href     = url
      a.download = `mylo_rapport_${new Date().toISOString().slice(0,10)}.pdf`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      alert('Erreur : ' + e.message)
    } finally {
      setGenerating(false)
    }
  }

  const downloadCSV = () => {
    const token = localStorage.getItem('mylo_access')
    const a = document.createElement('a')
    a.href = `https://mylo-ids.site/api/reports/export/csv/?token=${token}`
    // Utiliser fetch pour les téléchargements authentifiés
    fetch('https://mylo-ids.site/api/reports/export/csv/', {
      headers: { Authorization: `Bearer ${token}` }
    }).then(r => r.blob()).then(blob => {
      const url = URL.createObjectURL(blob)
      a.href = url
      a.download = `mylo_alertes_${new Date().toISOString().slice(0,10)}.csv`
      a.click()
      URL.revokeObjectURL(url)
    })
  }

  const load = async (silent = false) => {
    if (!silent) setLoading(true)
    try {
      const token = localStorage.getItem('mylo_access')
      const [s, r, tl] = await Promise.all([
        getAlertStats(),
        getRiverStatus(),
        fetch('https://mylo-ids.site/api/alerts/timeline/?hours=24', {
          headers: { Authorization: `Bearer ${token}` }
        }).then(r => r.json()),
      ])
      setStats(s)
      setRiver(r)
      if (tl?.timeline) { setTimeline(tl.timeline); setTlTypes(tl.attack_types || []) }
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
    // Auto-refresh toutes les 15 secondes, sans réafficher l'écran de chargement
    const interval = setInterval(() => load(true), 15_000)
    return () => clearInterval(interval)
  }, [])

  if (loading) return (
    <div style={{ padding: 32, color: 'var(--text-secondary)' }}>Chargement des statistiques...</div>
  )

  if (!stats) return (
    <div style={{ padding: 32, color: '#EF4444' }}>
      Erreur de connexion au backend Django (port 8001)
    </div>
  )

  const byType     = stats.by_type     || {}
  const bySeverity = stats.by_severity || {}

  const pieData = Object.entries(byType)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }))

  const barData = Object.entries(byType).map(([name, value]) => ({
    name, value, fill: COLORS[name] || '#3B82F6',
  }))

  const severityData = [
    { name: 'CRITICAL', value: bySeverity.CRITICAL || 0, fill: '#EF4444' },
    { name: 'HIGH',     value: bySeverity.HIGH     || 0, fill: '#F97316' },
    { name: 'MEDIUM',   value: bySeverity.MEDIUM   || 0, fill: '#EAB308' },
    { name: 'LOW',      value: bySeverity.LOW      || 0, fill: '#22C55E' },
  ].filter(d => d.value > 0)

  return (
    <div className="mylo-page" style={{ color: 'var(--text-primary)' }}>

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 28, flexWrap: 'wrap', gap: 16 }}>
        <div>
          <h1 style={{ margin: '0 0 8px', fontSize: 22, fontWeight: 800 }}>Statistiques</h1>
          <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: 13 }}>
            Vue d'ensemble — 9 classes d'attaques
            <span style={{ marginLeft: 12, color: 'var(--text-faint)', fontSize: 11 }}>
              · Rafraîchissement auto toutes les 15s
            </span>
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          <button onClick={downloadCSV} style={{
            padding: '8px 14px', borderRadius: 8, border: '1px solid var(--border-color)',
            background: 'transparent', color: 'var(--text-secondary)', cursor: 'pointer',
            display: 'flex', alignItems: 'center', gap: 6, fontSize: 13,
          }}>
            <FileText size={14} /> CSV
          </button>
          <button onClick={downloadPDF} disabled={generating} style={{
            padding: '8px 16px', borderRadius: 8, border: 'none',
            background: generating ? '#1E3A6E' : '#3B82F6',
            color: '#fff', cursor: generating ? 'not-allowed' : 'pointer',
            display: 'flex', alignItems: 'center', gap: 6, fontSize: 13, fontWeight: 600,
          }}>
            <FileDown size={14} />
            {generating ? 'Génération...' : 'Rapport PDF'}
          </button>
          <button onClick={load} style={{
            padding: '8px 14px', borderRadius: 8, border: '1px solid var(--border-color)',
            background: 'transparent', color: 'var(--text-secondary)', cursor: 'pointer',
            display: 'flex', alignItems: 'center', gap: 6, fontSize: 13,
          }}>
            <RefreshCw size={14} /> Actualiser
          </button>
        </div>
      </div>

      {/* KPI */}
      <div className="mylo-grid-cards" style={{ gap: 16, marginBottom: 28 }}>
        {[
          { label: 'Total analysé',   value: stats.total,   color: '#3B82F6' },
          { label: 'Alertes',        value: stats.attacks, color: '#EF4444' },
          { label: 'Normal',          value: stats.normal,  color: '#22C55E' },
          { label: "Taux d'attaque",  value: `${(stats.attack_rate * 100).toFixed(1)}%`, color: '#F97316' },
        ].map(({ label, value, color }) => (
          <div key={label} style={{
            background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: 12, padding: '20px 24px',
          }}>
            <div style={{ fontSize: 28, fontWeight: 800, color }}>{value}</div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>{label}</div>
          </div>
        ))}
      </div>

      {/* Alertes non traitées — cliquable */}
      {stats.new_alerts > 0 && (
        <div
          onClick={() => navigate('/alerts?status=new')}
          style={{
            padding: '12px 20px', borderRadius: 10, marginBottom: 20,
            background: 'rgba(239,68,68,0.1)', border: '1px solid #EF4444',
            color: '#EF4444', fontWeight: 600, fontSize: 14,
            cursor: 'pointer',
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            transition: 'background 0.2s',
          }}
          onMouseEnter={e => e.currentTarget.style.background = 'rgba(239,68,68,0.18)'}
          onMouseLeave={e => e.currentTarget.style.background = 'rgba(239,68,68,0.1)'}
        >
          <span>
            🚨 {stats.new_alerts} alerte{stats.new_alerts > 1 ? 's' : ''} non traitée{stats.new_alerts > 1 ? 's' : ''}
          </span>
          <span style={{ fontSize: 12, opacity: 0.8, display: 'flex', alignItems: 'center', gap: 4 }}>
            Voir toutes →
          </span>
        </div>
      )}

      {/* Timeline attaques 24h */}
      <div style={{ background:'var(--bg-card)', border:'1px solid var(--border-color)', borderRadius:12, padding:24, marginBottom:20 }}>
        <h3 style={{ margin:'0 0 20px', fontSize:14, color:'var(--text-secondary)', fontWeight:600, letterSpacing:'0.05em' }}>
          TIMELINE DES ATTAQUES — 24 DERNIÈRES HEURES
          <span style={{ marginLeft:12, fontSize:11, color:'var(--text-muted)', fontWeight:400 }}>
            {timeline.filter(t => t.total > 0).length > 0
              ? `${timeline.reduce((s,t) => s+t.total, 0)} attaques détectées`
              : 'Aucune attaque sur 24h — réseau calme ✓'}
          </span>
        </h3>
        <ResponsiveContainer width="100%" height={200}>
          <LineChart data={timeline} margin={{ top:0, right:10, left:-20, bottom:0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" />
            <XAxis dataKey="hour" tick={{ fill:'var(--text-muted)', fontSize:9 }} axisLine={false} tickLine={false}
              interval={Math.floor((timeline.length || 1) / 8)} />
            <YAxis tick={{ fill:'var(--text-muted)', fontSize:9 }} axisLine={false} tickLine={false} allowDecimals={false} />
            <Tooltip contentStyle={{ background:'var(--bg-card)', border:'1px solid var(--border-color)', borderRadius:8, color:'var(--text-primary)', fontSize:11 }}
              labelStyle={{ color:'var(--text-secondary)' }} />
            <Line type="monotone" dataKey="total" stroke="#3B82F6" strokeWidth={2}
              dot={false} name="Total" />
            {tlTypes.slice(0, 4).map(t => (
              <Line key={t} type="monotone" dataKey={t}
                stroke={COLORS[t] || 'var(--text-secondary)'} strokeWidth={1.5}
                dot={false} name={t} />
            ))}
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Graphiques */}
      <div className="mylo-grid-2" style={{ gap: 16, marginBottom: 20 }}>
        {/* Pie — types */}
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: 12, padding: 24 }}>
          <h3 style={{ margin: '0 0 20px', fontSize: 14, color: 'var(--text-secondary)', fontWeight: 600 }}>
            RÉPARTITION PAR TYPE (9 CLASSES)
          </h3>
          {pieData.length === 0 ? (
            <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>Aucune attaque détectée</div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={55} outerRadius={85}
                  dataKey="value" paddingAngle={3}>
                  {pieData.map(entry => (
                    <Cell key={entry.name} fill={COLORS[entry.name] || '#3B82F6'} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: 8, color: 'var(--text-primary)' }} />
                <Legend formatter={v => <span style={{ color: 'var(--text-secondary)', fontSize: 11 }}>{v}</span>} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Bar — sévérités */}
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: 12, padding: 24 }}>
          <h3 style={{ margin: '0 0 20px', fontSize: 14, color: 'var(--text-secondary)', fontWeight: 600 }}>
            RÉPARTITION PAR SÉVÉRITÉ
          </h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={severityData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
              <XAxis dataKey="name" tick={{ fill: 'var(--text-secondary)', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: 'var(--text-secondary)', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: 8, color: 'var(--text-primary)' }} />
              <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                {severityData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Bar — tous les types */}
      {barData.length > 0 && (
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: 12, padding: 24, marginBottom: 20 }}>
          <h3 style={{ margin: '0 0 20px', fontSize: 14, color: 'var(--text-secondary)', fontWeight: 600 }}>
            DISTRIBUTION DES ATTAQUES PAR TYPE
          </h3>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={barData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
              <XAxis dataKey="name" tick={{ fill: 'var(--text-secondary)', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: 'var(--text-secondary)', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: 8, color: 'var(--text-primary)' }} />
              <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                {barData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Top IPs */}
      {stats.top_ips?.length > 0 && (
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: 12, padding: 24, marginBottom: 20 }}>
          <h3 style={{ margin: '0 0 16px', fontSize: 14, color: 'var(--text-secondary)', fontWeight: 600 }}>
            TOP IPs SUSPECTES
          </h3>
          {stats.top_ips.map((ip, i) => (
            <div
              key={i}
              onClick={() => navigate(`/alerts?ip=${ip.src_ip}`)}
              style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                padding: '8px 0', borderBottom: '1px solid var(--bg-primary)', fontSize: 13,
                cursor: 'pointer',
              }}
              onMouseEnter={e => e.currentTarget.style.opacity = '0.7'}
              onMouseLeave={e => e.currentTarget.style.opacity = '1'}
            >
              <span style={{ fontFamily: 'monospace', color: 'var(--text-primary)' }}>{ip.src_ip}</span>
              <span style={{
                background: 'rgba(239,68,68,0.15)', color: '#EF4444',
                padding: '2px 10px', borderRadius: 20, fontSize: 11, fontWeight: 700,
              }}>
                {ip.count} alertes
              </span>
            </div>
          ))}
        </div>
      )}

      {/* River Status */}
      {river && (
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: 12, padding: 24 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
            <Brain size={18} color="#3B82F6" />
            <h3 style={{ margin: 0, fontSize: 14, color: 'var(--text-secondary)', fontWeight: 600 }}>
              RIVER — APPRENTISSAGE EN LIGNE
            </h3>
            <span style={{
              marginLeft: 'auto', fontSize: 11, fontWeight: 700, padding: '2px 10px', borderRadius: 20,
              background: river.status === 'active' ? 'rgba(34,197,94,0.15)' : 'rgba(148,163,184,0.15)',
              color: river.status === 'active' ? '#22C55E' : 'var(--text-secondary)',
            }}>
              {river.status === 'active' ? '● ACTIF' : '○ EN ATTENTE'}
            </span>
          </div>

          <div className="mylo-grid-3" style={{ gap: 16, marginBottom: 16 }}>
            {[
              { label: 'Modèle',      value: river.model_type },
              { label: 'Flux appris', value: river.total_learned.toLocaleString() },
              { label: 'Accuracy',    value: river.total_learned > 0 ? `${(river.accuracy * 100).toFixed(1)}%` : 'N/A' },
            ].map(({ label, value }) => (
              <div key={label}>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>{label}</div>
                <div style={{ fontSize: 14, color: 'var(--text-primary)', fontWeight: 600 }}>{value}</div>
              </div>
            ))}
          </div>

          <div className="mylo-grid-cards" style={{ gap: 8 }}>
            {Object.entries(river.counts || {}).map(([cls, count]) => (
              <div key={cls} style={{
                background: 'var(--bg-primary)', borderRadius: 8, padding: '8px 10px', textAlign: 'center',
              }}>
                <div style={{ fontSize: 16, fontWeight: 800, color: COLORS[cls] || '#3B82F6' }}>{count}</div>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>{cls}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}