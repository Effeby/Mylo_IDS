import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Activity, AlertTriangle, CheckCircle,
         Brain, Zap, Eye, Ban, RefreshCw, ArrowRight } from 'lucide-react'
import { getAlertStats, getRiverStatus, getOrganisationName } from '../api/mylo'
import AlertBadge from '../components/AlertBadge'

const DJANGO_URL = import.meta.env.VITE_DJANGO_URL || 'https://mylo-ids.site'

const COLORS = {
  Normal:'#22C55E', DoS:'#EF4444', DDoS:'#DC2626',
  Probe:'#EAB308', R2L:'#F97316', U2R:'#A855F7',
  BruteForce:'#EC4899', WebAttack:'#14B8A6',
  Botnet:'#F43F5E', Infiltration:'#8B5CF6',
}

const SEV_COLOR = {
  CRITICAL:'#EF4444', HIGH:'#F97316', MEDIUM:'#EAB308', LOW:'#22C55E'
}

async function fetchRecent(token) {
  const res = await fetch(
    `${DJANGO_URL}/api/alerts/?limit=5&ordering=-detected_at`,
    { headers: { Authorization: `Bearer ${token}` } }
  )
  const data = await res.json()
  return data.results || data
}

function formatDate(iso) {
  const dt = new Date(iso)
  return dt.toLocaleDateString('fr-FR', { day:'2-digit', month:'2-digit' }) +
    ' ' + dt.toLocaleTimeString('fr-FR', { hour:'2-digit', minute:'2-digit' })
}

export default function Dashboard() {
  const navigate  = useNavigate()
  const [stats,   setStats]   = useState(null)
  const [river,   setRiver]   = useState(null)
  const [recent,  setRecent]  = useState([])
  const [loading, setLoading] = useState(true)
  const token = localStorage.getItem('mylo_access')

  const load = async () => {
    try {
      const [s, r, rec] = await Promise.all([
        getAlertStats(),
        getRiverStatus(),
        fetchRecent(token),
      ])
      setStats(s); setRiver(r); setRecent(rec)
    } catch(e) { console.error(e) }
    finally { setLoading(false) }
  }

  useEffect(() => {
    load()
    const i = setInterval(load, 15_000)
    return () => clearInterval(i)
  }, [])

  if (loading) return (
    <div style={{ padding:32, color:'#94A3B8', fontSize:14 }}>
      Chargement du dashboard...
    </div>
  )

  const byType     = stats?.by_type     || {}
  const bySeverity = stats?.by_severity || {}
  const topTypes   = Object.entries(byType).sort((a,b) => b[1]-a[1]).slice(0,5)
  const total      = stats?.total || 0
  const attacks    = stats?.attacks || 0
  const attackRate = total > 0 ? ((attacks/total)*100).toFixed(1) : '0.0'
  const newAlerts  = stats?.new_alerts || 0

  return (
    <div style={{ padding:32, color:'#F8FAFC' }}>

      {/* ── Header ── */}
      <div style={{ marginBottom:28 }}>
        <div style={{ display:'flex', alignItems:'center', gap:12, marginBottom:6 }}>
          <div style={{
            width:42, height:42, borderRadius:10,
            background:'linear-gradient(135deg,#3B82F6,#1E40AF)',
            display:'flex', alignItems:'center', justifyContent:'center',
          }}>
            <Shield size={22} color="#fff" />
          </div>
          <div>
            <h1 style={{ margin:0, fontSize:22, fontWeight:800 }}>{getOrganisationName()} — Overview</h1>
            <p style={{ margin:0, color:'#475569', fontSize:12 }}>
              Mylo IPS · Rafraîchissement auto toutes les 15s
            </p>
          </div>
        </div>
      </div>

      {/* ── KPI Row ── */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:16, marginBottom:20 }}>
        {[
          { label:'Flux analysés',    value:total.toLocaleString(),   color:'#3B82F6', icon:Activity },
          { label:'Alertes',         value:attacks.toLocaleString(), color:'#EF4444', icon:AlertTriangle },
          { label:'Trafic normal',    value:(total-attacks).toLocaleString(), color:'#22C55E', icon:CheckCircle },
          { label:'Taux d\'attaque',  value:`${attackRate}%`,         color:'#F97316', icon:Zap },
        ].map(({ label, value, color, icon:Icon }) => (
          <div key={label} style={{
            background:'#0F1629', border:'1px solid #1E2D4F',
            borderRadius:12, padding:'20px 24px',
          }}>
            <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start' }}>
              <div>
                <div style={{ fontSize:28, fontWeight:800, color }}>{value}</div>
                <div style={{ fontSize:12, color:'#94A3B8', marginTop:4 }}>{label}</div>
              </div>
              <div style={{
                width:40, height:40, borderRadius:10,
                background:`${color}20`,
                display:'flex', alignItems:'center', justifyContent:'center',
              }}>
                <Icon size={20} color={color} />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* ── Alertes non traitées ── */}
      {newAlerts > 0 && (
        <div onClick={() => navigate('/alerts?status=new')} style={{
          padding:'14px 20px', borderRadius:10, marginBottom:20,
          background:'rgba(239,68,68,0.1)', border:'1px solid #EF4444',
          color:'#EF4444', fontWeight:600, fontSize:14, cursor:'pointer',
          display:'flex', justifyContent:'space-between', alignItems:'center',
          transition:'background 0.15s',
        }}
          onMouseEnter={e => e.currentTarget.style.background='rgba(239,68,68,0.18)'}
          onMouseLeave={e => e.currentTarget.style.background='rgba(239,68,68,0.1)'}
        >
          <span>🚨 {newAlerts} alerte{newAlerts > 1 ? 's' : ''} non traitée{newAlerts > 1 ? 's' : ''} — Action requise</span>
          <span style={{ fontSize:12 }}>Traiter maintenant →</span>
        </div>
      )}

      {/* ── Statut système ── */}
      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr 1fr', gap:16, marginBottom:20 }}>

        {/* Mylo IPS */}
        <div style={{ background:'#0F1629', border:'1px solid #1E2D4F', borderRadius:12, padding:20 }}>
          <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:12 }}>
            <Shield size={16} color="#3B82F6" />
            <span style={{ fontSize:12, fontWeight:700, color:'#94A3B8', letterSpacing:'0.05em' }}>
              Mylo IPS
            </span>
            <span style={{
              marginLeft:'auto', fontSize:10, fontWeight:700,
              padding:'2px 8px', borderRadius:20,
              background:'rgba(34,197,94,0.15)', color:'#22C55E',
            }}>● ACTIF</span>
          </div>
          <div style={{ fontSize:12, color:'#64748B' }}>Modèle XGBoost 9 classes</div>
          <div style={{ fontSize:12, color:'#64748B', marginTop:4 }}>
            Accuracy : <span style={{ color:'#3B82F6', fontWeight:600 }}>90.29%</span>
          </div>
          <div style={{ fontSize:12, color:'#64748B', marginTop:4 }}>
            Datasets : <span style={{ color:'#F8FAFC' }}>8 sources · 579K lignes</span>
          </div>
        </div>

        {/* River */}
        <div style={{ background:'#0F1629', border:'1px solid #1E2D4F', borderRadius:12, padding:20 }}>
          <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:12 }}>
            <Brain size={16} color="#3B82F6" />
            <span style={{ fontSize:12, fontWeight:700, color:'#94A3B8', letterSpacing:'0.05em' }}>
              RIVER — ONLINE LEARNING
            </span>
            <span style={{
              marginLeft:'auto', fontSize:10, fontWeight:700,
              padding:'2px 8px', borderRadius:20,
              background: river?.status === 'active' ? 'rgba(34,197,94,0.15)' : 'rgba(148,163,184,0.15)',
              color: river?.status === 'active' ? '#22C55E' : '#94A3B8',
            }}>
              {river?.status === 'active' ? '● ACTIF' : '○ ATTENTE'}
            </span>
          </div>
          <div style={{ fontSize:12, color:'#64748B' }}>
            Flux appris : <span style={{ color:'#F8FAFC', fontWeight:600 }}>
              {river?.total_learned?.toLocaleString() || 0}
            </span>
          </div>
          <div style={{ fontSize:12, color:'#64748B', marginTop:4 }}>
            Accuracy : <span style={{ color:'#22C55E', fontWeight:600 }}>
              {river?.total_learned > 0 ? `${(river.accuracy*100).toFixed(1)}%` : 'N/A'}
            </span>
          </div>
          <div style={{ fontSize:12, color:'#64748B', marginTop:4 }}>
            Modèle : <span style={{ color:'#F8FAFC' }}>HoeffdingAdaptiveTree</span>
          </div>
        </div>

        {/* Sévérités */}
        <div style={{ background:'#0F1629', border:'1px solid #1E2D4F', borderRadius:12, padding:20 }}>
          <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:12 }}>
            <AlertTriangle size={16} color="#EF4444" />
            <span style={{ fontSize:12, fontWeight:700, color:'#94A3B8', letterSpacing:'0.05em' }}>
              PAR SÉVÉRITÉ
            </span>
          </div>
          {[
            { k:'CRITICAL', label:'Critique' },
            { k:'HIGH',     label:'Élevé'    },
            { k:'MEDIUM',   label:'Moyen'    },
            { k:'LOW',      label:'Faible'   },
          ].map(({ k, label }) => {
            const val  = bySeverity[k] || 0
            const pct  = attacks > 0 ? (val/attacks*100) : 0
            return (
              <div key={k} style={{ marginBottom:6 }}>
                <div style={{ display:'flex', justifyContent:'space-between', marginBottom:3 }}>
                  <span style={{ fontSize:11, color: SEV_COLOR[k] }}>{label}</span>
                  <span style={{ fontSize:11, color:'#64748B' }}>{val}</span>
                </div>
                <div style={{ height:4, background:'#1E2D4F', borderRadius:2 }}>
                  <div style={{
                    height:'100%', borderRadius:2,
                    width:`${pct}%`, background: SEV_COLOR[k],
                    transition:'width 0.5s',
                  }} />
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* ── Répartition types + Dernières alertes ── */}
      <div style={{ display:'grid', gridTemplateColumns:'1fr 1.5fr', gap:16, marginBottom:20 }}>

        {/* Types d'attaques */}
        <div style={{ background:'#0F1629', border:'1px solid #1E2D4F', borderRadius:12, padding:20 }}>
          <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:16 }}>
            <span style={{ fontSize:12, fontWeight:700, color:'#94A3B8', letterSpacing:'0.05em' }}>
              TYPES D'ATTAQUES
            </span>
            <button onClick={() => navigate('/stats')} style={{
              background:'none', border:'none', color:'#3B82F6',
              fontSize:11, cursor:'pointer', display:'flex', alignItems:'center', gap:4,
            }}>
              Voir stats <ArrowRight size={11} />
            </button>
          </div>
          {topTypes.length === 0 ? (
            <div style={{ color:'#475569', fontSize:13, textAlign:'center', padding:'20px 0' }}>
              Aucune attaque détectée
            </div>
          ) : topTypes.map(([type, count]) => {
            const pct = attacks > 0 ? (count/attacks*100) : 0
            return (
              <div key={type} style={{ marginBottom:10 }}>
                <div style={{ display:'flex', justifyContent:'space-between', marginBottom:4 }}>
                  <span style={{ fontSize:12, color: COLORS[type] || '#94A3B8', fontWeight:600 }}>
                    {type}
                  </span>
                  <span style={{ fontSize:12, color:'#64748B' }}>{count} ({pct.toFixed(0)}%)</span>
                </div>
                <div style={{ height:5, background:'#1E2D4F', borderRadius:3 }}>
                  <div style={{
                    height:'100%', borderRadius:3,
                    width:`${pct}%`,
                    background: COLORS[type] || '#3B82F6',
                    transition:'width 0.5s',
                  }} />
                </div>
              </div>
            )
          })}
        </div>

        {/* Dernières alertes */}
        <div style={{ background:'#0F1629', border:'1px solid #1E2D4F', borderRadius:12, padding:20 }}>
          <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:16 }}>
            <span style={{ fontSize:12, fontWeight:700, color:'#94A3B8', letterSpacing:'0.05em' }}>
              DERNIÈRES ALERTES
            </span>
            <button onClick={() => navigate('/alerts')} style={{
              background:'none', border:'none', color:'#3B82F6',
              fontSize:11, cursor:'pointer', display:'flex', alignItems:'center', gap:4,
            }}>
              Voir toutes <ArrowRight size={11} />
            </button>
          </div>
          {recent.length === 0 ? (
            <div style={{ color:'#475569', fontSize:13, textAlign:'center', padding:'20px 0' }}>
              Aucune alerte récente
            </div>
          ) : recent.map(a => (
            <div key={a.id} onClick={() => navigate('/alerts')} style={{
              display:'flex', alignItems:'center', gap:12,
              padding:'9px 0', borderBottom:'1px solid #0A0E1A',
              cursor:'pointer',
            }}>
              <div style={{
                width:8, height:8, borderRadius:'50%', flexShrink:0,
                background: a.is_attack ? (COLORS[a.attack_type] || '#EF4444') : '#22C55E',
              }} />
                <div style={{ flex:1, minWidth:0 }}>
                <div style={{ fontSize:12, fontWeight:600, color: a.is_attack ? '#F8FAFC' : '#64748B' }}>
                  {a.attack_type}
                  {a.src_ip && (
                    <span style={{ display:'inline-flex', alignItems:'center', gap:8, marginLeft:8 }}>
                      <span style={{ fontFamily:'monospace', color:'#475569', fontWeight:400, fontSize:11 }}>{a.src_ip}</span>
                      <span style={{ fontSize:11, padding:'2px 6px', borderRadius:8, display:'inline-flex', alignItems:'center', gap:6, background: a.source === 'wazuh' ? 'rgba(124,58,237,0.12)' : 'rgba(99,102,241,0.08)', color: a.source === 'wazuh' ? '#7C3AED' : '#6366F1' }} title={a.source || 'scapy'}>
                        {a.source === 'wazuh' ? <Shield size={12} color="#7C3AED" /> : <svg width="12" height="12" viewBox="0 0 8 8" style={{borderRadius:6, display:'block'}}><circle cx="4" cy="4" r="4" fill="#6366F1"/></svg>}
                        <span style={{ lineHeight:1 }}>{a.source || 'scapy'}</span>
                      </span>
                    </span>
                  )}
                </div>
                <div style={{ fontSize:11, color:'#475569', marginTop:1 }}>
                  {formatDate(a.detected_at)}
                </div>
              </div>
              <AlertBadge severity={a.severity} />
            </div>
          ))}
        </div>
      </div>

      {/* ── Actions rapides ── */}
      <div style={{ background:'#0F1629', border:'1px solid #1E2D4F', borderRadius:12, padding:20 }}>
        <div style={{ fontSize:12, fontWeight:700, color:'#94A3B8', letterSpacing:'0.05em', marginBottom:14 }}>
          ACTIONS RAPIDES
        </div>
        <div style={{ display:'flex', gap:12, flexWrap:'wrap' }}>
          {[
            { label:'Live Monitor',      icon:Eye,           color:'#22C55E', path:'/monitor'  },
            { label:'Alertes actives',   icon:AlertTriangle, color:'#EF4444', path:'/alerts?status=new' },
            { label:'Statistiques',      icon:Activity,      color:'#3B82F6', path:'/stats'    },
            { label:'Paramètres IDS',    icon:Zap,           color:'#A855F7', path:'/settings' },
            { label:'Bloquer une IP',    icon:Ban,           color:'#F97316', path:'/alerts'   },
          ].map(({ label, icon:Icon, color, path }) => (
            <button key={label} onClick={() => navigate(path)} style={{
              display:'flex', alignItems:'center', gap:8,
              padding:'10px 18px', borderRadius:8,
              background:`${color}15`, border:`1px solid ${color}40`,
              color, cursor:'pointer', fontSize:13, fontWeight:600,
              transition:'all 0.15s',
            }}
              onMouseEnter={e => { e.currentTarget.style.background=`${color}25`; e.currentTarget.style.borderColor=color }}
              onMouseLeave={e => { e.currentTarget.style.background=`${color}15`; e.currentTarget.style.borderColor=`${color}40` }}
            >
              <Icon size={15} />
              {label}
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}