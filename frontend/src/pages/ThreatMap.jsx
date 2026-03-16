import { useState, useEffect, useRef } from 'react'
import { MapPin, RefreshCw, AlertTriangle, Globe, Info } from 'lucide-react'
import { getAlerts } from '../api/mylo'

const DJANGO_URL = import.meta.env.VITE_DJANGO_URL || 'http://localhost:8001'

const ATTACK_COLORS = {
  DoS:          '#EF4444',
  DDoS:         '#DC2626',
  Probe:        '#EAB308',
  R2L:          '#F97316',
  U2R:          '#A855F7',
  BruteForce:   '#EC4899',
  WebAttack:    '#14B8A6',
  Botnet:       '#F43F5E',
  Infiltration: '#8B5CF6',
  Normal:       '#22C55E',
}

// IPs cibles connues du réseau surveillé (serveurs)
const TARGET_SERVERS = {
  '10.0.0.1':    'Serveur Principal',
  '10.0.0.2':    'Serveur Web',
  '10.0.0.3':    'Serveur Auth',
  '10.0.0.4':    'Serveur API',
  '192.168.1.5': 'Poste Admin',
}

const geoCache = {}

// Types de connexion suspects par organisation/plage
function detectConnectionType(org, ip) {
  const orgLower = (org || '').toLowerCase()
  if (orgLower.includes('tor') || orgLower.includes('torproject'))
    return { type: 'Nœud Tor', icon: '🧅', risk: 'CRITIQUE' }
  if (orgLower.includes('vpn') || orgLower.includes('mullvad') || orgLower.includes('nordvpn') ||
      orgLower.includes('expressvpn') || orgLower.includes('protonvpn'))
    return { type: 'VPN', icon: '🔒', risk: 'ÉLEVÉ' }
  if (orgLower.includes('proxy') || orgLower.includes('anonymous'))
    return { type: 'Proxy', icon: '🎭', risk: 'ÉLEVÉ' }
  if (orgLower.includes('hosting') || orgLower.includes('server') || orgLower.includes('cloud') ||
      orgLower.includes('digital ocean') || orgLower.includes('amazon') || orgLower.includes('linode'))
    return { type: 'Serveur Cloud', icon: '☁️', risk: 'MOYEN' }
  if (orgLower.includes('mobile') || orgLower.includes('telecom') || orgLower.includes('wireless'))
    return { type: 'Mobile', icon: '📱', risk: 'FAIBLE' }
  // IPs Tor connues
  if (ip === '185.220.101.99' || ip === '185.220.100.253')
    return { type: 'Nœud Tor', icon: '🧅', risk: 'CRITIQUE' }
  return { type: 'FAI Résidentiel/Commercial', icon: '🏢', risk: 'NORMAL' }
}

async function geolocateIP(ip) {
  if (!ip || ip.startsWith('192.168') || ip.startsWith('10.') ||
      ip.startsWith('172.16') || ip.startsWith('127.')) return null
  if (geoCache[ip]) return geoCache[ip]
  try {
    const res  = await fetch(`https://ipapi.co/${ip}/json/`)
    const data = await res.json()
    if (data.latitude && data.longitude) {
      const connType = detectConnectionType(data.org, ip)
      const result = {
        ip,
        lat:      data.latitude,
        lng:      data.longitude,
        city:     data.city     || '?',
        region:   data.region   || '?',
        postal:   data.postal   || '?',
        country:  data.country_name || '?',
        org:      data.org      || '?',
        isp:      data.org      || '?',
        conn_type: connType,
      }
      geoCache[ip] = result
      return result
    }
  } catch(e) {}
  return null
}

export default function ThreatMap() {
  const mapRef     = useRef(null)
  const leafletRef = useRef(null)
  const markersRef = useRef([])
  const linesRef   = useRef([])

  const [geoPoints,    setGeoPoints]    = useState([])
  const [loading,      setLoading]      = useState(false)
  const [progress,     setProgress]     = useState(0)
  const [selected,     setSelected]     = useState(null)
  const [showInfo,     setShowInfo]     = useState(false)
  const [stats,        setStats]        = useState({ total: 0, countries: 0, topCountries: '—' })
  const [serverCoords, setServerCoords] = useState({ lat: 0, lng: 0, name: 'Votre réseau' })

  // Charger la localisation du réseau depuis les paramètres IDS
  useEffect(() => {
    const token = localStorage.getItem('mylo_access')
    fetch(`${DJANGO_URL}/api/alerts/settings/`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    })
    .then(r => r.json())
    .then(data => {
      if (data.network_latitude && data.network_longitude) {
        setServerCoords({
          lat:  data.network_latitude,
          lng:  data.network_longitude,
          name: data.network_name || 'Votre réseau',
        })
      }
    })
    .catch(() => {})
  }, [])

  // Auto-refresh toutes les 30s
  useEffect(() => {
    const interval = setInterval(() => {
      if (leafletRef.current) loadThreats()
    }, 30_000)
    return () => clearInterval(interval)
  }, [])

  // Charger Leaflet
  useEffect(() => {
    const link   = document.createElement('link')
    link.rel     = 'stylesheet'
    link.href    = 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css'
    document.head.appendChild(link)

    const script   = document.createElement('script')
    script.src     = 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js'
    script.onload  = () => {
      initMap()
      // Forcer Leaflet à recalculer la taille après rendu
      setTimeout(() => { if (leafletRef.current) leafletRef.current.invalidateSize() }, 300)
    }
    document.head.appendChild(script)

    return () => {
      if (leafletRef.current) { leafletRef.current.remove(); leafletRef.current = null }
    }
  }, [])

  const initMap = () => {
    if (!mapRef.current || leafletRef.current) return
    const L   = window.L
    const map = L.map(mapRef.current, {
      center: [20, 0], zoom: 2,
      zoomControl: true, attributionControl: false,
    })
    // Fond dark avec fallback
    const tile = L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', { maxZoom: 18 })
    tile.on('tileerror', () => {
      tile.remove()
      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 18 }).addTo(map)
    })
    tile.addTo(map)
    leafletRef.current = map
    loadThreats()
  }

  const loadThreats = async () => {
    setLoading(true)
    setProgress(0)
    try {
      const data   = await getAlerts({ limit: 500 })
      const alerts = (data.results || data).filter(a => a.is_attack && a.src_ip)
      const uniqueIPs = [...new Map(alerts.map(a => [a.src_ip, a])).values()]

      const points = []
      for (let i = 0; i < uniqueIPs.length; i++) {
        const alert = uniqueIPs[i]
        setProgress(Math.round((i / uniqueIPs.length) * 100))
        const geo = await geolocateIP(alert.src_ip)
        if (geo) {
          points.push({
            ...geo,
            attack_type: alert.attack_type,
            severity:    alert.severity,
            dst_ip:      alert.dst_ip,
          })
        }
        if (i % 5 === 0) await new Promise(r => setTimeout(r, 150))
      }

      setGeoPoints(points)
      updateMap(points)
      updateStats(points)
    } catch(e) { console.error(e) }
    finally { setLoading(false); setProgress(100) }
  }

  // Utiliser les coordonnées dynamiques depuis les paramètres IDS
  const SERVER_COORDS = serverCoords

  const updateMap = (points) => {
    const L = window.L
    if (!L || !leafletRef.current) return

    // Supprimer anciens marqueurs et lignes
    markersRef.current.forEach(m => m.remove())
    linesRef.current.forEach(l => l.remove())
    markersRef.current = []
    linesRef.current   = []

    // Marqueur serveur cible (étoile verte)
    const serverIcon = L.divIcon({
      html: `<div style="
        width:14px;height:14px;
        background:#22C55E;border-radius:3px;
        border:2px solid #fff;
        box-shadow:0 0 12px #22C55E;
        transform:rotate(45deg);
      "></div>`,
      className: '', iconSize: [14, 14],
    })
    const serverMarker = L.marker([SERVER_COORDS.lat, SERVER_COORDS.lng], { icon: serverIcon })
      .addTo(leafletRef.current)
      .bindTooltip(SERVER_COORDS.name, { permanent: false })
    markersRef.current.push(serverMarker)

    points.forEach(pt => {
      const color = ATTACK_COLORS[pt.attack_type] || '#94A3B8'
      const size  = pt.severity === 'CRITICAL' ? 16
                  : pt.severity === 'HIGH'     ? 13
                  : pt.severity === 'MEDIUM'   ? 10 : 8

      // Marqueur IP attaquante
      const icon = L.divIcon({
        html: `<div style="
          width:${size}px;height:${size}px;
          background:${color};border-radius:50%;
          border:2px solid rgba(255,255,255,0.4);
          box-shadow:0 0 ${size+4}px ${color}90;
          cursor:pointer;
        "></div>`,
        className: '', iconSize: [size, size],
      })

      const marker = L.marker([pt.lat, pt.lng], { icon })
        .addTo(leafletRef.current)
        .bindTooltip(`${pt.ip} — ${pt.attack_type}`, { permanent: false })
        .on('click', () => setSelected(pt))
      markersRef.current.push(marker)

      // Ligne de flux attaquant → serveur (arc animé)
      const line = L.polyline(
        [[pt.lat, pt.lng], [SERVER_COORDS.lat, SERVER_COORDS.lng]],
        {
          color,
          weight:    1.5,
          opacity:   0.6,
          dashArray: '6, 6',
          dashOffset: '0',
        }
      ).addTo(leafletRef.current)
      linesRef.current.push(line)

      // Animer le dash offset
      let offset = 0
      const animate = () => {
        offset = (offset + 1) % 20
        line.setStyle({ dashOffset: String(-offset) })
        requestAnimationFrame(animate)
      }
      requestAnimationFrame(animate)
    })
  }

  const updateStats = (points) => {
    const countryCount = {}
    points.forEach(p => { countryCount[p.country] = (countryCount[p.country] || 0) + 1 })
    const topCountries = Object.entries(countryCount)
      .sort((a,b) => b[1]-a[1]).slice(0,3)
      .map(([c, n]) => `${c} (${n})`).join(' • ') || '—'
    setStats({
      total:       points.length,
      countries:   Object.keys(countryCount).length,
      topCountries,
    })
  }

  return (
    <div style={{ padding:32, color:'#F8FAFC', height:'100vh', maxHeight:'100vh', display:'flex', flexDirection:'column', overflow:'hidden', boxSizing:'border-box' }}>

      {/* Header */}
      <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:16 }}>
        <div style={{ display:'flex', alignItems:'center', gap:12 }}>
          <div style={{ width:42, height:42, borderRadius:10, background:'linear-gradient(135deg,#3B82F6,#1E40AF)', display:'flex', alignItems:'center', justifyContent:'center' }}>
            <Globe size={22} color="#fff" />
          </div>
          <div>
            <h1 style={{ margin:0, fontSize:22, fontWeight:800 }}>Threat Map</h1>
            <p style={{ margin:0, color:'#94A3B8', fontSize:13 }}>
              Géolocalisation des IP attaquantes · Refresh auto 30s
            </p>
          </div>
        </div>
        <div style={{ display:'flex', gap:10 }}>
          <button onClick={() => setShowInfo(v => !v)} style={{
            padding:'8px 12px', borderRadius:8,
            border:`1px solid ${showInfo ? '#F97316' : '#1E2D4F'}`,
            background: showInfo ? 'rgba(249,115,22,0.1)' : 'transparent',
            color: showInfo ? '#F97316' : '#94A3B8', cursor:'pointer',
            display:'flex', alignItems:'center', gap:6, fontSize:12,
          }}>
            <Info size={14} /> Fiabilité
          </button>
          <button onClick={loadThreats} disabled={loading} style={{
            padding:'8px 16px', borderRadius:8, border:'1px solid #1E2D4F',
            background:'transparent', color:'#94A3B8',
            cursor: loading ? 'not-allowed' : 'pointer',
            display:'flex', alignItems:'center', gap:6, fontSize:13,
          }}>
            <RefreshCw size={14} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} />
            {loading ? `Géoloc... ${progress}%` : 'Actualiser'}
          </button>
        </div>
      </div>

      {/* Avertissement fiabilité */}
      {showInfo && (
        <div style={{
          padding:'14px 18px', borderRadius:10, marginBottom:12,
          background:'rgba(249,115,22,0.08)', border:'1px solid #F97316',
          fontSize:12, color:'#FED7AA', lineHeight:1.6,
        }}>
          <div style={{ fontWeight:700, marginBottom:6, color:'#F97316' }}>
            ⚠️ Avertissement — Fiabilité de la géolocalisation IP
          </div>
          La localisation affichée sur cette carte est une <strong>approximation</strong> basée sur l'adresse IP source.
          Elle peut être inexacte car les attaquants utilisent souvent des techniques de dissimulation :
          <br/>
          <strong>🧅 Nœuds Tor</strong> — l'IP de sortie Tor peut être en Allemagne mais l'attaquant est ailleurs ·
          <strong>🔒 VPN</strong> — masque la vraie localisation ·
          <strong>🎭 Proxy/Botnet</strong> — machine compromise d'un pays tiers utilisée comme relais.
          <br/>
          <em>Cette carte est un outil d'investigation, pas une preuve géographique.</em>
        </div>
      )}

      {/* KPIs */}
      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr 2fr', gap:12, marginBottom:12 }}>
        <div style={{ background:'#0F1629', border:'1px solid #1E2D4F', borderRadius:10, padding:'12px 16px', display:'flex', alignItems:'center', gap:10 }}>
          <MapPin size={18} color="#3B82F6" />
          <div>
            <div style={{ fontSize:20, fontWeight:800, color:'#3B82F6' }}>{stats.total}</div>
            <div style={{ fontSize:11, color:'#94A3B8' }}>IPs localisées</div>
          </div>
        </div>
        <div style={{ background:'#0F1629', border:'1px solid #1E2D4F', borderRadius:10, padding:'12px 16px', display:'flex', alignItems:'center', gap:10 }}>
          <Globe size={18} color="#F97316" />
          <div>
            <div style={{ fontSize:20, fontWeight:800, color:'#F97316' }}>{stats.countries}</div>
            <div style={{ fontSize:11, color:'#94A3B8' }}>Pays d'origine</div>
          </div>
        </div>
        <div style={{ background:'#0F1629', border:'1px solid #1E2D4F', borderRadius:10, padding:'12px 16px', display:'flex', alignItems:'center', gap:10 }}>
          <AlertTriangle size={18} color="#EF4444" />
          <div>
            <div style={{ fontSize:13, fontWeight:700, color:'#EF4444' }}>{stats.topCountries}</div>
            <div style={{ fontSize:11, color:'#94A3B8' }}>Top pays attaquants</div>
          </div>
        </div>
      </div>

      {/* Légende */}
      <div style={{ display:'flex', gap:16, marginBottom:10, flexWrap:'wrap', alignItems:'center' }}>
        {Object.entries(ATTACK_COLORS).filter(([k]) => k !== 'Normal').map(([type, color]) => (
          <div key={type} style={{ display:'flex', alignItems:'center', gap:4, fontSize:11, color:'#94A3B8' }}>
            <div style={{ width:8, height:8, borderRadius:'50%', background:color }} />{type}
          </div>
        ))}
        <div style={{ display:'flex', alignItems:'center', gap:4, fontSize:11, color:'#22C55E', marginLeft:'auto' }}>
          <div style={{ width:10, height:10, background:'#22C55E', transform:'rotate(45deg)' }} />
          Votre réseau
        </div>
        <div style={{ display:'flex', alignItems:'center', gap:4, fontSize:11, color:'#94A3B8' }}>
          <div style={{ width:20, height:2, background:'#94A3B8', borderTop:'2px dashed #94A3B8' }} />
          Flux d'attaque
        </div>
      </div>

      {/* Carte */}
      <div style={{ flex:1, position:'relative', borderRadius:12, overflow:'hidden', border:'1px solid #1E2D4F', minHeight:0 }}>
        <div ref={mapRef} style={{ width:'100%', height:'100%', minHeight:300 }} />

        {/* Panneau détail */}
        {selected && (
          <div style={{
            position:'absolute', top:16, right:16, zIndex:1000,
            background:'rgba(10,14,26,0.97)', border:'1px solid #1E2D4F',
            borderRadius:12, padding:20, width:280,
            backdropFilter:'blur(10px)',
          }}>
            <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:12 }}>
              <span style={{ fontWeight:700, fontSize:14, color:'#F8FAFC' }}>IP Attaquante</span>
              <button onClick={() => setSelected(null)} style={{ background:'none', border:'none', color:'#94A3B8', cursor:'pointer', fontSize:16 }}>✕</button>
            </div>

            {/* IP + type connexion */}
            <div style={{ fontFamily:'monospace', fontSize:15, fontWeight:800, color: ATTACK_COLORS[selected.attack_type] || '#F8FAFC', marginBottom:8 }}>
              {selected.ip}
            </div>
            <div style={{
              display:'inline-flex', alignItems:'center', gap:5,
              padding:'3px 10px', borderRadius:20, marginBottom:14,
              background: selected.conn_type?.risk === 'CRITIQUE' ? 'rgba(239,68,68,0.15)' :
                          selected.conn_type?.risk === 'ÉLEVÉ'   ? 'rgba(249,115,22,0.15)' :
                          'rgba(100,116,139,0.15)',
              border: `1px solid ${
                selected.conn_type?.risk === 'CRITIQUE' ? '#EF4444' :
                selected.conn_type?.risk === 'ÉLEVÉ'   ? '#F97316' : '#475569'
              }`,
              color: selected.conn_type?.risk === 'CRITIQUE' ? '#EF4444' :
                     selected.conn_type?.risk === 'ÉLEVÉ'   ? '#F97316' : '#94A3B8',
              fontSize:11, fontWeight:700,
            }}>
              {selected.conn_type?.icon} {selected.conn_type?.type}
            </div>

            {/* Infos */}
            {[
              { label:'Ville',          value: selected.city },
              { label:'Région',         value: selected.region },
              { label:'Code postal',    value: selected.postal },
              { label:'Pays',           value: selected.country },
              { label:'FAI / Org',      value: selected.isp },
              { label:'Type attaque',   value: selected.attack_type },
              { label:'Sévérité',       value: selected.severity },
              { label:'Cible',          value: TARGET_SERVERS[selected.dst_ip] || selected.dst_ip || '?' },
            ].map(({ label, value }) => (
              <div key={label} style={{ display:'flex', justifyContent:'space-between', fontSize:12, marginBottom:5 }}>
                <span style={{ color:'#475569' }}>{label}</span>
                <span style={{ color:'#F8FAFC', maxWidth:160, textAlign:'right', wordBreak:'break-all' }}>{value || '—'}</span>
              </div>
            ))}

            {/* Avertissement mini */}
            <div style={{ marginTop:10, padding:'8px 10px', borderRadius:6, background:'rgba(249,115,22,0.08)', border:'1px solid #F9731630', fontSize:10, color:'#FED7AA' }}>
              ⚠️ Localisation approximative — l'attaquant peut utiliser un VPN, proxy ou nœud Tor pour masquer sa vraie position.
            </div>
          </div>
        )}

        {/* Message vide */}
        {!loading && geoPoints.length === 0 && (
          <div style={{ position:'absolute', top:'50%', left:'50%', transform:'translate(-50%,-50%)', textAlign:'center', color:'#475569', pointerEvents:'none' }}>
            <Globe size={48} style={{ marginBottom:12, opacity:0.3 }} />
            <p style={{ margin:0, fontSize:14 }}>Aucune IP externe à géolocaliser</p>
            <p style={{ margin:'4px 0 0', fontSize:12 }}>Lance seed_map.py pour peupler la carte</p>
          </div>
        )}
      </div>

      <style>{`
        @keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
      `}</style>
    </div>
  )
}