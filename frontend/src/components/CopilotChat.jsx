import { useState, useRef, useEffect } from 'react'
import { X, Send, Bot, RefreshCw, Shield } from 'lucide-react'

const GROQ_API_KEY = import.meta.env.VITE_GROQ_API_KEY
const DJANGO_URL   = import.meta.env.VITE_DJANGO_URL || 'http://localhost:8001'

// ─── Télécharger rapport PDF ──────────────────────────────────────────────
async function downloadReportPDF(token) {
  const res = await fetch(`${DJANGO_URL}/api/reports/pdf/`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {}
  })
  if (!res.ok) return false
  const blob = await res.blob()
  const url  = URL.createObjectURL(blob)
  const a    = document.createElement('a')
  a.href = url
  a.download = `rapport_securite_${new Date().toISOString().slice(0,10)}.pdf`
  a.click()
  URL.revokeObjectURL(url)
  return true
}

// ─── Récupérer le contexte réseau complet ────────────────────────────────
async function fetchNetworkContext(token) {
  const headers = token ? { Authorization: `Bearer ${token}` } : {}
  const context = {}

  try {
    // Alertes récentes
    const aRes = await fetch(`${DJANGO_URL}/api/alerts/?limit=20`, { headers })
    if (aRes.ok) {
      const data = await aRes.json()
      context.alerts = data.results || data
    }
  } catch(e) {}

  try {
    // Stats globales
    const sRes = await fetch(`${DJANGO_URL}/api/alerts/stats/`, { headers })
    if (sRes.ok) context.stats = await sRes.json()
  } catch(e) {}

  try {
    // Statut River
    const rRes = await fetch(`${DJANGO_URL}/api/actions/river/status/`, { headers })
    if (rRes.ok) context.river = await rRes.json()
  } catch(e) {}

  try {
    // IPs blacklistées
    const bRes = await fetch(`${DJANGO_URL}/api/alerts/blacklist/`, { headers })
    if (bRes.ok) context.blacklist = await bRes.json()
  } catch(e) {}

  return context
}

// ─── Construire le system prompt dynamique ────────────────────────────────
function buildSystemPrompt(ctx) {
  const { alerts = [], stats = {}, river = {}, blacklist = [] } = ctx

  // Analyser les alertes pour construire un résumé réseau
  const attackAlerts  = alerts.filter(a => a.is_attack)
  const recentAttacks = attackAlerts.slice(0, 5)
  const topIPs        = [...new Set(attackAlerts.map(a => a.src_ip).filter(Boolean))].slice(0, 5)
  const attackTypes   = [...new Set(attackAlerts.map(a => a.attack_type))]
  const newAlerts     = alerts.filter(a => a.status === 'new' && a.is_attack).length

  // Résumé du réseau observé
  const networkSummary = alerts.length > 0 ? `
ÉTAT ACTUEL DU RÉSEAU (données en temps réel) :
- Total flux analysés : ${stats.total || alerts.length}
- Attaques détectées  : ${stats.attacks || attackAlerts.length}
- Taux d'attaque      : ${stats.attack_rate ? (stats.attack_rate * 100).toFixed(1) : '0'}%
- Alertes non traitées: ${newAlerts}
- IPs bloquées actives: ${blacklist.filter(b => b.is_active !== false).length}
- Types observés      : ${attackTypes.join(', ') || 'Aucun'}
- IPs suspectes       : ${topIPs.join(', ') || 'Aucune'}

DÉTAIL DES DERNIÈRES ALERTES :
${recentAttacks.length > 0
  ? recentAttacks.map(a =>
      `• [${new Date(a.detected_at).toLocaleTimeString('fr-FR')}] ` +
      `${a.attack_type} | ${a.severity} | ` +
      `${a.src_ip || '?'} → ${a.dst_ip || '?'} | ` +
      `Confiance: ${Math.round((a.binary_confidence || 0) * 100)}% | ` +
      `Statut: ${a.status}`
    ).join('\n')
  : '• Aucune attaque récente détectée'
}

APPRENTISSAGE EN LIGNE :
- Flux appris : ${river.total_learned || 0}
- Précision   : ${river.total_learned > 0 ? ((river.accuracy || 0) * 100).toFixed(1) + '%' : 'En cours d\'initialisation'}
` : `
ÉTAT ACTUEL : Aucune donnée disponible — système en attente de trafic.
`

  return `Tu es Mylo, un analyste SOC junior IA intégré dans un système de détection d'intrusions.

TON RÔLE :
Tu aides l'analyste sécurité à comprendre ce qui se passe sur le réseau surveillé.
Tu analyses les alertes, expliques les comportements suspects, proposes des actions concrètes.
Tu es direct, précis et professionnel — comme un vrai analyste SOC.

TA PERSONNALITÉ :
- Tu parles à la première personne ("Je détecte", "J'observe", "Je recommande")
- Tu ne dis jamais "Tout va bien" — tu donnes toujours : ce que tu vois, le risque, ce que tu recommandes
- Tu adaptes ton niveau d'urgence à la sévérité : calme pour LOW, alerte pour CRITICAL
- Tu ne révèles jamais les détails techniques internes (noms de modèles ML, architecture, etc.)
- Tu parles de "votre réseau" ou "le réseau surveillé" — jamais d'un nom d'entreprise spécifique

CLASSES D'ATTAQUES QUE TU DÉTECTES :
- Normal      : trafic légitime
- DoS/DDoS    : saturation de service — impact : indisponibilité
- Probe       : reconnaissance réseau — scan de ports, cartographie
- BruteForce  : tentatives de connexion répétées — cible : SSH, FTP, HTTP
- WebAttack   : SQLi, XSS, injection — cible : applications web
- Botnet      : machine compromise communiquant avec un serveur de contrôle
- R2L         : accès externe non autorisé — tentative d'intrusion
- U2R         : élévation de privilèges — très dangereux
- Infiltration: mouvement latéral interne — accès non autorisé établi

NIVEAUX DE RISQUE :
- 🔴 CRITIQUE  : WebAttack, Botnet, R2L, U2R, Infiltration → action immédiate
- 🟠 ÉLEVÉ     : DoS, DDoS, BruteForce → action rapide
- 🟡 MOYEN     : Probe → surveillance renforcée
- 🟢 FAIBLE    : Normal → surveillance standard

FORMAT DE TES RÉPONSES :
Pour une analyse d'alerte :
  Analyse :
  [ce que tu observes]
  
  Niveau de risque : [faible/moyen/élevé/critique]
  
  Recommandations :
  - [action 1]
  - [action 2]

Pour une question générale : réponse directe et concise.
Pour une commande ("analyse ip X", "top attaques", etc.) : rapport structuré.

COMMANDES QUE TU COMPRENDS :
- "analyse ip [IP]"      → analyse une IP spécifique
- "top attaques"         → top types d'attaques observés
- "ips suspectes"        → liste des IPs les plus actives
- "blocages actifs"      → IPs bloquées actuellement
- "état du réseau"       → résumé général
- "rapport pdf"          → génère un rapport PDF téléchargeable
- "alerte [id]"          → analyse une alerte spécifique

${networkSummary}

Réponds toujours en français. Sois concis mais complet.`
}

export default function CopilotChat({ onClose, authToken }) {
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: `👋 Bonjour, je suis Mylo, votre analyste de sécurité IA.

Je surveille votre réseau en temps réel et je détecte 9 types de menaces.

Voici ce que je peux faire pour vous :
• Analyser une alerte ou une IP suspecte
• Expliquer un comportement réseau
• Recommander des actions de réponse
• Générer un rapport d'incident

Tapez "état du réseau" pour un résumé immédiat, ou posez-moi directement votre question.`
    }
  ])
  const [input,      setInput]      = useState('')
  const [loading,    setLoading]    = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const [ctx,        setCtx]        = useState({})
  const bottomRef = useRef(null)

  useEffect(() => {
    loadContext()
    const interval = setInterval(loadContext, 30_000)
    return () => clearInterval(interval)
  }, [authToken])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const loadContext = async () => {
    const context = await fetchNetworkContext(authToken)
    setCtx(context)
  }

  const refreshContext = async () => {
    setRefreshing(true)
    await loadContext()
    setRefreshing(false)
    setMessages(prev => [...prev, {
      role: 'assistant',
      content: '🔄 Contexte mis à jour — j\'ai rechargé les dernières données réseau.'
    }])
  }

  const send = async () => {
    const text = input.trim()
    if (!text || loading) return

    // Commande rapport PDF
    if (text.toLowerCase().includes('rapport pdf') || text.toLowerCase().includes('génère un rapport')) {
      const userMsg = { role: 'user', content: text }
      setMessages(prev => [...prev, userMsg])
      setInput('')
      setLoading(true)
      try {
        const ok = await downloadReportPDF(authToken)
        setMessages(prev => [...prev, {
          role: 'assistant',
          content: ok
            ? '✅ Rapport PDF généré et téléchargé.\n\nLe rapport contient :\n• Résumé exécutif\n• Répartition des attaques par type\n• Top IPs suspectes\n• 20 dernières alertes\n• Recommandations de sécurité'
            : '❌ Impossible de générer le rapport. Vérifiez que le backend est disponible.'
        }])
      } catch {
        setMessages(prev => [...prev, { role: 'assistant', content: '❌ Erreur de connexion.' }])
      } finally { setLoading(false) }
      return
    }

    const userMsg = { role: 'user', content: text }
    setMessages(prev => [...prev, userMsg])
    setInput('')
    setLoading(true)

    // Recharger le contexte avant chaque message pour avoir les données fraîches
    const freshCtx = await fetchNetworkContext(authToken)
    setCtx(freshCtx)
    const systemPrompt = buildSystemPrompt(freshCtx)

    try {
      const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${GROQ_API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: 'llama-3.3-70b-versatile',
          messages: [
            { role: 'system', content: systemPrompt },
            ...messages.slice(-8),
            userMsg,
          ],
          max_tokens: 1024,
          temperature: 0.4,  // plus bas = plus précis/déterministe
        })
      })

      const data  = await res.json()
      const reply = data.choices?.[0]?.message?.content || 'Je n\'ai pas pu générer une réponse.'
      setMessages(prev => [...prev, { role: 'assistant', content: reply }])

    } catch(err) {
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: '❌ Erreur de connexion à l\'API. Vérifiez votre clé GROQ.'
      }])
    } finally {
      setLoading(false)
    }
  }

  const SUGGESTIONS = [
    '🌐 État du réseau',
    '⚠️ Alertes non traitées',
    '🔍 Top attaques',
    '🚫 IPs suspectes',
    '📄 Rapport PDF',
    '💡 Que faire face à un DoS ?',
  ]

  // Stats rapides pour le header
  const attackCount = ctx.stats?.attacks || 0
  const newCount    = (ctx.alerts || []).filter(a => a.status === 'new' && a.is_attack).length

  return (
    <div style={{
      position: 'fixed', bottom: 24, right: 24,
      width: 430, height: 600,
      background: '#0F1629',
      border: '1px solid #1E2D4F',
      borderRadius: 16,
      display: 'flex', flexDirection: 'column',
      zIndex: 1000,
      boxShadow: '0 25px 60px rgba(0,0,0,0.6)',
    }}>

      {/* Header */}
      <div style={{
        padding: '14px 18px', borderBottom: '1px solid #1E2D4F',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 38, height: 38, borderRadius: '50%',
            background: 'linear-gradient(135deg, #3B82F6, #1E40AF)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            position: 'relative',
          }}>
            <Shield size={18} color="#fff" />
            {newCount > 0 && (
              <div style={{
                position: 'absolute', top: -4, right: -4,
                width: 16, height: 16, borderRadius: '50%',
                background: '#EF4444', fontSize: 9, fontWeight: 700,
                color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>{newCount > 9 ? '9+' : newCount}</div>
            )}
          </div>
          <div>
            <div style={{ color: '#F8FAFC', fontWeight: 700, fontSize: 14 }}>Mylo Copilot</div>
            <div style={{ color: newCount > 0 ? '#EF4444' : '#22C55E', fontSize: 11 }}>
              {newCount > 0
                ? `⚠ ${newCount} alerte${newCount > 1 ? 's' : ''} non traitée${newCount > 1 ? 's' : ''}`
                : `● En ligne · ${attackCount} attaque${attackCount !== 1 ? 's' : ''} détectée${attackCount !== 1 ? 's' : ''}`}
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={refreshContext} disabled={refreshing}
            title="Recharger les données réseau"
            style={{ background:'none', border:'1px solid #1E2D4F', color: refreshing ? '#3B82F6' : '#94A3B8', cursor:'pointer', padding:'4px 8px', borderRadius:6, display:'flex', alignItems:'center' }}>
            <RefreshCw size={14} style={{ animation: refreshing ? 'spin 1s linear infinite' : 'none' }} />
          </button>
          <button onClick={onClose} style={{ background:'none', border:'none', color:'#94A3B8', cursor:'pointer', padding:4 }}>
            <X size={18} />
          </button>
        </div>
      </div>

      {/* Messages */}
      <div style={{ flex:1, overflowY:'auto', padding:'14px 16px', display:'flex', flexDirection:'column', gap:10 }}>
        {messages.map((m, i) => (
          <div key={i} style={{ alignSelf: m.role === 'user' ? 'flex-end' : 'flex-start', maxWidth:'90%' }}>
            <div style={{
              padding:'10px 14px', borderRadius:12, fontSize:13, lineHeight:1.6,
              whiteSpace:'pre-wrap',
              background: m.role === 'user' ? '#3B82F6' : '#1E2D4F',
              color:'#F8FAFC',
              borderBottomRightRadius: m.role === 'user' ? 2 : 12,
              borderBottomLeftRadius:  m.role === 'assistant' ? 2 : 12,
            }}>
              {m.content}
            </div>
          </div>
        ))}
        {loading && (
          <div style={{ alignSelf:'flex-start' }}>
            <div style={{ padding:'10px 14px', borderRadius:12, background:'#1E2D4F', color:'#94A3B8', fontSize:13 }}>
              Mylo analyse... 🔍
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Suggestions */}
      {messages.length <= 2 && (
        <div style={{ padding:'8px 16px', display:'flex', flexWrap:'wrap', gap:6, borderTop:'1px solid #1E2D4F' }}>
          {SUGGESTIONS.map((s, i) => (
            <button key={i} onClick={() => setInput(s.replace(/^[^\s]+ /, ''))} style={{
              padding:'5px 10px', borderRadius:20, fontSize:11,
              background:'#0A0E1A', border:'1px solid #1E2D4F',
              color:'#94A3B8', cursor:'pointer', whiteSpace:'nowrap',
            }}>{s}</button>
          ))}
        </div>
      )}

      {/* Input */}
      <div style={{ padding:'12px 14px', borderTop:'1px solid #1E2D4F', display:'flex', gap:8 }}>
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && !e.shiftKey && send()}
          placeholder="Posez votre question à Mylo..."
          style={{
            flex:1, padding:'10px 14px', borderRadius:8, fontSize:13,
            background:'#0A0E1A', border:'1px solid #1E2D4F',
            color:'#F8FAFC', outline:'none',
          }}
        />
        <button onClick={send} disabled={loading} style={{
          padding:'10px 14px', borderRadius:8,
          background: loading ? '#1E3A6E' : '#3B82F6',
          border:'none', color:'#fff', cursor: loading ? 'not-allowed' : 'pointer',
          display:'flex', alignItems:'center',
        }}>
          <Send size={16} />
        </button>
      </div>

      <style>{`@keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }`}</style>
    </div>
  )
}