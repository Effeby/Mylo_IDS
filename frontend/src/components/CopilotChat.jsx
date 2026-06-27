import { useState, useRef, useEffect } from 'react'
import { X, Send, Bot, RefreshCw, Shield } from 'lucide-react'

const DJANGO_URL = import.meta.env.VITE_DJANGO_URL || 'https://mylo-ids.site'

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

// ─── Récupérer le contexte réseau (juste pour les badges du header) ──────
// Le system prompt riche (alertes, stats, river, blacklist) est désormais
// construit côté backend par /api/alerts/copilot/, avec un accès direct à
// la BDD — plus besoin de le reconstruire ici.
async function fetchNetworkContext(token) {
  const headers = token ? { Authorization: `Bearer ${token}` } : {}
  const context = {}

  try {
    const aRes = await fetch(`${DJANGO_URL}/api/alerts/?limit=20`, { headers })
    if (aRes.ok) {
      const data = await aRes.json()
      context.alerts = data.results || data
    }
  } catch(e) {}

  try {
    const sRes = await fetch(`${DJANGO_URL}/api/alerts/stats/`, { headers })
    if (sRes.ok) context.stats = await sRes.json()
  } catch(e) {}

  return context
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

    // Rafraîchir les badges du header en arrière-plan (n'affecte pas la requête)
    fetchNetworkContext(authToken).then(setCtx)

    try {
      const res = await fetch(`${DJANGO_URL}/api/alerts/copilot/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
        },
        body: JSON.stringify({
          message: text,
          // L'agent backend exécute réellement les actions (whitelist_ip,
          // blacklist_ip...) et construit son propre contexte réseau à jour
          // depuis la BDD — on lui passe juste l'historique de conversation.
          history: messages.slice(-8).map(m => ({ role: m.role, content: m.content })),
        }),
      })

      const data = await res.json()
      if (!res.ok || data.error) {
        setMessages(prev => [...prev, {
          role: 'assistant',
          content: `❌ ${data.error || 'Le Copilot est momentanément indisponible.'}`
        }])
      } else {
        setMessages(prev => [...prev, {
          role: 'assistant',
          content: data.reply || 'Je n\'ai pas pu générer une réponse.'
        }])
      }

    } catch(err) {
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: '❌ Erreur de connexion au serveur Mylo.'
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