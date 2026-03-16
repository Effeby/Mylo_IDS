import { useState, useEffect } from 'react'
import { Save, RefreshCw, Shield, Zap, Brain, Bell, AlertTriangle, MapPin } from 'lucide-react'

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
}

async function apiFetch(path, options = {}) {
  const token = localStorage.getItem('mylo_access')
  const res = await fetch(`${DJANGO_URL}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    ...options,
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}

// ─── Composants UI réutilisables ─────────────────────────────────────

function Section({ icon: Icon, title, color = '#3B82F6', children }) {
  return (
    <div style={{
      background: '#0F1629', border: '1px solid #1E2D4F',
      borderRadius: 12, padding: 24, marginBottom: 16,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20 }}>
        <div style={{
          width: 34, height: 34, borderRadius: 8,
          background: `${color}20`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <Icon size={16} color={color} />
        </div>
        <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: '#F8FAFC' }}>{title}</h3>
      </div>
      {children}
    </div>
  )
}

function Toggle({ label, desc, value, onChange }) {
  return (
    <div style={{
      display: 'flex', justifyContent: 'space-between', alignItems: 'center',
      padding: '12px 0', borderBottom: '1px solid #0A0E1A',
    }}>
      <div>
        <div style={{ fontSize: 13, color: '#F8FAFC', fontWeight: 500 }}>{label}</div>
        {desc && <div style={{ fontSize: 11, color: '#475569', marginTop: 2 }}>{desc}</div>}
      </div>
      <button onClick={() => onChange(!value)} style={{
        width: 44, height: 24, borderRadius: 12, border: 'none',
        background: value ? '#3B82F6' : '#1E2D4F',
        cursor: 'pointer', position: 'relative', transition: 'background 0.2s',
        flexShrink: 0,
      }}>
        <div style={{
          width: 18, height: 18, borderRadius: '50%', background: '#fff',
          position: 'absolute', top: 3,
          left: value ? 23 : 3,
          transition: 'left 0.2s',
        }} />
      </button>
    </div>
  )
}

function Slider({ label, desc, value, min, max, step = 0.01, onChange, color = '#3B82F6', format }) {
  const pct = ((value - min) / (max - min)) * 100
  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
        <div>
          <span style={{ fontSize: 13, color: '#F8FAFC', fontWeight: 500 }}>{label}</span>
          {desc && <span style={{ fontSize: 11, color: '#475569', marginLeft: 8 }}>{desc}</span>}
        </div>
        <span style={{
          fontSize: 13, fontWeight: 700, color, fontFamily: 'monospace',
          background: `${color}15`, padding: '2px 8px', borderRadius: 6,
        }}>
          {format ? format(value) : value}
        </span>
      </div>
      <div style={{ position: 'relative', height: 6, background: '#1E2D4F', borderRadius: 3 }}>
        <div style={{
          position: 'absolute', left: 0, top: 0, height: '100%',
          width: `${pct}%`, background: color, borderRadius: 3,
          transition: 'width 0.1s',
        }} />
        <input
          type="range" min={min} max={max} step={step}
          value={value}
          onChange={e => onChange(parseFloat(e.target.value))}
          style={{
            position: 'absolute', inset: 0, opacity: 0,
            width: '100%', cursor: 'pointer', margin: 0,
          }}
        />
      </div>
    </div>
  )
}

function Input({ label, desc, value, onChange, type = 'text', placeholder }) {
  return (
    <div style={{ marginBottom: 14 }}>
      <label style={{ fontSize: 12, color: '#64748B', fontWeight: 600,
        display: 'block', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
        {label}
      </label>
      {desc && <div style={{ fontSize: 11, color: '#475569', marginBottom: 6 }}>{desc}</div>}
      <input
        type={type} value={value} placeholder={placeholder}
        onChange={e => onChange(e.target.value)}
        style={{
          width: '100%', padding: '9px 12px', borderRadius: 8, fontSize: 13,
          background: '#0A0E1A', border: '1px solid #1E2D4F',
          color: '#F8FAFC', outline: 'none', boxSizing: 'border-box',
        }}
      />
    </div>
  )
}

// ─── Page principale ──────────────────────────────────────────────────

export default function Settings() {
  const [cfg, setCfg]       = useState(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving]   = useState(false)
  const [saved, setSaved]     = useState(false)
  const [error, setError]     = useState(null)

  const load = async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await apiFetch('/api/alerts/settings/')
      setCfg(data)
    } catch (e) {
      setError('Impossible de charger les paramètres — vérifie que Django tourne sur :8001')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const set = (key, val) => setCfg(prev => ({ ...prev, [key]: val }))
  const setThreshold = (cls, val) => setCfg(prev => ({
    ...prev, thresholds: { ...prev.thresholds, [cls]: val }
  }))

  const save = async () => {
    setSaving(true)
    setError(null)
    try {
      await apiFetch('/api/alerts/settings/', {
        method: 'PUT',
        body: JSON.stringify(cfg),
      })
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch {
      setError('Erreur lors de la sauvegarde')
    } finally {
      setSaving(false)
    }
  }

  if (loading) return (
    <div style={{ padding: 32, color: '#94A3B8' }}>Chargement des paramètres...</div>
  )
  if (error && !cfg) return (
    <div style={{ padding: 32, color: '#EF4444' }}>{error}</div>
  )

  return (
    <div style={{ padding: 32, color: '#F8FAFC', maxWidth: 860 }}>

      {/* ── Header ── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 28 }}>
        <div>
          <h1 style={{ margin: '0 0 6px', fontSize: 22, fontWeight: 800 }}>Paramètres IDS</h1>
          <p style={{ margin: 0, color: '#94A3B8', fontSize: 13 }}>
            Configuration du moteur de détection Mylo
            {cfg?.updated_at && (
              <span style={{ marginLeft: 12, color: '#334155' }}>
                · Mis à jour {new Date(cfg.updated_at).toLocaleString('fr-FR')}
                {cfg.updated_by && ` par ${cfg.updated_by}`}
              </span>
            )}
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button onClick={load} style={{
            padding: '9px 16px', borderRadius: 8, border: '1px solid #1E2D4F',
            background: 'transparent', color: '#94A3B8', cursor: 'pointer',
            display: 'flex', alignItems: 'center', gap: 6, fontSize: 13,
          }}>
            <RefreshCw size={14} /> Réinitialiser
          </button>
          <button onClick={save} disabled={saving} style={{
            padding: '9px 20px', borderRadius: 8, border: 'none',
            background: saved ? '#22C55E' : saving ? '#1E3A6E' : '#3B82F6',
            color: '#fff', cursor: saving ? 'not-allowed' : 'pointer',
            display: 'flex', alignItems: 'center', gap: 6,
            fontSize: 13, fontWeight: 700, transition: 'background 0.2s',
          }}>
            <Save size={14} />
            {saved ? '✓ Sauvegardé !' : saving ? 'Sauvegarde...' : 'Sauvegarder'}
          </button>
        </div>
      </div>

      {error && (
        <div style={{
          padding: '10px 16px', borderRadius: 8, marginBottom: 16,
          background: 'rgba(239,68,68,0.1)', border: '1px solid #EF4444',
          color: '#EF4444', fontSize: 13,
        }}>⚠️ {error}</div>
      )}

      {/* ── 1. Détection ── */}
      <Section icon={Shield} title="Détection" color="#3B82F6">
        <Slider
          label="Seuil binaire (Normal / Attaque)"
          desc="Probabilité minimale pour déclarer une attaque"
          value={cfg.binary_threshold} min={0.1} max={0.9} step={0.01}
          onChange={v => set('binary_threshold', v)}
          format={v => `${(v * 100).toFixed(0)}%`}
          color="#3B82F6"
        />
        <Slider
          label="Confiance alerte 'Nouvelle'"
          desc="En dessous → statut 'À vérifier'"
          value={cfg.confidence_alert} min={0.1} max={0.99} step={0.01}
          onChange={v => set('confidence_alert', v)}
          format={v => `${(v * 100).toFixed(0)}%`}
          color="#EAB308"
        />
      </Section>

      {/* ── 2. Thresholds par classe ── */}
      <Section icon={Zap} title="Seuils par classe d'attaque" color="#A855F7">
        <p style={{ fontSize: 12, color: '#475569', marginTop: 0, marginBottom: 16 }}>
          Plus le seuil est bas, plus Mylo est sensible pour cette classe (plus de détections, plus de faux positifs possibles).
        </p>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 32px' }}>
          {Object.entries(cfg.thresholds || {}).map(([cls, val]) => (
            <Slider
              key={cls}
              label={cls}
              value={val} min={0.05} max={0.95} step={0.01}
              onChange={v => setThreshold(cls, v)}
              format={v => `${(v * 100).toFixed(0)}%`}
              color={ATTACK_COLORS[cls] || '#94A3B8'}
            />
          ))}
        </div>
      </Section>

      {/* ── 3. Blocage automatique ── */}
      <Section icon={AlertTriangle} title="Blocage automatique" color="#EF4444">
        <Toggle
          label="Blocage automatique activé"
          desc="Bloque automatiquement les IP dont le score dépasse le seuil"
          value={cfg.auto_block_enabled}
          onChange={v => set('auto_block_enabled', v)}
        />
        <div style={{ marginTop: 16 }}>
          <Slider
            label="Seuil de blocage automatique"
            desc="Score minimum pour déclencher le blocage"
            value={cfg.auto_block_threshold} min={0.5} max={0.99} step={0.01}
            onChange={v => set('auto_block_threshold', v)}
            format={v => `${(v * 100).toFixed(0)}%`}
            color="#EF4444"
          />
          <Slider
            label="Durée du blocage"
            value={cfg.auto_block_duration} min={300} max={86400} step={300}
            onChange={v => set('auto_block_duration', v)}
            format={v => {
              const h = Math.floor(v / 3600)
              const m = Math.floor((v % 3600) / 60)
              return h > 0 ? `${h}h${m > 0 ? m + 'm' : ''}` : `${m}m`
            }}
            color="#F97316"
          />
        </div>
      </Section>

      {/* ── 4. River ── */}
      <Section icon={Brain} title="Apprentissage en ligne (River)" color="#22C55E">
        <Toggle
          label="River activé"
          desc="Mylo apprend en continu depuis le trafic réel"
          value={cfg.river_enabled}
          onChange={v => set('river_enabled', v)}
        />
        <div style={{ marginTop: 16 }}>
          <Slider
            label="Seuil d'apprentissage River"
            desc="Confiance minimum pour que River apprenne automatiquement"
            value={cfg.river_learn_threshold} min={0.3} max={0.99} step={0.01}
            onChange={v => set('river_learn_threshold', v)}
            format={v => `${(v * 100).toFixed(0)}%`}
            color="#22C55E"
          />
        </div>
      </Section>

      {/* ── 5. Notifications ── */}
      <Section icon={Bell} title="Notifications" color="#F97316">
        <Toggle
          label="Notifications activées"
          value={cfg.notif_enabled}
          onChange={v => set('notif_enabled', v)}
        />
        {cfg.notif_enabled && (
          <div style={{ marginTop: 16 }}>
            <div style={{ marginBottom: 14 }}>
              <label style={{ fontSize: 12, color: '#64748B', fontWeight: 600,
                display: 'block', marginBottom: 6 }}>SÉVÉRITÉ MINIMALE</label>
              <div style={{ display: 'flex', gap: 8 }}>
                {['CRITICAL', 'HIGH', 'MEDIUM'].map(s => (
                  <button key={s} onClick={() => set('notif_min_severity', s)} style={{
                    padding: '6px 14px', borderRadius: 6, fontSize: 12, fontWeight: 600,
                    border: `1px solid ${cfg.notif_min_severity === s ? '#3B82F6' : '#1E2D4F'}`,
                    background: cfg.notif_min_severity === s ? 'rgba(59,130,246,0.15)' : 'transparent',
                    color: cfg.notif_min_severity === s ? '#3B82F6' : '#64748B',
                    cursor: 'pointer',
                  }}>{s}</button>
                ))}
              </div>
            </div>
            <Input label="Token Telegram Bot"
              value={cfg.notif_telegram_token} placeholder="1234567890:AAF..."
              onChange={v => set('notif_telegram_token', v)} />
            <Input label="Chat ID Telegram"
              value={cfg.notif_telegram_chat} placeholder="-100123456789"
              onChange={v => set('notif_telegram_chat', v)} />
            <Input label="Email d'alerte"
              value={cfg.notif_email} type="email" placeholder="admin@securebank.ci"
              onChange={v => set('notif_email', v)} />
            <Input label="Webhook URL"
              value={cfg.notif_webhook_url} placeholder="https://hooks.slack.com/..."
              onChange={v => set('notif_webhook_url', v)} />
          </div>
        )}
      </Section>

      <Section icon={MapPin} title="Localisation du réseau surveillé" color="#14B8A6">
        <Input label="Nom du réseau" desc="Nom affiché sur la Threat Map (ex: SecureBank, Acme Corp...)"
          value={cfg?.network_name || ''} onChange={v => set('network_name', v)} />
        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16 }}>
          <Input label="Latitude" desc="Ex: 5.3600 pour Abidjan" type="number"
            value={cfg?.network_latitude || 0} onChange={v => set('network_latitude', parseFloat(v)||0)} />
          <Input label="Longitude" desc="Ex: -4.0083 pour Abidjan" type="number"
            value={cfg?.network_longitude || 0} onChange={v => set('network_longitude', parseFloat(v)||0)} />
        </div>
        <div style={{ fontSize:11, color:'#475569', marginTop:4 }}>
          💡 Trouve les coordonnées sur <a href="https://www.latlong.net" target="_blank" rel="noreferrer" style={{color:'#3B82F6'}}>latlong.net</a>
           — Ces coordonnées placent le marqueur ◆ sur la Threat Map.
        </div>
      </Section>

      {/* Bouton save en bas */}
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 8 }}>
        <button onClick={save} disabled={saving} style={{
          padding: '11px 28px', borderRadius: 8, border: 'none',
          background: saved ? '#22C55E' : '#3B82F6',
          color: '#fff', cursor: 'pointer', fontWeight: 700, fontSize: 14,
          display: 'flex', alignItems: 'center', gap: 8,
        }}>
          <Save size={16} />
          {saved ? '✓ Sauvegardé !' : 'Sauvegarder les paramètres'}
        </button>
      </div>
    </div>
  )
}