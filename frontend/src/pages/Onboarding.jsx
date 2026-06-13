import { useState } from 'react'
import {
  Building2, Globe, Network, Shield, Bell, Users,
  CheckCircle, ChevronRight, ChevronLeft, Plus, Trash2,
  Wifi, Eye, Zap, MapPin, Mail, Phone, Send
} from 'lucide-react'

const DJANGO_URL = import.meta.env.VITE_DJANGO_URL || 'http://localhost:8001'

const SECTORS = [
  { value: 'banking',    label: 'Banque / Finance' },
  { value: 'health',     label: 'Santé' },
  { value: 'industry',   label: 'Industrie' },
  { value: 'government', label: 'Gouvernement' },
  { value: 'education',  label: 'Éducation' },
  { value: 'telecom',    label: 'Télécommunications' },
  { value: 'retail',     label: 'Commerce / Distribution' },
  { value: 'other',      label: 'Autre' },
]

const ROLES = [
  { value: 'org_admin',   label: 'Administrateur',  level: 4 },
  { value: 'soc_manager', label: 'Manager SOC',     level: 3 },
  { value: 'soc_analyst', label: 'Analyste SOC',    level: 2 },
  { value: 'viewer',      label: 'Observateur',     level: 1 },
]

const DEPLOY_MODES = [
  { value: 'scapy',     label: 'Agent local',        desc: 'Capture Scapy sur ce serveur — idéal pour démarrer', icon: '🖥️' },
  { value: 'suricata',  label: 'Suricata intégré',   desc: 'Logs Suricata envoyés à Mylo — recommandé', icon: '🛡️' },
  { value: 'netflow',   label: 'NetFlow / IPFIX',    desc: 'Résumés de flux depuis le switch — trafic dense', icon: '📊' },
  { value: 'multiagent',label: 'Multi-agents',       desc: 'Un agent par segment réseau — précision maximale', icon: '🌐' },
]

const IDS_MODES = [
  { value: 'observation', label: 'Mode Observation', desc: 'Mylo surveille et alerte sans bloquer. Recommandé pour les 2-4 premières semaines.', icon: Eye, color: '#3B82F6' },
  { value: 'active',      label: 'Mode Actif (IPS)', desc: 'Mylo peut bloquer automatiquement. À activer après la phase de baseline.', icon: Zap, color: '#EF4444' },
]

const BASELINE_DURATIONS = [
  { value: 7,  label: '1 semaine',  desc: 'Réseau simple, peu de machines' },
  { value: 14, label: '2 semaines', desc: 'Recommandé pour la plupart des réseaux' },
  { value: 30, label: '1 mois',     desc: 'Réseaux complexes, trafic saisonnier' },
]

const S = {
  page:    { minHeight: '100vh', background: '#070B14', color: '#F8FAFC', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24 },
  card:    { width: '100%', maxWidth: 720, background: '#0F1629', border: '1px solid #1E2D4F', borderRadius: 16, padding: 40 },
  input:   { width: '100%', padding: '10px 14px', borderRadius: 8, background: '#0A0E1A', border: '1px solid #1E2D4F', color: '#F8FAFC', fontSize: 14, outline: 'none', boxSizing: 'border-box' },
  label:   { fontSize: 12, color: '#94A3B8', fontWeight: 600, marginBottom: 6, display: 'block', letterSpacing: '0.05em' },
  btn:     { padding: '12px 24px', borderRadius: 8, border: 'none', cursor: 'pointer', fontWeight: 700, fontSize: 14, display: 'flex', alignItems: 'center', gap: 8 },
  error:   { color: '#EF4444', fontSize: 12, marginTop: 4 },
}

function Field({ label, children, desc }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <label style={S.label}>{label}</label>
      {children}
      {desc && <div style={{ fontSize: 11, color: '#475569', marginTop: 4 }}>{desc}</div>}
    </div>
  )
}

function StepIndicator({ current, total }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 32 }}>
      {Array.from({ length: total }).map((_, i) => (
        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{
            width: 32, height: 32, borderRadius: '50%',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 13, fontWeight: 700,
            background: i < current ? '#22C55E' : i === current ? '#3B82F6' : '#1E2D4F',
            color: i <= current ? '#fff' : '#475569',
            border: i === current ? '2px solid #3B82F6' : 'none',
            transition: 'all 0.3s',
          }}>
            {i < current ? <CheckCircle size={16} /> : i + 1}
          </div>
          {i < total - 1 && (
            <div style={{ width: 40, height: 2, background: i < current ? '#22C55E' : '#1E2D4F', transition: 'all 0.3s' }} />
          )}
        </div>
      ))}
    </div>
  )
}

export default function Onboarding({ authToken, onComplete }) {
  const [step, setStep]     = useState(0)
  const [saving, setSaving] = useState(false)
  const [error, setError]   = useState('')

  // ── Données du wizard ─────────────────────────────────────────────
  // Préremplir depuis les données d'inscription
  const _user = (() => { try { return JSON.parse(localStorage.getItem('mylo_user') || '{}') } catch { return {} } })()
  const [org, setOrg] = useState({
    name:    _user?.organisation?.name    || '',
    sector:  _user?.organisation?.sector  || 'other',
    email:   _user?.organisation?.email   || '',
    phone:   '',
    website: '',
  })

  const [network, setNetwork] = useState({
    network_name: '', network_address: '',
    network_latitude: '', network_longitude: '',
    deploy_mode: 'suricata',
    vlans: [{ name: 'VLAN Serveurs', range: '192.168.10.0/24', critical: true }],
  })

  const [idsConfig, setIdsConfig] = useState({
    ids_mode: 'observation',
    baseline_days: 14,
    auto_block_threshold: 0.85,
  })

  const [notifs, setNotifs] = useState({
    notif_enabled: false,
    notif_telegram_token: '', notif_telegram_chat: '',
    notif_email: '', notif_min_severity: 'HIGH',
  })

  const [members, setMembers] = useState([
    { username: '', first_name: '', last_name: '', email: '', role: 'soc_analyst', poste: '', password: '' }
  ])

  const steps = [
    { title: 'Réseau',          icon: Network },
    { title: 'Mode IDS',        icon: Shield },
    { title: 'Notifications',   icon: Bell },
    { title: 'Équipe SOC',      icon: Users },
    { title: 'Finalisation',    icon: CheckCircle },
  ]

  // ── Validation par étape ──────────────────────────────────────────
  const validate = () => {
    setError('')
    if (step === 0) {
      if (!network.network_name.trim()) return setError('Le nom du réseau est requis'), false
    }
    return true
  }

  const next = () => { if (validate()) setStep(s => Math.min(s + 1, steps.length - 1)) }
  const prev = () => setStep(s => Math.max(s - 1, 0))

  // ── Soumission finale ─────────────────────────────────────────────
  const submit = async () => {
    setSaving(true)
    setError('')
    // Lire le token frais au moment du submit
    const token = authToken || localStorage.getItem('mylo_access')
    const headers = {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    }
    try {
      // 1. Onboarding organisation
      const r1 = await fetch(`${DJANGO_URL}/api/auth/onboarding/`, {
        method: 'POST', headers,
        body: JSON.stringify({
          ...org,
          ...network,
          notif_enabled:        notifs.notif_enabled,
          notif_telegram_token: notifs.notif_telegram_token,
          notif_telegram_chat:  notifs.notif_telegram_chat,
          notif_email:          notifs.notif_email,
          notif_min_severity:   notifs.notif_min_severity,
          ids_mode:             idsConfig.ids_mode,
          baseline_days:        idsConfig.baseline_days,
        }),
      })
      if (!r1.ok) throw new Error('Erreur lors de la configuration')

      // 2. Créer les membres (ignorer ceux sans username)
      for (const m of members) {
        if (!m.username.trim()) continue
        await fetch(`${DJANGO_URL}/api/auth/users/`, {
          method: 'POST', headers,
          body: JSON.stringify(m),
        })
      }

      // 3. Mettre à jour les settings IDS
      await fetch(`${DJANGO_URL}/api/alerts/settings/`, {
        method: 'PUT', headers,
        body: JSON.stringify({
          auto_block_enabled:  idsConfig.ids_mode === 'active',
          auto_block_threshold: idsConfig.auto_block_threshold,
          notif_enabled:       notifs.notif_enabled,
          notif_telegram_token: notifs.notif_telegram_token,
          notif_telegram_chat:  notifs.notif_telegram_chat,
          notif_email:         notifs.notif_email,
          notif_min_severity:  notifs.notif_min_severity,
          network_name:        network.network_name,
          network_latitude:    parseFloat(network.network_latitude) || 0,
          network_longitude:   parseFloat(network.network_longitude) || 0,
        }),
      })

      onComplete()
    } catch(e) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  // ── Rendu des étapes ─────────────────────────────────────────────
  const renderStep = () => {
    switch(step) {

      // ── ÉTAPE 0 — Réseau ─────────────────────────────────────────
      case 0: return (
        <div>
          <h2 style={{ margin: '0 0 8px', fontSize: 22, fontWeight: 800 }}>Bienvenue sur Mylo IPS 🛡️</h2>
          <p style={{ color: '#64748B', marginBottom: 24, fontSize: 13 }}>
            Configurons maintenant votre réseau surveillé.
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <Field label="NOM DU RÉSEAU *">
              <input style={S.input} placeholder="Ex: Réseau HQ Abidjan"
                value={network.network_name} onChange={e => setNetwork(p => ({...p, network_name: e.target.value}))} />
            </Field>
            <Field label="ADRESSE PHYSIQUE">
              <input style={S.input} placeholder="Ex: Avenue Noguès, Abidjan"
                value={network.network_address} onChange={e => setNetwork(p => ({...p, network_address: e.target.value}))} />
            </Field>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <Field label="LATITUDE" desc="Trouvez sur latlong.net">
              <input style={S.input} type="number" placeholder="5.3600"
                value={network.network_latitude} onChange={e => setNetwork(p => ({...p, network_latitude: e.target.value}))} />
            </Field>
            <Field label="LONGITUDE">
              <input style={S.input} type="number" placeholder="-4.0083"
                value={network.network_longitude} onChange={e => setNetwork(p => ({...p, network_longitude: e.target.value}))} />
            </Field>
          </div>

          <Field label="MODE DE DÉPLOIEMENT">
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
              {DEPLOY_MODES.map(m => (
                <div key={m.value} onClick={() => setNetwork(p => ({...p, deploy_mode: m.value}))}
                  style={{
                    padding: '12px 14px', borderRadius: 8, cursor: 'pointer', transition: 'all 0.2s',
                    border: `1px solid ${network.deploy_mode === m.value ? '#3B82F6' : '#1E2D4F'}`,
                    background: network.deploy_mode === m.value ? 'rgba(59,130,246,0.08)' : '#0A0E1A',
                  }}>
                  <div style={{ fontSize: 18, marginBottom: 4 }}>{m.icon}</div>
                  <div style={{ fontSize: 13, fontWeight: 700, color: '#F8FAFC' }}>{m.label}</div>
                  <div style={{ fontSize: 11, color: '#64748B', marginTop: 2 }}>{m.desc}</div>
                </div>
              ))}
            </div>
          </Field>

          {/* VLANs */}
          <Field label="SEGMENTS RÉSEAU / VLANs">
            {network.vlans.map((v, i) => (
              <div key={i} style={{ display: 'grid', gridTemplateColumns: '2fr 2fr 1fr auto', gap: 8, marginBottom: 8, alignItems: 'center' }}>
                <input style={S.input} placeholder="Nom (ex: VLAN Serveurs)"
                  value={v.name} onChange={e => {
                    const vlans = [...network.vlans]
                    vlans[i].name = e.target.value
                    setNetwork(p => ({...p, vlans}))
                  }} />
                <input style={S.input} placeholder="Plage (ex: 192.168.10.0/24)"
                  value={v.range} onChange={e => {
                    const vlans = [...network.vlans]
                    vlans[i].range = e.target.value
                    setNetwork(p => ({...p, vlans}))
                  }} />
                <select style={S.input} value={v.critical ? 'true' : 'false'} onChange={e => {
                  const vlans = [...network.vlans]
                  vlans[i].critical = e.target.value === 'true'
                  setNetwork(p => ({...p, vlans}))
                }}>
                  <option value="true">🔴 Critique</option>
                  <option value="false">🟢 Standard</option>
                </select>
                <button onClick={() => setNetwork(p => ({...p, vlans: p.vlans.filter((_, j) => j !== i)}))}
                  style={{ background: 'none', border: 'none', color: '#EF4444', cursor: 'pointer', padding: 4 }}>
                  <Trash2 size={16} />
                </button>
              </div>
            ))}
            <button onClick={() => setNetwork(p => ({...p, vlans: [...p.vlans, {name:'', range:'', critical:false}]}))}
              style={{ ...S.btn, background: 'transparent', border: '1px dashed #1E2D4F', color: '#64748B', fontSize: 12, marginTop: 4 }}>
              <Plus size={14} /> Ajouter un segment
            </button>
          </Field>
        </div>
      )

      // ── ÉTAPE 1 — Mode IDS ───────────────────────────────────────
      case 1: return (
        <div>
          <h2 style={{ margin: '0 0 8px', fontSize: 20, fontWeight: 800 }}>Mode de détection</h2>
          <p style={{ color: '#64748B', marginBottom: 24, fontSize: 13 }}>
            Choisissez comment Mylo va réagir aux menaces détectées.
          </p>

          <Field label="MODE IDS">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {IDS_MODES.map(m => {
                const Icon = m.icon
                const selected = idsConfig.ids_mode === m.value
                return (
                  <div key={m.value} onClick={() => setIdsConfig(p => ({...p, ids_mode: m.value}))}
                    style={{
                      padding: '16px 20px', borderRadius: 10, cursor: 'pointer',
                      border: `1px solid ${selected ? m.color : '#1E2D4F'}`,
                      background: selected ? `${m.color}10` : '#0A0E1A',
                      display: 'flex', alignItems: 'center', gap: 14,
                    }}>
                    <div style={{ width: 40, height: 40, borderRadius: 8, background: `${m.color}20`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <Icon size={20} color={m.color} />
                    </div>
                    <div>
                      <div style={{ fontWeight: 700, fontSize: 14, color: selected ? m.color : '#F8FAFC' }}>{m.label}</div>
                      <div style={{ fontSize: 12, color: '#64748B', marginTop: 2 }}>{m.desc}</div>
                    </div>
                    {selected && <CheckCircle size={20} color={m.color} style={{ marginLeft: 'auto' }} />}
                  </div>
                )
              })}
            </div>
          </Field>

          <Field label="DURÉE DE LA PHASE DE BASELINE" desc="Pendant cette période, Mylo apprend le comportement normal de votre réseau avant d'alerter.">
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 10 }}>
              {BASELINE_DURATIONS.map(d => (
                <div key={d.value} onClick={() => setIdsConfig(p => ({...p, baseline_days: d.value}))}
                  style={{
                    padding: '12px', borderRadius: 8, cursor: 'pointer', textAlign: 'center',
                    border: `1px solid ${idsConfig.baseline_days === d.value ? '#3B82F6' : '#1E2D4F'}`,
                    background: idsConfig.baseline_days === d.value ? 'rgba(59,130,246,0.08)' : '#0A0E1A',
                  }}>
                  <div style={{ fontSize: 18, fontWeight: 800, color: '#3B82F6' }}>{d.label}</div>
                  <div style={{ fontSize: 11, color: '#64748B', marginTop: 4 }}>{d.desc}</div>
                </div>
              ))}
            </div>
          </Field>

          {idsConfig.ids_mode === 'active' && (
            <Field label="SEUIL DE BLOCAGE AUTOMATIQUE" desc="Mylo bloque automatiquement si la confiance dépasse ce seuil.">
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <input type="range" min={0.5} max={1} step={0.05}
                  value={idsConfig.auto_block_threshold}
                  onChange={e => setIdsConfig(p => ({...p, auto_block_threshold: parseFloat(e.target.value)}))}
                  style={{ flex: 1 }} />
                <span style={{ color: '#EF4444', fontWeight: 800, fontSize: 18, minWidth: 50 }}>
                  {Math.round(idsConfig.auto_block_threshold * 100)}%
                </span>
              </div>
            </Field>
          )}

          <div style={{ padding: '14px 16px', borderRadius: 8, background: 'rgba(59,130,246,0.06)', border: '1px solid #1E2D4F', fontSize: 12, color: '#94A3B8' }}>
            💡 <strong>Recommandation :</strong> Commencez en mode Observation pendant {idsConfig.baseline_days} jours.
            Une fois la baseline établie, passez en mode Actif progressivement.
          </div>
        </div>
      )

      // ── ÉTAPE 2 — Notifications ──────────────────────────────────
      case 2: return (
        <div>
          <h2 style={{ margin: '0 0 8px', fontSize: 20, fontWeight: 800 }}>Notifications & Alertes</h2>
          <p style={{ color: '#64748B', marginBottom: 24, fontSize: 13 }}>
            Configurez comment votre équipe sera notifiée des incidents.
          </p>

          {/* Toggle Telegram */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '14px 16px', borderRadius: 10, border: '1px solid #1E2D4F', background: '#0A0E1A', marginBottom: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ fontSize: 20 }}>📱</span>
              <div>
                <div style={{ fontWeight: 700, fontSize: 14 }}>Notifications Telegram</div>
                <div style={{ fontSize: 12, color: '#64748B' }}>Recevoir les alertes sur Telegram</div>
              </div>
            </div>
            <div onClick={() => setNotifs(p => ({...p, notif_enabled: !p.notif_enabled}))}
              style={{
                width: 44, height: 24, borderRadius: 12, cursor: 'pointer', position: 'relative',
                background: notifs.notif_enabled ? '#22C55E' : '#1E2D4F', transition: 'all 0.2s',
              }}>
              <div style={{
                position: 'absolute', top: 2, width: 20, height: 20, borderRadius: '50%', background: '#fff',
                left: notifs.notif_enabled ? 22 : 2, transition: 'all 0.2s',
              }} />
            </div>
          </div>

          {notifs.notif_enabled && (
            <>
              <Field label="TOKEN BOT TELEGRAM">
                <input style={S.input} placeholder="8649586999:AAGJ1T..."
                  value={notifs.notif_telegram_token}
                  onChange={e => setNotifs(p => ({...p, notif_telegram_token: e.target.value}))} />
              </Field>
              <Field label="CHAT ID TELEGRAM">
                <input style={S.input} placeholder="5225530595"
                  value={notifs.notif_telegram_chat}
                  onChange={e => setNotifs(p => ({...p, notif_telegram_chat: e.target.value}))} />
              </Field>
            </>
          )}

          <Field label="EMAIL DE NOTIFICATION">
            <input style={S.input} type="email" placeholder="soc-alerts@entreprise.com"
              value={notifs.notif_email}
              onChange={e => setNotifs(p => ({...p, notif_email: e.target.value}))} />
          </Field>

          <Field label="SÉVÉRITÉ MINIMALE POUR NOTIFIER">
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 10 }}>
              {[['CRITICAL','🔴','#EF4444'],['HIGH','🟠','#F97316'],['MEDIUM','🟡','#EAB308']].map(([val,icon,color]) => (
                <div key={val} onClick={() => setNotifs(p => ({...p, notif_min_severity: val}))}
                  style={{
                    padding: '10px', borderRadius: 8, cursor: 'pointer', textAlign: 'center',
                    border: `1px solid ${notifs.notif_min_severity === val ? color : '#1E2D4F'}`,
                    background: notifs.notif_min_severity === val ? `${color}15` : '#0A0E1A',
                  }}>
                  <div style={{ fontSize: 20 }}>{icon}</div>
                  <div style={{ fontSize: 12, fontWeight: 700, color: notifs.notif_min_severity === val ? color : '#94A3B8', marginTop: 4 }}>{val}</div>
                </div>
              ))}
            </div>
          </Field>
        </div>
      )

      // ── ÉTAPE 3 — Équipe SOC ─────────────────────────────────────
      case 3: return (
        <div>
          <h2 style={{ margin: '0 0 8px', fontSize: 20, fontWeight: 800 }}>Équipe SOC</h2>
          <p style={{ color: '#64748B', marginBottom: 24, fontSize: 13 }}>
            Ajoutez les membres de votre équipe de sécurité. Vous pouvez passer cette étape.
          </p>

          {members.map((m, i) => (
            <div key={i} style={{ background: '#0A0E1A', border: '1px solid #1E2D4F', borderRadius: 10, padding: 16, marginBottom: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                <span style={{ fontWeight: 700, color: '#94A3B8', fontSize: 13 }}>Membre {i + 1}</span>
                {members.length > 1 && (
                  <button onClick={() => setMembers(p => p.filter((_, j) => j !== i))}
                    style={{ background: 'none', border: 'none', color: '#EF4444', cursor: 'pointer' }}>
                    <Trash2 size={14} />
                  </button>
                )}
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <Field label="PRÉNOM">
                  <input style={S.input} placeholder="Jean"
                    value={m.first_name} onChange={e => { const ms=[...members]; ms[i].first_name=e.target.value; setMembers(ms) }} />
                </Field>
                <Field label="NOM">
                  <input style={S.input} placeholder="Dupont"
                    value={m.last_name} onChange={e => { const ms=[...members]; ms[i].last_name=e.target.value; setMembers(ms) }} />
                </Field>
                <Field label="NOM D'UTILISATEUR">
                  <input style={S.input} placeholder="jean.dupont"
                    value={m.username} onChange={e => { const ms=[...members]; ms[i].username=e.target.value; setMembers(ms) }} />
                </Field>
                <Field label="EMAIL">
                  <input style={S.input} type="email" placeholder="jean@entreprise.com"
                    value={m.email} onChange={e => { const ms=[...members]; ms[i].email=e.target.value; setMembers(ms) }} />
                </Field>
                <Field label="POSTE">
                  <input style={S.input} placeholder="Ex: Analyste SOC Senior"
                    value={m.poste} onChange={e => { const ms=[...members]; ms[i].poste=e.target.value; setMembers(ms) }} />
                </Field>
                <Field label="RÔLE">
                  <select style={S.input} value={m.role} onChange={e => {
                    const ms=[...members]
                    const r = ROLES.find(r => r.value === e.target.value)
                    ms[i].role = r.value
                    ms[i].habilitation_level = r.level
                    setMembers(ms)
                  }}>
                    {ROLES.map(r => <option key={r.value} value={r.value}>{r.label} (Niveau {r.level})</option>)}
                  </select>
                </Field>
                <Field label="MOT DE PASSE PROVISOIRE">
                  <input style={S.input} type="password" placeholder="••••••••"
                    value={m.password} onChange={e => { const ms=[...members]; ms[i].password=e.target.value; setMembers(ms) }} />
                </Field>
              </div>
            </div>
          ))}

          <button onClick={() => setMembers(p => [...p, { username:'', first_name:'', last_name:'', email:'', role:'soc_analyst', poste:'', password:'' }])}
            style={{ ...S.btn, background: 'transparent', border: '1px dashed #1E2D4F', color: '#64748B', fontSize: 13, width: '100%', justifyContent: 'center' }}>
            <Plus size={16} /> Ajouter un membre
          </button>
        </div>
      )

      // ── ÉTAPE 4 — Récapitulatif ──────────────────────────────────
      case 4: return (
        <div>
          <h2 style={{ margin: '0 0 8px', fontSize: 20, fontWeight: 800 }}>Récapitulatif</h2>
          <p style={{ color: '#64748B', marginBottom: 24, fontSize: 13 }}>
            Vérifiez les informations avant de finaliser.
          </p>

          {[
            {
              icon: Building2, color: '#3B82F6', title: 'Organisation',
              items: [
                ['Nom', org.name],
                ['Secteur', SECTORS.find(s => s.value === org.sector)?.label],
                ['Email', org.email],
              ]
            },
            {
              icon: Network, color: '#22C55E', title: 'Réseau',
              items: [
                ['Réseau', network.network_name],
                ['Déploiement', DEPLOY_MODES.find(d => d.value === network.deploy_mode)?.label],
                ['Segments', `${network.vlans.length} VLAN(s)`],
              ]
            },
            {
              icon: Shield, color: '#F97316', title: 'Mode IDS',
              items: [
                ['Mode', IDS_MODES.find(m => m.value === idsConfig.ids_mode)?.label],
                ['Baseline', `${idsConfig.baseline_days} jours`],
              ]
            },
            {
              icon: Users, color: '#A855F7', title: 'Équipe',
              items: [
                ['Membres', `${members.filter(m => m.username).length} membre(s) à créer`],
              ]
            },
          ].map(({ icon: Icon, color, title, items }) => (
            <div key={title} style={{ background: '#0A0E1A', border: '1px solid #1E2D4F', borderRadius: 10, padding: '14px 18px', marginBottom: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                <Icon size={16} color={color} />
                <span style={{ fontWeight: 700, fontSize: 13, color }}>{title}</span>
              </div>
              {items.map(([k, v]) => (
                <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, marginBottom: 4 }}>
                  <span style={{ color: '#475569' }}>{k}</span>
                  <span style={{ color: '#F8FAFC', fontWeight: 600 }}>{v || '—'}</span>
                </div>
              ))}
            </div>
          ))}

          <div style={{ padding: '14px 16px', borderRadius: 8, background: 'rgba(34,197,94,0.06)', border: '1px solid #22C55E30', fontSize: 12, color: '#86EFAC' }}>
            ✅ Après la finalisation, Mylo IPS démarrera en <strong>mode {idsConfig.ids_mode === 'observation' ? 'Observation' : 'Actif'}</strong> avec une phase de baseline de <strong>{idsConfig.baseline_days} jours</strong>.
          </div>
        </div>
      )

      default: return null
    }
  }

  return (
    <div style={S.page}>
      <div style={S.card}>

        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 32 }}>
          <div style={{ width: 44, height: 44, borderRadius: 10, background: 'linear-gradient(135deg,#3B82F6,#1E40AF)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Shield size={22} color="#fff" />
          </div>
          <div>
            <div style={{ fontWeight: 800, fontSize: 18 }}>Mylo IPS</div>
            <div style={{ fontSize: 12, color: '#64748B' }}>Configuration initiale</div>
          </div>
        </div>

        <StepIndicator current={step} total={steps.length} />

        {/* Titre de l'étape */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 24 }}>
          {(() => { const Icon = steps[step].icon; return <Icon size={18} color="#3B82F6" /> })()}
          <span style={{ fontSize: 13, color: '#3B82F6', fontWeight: 700, letterSpacing: '0.05em' }}>
            ÉTAPE {step + 1}/{steps.length} — {steps[step].title.toUpperCase()}
          </span>
        </div>

        {/* Contenu */}
        {renderStep()}

        {/* Erreur */}
        {error && <div style={{ ...S.error, marginBottom: 16, fontSize: 13 }}>⚠️ {error}</div>}

        {/* Navigation */}
        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 32 }}>
          <button onClick={prev} disabled={step === 0} style={{
            ...S.btn,
            background: step === 0 ? '#0A0E1A' : '#1E2D4F',
            color: step === 0 ? '#475569' : '#F8FAFC',
            cursor: step === 0 ? 'not-allowed' : 'pointer',
          }}>
            <ChevronLeft size={16} /> Précédent
          </button>

          {step < steps.length - 1 ? (
            <button onClick={next} style={{ ...S.btn, background: '#3B82F6', color: '#fff' }}>
              Suivant <ChevronRight size={16} />
            </button>
          ) : (
            <button onClick={submit} disabled={saving} style={{
              ...S.btn,
              background: saving ? '#1E3A6E' : '#22C55E',
              color: '#fff',
              cursor: saving ? 'not-allowed' : 'pointer',
            }}>
              {saving ? 'Configuration...' : 'Lancer Mylo IPS'} <CheckCircle size={16} />
            </button>
          )}
        </div>

        {/* Skip (étape équipe) */}
        {step === 3 && (
          <div style={{ textAlign: 'center', marginTop: 12 }}>
            <button onClick={next} style={{ background: 'none', border: 'none', color: '#475569', cursor: 'pointer', fontSize: 12 }}>
              Passer cette étape →
            </button>
          </div>
        )}
      </div>
    </div>
  )
}