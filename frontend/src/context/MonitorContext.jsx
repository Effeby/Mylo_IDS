import { createContext, useContext, useState, useEffect, useRef } from 'react'
import { getAlerts } from '../api/mylo'

const MonitorContext = createContext(null)

// Son d'alerte — créé à la demande (après interaction utilisateur)
function playAlertSound(severity) {
  try {
    const files = {
      CRITICAL: '/sounds/alert-critical.wav',
      HIGH:     '/sounds/alert-high.wav',
      MEDIUM:   '/sounds/alert-medium.wav',
    }
    const audio = new Audio(files[severity] || files['HIGH'])
    audio.volume = severity === 'CRITICAL' ? 1.0 : severity === 'HIGH' ? 0.7 : 0.5
    audio.play().catch(() => {
      // Fallback bip Web Audio
      try {
        const ctx  = new (window.AudioContext || window.webkitAudioContext)()
        const freq = severity === 'CRITICAL' ? 1100 : severity === 'HIGH' ? 880 : 660
        ;[0, 0.15, 0.30].forEach(delay => {
          const osc  = ctx.createOscillator()
          const gain = ctx.createGain()
          osc.connect(gain); gain.connect(ctx.destination)
          osc.frequency.value = freq
          osc.type = 'sine'
          gain.gain.setValueAtTime(0.3, ctx.currentTime + delay)
          gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + delay + 0.12)
          osc.start(ctx.currentTime + delay)
          osc.stop(ctx.currentTime + delay + 0.12)
        })
      } catch(e) {}
    })
  } catch(e) {}
}

export function MonitorProvider({ children }) {
  const [results,   setResults]   = useState([])
  const [running,   setRunning]   = useState(false)
  const [stats,     setStats]     = useState({ total: 0, attacks: 0, normal: 0 })
  const [captureOk, setCaptureOk] = useState(null)
  const lastIdRef   = useRef(0)
  const intervalRef = useRef(null)

  useEffect(() => {
    if (running) {
      intervalRef.current = setInterval(async () => {
        try {
          const alerts = await getAlerts({ limit: 20 })
          if (!alerts || alerts.length === 0) {
            setCaptureOk(false)
            return
          }
          setCaptureOk(true)

          const newAlerts = alerts.filter(a => a.id > lastIdRef.current)
          if (newAlerts.length === 0) return

          lastIdRef.current = Math.max(...newAlerts.map(a => a.id))
          setResults(prev => [...newAlerts, ...prev].slice(0, 100))

          // Compter correctement — is_attack peut être true/false ou 1/0
          const attackCount = newAlerts.filter(a => a.is_attack === true || a.is_attack === 1).length
          const normalCount = newAlerts.length - attackCount

          setStats(prev => ({
            total:   prev.total   + newAlerts.length,
            attacks: prev.attacks + attackCount,
            normal:  prev.normal  + normalCount,
          }))

          // Son — jouer pour les nouvelles attaques
          const newAttacks = newAlerts.filter(a =>
            (a.is_attack === true || a.is_attack === 1) &&
            ['CRITICAL', 'HIGH', 'MEDIUM'].includes(a.severity)
          )
          if (newAttacks.length > 0) {
            // Jouer le son le plus grave
            const worst = newAttacks.sort((a, b) => {
              const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2 }
              return (order[a.severity] || 3) - (order[b.severity] || 3)
            })[0]
            playAlertSound(worst.severity)
          }
        } catch(e) {
          setCaptureOk(false)
        }
      }, 2000)
    } else {
      clearInterval(intervalRef.current)
    }
    return () => clearInterval(intervalRef.current)
  }, [running])

  const start = async () => {
    try {
      const alerts = await getAlerts({ limit: 1 })
      if (alerts && alerts.length > 0) {
        lastIdRef.current = alerts[0].id
      }
    } catch(e) {}
    setResults([])
    setStats({ total: 0, attacks: 0, normal: 0 })
    setCaptureOk(null)
    setRunning(true)
  }

  const stop = () => {
    setRunning(false)
    setCaptureOk(null)
  }

  return (
    <MonitorContext.Provider value={{ results, running, stats, captureOk, start, stop }}>
      {children}
    </MonitorContext.Provider>
  )
}

export function useMonitor() {
  return useContext(MonitorContext)
}