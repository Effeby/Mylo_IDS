import { BrowserRouter, Routes, Route, Navigate, useLocation, useNavigate, Outlet } from 'react-router-dom'

import { useState, useRef, useEffect } from 'react'
import { ChevronUp, Menu } from 'lucide-react'
import Sidebar, { SIDEBAR_WIDTH } from './components/Sidebar'
import CopilotChat from './components/CopilotChat'
import Login from './pages/Login'
import Monitor from './pages/Monitor'
import Alerts from './pages/Alerts'
import Stats from './pages/Stats'
import Settings from './pages/Settings'
import { MonitorProvider } from './context/MonitorContext'
import Dashboard from './pages/Dashboard'
import Onboarding from './pages/Onboarding'
import Register from './pages/Register'
import AuditLog from './pages/AuditLog'
import Behavior from './pages/Behavior'
import Correlation from './pages/Correlation'
import SetupTOTP from './pages/SetupTOTP'
import VerifyTOTP from './pages/VerifyTOTP'
import ChangePassword from './pages/ChangePassword'
import NotFound from './pages/NotFound'

const DJANGO_URL = import.meta.env.VITE_DJANGO_URL || 'https://mylo-ids.site'



// ─── Son d'alerte global ──────────────────────────────────────────────────────
function playAlertSound(severity = 'HIGH') {
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

// ─── Polling global alertes ───────────────────────────────────────────────────
function useGlobalAlertSound() {
  const lastIdRef      = useRef(0)
  const initializedRef = useRef(false)

  useEffect(() => {
    const check = async () => {
      const token = localStorage.getItem('mylo_access')
      if (!token) return
      try {
        const res  = await fetch(`${DJANGO_URL}/api/alerts/?limit=10`, {
          headers: { Authorization: `Bearer ${token}` }
        })
        if (!res.ok) return
        const data = await res.json()
        const list = data.results || data
        if (list.length === 0) return

        const latestId = list[0].id
        if (!initializedRef.current) {
          lastIdRef.current    = latestId
          initializedRef.current = true
          return
        }

        const newAttacks = list.filter(a =>
          a.id > lastIdRef.current &&
          a.is_attack &&
          ['CRITICAL', 'HIGH', 'MEDIUM'].includes(a.severity)
        )

        if (newAttacks.length > 0) {
          const worst = newAttacks.sort((a, b) => {
            const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2 }
            return (order[a.severity] || 3) - (order[b.severity] || 3)
          })[0]
          playAlertSound(worst.severity)
        }
        lastIdRef.current = latestId
      } catch(e) {}
    }

    const timeout = setTimeout(() => {
      check()
      const interval = setInterval(check, 4000)
      return () => clearInterval(interval)
    }, 2000)

    return () => clearTimeout(timeout)
  }, [])
}

// ─── Guard : redirige vers onboarding si pas encore configuré ────────────────
function OnboardingGuard({ children }) {
  const navigate  = useNavigate()
  const location  = useLocation()

  useEffect(() => {
    // Ne pas rediriger si déjà sur ces pages publiques
    if (['/onboarding', '/', '/register', '/totp-setup', '/totp-verify', '/password-change', '/404'].includes(location.pathname)) return

    const token = localStorage.getItem('mylo_access')
    if (!token) return

    try {
      const user = JSON.parse(localStorage.getItem('mylo_user') || '{}')
      if (user?.organisation && user.organisation.is_setup_done === false) {
        navigate('/onboarding', { replace: true })
      }
    } catch(e) {}
  }, [location.pathname])

  return children
}

// ─── Guard auth (anti-retour après logout) ────────────────────────────────
function AuthGuard() {
  const navigate = useNavigate()
  const location = useLocation()

  useEffect(() => {
    const publicPaths = new Set([
      '/',
      '/register',
      '/onboarding',
      '/totp-setup',
      '/totp-verify',
      '/password-change',
      '/404',
    ])



    if (publicPaths.has(location.pathname)) return

    const token = localStorage.getItem('mylo_access')
    if (token) return

    // Evite de laisser l'historique navigateur ramener sur des routes privées après logout.
    navigate('/', { replace: true })
  }, [location.pathname, navigate])

  return <Outlet />
}


const MOBILE_BREAKPOINT = 900

function useIsMobile() {
  const [isMobile, setIsMobile] = useState(
    typeof window !== 'undefined' ? window.innerWidth <= MOBILE_BREAKPOINT : false
  )
  useEffect(() => {
    const onResize = () => setIsMobile(window.innerWidth <= MOBILE_BREAKPOINT)
    window.addEventListener('resize', onResize)
    return () => window.removeEventListener('resize', onResize)
  }, [])
  return isMobile
}

// ─── Layout ───────────────────────────────────────────────────────────────────
function Layout({ children }) {

  const [copilotOpen, setCopilotOpen]     = useState(false)
  const [showScrollTop, setShowScrollTop] = useState(false)
  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem('mylo_sidebar_collapsed') === 'true'
  )
  const [mobileOpen, setMobileOpen] = useState(false)
  const mainRef  = useRef(null)
  const location = useLocation()
  const isMobile = useIsMobile()

  // Sidebar affichée uniquement sur les pages privées connues. Tout le reste
  // (login, onboarding, 404, ou n'importe quelle route inconnue qui tombe sur
  // la route catch-all "*") s'affiche en plein écran, sans menu.
  const PRIVATE_PATHS = ['/dashboard', '/monitor', '/alerts', '/stats', '/settings', '/audit', '/behavior', '/correlation']
  const noSidebar = !PRIVATE_PATHS.includes(location.pathname)


  useGlobalAlertSound()

  // Ferme le tiroir mobile à chaque changement de page.
  useEffect(() => { setMobileOpen(false) }, [location.pathname])

  const handleScroll = () => {
    if (mainRef.current) setShowScrollTop(mainRef.current.scrollTop > 300)
  }

  const toggleSidebar = () => {
    if (isMobile) {
      setMobileOpen(o => !o)
    } else {
      setCollapsed(c => {
        const next = !c
        localStorage.setItem('mylo_sidebar_collapsed', String(next))
        return next
      })
    }
  }

  if (noSidebar) return children

  // Desktop : la sidebar est repliée via un wrapper qui réduit sa largeur à 0
  // et masque le débordement — on cache ainsi tout le menu (pas juste une
  // version réduite), exactement comme demandé ("la cacher ou l'afficher").
  // Mobile : la sidebar est position:fixed (cf. Sidebar.jsx) et ne prend donc
  // aucune place dans le flux, le wrapper peut rester à largeur 0.
  const desktopWrapperWidth = isMobile ? 0 : (collapsed ? 0 : SIDEBAR_WIDTH)

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden', background: '#0A0E1A' }}>
      <div style={{
        flexShrink: 0, height: '100vh', overflow: 'hidden',
        width: desktopWrapperWidth,
        transition: 'width 0.22s ease',
      }}>
        <Sidebar
          onCopilot={() => setCopilotOpen(!copilotOpen)}
          isMobile={isMobile}
          mobileOpen={mobileOpen}
          onCloseMobile={() => setMobileOpen(false)}
        />
      </div>

      {isMobile && mobileOpen && (
        <div className="mylo-sidebar-backdrop" onClick={() => setMobileOpen(false)} />
      )}

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        {/* Barre fixe contenant le bouton menu — fait partie du flux normal,
            ne chevauche donc jamais le contenu des pages (contrairement à un
            bouton flottant en position:fixed). */}
        <div style={{
          flexShrink: 0, height: 44, display: 'flex', alignItems: 'center',
          padding: '0 12px', borderBottom: '1px solid #1E2D4F', background: '#0A0E1A',
        }}>
          <button
            onClick={toggleSidebar}
            aria-label="Afficher/masquer le menu"
            title="Afficher/masquer le menu"
            style={{
              width: 32, height: 32, borderRadius: 8,
              border: '1px solid #1E2D4F', background: '#0F1629',
              color: '#94A3B8', cursor: 'pointer',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}
          >
            <Menu size={17} />
          </button>
        </div>

        <main
          ref={mainRef}
          onScroll={handleScroll}
          style={{ flex: 1, overflowY: 'auto', position: 'relative', minWidth: 0 }}
        >
          {children}
          {showScrollTop && (
            <button
              onClick={() => mainRef.current?.scrollTo({ top: 0, behavior: 'smooth' })}
              style={{
                position: 'fixed', bottom: 28, right: 28, zIndex: 999,
                padding: '8px 18px', borderRadius: 24,
                border: '1px solid #1E2D4F', background: '#0F1629',
                color: '#94A3B8', cursor: 'pointer', fontSize: 12, fontWeight: 600,
                display: 'flex', alignItems: 'center', gap: 6,
                boxShadow: '0 4px 20px rgba(0,0,0,0.4)',
              }}
            >
              <ChevronUp size={14} /> Retour en haut
            </button>
          )}
        </main>
      </div>
      {copilotOpen && (
        <CopilotChat
          onClose={() => setCopilotOpen(false)}
          authToken={localStorage.getItem('mylo_access')}
        />
      )}
    </div>
  )
}

// ─── App ──────────────────────────────────────────────────────────────────────
export default function App() {
  return (
    <BrowserRouter>
      <MonitorProvider>
        <Layout>
          <OnboardingGuard>
            <Routes>
              <Route path="/"                element={<Login />} />
              <Route path="/register"        element={<Register />} />
              <Route path="/onboarding"      element={
                <Onboarding
                  authToken={localStorage.getItem('mylo_access')}
                  onComplete={() => {
                    // Mettre à jour le user local
                    try {
                      const u = JSON.parse(localStorage.getItem('mylo_user') || '{}')
                      if (u.organisation) u.organisation.is_setup_done = true
                      localStorage.setItem('mylo_user', JSON.stringify(u))
                    } catch(e) {}
                    window.location.href = '/totp-setup'
                  }}
                />
              } />
              <Route path="/totp-setup"       element={<SetupTOTP />} />
              <Route path="/totp-verify"      element={<VerifyTOTP />} />
              <Route path="/password-change" element={<ChangePassword />} />

              <Route path="/404"             element={<NotFound />} />

              <Route element={<AuthGuard />}>
                <Route path="/dashboard"   element={<Dashboard />} />
                <Route path="/monitor"     element={<Monitor />} />
                <Route path="/alerts"      element={<Alerts />} />
                <Route path="/stats"       element={<Stats />} />
                <Route path="/settings"    element={<Settings />} />
                <Route path="/audit"        element={<AuditLog />} />
                <Route path="/behavior"     element={<Behavior />} />
                <Route path="/correlation"  element={<Correlation />} />
              </Route>

              <Route path="*"            element={<NotFound />} />
            </Routes>
          </OnboardingGuard>
        </Layout>
      </MonitorProvider>
    </BrowserRouter>
  )
}