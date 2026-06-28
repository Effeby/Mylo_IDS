import { useState } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import { Activity, Bell, BarChart2, LogOut, Shield, Settings, LayoutDashboard, ClipboardList, Brain, Link2, X, ChevronLeft, ChevronRight, Bot } from 'lucide-react'

const DJANGO_URL = import.meta.env.VITE_DJANGO_URL || 'https://mylo-ids.site'
const MYLO_LOGO_URL = '/mylo_logo.png' // Put the new Mylo logo image here in frontend/public/mylo_logo.png

const nav = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Overview',       minLevel: 1 },
  { to: '/monitor',   icon: Activity,        label: 'Live Monitor',   minLevel: 1 },
  { to: '/alerts',    icon: Bell,            label: 'Alertes',        minLevel: 1 },
  { to: '/stats',     icon: BarChart2,       label: 'Statistiques',   minLevel: 1 },
  { to: '/settings',  icon: Settings,        label: 'Paramètres',     minLevel: 1 },
  { to: '/audit',     icon: ClipboardList,   label: 'Journal Audit',  minLevel: 3 },
  { to: '/behavior', icon: Brain, label: 'Profils IP', minLevel: 1 },
  { to: '/correlation', icon: Link2, label: 'Corrélations', minLevel: 1 },
]

export const SIDEBAR_WIDTH = 220
export const SIDEBAR_COLLAPSED_WIDTH = 72

export default function Sidebar({ onCopilot, isMobile = false, mobileOpen = false, onCloseMobile, collapsed = false, onToggleCollapse }) {
  const navigate = useNavigate()
  // Le repli (icônes seules) ne s'applique qu'au desktop — sur mobile la
  // sidebar est un tiroir plein écran, toujours pleine largeur quand ouverte.
  const rail = collapsed && !isMobile

  const currentUser = (() => {
    try { return JSON.parse(localStorage.getItem('mylo_user') || '{}') }
    catch { return {} }
  })()
  const [logoLoaded, setLogoLoaded] = useState(true)
  const userLevel = currentUser?.habilitation_level || 1
  const orgName   = currentUser?.organisation?.name || 'Mylo IPS'

  const handleLogout = async () => {
    try {
      const refresh = localStorage.getItem('mylo_refresh')
      const token   = localStorage.getItem('mylo_access')
      if (token) {
        await fetch(`${DJANGO_URL}/api/auth/logout/`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify({ refresh }),
        })
      }
    } catch(e) {}

    // Désauth local
    localStorage.removeItem('mylo_access')
    localStorage.removeItem('mylo_refresh')
    localStorage.removeItem('mylo_user')

    // Empêche le bouton "Retour" de remonter sur des routes privées.
    // On remplit l'historique avec une entrée vers '/'.
    try {
      window.history.pushState({}, '', '/')
      window.history.replaceState({}, '', '/')
      // Ajoute un second step pour limiter le retour immédiat.
      window.history.pushState({}, '', '/')
    } catch(e) {}

    navigate('/', { replace: true })
  }


  const visibleNav = nav.filter(item => userLevel >= item.minLevel)

  return (
    <aside style={{
      width: isMobile ? SIDEBAR_WIDTH : (rail ? SIDEBAR_COLLAPSED_WIDTH : SIDEBAR_WIDTH),
      minHeight: '100vh', background: '#0F1629',
      borderRight: '1px solid #1E2D4F', display: 'flex',
      flexDirection: 'column', padding: '24px 0', flexShrink: 0,
      boxShadow: '4px 0 24px rgba(0,0,0,0.25)',
      transition: 'width 0.22s ease',
      ...(isMobile ? {
        position: 'fixed', top: 0, left: 0, height: '100vh', zIndex: 999,
        transform: mobileOpen ? 'translateX(0)' : 'translateX(-100%)',
        transition: 'transform 0.22s ease',
        boxShadow: mobileOpen ? '4px 0 24px rgba(0,0,0,0.5)' : 'none',
      } : {}),
    }}>
      {/* Logo + toggle — toujours sur la même ligne, repliée ou non */}
      <div style={{
        padding: rail ? '0 6px 16px' : '0 24px 24px', borderBottom: '1px solid #1E2D4F',
        display: 'flex', alignItems: 'center',
        justifyContent: rail ? 'center' : 'space-between',
        gap: rail ? 6 : 0,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
          <div style={{
            width: rail ? 28 : 38, height: rail ? 28 : 38, borderRadius: rail ? 8 : 10, flexShrink: 0,
            background: '#0F1629',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            overflow: 'hidden',
            transition: 'width 0.22s ease, height 0.22s ease',
          }}>
            {rail ? (
              <Shield size={15} color="#fff" />
            ) : logoLoaded ? (
              <img
                src={MYLO_LOGO_URL}
                alt="Mylo logo"
                style={{ width: '100%', height: '100%', objectFit: 'cover' }}
                onError={(event) => {
                  setLogoLoaded(false)
                  event.currentTarget.style.display = 'none'
                }}
              />
            ) : (
              <Shield size={20} color="#fff" />
            )}
          </div>
          {!rail && (
            <div style={{ minWidth: 0 }}>
              <div style={{ color: '#F8FAFC', fontWeight: 800, fontSize: 16 }}>Mylo IPS</div>
              <div style={{ color: '#3B82F6', fontSize: 11, fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                for {orgName}
              </div>
            </div>
          )}
        </div>

        {isMobile ? (
          <button
            onClick={onCloseMobile}
            aria-label="Fermer le menu"
            style={{ background: 'none', border: 'none', color: '#94A3B8', cursor: 'pointer', padding: 6, flexShrink: 0, transition: 'color 0.18s' }}
          >
            <X size={20} />
          </button>
        ) : (
          <button
            onClick={onToggleCollapse}
            aria-label={rail ? 'Agrandir le menu' : 'Réduire le menu'}
            title={rail ? 'Agrandir le menu' : 'Réduire le menu'}
            style={{
              width: rail ? 22 : 28, height: rail ? 22 : 28, borderRadius: 7, flexShrink: 0,
              border: '1px solid #1E2D4F', background: '#131C33',
              color: '#94A3B8', cursor: 'pointer',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              transition: 'background 0.18s, color 0.18s, border-color 0.18s, width 0.22s ease, height 0.22s ease',
            }}
            onMouseEnter={(e) => { e.currentTarget.style.color = '#3B82F6'; e.currentTarget.style.borderColor = '#3B82F6' }}
            onMouseLeave={(e) => { e.currentTarget.style.color = '#94A3B8'; e.currentTarget.style.borderColor = '#1E2D4F' }}
          >
            {rail ? <ChevronRight size={13} /> : <ChevronLeft size={15} />}
          </button>
        )}
      </div>

      {/* Navigation */}
      <nav style={{ flex: 1, padding: '16px 12px' }}>
        {visibleNav.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to} to={to} title={rail ? label : undefined}
            onClick={() => isMobile && onCloseMobile?.()}
            style={({ isActive }) => ({
              display: 'flex', alignItems: 'center', gap: 12,
              justifyContent: rail ? 'center' : 'flex-start',
              padding: rail ? '10px 0' : '10px 12px', borderRadius: 8, marginBottom: 4,
              textDecoration: 'none', fontSize: 14, fontWeight: 500,
              background: isActive ? 'rgba(59,130,246,0.15)' : 'transparent',
              color: isActive ? '#3B82F6' : '#94A3B8',
              borderLeft: isActive ? '3px solid #3B82F6' : '3px solid transparent',
              transition: 'all 0.2s ease',
            })}>
            <Icon size={18} />
            {!rail && label}
          </NavLink>
        ))}
      </nav>

      {/* Copilot */}
      <div style={{ padding: rail ? '0 8px 16px' : '0 12px 16px' }}>
        <button onClick={onCopilot} title={rail ? 'Mylo Copilot' : undefined} style={{
          width: '100%', padding: rail ? '10px 0' : '10px 12px', borderRadius: 8,
          background: 'rgba(59,130,246,0.1)', border: '1px solid #3B82F6',
          color: '#3B82F6', cursor: 'pointer', fontSize: 13, fontWeight: 600,
          display: 'flex', alignItems: 'center', justifyContent: rail ? 'center' : 'flex-start', gap: 8,
          transition: 'background 0.18s',
        }}>
          <Bot size={16} /> {!rail && 'Mylo Copilot'}
        </button>
      </div>

      {/* User + Logout */}
      <div style={{ padding: '0 12px', borderTop: '1px solid #1E2D4F', paddingTop: 12 }}>
        {!rail && (
          <div style={{ padding: '8px 12px', marginBottom: 4 }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: '#F8FAFC', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {currentUser?.fullname || currentUser?.username || '—'}
            </div>
            <div style={{ fontSize: 11, color: '#475569', marginTop: 2 }}>
              {currentUser?.role_display || 'Utilisateur'}
            </div>
          </div>
        )}
        <button onClick={handleLogout} title={rail ? 'Déconnexion' : undefined} style={{
          width: '100%', display: 'flex', alignItems: 'center', gap: 12,
          justifyContent: rail ? 'center' : 'flex-start',
          padding: '10px 12px', borderRadius: 8,
          background: 'none', border: 'none',
          color: '#94A3B8', fontSize: 14, cursor: 'pointer',
          transition: 'color 0.18s',
        }}>
          <LogOut size={18} /> {!rail && 'Déconnexion'}
        </button>
      </div>
    </aside>
  )
}
