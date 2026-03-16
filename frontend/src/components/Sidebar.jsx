import { NavLink } from 'react-router-dom'
import { Activity, Bell, BarChart2, LogOut, Shield, Settings, LayoutDashboard, Map } from 'lucide-react'

const nav = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Overview' },
  { to: '/monitor',  icon: Activity,  label: 'Live Monitor' },
  { to: '/alerts',   icon: Bell,      label: 'Alertes' },
  { to: '/stats',    icon: BarChart2, label: 'Statistiques' },
  { to: '/settings', icon: Settings,  label: 'Paramètres' },
  { to: '/map', icon: Map, label: 'Threat Map' }
]


export default function Sidebar({ onCopilot }) {
  return (
    <aside style={{
      width: 220, minHeight: '100vh', background: '#0F1629',
      borderRight: '1px solid #1E2D4F', display: 'flex',
      flexDirection: 'column', padding: '24px 0',
    }}>
      {/* Logo */}
      <div style={{ padding: '0 24px 32px', borderBottom: '1px solid #1E2D4F' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 38, height: 38, borderRadius: 10,
            background: 'linear-gradient(135deg, #3B82F6, #1E40AF)',
            display: 'flex', alignItems: 'center', justifyContent: 'center'
          }}>
            <Shield size={20} color="#fff" />
          </div>
          <div>
            <div style={{ color: '#F8FAFC', fontWeight: 700, fontSize: 18 }}>Mylo</div>
            <div style={{ color: '#94A3B8', fontSize: 11 }}>IDS SecureBank</div>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav style={{ flex: 1, padding: '24px 12px' }}>
        {nav.map(({ to, icon: Icon, label }) => (
          <NavLink key={to} to={to} style={({ isActive }) => ({
            display: 'flex', alignItems: 'center', gap: 12,
            padding: '10px 12px', borderRadius: 8, marginBottom: 4,
            textDecoration: 'none', fontSize: 14, fontWeight: 500,
            background: isActive ? 'rgba(59,130,246,0.15)' : 'transparent',
            color: isActive ? '#3B82F6' : '#94A3B8',
            borderLeft: isActive ? '3px solid #3B82F6' : '3px solid transparent',
            transition: 'all 0.2s',
          })}>
            <Icon size={18} />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Copilot Button */}
      <div style={{ padding: '0 12px 16px' }}>
        <button onClick={onCopilot} style={{
          width: '100%', padding: '10px 12px', borderRadius: 8,
          background: 'rgba(59,130,246,0.1)', border: '1px solid #3B82F6',
          color: '#3B82F6', cursor: 'pointer', fontSize: 13, fontWeight: 600,
          display: 'flex', alignItems: 'center', gap: 8,
        }}>
          🤖 Mylo Copilot
        </button>
      </div>

      {/* Logout */}
      <div style={{ padding: '0 12px' }}>
        <NavLink to="/" style={{
          display: 'flex', alignItems: 'center', gap: 12,
          padding: '10px 12px', borderRadius: 8, textDecoration: 'none',
          color: '#94A3B8', fontSize: 14,
        }}>
          <LogOut size={18} /> Déconnexion
        </NavLink>
      </div>
    </aside>
  )
}