const colors = {
  CRITICAL: { bg: 'rgba(239,68,68,0.15)',  text: '#EF4444', border: '#EF4444' },
  HIGH:     { bg: 'rgba(249,115,22,0.15)', text: '#F97316', border: '#F97316' },
  MEDIUM:   { bg: 'rgba(234,179,8,0.15)',  text: '#EAB308', border: '#EAB308' },
  LOW:      { bg: 'rgba(34,197,94,0.15)',  text: '#22C55E', border: '#22C55E' },
}

export default function AlertBadge({ severity }) {
  const c = colors[severity] || colors.LOW
  return (
    <span style={{
      padding: '3px 10px', borderRadius: 20, fontSize: 11, fontWeight: 700,
      background: c.bg, color: c.text, border: `1px solid ${c.border}`,
      letterSpacing: '0.05em',
    }}>
      {severity}
    </span>
  )
}
