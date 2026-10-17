import { useState, useRef, useEffect } from 'react'
import { NavLink } from 'react-router-dom'
import { Cloud,
  LayoutDashboard, Activity, Settings,
  Globe, Ban, CheckCircle, FolderOpen,
  Search, Globe2, ShieldAlert, FileText,
  BarChart2, Bell,
  Zap, Sliders,
  ShieldCheck, Wrench,
  ShieldQuestion, Radar, Lock, FileCode, Server, Network, KeyRound, Fingerprint,
  Clock, Database, LayoutTemplate, FileBarChart, Archive, Send,
  ChevronDown, ChevronLeft, X, Menu
} from 'lucide-react'

export const NAV = [
  { group: 'Overview', items: [
    { path: '/',              icon: LayoutDashboard, label: 'Dashboard' },
    { path: '/attack-map',    icon: Globe2,          label: 'Attack Map' },
    { path: '/threats',       icon: ShieldAlert,     label: 'Threats' },
    { path: '/security-score', icon: ShieldCheck,    label: 'Security' },
    { path: '/analytics',  icon: BarChart2,       label: 'Analytics' },
  ]},
  { group: 'WAF Engine', items: [
    { path: '/rules',          icon: Wrench,      label: 'Rules' },
    { path: '/engine',         icon: Zap,         label: 'Engine Mode' },
    { path: '/paranoia',       icon: Sliders,     label: 'Paranoia Levels' },
    { path: '/performance-mode', icon: Zap,       label: 'Performance Mode' },
  ]},
  { group: 'Protection', items: [
    { path: '/protection/sensitive-files',icon: FolderOpen,     label: 'Sensitive Files' },
    { path: '/protection/bans',           icon: Ban,            label: 'Active Bans' },
    { path: '/protection/challenge',      icon: ShieldQuestion, label: 'Challenge Gate' },
    { path: '/protection/threat-intel',   icon: Radar,          label: 'Threat Intel' },
    { path: '/protection/behavior',       icon: Activity,       label: 'Behavioural Banning' },
    { path: '/protection/tool-fingerprint', icon: Fingerprint,  label: 'Tool Fingerprinting' },
  ]},
  { group: 'Access Control', items: [
    { path: '/ip/whitelist', icon: CheckCircle, label: 'IP Whitelist' },
    { path: '/ip/blacklist', icon: Ban,         label: 'IP Blacklist' },
    { path: '/geo',          icon: Globe,       label: 'Geo Blocking' },
  ]},
  { group: 'Configuration', items: [
    { path: '/config/access',   icon: ShieldAlert, label: 'Access Control' },
    { path: '/config/headers',  icon: FileCode,    label: 'Content & Headers' },
    { path: '/config/tls',      icon: Lock,        label: 'TLS & Certificates' },
    { path: '/config/proxy',    icon: Server,      label: 'Reverse Proxy' },
    { path: '/config/network',  icon: Network,     label: 'Network' },
    { path: '/config/advanced', icon: KeyRound,    label: 'Advanced' },
  ]},
  { group: 'System', items: [
    { path: '/logs',     icon: FileText,  label: 'Logs' },
    { path: '/settings', icon: Settings,  label: 'Settings' },
    { path: '/alerts',   icon: Bell,      label: 'Alerts' },
    { path: '/system/jobs',      icon: Clock,          label: 'Scheduled Jobs' },
    { path: '/system/orchestration', icon: Network,    label: 'Docker & Kubernetes' },
    { path: '/system/caches',    icon: Database,       label: 'Caches' },
    { path: '/system/templates', icon: LayoutTemplate, label: 'Templates' },
    { path: '/system/reports',   icon: FileBarChart,   label: 'Reports' },
    { path: '/system/backups',   icon: Archive,        label: 'Backups' },
    { path: '/system/2fa',       icon: KeyRound,       label: 'Two-Factor' },
    { path: '/system/telemetry', icon: Send,           label: 'Telemetry' },
    { path: '/origin-scanner',   icon: Search,         label: 'Origin Exposure Scanner' },
    { path: '/diagnostics',      icon: Activity,       label: 'Setup Diagnostics' },
    { path: '/about',    icon: Wrench,    label: 'About / Versions' },
  ]},
  { group: 'Cloudflare', items: [
    { path: '/cloudflare',       icon: Cloud,        label: 'Cloudflare Wizard' },
  ]},
]

let groupSeq = 0

function NavGroup({ group, items, onClose }) {
  const [open, setOpen] = useState(true)
  const contentRef = useRef(null)
  const [height, setHeight] = useState('auto')
  const panelId = useRef(`nav-group-${++groupSeq}`).current

  useEffect(() => {
    if (contentRef.current) {
      setHeight(open ? `${contentRef.current.scrollHeight}px` : '0px')
    }
  }, [open])

  return (
    <div style={{ marginBottom: 2 }}>
      <button
        onClick={() => setOpen(o => !o)}
        className="nav-group-label"
        aria-expanded={open}
        aria-controls={panelId}
      >
        {group}
        <span style={{ transition: `transform var(--dur-2) var(--ease-out)`, transform: open ? 'rotate(0deg)' : 'rotate(-90deg)', display: 'inline-flex' }}>
          <ChevronDown size={9} style={{ opacity: 0.5 }} aria-hidden="true" />
        </span>
      </button>
      <div
        id={panelId}
        ref={contentRef}
        style={{
          overflow: 'hidden',
          maxHeight: height,
          opacity: open ? 1 : 0,
          visibility: open ? 'visible' : 'hidden',
          transition: open
            ? 'max-height var(--dur-3) var(--ease-out), opacity var(--dur-2) ease, visibility 0s'
            : 'max-height var(--dur-3) var(--ease-out), opacity var(--dur-2) ease, visibility 0s linear var(--dur-3)',
        }}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 1, paddingBottom: 4 }}>
          {items.map(({ path, icon: Icon, label }) => (
            <NavLink
              key={path} to={path} end={path === '/'}
              className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
              onClick={onClose}
              title={label}
            >
              <Icon size={13} className="nav-icon" style={{ flexShrink: 0 }} aria-hidden="true" />
              <span className="nav-item-label" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{label}</span>
            </NavLink>
          ))}
        </div>
      </div>
    </div>
  )
}

export default function Sidebar({ open, onClose, collapsed, onToggleCollapse }) {
  const navRef = useRef(null)
  const [scrolled, setScrolled] = useState(false)

  useEffect(() => {
    const el = navRef.current
    if (!el) return
    const handler = () => setScrolled(el.scrollTop > 40)
    el.addEventListener('scroll', handler)
    return () => el.removeEventListener('scroll', handler)
  }, [])

  return (
    <>
      <div className={`sidebar-overlay ${open ? 'open' : ''}`} onClick={onClose} />
      <aside className={`sidebar ${open ? 'open' : ''} ${collapsed ? 'collapsed' : ''}`}>
        <div className="sidebar-head">
          <div className="sidebar-brand">
            <div className="animate-logo" style={{ width: 28, height: 28, borderRadius: 8, background: 'color-mix(in srgb, var(--cat-accent) 20%, transparent)', display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden', flexShrink: 0 }}>
              <img src="/assets/logo/catwaf-icon-256.png" alt="CatWAF" style={{ width: 20, height: 20, objectFit: 'contain' }} />
            </div>
            <div className="sidebar-brand-text">
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--cat-text)', lineHeight: 1 }}>CatWAF</div>
              <div style={{ fontSize: 10, color: 'var(--cat-sub)', marginTop: 2 }}>Control Panel</div>
            </div>
          </div>

          <button
            className="sidebar-collapse-btn"
            onClick={onToggleCollapse}
            title={collapsed ? 'Expand control panel' : 'Collapse control panel'}
            aria-label={collapsed ? 'Expand control panel' : 'Collapse control panel'}
            aria-expanded={!collapsed}
          >
            <ChevronLeft size={15} />
          </button>

          <button
            className="btn btn-ghost btn-sm sidebar-close-btn"
            onClick={onClose}
            style={{ display: open ? 'flex' : 'none' }}
            aria-label="Close navigation"
          >
            <X size={14} aria-hidden="true" />
          </button>
        </div>

        <nav ref={navRef} className={`sidebar-nav ${scrolled ? 'scrolled' : ''}`} aria-label="CatWAF sections">
          {NAV.map(({ group, items }) => (
            <NavGroup key={group} group={group} items={items} onClose={onClose} />
          ))}
        </nav>

        <div className="sidebar-foot">
          <div className="sidebar-foot-full" style={{ fontSize: 10, color: 'var(--cat-sub)', opacity: 0.4 }}>Coraza + OWASP CRS v4.7</div>
          <div className="sidebar-foot-mini" aria-hidden="true">CRS</div>
        </div>
      </aside>
    </>
  )
}

export function MobileMenuButton({ onClick }) {
  return (
    <button className="btn btn-ghost btn-sm" onClick={onClick} style={{ padding: '6px 8px' }} aria-label="Open navigation">
      <Menu size={18} aria-hidden="true" />
    </button>
  )
}
