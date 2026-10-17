import React, { useState, useCallback, Suspense, lazy } from 'react'
import { Routes, Route } from 'react-router-dom'
import { Check } from 'lucide-react'
import Sidebar from './components/Sidebar.jsx'
import Header from './components/Header.jsx'
import WelcomeTour, { useTour } from './components/WelcomeTour.jsx'
import Dashboard from './pages/Dashboard.jsx'
import { Spinner } from './components/ui.jsx'
import { api } from './utils/api.js'
import { CatAIDock } from './components/catai/CatAIDock.jsx'
import { usePreferences } from './utils/preferences.jsx'

const AttackMap           = lazy(() => import('./pages/AttackMap.jsx'))
const ThreatsPage         = lazy(() => import('./pages/Threats.jsx'))
const RulesPage           = lazy(() => import('./pages/RulesPage.jsx'))
const LogsPage            = lazy(() => import('./pages/LogsPage.jsx'))
const SecurityScorePage   = lazy(() => import('./pages/SecurityScorePage.jsx'))
const ParanoiaPage        = lazy(() => import('./pages/Paranoia.jsx'))
const SensitiveFiles      = lazy(() => import('./pages/SensitiveFiles.jsx'))
const CloudflareWizardPage = lazy(() => import('./pages/V2Pages.jsx').then(m => ({ default: m.CloudflareWizardPage })))
const AlertsV2Page        = lazy(() => import('./pages/V2Pages.jsx').then(m => ({ default: m.AlertsV2Page })))
const OriginScannerPage   = lazy(() => import('./pages/OpsPages.jsx').then(m => ({ default: m.OriginScannerPage })))
const PerformanceModePage = lazy(() => import('./pages/OpsPages.jsx').then(m => ({ default: m.PerformanceModePage })))
const DiagnosticsPage     = lazy(() => import('./pages/OpsPages.jsx').then(m => ({ default: m.DiagnosticsPage })))
const EnginePage          = lazy(() => import('./pages/Pages.jsx').then(m => ({ default: m.EnginePage })))
const IPListPage          = lazy(() => import('./pages/Pages.jsx').then(m => ({ default: m.IPListPage })))
const GeoPage             = lazy(() => import('./pages/Pages.jsx').then(m => ({ default: m.GeoPage })))
const AnalyticsPage       = lazy(() => import('./pages/Pages.jsx').then(m => ({ default: m.AnalyticsPage })))
const AboutPage           = lazy(() => import('./pages/Pages.jsx').then(m => ({ default: m.AboutPage })))

const BansPage            = lazy(() => import('./pages/ProtectionPages.jsx').then(m => ({ default: m.BansPage })))
const ChallengePage       = lazy(() => import('./pages/ProtectionPages.jsx').then(m => ({ default: m.ChallengePage })))
const ThreatIntelPage     = lazy(() => import('./pages/ProtectionPages.jsx').then(m => ({ default: m.ThreatIntelPage })))
const BehaviorPage        = lazy(() => import('./pages/ProtectionPages.jsx').then(m => ({ default: m.BehaviorPage })))
const ToolFingerprintPage = lazy(() => import('./pages/ProtectionPages.jsx').then(m => ({ default: m.ToolFingerprintPage })))

const AccessControlPage   = lazy(() => import('./pages/ConfigPages.jsx').then(m => ({ default: m.AccessControlPage })))
const HeadersPage         = lazy(() => import('./pages/ConfigPages.jsx').then(m => ({ default: m.HeadersPage })))
const TlsPage             = lazy(() => import('./pages/ConfigPages.jsx').then(m => ({ default: m.TlsPage })))
const ProxyPage           = lazy(() => import('./pages/ConfigPages.jsx').then(m => ({ default: m.ProxyPage })))
const NetworkConfigPage   = lazy(() => import('./pages/ConfigPages.jsx').then(m => ({ default: m.NetworkPage })))
const AdvancedConfigPage  = lazy(() => import('./pages/ConfigPages.jsx').then(m => ({ default: m.AdvancedConfigPage })))

const JobsPage            = lazy(() => import('./pages/OpsExtraPages.jsx').then(m => ({ default: m.JobsPage })))
const CachesPage          = lazy(() => import('./pages/OpsExtraPages.jsx').then(m => ({ default: m.CachesPage })))
const TemplatesPage       = lazy(() => import('./pages/OpsExtraPages.jsx').then(m => ({ default: m.TemplatesPage })))
const ReportsPage         = lazy(() => import('./pages/OpsExtraPages.jsx').then(m => ({ default: m.ReportsPage })))
const TwoFactorPage       = lazy(() => import('./pages/OpsExtraPages.jsx').then(m => ({ default: m.TwoFactorPage })))
const BackupsPage         = lazy(() => import('./pages/OpsExtraPages.jsx').then(m => ({ default: m.BackupsPage })))
const TelemetryPage       = lazy(() => import('./pages/OpsExtraPages.jsx').then(m => ({ default: m.TelemetryPage })))
const OrchestrationPage   = lazy(() => import('./pages/OrchestrationPage.jsx'))

const THEME_OPTIONS = [
  { id: 'dark',     label: 'Dark',       desc: 'Blue-accented dark theme',            preview: ['#0d0f14','#13161d','#4f8ef7'] },
  { id: 'black',    label: 'Pure Black', desc: 'OLED-friendly, monochrome',           preview: ['#000000','#111111','#ffffff'] },
  { id: 'white',    label: 'Pure White', desc: 'Clean light mode',                    preview: ['#f8fafc','#ffffff','#6366f1'] },
  { id: 'midnight', label: 'Midnight',   desc: 'Deep purple midnight',                preview: ['#070712','#0d0d1f','#818cf8'] },
]
const MOTION_OPTIONS = [
  { id: 'full',    label: 'Full',    desc: 'All animations at full speed' },
  { id: 'reduced', label: 'Reduced', desc: 'Shorter, calmer transitions' },
  { id: 'minimal', label: 'Minimal', desc: 'Only essential motion' },
  { id: 'off',     label: 'Off',     desc: 'No animation anywhere' },
]
const MAP_PROJECTION_OPTIONS = [
  { id: '2d', label: '2D Map' },
  { id: '3d', label: '3D Planet' },
]
const MAP_PERFORMANCE_OPTIONS = [
  { id: 'low',      label: 'Low',      desc: 'Sparse dots, fewer markers' },
  { id: 'balanced', label: 'Balanced', desc: 'Recommended default' },
  { id: 'high',     label: 'High',     desc: 'Dense dots, more markers' },
]

function PickerGroup({ options, value, onChange, columns = 3, swatch }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: `repeat(${columns}, 1fr)`, gap: 8 }}>
      {options.map(o => {
        const active = value === o.id
        return (
          <button
            key={o.id}
            onClick={() => onChange(o.id)}
            aria-pressed={active}
            style={{
              display: 'flex', flexDirection: 'column', gap: 4, padding: '10px 12px',
              borderRadius: 'calc(9px * var(--cat-radius, 1))',
              border: `1px solid ${active ? 'var(--cat-accent)' : 'var(--cat-border)'}`,
              background: active ? 'color-mix(in srgb, var(--cat-accent) 8%, transparent)' : 'var(--cat-surface)',
              cursor: 'pointer', textAlign: 'left', transition: 'all 0.15s ease',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              {swatch && swatch(o)}
              <span style={{ fontSize: 12.5, fontWeight: 600, color: active ? 'var(--cat-accent)' : 'var(--cat-text)' }}>{o.label}</span>
            </div>
            {o.desc && <span style={{ fontSize: 10.5, color: 'var(--cat-sub)' }}>{o.desc}</span>}
          </button>
        )
      })}
    </div>
  )
}

function SettingsPage() {
  const { reset: resetTour } = useTour()
  const { prefs, set } = usePreferences()
  const [sysInfo, setSysInfo] = useState(null)
  React.useEffect(() => { api.get('/diagnostics').then(setSysInfo).catch(() => setSysInfo(null)) }, [])

  return (
    <div className="p-6 space-y-5 page-enter">
      <div className="card animate-slide-up">
        <div className="section-title">Theme</div>
        <div className="grid grid-cols-2 gap-3">
          {THEME_OPTIONS.map(t => (
            <button
              key={t.id}
              onClick={() => set('theme', t.id)}
              style={{
                display: 'flex', alignItems: 'center', gap: 12, padding: '12px 14px',
                borderRadius: 10, border: `1px solid ${prefs.theme === t.id ? 'var(--cat-accent)' : 'var(--cat-border)'}`,
                background: prefs.theme === t.id ? 'color-mix(in srgb, var(--cat-accent) 8%, transparent)' : 'var(--cat-surface)',
                cursor: 'pointer', textAlign: 'left', transition: 'all 0.15s ease',
              }}
            >
              <div style={{ display: 'flex', gap: 3, flexShrink: 0 }}>
                {t.preview.map((c, i) => (
                  <div key={i} style={{ width: 12, height: 12, borderRadius: 3, background: c, border: '1px solid rgba(255,255,255,0.1)' }} />
                ))}
              </div>
              <div>
                <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--cat-text)' }}>{t.label}</div>
                <div style={{ fontSize: 11, color: 'var(--cat-sub)', marginTop: 1 }}>{t.desc}</div>
              </div>
              {prefs.theme === t.id && (
                <div style={{ marginLeft: 'auto', color: 'var(--cat-accent)', display: 'flex' }}><Check size={14} /></div>
              )}
            </button>
          ))}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 12, paddingTop: 12, borderTop: '1px solid var(--cat-border)' }}>
          <input
            type="color"
            value={/^#[0-9a-f]{6}$/i.test(prefs.accentCustom) ? prefs.accentCustom : '#4f8ef7'}
            onChange={e => set('accentCustom', e.target.value)}
            style={{ width: 32, height: 32, padding: 0, border: '1px solid var(--cat-border)', borderRadius: 6, cursor: 'pointer', background: 'none' }}
          />
          <div style={{ fontSize: 11.5, color: 'var(--cat-sub)' }}>Custom accent color, overrides the theme's default</div>
          {prefs.accentCustom && (
            <button className="btn btn-sm btn-ghost" style={{ marginLeft: 'auto' }} onClick={() => set('accentCustom', '')}>
              Reset
            </button>
          )}
        </div>
      </div>

      <div className="card animate-slide-up">
        <div className="section-title">Motion</div>
        <PickerGroup options={MOTION_OPTIONS} value={prefs.motion} onChange={v => set('motion', v)} columns={2} />
        <div style={{ fontSize: 10.5, color: 'var(--cat-sub)', marginTop: 10 }}>
          Controls animation across the sidebar, charts, live events, and the Attack Map. Defaults to your system's reduced-motion preference.
        </div>
      </div>

      <div className="card animate-slide-up">
        <div className="section-title">Attack Map</div>
        <div style={{ fontSize: 11, color: 'var(--cat-sub)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Default Projection</div>
        <PickerGroup options={MAP_PROJECTION_OPTIONS} value={prefs.mapProjection} onChange={v => set('mapProjection', v)} columns={2} />
        <div style={{ fontSize: 11, color: 'var(--cat-sub)', margin: '14px 0 8px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Performance</div>
        <PickerGroup options={MAP_PERFORMANCE_OPTIONS} value={prefs.mapPerformance} onChange={v => set('mapPerformance', v)} columns={3} />
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 14 }}>
          <div style={{ fontSize: 12.5, color: 'var(--cat-text)' }}>Auto-rotate 3D planet</div>
          <button className={`btn btn-sm ${prefs.mapAutoRotate === 'on' ? 'btn-primary' : 'btn-ghost'}`} onClick={() => set('mapAutoRotate', prefs.mapAutoRotate === 'on' ? 'off' : 'on')}>
            {prefs.mapAutoRotate === 'on' ? 'On' : 'Off'}
          </button>
        </div>
      </div>

      <div className="card animate-slide-up">
        <div className="section-title">Dashboard Widgets</div>
        {[
          ['dashboardAttackTypes', 'Attack Types chart'],
          ['dashboardRecentRequests', 'Recent Requests table'],
          ['dashboardTopTargets', 'Top Targeted IPs'],
        ].map(([field, label]) => (
          <div key={field} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '7px 0' }}>
            <div style={{ fontSize: 12.5, color: 'var(--cat-text)' }}>{label}</div>
            <button className={`btn btn-sm ${prefs[field] === 'on' ? 'btn-primary' : 'btn-ghost'}`} onClick={() => set(field, prefs[field] === 'on' ? 'off' : 'on')}>
              {prefs[field] === 'on' ? 'Shown' : 'Hidden'}
            </button>
          </div>
        ))}
      </div>

      <div className="card animate-slide-up">
        <div className="section-title">Onboarding</div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div style={{ fontSize: 13, color: 'var(--cat-text)', fontWeight: 500 }}>Welcome Tour</div>
            <div style={{ fontSize: 12, color: 'var(--cat-sub)', marginTop: 2 }}>Replay the guided tour of every CatWAF feature</div>
          </div>
          <button className="btn btn-ghost btn-sm" onClick={() => { resetTour(); window.location.reload() }} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <img src="/assets/logo/catwaf-icon-256.png" alt="" style={{ width: 14, height: 14, objectFit: 'contain' }} /> Replay Tour
          </button>
        </div>
      </div>

      <div className="card animate-slide-up">
        <div className="section-title">About CatWAF</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {[
            { k: 'Version', v: sysInfo?.catwaf_version || '—' },
            { k: 'Edition', v: sysInfo?.edition ? sysInfo.edition[0].toUpperCase() + sysInfo.edition.slice(1) : '—' },
            { k: 'Engine', v: 'Coraza WAF + Caddy' },
            { k: 'Ruleset', v: 'OWASP CRS' },
            { k: 'Frontend', v: 'React + Vite' },
            { k: 'Backend', v: 'Node/Express' },
            { k: 'Runtime', v: sysInfo?.node_version || '—' },
            { k: 'Persistence', v: 'SQLite (node:sqlite)' },
          ].map(({ k, v }) => (
            <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, padding: '8px 0', borderBottom: '1px solid var(--cat-border)' }}>
              <span style={{ color: 'var(--cat-sub)' }}>{k}</span>
              <span style={{ color: 'var(--cat-text)', fontWeight: 500 }}>{v}</span>
            </div>
          ))}
        </div>

        <div className="catwaf-credit">
          <img src="/assets/logo/catwaf-icon-256.png" alt="" />
          <div className="catwaf-credit-text">
            <span>MADE BY <strong>Zachary Yanakiev</strong></span>
            <span className="catwaf-credit-initials">K.Z.</span>
          </div>
        </div>
      </div>

    </div>
  )
}

function RouteFallback() {
  const [visible, setVisible] = useState(false)
  React.useEffect(() => {
    const t = setTimeout(() => setVisible(true), 180)
    return () => clearTimeout(t)
  }, [])
  return (
    <div
      role="status"
      aria-live="polite"
      aria-busy="true"
      style={{
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        height: '60vh', color: 'var(--cat-sub)',
        opacity: visible ? 1 : 0, transition: 'opacity var(--dur-2) ease',
      }}
    >
      <Spinner size={22} label="Loading page" />
    </div>
  )
}

export default function App() {
  const [refreshKey, setRefreshKey] = useState(0)
  const refresh = useCallback(() => setRefreshKey(k => k + 1), [])
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [sidebarCollapsed, setSidebarCollapsed] = useState(
    () => localStorage.getItem('catwaf-sidebar-collapsed') === '1'
  )
  const { show: showTour, setShow: setShowTour } = useTour()

  React.useEffect(() => {
    const openTour = () => setShowTour(true)
    window.addEventListener('catwaf-open-tour', openTour)
    return () => window.removeEventListener('catwaf-open-tour', openTour)
  }, [setShowTour])

  return (
    <div className="app-shell">
      <a href="#main-content" className="skip-link">Skip to main content</a>
      <Sidebar
        open={sidebarOpen}
        onClose={() => setSidebarOpen(false)}
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed(c => {
          localStorage.setItem('catwaf-sidebar-collapsed', c ? '0' : '1')
          return !c
        })}
      />
      <div className="main-content">
        <Header onMenuClick={() => setSidebarOpen(s => !s)} />
        {showTour && <WelcomeTour onDone={() => setShowTour(false)} />}
        <main id="main-content" tabIndex={-1} className="page-scroll" key={refreshKey} style={{ position: "relative" }}>
          <Suspense fallback={<RouteFallback />}>
          <Routes>
            <Route path="/"               element={<Dashboard />} />
            <Route path="/attack-map"     element={<AttackMap />} />
            <Route path="/threats"        element={<ThreatsPage />} />
            <Route path="/security-score" element={<SecurityScorePage />} />
            <Route path="/analytics"      element={<AnalyticsPage />} />

            <Route path="/rules"          element={<RulesPage />} />
            <Route path="/engine"         element={<EnginePage />} />
            <Route path="/paranoia"       element={<ParanoiaPage />} />
            <Route path="/performance-mode"element={<PerformanceModePage />} />

            <Route path="/protection/sensitive-files" element={<SensitiveFiles />} />
            <Route path="/protection/bans"        element={<BansPage />} />
            <Route path="/protection/challenge"   element={<ChallengePage />} />
            <Route path="/protection/threat-intel" element={<ThreatIntelPage />} />
            <Route path="/protection/behavior"    element={<BehaviorPage />} />
            <Route path="/protection/tool-fingerprint" element={<ToolFingerprintPage />} />

            <Route path="/ip/whitelist"   element={<IPListPage listType="whitelist" />} />
            <Route path="/ip/blacklist"   element={<IPListPage listType="blacklist" />} />
            <Route path="/geo"            element={<GeoPage />} />

            <Route path="/config/access"   element={<AccessControlPage />} />
            <Route path="/config/headers"  element={<HeadersPage />} />
            <Route path="/config/tls"      element={<TlsPage />} />
            <Route path="/config/proxy"    element={<ProxyPage />} />
            <Route path="/config/network"  element={<NetworkConfigPage />} />
            <Route path="/config/advanced" element={<AdvancedConfigPage />} />

            <Route path="/system/jobs"      element={<JobsPage />} />
            <Route path="/system/orchestration" element={<OrchestrationPage />} />
            <Route path="/system/caches"    element={<CachesPage />} />
            <Route path="/system/templates" element={<TemplatesPage />} />
            <Route path="/system/reports"   element={<ReportsPage />} />
            <Route path="/system/backups"   element={<BackupsPage />} />
            <Route path="/system/2fa"       element={<TwoFactorPage />} />
            <Route path="/system/telemetry" element={<TelemetryPage />} />

            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/origin-scanner"  element={<OriginScannerPage />} />
            <Route path="/logs"            element={<LogsPage />} />
            <Route path="/diagnostics"     element={<DiagnosticsPage />} />
            <Route path="/about"    element={<AboutPage />} />
            <Route path="/cloudflare"       element={<CloudflareWizardPage />} />
            <Route path="/alerts"           element={<AlertsV2Page />} />
          </Routes>
          </Suspense>
        </main>
      </div>
      <CatAIDock />
    </div>
  )
}
