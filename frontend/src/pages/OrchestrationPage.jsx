import { useEffect, useState } from 'react'
import { Network, RefreshCw, Eye, Play } from 'lucide-react'
import { api } from '../utils/api'
import SettingsForm from '../components/SettingsForm'
import { Toast, Spinner } from '../components/ui'
import { PageHeader, useToast } from '../components/pageKit'

export default function OrchestrationPage() {
  const { toast, show, hide } = useToast()
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')
  const [result, setResult] = useState(null)
  async function load() {
    try {
      const [docker, kubernetes] = await Promise.all([api.get('/autoconf'), api.get('/kubernetes')])
      setData({ docker, kubernetes }); setError('')
    } catch (e) { setError(e.message) }
  }
  useEffect(() => { load() }, [])
  async function scan(source, dryRun) {
    setBusy(source); setResult(null)
    try {
      const r = await api.post(source === 'docker' ? '/autoconf/scan' : '/kubernetes/scan', { dry_run: dryRun })
      setResult({ source, ...r })
      show(r.skipped ? 'Controller is disabled' : r.dryRun ? 'Preview ready' : !r.changed ? 'Configuration is already up to date' : r.reloaded ? 'Configuration applied and reloaded' : 'Configuration saved; check proxy reload status')
      await load()
    } catch (e) { show(e.message, 'error') }
    finally { setBusy('') }
  }
  return <div className="p-6 max-w-5xl mx-auto page-enter space-y-4">
    {toast && <Toast {...toast} onClose={hide} />}
    <PageHeader icon={Network} title="Docker & Kubernetes" subtitle="Discover, preview, and reconcile protected application routes" />
    <SettingsForm group="sites" onSaved={() => { show('Site capacity saved'); load() }} onError={m => show(m, 'error')} />
    {error && <div role="alert" className="card">{error}<button className="btn btn-sm btn-ghost" onClick={load}><RefreshCw size={14} /> Retry</button></div>}
    {!data && !error && <Spinner label="Loading controllers" />}
    {['docker', 'kubernetes'].map(source => <section className="space-y-3" key={source}>
      <SettingsForm group={source === 'docker' ? 'autoconf' : 'kubernetes'} onSaved={() => { show('Settings saved'); load() }} onError={m => show(m, 'error')} />
      <div className="card">
        <div className="flex items-center justify-between gap-3 mb-3">
          <h2 className="section-title">{source === 'docker' ? 'Docker routes' : 'Kubernetes ingress routes'}</h2>
          <div className="flex gap-2">
            <button className="btn btn-sm btn-ghost" disabled={!!busy || !data?.[source]?.enabled} onClick={() => scan(source, true)}><Eye size={14} /> Preview</button>
            <button className="btn btn-sm btn-primary" disabled={!!busy || !data?.[source]?.enabled} onClick={() => scan(source, false)}><Play size={14} /> Reconcile now</button>
          </div>
        </div>
        {busy === source && <Spinner label="Reconciling routes" />}
        {data?.[source]?.last?.error && <p role="alert" className="text-sm text-red-400 mb-3">Last reconciliation failed: {data[source].last.error}</p>}
        {!data?.[source]?.routes?.length ? <p className="text-sm text-cat-sub">No routes managed by this controller.</p> :
          <div className="overflow-x-auto"><table className="w-full text-left text-sm">
            <thead><tr><th>Host</th><th>Path</th><th>Match</th><th>Upstream</th><th>TLS</th></tr></thead>
            <tbody>{data[source].routes.map(r => <tr key={r.id}><td>{r.host}</td><td>{r.path}</td><td>{r.pathType}</td><td>{r.upstream}</td><td>{r.tls}</td></tr>)}</tbody>
          </table></div>}
        {result?.source === source && <div className="mt-3" aria-live="polite">
          <p className="text-sm">{result.dryRun ? 'Preview' : 'Reconciliation'}: {result.routes?.length || 0} routes, {result.removed || 0} removals. {result.changed ? 'Changes detected.' : 'No changes.'}</p>
          {result.reloadError && <p role="alert" className="text-sm text-red-400">{result.reloadError}</p>}
          {result.dryRun && <pre className="mt-2 text-xs overflow-x-auto">{JSON.stringify(result.routes, null, 2)}</pre>}
        </div>}
      </div>
    </section>)}
  </div>
}
