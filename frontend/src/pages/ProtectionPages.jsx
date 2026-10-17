import { useCallback, useEffect, useState } from 'react'
import { api, apiBlobUrl } from '../utils/api.js'
import SettingsForm from '../components/SettingsForm.jsx'
import { Toast, Badge, Spinner, EmptyState } from '../components/ui.jsx'
import { PageHeader, useToast, Caveat, KeyValue, relativeTime } from '../components/pageKit.jsx'
import {
  Ban, ShieldQuestion, Radar, Activity, Search, Trash2, RotateCcw,
  Play, Eye, Plus, AlertTriangle, CheckCircle, RefreshCw, Fingerprint,
} from 'lucide-react'

// ─── Bans (#61) ─────────────────────────────────────────────────────────

function expiryLabel(ban) {
  if (ban.permanent) return <Badge color="red">permanent</Badge>
  return <Badge color="orange">expires {relativeTime(ban.expires_at)}</Badge>
}

function EnforcementStatusCard() {
  const [status, setStatus] = useState(null)

  useEffect(() => {
    api.get('/protect/status').then(setStatus).catch(() => setStatus(null))
  }, [])

  if (!status) return null

  const edge = status.edge_bans || {}
  const kernel = status.kernel_bans

  return (
    <div className="card">
      <div className="section-title">Edge &amp; kernel enforcement</div>
      <div className="flex flex-wrap gap-1.5 items-center">
        {status.ddos?.emergency
          ? <Badge color="red">UNDER-ATTACK MODE ON</Badge>
          : <Badge color="muted">under-attack mode off</Badge>}
        <Badge color={status.canary?.enabled ? 'green' : 'muted'}>
          canary {status.canary?.enabled ? 'enabled' : 'off'}
        </Badge>
        {edge.enabled ? (
          <>
            <Badge color="green">edge bans enabled</Badge>
            <span className="text-xs text-cat-text">{edge.rendered ?? 0} IPs dropped at the edge</span>
          </>
        ) : (
          <Badge color="muted">edge bans off</Badge>
        )}
        {!kernel ? (
          <Badge color="muted">kernel drops unavailable</Badge>
        ) : kernel.preflight_ok ? (
          <>
            <Badge color={kernel.enabled ? 'green' : 'muted'}>kernel drops {kernel.enabled ? 'enabled' : 'off'}</Badge>
            <span className="text-xs text-cat-text">{kernel.entries ?? 0} entries mirrored into nftables</span>
          </>
        ) : (
          <span className="text-xs" style={{ color: '#f87171' }}>
            {(kernel.problems || []).join(' · ') || 'preflight failed'}
          </span>
        )}
      </div>
    </div>
  )
}

export function BansPage() {
  const { toast, show, hide } = useToast()
  const [data, setData] = useState(null)
  const [filter, setFilter] = useState('')
  const [busy, setBusy] = useState(false)
  const [target, setTarget] = useState('')
  const [minutes, setMinutes] = useState('60')
  const [reason, setReason] = useState('')

  const load = useCallback(() => {
    const q = filter ? `?source=${encodeURIComponent(filter)}` : ''
    return api.get(`/bans${q}`).then(setData).catch(e => show(e.message, 'error'))
  }, [filter]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { load() }, [load])

  const act = async (fn, message) => {
    setBusy(true)
    try { await fn(); show(message); await load() }
    catch (e) { show(e.message, 'error') }
    finally { setBusy(false) }
  }

  const addBan = () => act(
    () => api.post('/bans', {
      target: target.trim(),
      seconds: minutes.trim() === '' ? null : Math.max(1, Math.round(Number(minutes) * 60)),
      reason: reason.trim(),
    }).then(() => { setTarget(''); setReason('') }),
    'Ban added',
  )

  const stats = data?.stats

  return (
    <div className="p-6 max-w-4xl mx-auto page-enter space-y-4">
      {toast && <Toast {...toast} onClose={hide} />}
      <PageHeader
        icon={Ban} color="red"
        title="Active bans"
        subtitle="Every address CatWAF is currently refusing, whichever feature decided it"
      />

      <EnforcementStatusCard />

      <Caveat tone="info" title="This list is temporary and automatic — your IP blocklist is not">
        <p>
          Several features can independently stop an address: behavioural banning, DNSBL hits, the challenge gate, community
          lists and the threat feed. They all write here, so there is one place to answer "why is this visitor blocked, and how
          do I let them back in". Lifting a ban here does <strong>not</strong> touch the manual IP blocklist, which stays
          permanent and operator-curated.
        </p>
      </Caveat>

      {stats && (
        <div className="card">
          <div className="section-title">Right now</div>
          <div className="flex flex-wrap gap-4 mb-3">
            {[['Total', stats.total], ['Permanent', stats.permanent], ['Temporary', stats.temporary]].map(([k, v]) => (
              <div key={k}>
                <div className="text-lg font-bold text-cat-text">{v}</div>
                <div className="text-[11px] text-cat-sub uppercase tracking-wide">{k}</div>
              </div>
            ))}
            {stats.next_expiry && (
              <div>
                <div className="text-lg font-bold text-cat-text">{relativeTime(stats.next_expiry)}</div>
                <div className="text-[11px] text-cat-sub uppercase tracking-wide">Next expiry</div>
              </div>
            )}
          </div>
          {stats.by_source.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {stats.by_source.map(s => (
                <button
                  key={s.source}
                  className={`badge ${filter === s.source ? 'badge-blue' : ''}`}
                  style={{ cursor: 'pointer' }}
                  title={s.label}
                  onClick={() => setFilter(filter === s.source ? '' : s.source)}
                >
                  {s.label} · {s.count}
                </button>
              ))}
              {filter && (
                <button className="btn btn-sm btn-ghost" onClick={() => setFilter('')}>Show all</button>
              )}
            </div>
          )}
        </div>
      )}

      <div className="card">
        <div className="section-title">Ban an address by hand</div>
        <div className="flex flex-wrap gap-2 items-end">
          <div style={{ flex: '2 1 200px' }}>
            <label className="text-[10px] text-cat-sub uppercase tracking-wide block mb-1">IP or CIDR</label>
            <input className="input" value={target} onChange={e => setTarget(e.target.value)} placeholder="203.0.113.7 or 203.0.113.0/24" />
          </div>
          <div style={{ flex: '1 1 110px' }}>
            <label className="text-[10px] text-cat-sub uppercase tracking-wide block mb-1">Minutes (blank = forever)</label>
            <input className="input" type="number" min="1" value={minutes} onChange={e => setMinutes(e.target.value)} />
          </div>
          <div style={{ flex: '2 1 180px' }}>
            <label className="text-[10px] text-cat-sub uppercase tracking-wide block mb-1">Reason</label>
            <input className="input" value={reason} onChange={e => setReason(e.target.value)} placeholder="Optional note" />
          </div>
          <button className="btn btn-sm btn-primary" disabled={busy || !target.trim()} onClick={addBan}>
            <Plus size={13} /> Ban
          </button>
        </div>
        <p className="text-[11px] text-cat-sub mt-2">
          CatWAF refuses a range that covers the address you are connected from — banning it would lock you out of the dashboard.
        </p>
      </div>

      <div className="card">
        <div className="flex items-center justify-between mb-1">
          <div className="section-title" style={{ marginBottom: 0 }}>
            {filter ? `Bans from "${filter}"` : 'All active bans'}
          </div>
          <div className="flex gap-2">
            <button className="btn btn-sm btn-ghost" onClick={load} disabled={busy}><RefreshCw size={13} /> Refresh</button>
            <button
              className="btn btn-sm btn-ghost" disabled={busy || !data?.bans?.length}
              onClick={() => act(() => api.post('/bans/clear', {}), 'All automatic bans lifted')}
            >
              <Trash2 size={13} /> Lift all
            </button>
          </div>
        </div>

        {!data ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 28 }}><Spinner label="Loading bans" /></div>
        ) : data.bans.length === 0 ? (
          <EmptyState
            icon={CheckCircle}
            title="Nothing is banned"
            desc={filter ? 'No active bans from this source.' : 'No address is currently being refused by an automatic rule.'}
          />
        ) : (
          <div className="space-y-2 mt-2">
            {data.bans.map(ban => (
              <div key={ban.id} className="flex items-start justify-between gap-3" style={{ padding: 10, borderRadius: 8, border: '1px solid var(--cat-border)' }}>
                <div style={{ minWidth: 0 }}>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs text-cat-text" style={{ fontFamily: 'monospace', fontWeight: 600 }}>{ban.target}</span>
                    <Badge>{ban.source_label}</Badge>
                    {expiryLabel(ban)}
                    {ban.hits > 1 && <span className="text-[10.5px] text-cat-sub">{ban.hits} hits</span>}
                  </div>
                  <div className="text-[11.5px] text-cat-sub mt-1">{ban.reason}</div>
                  <div className="text-[10.5px] text-cat-sub mt-0.5" style={{ opacity: 0.7 }}>
                    banned {relativeTime(ban.created_at)}
                  </div>
                </div>
                <button
                  className="btn btn-sm btn-ghost" disabled={busy}
                  onClick={() => act(() => api.delete(`/bans/${ban.id}`), `${ban.target} unbanned`)}
                >
                  Lift now
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Challenge gate (#1–#5) ─────────────────────────────────────────────

export function ChallengePage() {
  const { toast, show, hide } = useToast()
  const [status, setStatus] = useState(null)
  const [previewUrl, setPreviewUrl] = useState('')
  const [previewError, setPreviewError] = useState('')
  const [scope, setScope] = useState({ ip: '', uri: '/', user_agent: '', country: '' })
  const [scopeResult, setScopeResult] = useState(null)
  const [version, setVersion] = useState(0)

  const loadStatus = () => api.get('/challenge/status').then(setStatus).catch(() => setStatus(null))
  useEffect(() => { loadStatus() }, [version])

  // The preview is real HTML from the real issuer, so it has to be fetched
  // over the signed admin path and handed to the iframe as a blob — an
  // <iframe src> would miss the request signature entirely.
  useEffect(() => {
    let revoked = false
    let url = ''
    setPreviewError('')
    apiBlobUrl('/challenge/preview')
      .then(u => { if (revoked) { URL.revokeObjectURL(u); return } url = u; setPreviewUrl(u) })
      .catch(e => { setPreviewUrl(''); setPreviewError(e.message) })
    return () => { revoked = true; if (url) URL.revokeObjectURL(url) }
  }, [version])

  const runScopeTest = async () => {
    try {
      setScopeResult(await api.post('/challenge/scope-test', {
        ip: scope.ip.trim(),
        uri: scope.uri.trim() || '/',
        user_agent: scope.user_agent,
        country: scope.country.trim() || null,
        suspicious: true,
      }))
    } catch (e) { show(e.message, 'error') }
  }

  return (
    <div className="p-6 max-w-3xl mx-auto page-enter space-y-4">
      {toast && <Toast {...toast} onClose={hide} />}
      <PageHeader
        icon={ShieldQuestion} color="purple"
        title="Challenge gate"
        subtitle="Make an unrecognised visitor prove they are a browser before the origin sees them"
      />

      {status && (
        <div className="card">
          <div className="flex items-center justify-between mb-2">
            <div className="section-title" style={{ marginBottom: 0 }}>State</div>
            <button className="btn btn-sm btn-ghost" onClick={async () => {
              try { await api.post('/challenge/reset', {}); show('Pending challenges cleared'); setVersion(v => v + 1) }
              catch (e) { show(e.message, 'error') }
            }}>
              <RotateCcw size={13} /> Clear pending
            </button>
          </div>
          <KeyValue rows={[
            ['Mode', status.mode],
            ['Provider', status.provider],
            ['Trigger', status.trigger],
            ['Challenges awaiting an answer', status.pending],
            ['Addresses with recorded failures', status.tracked_failures],
            status.provider !== 'builtin' && ['Site key', status.site_key_set ? 'set' : 'not set'],
            status.provider !== 'builtin' && ['Secret key', status.secret_key_set ? 'set' : 'not set'],
          ]} />
        </div>
      )}

      <SettingsForm group="challenge" onSaved={() => { show('Applied'); setVersion(v => v + 1) }} onError={m => show(m, 'error')} />

      <div className="card">
        <div className="section-title">What a challenged visitor sees</div>
        {previewUrl ? (
          <>
            <p className="text-xs text-cat-sub mb-3">
              Rendered by the same code that serves live traffic, with a real token issued to your own address — not a mockup.
            </p>
            <iframe
              title="Challenge page preview"
              src={previewUrl}
              sandbox=""
              style={{ width: '100%', height: 380, border: '1px solid var(--cat-border)', borderRadius: 8, background: '#fff' }}
            />
            <p className="text-[10.5px] text-cat-sub mt-2" style={{ opacity: 0.7 }}>
              Scripts are disabled inside this frame, so the proof-of-work will not run here — the layout and copy are what it checks.
            </p>
          </>
        ) : (
          <p className="text-xs text-cat-sub">{previewError || 'Loading…'}</p>
        )}
      </div>

      <div className="card">
        <div className="section-title">Would this visitor be challenged?</div>
        <p className="text-xs text-cat-sub mb-3">
          Runs the real scoping rules — exemptions, paths, country, user agent — against a hypothetical request.
        </p>
        <div className="flex flex-wrap gap-2 items-end">
          <div style={{ flex: '1 1 150px' }}>
            <label className="text-[10px] text-cat-sub uppercase tracking-wide block mb-1">IP</label>
            <input className="input" value={scope.ip} onChange={e => setScope(s => ({ ...s, ip: e.target.value }))} placeholder="203.0.113.7" />
          </div>
          <div style={{ flex: '1 1 130px' }}>
            <label className="text-[10px] text-cat-sub uppercase tracking-wide block mb-1">Path</label>
            <input className="input" value={scope.uri} onChange={e => setScope(s => ({ ...s, uri: e.target.value }))} />
          </div>
          <div style={{ flex: '0 1 90px' }}>
            <label className="text-[10px] text-cat-sub uppercase tracking-wide block mb-1">Country</label>
            <input className="input" value={scope.country} onChange={e => setScope(s => ({ ...s, country: e.target.value }))} placeholder="DE" />
          </div>
          <div style={{ flex: '2 1 220px' }}>
            <label className="text-[10px] text-cat-sub uppercase tracking-wide block mb-1">User agent</label>
            <input className="input" value={scope.user_agent} onChange={e => setScope(s => ({ ...s, user_agent: e.target.value }))} placeholder="Mozilla/5.0…" />
          </div>
          <button className="btn btn-sm btn-ghost" onClick={runScopeTest}><Play size={13} /> Test</button>
        </div>
        {scopeResult && (
          <div style={{ marginTop: 12, padding: 10, borderRadius: 8, background: 'var(--cat-bg)', border: '1px solid var(--cat-border)' }}>
            <div className="text-xs text-cat-text font-medium mb-1">
              {scopeResult.exempt
                ? 'Exempt — this request would pass straight through.'
                : scopeResult.decision
                  ? 'This request would be challenged.'
                  : 'This request would not be challenged.'}
            </div>
            <pre style={{ margin: 0, fontSize: 11, color: 'var(--cat-sub)', whiteSpace: 'pre-wrap' }}>
              {JSON.stringify(scopeResult, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Threat intelligence (#7–#13) ───────────────────────────────────────

function LookupTool({ label, placeholder, run }) {
  const [value, setValue] = useState('')
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const go = async () => {
    setBusy(true); setError(''); setResult(null)
    try { setResult(await run(value.trim())) }
    catch (e) { setError(e.message) }
    finally { setBusy(false) }
  }

  return (
    <div style={{ padding: 10, borderRadius: 8, border: '1px solid var(--cat-border)' }}>
      <div className="text-xs text-cat-text font-medium mb-2">{label}</div>
      <div className="flex gap-2">
        <input
          className="input flex-1" value={value} placeholder={placeholder}
          onChange={e => setValue(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter' && value.trim()) { e.preventDefault(); go() } }}
        />
        <button className="btn btn-sm btn-ghost" disabled={busy || !value.trim()} onClick={go}>
          {busy ? <Spinner size={13} /> : <Search size={13} />}
        </button>
      </div>
      {error && <div className="text-[11px] mt-2" style={{ color: '#f87171' }}>{error}</div>}
      {result && (
        <pre style={{ margin: '8px 0 0', padding: 9, fontSize: 11, background: 'var(--cat-bg)', border: '1px solid var(--cat-border)', borderRadius: 8, maxHeight: 220, overflow: 'auto', whiteSpace: 'pre-wrap' }}>
          {JSON.stringify(result, null, 2)}
        </pre>
      )}
    </div>
  )
}

export function ThreatIntelPage() {
  const { toast, show, hide } = useToast()
  const [tradeoffs, setTradeoffs] = useState(null)
  const [lists, setLists] = useState(null)
  const [busy, setBusy] = useState(false)

  const loadLists = () => api.get('/intel/lists').then(setLists).catch(() => setLists(null))

  useEffect(() => {
    api.get('/intel/probe/tradeoffs').then(setTradeoffs).catch(() => setTradeoffs(null))
    loadLists()
  }, [])

  const refreshLists = async (sourceId) => {
    setBusy(true)
    try {
      const r = await api.post('/intel/lists/refresh', sourceId ? { source_id: sourceId } : {})
      show(`Refreshed${r.entries !== undefined ? `: ${r.entries} entries` : ''}`)
      await loadLists()
    } catch (e) { show(e.message, 'error') }
    finally { setBusy(false) }
  }

  return (
    <div className="p-6 max-w-3xl mx-auto page-enter space-y-4">
      {toast && <Toast {...toast} onClose={hide} />}
      <PageHeader
        icon={Radar} color="orange"
        title="Threat intelligence"
        subtitle="Reputation signals that decide an address before it reaches your rules"
      />

      <div className="card">
        <div className="section-title">Look up an address</div>
        <p className="text-xs text-cat-sub mb-3">
          Each of these runs the same lookup the live pipeline runs, including its cache — useful when a visitor complains and you
          need to know what CatWAF actually saw.
        </p>
        <div className="space-y-2">
          <LookupTool label="Whole pipeline — what would happen to this address?" placeholder="203.0.113.7"
            run={ip => api.post('/protect/test', { ip })} />
          <LookupTool label="ASN / origin network" placeholder="203.0.113.7"
            run={ip => api.get(`/intel/asn/${encodeURIComponent(ip)}`)} />
          <LookupTool label="Reverse DNS (forward-confirmed)" placeholder="66.249.66.1"
            run={ip => api.get(`/intel/rdns/${encodeURIComponent(ip)}`)} />
          <LookupTool label="DNS blackhole lists" placeholder="203.0.113.7"
            run={ip => api.get(`/intel/dnsbl/${encodeURIComponent(ip)}`)} />
        </div>
      </div>

      <SettingsForm group="asn_lists" onSaved={() => show('Applied')} onError={m => show(m, 'error')} />
      <SettingsForm group="rdns_lists" onSaved={() => show('Applied')} onError={m => show(m, 'error')} />
      <SettingsForm group="greylist" onSaved={() => show('Applied')} onError={m => show(m, 'error')} />
      <SettingsForm group="dnsbl" onSaved={() => show('Applied')} onError={m => show(m, 'error')} />

      <SettingsForm group="community_lists" onSaved={() => { show('Applied'); loadLists() }} onError={m => show(m, 'error')} />

      {lists && (
        <div className="card">
          <div className="flex items-center justify-between mb-2">
            <div className="section-title" style={{ marginBottom: 0 }}>Subscribed lists</div>
            <button className="btn btn-sm btn-ghost" disabled={busy} onClick={() => refreshLists(null)}>
              <RefreshCw size={13} /> Refresh all
            </button>
          </div>
          {lists.sources.length === 0 ? (
            <p className="text-xs text-cat-sub">No sources configured.</p>
          ) : (
            <div className="space-y-2">
              {lists.sources.map(s => (
                <div key={s.id} className="flex items-center justify-between gap-3" style={{ padding: 9, borderRadius: 8, border: '1px solid var(--cat-border)' }}>
                  <div style={{ minWidth: 0 }}>
                    <div className="text-xs text-cat-text font-medium">
                      {s.name || s.id} {s.enabled === false && <Badge color="muted">disabled</Badge>}
                    </div>
                    <div className="text-[10.5px] text-cat-sub mt-0.5" style={{ wordBreak: 'break-all' }}>{s.url}</div>
                    <div className="text-[10.5px] text-cat-sub mt-0.5">
                      {s.entries} entries · refreshed {relativeTime(s.last_refresh)} · action {s.action || 'block'}
                    </div>
                  </div>
                  <div className="flex gap-2 flex-shrink-0">
                    <button className="btn btn-sm btn-ghost" disabled={busy} onClick={() => refreshLists(s.id)}>Refresh</button>
                    <button className="btn btn-sm btn-ghost" disabled={busy} onClick={async () => {
                      try { await api.delete(`/intel/lists/${encodeURIComponent(s.id)}`); show('Entries cleared'); loadLists() }
                      catch (e) { show(e.message, 'error') }
                    }}>Clear</button>
                  </div>
                </div>
              ))}
            </div>
          )}
          <p className="text-[11px] text-cat-sub mt-3">
            {lists.total_entries} entries stored in total.
          </p>
        </div>
      )}

      <SettingsForm group="threat_feed" onSaved={() => show('Applied')} onError={m => show(m, 'error')} />
      <SettingsForm group="threat_network" onSaved={() => show('Applied')} onError={m => show(m, 'error')} />

      {/* probe.TRADEOFFS is shown verbatim: this feature is off by default for
          reasons the operator has to weigh, not a recommendation to enable. */}
      <Caveat tone="warn" title="Before switching on active client probing">
        {tradeoffs?.tradeoffs?.map((t, i) => (
          <p key={i} style={{ display: 'flex', gap: 7 }}>
            <AlertTriangle size={12} style={{ flexShrink: 0, marginTop: 2, color: '#fbbf24' }} />
            <span>{t}</span>
          </p>
        )) || <p>Loading…</p>}
      </Caveat>

      <SettingsForm group="client_probe" onSaved={() => show('Applied')} onError={m => show(m, 'error')} />
    </div>
  )
}

// ─── Behavioural banning (#6) ───────────────────────────────────────────

export function BehaviorPage() {
  const { toast, show, hide } = useToast()
  const [preview, setPreview] = useState(null)
  const [busy, setBusy] = useState(false)

  const load = () => api.get('/protect/behavior').then(setPreview).catch(e => show(e.message, 'error'))
  useEffect(() => { load() }, [])

  const runSweep = async (dryRun) => {
    setBusy(true)
    try {
      const r = await api.post('/protect/behavior/run', { dry_run: dryRun })
      if (r.skipped === 'disabled') show('Behavioural banning is switched off — nothing was done.', 'info')
      else show(dryRun ? `${r.banned?.length || 0} address(es) would be banned` : `${r.banned?.length || 0} address(es) banned`)
      await load()
    } catch (e) { show(e.message, 'error') }
    finally { setBusy(false) }
  }

  return (
    <div className="p-6 max-w-3xl mx-auto page-enter space-y-4">
      {toast && <Toast {...toast} onClose={hide} />}
      <PageHeader
        icon={Activity} color="orange"
        title="Behavioural banning"
        subtitle="Ban addresses that generate a burst of errors — the signature of scanning"
      />

      <div className="card">
        <div className="flex items-center justify-between mb-1">
          <div className="section-title" style={{ marginBottom: 0 }}>Who this would catch right now</div>
          <div className="flex gap-2">
            <button className="btn btn-sm btn-ghost" onClick={load} disabled={busy}><RefreshCw size={13} /> Refresh</button>
            <button className="btn btn-sm btn-ghost" onClick={() => runSweep(true)} disabled={busy}><Eye size={13} /> Dry run</button>
            <button className="btn btn-sm btn-primary" onClick={() => runSweep(false)} disabled={busy || !preview?.enabled}>
              <Play size={13} /> Sweep now
            </button>
          </div>
        </div>
        <p className="text-xs text-cat-sub mb-3">
          Read from your real request log with the thresholds below. Check this before turning the feature on — a legitimate
          client that 404s a lot looks identical to a scanner from here.
        </p>

        {!preview ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 24 }}><Spinner label="Loading" /></div>
        ) : (
          <>
            <div className="flex flex-wrap gap-2 mb-3">
              <Badge color={preview.enabled ? 'green' : 'muted'}>{preview.enabled ? 'enabled' : 'not enabled'}</Badge>
              <Badge>threshold {preview.threshold}</Badge>
              <Badge>window {preview.window_sec}s</Badge>
            </div>
            {preview.would_ban.length === 0 ? (
              <EmptyState
                icon={CheckCircle}
                title="Nobody crosses the threshold"
                desc="No address in your log has produced enough bad responses inside the window."
              />
            ) : (
              <div className="space-y-2">
                {preview.would_ban.map(o => (
                  <div key={o.ip} className="flex items-center justify-between gap-3" style={{ padding: 9, borderRadius: 8, border: '1px solid var(--cat-border)' }}>
                    <div>
                      <div className="text-xs text-cat-text" style={{ fontFamily: 'monospace' }}>{o.ip}</div>
                      <div className="text-[10.5px] text-cat-sub mt-0.5">{o.breakdown.join(', ')}</div>
                    </div>
                    <Badge color="orange">{o.count} bad responses</Badge>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>

      <SettingsForm group="bad_behavior" onSaved={() => { show('Applied'); load() }} onError={m => show(m, 'error')} />
    </div>
  )
}

// ─── Scanner tool fingerprinting ─────────────────────────────────────────

function tierBadge(tier) {
  if (tier === 'exact') return <Badge color="red">exact match — would be banned</Badge>
  if (tier === 'close') return <Badge color="orange">close match — would be challenged</Badge>
  return <Badge color="green">no match</Badge>
}

export function ToolFingerprintPage() {
  const { toast, show, hide } = useToast()
  const [bans, setBans] = useState(null)
  const [busy, setBusy] = useState(false)
  const [ua, setUa] = useState('sqlmap/1.7.2#stable (http://sqlmap.org)')
  const [result, setResult] = useState(null)

  const load = useCallback(() => {
    return api.get('/bans?source=tools_fingerprint').then(setBans).catch(e => show(e.message, 'error'))
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { load() }, [load])

  const runTest = async () => {
    setBusy(true)
    try {
      const r = await api.post('/protect/test', { ip: '203.0.113.1', user_agent: ua, headers: ['host', 'accept', 'user-agent'] })
      setResult(r.fingerprint)
    } catch (e) { show(e.message, 'error') }
    finally { setBusy(false) }
  }

  return (
    <div className="p-6 max-w-3xl mx-auto page-enter space-y-4">
      {toast && <Toast {...toast} onClose={hide} />}
      <PageHeader
        icon={Fingerprint} color="red"
        title="Scanner tool fingerprinting"
        subtitle="Score requests against known offensive tool signatures — ban an exact match, challenge a close one"
      />

      <Caveat tone="info" title="Two tiers, two responses">
        <p>
          An exact User-Agent match (sqlmap, nikto, nmap, gobuster and friends) is high-confidence enough to ban the address
          outright. A request that only <em>resembles</em> a known tool — similar User-Agent, a header set that looks scripted
          rather than browser-like — is lower confidence, so it gets sent through the challenge gate instead of banned. The
          challenge gate must have a mode selected (Protection → Challenge Gate) for that CAPTCHA to actually be shown.
        </p>
      </Caveat>

      <div className="card">
        <div className="section-title">Test a User-Agent</div>
        <div className="flex flex-wrap gap-2 items-end">
          <div style={{ flex: '1 1 320px' }}>
            <label className="text-[10px] text-cat-sub uppercase tracking-wide block mb-1">User-Agent</label>
            <input className="input" value={ua} onChange={e => setUa(e.target.value)} placeholder="e.g. sqlmap/1.7.2" />
          </div>
          <button className="btn btn-sm btn-primary" disabled={busy || !ua.trim()} onClick={runTest}>
            <Search size={13} /> Test
          </button>
        </div>
        {result !== null && (
          <div className="mt-3 flex items-center gap-2 flex-wrap">
            {tierBadge(result?.tier)}
            {result?.tool && <span className="text-xs text-cat-sub">matched tool: {result.tool}</span>}
            {result?.score !== undefined && <span className="text-[10.5px] text-cat-sub">score {result.score.toFixed(2)}</span>}
          </div>
        )}
      </div>

      <div className="card">
        <div className="flex items-center justify-between mb-1">
          <div className="section-title" style={{ marginBottom: 0 }}>Recent exact-match bans</div>
          <button className="btn btn-sm btn-ghost" onClick={load} disabled={busy}><RefreshCw size={13} /> Refresh</button>
        </div>
        {!bans ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 24 }}><Spinner label="Loading" /></div>
        ) : bans.bans.length === 0 ? (
          <EmptyState icon={CheckCircle} title="No fingerprint bans yet" desc="Nothing has been fingerprinted as an exact tool match." />
        ) : (
          <div className="space-y-2 mt-2">
            {bans.bans.map(ban => (
              <div key={ban.id} className="flex items-start justify-between gap-3" style={{ padding: 10, borderRadius: 8, border: '1px solid var(--cat-border)' }}>
                <div style={{ minWidth: 0 }}>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs text-cat-text" style={{ fontFamily: 'monospace', fontWeight: 600 }}>{ban.target}</span>
                    {expiryLabel(ban)}
                    {ban.hits > 1 && <span className="text-[10.5px] text-cat-sub">{ban.hits} hits</span>}
                  </div>
                  <div className="text-[11.5px] text-cat-sub mt-1">{ban.reason}</div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <SettingsForm group="tools_fingerprint" onSaved={() => { show('Applied'); load() }} onError={m => show(m, 'error')} />
    </div>
  )
}
