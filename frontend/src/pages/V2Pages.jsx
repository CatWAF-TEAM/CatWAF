import React, { useEffect, useState } from 'react'
import { api } from '../utils/api.js'
import { SectionTitle, Toggle, Input, ActionBar, Spinner, Toast, EmptyState } from '../components/ui.jsx'
import {
  Cloud, Shield, Globe, CheckCircle, XCircle,
  Zap, Lock, Key, Copy, ChevronRight, Bell, MessageSquare, Webhook
} from 'lucide-react'

function useToast() {
  const [toast, setToast] = useState(null)
  const show = (message, type='success') => { setToast({ message, type, id: Date.now() }) }
  const hide = () => setToast(null)
  return { toast, show, hide }
}

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false)
  return (
    <button className="btn btn-ghost btn-sm" onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(()=>setCopied(false),1500) }}>
      {copied ? <CheckCircle size={12} className="text-cat-green"/> : <Copy size={12}/>}
    </button>
  )
}

const CF_STEPS = [
  { id:'token',   title:'Connect Cloudflare',    icon:Key,          desc:'Enter your Cloudflare API token' },
  { id:'zone',    title:'Choose Zone',            icon:Globe,        desc:'Select which domain to protect' },
  { id:'dns',     title:'Verify DNS',             icon:CheckCircle,  desc:'Confirm DNS records are correct' },
  { id:'proxy',   title:'Enable Orange Cloud',    icon:Cloud,        desc:'Turn on Cloudflare proxy' },
  { id:'cert',    title:'Generate Origin Cert',   icon:Lock,         desc:'Create origin certificate' },
  { id:'firewall',title:'Verify Origin Firewall', icon:Shield,       desc:'Block direct IP access' },
  { id:'test',    title:'Test Everything',        icon:Zap,          desc:'Run connectivity checks' },
]

export function CloudflareWizardPage() {
  const [step, setStep] = useState(0)
  const [token, setToken] = useState('')
  const [zones, setZones] = useState([])
  const [selectedZone, setSelectedZone] = useState(null)
  const [recordId, setRecordId] = useState(null)
  const [status, setStatus] = useState({})
  const [busy, setBusy] = useState(false)
  const [results, setResults] = useState({})
  const { toast, show, hide } = useToast()

  const fetchZones = async () => {
    setBusy(true)
    try {
      const d = await api.post('/cloudflare/zones', { token })
      setZones(d.zones || [])
      setStep(1)
      show('Connected to Cloudflare!')
    } catch(e) { show(e.message, 'error') }
    finally { setBusy(false) }
  }

  const runStep = async (action) => {
    setBusy(true)
    try {
      const d = await api.post(`/cloudflare/${action}`, { token, zone_id: selectedZone?.id, record_id: recordId })
      setResults(r => ({ ...r, [action]: d }))
      setStatus(s => ({ ...s, [action]: 'ok' }))
      if (action === 'verify-dns' && d.records?.[0]?.id) setRecordId(d.records[0].id)
      setStep(s => Math.min(s+1, CF_STEPS.length-1))
      show(d.message || 'Done!')
    } catch(e) {
      setStatus(s => ({ ...s, [action]: 'error' }))
      show(e.message, 'error')
    }
    finally { setBusy(false) }
  }

  const stepActions = ['token','zone','dns','proxy','cert','firewall','test']

  return (
    <div className="p-6 max-w-3xl mx-auto page-enter">
      {toast && <Toast {...toast} onClose={hide}/>}
      <div className="flex items-center gap-3 mb-6">
        <div className="stat-icon orange"><Cloud size={18}/></div>
        <div>
          <h1 className="text-lg font-bold text-cat-text">Cloudflare Proxy Wizard</h1>
          <p className="text-xs text-cat-sub">Hide your origin IP and route traffic through Cloudflare</p>
        </div>
      </div>

      <div className="flex gap-1 mb-8 overflow-x-auto pb-2">
        {CF_STEPS.map((s,i) => {
          const Icon = s.icon
          const done = i < step
          const active = i === step
          return (
            <div key={s.id} className="flex items-center gap-1 flex-shrink-0">
              <div className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium transition-all duration-300 ${active?'bg-cat-accent text-white':done?'bg-cat-green/15 text-cat-green':'bg-cat-muted text-cat-sub'}`}>
                {done ? <CheckCircle size={12}/> : <Icon size={12}/>}
                <span className="hidden sm:block">{s.title}</span>
                <span className="sm:hidden">{i+1}</span>
              </div>
              {i < CF_STEPS.length-1 && <ChevronRight size={12} className="text-cat-border flex-shrink-0"/>}
            </div>
          )
        })}
      </div>

      <div className="card animate-card-in">
        <div className="flex items-center gap-3 mb-5">
          {React.createElement(CF_STEPS[step].icon, { size:20, className:'text-cat-accent' })}
          <div>
            <div className="font-semibold text-cat-text">{CF_STEPS[step].title}</div>
            <div className="text-xs text-cat-sub">{CF_STEPS[step].desc}</div>
          </div>
        </div>

        {step === 0 && (
          <div className="space-y-4">
            <div className="p-3 rounded-lg bg-cat-muted/50 text-xs text-cat-sub leading-relaxed">
              Get your API token from <strong className="text-cat-text">Cloudflare Dashboard → My Profile → API Tokens</strong>. Create a token with <strong className="text-cat-text">Zone:Edit</strong> and <strong className="text-cat-text">DNS:Edit</strong> permissions.
            </div>
            <Input label="Cloudflare API Token" type="password" placeholder="Bearer token..." value={token} onChange={e=>setToken(e.target.value)}/>
            <ActionBar>
              <button className="btn btn-primary" onClick={fetchZones} disabled={busy||!token}>
                {busy?<><Spinner size={13}/>Connecting...</>:<><Key size={13}/>Connect</>}
              </button>
            </ActionBar>
          </div>
        )}

        {step === 1 && (
          <div className="space-y-4">
            <SectionTitle>Select Domain to Protect</SectionTitle>
            <div className="space-y-2">
              {zones.map(z => (
                <button key={z.id} onClick={()=>setSelectedZone(z)}
                  className={`w-full flex items-center justify-between p-3 rounded-lg border transition-all ${selectedZone?.id===z.id?'border-cat-accent bg-cat-accent/10':'border-cat-border hover:border-cat-muted'}`}>
                  <div className="flex items-center gap-3">
                    <Globe size={15} className="text-cat-sub"/>
                    <div className="text-left">
                      <div className="text-sm font-medium text-cat-text">{z.name}</div>
                      <div className="text-xs text-cat-sub">{z.status}</div>
                    </div>
                  </div>
                  {selectedZone?.id===z.id && <CheckCircle size={15} className="text-cat-accent"/>}
                </button>
              ))}
              {zones.length === 0 && <EmptyState icon={Globe} title="No zones found" desc="Make sure your token has Zone:Read permission"/>}
            </div>
            <ActionBar>
              <button className="btn btn-ghost" onClick={()=>setStep(0)}>Back</button>
              <button className="btn btn-primary" onClick={()=>setStep(2)} disabled={!selectedZone}>
                Continue <ChevronRight size={13}/>
              </button>
            </ActionBar>
          </div>
        )}

        {step === 2 && (
          <div className="space-y-4">
            <div className="p-3 rounded-lg border border-cat-border">
              <div className="flex items-center justify-between">
                <span className="text-sm text-cat-text">{selectedZone?.name}</span>
                <span className="badge badge-blue">Selected</span>
              </div>
            </div>
            <p className="text-xs text-cat-sub">CatWAF will check your DNS records and verify they point to your server correctly.</p>
            <ActionBar>
              <button className="btn btn-ghost" onClick={()=>setStep(1)}>Back</button>
              <button className="btn btn-primary" onClick={()=>runStep('verify-dns')} disabled={busy}>
                {busy?<><Spinner size={13}/>Checking...</>:<><CheckCircle size={13}/>Verify DNS</>}
              </button>
            </ActionBar>
          </div>
        )}

        {step === 3 && (
          <div className="space-y-4">
            <p className="text-xs text-cat-sub">Enable Cloudflare proxy (orange cloud) to hide your origin IP. All traffic will route through Cloudflare's network.</p>
            <div className="p-4 rounded-lg bg-orange-500/10 border border-orange-500/20">
              <div className="flex items-center gap-2 text-orange-400 text-sm font-medium mb-1"><Cloud size={14}/> Orange Cloud Mode</div>
              <div className="text-xs text-orange-300/70">Your origin IP will be hidden. Cloudflare becomes the public face of your site.</div>
            </div>
            <ActionBar>
              <button className="btn btn-ghost" onClick={()=>setStep(2)}>Back</button>
              <button className="btn btn-primary" onClick={()=>runStep('enable-proxy')} disabled={busy}>
                {busy?<><Spinner size={13}/>Enabling...</>:<><Cloud size={13}/>Enable Proxy</>}
              </button>
            </ActionBar>
          </div>
        )}

        {step === 4 && (
          <div className="space-y-4">
            <p className="text-xs text-cat-sub">Generate a Cloudflare Origin Certificate to encrypt traffic between Cloudflare and your server.</p>
            <ActionBar>
              <button className="btn btn-ghost" onClick={()=>setStep(3)}>Back</button>
              <button className="btn btn-primary" onClick={()=>runStep('gen-cert')} disabled={busy}>
                {busy?<><Spinner size={13}/>Generating...</>:<><Lock size={13}/>Generate Certificate</>}
              </button>
            </ActionBar>
          </div>
        )}

        {step === 5 && (
          <div className="space-y-4">
            <p className="text-xs text-cat-sub">Block direct access to your server IP — only Cloudflare IPs will be allowed through.</p>
            <ActionBar>
              <button className="btn btn-ghost" onClick={()=>setStep(4)}>Back</button>
              <button className="btn btn-primary" onClick={()=>runStep('lock-origin')} disabled={busy}>
                {busy?<><Spinner size={13}/>Locking...</>:<><Shield size={13}/>Lock Origin</>}
              </button>
            </ActionBar>
          </div>
        )}

        {step === 6 && (
          <div className="space-y-4">
            <p className="text-xs text-cat-sub">Running final connectivity checks...</p>
            {results.test && (
              <div className="space-y-2">
                {Object.entries(results.test.checks||{}).map(([k,v]) => (
                  <div key={k} className="flex items-center justify-between p-2 rounded-lg bg-cat-surface">
                    <span className="text-xs text-cat-text">{k}</span>
                    {v ? <CheckCircle size={13} className="text-cat-green"/> : <XCircle size={13} className="text-cat-red"/>}
                  </div>
                ))}
              </div>
            )}
            <ActionBar>
              <button className="btn btn-ghost" onClick={()=>setStep(5)}>Back</button>
              <button className="btn btn-primary" onClick={()=>runStep('test')} disabled={busy}>
                {busy?<><Spinner size={13}/>Testing...</>:<><Zap size={13}/>Run Tests</>}
              </button>
            </ActionBar>
          </div>
        )}
      </div>
    </div>
  )
}

export function AlertsV2Page() {
  const [cfg, setCfg] = useState({ slack_webhook:'', telegram_bot_token:'', telegram_chat_id:'', discord_webhook:'', custom_webhook:'', email_to:'', spike_threshold:100, alert_on_block:true, alert_on_spike:true, alert_on_engine_change:true })
  const [busy, setBusy] = useState(false)
  const [testing, setTesting] = useState('')
  const [dispatchEnabled, setDispatchEnabled] = useState(null)
  const [dispatchBusy, setDispatchBusy] = useState(false)
  const { toast, show, hide } = useToast()

  useEffect(() => { api.get('/alerts').then(d=>setCfg(c=>({...c,...d}))).catch(()=>{}) }, [])
  useEffect(() => {
    api.get('/settings/alert_dispatch')
      .then(d => setDispatchEnabled(!!d.values?.enabled))
      .catch(() => {})
  }, [])

  const save = async () => {
    setBusy(true)
    try { await api.post('/alerts', cfg); show('Alert settings saved!') }
    catch(e) { show(e.message,'error') }
    finally { setBusy(false) }
  }

  const updateDispatch = async v => {
    setDispatchBusy(true)
    try {
      const res = await api.patch('/settings/alert_dispatch', { enabled: v })
      setDispatchEnabled(!!res.values?.enabled)
      show(
        res.reloaded === false && res.reload_error ? `Saved, but Caddy did not reload: ${res.reload_error}` : `Alert delivery ${v ? 'enabled' : 'disabled'}`,
        res.reload_error ? 'error' : 'success',
      )
    }
    catch(e) { show(e.message,'error') }
    finally { setDispatchBusy(false) }
  }

  const test = async (channel) => {
    setTesting(channel)
    try { await api.post('/alerts/test',{channel}); show(`Test sent to ${channel}!`) }
    catch(e) { show(e.message,'error') }
    finally { setTesting('') }
  }

  const channels = [
    { id:'slack',    label:'Slack',    icon:MessageSquare, field:'slack_webhook',        placeholder:'https://hooks.slack.com/...' },
    { id:'discord',  label:'Discord',  icon:MessageSquare, field:'discord_webhook',      placeholder:'https://discord.com/api/webhooks/...' },
    { id:'telegram', label:'Telegram', icon:Bell,          field:'telegram_bot_token',   placeholder:'Bot token from @BotFather' },
    { id:'webhook',  label:'Webhook',  icon:Webhook,       field:'custom_webhook',       placeholder:'https://your-webhook.com/...' },
    { id:'email',    label:'Email',    icon:Bell,          field:'email_to',             placeholder:'admin@yoursite.com' },
  ]

  return (
    <div className="p-6 max-w-2xl mx-auto page-enter">
      {toast && <Toast {...toast} onClose={hide}/>}
      <div className="flex items-center gap-3 mb-6">
        <div className="stat-icon accent"><Bell size={18}/></div>
        <div>
          <h1 className="text-lg font-bold text-cat-text">Alerts &amp; Notifications</h1>
          <p className="text-xs text-cat-sub">Get notified on Discord, Slack, Telegram, or webhooks</p>
        </div>
      </div>

      <div className="card mb-4">
        <SectionTitle>Alert Triggers</SectionTitle>
        <div className="space-y-3">
          {[['alert_on_block','Alert on every block'],['alert_on_spike','Alert on traffic spike'],['alert_on_engine_change','Alert on engine mode change']].map(([k,label]) => (
            <div key={k} className="flex items-center justify-between">
              <span className="text-sm text-cat-text">{label}</span>
              <Toggle on={cfg[k]} onChange={v=>setCfg(c=>({...c,[k]:v}))}/>
            </div>
          ))}
          <div className="flex items-center gap-3 pt-2 border-t border-cat-border">
            <span className="text-sm text-cat-text flex-1">Spike threshold (req/min)</span>
            <input className="input" type="number" style={{width:80}} value={cfg.spike_threshold} onChange={e=>setCfg(c=>({...c,spike_threshold:+e.target.value}))}/>
          </div>
        </div>
      </div>

      <div className="card mb-4">
        <div className="flex items-center justify-between">
          <span className="text-sm text-cat-text">Deliver alerts automatically</span>
          <Toggle on={!!dispatchEnabled} onChange={updateDispatch} disabled={dispatchBusy || dispatchEnabled === null}/>
        </div>
      </div>

      <div className="space-y-3">
        {channels.map(ch => {
          const Icon = ch.icon
          return (
            <div key={ch.id} className="card">
              <div className="flex items-center gap-2 mb-3">
                <Icon size={15} className="text-cat-accent"/>
                <span className="text-sm font-medium text-cat-text">{ch.label}</span>
              </div>
              <div className="flex gap-2">
                <input className="input flex-1" type={ch.id==='email'?'email':'text'} placeholder={ch.placeholder} value={cfg[ch.field]||''} onChange={e=>setCfg(c=>({...c,[ch.field]:e.target.value}))}/>
                {ch.id==='telegram' && (
                  <input className="input" style={{width:120}} placeholder="Chat ID" value={cfg.telegram_chat_id||''} onChange={e=>setCfg(c=>({...c,telegram_chat_id:e.target.value}))}/>
                )}
                <button className="btn btn-ghost btn-sm" onClick={()=>test(ch.id)} disabled={testing===ch.id||!cfg[ch.field]}>
                  {testing===ch.id?<Spinner size={12}/>:'Test'}
                </button>
              </div>
            </div>
          )
        })}
      </div>

      <p className="text-[11px] text-cat-sub mt-3">Delivery runs only when enabled here AND a channel URL is saved.</p>

      <ActionBar>
        <button className="btn btn-primary" onClick={save} disabled={busy}>
          {busy?<><Spinner size={13}/>Saving...</>:<>Save Alerts</>}
        </button>
      </ActionBar>
    </div>
  )
}
