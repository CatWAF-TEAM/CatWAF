import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  LayoutDashboard, Activity, BarChart2, Zap, Sliders, TrendingUp,
  ShieldCheck, Wrench, MessageCircle,
  Globe, FolderOpen, CheckCircle, Ban, Bell,
  Settings, Search, Cloud, ChevronRight,
  ChevronLeft, X, Play, SkipForward
} from 'lucide-react'

const TOUR_KEY = 'catwaf_tour_v3_done'

const STEPS = [
  {
    path: '/',
    icon: LayoutDashboard,
    title: 'Dashboard',
    color: '#4f8ef7',
    desc: 'Your starting point. Requests seen, attacks blocked, current paranoia level, and the most recent requests to hit your site.',
    tips: ['Everything here is real — a new install honestly shows zeros', 'The PL badge is your current Paranoia Level', 'Numbers refresh on their own'],
  },
  {
    path: '/security-score',
    icon: ShieldCheck,
    title: 'Security Score',
    color: '#22d3a0',
    desc: 'A graded checklist of how well your setup is locked down, with specific fixes rather than vague advice. Start here if you are not sure what to do next.',
    tips: ['Work top-down — high-severity items first', 'Each item says exactly what to change', 'The score updates as soon as you fix something'],
  },
  {
    path: '/analytics',
    icon: BarChart2,
    title: 'Analytics',
    color: '#a78bfa',
    desc: 'Traffic and attacks over time — what is being blocked, which attack types are showing up, and when.',
    tips: ['Empty until real traffic flows through Caddy', 'Attack types come from the OWASP rules that matched'],
  },
  {
    path: '/engine',
    icon: Zap,
    title: 'Engine Mode',
    color: '#f2b23c',
    desc: 'The master switch. Blocking drops attacks, Detection Only logs them without blocking, and Off disables inspection entirely.',
    tips: ['Detection Only is the safe way to trial new settings', 'Off means no protection at all — use it only to rule things out'],
  },
  {
    path: '/paranoia',
    icon: Sliders,
    title: 'Paranoia Levels',
    color: '#f25c5c',
    desc: 'How suspicious the OWASP rules are, from 1 to 4. Level 1 blocks clear attacks with almost no risk to real visitors; level 4 is strict enough to need tuning.',
    tips: ['1 is the default and right for most sites', 'Raise one level at a time and watch for false positives', 'If real visitors get blocked, drop back down'],
  },
  {
    path: '/performance-mode',
    icon: TrendingUp,
    title: 'Performance Mode',
    color: '#22d3a0',
    desc: 'Trade inspection depth for speed — useful on small servers. Shows what each setting actually costs you in coverage.',
    tips: ['Only worth touching if the WAF is measurably slowing you down', 'Sampling inspects a percentage of traffic, not all of it'],
  },
  {
    path: '/protection/sensitive-files',
    icon: FolderOpen,
    title: 'Sensitive Files',
    color: '#f2b23c',
    desc: 'Blocks access to the things that should never be public — .env, .git, backups, config files — across five graduated levels. Includes a scanner that walks your real webroot.',
    tips: ['The scanner needs WEBROOT_PATH set to report anything', 'It reports what it actually found, never a sample list'],
  },
  {
    path: '/ip/whitelist',
    icon: CheckCircle,
    title: 'IP Allowlist',
    color: '#22d3a0',
    desc: 'Addresses that bypass the WAF entirely. The fastest way to unblock a real customer caught by a false positive.',
    tips: ['Entries can expire automatically — prefer that to permanent', 'An allowlisted IP skips every rule, so keep the list short'],
  },
  {
    path: '/ip/blacklist',
    icon: Ban,
    title: 'IP Blocklist',
    color: '#f25c5c',
    desc: 'Addresses and CIDR ranges blocked outright, before any rule runs.',
    tips: ['CatWAF refuses to let you block your own address', 'Ranges work too, e.g. 203.0.113.0/24'],
  },
  {
    path: '/geo',
    icon: Globe,
    title: 'Geo Blocking',
    color: '#a78bfa',
    desc: 'Block entire countries by ISO code. Blunt, but effective when you only serve one region.',
    tips: ['Check your real visitors first — this blocks customers too', 'VPN users appear to come from elsewhere'],
  },
  {
    path: '/cloudflare',
    icon: Cloud,
    title: 'Cloudflare Wizard',
    color: '#f2b23c',
    desc: 'Verifies your zone, turns on proxying, enforces strict SSL, and locks your origin so traffic cannot bypass Cloudflare.',
    tips: ['Origin locking is the step people skip and regret', 'Needs a Cloudflare API token with zone permissions'],
  },
  {
    path: '/origin-scanner',
    icon: Search,
    title: 'Origin Exposure Scanner',
    color: '#f25c5c',
    desc: 'Checks whether your real server is still reachable directly, bypassing the WAF completely. A protected site with an exposed origin is not protected.',
    tips: ['Run this after any DNS or proxy change', 'An exposed origin makes every other setting here optional to an attacker'],
  },
  {
    path: '/alerts',
    icon: Bell,
    title: 'Alerts',
    color: '#4f8ef7',
    desc: 'Get told when something happens — Discord, Slack, Telegram, or your own webhook.',
    tips: ['Set a spike threshold so normal traffic stays quiet', 'Send a test alert to confirm the webhook works'],
  },
  {
    path: '/diagnostics',
    icon: Activity,
    title: 'Setup Diagnostics',
    color: '#7c8db0',
    desc: 'Checks the plumbing — is Caddy running, is the WAF actually in the request path, is the database writable. The first place to look when something seems wrong.',
    tips: ['Run this before opening a bug report', 'It tells you which specific piece is not wired up'],
  },
  {
    path: '/settings',
    icon: Settings,
    title: 'Settings',
    color: '#7c8db0',
    desc: 'Theme, allowed HTTP methods, request size limits, and content-type rules.',
    tips: ['Four themes, switched without a reload', 'Restricting HTTP methods is a free, low-risk win'],
  },
  {
    path: '/about',
    icon: Wrench,
    title: 'About & Versions',
    color: '#a78bfa',
    desc: 'What version you are running and what it is built on — reported from the running process, never hardcoded.',
    tips: ['Useful when reporting a bug', 'Version comes from the server, so it cannot drift'],
  },
  {
    path: null,
    icon: MessageCircle,
    title: 'CatAI — your assistant',
    color: '#22d3a0',
    desc: 'The cat in the corner. Ask it anything about CatWAF, or just tell it what you want: "block traffic from China", "set paranoia to 3", "am I protected?". It runs entirely on this machine — nothing about your site leaves it.',
    tips: ['Drag the cat anywhere; press / to jump to the chat box', 'Changes that strengthen protection apply instantly, with undo', 'Anything that weakens protection always asks first', 'Optional — enable it with CATAI_ENABLED in your .env'],
  },
]

export default function WelcomeTour({ onDone }) {
  const [phase, setPhase] = useState('welcome')
  const [step, setStep] = useState(0)
  const [animating, setAnimating] = useState(false)
  const navigate = useNavigate()
  const panelRef = useRef(null)

  const current = STEPS[step]
  const Icon = current?.icon

  const goTo = (idx) => {
    if (animating) return
    setAnimating(true)
    setTimeout(() => {
      setStep(idx)
      if (STEPS[idx]?.path) navigate(STEPS[idx].path)
      setAnimating(false)
    }, 180)
  }

  const next = () => { if (step < STEPS.length - 1) goTo(step + 1); else finish() }
  const prev = () => { if (step > 0) goTo(step - 1) }

  const finish = () => {
    setPhase('done')
    setTimeout(() => {
      localStorage.setItem(TOUR_KEY, '1')
      onDone()
    }, 800)
  }

  const skip = () => {
    localStorage.setItem(TOUR_KEY, '1')
    onDone()
  }

  useEffect(() => {
    const h = (e) => {
      if (phase !== 'tour') return
      if (e.key === 'ArrowRight' || e.key === 'ArrowDown') next()
      if (e.key === 'ArrowLeft'  || e.key === 'ArrowUp')   prev()
      if (e.key === 'Escape') skip()
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [phase, step, animating])

  if (phase === 'done') return (
    <div style={{ position:'fixed',inset:0,zIndex:300,display:'flex',alignItems:'center',justifyContent:'center',background:'rgba(0,0,0,.7)',backdropFilter:'blur(8px)',animation:'fadeIn .3s ease' }}>
      <div style={{ textAlign:'center', animation:'cardIn .5s cubic-bezier(.16,1,.3,1)' }}>
        <img src="/assets/logo/catwaf-icon-256.png" alt="CatWAF" style={{ width: 64, height: 64, marginBottom: 16, objectFit: 'contain' }} />
        <div style={{ fontSize:24, fontWeight:700, color:'var(--cat-text)', marginBottom:8 }}>You're all set!</div>
        <div style={{ fontSize:14, color:'var(--cat-sub)' }}>CatWAF is ready to protect your app.</div>
      </div>
    </div>
  )

  if (phase === 'welcome') return (
    <div style={{ position:'fixed',inset:0,zIndex:300,display:'flex',alignItems:'center',justifyContent:'center',background:'rgba(0,0,0,.75)',backdropFilter:'blur(10px)',animation:'fadeIn .25s ease',padding:24 }}>
      <div style={{ width:'100%',maxWidth:520,background:'var(--cat-card)',border:'1px solid var(--cat-border)',borderRadius:20,padding:36,boxShadow:'0 32px 80px rgba(0,0,0,.6)',animation:'cardIn .4s cubic-bezier(.16,1,.3,1)' }}>

        <div style={{ textAlign:'center', marginBottom:24 }}>
          <img src="/assets/logo/catwaf-icon-256.png" alt="CatWAF" style={{ width: 52, height: 52, animation: 'logoFloat 4s ease-in-out infinite', display: 'inline-block', objectFit: 'contain' }} />
          <div style={{ fontSize:22, fontWeight:800, color:'var(--cat-text)', letterSpacing:'-.02em', marginTop:8 }}>Welcome to CatWAF</div>
          <div style={{ fontSize:13, color:'var(--cat-sub)', marginTop:6, lineHeight:1.6 }}>
            A web application firewall for your site, powered by Coraza + the OWASP Core Rule Set.<br/>
            Here's a quick tour so you know where everything is.
          </div>
        </div>

        <div style={{ display:'flex', flexWrap:'wrap', gap:8, justifyContent:'center', marginBottom:28 }}>
          {['Coraza WAF','OWASP CRS','Paranoia levels','IP + geo blocking','Sensitive files','Cloudflare wizard','Security score','CatAI assistant'].map(f => (
            <span key={f} style={{ background:'color-mix(in srgb,var(--cat-accent) 12%,transparent)',color:'var(--cat-accent)',borderRadius:999,padding:'3px 10px',fontSize:11,fontWeight:500 }}>{f}</span>
          ))}
        </div>

        <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:12, marginBottom:28 }}>
          {[[String(STEPS.filter(s => s.path).length),'Pages'],['4','Paranoia levels'],['Local','AI assistant']].map(([n,l]) => (
            <div key={l} style={{ textAlign:'center', padding:'12px 8px', borderRadius:12, background:'var(--cat-surface)', border:'1px solid var(--cat-border)' }}>
              <div style={{ fontSize:22, fontWeight:800, color:'var(--cat-accent)', letterSpacing:'-.02em' }}>{n}</div>
              <div style={{ fontSize:11, color:'var(--cat-sub)', marginTop:2 }}>{l}</div>
            </div>
          ))}
        </div>

        <div style={{ display:'flex', gap:10 }}>
          <button onClick={skip} style={{ flex:1, padding:'11px 0', borderRadius:10, background:'var(--cat-muted)', border:'none', color:'var(--cat-sub)', fontSize:13, cursor:'pointer', transition:'all .15s', fontWeight:500 }}
            onMouseEnter={e=>e.target.style.background='var(--cat-border)'}
            onMouseLeave={e=>e.target.style.background='var(--cat-muted)'}>
            Skip Tour
          </button>
          <button onClick={()=>{ setPhase('tour'); navigate(STEPS[0].path) }}
            style={{ flex:2, padding:'11px 0', borderRadius:10, background:'var(--cat-accent)', border:'none', color:'var(--cat-accent-ink)', fontSize:13, fontWeight:600, cursor:'pointer', display:'flex', alignItems:'center', justifyContent:'center', gap:8, transition:'all .2s cubic-bezier(.16,1,.3,1)' }}
            onMouseEnter={e=>{ e.currentTarget.style.transform='translateY(-2px)'; e.currentTarget.style.boxShadow=`0 8px 24px color-mix(in srgb,var(--cat-accent) 60%,transparent)` }}
            onMouseLeave={e=>{ e.currentTarget.style.transform=''; e.currentTarget.style.boxShadow='' }}>
            <Play size={15}/> Start Tour ({STEPS.length} stops)
          </button>
        </div>
      </div>
    </div>
  )

  return (
    <>
      <div style={{ position:'fixed',inset:0,zIndex:200,background:'rgba(0,0,0,.35)',pointerEvents:'none' }}/>

      <div ref={panelRef} style={{
        position:'fixed', bottom:24, right:24, zIndex:201,
        width:340, background:'var(--cat-card)',
        border:'1px solid var(--cat-border)', borderRadius:16,
        boxShadow:'0 24px 60px rgba(0,0,0,.5)',
        overflow:'hidden',
        opacity: animating ? 0 : 1,
        transform: animating ? 'translateY(8px) scale(.98)' : 'translateY(0) scale(1)',
        transition:'opacity .18s ease,transform .18s ease',
      }}>
        <div style={{ height:3, background:'var(--cat-muted)' }}>
          <div style={{ height:'100%', background:`linear-gradient(90deg,${current.color},color-mix(in srgb,${current.color} 60%,var(--cat-accentL)))`, width:`${((step+1)/STEPS.length)*100}%`, transition:'width .3s cubic-bezier(.16,1,.3,1)', borderRadius:2 }}/>
        </div>

        <div style={{ padding:'14px 16px 0', display:'flex', alignItems:'center', justifyContent:'space-between' }}>
          <div style={{ display:'flex', alignItems:'center', gap:10 }}>
            <div style={{ width:32, height:32, borderRadius:9, background:`color-mix(in srgb,${current.color} 18%,transparent)`, display:'flex', alignItems:'center', justifyContent:'center', flexShrink:0 }}>
              <Icon size={16} style={{ color:current.color }}/>
            </div>
            <div>
              <div style={{ fontSize:13, fontWeight:700, color:'var(--cat-text)', lineHeight:1.1 }}>{current.title}</div>
              <div style={{ fontSize:10, color:'var(--cat-sub)', marginTop:2 }}>{step+1} of {STEPS.length}</div>
            </div>
          </div>
          <button onClick={skip} style={{ background:'none', border:'none', color:'var(--cat-sub)', cursor:'pointer', padding:4, borderRadius:6, display:'flex', alignItems:'center', transition:'color .15s' }}
            onMouseEnter={e=>e.currentTarget.style.color='var(--cat-text)'}
            onMouseLeave={e=>e.currentTarget.style.color='var(--cat-sub)'}>
            <X size={15}/>
          </button>
        </div>

        <div style={{ padding:'12px 16px' }}>
          <p style={{ fontSize:12, color:'var(--cat-sub)', lineHeight:1.7, margin:'0 0 12px' }}>{current.desc}</p>

          <div style={{ background:'var(--cat-surface)', borderRadius:10, padding:'10px 12px', border:'1px solid var(--cat-border)' }}>
            <div style={{ fontSize:10, fontWeight:600, textTransform:'uppercase', letterSpacing:'.08em', color:'var(--cat-sub)', opacity:.6, marginBottom:6 }}>Tips</div>
            <div style={{ display:'flex', flexDirection:'column', gap:5 }}>
              {current.tips.map((t,i) => (
                <div key={i} style={{ display:'flex', gap:7, alignItems:'flex-start' }}>
                  <span style={{ color:current.color, fontSize:10, marginTop:2, flexShrink:0 }}>→</span>
                  <span style={{ fontSize:11, color:'var(--cat-text)', lineHeight:1.5 }}>{t}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div style={{ display:'flex', justifyContent:'center', gap:4, padding:'0 16px 10px' }}>
          {STEPS.map((_,i) => (
            <button key={i} onClick={()=>goTo(i)} style={{ width:i===step?16:5, height:5, borderRadius:3, background:i===step?current.color:i<step?'color-mix(in srgb,'+current.color+' 40%,var(--cat-muted))':'var(--cat-muted)', border:'none', cursor:'pointer', transition:'all .25s cubic-bezier(.16,1,.3,1)', padding:0 }}/>
          ))}
        </div>

        <div style={{ padding:'0 16px 14px', display:'flex', gap:8 }}>
          <button onClick={prev} disabled={step===0}
            style={{ flex:1, padding:'8px 0', borderRadius:8, background:'var(--cat-muted)', border:'none', color:'var(--cat-sub)', fontSize:12, cursor:step===0?'not-allowed':'pointer', opacity: step === 0 ? 0.4 : 1, display:'flex', alignItems:'center', justifyContent:'center', gap:5, transition:'all .15s', fontWeight:500 }}>
            <ChevronLeft size={13}/> Back
          </button>
          <button onClick={next}
            style={{ flex:2, padding:'8px 0', borderRadius:8, background:current.color, border:'none', color:'white', fontSize:12, fontWeight:600, cursor:'pointer', display:'flex', alignItems:'center', justifyContent:'center', gap:5, transition:'all .2s cubic-bezier(.16,1,.3,1)', boxShadow:`0 4px 12px color-mix(in srgb,${current.color} 40%,transparent)` }}
            onMouseEnter={e=>e.currentTarget.style.transform='translateY(-1px)'}
            onMouseLeave={e=>e.currentTarget.style.transform=''}>
            {step < STEPS.length-1 ? <><ChevronRight size={13}/> Next</> : <><CheckCircle size={13}/> Finish</>}
          </button>
        </div>

        <div style={{ borderTop:'1px solid var(--cat-border)', padding:'7px 16px', display:'flex', alignItems:'center', justifyContent:'space-between' }}>
          <span style={{ fontSize:10, color:'var(--cat-sub)', opacity:.5 }}>
            <kbd style={{ background:'var(--cat-muted)', borderRadius:3, padding:'1px 4px', fontSize:9 }}>←→</kbd> navigate
            <kbd style={{ background:'var(--cat-muted)', borderRadius:3, padding:'1px 4px', fontSize:9, marginLeft:6 }}>ESC</kbd> skip
          </span>
          <button onClick={skip} style={{ background:'none', border:'none', fontSize:10, color:'var(--cat-sub)', cursor:'pointer', opacity:.5 }}>
            <SkipForward size={11}/> Skip all
          </button>
        </div>
      </div>
    </>
  )
}

export function useTour() {
  const [show, setShow] = useState(!localStorage.getItem(TOUR_KEY))
  const reset = () => { localStorage.removeItem(TOUR_KEY); setShow(true) }
  return { show, setShow, reset }
}
