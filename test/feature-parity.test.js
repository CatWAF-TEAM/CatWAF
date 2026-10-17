const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('fs')
const os = require('os')
const path = require('path')
const http = require('http')
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-parity-'))
process.env.DB_DIR = dir
process.env.JWT_SECRET = 'parity-fixture-secret-'.repeat(4)
process.env.CADDYFILE_PATH = path.join(dir, 'Caddyfile')
process.env.CORAZA_AUDIT_LOG = path.join(dir, 'audit.json')
process.env.CADDY_ADMIN_URL = 'http://127.0.0.1:1'
fs.writeFileSync(process.env.CADDYFILE_PATH, 'http://fixture.invalid {\n respond "fixture"\n}\n')
fs.writeFileSync(process.env.CORAZA_AUDIT_LOG, '')
const settings = require('../backend/services/settings')
const challenge = require('../backend/services/challenge')
const managed = require('../backend/services/managedRoutes')
const state = require('../backend/services/state')
const db = require('../backend/services/db')
const tx = require('../backend/services/configTx')
const k8s = require('../backend/services/kubernetes')
function set(group, patch) { const r = settings.set(group, patch); assert.equal(r.ok, true, r.error) }
const client = { ip: '198.51.100.54', userAgent: 'fixture-browser' }

test('cookie challenge proves a cookie round trip, binds the client, and consumes its nonce', async () => {
  set('challenge', { mode: 'cookie', trigger: 'all' })
  const issued = challenge.issue(client)
  assert.match(challenge.pendingCookieHeader(issued.id, 30), /HttpOnly; SameSite=Strict; Secure/)
  assert.equal((await challenge.solve({ ...client, id: issued.id })).ok, false)
  assert.equal((await challenge.solve({ ...client, id: issued.id, cookieId: issued.id, userAgent: 'other' })).ok, false)
  const solved = await challenge.solve({ ...client, id: issued.id, cookieId: issued.id })
  assert.equal(solved.ok, true)
  assert.equal(challenge.verifyToken(solved.token, client).valid, true)
  assert.equal((await challenge.solve({ ...client, id: issued.id, cookieId: issued.id })).ok, false)
  set('challenge', { mode: 'captcha' })
  assert.equal(challenge.verifyToken(solved.token, client).valid, false)
})

test('CAPTCHA image carries pixels, never text containing the answer', () => {
  const captcha = require('../backend/services/challenge/captcha')
  const svg = captcha.renderSvg('ABCDE')
  assert.doesNotMatch(svg, /<text|ABCDE|data-answer/)
  const png = Buffer.from(svg.match(/base64,([^"<]+)/)[1], 'base64')
  assert.equal(png.subarray(1,4).toString(), 'PNG')
  assert.ok(png.length > 500)
  assert.equal(captcha.matches('ABCDE', 'abcde'), true)
  assert.equal(captcha.matches('ABCDE', 'ABCDF'), false)
})

test('challenge providers reject wrong hosts, stale tokens, transport failures, and concurrent replay', async () => {
  const providers = require('../backend/services/challenge/providers')
  const guard = require('../backend/services/netGuard')
  const original = guard.guardedFetch
  const cfg = { site_key: 'site', secret_key: 'secret', provider_hostnames: [] }
  let data = { success: true, hostname: 'example.com', challenge_ts: new Date().toISOString() }
  let status = true
  guard.guardedFetch = async () => ({ response: { ok: status, json: async () => data } })
  try {
    assert.equal((await providers.verify('recaptcha', 'response', cfg, client.ip, 'example.com')).ok, true)
    assert.equal((await providers.verify('recaptcha', 'response', cfg, client.ip, 'evil.example')).ok, false)
    data.challenge_ts = new Date(0).toISOString()
    assert.equal((await providers.verify('recaptcha', 'response', cfg, client.ip, 'example.com')).ok, false)
    status = false
    assert.equal((await providers.verify('recaptcha', 'response', cfg, client.ip, 'example.com')).ok, false)
    let release
    guard.guardedFetch = async () => { await new Promise(r => { release = r }); return { response: { ok: true, json: async () => ({ success: true, hostname: 'example.com', challenge_ts: new Date().toISOString() }) } } }
    set('challenge', { mode: 'provider', provider: 'recaptcha', site_key: 'site', secret_key: 'secret' })
    const issued = challenge.issue(client)
    const solving = challenge.solve({ ...client, id: issued.id, providerToken: 'token', hostname: 'example.com' })
    assert.equal((await challenge.solve({ ...client, id: issued.id, providerToken: 'token', hostname: 'example.com' })).ok, false)
    release()
    assert.equal((await solving).ok, true)
  } finally { guard.guardedFetch = original; settings.reset('challenge') }
})

test('CrowdSec native query handles ranges, expiry, changed credentials, CAPTCHA, and fail-closed errors', async () => {
  const feed = require('../backend/services/intel/threatFeed')
  const enforce = require('../backend/services/enforce')
  const cache = require('../backend/services/intel/cache')
  let payload = [{ scope: 'Range', value: '198.51.100.0/24', type: 'ban', duration: '0.05s' }]
  let code = 200, calls = 0
  const server = http.createServer((req,res) => { calls++; assert.ok(req.url.startsWith('/v1/decisions?ip=')); res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(payload)) })
  await new Promise(r => server.listen(0, '127.0.0.1', r))
  set('threat_feed', { enabled: true, url: 'http://127.0.0.1:' + server.address().port, cache_seconds: 60, api_key: 'one', fail_open: false })
  try {
    assert.equal((await feed.evaluate(client.ip)).decision, 'block')
    assert.equal(require('../backend/services/bans').check(client.ip), null, 'external decisions must not become stale local bans')
    await new Promise(r => setTimeout(r, 80))
    payload = null
    assert.equal(await feed.evaluate(client.ip), null)
    const before = calls
    set('threat_feed', { api_key: 'two' })
    payload = [{ scope: 'Username', value: client.ip, type: 'ban', duration: '1h' }]
    assert.equal(await feed.evaluate(client.ip), null)
    assert.ok(calls > before)
    cache.clear(feed.NS)
    payload = [{ scope: 'Ip', value: client.ip, type: 'captcha', duration: '1h' }]
    assert.equal((await enforce.classify({ ...client, uri: '/api/exempt' })).action, 'block', 'disabled challenge cannot bypass a CAPTCHA decision')
    set('challenge', { mode: 'captcha' })
    assert.equal((await enforce.classify({ ...client, uri: '/api/exempt' })).action, 'challenge', 'external CAPTCHA survives ordinary path exemptions')
    cache.clear(feed.NS); code = 503
    assert.equal((await feed.evaluate(client.ip)).decision, 'block')
    set('threat_feed', { fail_open: true })
    assert.equal((await feed.evaluate(client.ip)).decision, 'unavailable')
    assert.equal(feed.durationSeconds('-5s', 0), 0)
    assert.equal(feed.durationSeconds('4h30m', 0), 16200)
    assert.throws(() => feed.parseDecisions({ nonsense: true }), /Invalid/)
    assert.throws(() => feed.parseDecisions([null]), /Invalid/)
    assert.throws(() => feed.parseDecisions([{type:'ban',value:client.ip}]), /Invalid/)
  } finally { server.closeAllConnections(); await new Promise(r => server.close(r)); settings.reset('threat_feed'); settings.reset('challenge') }
})

test('Docker labels create scoped routes, reject malformed input, and never mutate global WAF policy', async () => {
  const auto = require('../backend/services/autoconf')
  set('sites', { max_sites: 10 })
  set('autoconf', { enabled: true, remove_orphans: true })
  const container = { id: 'a'.repeat(64), name: 'app', running: true, labels: { 'catwaf.enable':'true', 'catwaf.host':'app.example.com', 'catwaf.port':'3000', 'catwaf.paranoia':'3' }, networks: { edge: { IPAddress:'172.19.0.2' } } }
  const originalWaf = JSON.stringify(state.WAF)
  const preview = await auto.scan({ dryRun: true, containers: [container] })
  assert.equal(preview.ok, true, preview.error)
  assert.equal(preview.routes[0].upstream, '172.19.0.2:3000')
  assert.equal(preview.routes[0].policy.waf.paranoia_level, 3)
  assert.deepEqual(managed.read(), {})
  assert.equal(JSON.stringify(state.WAF), originalWaf)
  const invalid = await auto.scan({ dryRun: false, containers: [{ ...container, labels: { ...container.labels, 'catwaf.port': '3000\n}' } }] })
  assert.equal(invalid.ok, false)
  assert.deepEqual(managed.read(), {})
  settings.reset('autoconf')
})

test('managed route publication rolls back on validation failure and preserves other controller ownership', () => {
  const route = { id:'docker/app', host:'app.example.com', path:'/foo', pathType:'Prefix', upstream:'127.0.0.1:3000' }
  const before = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8')
  const validate = tx.validateCaddyfile
  tx.validateCaddyfile = () => ({ ok:false, error:'injected validation failure' })
  try {
    const result = managed.reconcile('docker', [route])
    assert.equal(result.ok, false)
    assert.equal(result.rolledBack, true)
    assert.deepEqual(managed.read(), {})
    assert.equal(fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8'), before)
  } finally { tx.validateCaddyfile = validate }
  // Unit fixture validates source rendering separately from the real proxy suite.
  db.setState(managed.KEY, { docker:{ routes:[route], certificates:{} } })
  const result = managed.reconcile('kubernetes', [{ ...route, id:'default/ingress', host:'ingress.example.com', path:'/foo', pathType:'Exact' }], { dryRun:true })
  assert.equal(result.ok, true)
  assert.equal(managed.allRoutes().length, 1)
  assert.throws(() => managed.reconcile('kubernetes', [{ ...route, id:'conflict' }], { dryRun:true }), /Duplicate managed route/)
  const source = require('../backend/services/render/util').withoutAssetWrites(() => managed.render({docker:{routes:[route, {...route,id:'exact',pathType:'Exact'}]}}, state.WAF))
  assert.match(source, /path "\/foo" "\/foo\/\*"/)
  assert.ok(source.indexOf('path "/foo"\n') < source.indexOf('path "/foo" "/foo/*"'))
  assert.match(source, /coraza_waf/)
  db.setState(managed.KEY, {})
})

test('first manual ban rolls back with its enforcement gate when configuration validation fails', () => {
  const bans = require('../backend/services/bans'), validate = tx.validateCaddyfile
  tx.validateCaddyfile = () => ({ ok:false, error:'injected failure' })
  try {
    assert.equal(bans.addManual({target:'203.0.113.45',seconds:60}).ok,false)
    assert.equal(bans.check('203.0.113.45'),null)
    assert.equal(settings.get('ban_enforcement').enabled,false)
  } finally {tx.validateCaddyfile=validate}
})

test('scheduler reports explicit controller failures as failures', async () => {
  const jobs=require('../backend/services/jobs')
  jobs.register('fixture.controller',{fn:async()=>({ok:false,error:'API unavailable'})})
  const result=await jobs.runJob('fixture.controller',{manual:true})
  assert.equal(result.ok,false)
  assert.equal(jobs.list().find(j=>j.name==='fixture.controller').last_run.ok,false)
})

test('Kubernetes selects its class, resolves named service ports, and retains routes on failed reads', async () => {
  set('kubernetes', { enabled:true })
  const ingress = { metadata:{name:'web',namespace:'default'}, spec:{ingressClassName:'catwaf',rules:[{host:'web.example.com',http:{paths:[{path:'/api',pathType:'Prefix',backend:{service:{name:'web',port:{name:'http'}}}}]}}]} }
  const service = {metadata:{name:'web',namespace:'default'},spec:{clusterIP:'10.96.0.50',ports:[{name:'http',port:8080}]}}
  let fail = false
  const api = { get: async uri => {
    if (fail) throw new Error('API unavailable')
    if (uri.includes('ingressclasses')) return {spec:{controller:'catwaf.com/ingress-controller'}}
    return {items:uri.includes('/ingresses') ? [ingress] : [service], metadata:{}}
  } }
  const result = await k8s.scan({api,dryRun:true})
  assert.equal(result.ok,true,result.error)
  assert.equal(result.routes[0].upstream,'10.96.0.50:8080')
  db.setState(managed.KEY,{kubernetes:{routes:result.routes,certificates:{}}})
  fail = true
  assert.equal((await k8s.scan({api,dryRun:false})).ok,false)
  assert.equal(managed.allRoutes().length,1)
  fail = false
  ingress.spec.ingressClassName = 'another'
  const ignored = await k8s.scan({api,dryRun:true})
  assert.equal(ignored.routes.length,0)
  assert.equal(ignored.removed,1)
  ingress.spec.ingressClassName = 'catwaf'
  ingress.spec.rules[0].http.paths[0].pathType = 'ImplementationSpecific'
  assert.equal((await k8s.scan({api,dryRun:true})).ok,false)
  assert.equal(managed.allRoutes().length,1)
  const racedApi={get:async uri=>{
    if(uri.includes('ingressclasses')) {set('kubernetes',{enabled:false});return {spec:{controller:'catwaf.com/ingress-controller'}}}
    return {items:[],metadata:{}}
  }}
  const raced=await k8s.scan({api:racedApi,dryRun:false})
  assert.equal(raced.ok,false)
  assert.match(raced.error,/settings changed/)
  assert.equal(managed.allRoutes().length,1,'disabled controller cannot publish an in-flight empty inventory')
  db.setState(managed.KEY,{})
  settings.reset('kubernetes')
})
