// test/apps-api.test.js — the HTTP surface over the application pipeline.
//
// The pipeline itself is covered by test/discovery.test.js (with an injected
// Docker client) and test/protect-e2e.test.js. What is proven here is the
// part only the API can get wrong:
//
//   * the routes are reachable only through the signed, rotating admin path
//   * protecting, discovering and previewing all require an administrator
//   * a preview never claims protection, and neither does the inventory
//   * concurrent pipeline runs are refused rather than racing each other
//   * the Caddyfile inventory reader reconstructs what apply.js wrote
//
// Docker is optional. Where it is absent, discovery answers with an explicit
// reason and the test asserts that shape instead of skipping.

const os = require('os'), fs = require('fs'), path = require('path')
const DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-apps-'))
process.env.DB_DIR = DIR
process.env.JWT_SECRET = 'a'.repeat(64)
process.env.CATWAF_SETUP_TOKEN = 'bootstrap-test-token-'.repeat(3)
process.env.CADDYFILE_PATH = path.join(DIR, 'Caddyfile')
process.env.CORAZA_AUDIT_LOG = path.join(DIR, 'logs', 'audit.json')

// Never let a config reload reach a Caddy running on this machine.
// `reloadCaddy()` POSTs to CADDY_ADMIN_URL, which defaults to Caddy's real
// admin port — running the suite on a host where CatWAF is live would replace
// that Caddy's configuration with this file's fixture and take the site down.
process.env.CADDY_ADMIN_URL = process.env.CADDY_ADMIN_URL || 'http://127.0.0.1:19918'
fs.writeFileSync(process.env.CADDYFILE_PATH, '{\n}\n\nexample.com {\n    reverse_proxy 127.0.0.1:3000\n}\n')

const R = path.join(__dirname, '..')
const crypto = require('crypto')
const { app } = require(R + '/backend/server.js')

let pass = 0, fail = 0
const check = (n, c, x) => c ? (pass++, console.log('  ok   ' + n)) : (fail++, console.log('  FAIL ' + n, JSON.stringify(x ?? '').slice(0, 300)))
const section = n => console.log(`\n== ${n} ==`)

// ─── The inventory reader, as a unit ────────────────────────────────────

section('Caddyfile inventory reader')
{
  const generator = require(R + '/backend/services/proxy/generator.js')
  const inventory = require(R + '/backend/services/proxy/inventory.js')
  const state = require(R + '/backend/services/state.js')

  const routes = [
    { name: 'shop', runtime: 'PHP 8.3', containerName: 'shop_nginx', listenPort: 8080, upstream: '172.18.0.4:80' },
    { name: 'api', runtime: 'Node.js', containerName: 'api_svc', listenPort: 8081, upstream: '172.18.0.7:3000' },
  ]
  const region = generator.buildAutoRegion(routes, state.WAF)
  const parsed = inventory.parseRoutes(region)

  check('reads back every generated route', parsed.length === 2, parsed)
  check('reads back the name', parsed[0].name === 'shop', parsed[0])
  check('reads back the runtime', parsed[0].runtime === 'PHP 8.3', parsed[0])
  check('reads back the container', parsed[0].containerName === 'shop_nginx', parsed[0])
  check('reads back the listen port', parsed[0].listenPort === 8080, parsed[0])
  check('reads back the upstream', parsed[0].upstream === '172.18.0.4:80', parsed[0])
  check('keeps routes in order', parsed[1].listenPort === 8081, parsed[1])
  check('a file with no generated region yields no routes', inventory.parseRoutes('example.com {\n}\n').length === 0)
}

const server = app.listen(0, '127.0.0.1', async () => {
  const base = `http://127.0.0.1:${server.address().port}`

  async function raw(m, p, o = {}) {
    const opts = { method: m, headers: { 'Content-Type': 'application/json', ...(o.headers || {}) } }
    if (o.body !== undefined) opts.body = typeof o.body === 'string' ? o.body : JSON.stringify(o.body)
    const res = await fetch(base + p, opts)
    const text = await res.text()
    let j = text
    try { j = JSON.parse(text) } catch {}
    return { status: res.status, json: j, text }
  }

  await raw('POST', '/api/setup/account', { headers: { 'X-CatWAF-Setup-Token': process.env.CATWAF_SETUP_TOKEN }, body: { username: 'owner', password: 'correct-horse-battery' } })

  async function session(username, password) {
    const login = await raw('POST', '/api/auth/login', { body: { username, password } })
    const { token, sessionKey, api } = login.json
    const sign = (m, p, body) => {
      const ts = String(Date.now()), nonce = crypto.randomBytes(16).toString('hex')
      const bh = crypto.createHash('sha256').update(body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(body))).digest('hex')
      const sig = crypto.createHmac('sha256', sessionKey).update([m.toUpperCase(), p, ts, nonce, bh].join('\n')).digest('hex')
      return { Authorization: `Bearer ${token}`, 'X-CatWAF-Ts': ts, 'X-CatWAF-Nonce': nonce, 'X-CatWAF-Sig': sig }
    }
    return {
      login,
      G: p => raw('GET', api.basePath + p, { headers: sign('GET', p) }),
      P: (p, body) => raw('POST', api.basePath + p, { body, headers: sign('POST', p, body) }),
    }
  }

  const admin = await session('owner', 'correct-horse-battery')
  check('admin logs in', admin.login.status === 200, admin.login)

  section('the pipeline is behind the admin gate')
  const bare = await raw('GET', '/api/apps')
  check('/api/apps is not reachable at a fixed path', bare.status === 404, bare)
  const bareProtect = await raw('POST', '/api/apps/protect', { body: {} })
  check('/api/apps/protect is not reachable at a fixed path', bareProtect.status === 404, bareProtect)

  section('inventory')
  const apps = await admin.G('/api/apps')
  check('inventory reads the live Caddyfile', apps.status === 200 && apps.json.ok === true, apps)
  check('a Caddyfile with no generated region reports no routes', apps.json.routes.length === 0, apps.json)
  check('inventory reports whether a generated region exists', apps.json.hasRegion === false, apps.json)
  check('inventory never claims protection', !('protected' in apps.json), Object.keys(apps.json))
  check('inventory says applied is not protected', /not the same as protected/i.test(apps.json.note), apps.json.note)

  section('verify with nothing applied')
  const verifyEmpty = await admin.P('/api/apps/verify', {})
  check('verify answers rather than erroring', verifyEmpty.status === 200, verifyEmpty)
  check('verify reports nothing to verify', verifyEmpty.json.verification.allProtected === false, verifyEmpty.json)
  check('verify explains why', /has not applied any/i.test(verifyEmpty.json.detail || ''), verifyEmpty.json)

  section('discovery')
  const disc = await admin.P('/api/apps/discover', { skip_http_probe: true })
  check('discovery answers 200 whether or not Docker is present', disc.status === 200, disc)
  if (disc.json.ok) {
    check('discovery returns a container inventory', Array.isArray(disc.json.containers), disc.json)
    check('discovery returns web apps separately', Array.isArray(disc.json.web_apps), disc.json)
    const leaky = JSON.stringify(disc.json)
    check('discovery never returns raw container env', !/"env"\s*:/.test(leaky))
    check('discovery never returns raw container labels', !/"labels"\s*:/.test(leaky))
    for (const c of disc.json.containers.slice(0, 3)) {
      check(`container "${c.name}" is summarised, not raw`, 'isWeb' in c && 'runtime' in c && !('processes' in c), Object.keys(c))
    }
  } else {
    check('discovery explains why it could not run', typeof disc.json.detail === 'string' && disc.json.detail.length > 0, disc.json)
    check('discovery returns a machine-readable code', typeof disc.json.code === 'string', disc.json)
  }

  section('preview never protects')
  const preview = await admin.P('/api/apps/preview', {})
  check('preview answers 200', preview.status === 200, preview)
  check('preview is marked as a dry run', preview.json.dry_run === true, preview.json)
  check('preview never reports protection', preview.json.protected === false, preview.json)
  check('preview leaves the Caddyfile untouched',
    !fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8').includes('@@CATWAF_AUTO_START@@'))

  section('role enforcement')
  const { addUser } = require(R + '/backend/middleware/auth')
  addUser({ username: 'readonly', password: 'correct-horse-battery', role: 'viewer' })
  const viewer = await session('readonly', 'correct-horse-battery')
  check('a viewer logs in', viewer.login.status === 200, viewer.login)
  const viewerProtect = await viewer.P('/api/apps/protect', {})
  check('a viewer cannot protect', viewerProtect.status === 403, viewerProtect)
  const viewerDiscover = await viewer.P('/api/apps/discover', { skip_http_probe: true })
  // Discovery enumerates host containers and probes their ports — that is a
  // write-role capability now, matching /api/apps/protect and the intel
  // probe endpoints. A read-only account must be refused.
  check('a viewer cannot discover (host probing is admin-only)', viewerDiscover.status === 403, viewerDiscover.status)

  section('concurrent runs are refused')
  // Hold the first operation at a barrier. An empty Docker inventory can
  // otherwise finish before the second HTTP request arrives.
  const protectSvc = require(R + '/backend/services/proxy/protect')
  const originalProtect = protectSvc.protect
  let entered, release
  const started = new Promise(resolve => { entered = resolve })
  const pending = new Promise(resolve => { release = resolve })
  protectSvc.protect = async () => { entered(); await pending; return { ok: true, stage: 'preview' } }
  try {
    const firstRequest = admin.P('/api/apps/preview', {})
    await started
    const refused = await admin.P('/api/apps/preview', {})
    release()
    const first = await firstRequest
    check('one run succeeds and the other is refused', first.status === 200 && refused.status === 409, [first.status, refused.status])
    check('the refusal says what is already running', /already running/i.test(refused.json.detail || ''), refused.json)
  } finally { release(); protectSvc.protect = originalProtect }
  const afterBusy = await admin.G('/api/apps')
  check('the busy flag clears again', afterBusy.json.busy === null, afterBusy.json.busy)

  console.log(`\n${pass} passed, ${fail} failed`)
  server.close()
  process.exit(fail ? 1 : 0)
})
