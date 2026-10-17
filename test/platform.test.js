#!/usr/bin/env node

const fs = require('fs')
const os = require('os')
const path = require('path')

const ROOT = path.join(__dirname, '..')
const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-platform-'))

process.env.DB_DIR = path.join(WORK, 'db')
process.env.JWT_SECRET = 'p'.repeat(64)
// The provisioning section below calls prov.apply(), which reloads Caddy.
// Left at the default admin endpoint that reload reached whatever Caddy owns
// :2019 on this machine and replaced its live configuration with this file's
// `catwaf.example.com` dashboard fixture — a running CatWAF stopped serving
// the site it was protecting. Must be set before caddy.js is first required,
// since it reads the endpoint at module load.
// Unconditional: an inherited CADDY_ADMIN_URL could point this suite's fixture
// Caddyfile load at a live Caddy instance.
process.env.CADDY_ADMIN_URL = 'http://127.0.0.1:19918'
fs.mkdirSync(process.env.DB_DIR, { recursive: true })

let pass = 0, fail = 0
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  ok   ' + name) }
  else { fail++; console.log('  FAIL ' + name, extra !== undefined ? JSON.stringify(extra) : '') }
}
function section(t) { console.log('\n== ' + t + ' ==') }

process.on('exit', () => { try { fs.rmSync(WORK, { recursive: true, force: true }) } catch {} })

const envSvc = require(path.join(ROOT, 'backend/services/environment.js'))
const prov = require(path.join(ROOT, 'backend/services/provision.js'))
const auth = require(path.join(ROOT, 'backend/middleware/auth.js'))

;(async () => {
  section('environment detection')
  const env = await envSvc.detect()
  check('detect() returns a structured object', env && typeof env === 'object')
  for (const key of ['os', 'runtime', 'container', 'init', 'caddy', 'nginx', 'apache', 'cpanel', 'existing', 'ports']) {
    check(`detect() includes "${key}"`, key in env)
  }
  check('os.platform matches process.platform', env.os.platform === process.platform)
  check('runtime.node matches process.version', env.runtime.node === process.version)
  check('primaryWebServer is one of the known values',
    ['caddy', 'nginx', 'apache', 'cpanel', 'none'].includes(env.primaryWebServer), env.primaryWebServer)
  check('detection never throws on a machine without cPanel', typeof env.cpanel.detected === 'boolean')
  check('cPanel automation is never claimed to be supported', env.cpanel.automationSupported === false)
  check('Plesk automation is never claimed to be supported', env.plesk.automationSupported === false)
  check('DirectAdmin automation is never claimed to be supported', env.directadmin.automationSupported === false)

  section('nginx server_name parsing')
  const nginxConf = `
    server {
      listen 80;
      server_name example.com www.example.com;
    }
    server {
      server_name  *.wild.example.org  _;
    }
    server { server_name ~^regex\\.example\\.net$; }
  `
  const names = envSvc.parseNginxServerNames(nginxConf)
  check('parses multiple server_name values', names.includes('example.com') && names.includes('www.example.com'), names)
  check('strips wildcard prefix', names.includes('wild.example.org'), names)
  check('ignores the catch-all "_"', !names.includes('_'), names)
  check('ignores regex server names', !names.some(n => n.startsWith('~')), names)

  section('cPanel userdatadomains parsing')
  const udd = [
    'example.com: alice==alice==main==/home/alice/public_html==192.0.2.10==80',
    'sub.example.com: alice==alice==sub==/home/alice/public_html/sub==192.0.2.10==80',
    'other.test: bob==bob==main==/home/bob/public_html==192.0.2.11==80',
    '',
    '# a comment line',
  ].join('\n')
  const sites = envSvc.parseUserDataDomains(udd)
  check('parses one entry per domain', sites.length === 3, sites.length)
  check('extracts the owning user', sites[0].user === 'alice', sites[0])
  check('extracts the document root', sites[0].docroot === '/home/alice/public_html', sites[0])
  check('extracts the type', sites[0].type === 'main', sites[0])
  check('extracts the ip', sites[0].ip === '192.0.2.10', sites[0])

  const altLayout = envSvc.parseUserDataDomains('alt.example.com: carol==carol==carol==addon==/home/carol/alt==203.0.113.7==2001:db8::1==80==443')
  check('field order variation still yields the docroot', altLayout[0].docroot === '/home/carol/alt', altLayout[0])
  check('field order variation still yields the ip', altLayout[0].ip === '203.0.113.7', altLayout[0])
  check('field order variation still yields the type', altLayout[0].type === 'addon', altLayout[0])
  check('skips comments and blank lines', !sites.some(s => s.domain.startsWith('#')))

  section('dashboard hostname selection')
  check('dashboardHostFor prefixes catwaf.', prov.dashboardHostFor('example.com') === 'catwaf.example.com')
  check('rejects an invalid hostname', !!prov.validateHostname('not a domain'))
  check('accepts a valid hostname', prov.validateHostname('example.com') === null)
  check('rejects an empty hostname', !!prov.validateHostname(''))

  const fakeCpanelEnv = {
    ...env,
    cpanel: { detected: true, sites: [{ domain: 'zzz.example.com' }, { domain: 'example.com' }], automationSupported: false },
    nginx: { ...env.nginx, domains: [] },
    apache: { ...env.apache, domains: [] },
  }
  check('guessBaseDomain prefers the shortest domain', envSvc.guessBaseDomain(fakeCpanelEnv) === 'example.com', envSvc.guessBaseDomain(fakeCpanelEnv))
  check('guessBaseDomain ignores localhost',
    envSvc.guessBaseDomain({ cpanel: { sites: [{ domain: 'localhost' }] }, nginx: { domains: [] }, apache: { domains: [] } }) === null)

  section('generated web server configuration')
  const opts = { dashboardHost: 'catwaf.example.com', apiPort: 8000, distPath: '/srv/catwaf/dist' }

  const caddyCfg = prov.caddyConfig(opts)
  check('caddy config names the dashboard host', caddyCfg.includes('catwaf.example.com'))
  check('caddy config proxies /api', caddyCfg.includes('handle /api/*'))
  check('caddy config proxies the rotating /g gate', caddyCfg.includes('handle /g/*'))
  check('caddy config serves the SPA fallback', caddyCfg.includes('try_files {path} /index.html'))

  const nginxCfg = prov.nginxConfig(opts)
  check('nginx config sets server_name', nginxCfg.includes('server_name catwaf.example.com;'))
  check('nginx config proxies /api/', nginxCfg.includes('location /api/'))
  check('nginx config proxies /g/', nginxCfg.includes('location /g/'))
  check('nginx config forwards the client IP', nginxCfg.includes('X-Forwarded-For'))
  check('nginx config has the SPA fallback', nginxCfg.includes('try_files $uri $uri/ /index.html;'))

  const apacheCfg = prov.apacheConfig(opts)
  check('apache config sets ServerName', apacheCfg.includes('ServerName catwaf.example.com'))
  check('apache config reverse-proxies the API', apacheCfg.includes('ProxyPass        /api/'))
  check('apache config sets FallbackResource', apacheCfg.includes('FallbackResource /index.html'))

  section('cPanel is detection-only, never automated')
  const cpanelPlan = prov.plan({ env: fakeCpanelEnv, baseDomain: 'example.com', target: 'cpanel' })
  check('cPanel plan is produced', cpanelPlan.ok)
  check('cPanel plan is NOT automatable', cpanelPlan.automatable === false)
  check('cPanel plan states NOT AVAILABLE', /NOT AVAILABLE/.test(cpanelPlan.unsupportedReason || ''))
  check('cPanel plan still offers reference config', typeof cpanelPlan.config === 'string' && cpanelPlan.config.length > 0)
  const applied = prov.apply(cpanelPlan)
  check('applying a cPanel plan is refused', applied.ok === false, applied)

  section('provisioning writes, validates, and rolls back')
  const target = path.join(WORK, 'Caddyfile')
  const original = '{\n    order coraza_waf first\n}\n\n:9600 {\n    respond "orig" 200\n}\n'
  fs.writeFileSync(target, original)
  process.env.CADDYFILE_PATH = target
  delete require.cache[require.resolve(path.join(ROOT, 'backend/services/caddy.js'))]

  const plan = prov.plan({ env, baseDomain: 'example.com', target: 'caddy', distPath: path.join(WORK, 'dist') })
  check('caddy plan is automatable', plan.automatable === true, plan.destination)

  const caddyAvailable = (() => {
    try { require('child_process').execFileSync('caddy', ['version'], { timeout: 5000, stdio: 'ignore' }); return true } catch { return false }
  })()

  if (caddyAvailable) {
    const good = prov.apply(plan)
    check('apply succeeds with valid config', good.ok === true, good.error)
    check('apply creates a backup', !!good.backup && fs.existsSync(good.backup))
    check('apply validated the result', good.validated === true)
    const written = fs.readFileSync(target, 'utf8')
    check('written config keeps the original site block', written.includes(':9600'))
    check('written config is marked as CatWAF-managed', written.includes('@@CATWAF_DASHBOARD_START@@'))

    fs.writeFileSync(target, original)
    const badPlan = { ...plan, config: 'catwaf.example.com {\n    not_a_real_directive yes\n}\n' }
    const bad = prov.apply(badPlan)
    check('apply rejects invalid config', bad.ok === false)
    check('apply reports the rollback', bad.rolledBack === true)
    check('original config is restored byte-for-byte', fs.readFileSync(target, 'utf8') === original)
  } else {
    console.log('  SKIP  caddy binary not available — apply/rollback checks need it')
  }

  section('user lifecycle')
  check('starts with no accounts', auth.needsBootstrap())
  auth.addUser({ username: 'root_admin', password: 'longenoughpw1', role: 'admin' })
  check('created an admin', auth.listUsers().length === 1)
  check('password is bcrypt-hashed, never plaintext', /^\$2[aby]\$/.test(auth.USERS[0].password_hash))
  check('plaintext password is not stored anywhere on the record',
    !JSON.stringify(auth.USERS[0]).includes('longenoughpw1'))
  check('correct password verifies', auth.verifyPassword('root_admin', 'longenoughpw1'))
  check('wrong password is rejected', !auth.verifyPassword('root_admin', 'nope'))

  let threw = null
  try { auth.addUser({ username: 'shortpw', password: 'abc', role: 'viewer' }) } catch (e) { threw = e.message }
  check('rejects a password under the minimum length', !!threw, threw)

  threw = null
  try { auth.addUser({ username: 'baddie', password: 'longenoughpw1', role: 'superuser' }) } catch (e) { threw = e.message }
  check('rejects an unknown role', !!threw, threw)

  threw = null
  try { auth.addUser({ username: 'root_admin', password: 'longenoughpw1', role: 'viewer' }) } catch (e) { threw = e.message }
  check('rejects a duplicate username', !!threw, threw)

  threw = null
  try { auth.removeUser('root_admin') } catch (e) { threw = e.message }
  check('refuses to remove the last admin', !!threw, threw)

  threw = null
  try { auth.setRole('root_admin', 'viewer') } catch (e) { threw = e.message }
  check('refuses to demote the last admin', !!threw, threw)

  auth.addUser({ username: 'second_admin', password: 'longenoughpw2', role: 'admin' })
  const removed = auth.removeUser('root_admin')
  check('removes an admin once another exists', removed.username === 'root_admin')
  check('listUsers never exposes password hashes',
    auth.listUsers().every(u => !('password_hash' in u)), auth.listUsers()[0])

  check('USERS proxy supports filter (hole-skipping array methods)',
    auth.USERS.filter(u => u.role === 'admin').length === auth.listUsers().filter(u => u.role === 'admin').length,
    { viaProxy: auth.USERS.filter(u => u.role === 'admin').length, viaList: auth.listUsers().filter(u => u.role === 'admin').length })
  check('USERS proxy supports map', auth.USERS.map(u => u.username).length === auth.USERS.length)
  check('USERS proxy supports some', auth.USERS.some(u => u.role === 'admin'))
  check('USERS proxy supports spread', [...auth.USERS].length === auth.USERS.length)

  section('service manager')
  const svc = require(path.join(ROOT, 'src/tui/service.js'))
  const st = svc.status()
  check('status() reports a manager', ['systemd', 'process'].includes(st.manager), st)
  check('status() reports a boolean running state', typeof st.running === 'boolean')
  check('logs() returns a plan', ['journalctl', 'file'].includes(svc.logs().mode))

  section('no docker socket dependency anywhere')
  const compose = fs.readFileSync(path.join(ROOT, 'docker-compose.yml'), 'utf8')
  check('docker-compose.yml does not mount the docker socket', !compose.includes('/var/run/docker.sock'))
  const composeConfig = require('js-yaml').load(compose)
  check('backend uses the private Caddy admin socket', composeConfig.services.backend.environment.CADDY_ADMIN_SOCKET === '/run/catwaf-admin/admin.sock')
  check('origin cannot mount the Caddy admin socket', !(composeConfig.services['test-app'].volumes || []).some(v => String(v).includes('caddy-admin')))
  check('dashboard HTTP listener is loopback-only', composeConfig.services.caddy.ports.includes('127.0.0.1:8081:8081'))
  // The vulnerable demo app is the protected site's ORIGIN (:8082). It is
  // published so the origin port is addressable for local inspection and so
  // the WAF-vs-no-WAF difference can be demonstrated — but only on loopback,
  // because a request that reaches it directly is never inspected by Coraza.
  // Anything other than a 127.0.0.1 bind here is a WAF bypass on the network.
  // (The old assertion here read `compose.split('volumes:')[0]`, which cut the
  // string at the *backend* service's volumes key — before `test-app:` even
  // appears — so it passed no matter what was published.)
  const testAppBlock = compose.slice(compose.indexOf('\n  test-app:'))
  const testAppPorts = [...testAppBlock.matchAll(/^\s*-\s*"([^"]+)"/gm)].map(m => m[1])
  check('test app service block was located', testAppBlock.includes('TestApp.Dockerfile'))
  check('test app is never published on a wildcard bind',
    testAppPorts.every(p => p.startsWith('127.0.0.1:')), testAppPorts)
  check('test app origin is published on :8082',
    testAppPorts.some(p => /^127\.0\.0\.1:8082:/.test(p)), testAppPorts)
  const caddySource = fs.readFileSync(path.join(ROOT, 'backend/services/caddy.js'), 'utf8')
  check('caddy service never shells out to docker', !/\bdocker\b/.test(caddySource))

  section('input validation on outbound-request routes')
  const cfSource = fs.readFileSync(path.join(ROOT, 'backend/routes/cloudflare.js'), 'utf8')
  check('zone_id is validated before use', /isValidZoneId\(zone_id\)/.test(cfSource))
  check('record_id is validated before use', /isValidRecordId\(rid\)/.test(cfSource))
  check('domain from the API is hostname-validated before fetch', /isValidHostname\(domain\)/.test(cfSource))
  check('reachability probe goes through the SSRF guard', /netGuard\.guardedFetch\(/.test(cfSource))
  const guardSource = fs.readFileSync(path.join(ROOT, 'backend/services/netGuard.js'), 'utf8')
  check('guarded outbound fetch has a timeout', /AbortSignal\.timeout/.test(guardSource))
  // Redirect handling is a manual hop loop: each hop is re-validated before
  // connecting (protocol allowlist + address pin), never delegated to fetch.
  check('guarded fetch does not blindly follow redirects', /MAX_REDIRECTS/.test(guardSource) && /res\.statusCode !== 307/.test(guardSource))
  check('guarded fetch caps redirect depth', /MAX_REDIRECTS/.test(guardSource))
  check('guarded fetch restricts protocols', /ALLOWED_PROTOCOLS/.test(guardSource))
  // Anti-rebinding: connections must go through the pinned-lookup transport,
  // which resolves once, validates, and hands only judged addresses to the
  // socket — the hostname is never resolved twice.
  check('outbound connections use DNS-pinned lookup', /makePinnedLookup/.test(guardSource) && /lookup: makePinnedLookup/.test(guardSource))
  const scannerSource = fs.readFileSync(path.join(ROOT, 'backend/routes/scanner.js'), 'utf8')
  check('origin scanner refuses non-public destinations', /reasonNotPublic\(/.test(scannerSource))

  section('no unsafe shell execution')
  for (const rel of ['backend', 'src', 'scripts', 'bin']) {
    const dir = path.join(ROOT, rel)
    const files = []
    const walk = d => {
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        if (e.name === 'node_modules') continue
        const full = path.join(d, e.name)
        if (e.isDirectory()) walk(full)
        else if (e.name.endsWith('.js')) files.push(full)
      }
    }
    try { walk(dir) } catch { continue }
    const offenders = files.filter(f => {
      const body = fs.readFileSync(f, 'utf8')
      return /\bexecSync\s*\(/.test(body) || /shell:\s*true/.test(body)
    })
    check(`${rel}/ uses no execSync and no shell:true`, offenders.length === 0, offenders.map(f => path.relative(ROOT, f)))
  }

  section('schema migration rejects unsafe identifiers')
  const dbSource = fs.readFileSync(path.join(ROOT, 'backend/services/db.js'), 'utf8')
  check('migration validates table identifiers', /SAFE_IDENTIFIER\.test\(table\)/.test(dbSource))
  check('migration validates column identifiers', /SAFE_IDENTIFIER\.test\(name\)/.test(dbSource))
  check('migration validates column types', /SAFE_COLUMN_TYPE\.test\(type\)/.test(dbSource))

  section('errors do not leak stack traces to clients')
  const ehSource = fs.readFileSync(path.join(ROOT, 'backend/middleware/errorHandler.js'), 'utf8')
  const responseBlock = ehSource.slice(ehSource.indexOf('res.status(status).json'))
  check('error response body contains no stack', !/stack/.test(responseBlock), responseBlock.slice(0, 120))
  check('5xx responses return a generic message', /Internal server error/.test(ehSource))

  console.log(`\n${pass} passed, ${fail} failed`)
  process.exit(fail ? 1 : 0)
})().catch(e => {
  console.error('\nharness error:', e.stack || e.message)
  process.exit(1)
})
