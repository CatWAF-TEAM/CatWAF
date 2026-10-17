const os = require('os'), fs = require('fs'), path = require('path')
const DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-boot-'))
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
const { app } = require(R + '/backend/server.js')
const settings = require(R + '/backend/services/settings')
const jobs = require(R + '/backend/services/jobs')
require(R + '/backend/services/jobRegistry').registerAll()
const crypto = require('crypto')

let pass = 0, fail = 0
const check = (n, c, x) => c ? (pass++, console.log('  ok   ' + n)) : (fail++, console.log('  FAIL ' + n, JSON.stringify(x ?? '').slice(0,300)))

const server = app.listen(0, '127.0.0.1', async () => {
  const base = `http://127.0.0.1:${server.address().port}`
  async function raw(m, p, o = {}) {
    const opts = { method: m, headers: { 'Content-Type': 'application/json', ...(p.startsWith('/api/setup/') ? { 'X-CatWAF-Setup-Token': process.env.CATWAF_SETUP_TOKEN } : {}), ...(o.headers||{}) } }
    if (o.body !== undefined) opts.body = typeof o.body === 'string' ? o.body : JSON.stringify(o.body)
    const res = await fetch(base + p, opts)
    const text = await res.text()
    let j = text
    try { j = JSON.parse(text) } catch {}
    return { status: res.status, json: j, text, headers: res.headers }
  }

  console.log('\n== setup wizard (#52) ==')
  const st = await raw('GET', '/api/setup/status')
  check('setup status available before bootstrap', st.status === 200 && st.json.needs_setup === true, st)
  const acct = await raw('POST', '/api/setup/account', { body: { username: 'owner', password: 'correct-horse-battery' } })
  check('creates the admin account', acct.status === 200 && acct.json.ok, acct)
  const after = await raw('GET', '/api/setup/status')
  check('setup 404s once an admin exists', after.status === 404, after)

  console.log('\n== login + signed session ==')
  const login = await raw('POST', '/api/auth/login', { body: { username: 'owner', password: 'correct-horse-battery' } })
  check('login works', login.status === 200, login)
  const { token, sessionKey, api } = login.json
  function signed(m, p, body) {
    const ts = String(Date.now()), nonce = crypto.randomBytes(16).toString('hex')
    const bh = crypto.createHash('sha256').update(body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(body))).digest('hex')
    const sig = crypto.createHmac('sha256', sessionKey).update([m.toUpperCase(), p, ts, nonce, bh].join('\n')).digest('hex')
    return { Authorization: `Bearer ${token}`, 'X-CatWAF-Ts': ts, 'X-CatWAF-Nonce': nonce, 'X-CatWAF-Sig': sig }
  }
  const G = (p) => raw('GET', api.basePath + p, { headers: signed('GET', p) })
  const P = (p, body) => raw('POST', api.basePath + p, { body, headers: signed('POST', p, body) })

  console.log('\n== settings API ==')
  const schema = await G('/api/settings/schema')
  check('schema lists every group', schema.status === 200 && Object.keys(schema.json.groups).length >= 30, Object.keys(schema.json.groups||{}).length)
  const all = await G('/api/settings')
  check('settings read works', all.status === 200 && all.json.settings.access, all.status)
  const bad = await P('/api/settings/access', { blocked_status_code: 99 })
  check('invalid value rejected', bad.status === 400, bad)
  const good = await P('/api/settings/headers', { preset: 'strict' })
  check('valid value applied', good.status === 200 && good.json.values.preset === 'strict', good)
  const unknown = await P('/api/settings/headers', { nope: 1 })
  check('unknown field rejected', unknown.status === 400, unknown)

  console.log('\n== secret redaction ==')
  await P('/api/settings/metrics', { enabled: true, token: 'super-secret-token', require_token: true })
  const m = await G('/api/settings/metrics')
  check('secret not returned', m.json.values.token === '' && m.json.values.token_set === true, m.json.values)
  check('secret survives an unrelated write', settings.get('metrics').token === 'super-secret-token')

  console.log('\n== preview / diff (#50) ==')
  const prev = await P('/api/settings/access/preview', { reject_unknown_host: true, known_hosts: ['example.com'] })
  check('preview returns a diff', prev.status === 200 && prev.json.changed === true, prev.status)
  check('preview did not persist', settings.get('access').reject_unknown_host === false, settings.get('access').reject_unknown_host)

  console.log('\n== bans (#61) ==')
  const banned = await P('/api/bans', { target: '203.0.113.9', seconds: 600, reason: 'test' })
  check('ban created', banned.status === 200 && banned.json.ok, banned)
  const banList = await G('/api/bans')
  check('ban listed with its source', banList.json.bans.some(b => b.target === '203.0.113.9' && b.source === 'manual'), banList.json.bans)
  const self = await P('/api/bans', { target: '127.0.0.1', seconds: 60 })
  check('self-ban refused', self.status === 400 && self.json.code === 'SELF_BLOCK', self)

  console.log('\n== enforcement hop ==')
  const secrets = require(R + '/backend/services/secrets')
  const noKey = await raw('GET', '/api/enforce')
  check('enforce needs the shared key', noKey.status === 404, noKey)
  await P('/api/settings/dnsbl', { enabled: true })
  const enf = await raw('GET', '/api/enforce', { headers: { 'X-CatWAF-Enforce-Key': secrets.derive('enforce-key'), 'X-CatWAF-Client-IP': '203.0.113.9' } })
  check('banned address is blocked by the hop', enf.status === 403 || enf.status === 404, { s: enf.status, v: enf.headers.get('x-catwaf-verdict') })
  const clean = await raw('GET', '/api/enforce', { headers: { 'X-CatWAF-Enforce-Key': secrets.derive('enforce-key'), 'X-CatWAF-Client-IP': '198.51.100.5' } })
  check('clean address allowed', clean.status === 200 && clean.json.action === 'allow', clean)

  console.log('\n== challenge gate (#1-#4) ==')
  await P('/api/settings/challenge', { mode: 'captcha', trigger: 'all' })
  const page = await raw('GET', '/catwaf-challenge?return_to=/dashboard')
  check('challenge page served', page.status === 503 && page.text.includes('<svg'), page.status)
  const openRedirect = require(R + '/backend/services/challenge').safeReturnTo('//evil.example.com')
  check('open redirect refused', openRedirect === '/', openRedirect)

  console.log('\n== metrics (#46) ==')
  const noTok = await raw('GET', '/metrics')
  check('metrics needs a token', noTok.status === 401, noTok)
  const withTok = await raw('GET', '/metrics', { headers: { Authorization: 'Bearer super-secret-token' } })
  check('metrics served with a token', withTok.status === 200 && withTok.text.includes('catwaf_build_info'), withTok.status)

  console.log('\n== 2FA (#49) ==')
  const totp = require(R + '/backend/services/totp')
  const enroll = await P('/api/auth/2fa/enroll', {})
  check('enrollment returns an otpauth URI', enroll.status === 200 && enroll.json.uri.startsWith('otpauth://totp/'), enroll.status)
  const code = totp.totp(enroll.json.secret)
  const confirm = await P('/api/auth/2fa/confirm', { code })
  check('confirm with a live code works', confirm.status === 200 && confirm.json.recovery_codes.length === 10, confirm)
  const loginNo2fa = await raw('POST', '/api/auth/login', { body: { username: 'owner', password: 'correct-horse-battery' } })
  check('login now demands the second factor', loginNo2fa.status === 401 && loginNo2fa.json.code === 'TOTP_REQUIRED', loginNo2fa)

  // The code just used to confirm enrollment is spent. Anyone who saw it
  // being typed must not be able to log in with it for the rest of its
  // window, so the login below deliberately uses the next one.
  const replay = await raw('POST', '/api/auth/login', { body: { username: 'owner', password: 'correct-horse-battery', totp: code } })
  check('the code that confirmed enrollment cannot be replayed to log in', replay.status === 401, replay)

  const nextCode = totp.totp(enroll.json.secret, { at: Date.now() + 30_000 })
  const login2fa = await raw('POST', '/api/auth/login', { body: { username: 'owner', password: 'correct-horse-battery', totp: nextCode } })
  check('login with the next code works', login2fa.status === 200, login2fa)

  console.log('\n== jobs, caches, reports, templates, plugins ==')
  const jl = await G('/api/jobs')
  check('jobs registered', jl.status === 200 && jl.json.jobs.length >= 9, jl.json.jobs?.length)
  const cl = await G('/api/caches')
  check('caches enumerated', cl.status === 200 && cl.json.namespaces.length >= 10, cl.json.namespaces?.length)
  const rep = await raw('GET', api.basePath + '/api/reports?format=csv', { headers: signed('GET', '/api/reports?format=csv') })
  check('CSV report exported', rep.status === 200 && rep.text.includes('# CatWAF report'), rep.status)
  const tpl = await G('/api/templates')
  check('built-in templates present', tpl.json.templates.length >= 4, tpl.json.templates?.length)
  const applyTpl = await P('/api/templates/static-site/apply', { dry_run: true })
  check('template dry run works', applyTpl.status === 200 && Array.isArray(applyTpl.json.changes), applyTpl)
  const evilPlugin = await P('/api/plugins', { catwaf_plugin: 1, id: 'evil', name: 'Evil', code: 'require("fs")' })
  check('plugin with code refused', evilPlugin.status === 400 && /data only/.test(evilPlugin.json.detail), evilPlugin)
  const okPlugin = await P('/api/plugins', { catwaf_plugin: 1, id: 'hardening', name: 'Hardening', settings_defaults: { headers: { preset: 'strict' } } })
  check('data-only plugin accepted', okPlugin.status === 200, okPlugin)

  console.log(`\n${pass} passed, ${fail} failed\n`)
  server.close(); jobs.stop()
  // Windows keeps SQLite handles open until exit; cleanup must not mask failures.
  try { fs.rmSync(DIR, { recursive: true, force: true }) } catch {}
  process.exit(fail ? 1 : 0)
})
