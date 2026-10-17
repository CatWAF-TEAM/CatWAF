#!/usr/bin/env node

const fs = require('fs')
const os = require('os')
const path = require('path')
const http = require('http')
const { execFileSync, spawn } = require('child_process')

const ROOT = path.join(__dirname, '..')
const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-e2e-'))
const LOG_DIR = path.join(WORK, 'logs')
const AUDIT_LOG = path.join(LOG_DIR, 'audit.json')
const CADDYFILE = path.join(WORK, 'Caddyfile')
const DB_DIR = path.join(WORK, 'db')

const APP_PORT = Number(process.env.E2E_APP_PORT || 19080)
const WAF_PORT = Number(process.env.E2E_WAF_PORT || 19099)
const ADMIN_PORT = Number(process.env.E2E_ADMIN_PORT || 19019)
const ADMIN_URL = `http://127.0.0.1:${ADMIN_PORT}`

fs.mkdirSync(LOG_DIR, { recursive: true })
fs.mkdirSync(DB_DIR, { recursive: true })

process.env.DB_DIR = DB_DIR
process.env.CADDYFILE_PATH = CADDYFILE
process.env.CADDY_ADMIN_URL = ADMIN_URL
process.env.CORAZA_AUDIT_LOG = AUDIT_LOG
process.env.JWT_SECRET = 'e'.repeat(64)

let pass = 0, fail = 0, skipped = false
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  ok   ' + name) }
  else { fail++; console.log('  FAIL ' + name, extra !== undefined ? JSON.stringify(extra) : '') }
}
function section(t) { console.log('\n== ' + t + ' ==') }

function haveCaddyWithCoraza() {
  try {
    const mods = execFileSync('caddy', ['list-modules'], { timeout: 8000 }).toString()
    return mods.includes('http.handlers.waf')
  } catch { return false }
}

function get(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, { headers }, res => {
      let body = ''
      res.on('data', c => { body += c })
      res.on('end', () => resolve({ status: res.statusCode, body }))
    })
    req.on('error', reject)
    req.setTimeout(8000, () => { req.destroy(new Error('timeout')) })
  })
}

async function waitFor(fn, attempts = 40, delayMs = 250) {
  for (let i = 0; i < attempts; i++) {
    try { if (await fn()) return true } catch {}
    await new Promise(r => setTimeout(r, delayMs))
  }
  return false
}

let appProc = null
let caddyProc = null

function cleanup() {
  try { if (appProc) appProc.kill('SIGKILL') } catch {}
  try { if (caddyProc) caddyProc.kill('SIGKILL') } catch {}
  try { fs.rmSync(WORK, { recursive: true, force: true }) } catch {}
}
process.on('exit', cleanup)
process.on('SIGINT', () => { cleanup(); process.exit(130) })

;(async () => {
  section('prerequisites')
  if (!haveCaddyWithCoraza()) {
    console.log('  SKIP  caddy with the Coraza module (http.handlers.waf) is not on PATH.')
    console.log('        This test proves real WAF blocking and cannot be faked without it.')
    console.log('        Install it: npm install   (or see docs/installation.md)')
    skipped = true
    console.log('\n0 passed, 0 failed, SKIPPED (no caddy+coraza)')
    process.exit(0)
  }
  check('caddy binary with Coraza module present', true)

  appProc = spawn(process.execPath, [path.join(ROOT, 'test', 'testapp', 'server.js')], {
    env: { ...process.env, TEST_APP_PORT: String(APP_PORT), TEST_APP_HOST: '127.0.0.1' },
    stdio: 'ignore',
  })
  const appUp = await waitFor(async () => (await get(`http://127.0.0.1:${APP_PORT}/healthz`)).status === 200)
  check('local-only test app is listening', appUp)
  if (!appUp) { console.log('\n' + pass + ' passed, ' + (fail + 1) + ' failed'); process.exit(1) }

  fs.writeFileSync(CADDYFILE, [
    '{',
    `    admin 127.0.0.1:${ADMIN_PORT}`,
    '    order coraza_waf first',
    '}',
    '',
    `:${WAF_PORT} {`,
    `    reverse_proxy 127.0.0.1:${APP_PORT}`,
    '}',
    '',
  ].join('\n'))

  const state = require(path.join(ROOT, 'backend/services/state'))
  state.WAF.engine = 'On'
  state.WAF.paranoia_level = 1
  state.WAF.audit_log = true
  state.WAF.geo_blocking = []
  state.WAF.ip_blacklist = []

  // This test stands up Caddy on its own, with no CatWAF API behind it —
  // which is exactly what a default install must tolerate. Any enabled
  // runtime-enforcement feature renders a `forward_auth` hop back into that
  // API, and Caddy reads a failed dial as a denial, so every request below
  // would 502 before Coraza's verdict could be observed.
  //
  // Nothing is switched off here on purpose: this asserts the shipped default
  // rather than arranging for it. If a runtime feature is ever defaulted back
  // on, this test fails, and it should — see the comment on tools_fingerprint
  // in backend/services/settings/schema.js and docs/protection.md.
  const enforce = require(path.join(ROOT, 'backend/services/enforce'))
  check('a default install renders no hop back into the CatWAF API',
    enforce.isActive() === false, enforce.activeFeatures())

  const caddySvc = require(path.join(ROOT, 'backend/services/caddy'))
  caddySvc.patchWAFCaddyfile(state.WAF)

  const generated = fs.readFileSync(CADDYFILE, 'utf8')
  check('WAF block written into the Caddyfile', generated.includes('coraza_waf {'))
  check('OWASP CRS is loaded by the generated config', generated.includes('load_owasp_crs'))
  check('SecRuleEngine reflects engine mode', generated.includes('SecRuleEngine On'))
  check('audit log path points at our test log', generated.includes(AUDIT_LOG))

  caddyProc = spawn('caddy', ['run', '--config', CADDYFILE], { stdio: 'ignore' })
  const wafUp = await waitFor(async () => {
    const r = await get(`http://127.0.0.1:${WAF_PORT}/`)
    return r.status === 200
  })
  check('caddy is serving with Coraza in the chain', wafUp)
  if (!wafUp) { console.log('\n' + pass + ' passed, ' + (fail + 1) + ' failed'); process.exit(1) }

  section('allowed traffic reaches the application')
  const normal = await get(`http://127.0.0.1:${WAF_PORT}/`)
  check('normal request returns 200', normal.status === 200, normal.status)
  check('response really came from the test app', normal.body.includes('CATWAF SECURITY TEST ENVIRONMENT'))

  section('malicious traffic is blocked by Coraza')
  const secret = 'audit-privacy-test-secret-1234567890'
  const sqli = await get(`http://127.0.0.1:${WAF_PORT}/?id=1+UNION+SELECT+1,2,3--`, { Authorization: 'Bearer ' + secret, Cookie: 'session=' + secret })
  check('SQL injection pattern is blocked with 403', sqli.status === 403, sqli.status)
  check('blocked response did NOT reach the app', !sqli.body.includes('CATWAF SECURITY TEST ENVIRONMENT'))

  const xss = await get(`http://127.0.0.1:${WAF_PORT}/?q=%3Cscript%3Ealert(1)%3C/script%3E`)
  check('XSS pattern is blocked with 403', xss.status === 403, xss.status)

  const scanner = await get(`http://127.0.0.1:${WAF_PORT}/`, { 'User-Agent': 'sqlmap/1.0' })
  check('known scanner user-agent is blocked with 403', scanner.status === 403, scanner.status)

  section('events flow into CatWAF audit ingestion')
  const auditWritten = await waitFor(() => fs.existsSync(AUDIT_LOG) && fs.statSync(AUDIT_LOG).size > 0, 40, 250)
  check('Coraza wrote a JSON audit log', auditWritten)

  const requestLog = require(path.join(ROOT, 'backend/services/requestLog'))
  requestLog._resetOffsetForTests()
  const ingest = requestLog.ingestNewEntries()
  check('CatWAF ingested audit entries', ingest.ingested >= 3, ingest)

  const rows = requestLog.getRecent(50)
  const blocked = rows.filter(r => r.action === 'block')
  check('ingested rows are recorded as blocked, not passed', blocked.length >= 3, { total: rows.length, blocked: blocked.length })

  const sqliRow = rows.find(r => (r.uri || '').includes('UNION'))
  check('SQLi event was captured', !!sqliRow)
  if (sqliRow) {
    check('SQLi row action is block', sqliRow.action === 'block', sqliRow.action)
    check('SQLi row status is 403', sqliRow.status === 403, sqliRow.status)
    check('SQLi row classified as SQLi', sqliRow.attack_type === 'SQLi', sqliRow.attack_type)
    check('SQLi row carries rule IDs', Array.isArray(sqliRow.rule_ids) && sqliRow.rule_ids.length > 0, sqliRow.rule_ids)
    check('SQLi row records severity', !!sqliRow.severity, sqliRow.severity)
    check('SQLi row records a human-readable reason', !!sqliRow.reason, sqliRow.reason)
    check('SQLi row timestamp is ISO-8601', !Number.isNaN(Date.parse(sqliRow.ts)) && /\dT\d/.test(sqliRow.ts), sqliRow.ts)
    check('SQLi row records method', sqliRow.method === 'GET', sqliRow.method)
    check('SQLi row records client ip', !!sqliRow.ip, sqliRow.ip)
  }

  const scannerRow = rows.find(r => r.attack_type === 'Scanner Detection')
  check('scanner event classified without retaining request headers', !!scannerRow)
  check('raw user-agent headers are omitted from ingested audit rows', rows.every(r => !r.user_agent))

  section('time-window aggregation sees the events')
  const counts = requestLog.getCounts(24 * 60 * 60 * 1000)
  check('24h counts include the blocked requests', counts.blocked >= 3, counts)
  const types = requestLog.getAttackTypeCounts(24 * 60 * 60 * 1000)
  check('attack-type breakdown is populated', Object.keys(types).length >= 2, types)

  section('no secrets are persisted from request headers')
  const cols = Object.keys(rows[0] || {})
  const forbidden = ['authorization', 'cookie', 'cookies', 'token', 'password', 'headers', 'body']
  const leaked = cols.filter(c => forbidden.includes(c.toLowerCase()))
  check('request_log stores no header/body/secret columns', leaked.length === 0, leaked)
  const serialized = JSON.stringify(rows)
  check('no Authorization value present in stored rows', !/Bearer\s+[A-Za-z0-9._-]{10,}/.test(serialized))
  check('request secrets absent from both raw audit log and database', !serialized.includes(secret) && !fs.readFileSync(AUDIT_LOG, 'utf8').includes(secret))

  section('reload works without Docker')
  const reload = caddySvc.reloadCaddy()
  check('reloadCaddy() succeeded', reload.reloaded === true, reload)
  check('reload used a non-Docker mechanism', ['caddy-binary', 'admin-api'].includes(reload.method), reload.method)
  const caddySource = fs.readFileSync(path.join(ROOT, 'backend/services/caddy.js'), 'utf8')
  check('caddy.js contains no docker invocations', !/\bdocker\b/.test(caddySource))

  console.log(`\n${pass} passed, ${fail} failed`)
  cleanup()
  process.exit(fail ? 1 : 0)
})().catch(e => {
  console.error('\nE2E harness error:', e.message)
  cleanup()
  process.exit(1)
})
