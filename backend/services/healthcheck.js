const fs = require('fs')
const net = require('net')
const path = require('path')

const state = require('./state')
const db = require('./db')
const caddySvc = require('./caddy')
const rulesSvc = require('./rules')
const requestLog = require('./requestLog')
const configTx = require('./configTx')
const edition = require('./edition')

const HEALTHY = 'healthy'
const DEGRADED = 'degraded'
const UNHEALTHY = 'unhealthy'

const RANK = { [HEALTHY]: 0, [DEGRADED]: 1, [UNHEALTHY]: 2 }

function worst(statuses) {
  return statuses.reduce((acc, s) => (RANK[s] > RANK[acc] ? s : acc), HEALTHY)
}

function checkPort(port, host = '127.0.0.1', timeout = 700) {
  return new Promise(resolve => {
    const sock = new net.Socket()
    let done = false
    const finish = v => { if (!done) { done = true; try { sock.destroy() } catch {} ; resolve(v) } }
    sock.setTimeout(timeout)
    sock.once('connect', () => finish(true))
    sock.once('timeout', () => finish(false))
    sock.once('error', () => finish(false))
    sock.connect(port, host)
  })
}

async function collect() {
  const checks = []
  const add = (name, status, detail, hint) => checks.push({ name, status, detail: detail || null, hint: hint || null })

  const lite = edition.isLite()
  const apiPort = Number(process.env.PORT || 8000)
  const apiHost = process.env.HOST || '127.0.0.1'
  if (!lite) {
    const apiUp = await checkPort(apiPort, apiHost === '0.0.0.0' ? '127.0.0.1' : apiHost)
    add('CatWAF API', apiUp ? HEALTHY : DEGRADED,
      apiUp ? `listening on ${apiHost}:${apiPort}` : `nothing listening on ${apiHost}:${apiPort}`,
      apiUp ? null : 'Start CatWAF with `catwaf start`. Core WAF filtering is independent; enabled runtime enforcement and upload scanning require the API.')
  }

  const caddyRunning = caddySvc.isCaddyRunning()
  add('Caddy', caddyRunning ? HEALTHY : UNHEALTHY,
    caddyRunning ? 'running' : 'not running',
    caddyRunning ? null : 'Nothing is being filtered while Caddy is down. Start it with `catwaf start` or `caddy run --config <Caddyfile>`.')

  const modules = caddySvc.getCaddyModules()
  const corazaPresent = modules.includes('http.handlers.waf')
  add('Coraza module', corazaPresent ? HEALTHY : UNHEALTHY,
    corazaPresent ? 'http.handlers.waf available' : 'not present in this Caddy build',
    corazaPresent ? null : 'Rebuild Caddy: xcaddy build --with github.com/corazawaf/coraza-caddy/v2')

  const ruleStats = rulesSvc.stats()
  add('OWASP CRS', ruleStats.indexAvailable ? HEALTHY : DEGRADED,
    ruleStats.indexAvailable
      ? `${ruleStats.indexed} rules indexed${ruleStats.sources[0] ? ` from ${path.basename(ruleStats.sources[0].dir)}` : ''}`
      : 'no local CRS rule files found',
    ruleStats.indexAvailable ? null : 'Rule descriptions will be unavailable. CRS still runs inside Caddy — only CatWAF\'s local metadata index is missing. Set CATWAF_CRS_PATH to a CRS rules directory to enable it.')

  const cfPath = caddySvc.CADDYFILE_PATH
  const cfExists = fs.existsSync(cfPath)
  if (!cfExists) {
    add('Caddyfile', UNHEALTHY, `missing at ${cfPath}`, 'Run `catwaf setup` to generate one.')
  } else {
    let writable = false
    try { fs.accessSync(cfPath, fs.constants.W_OK); writable = true } catch {}
    const v = configTx.validateCaddyfile(cfPath)
    if (!v.ok) add('Configuration validity', UNHEALTHY, v.error, 'Caddy will refuse this config. Fix it before restarting.')
    else if (v.skipped) add('Configuration validity', DEGRADED, v.skipped, 'Install Caddy to allow CatWAF to validate configuration.')
    else add('Configuration validity', HEALTHY, 'Caddyfile validates')

    add('Caddyfile writable', writable ? HEALTHY : UNHEALTHY,
      writable ? cfPath : `${cfPath} is not writable by this user`,
      writable ? null : 'WAF changes will fail. Run as a user that can write it, or set CADDYFILE_PATH.')

    const body = fs.readFileSync(cfPath, 'utf8')
    const hasCoraza = /(^|\n)\s*coraza_waf\s*\{/.test(body)
    const hasOrder = /order\s+coraza_waf\s+first/.test(body)
    const blocking = hasCoraza && hasOrder && state.WAF.engine === 'On'
    add('WAF interception', blocking ? HEALTHY : UNHEALTHY,
      !hasCoraza ? 'no Coraza handler in the Caddyfile'
        : !hasOrder ? 'missing `order coraza_waf first` — requests can bypass Coraza'
        : state.WAF.engine !== 'On' ? `engine is ${state.WAF.engine} — attacks are not blocked`
        : `configured engine On at paranoia level ${state.WAF.paranoia_level}; live blocking requires a request probe`,
      blocking ? null : 'Apply WAF engine On to regenerate the block, and confirm `order coraza_waf first` is in the global options.')
  }

  let dbOk = false, dbDetail = null
  try {
    db.getDb().prepare('SELECT 1').get()
    dbOk = true
    dbDetail = db.DB_PATH
  } catch (e) { dbDetail = e.message }
  add('Database', dbOk ? HEALTHY : UNHEALTHY, dbDetail,
    dbOk ? null : 'Check DB_DIR/DB_PATH permissions.')

  if (dbOk) {
    try {
      configTx.assertReady()
      if (fs.existsSync(configTx.journalPath())) throw new Error('A configuration transaction journal still needs recovery.')
      add('Configuration recovery', HEALTHY, 'no pending database restore or configuration transaction')
    } catch (e) {
      add('Configuration recovery', UNHEALTHY, e.message, 'Complete recovery before starting services or applying further changes; see docs/security-recovery.md.')
    }
    try {
      const cols = db.getDb().prepare('PRAGMA table_info(request_log)').all().map(c => c.name)
      const missing = ['ts', 'action', 'attack_type', 'rule_ids', 'severity', 'reason'].filter(c => !cols.includes(c))
      add('Event schema', missing.length ? UNHEALTHY : HEALTHY,
        missing.length ? `missing columns: ${missing.join(', ')}` : 'request_log schema current',
        missing.length ? 'Restart CatWAF once — migrations run at startup.' : null)
    } catch (e) {
      add('Event schema', DEGRADED, e.message)
    }
  }

  const auditPath = caddySvc.AUDIT_LOG_PATH
  const auditDir = path.dirname(auditPath)
  const auditDirExists = fs.existsSync(auditDir)
  if (!auditDirExists) {
    add('Audit log', UNHEALTHY, `directory missing: ${auditDir}`,
      `Caddy refuses to start the WAF handler without it. Create it: sudo mkdir -p ${auditDir}`)
  } else if (!fs.existsSync(auditPath)) {
    add('Audit log', state.WAF.audit_log ? DEGRADED : HEALTHY,
      state.WAF.audit_log ? 'no audit log written yet' : 'audit logging is disabled by configuration',
      state.WAF.audit_log ? 'Normal on a fresh install; it appears after the first relevant request.' : null)
  } else {
    const st = fs.statSync(auditPath)
    const ageMin = (Date.now() - st.mtimeMs) / 60000
    add('Audit log', HEALTHY, `${st.size} bytes, last written ${ageMin < 1 ? 'just now' : Math.round(ageMin) + ' min ago'}`)
  }

  if (dbOk) {
    try {
      const counts = requestLog.getCounts(24 * 3600000)
      const any = requestLog.hasAnyData()
      add('Event ingestion', HEALTHY,
        any ? `${counts.total} events in the last 24h (${counts.blocked} blocked)` : 'no events recorded yet',
        any ? null : 'Expected on a new install until traffic flows through Caddy.')
    } catch (e) {
      add('Event ingestion', DEGRADED, e.message)
    }
  }

  const distIndex = path.join(__dirname, '..', '..', 'frontend', 'dist', 'index.html')
  const built = fs.existsSync(distIndex)
  if (!lite) {
    add('Dashboard', built ? HEALTHY : DEGRADED,
      built ? 'build present' : 'not built',
      built ? null : 'Run `npm run build`.')
  }

  // Exercise the same HTTP endpoint and Unix socket used by config reloads.
  // An open TCP port is not proof of a working Caddy admin API, and probing
  // localhost:2019 in Docker misdiagnoses the permissioned socket deployment.
  const adminReachable = caddySvc.isAdminReachable()
  const adminEndpoint = caddySvc.CADDY_ADMIN_SOCKET || caddySvc.CADDY_ADMIN_URL
  add('Caddy admin API', adminReachable ? HEALTHY : UNHEALTHY,
    adminReachable ? `responding at ${adminEndpoint}` : `not responding at ${adminEndpoint}`,
    adminReachable ? null : 'Reload and recovery require this endpoint. Check Caddy and the configured socket permissions or admin address.')

  return checks
}

async function run() {
  const checks = await collect()
  const status = worst(checks.map(c => c.status))
  const counts = {
    healthy: checks.filter(c => c.status === HEALTHY).length,
    degraded: checks.filter(c => c.status === DEGRADED).length,
    unhealthy: checks.filter(c => c.status === UNHEALTHY).length,
  }
  return {
    status,
    counts,
    checks,
    checked_at: new Date().toISOString(),
    exit_code: status === HEALTHY ? 0 : status === DEGRADED ? 1 : 2,
  }
}

module.exports = { run, collect, HEALTHY, DEGRADED, UNHEALTHY, worst }
