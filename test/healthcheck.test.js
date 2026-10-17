const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs'), os = require('node:os'), path = require('node:path')
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-health-'))
Object.assign(process.env, {
  DB_DIR: dir, DB_PATH: path.join(dir, 'health.db'), CATWAF_EDITION: 'lite',
  CADDYFILE_PATH: path.join(dir, 'Caddyfile'), CORAZA_AUDIT_LOG: path.join(dir, 'audit.json'),
  CADDY_ADMIN_SOCKET: path.join(dir, 'admin.sock'), CADDY_ADMIN_URL: 'http://127.0.0.1:1',
  JWT_SECRET: 'health-fixture-only-'.repeat(4),
})
const caddy = require('../backend/services/caddy'), state = require('../backend/services/state')
const db = require('../backend/services/db'), tx = require('../backend/services/configTx')
const health = require('../backend/services/healthcheck')
const config = '{\n order coraza_waf first\n}\n:19991 {\n coraza_waf {\n load_owasp_crs\n }\n}\n'
fs.writeFileSync(process.env.CADDYFILE_PATH, config)
fs.writeFileSync(process.env.CORAZA_AUDIT_LOG, '')
process.on('exit', () => { try { fs.rmSync(dir, { recursive: true, force: true }) } catch {} })

test('health distinguishes install mode, admin HTTP response and incomplete recovery', async t => {
  t.mock.method(caddy, 'isCaddyRunning', () => true)
  t.mock.method(caddy, 'getCaddyModules', () => 'http.handlers.waf\n')
  t.mock.method(tx, 'validateCaddyfile', () => ({ ok: true }))
  let reachable = true
  const probe = t.mock.method(caddy, 'isAdminReachable', () => reachable)
  state.WAF.engine = 'On'
  const get = async name => (await health.collect()).find(c => c.name === name)

  await t.test('Lite does not require an API or dashboard', async () => {
    const checks = await health.collect()
    assert(!checks.some(c => c.name === 'CatWAF API' || c.name === 'Dashboard'))
    assert.equal(checks.find(c => c.name === 'Caddy admin API').status, 'healthy')
    assert.match(checks.find(c => c.name === 'Caddy admin API').detail, /admin\.sock/)
    assert(probe.mock.callCount() > 0)
  })
  await t.test('unreachable admin socket is unhealthy even if a Caddy process exists', async () => {
    reachable = false
    assert.equal((await get('Caddy admin API')).status, 'unhealthy')
    reachable = true
  })
  await t.test('a real unmanaged Coraza block is described correctly', async () => {
    const result = await get('WAF interception')
    assert.equal(result.status, 'healthy')
    assert.match(result.detail, /live blocking requires a request probe/)
  })
  await t.test('Off and DetectionOnly are not reported as blocking protection', async () => {
    for (const mode of ['Off', 'DetectionOnly']) {
      state.WAF.engine = mode
      assert.equal((await get('WAF interception')).status, 'unhealthy')
    }
    state.WAF.engine = 'On'
  })
  await t.test('a missing handler or missing ordering is unhealthy', async () => {
    for (const broken of [config.replace('coraza_waf {', 'respond {'), config.replace('order coraza_waf first', '')]) {
      fs.writeFileSync(process.env.CADDYFILE_PATH, broken)
      assert.equal((await get('WAF interception')).status, 'unhealthy')
    }
    fs.writeFileSync(process.env.CADDYFILE_PATH, config)
  })
  await t.test('pending restore and transaction recovery are unhealthy without mutating them', async () => {
    db.setState('database_restore_pending', { pending: true })
    assert.equal((await get('Configuration recovery')).status, 'unhealthy')
    assert.deepEqual(db.getState('database_restore_pending'), { pending: true })
    db.setState('database_restore_pending', null)
    fs.writeFileSync(tx.journalPath(), '{}')
    assert.equal((await get('Configuration recovery')).status, 'unhealthy')
    assert(fs.existsSync(tx.journalPath()))
    fs.unlinkSync(tx.journalPath())
    assert.equal((await get('Configuration recovery')).status, 'healthy')
  })
})
