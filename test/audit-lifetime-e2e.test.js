// A reload acknowledgement does not imply that older requests have finished.
// Keep this strict regression until audit retirement tracks writer lifetime.
const test = require('node:test'), assert = require('node:assert/strict')
const fs = require('node:fs'), path = require('node:path'), os = require('node:os'), http = require('node:http'), net = require('node:net')
const { spawn, execFile } = require('node:child_process'), { promisify } = require('node:util'), { once } = require('node:events')
const exec = promisify(execFile), sleep = ms => new Promise(resolve => setTimeout(resolve, ms))
const listen = async server => { server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port }

test('a request finishing after multiple rotations retains its audit record', { timeout: 30000 }, async t => {
  assert.match((await exec('caddy', ['list-modules'])).stdout, /http\.handlers\.waf/)
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-audit-lifetime-'))
  let proc, origin, request
  const timers = new Set()
  t.after(async () => {
    for (const timer of timers) clearTimeout(timer)
    if (origin) origin.closeAllConnections()
    if (request) await Promise.allSettled([request])
    if (proc && proc.exitCode === null && proc.signalCode === null) { const stopped = once(proc, 'exit'); proc.kill('SIGTERM'); await stopped }
    if (origin) await new Promise(resolve => origin.close(resolve))
    fs.rmSync(dir, { recursive: true, force: true })
  })
  const file = path.join(dir, 'Caddyfile'), auditPath = path.join(dir, 'audit.json'), socket = path.join(dir, 'admin.sock')
  Object.assign(process.env, { DB_DIR: dir, DB_PATH: path.join(dir, 'fixture.db'), CADDYFILE_PATH: file, CORAZA_AUDIT_LOG: auditPath, CADDY_ADMIN_SOCKET: socket, CADDY_ADMIN_URL: 'http://127.0.0.1:1', CATWAF_EDITION: 'lite', JWT_SECRET: 'local-audit-lifetime-fixture-'.repeat(4), XDG_DATA_HOME: dir, XDG_CONFIG_HOME: dir })
  let entered
  const active = new Promise(resolve => { entered = resolve })
  origin = http.createServer((req, res) => {
    res.statusCode = 500; res.setHeader('Content-Type', 'text/plain')
    if (req.url === '/audit-control') { res.end('control'); return }
    res.write('start\n'); entered()
    timers.add(setTimeout(() => res.end('finish\n'), 7000))
  })
  const originPort = await listen(origin), reservation = http.createServer(), port = await listen(reservation)
  await new Promise(resolve => reservation.close(resolve))
  const caddy = require('../backend/services/caddy'), state = require('../backend/services/state')
  const audit = require('../backend/services/auditLog'), logs = require('../backend/services/requestLog'), db = require('../backend/services/db')
  Object.assign(state.WAF, { engine: 'On', audit_log: true, paranoia_level: 1 })
  fs.writeFileSync(file, `{\n admin unix/${socket}|0600\n auto_https off\n order coraza_waf first\n}\nhttp://127.0.0.1:${port} {\n bind 127.0.0.1\n${caddy.buildWAFBlock(state.WAF)}\n reverse_proxy 127.0.0.1:${originPort}\n}\n`)
  const fd = fs.openSync(path.join(dir, 'caddy.log'), 'w')
  proc = spawn('caddy', ['run', '--config', file], { stdio: ['ignore', fd, fd] }); fs.closeSync(fd)
  let ready = false
  for (let n = 0; n < 80 && !ready; n++) {
    ready = await new Promise(resolve => { const s = net.connect(port, '127.0.0.1'); s.once('connect', () => { s.destroy(); resolve(true) }); s.once('error', () => resolve(false)) })
    if (!ready) await sleep(100)
  }
  assert(ready, 'real proxy must start')
  const control = await fetch(`http://127.0.0.1:${port}/audit-control`, { signal: AbortSignal.timeout(5000) })
  assert.equal(control.status, 500); await control.text(); await sleep(100)
  logs.ingestNewEntries()
  assert.equal(db.getDb().prepare('SELECT COUNT(*) AS n FROM request_log WHERE uri=?').get('/audit-control').n, 1, 'positive control: normal 500 responses must be audited')
  request = new Promise((resolve, reject) => {
    http.get(`http://127.0.0.1:${port}/late-audit-probe`, { agent: false, signal: AbortSignal.timeout(15000) }, res => {
      res.resume(); res.on('end', () => resolve(res.statusCode)); res.on('error', reject)
    }).on('error', reject)
  })
  request.catch(() => {})
  await Promise.race([active, request.then(() => { throw new Error('request finished before entering origin') })])
  const rotations = []
  for (let n = 0; n < 3; n++) {
    const result = audit.maintain({ force: true, env: { CATWAF_AUDIT_MAX_FILES: '1' } })
    assert.equal(result.ok, true, JSON.stringify(result)); rotations.push(result.pruned)
    await sleep(1100)
  }
  assert.equal(await request, 500)
  await sleep(200)
  logs.ingestNewEntries()
  const rows = db.getDb().prepare('SELECT id FROM request_log WHERE uri=?').all('/late-audit-probe')
  t.diagnostic(JSON.stringify({ rotations, originalLogExists: fs.existsSync(auditPath), matchingAuditRows: rows.length }))
  assert.equal(rows.length, 1, 'the completed request must remain auditable after rotation')
})
