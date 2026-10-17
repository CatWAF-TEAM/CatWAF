// Real Caddy + Coraza, loopback origins, private admin socket and temporary
// storage only. Missing Caddy is a failure: this is a required release gate.
const test = require('node:test'), assert = require('node:assert/strict')
const fs = require('node:fs'), os = require('node:os'), path = require('node:path')
const http = require('node:http'), { once } = require('node:events')
const { spawn, execFile } = require('node:child_process'), { promisify } = require('node:util')
const exec = promisify(execFile)
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))
const listen = async server => { server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port }
async function request(url, options = {}) {
  // Use fresh connections: reloads legitimately close idle keep-alive
  // sockets. This test measures requests accepted during reload, separately
  // from client-specific retries of a stale pooled connection.
  return new Promise((resolve, reject) => {
    const req = http.request(url, { agent: false, signal: AbortSignal.timeout(9000), ...options }, res => {
      let body = ''
      res.on('data', b => { body += b }); res.on('error', reject)
      res.on('end', () => resolve({ status: res.statusCode, body }))
    })
    req.on('error', error => { error.message += ` (${url})`; reject(error) }); req.end(options.body)
  })
}
async function waitFor(check) {
  for (let i = 0; i < 80; i++) { try { if (await check()) return } catch {} await sleep(100) }
  throw new Error('Fixture did not become ready')
}

test('WAF availability through reloads and dependency failures', { timeout: 90000 }, async t => {
  assert.match((await exec('caddy', ['list-modules'])).stdout, /http\.handlers\.waf/)
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-reliability-'))
  let caddyProc
  const servers = []
  t.after(async () => {
    if (caddyProc && caddyProc.exitCode === null && caddyProc.signalCode === null) {
      const stopped = once(caddyProc, 'exit'); caddyProc.kill('SIGTERM'); await stopped
    }
    for (const server of servers) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)) }
    if (process.env.CATWAF_RELIABILITY_LOG_DIR) {
      fs.mkdirSync(process.env.CATWAF_RELIABILITY_LOG_DIR, { recursive: true })
      for (const file of ['caddy.log', 'Caddyfile', 'gated.Caddyfile', 'audit.json']) {
        if (fs.existsSync(path.join(dir, file))) fs.copyFileSync(path.join(dir, file), path.join(process.env.CATWAF_RELIABILITY_LOG_DIR, 'native-' + file))
      }
    }
    try { fs.rmSync(dir, { recursive: true, force: true }) } catch {}
  })
  let originHits = 0, writes = 0
  const origin = http.createServer((req, res) => {
    originHits++
    if (req.method === 'POST') writes++
    req.resume()
    req.on('end', () => {
      const respond = () => { res.setHeader('Content-Type', 'text/plain'); res.end(req.method === 'POST' ? `written:${writes}` : 'reliability-origin') }
      req.url === '/slow' ? setTimeout(respond, 500) : respond()
    })
  })
  servers.push(origin)
  const originPort = await listen(origin)
  let authMode = 'allow'
  const auth = http.createServer((req, res) => {
    req.resume()
    if (authMode === 'stall') return
    res.statusCode = authMode === 'deny' ? 403 : 200
    res.end()
  })
  servers.push(auth)
  const authPort = await listen(auth)
  const reservation = http.createServer()
  const wafPort = await listen(reservation)
  await new Promise(resolve => reservation.close(resolve))
  const socket = path.join(dir, 'admin.sock')
  Object.assign(process.env, {
    DB_DIR: dir, DB_PATH: path.join(dir, 'fixture.db'), CADDYFILE_PATH: path.join(dir, 'Caddyfile'),
    CORAZA_AUDIT_LOG: path.join(dir, 'audit.json'), JWT_SECRET: 'reliability-only-'.repeat(4),
    CADDY_ADMIN_SOCKET: socket, CADDY_ADMIN_URL: 'http://127.0.0.1:2019',
    CATWAF_INTERNAL_HOST: '127.0.0.1', PORT: String(authPort), CATWAF_EDITION: 'lite',
    XDG_DATA_HOME: path.join(dir, 'data'), XDG_CONFIG_HOME: path.join(dir, 'config'),
  })
  const caddy = require('../backend/services/caddy'), state = require('../backend/services/state')
  const settings = require('../backend/services/settings')
  Object.assign(state.WAF, { engine: 'On', paranoia_level: 1, audit_log: true, geo_blocking: [], ip_blacklist: [] })
  const base = `{\n admin unix/${socket}|0600\n order coraza_waf first\n auto_https off\n}\nhttp://127.0.0.1:${wafPort} {\n bind 127.0.0.1\n reverse_proxy 127.0.0.1:${originPort}\n}\n`
  fs.writeFileSync(process.env.CADDYFILE_PATH, base)
  caddy.patchWAFCaddyfile(state.WAF)
  const baseline = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8')
  assert(!baseline.includes('forward_auth'), 'default Free has no API dependency')
  const fd = fs.openSync(path.join(dir, 'caddy.log'), 'a')
  caddyProc = spawn('caddy', ['run', '--config', process.env.CADDYFILE_PATH], { stdio: ['ignore', fd, fd] })
  fs.closeSync(fd)
  const url = `http://127.0.0.1:${wafPort}`
  await waitFor(async () => (await request(url)).body === 'reliability-origin')
  const reload = async text => {
    fs.writeFileSync(process.env.CADDYFILE_PATH, text)
    await exec('caddy', ['reload', '--config', process.env.CADDYFILE_PATH, '--address', `unix/${socket}`], { timeout: 15000 })
  }
  const attack = '/?id=1%20UNION%20SELECT%201,2,3--'
  const checkPair = async () => {
    assert.deepEqual(await request(url), { status: 200, body: 'reliability-origin' })
    assert.equal((await request(url + attack)).status, 403)
  }
  await t.test('the real permissioned Unix admin endpoint answers', () => assert(caddy.isAdminReachable()))
  await t.test('reload falls back to the Unix HTTP API when the CLI is unavailable', () => {
    const previousPath = process.env.PATH
    process.env.PATH = path.join(dir, 'no-executables')
    try {
      const result = caddy.reloadCaddy()
      assert.equal(result.reloaded, true, result.error)
      assert.equal(result.method, 'admin-api')
    } finally { process.env.PATH = previousPath }
  })
  await t.test('configured JSON content is allowed and MIME substrings are rejected', async () => {
    const before = writes
    assert.equal((await request(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"message":"hello"}' })).status, 200)
    assert.equal(writes, before + 1)
    for (const type of ['application/jso', 'application/jsonx', 'text/plain']) {
      assert.equal((await request(url, { method: 'POST', headers: { 'Content-Type': type }, body: '{"message":"hello"}' })).status, 403)
    }
    assert.equal(writes, before + 1)
  })
  await t.test('concurrent valid and invalid reloads never bypass or drop sampled requests', async () => {
    let running = true, samples = 0
    const failures = [], durations = []
    const workers = Array.from({ length: 4 }, async () => {
      while (running) {
        const start = performance.now()
        try { await checkPair(); samples += 2 } catch (error) { failures.push(error.message) }
        durations.push(performance.now() - start)
        await sleep(5)
      }
    })
    try {
      for (let revision = 1; revision <= 20; revision++) {
        await reload(baseline.replace('reverse_proxy ', `header X-Reliability-Revision ${revision}\n reverse_proxy `))
        await assert.rejects(reload(baseline.replace('reverse_proxy ', 'unrecognized_invalid_directive\n reverse_proxy ')))
      }
      const inFlight = request(url + '/slow')
      await sleep(100)
      await reload(baseline)
      assert.equal((await inFlight).body, 'reliability-origin', 'in-flight request survives reload')
    } finally { running = false; await Promise.all(workers) }
    durations.sort((a, b) => a - b)
    t.diagnostic(JSON.stringify({ sampledRequests: samples, concurrency: 4, validReloads: 21, rejectedReloads: 20, failedPairs: failures.length, pairLatencyP95Ms: Math.round(durations[Math.floor(durations.length * 0.95)]) }))
    assert(samples >= 40, `need traffic during reloads; observed ${samples}`)
    assert.deepEqual(failures, [])
  })
  await t.test('an origin outage cannot bypass Coraza, and origin restart recovers', async () => {
    origin.closeAllConnections(); await new Promise(resolve => origin.close(resolve))
    assert.equal((await request(url)).status, 502)
    assert.equal((await request(url + attack)).status, 403)
    origin.listen(originPort, '127.0.0.1'); await once(origin, 'listening')
    await checkPair()
  })
  await t.test('opt-in enforcement denies are not retried or bypassed', async () => {
    settings.set('tools_fingerprint', { enabled: true })
    const gated = caddy.renderCaddyfile(base, state.WAF)
    assert(gated.includes('forward_auth'))
    fs.writeFileSync(path.join(dir, 'gated.Caddyfile'), gated)
    await reload(gated)
    authMode = 'deny'
    const before = originHits
    assert.equal((await request(url)).status, 403)
    assert.equal(originHits, before)
    authMode = 'allow'
    const beforeWrites = writes
    assert.deepEqual(await request(url, { method: 'POST', body: 'message=hello', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }), { status: 200, body: `written:${beforeWrites + 1}` })
    assert.equal(writes, beforeWrites + 1, 'a state-changing request must be sent once')
  })
  await t.test('a wedged enforcement API fails within the transport deadline', async () => {
    authMode = 'stall'
    const before = originHits, started = performance.now()
    assert.equal((await request(url)).status, 504)
    const elapsed = performance.now() - started
    assert(elapsed >= 4500 && elapsed < 8000, `bounded enforcement failure took ${elapsed}ms`)
    assert.equal(originHits, before)
    authMode = 'allow'
    await checkPair()
    t.diagnostic(`stalled enforcement response: ${Math.round(elapsed)}ms`)
  })
  await t.test('stopping the API fails closed only while enforcement is enabled', async () => {
    auth.closeAllConnections(); await new Promise(resolve => auth.close(resolve))
    const before = originHits
    assert.equal((await request(url)).status, 502)
    assert.equal(originHits, before)
    settings.set('tools_fingerprint', { enabled: false })
    await reload(baseline)
    for (let i = 0; i < 20; i++) await checkPair()
  })
  await t.test('Caddy restart retains blocking configuration', async () => {
    const stopped = once(caddyProc, 'exit'); caddyProc.kill('SIGTERM'); await stopped
    assert.equal(caddy.isAdminReachable(), false)
    caddyProc = spawn('caddy', ['run', '--config', process.env.CADDYFILE_PATH], { stdio: 'ignore' })
    await waitFor(async () => (await request(url)).status === 200)
    await checkPair()
  })
})
