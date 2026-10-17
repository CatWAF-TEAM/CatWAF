#!/usr/bin/env node
// Strict real-WAF load/soak gate. HTTP/1 has no retries. HTTP/2 only
// reopens an explicitly REFUSED_STREAM (RFC 9113 §8.7, never processed),
// counts every refusal, and asserts a refused POST never reached origin.
// CATWAF_LOAD_SECONDS=86400 selects the full 24-hour soak; defaults to 900s.
const fs = require('node:fs'), path = require('node:path'), os = require('node:os')
const assert = require('node:assert/strict'), http = require('node:http'), https = require('node:https'), h2 = require('node:http2')
const { spawn, execFile } = require('node:child_process'), { promisify } = require('node:util'), { once } = require('node:events')
const exec = promisify(execFile), sleep = ms => new Promise(r => setTimeout(r, ms))
const seconds = Number(process.env.CATWAF_LOAD_SECONDS || 900)
const concurrency = Number(process.env.CATWAF_LOAD_CONCURRENCY || 24)
const pace = Number(process.env.CATWAF_LOAD_PACE_MS || 100)
assert(Number.isInteger(seconds) && seconds >= 60 && seconds <= 86400)
assert(Number.isInteger(concurrency) && concurrency >= 4 && concurrency <= 256)
assert(Number.isFinite(pace) && pace >= 0 && pace <= 1000)
const reportPath = path.resolve(process.env.CATWAF_LOAD_REPORT || 'load-validation.json')
const limits = { errors: 0, bypasses: 0, duplicateWrites: 0, p99Ms: 5000, rssMiB: 768, diskMiB: 1024, descriptors: 2048 }
const histogram = new Array(10001).fill(0)
const report = { startedAt: new Date().toISOString(), requestedSeconds: seconds, concurrency, paceMs: pace, limits, status: 'running', requests: 0, writes: 0, reloads: 0, rotations: 0, h2UnprocessedRefusals: 0, errorCount: 0, errors: [], peakRssMiB: 0, peakDiskMiB: 0, peakDescriptors: 0, protocols: {} }
const crypto = require('node:crypto')
const digest = crypto.createHash('sha256'), repo = path.resolve(__dirname, '..')
function hashSources(relative) {
  for (const entry of fs.readdirSync(path.join(repo, relative), { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    const name = path.join(relative, entry.name)
    if (entry.isDirectory()) hashSources(name)
    else if (entry.name.endsWith('.js')) digest.update(name).update('\0').update(fs.readFileSync(path.join(repo, name)))
  }
}
hashSources('backend'); digest.update(fs.readFileSync(__filename)); digest.update(fs.readFileSync(path.join(repo, 'package-lock.json')))
report.runtimeSourceSha256 = digest.digest('hex')
report.nodeVersion = process.version
// Continue measuring the full interval after a request failure. Every error
// still fails the final zero-error gate; bound retained examples, not counts.
function recordError(error) { report.errorCount++; if (report.errors.length < 1000) report.errors.push(error) }
const persist = () => { fs.mkdirSync(path.dirname(reportPath), { recursive: true }); fs.writeFileSync(reportPath + '.partial', JSON.stringify(report, null, 2)); fs.renameSync(reportPath + '.partial', reportPath) }
const listen = async s => { s.listen(0, '127.0.0.1'); await once(s, 'listening'); return s.address().port }
const reserve = async () => { const s = http.createServer(), port = await listen(s); await new Promise(r => s.close(r)); return port }
const disk = dir => fs.readdirSync(dir, { withFileTypes: true }).reduce((n, e) => n + (e.isDirectory() ? disk(path.join(dir, e.name)) : fs.statSync(path.join(dir, e.name)).size), 0)
async function main() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-load-'))
  let proc, running = true, started, origin, maintenance
  const workers = [], writes = new Set()
  let bypasses = 0, duplicateWrites = 0, next = 0, expectedWrites = 0
  try {
    assert.match((await exec('caddy', ['list-modules'])).stdout, /http\.handlers\.waf/)
    report.proxyVersion = (await exec('caddy', ['version'])).stdout.trim()
    const binary = process.env.PATH.split(path.delimiter).map(dir => path.join(dir, 'caddy')).find(file => { try { fs.accessSync(file, fs.constants.X_OK); return true } catch { return false } })
    report.proxySha256 = crypto.createHash('sha256').update(fs.readFileSync(binary)).digest('hex')
    const port = await reserve(), tlsPort = await reserve(), socket = path.join(dir, 'admin.sock')
    const file = path.join(dir, 'Caddyfile'), cert = path.join(dir, 'cert.pem'), key = path.join(dir, 'key.pem')
    await exec('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert, '-days', '2', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'])
    const ca = fs.readFileSync(cert)
    origin = http.createServer((req, res) => {
      let body = ''
      req.on('data', b => { body += b })
      req.on('end', () => {
        if (decodeURIComponent(req.url).includes('UNION SELECT')) bypasses++
        if (req.method === 'POST') { const id = JSON.parse(body).id; if (writes.has(id)) duplicateWrites++; writes.add(id) }
        res.setHeader('Content-Type', 'text/plain')
        if (req.url === '/stream') {
          let n = 0; const timer = setInterval(() => { res.write('chunk\n'); if (++n === 30) { clearInterval(timer); res.end() } }, 20)
          res.on('close', () => clearInterval(timer))
        } else res.end('load-origin')
      })
    })
    const originPort = await listen(origin)
    Object.assign(process.env, { DB_DIR: dir, DB_PATH: path.join(dir, 'fixture.db'), CADDYFILE_PATH: file, CORAZA_AUDIT_LOG: path.join(dir, 'audit.json'), CADDY_ADMIN_SOCKET: socket, CADDY_ADMIN_URL: 'http://127.0.0.1:1', CATWAF_EDITION: 'lite', JWT_SECRET: 'load-fixture-only-'.repeat(4), XDG_DATA_HOME: path.join(dir, 'data'), XDG_CONFIG_HOME: path.join(dir, 'config'), CATWAF_AUDIT_MAX_SIZE_MB: '4', CATWAF_AUDIT_MAX_FILES: '3' })
    const caddy = require('../backend/services/caddy'), state = require('../backend/services/state'), audit = require('../backend/services/auditLog')
    Object.assign(state.WAF, { engine: 'On', paranoia_level: 1, audit_log: true })
    const site = `bind 127.0.0.1\n reverse_proxy 127.0.0.1:${originPort}`
    // Explicitly enroll both sites using the production WAF block builder.
    // A shared snippet also keeps rotation's audit path identical.
    const config = `{\n admin unix/${socket}|0600\n auto_https off\n order coraza_waf first\n}\nhttp://127.0.0.1:${port} {\n import load_waf\n ${site}\n}\nhttps://localhost:${tlsPort} {\n tls ${cert} ${key}\n import load_waf\n ${site}\n}\n`
    fs.writeFileSync(file, config)
    fs.writeFileSync(file, config.replace('\nhttp://', `\n(load_waf) {\n${caddy.buildWAFBlock(state.WAF)}\n}\nhttp://`))
    const fd = fs.openSync(path.join(dir, 'caddy.log'), 'w')
    proc = spawn('caddy', ['run', '--config', file], { stdio: ['ignore', fd, fd], env: { ...process.env, GOMEMLIMIT: '512MiB' } }); fs.closeSync(fd)
    proc.on('exit', (code, signal) => { report.caddyExit = { code, signal } })
    fs.mkdirSync(path.dirname(reportPath), { recursive: true }); fs.copyFileSync(file, reportPath + '.Caddyfile')
    async function request(protocol, target, post) {
      const body = post ? JSON.stringify({ id: String(++next), message: 'hello' }) : undefined
      if (post) expectedWrites++
      if (protocol === 'h2') {
        for (let attempt = 0; attempt < 3; attempt++) {
        const session = h2.connect(`https://127.0.0.1:${tlsPort}`, { ca, servername: 'localhost' })
        session.setTimeout(9000, () => session.destroy(new Error('HTTP/2 connection deadline')))
        try {
          await once(session, 'connect')
          return await new Promise((resolve, reject) => {
            session.on('error', reject)
            const req = session.request({ ':path': target, ':method': post ? 'POST' : 'GET', ':authority': `localhost:${tlsPort}`, ...(post ? { 'content-type': 'application/json' } : {}) })
            let status, text = ''; req.setTimeout(9000, () => req.destroy(new Error('HTTP/2 deadline')))
            req.on('response', headers => { status = headers[':status'] }); req.on('data', b => { text += b }); req.on('error', e => { e.refusedBeforeProcessing = status === undefined && req.rstCode === h2.constants.NGHTTP2_REFUSED_STREAM; reject(e) })
            req.on('end', () => resolve({ status, body: text })); req.end(body)
          })
        } catch (error) {
          if (!error.refusedBeforeProcessing) throw error
          report.h2UnprocessedRefusals++
          if (post) assert.equal(writes.has(JSON.parse(body).id), false, 'REFUSED_STREAM must not have executed a POST')
          if (attempt === 2) throw error
        } finally { session.close(); session.destroy() }
        }
      }
      return new Promise((resolve, reject) => {
        const secure = protocol === 'https'
        const req = (secure ? https : http).request({ hostname: '127.0.0.1', port: secure ? tlsPort : port, path: target, method: post ? 'POST' : 'GET', agent: false, ca, servername: 'localhost', signal: AbortSignal.timeout(9000), headers: { Host: secure ? `localhost:${tlsPort}` : `127.0.0.1:${port}`, ...(post ? { 'Content-Type': 'application/json' } : {}) } }, res => {
          let body = ''; res.on('data', b => { body += b }); res.on('error', reject); res.on('end', () => resolve({ status: res.statusCode, body }))
        }); req.on('error', reject); req.end(body)
      })
    }
    let ready = false
    for (let i = 0; i < 80; i++) { try { ready = (await request('http', '/', false)).status === 200 } catch {} if (ready) break; await sleep(100) }
    assert(ready, 'WAF failed to start')
    started = performance.now()
    for (let worker = 0; worker < concurrency; worker++) workers.push((async () => {
      const protocol = ['http', 'https', 'h2'][worker % 3]
      let iteration = 0
      while (running && performance.now() - started < seconds * 1000) {
        const attack = ++iteration % 4 === 0, post = !attack && iteration % 3 === 0
        const stream = !attack && !post && iteration % 7 === 0
        const before = performance.now()
        try {
          const res = await request(protocol, attack ? '/?id=1%20UNION%20SELECT%201,2,3--' : stream ? '/stream' : '/', post)
          assert.equal(res.status, attack ? 403 : 200, `${protocol} ${attack ? 'attack' : 'benign'} status`)
          if (!attack) assert.equal(res.body, stream ? 'chunk\n'.repeat(30) : 'load-origin')
          report.requests++; report.protocols[protocol] = (report.protocols[protocol] || 0) + 1
        } catch (e) { recordError({ protocol, message: e.message }) }
        histogram[Math.min(10000, Math.ceil(performance.now() - before))]++
        if (pace) await sleep(pace)
      }
    })())
    maintenance = (async () => {
      while (running && performance.now() - started < seconds * 1000) {
        await sleep(2000)
        if (!running) break
        let text = fs.readFileSync(file, 'utf8').replace(/^# load revision.*\n/m, '')
        fs.writeFileSync(file, `# load revision ${++report.reloads}\n` + text)
        // --force is essential: a comment alone does not change adapted JSON.
        await exec('caddy', ['reload', '--force', '--config', file, '--address', `unix/${socket}`], { timeout: 20000 })
        const rotated = audit.maintain(); assert.equal(rotated.ok, true, JSON.stringify(rotated))
        if (rotated.rotated) report.rotations++
        const status = fs.readFileSync(`/proc/${proc.pid}/status`, 'utf8')
        report.peakRssMiB = Math.max(report.peakRssMiB, Number(status.match(/^VmRSS:\s+(\d+)/m)[1]) / 1024)
        report.peakDescriptors = Math.max(report.peakDescriptors, fs.readdirSync(`/proc/${proc.pid}/fd`).length)
        report.peakDiskMiB = Math.max(report.peakDiskMiB, disk(dir) / 1048576)
        report.elapsedSeconds = (performance.now() - started) / 1000
        report.writes = writes.size; persist()
        assert(report.peakRssMiB < limits.rssMiB, 'RSS budget exceeded')
        assert(report.peakDiskMiB < limits.diskMiB, 'disk budget exceeded')
        assert(report.peakDescriptors < limits.descriptors, 'descriptor budget exceeded')
      }
    })().catch(e => { recordError({ maintenance: e.message }); running = false })
    await Promise.all(workers); running = false; await maintenance
    report.elapsedSeconds = (performance.now() - started) / 1000
    report.writes = writes.size; report.expectedWrites = expectedWrites; report.bypasses = bypasses; report.duplicateWrites = duplicateWrites
    let cumulative = 0
    for (let i = 0; i < histogram.length; i++) { cumulative += histogram[i]; if (cumulative >= report.requests * 0.99) { report.p99Ms = i; break } }
    assert.equal(report.errorCount, 0, 'every failed request or maintenance operation blocks release')
    assert.deepEqual(report.errors, [])
    assert(report.elapsedSeconds >= seconds, 'load ended early')
    assert(report.requests >= seconds * 4, 'insufficient completed traffic')
    assert.equal(bypasses, 0); assert.equal(duplicateWrites, 0); assert.equal(writes.size, expectedWrites)
    assert(report.p99Ms < limits.p99Ms, 'p99 latency budget exceeded')
    assert(report.reloads >= seconds / 10, 'insufficient reload pressure')
    report.status = 'passed'
  } catch (error) { report.status = 'failed'; report.error = error.stack; process.exitCode = 1 }
  finally {
    running = false; await Promise.allSettled(workers); if (maintenance) await maintenance
    if (proc && proc.exitCode === null && proc.signalCode === null) { const stopped = once(proc, 'exit'); proc.kill('SIGTERM'); await stopped }
    if (origin) { origin.closeAllConnections(); await new Promise(r => origin.close(r)) }
    report.finishedAt = new Date().toISOString(); persist(); console.log(JSON.stringify(report))
    if (fs.existsSync(path.join(dir, 'caddy.log'))) fs.copyFileSync(path.join(dir, 'caddy.log'), reportPath + '.caddy.log')
    fs.rmSync(dir, { recursive: true, force: true })
  }
}
main().catch(e => { console.error(e); process.exitCode = 1 })
