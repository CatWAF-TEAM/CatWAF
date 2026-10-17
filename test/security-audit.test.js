// Security boundary regressions. Uses only local fixtures and loopback HTTP.
const assert = require('node:assert/strict')
const test = require('node:test')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const crypto = require('node:crypto')
const http = require('node:http')
const root = path.resolve(__dirname, '..')
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-security-audit-'))
Object.assign(process.env, {
  DB_DIR: dir, DB_PATH: path.join(dir, 'test.db'), JWT_SECRET: crypto.randomBytes(32).toString('hex'),
  CADDYFILE_PATH: path.join(dir, 'Caddyfile'), CORAZA_AUDIT_LOG: path.join(dir, 'audit.json'),
  CADDY_ADMIN_URL: 'http://127.0.0.1:1', CADDY_ADMIN_SOCKET: '', TRUST_PROXY_HOPS: '0',
  CATWAF_SETUP_TOKEN: '', CATWAF_BACKUP_PASSPHRASE: 'test-backup-passphrase', LOG_LEVEL: 'error',
})
fs.writeFileSync(process.env.CADDYFILE_PATH, ':19992 {\n respond "fixture" 200\n}\n')
const { app } = require('../backend/server')
const auth = require('../backend/middleware/auth')
const db = require('../backend/services/db')
const settings = require('../backend/services/settings')
const sessions = require('../backend/services/session')
const signing = require('../backend/middleware/signing')
const { currentSegment } = require('../backend/middleware/dynamicPath')
const netGuard = require('../backend/services/netGuard')

test('security boundary regressions and API authorization inventory', async t => {
  const server = app.listen(0, '127.0.0.1')
  await new Promise(resolve => server.once('listening', resolve))
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections() }))
  const base = `http://127.0.0.1:${server.address().port}`
  async function request(method, url, body, session, headers = {}) {
    const text = body === undefined ? undefined : JSON.stringify(body)
    if (session) {
      const ts = String(Date.now()), nonce = crypto.randomBytes(16).toString('hex')
      headers = { ...headers, Authorization: `Bearer ${session.token}`, 'X-CatWAF-Ts': ts, 'X-CatWAF-Nonce': nonce,
        'X-CatWAF-Sig': signing.sign(session.sessionKey, { method, path: url, ts, nonce, bodyHash: crypto.createHash('sha256').update(text || '').digest('hex') }) }
    }
    const gated = url.startsWith('/api/') && !url.startsWith('/api/auth/login') && !url.startsWith('/api/setup') && url !== '/api/handshake'
    const res = await fetch(base + (gated ? currentSegment().basePath : '') + url, {
      method, headers: { 'Content-Type': 'application/json', ...headers }, body: text, signal: AbortSignal.timeout(10000), redirect: 'manual',
    })
    const raw = await res.text()
    let json; try { json = JSON.parse(raw) } catch {}
    return { status: res.status, json, raw, headers: res.headers }
  }
  const password = 'Audit-password-2026'
  await t.test('web bootstrap needs an out-of-band token and closes after the first account', async () => {
    const payload = { username: 'owner', password }
    assert.equal((await request('POST', '/api/setup/account', payload)).status, 404)
    process.env.CATWAF_SETUP_TOKEN = 'b'.repeat(48)
    assert.equal((await request('POST', '/api/setup/account', payload)).status, 404)
    assert.equal((await request('POST', '/api/setup/account', payload, null, { 'X-CatWAF-Setup-Token': process.env.CATWAF_SETUP_TOKEN })).status, 200)
    assert.throws(() => auth.addUser({ username: 'second', password, role: 'admin', bootstrap: true }), /already completed/)
    assert.equal((await request('POST', '/api/setup/account', payload, null, { 'X-CatWAF-Setup-Token': process.env.CATWAF_SETUP_TOKEN })).status, 404)
    for (const username of ['__proto__', 'constructor', 'prototype', 'guest']) assert.throws(() => auth.addUser({ username, password }))
    assert.throws(() => auth.setPassword('owner', 'é'.repeat(37)), /72 UTF-8/)
  })
  auth.addUser({ username: 'readonly', password, role: 'viewer' })
  async function login(username) {
    const r = await request('POST', '/api/auth/login', { username, password })
    assert.equal(r.status, 200, r.raw)
    assert.match(r.headers.get('cache-control'), /no-store/)
    return r.json
  }
  const owner = await login('owner'), viewer = await login('readonly')

  await t.test('certificate filenames reject path traversal before any upstream call', async () => {
    const service = require('../backend/services/cloudflare'), original = service.cfFetch
    let calls = 0
    service.cfFetch = async () => { calls++; throw new Error('fixture upstream reached') }
    try {
      for (const zone_id of ['../../outside', '..\\outside', '/tmp/outside', '%2e%2e%2foutside', 'a'.repeat(32) + '/../outside', ['a'.repeat(32)], { id: 'a'.repeat(32) }]) {
        const result = await request('POST', '/api/cloudflare/gen-cert', { token: 'fixture', zone_id }, owner)
        assert.equal(result.status, 400, result.raw)
      }
      assert.equal(calls, 0, 'unvalidated paths must not reach certificate generation')
      assert.equal((await request('POST', '/api/cloudflare/gen-cert', { token: 'fixture', zone_id: 'a'.repeat(32) }, owner)).status, 500)
      assert.equal(calls, 1, 'a valid ID reaches the controlled upstream fixture')
      assert.equal(fs.existsSync(path.join(dir, 'certs')), false)
    } finally { service.cfFetch = original }
  })

  // Discover the actual declared surface, so new endpoints join the test.
  const routes = []
  for (const file of fs.readdirSync(path.join(root, 'backend/routes')).filter(f => f.endsWith('.js'))) {
    const source = fs.readFileSync(path.join(root, 'backend/routes', file), 'utf8')
    const re = /router\.(get|post|put|patch|delete|all)\('([^']+)'([^\n]*)/g
    for (const m of source.matchAll(re)) routes.push({ method: m[1].toUpperCase(), path: m[2], file, admin: /writeRequired/.test(m[3]), line: source.slice(0, m.index).split('\n').length })
  }
  const protectedRoutes = routes.filter(r => r.path.startsWith('/api/') && !/^\/api\/(setup|auth\/(login|status)|handshake|enforce|upload-gate)(?:\/|$)/.test(r.path))
  function example(p) { return p.replace(/:action\(enable\|disable\)/g, 'enable').replace(/:[a-zA-Z_]+/g, 'audit-fixture') }
  await t.test(`anonymous access denied across all ${protectedRoutes.length} protected route declarations`, async () => {
    for (const route of protectedRoutes) {
      const methods = route.method === 'GET' ? ['GET', 'HEAD'] : [route.method]
      for (const method of methods) {
        const r = await request(method, example(route.path), ['GET', 'HEAD'].includes(method) ? undefined : {})
        assert.equal(r.status, 401, `${method} ${route.path}: ${r.raw}`)
      }
    }
  })
  await t.test('viewer denied on every declared admin route', async () => {
    for (const route of protectedRoutes.filter(r => r.admin)) {
      const r = await request(route.method, example(route.path), route.method === 'GET' ? undefined : {}, viewer)
      assert.equal(r.status, 403, `${route.method} ${route.path}: ${r.raw}`)
    }
    assert.equal((await request('GET', '/api/diagnostics/export', undefined, viewer)).status, 403)
  })
  await t.test('JWT alone is insufficient on every protected route', async () => {
    for (const route of protectedRoutes) {
      const r = await request(route.method, example(route.path), route.method === 'GET' ? undefined : {}, null, { Authorization: `Bearer ${owner.token}` })
      assert.equal(r.status, 401, `${route.method} ${route.path}: ${r.raw}`)
    }
  })
  await t.test('signed request replay is rejected in another process', () => {
    const jti = 'cross-process-nonce', ts = String(Date.now()), nonce = crypto.randomBytes(16).toString('hex')
    const key = require('../backend/services/secrets').sessionKey(jti)
    const signature = signing.sign(key, { method: 'GET', path: '/api/stats', ts, nonce, bodyHash: crypto.createHash('sha256').update('').digest('hex') })
    const headers = { 'x-catwaf-ts': ts, 'x-catwaf-nonce': nonce, 'x-catwaf-sig': signature }
    const req = { user: { jti }, method: 'GET', signedPath: '/api/stats', get: key => headers[key] }
    let accepted = false
    signing.verifySignature(req, { status: () => { assert.fail('first request rejected') } }, () => { accepted = true })
    assert.equal(accepted, true)
    const script = `const signing=require('./backend/middleware/signing'); const headers=${JSON.stringify(headers)}; signing.verifySignature({user:{jti:${JSON.stringify(jti)}},method:'GET',signedPath:'/api/stats',get:k=>headers[k]}, {status(n){this.code=n;return this},json(v){console.log(JSON.stringify({status:this.code,...v}))}}, ()=>console.log('accepted'));`
    const result = require('node:child_process').execFileSync(process.execPath, ['-e', script], { cwd: root, encoding: 'utf8', windowsHide: true })
    assert.equal(JSON.parse(result).code, 'SIG_REPLAY')
  })
  await t.test('logout and missing/corrupt session state fail closed', async () => {
    const logged = await login('owner')
    assert.equal((await request('POST', '/api/auth/logout', {}, logged)).status, 200)
    for (let n = 0; n < 2; n++) assert.equal((await request('GET', '/api/stats', undefined, logged)).status, 401)
    assert.equal((await request('GET', '/api/handshake', undefined, null, { Authorization: `Bearer ${logged.token}` })).status, 401)
    const jwt = require('jsonwebtoken')
    const child = `const s=require('./backend/services/session'); console.log(JSON.stringify([s.touch(${JSON.stringify(jwt.decode(owner.token).jti)}, {}), s.touch(${JSON.stringify(jwt.decode(logged.token).jti)}, {})]));`
    const persisted = JSON.parse(require('node:child_process').execFileSync(process.execPath, ['-e', child], { cwd: root, encoding: 'utf8', windowsHide: true }))
    assert.equal(persisted[0].ok, true, 'active session survives loading in a new process')
    assert.equal(persisted[1].ok, false, 'revocation survives loading in a new process')
    const saved = db.getState(sessions.STORE_KEY)
    db.getDb().prepare('UPDATE waf_state SET value = ? WHERE key = ?').run('{broken', sessions.STORE_KEY)
    assert.equal((await request('GET', '/api/stats', undefined, owner)).status, 401)
    db.setState(sessions.STORE_KEY, saved)
  })
  await t.test('idle, binding, cap eviction and expiry remain rejected on retries', () => {
    const req = { ip: '192.0.2.1', headers: { 'user-agent': 'browser' } }, user = auth.findUser('owner')
    assert.equal(settings.set('session', { idle_timeout_min: 1, bind_ip: true, max_concurrent: 1 }).ok, true)
    sessions.open({ jti: 'idle', user, req })
    const store = db.getState(sessions.STORE_KEY)
    store.idle.last_seen = new Date(Date.now() - 120000).toISOString(); db.setState(sessions.STORE_KEY, store)
    assert.equal(sessions.touch('idle', req).code, 'SESSION_IDLE')
    assert.equal(sessions.touch('idle', req).ok, false)
    sessions.open({ jti: 'bound', user, req })
    assert.equal(sessions.touch('bound', { ...req, ip: '192.0.2.2' }).code, 'SESSION_BINDING')
    assert.equal(sessions.touch('bound', req).ok, false)
    sessions.open({ jti: 'old', user, req }); sessions.open({ jti: 'new', user, req })
    assert.equal(sessions.touch('old', req).ok, false)
    assert.equal(sessions.touch('new', req).ok, true)
    sessions.open({ jti: 'expired', user, req, expiresAt: Date.now() - 1 })
    assert.equal(sessions.touch('expired', req).ok, false)
    settings.reset('session')
  })
  await t.test('second-factor corruption is not treated as unenrolled', () => {
    const totp = require('../backend/services/totp')
    db.getDb().prepare('INSERT OR REPLACE INTO waf_state (key,value) VALUES (?,?)').run('totp', '{broken')
    assert.throws(() => totp.isEnabled('owner'))
    db.setState('totp', null)
    assert.throws(() => totp.isEnabled('owner'))
    db.setState('totp', {})
    db.setState('totp', { owner: 'damaged-record' })
    assert.throws(() => totp.isEnabled('owner'))
    db.setState('totp', {})
  })
  await t.test('password reset during an outstanding comparison cannot mint a token', async () => {
    const hasher = require('../backend/services/passwordHash'), original = hasher.compare
    auth.addUser({ username: 'reset-race', password, role: 'viewer' })
    let started, release
    const waiting = new Promise(resolve => { started = resolve })
    hasher.compare = () => { started(); return new Promise(resolve => { release = resolve }) }
    try {
      const pending = request('POST', '/api/auth/login', { username: 'reset-race', password })
      await waiting
      auth.setPassword('reset-race', 'Replacement-password-2026')
      release(true)
      assert.equal((await pending).status, 401)
    } finally { hasher.compare = original }
  })
  await t.test('a recovery code is single-use across concurrent processes', async () => {
    const totp = require('../backend/services/totp')
    const enrolled = totp.beginEnrollment('owner')
    const confirmed = totp.confirmEnrollment('owner', totp.totp(enrolled.secret))
    assert.equal(confirmed.ok, true)
    assert.throws(() => totp.beginEnrollment('owner'), /already enabled/)
    const script = `console.log(JSON.stringify(require('./backend/services/totp').verify('owner', ${JSON.stringify(confirmed.recovery_codes[0])})))`
    const child = () => new Promise((resolve, reject) => {
      const p = require('node:child_process').spawn(process.execPath, ['-e', script], { cwd: root, windowsHide: true })
      let output = ''; p.stdout.on('data', c => { output += c }); p.stderr.resume()
      p.once('error', reject); p.once('exit', code => code ? reject(new Error('TOTP child exited ' + code)) : resolve(JSON.parse(output)))
    })
    try { assert.equal((await Promise.all([child(), child()])).filter(r => r.ok).length, 1) }
    finally { totp.disable('owner') }
  })
  await t.test('async route failures return an error without leaving a hanging request', async () => {
    const geoip = require('../backend/services/geoip'), original = geoip.available
    const fresh = await login('owner')
    geoip.available = () => { throw new Error('async diagnostic failure fixture') }
    try { assert.equal((await request('GET', '/api/diagnostics', undefined, fresh)).status, 500) }
    finally { geoip.available = original }
  })
  await t.test('legacy templates and Redis configuration reads do not disclose credentials', () => {
    const templates = require('../backend/services/templates')
    db.setState(templates.STORE_KEY, { legacy: { id: 'legacy', settings: { metrics: { token: 'secret-fixture', enabled: true }, cluster: { url: 'rediss://user:secret-fixture@example.com/0' } }, waf: {} } })
    assert.ok(!JSON.stringify(templates.exportTemplate('legacy')).includes('secret-fixture'))
    assert.equal(templates.get('__proto__'), null)
    assert.equal(settings.validate('cluster', { url: 'rediss://user:password@example.com/0' }).ok, false)
  })
  await t.test('preview cannot publish transient settings or overwrite generated assets', () => {
    const preview = require('../backend/services/preview'), assets = require('../backend/services/render/util')
    const original = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8')
    const asset = assets.writeAsset('www/robots.txt', 'unchanged-fixture')
    const rows = () => db.getDb().prepare("SELECT key,value FROM waf_state WHERE key LIKE 'ext:%' ORDER BY key").all()
    const before = JSON.stringify(rows())
    const result = preview.preview({ mutate() {
      settings.set('robots', { enabled: true, mode: 'disallow-all' })
      assets.writeAsset('www/robots.txt', 'changed-fixture')
      const { DatabaseSync } = require('node:sqlite')
      const reader = new DatabaseSync(db.DB_PATH, { readOnly: true })
      try { assert.equal(reader.prepare("SELECT value FROM waf_state WHERE key='ext:robots'").get()?.value, undefined) } finally { reader.close() }
    } })
    assert.equal(result.ok, true, result.error)
    assert.equal(JSON.stringify(rows()), before)
    assert.equal(fs.readFileSync(asset, 'utf8'), 'unchanged-fixture')
    assert.equal(fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8'), original)
  })
  await t.test('Redis parser bounds nesting and measures bulk strings in bytes', () => {
    const { parseReply } = require('../backend/services/sharedState')
    assert.deepEqual(parseReply(Buffer.from('$2\r\né\r\n')), { value: 'é', consumed: 8 })
    assert.ok(parseReply(Buffer.from('$1048577\r\n')).error)
    assert.ok(parseReply(Buffer.from('*1\r\n'.repeat(40) + '+OK\r\n')).error)
  })
  await t.test('rediss sends TLS, never plaintext AUTH, to an untrusted endpoint', async () => {
    const net = require('node:net'), { RedisBackend } = require('../backend/services/sharedState')
    const chunks = []
    const peer = net.createServer(socket => socket.once('data', chunk => { chunks.push(chunk); socket.destroy() })).listen(0, '127.0.0.1')
    await new Promise(resolve => peer.once('listening', resolve))
    try {
      await assert.rejects(new RedisBackend({ url: `rediss://127.0.0.1:${peer.address().port}`, password: 'redis-secret-fixture', timeout_ms: 1000 }).ping())
      assert.equal(chunks[0]?.[0], 0x16)
      assert.ok(!Buffer.concat(chunks).includes(Buffer.from('redis-secret-fixture')))
    } finally { peer.close() }
  })
  await t.test('the upload proxy preserves HTTPS from the configured upstream', async () => {
    const net = require('node:net'), chunks = []
    const peer = net.createServer(socket => socket.once('data', chunk => { chunks.push(chunk); socket.destroy() })).listen(0, '127.0.0.1')
    await new Promise(resolve => peer.once('listening', resolve))
    const before = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8')
    const address = `127.0.0.1:${peer.address().port}`
    fs.writeFileSync(process.env.CADDYFILE_PATH, `example.com {\n reverse_proxy https://${address}\n}\n`)
    try {
      const res = await fetch(base + '/api/upload-gate', { method: 'POST', body: 'upload-secret-fixture', headers: {
        'X-CatWAF-Upload-Key': require('../backend/services/secrets').derive('upload-gate-key'),
        'X-CatWAF-Upload-Upstream': address, 'X-CatWAF-Upload-Path': '/upload',
      }, signal: AbortSignal.timeout(5000) })
      assert.equal(res.status, 502)
      await res.text()
      assert.equal(chunks[0]?.[0], 0x16)
      assert.ok(!Buffer.concat(chunks).includes(Buffer.from('upload-secret-fixture')))
    } finally { peer.close(); fs.writeFileSync(process.env.CADDYFILE_PATH, before) }
  })
  await t.test('dead lock recovery records ownership and live old holders are not evicted', () => {
    const lock = require('../backend/services/configLock')
    fs.writeFileSync(lock.LOCK_PATH, JSON.stringify({ pid: 99999999, id: 'dead', at: 0 }))
    lock.withConfigLock(() => assert.equal(lock._internal.lockInfo().pid, process.pid))
    assert.equal(fs.existsSync(lock.LOCK_PATH), false)
    fs.writeFileSync(lock.LOCK_PATH, JSON.stringify({ pid: process.pid, id: 'live', at: 0 }))
    try { assert.throws(() => lock.withConfigLock(() => assert.fail('live holder evicted'), { timeoutMs: 1, staleMs: 1 }), /Timed out/) }
    finally { fs.unlinkSync(lock.LOCK_PATH) }
  })
  await t.test('expanded IPv4-mapped addresses cannot reach private infrastructure', () => {
    for (const ip of ['0:0:0:0:0:ffff:7f00:1', '0000:0000:0000:0000:0000:ffff:0a00:0001', '::ffff:127.0.0.1', '64:ff9b:1::a00:1', 'fec0::1', '2002:7f00:1::']) assert.equal(netGuard.isPubliclyRoutable(ip), false, ip)
    for (const ip of ['8.8.8.8', '2606:4700:4700::1111', '0:0:0:0:0:ffff:808:808']) assert.equal(netGuard.isPubliclyRoutable(ip), true, ip)
  })
  await t.test('untrusted forwarding headers cannot choose a challenge identity', () => {
    const identity = require('../backend/services/gatewayIdentity'), secrets = require('../backend/services/secrets')
    const req = { ip: '192.0.2.1', headers: { 'x-real-ip': '198.51.100.1' } }
    assert.equal(identity.clientIp(req), req.ip)
    req.headers['x-catwaf-challenge-key'] = secrets.derive('challenge-key')
    assert.equal(identity.clientIp(req), '198.51.100.1')
  })
  await t.test('an exempt path cannot prime an allow for a challenged path', async () => {
    settings.set('challenge', { mode: 'cookie', trigger: 'all', exempt_paths: ['/public'] })
    const enforce = require('../backend/services/enforce')
    const context = { ip: '192.0.2.44', userAgent: 'Mozilla/5.0', headers: [] }
    assert.equal((await enforce.evaluate({ ...context, uri: '/public' })).action, 'allow')
    assert.equal((await enforce.evaluate({ ...context, uri: '/private' })).action, 'challenge')
    settings.reset('challenge')
  })
  await t.test('second-factor encryption rejects truncated authentication tags', () => {
    const totp = require('../backend/services/totp'), username = 'tag-length-fixture'
    const enrollment = totp.beginEnrollment(username)
    const store = db.getStateStrict(totp.STORE_KEY), original = store[username].secret
    const parts = original.split('.')
    try {
      for (const length of [4, 8, 12, 13, 14, 15]) {
        store[username].secret = [parts[0], Buffer.from(parts[1], 'base64').subarray(0, length).toString('base64'), parts[2]].join('.')
        db.setState(totp.STORE_KEY, store)
        assert.equal(totp.confirmEnrollment(username, totp.totp(enrollment.secret)).ok, false, `must refuse ${length}-byte tag`)
      }
      store[username].secret = original; db.setState(totp.STORE_KEY, store)
      assert.equal(totp.confirmEnrollment(username, totp.totp(enrollment.secret)).ok, true)
    } finally { const saved = db.getStateStrict(totp.STORE_KEY); delete saved[username]; db.setState(totp.STORE_KEY, saved) }
  })
  await t.test('HTML report exports escape attacker-controlled log fields', () => {
    const reports = require('../backend/services/reports')
    const payload = '</td><script>alert(document.domain)</script><td>'
    db.getDb().prepare('INSERT INTO request_log (id,ts,ip,method,uri,status,action) VALUES (?,?,?,?,?,?,?)').run('report-xss', new Date().toISOString(), '127.0.0.1', 'GET', payload, 403, 'block')
    const result = reports.generate({ format: 'html', from: new Date(Date.now() - 86400000).toISOString(), to: new Date(Date.now() + 86400000).toISOString() })
    assert.equal(result.ok, true)
    assert(result.body.includes('&lt;script&gt;alert(document.domain)&lt;/script&gt;'))
    assert(!result.body.includes(payload)); assert(!result.body.includes('<script>'))
    db.getDb().prepare('DELETE FROM request_log WHERE id=?').run('report-xss')
  })
  await t.test('encrypted backups reject ciphertext/header tampering and wrong keys', () => {
    const backups = require('../backend/services/backups'), file = path.join(dir, 'sample.enc')
    backups.encryptBufferToFile(Buffer.from('sensitive fixture'), file)
    const original = fs.readFileSync(file)
    assert.equal(backups.isEncrypted(file), true)
    assert.equal(backups.decryptFileToBuffer(file).toString(), 'sensitive fixture')
    for (const index of [10, 26, 40, original.length - 1]) {
      const corrupt = Buffer.from(original); corrupt[index] ^= 1; fs.writeFileSync(file, corrupt)
      assert.throws(() => backups.decryptFileToBuffer(file))
    }
    fs.writeFileSync(file, original)
    process.env.CATWAF_BACKUP_PASSPHRASE = 'different-passphrase'
    assert.throws(() => backups.decryptFileToBuffer(file))
    process.env.CATWAF_BACKUP_PASSPHRASE = 'test-backup-passphrase'
    fs.writeFileSync(process.env.CADDYFILE_PATH, 'header_up X-CatWAF-Enforce-Key "credential-fixture"\n')
    assert.ok(!JSON.stringify(backups.buildPayload()).includes('credential-fixture'))
  })
  await t.test('database backups contain committed WAL state and remain readable', () => {
    const backups = require('../backend/services/backups'), { DatabaseSync } = require('node:sqlite')
    const previous = settings.get('backups')
    settings.replace('backups', { ...previous, enabled: true, destination: dir, include_database: true, encrypt: false })
    db.setState('backup-regression', { committed: true })
    try {
      const result = backups.run()
      assert.ok(result.database, 'database snapshot was not created')
      const copy = new DatabaseSync(result.database, { readOnly: true })
      try {
        assert.equal(copy.prepare('PRAGMA integrity_check').get().integrity_check, 'ok')
        assert.equal(JSON.parse(copy.prepare('SELECT value FROM waf_state WHERE key=?').get('backup-regression').value).committed, true)
      } finally { copy.close() }
    } finally { settings.replace('backups', previous) }
  })
  await t.test('backup restoration rejects unvalidated settings before writing', () => {
    const backups = require('../backend/services/backups'), fixture = path.join(dir, 'untrusted-backup.json')
    const before = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8')
    fs.writeFileSync(fixture, JSON.stringify({ waf: {}, settings: { proxy: { upstream_tls_server_name: 'example.com\n} injected' } } }))
    const result = backups.restoreFromFile(fixture)
    assert.equal(result.ok, false)
    assert.match(result.error, /settings failed validation/)
    assert.equal(fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8'), before)
  })
  await t.test('redirects do not forward integration secrets to another origin', async () => {
    let leaked = 0
    const sink = http.createServer((req, res) => { leaked++; res.end('sink') }).listen(0, '127.0.0.1')
    await new Promise(resolve => sink.once('listening', resolve))
    const redirect = http.createServer((req, res) => { res.writeHead(307, { Location: `http://127.0.0.1:${sink.address().port}/` }); res.end() }).listen(0, '127.0.0.1')
    await new Promise(resolve => redirect.once('listening', resolve))
    try {
      await assert.rejects(netGuard.guardedFetch(`http://127.0.0.1:${redirect.address().port}/`, { allowLoopback: true, method: 'POST', headers: { Authorization: 'Bearer fixture' }, body: 'secret-fixture' }), /another origin/)
      assert.equal(leaked, 0)
    } finally { sink.closeAllConnections(); sink.close(); redirect.closeAllConnections(); redirect.close() }
  })
  console.log(`Audited authorization declarations: ${routes.length}; protected: ${protectedRoutes.length}; explicit admin: ${protectedRoutes.filter(r => r.admin).length}`)
})
