// trust-proxy.test.js — regression tests for the TRUST_PROXY_HOPS default.
//
// Direct deployments must NOT let X-Forwarded-For decide req.ip (rate-limit
// keys, CIDR checks); proxied deployments (DOMAIN/CATWAF_HTTPS or explicit
// hops) still must. The observable used here is the audit row the decoy
// 404 handler writes for unknown API paths: it records the client address
// as the server saw it.
const { spawn } = require('child_process')
const crypto = require('crypto')
const fs = require('fs')
const os = require('os')
const path = require('path')

const ROOT = path.join(__dirname, '..')

function makeEnv(dir, port, extra) {
  return {
    ...process.env,
    DB_DIR: path.join(dir, 'db'),
    CADDYFILE_PATH: path.join(dir, 'Caddyfile'),
    CORAZA_AUDIT_LOG: path.join(dir, 'audit.json'),
    PORT: String(port),
    CADDY_ADMIN_URL: 'http://127.0.0.1:19917',
    JWT_SECRET: 't'.repeat(64),
    CATWAF_SETUP_TOKEN: 'bootstrap-test-token-'.repeat(3),
    CATAI_ENABLED: 'false',
    ...extra,
  }
}

function pickFreePort() {
  // Bind-and-close so the suite never fires setup credentials at whatever
  // happens to already listen on a guessed port.
  return new Promise((resolve, reject) => {
    const net = require('net')
    const s = net.createServer()
    s.listen(0, '127.0.0.1', () => {
      const port = s.address().port
      s.close(() => resolve(port))
    })
    s.on('error', reject)
  })
}

const liveChildren = new Set()
process.on('exit', () => { for (const c of liveChildren) { try { c.kill('SIGKILL') } catch {} } })

function bootServer(env) {
  fs.mkdirSync(env.DB_DIR, { recursive: true })
  fs.writeFileSync(env.CADDYFILE_PATH, 'site:80 {\n  respond "test"\n}\n')
  const child = spawn(process.execPath, [path.join(ROOT, 'backend', 'server.js')], {
    env, stdio: ['ignore', 'ignore', 'ignore'],
  })
  const base = `http://127.0.0.1:${env.PORT}`
  liveChildren.add(child)
  const untilReady = (async () => {
    for (let i = 0; i < 60; i++) {
      try {
        const res = await fetch(`${base}/healthz`, { signal: AbortSignal.timeout(500) })
        if (res.ok) return
      } catch {}
      await new Promise(r => setTimeout(r, 250))
    }
    throw new Error(`server on :${env.PORT} never became healthy`)
  })()
  return { child, base, untilReady }
}

async function probeIp(base) {
  // Account creation during bootstrap is audited with the server-side view
  // of the client address ('setup.account-created' rows carry req.ip), a
  // clean observable for what trust-proxy decided. Each suite boots a fresh
  // data directory, so the wizard is open.
  await fetch(`${base}/api/setup/account`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': '203.0.113.7, 8.8.8.8', 'X-CatWAF-Setup-Token': 'bootstrap-test-token-'.repeat(3) },
    body: JSON.stringify({ username: 'tp-probe', password: 'correct-horse-battery', confirm: 'correct-horse-battery' }),
    signal: AbortSignal.timeout(5000),
  }).catch(() => {})
  await new Promise(r => setTimeout(r, 400))
}

function lastProbeIp(dbDir) {
  const { DatabaseSync } = require('node:sqlite')
  const db = new DatabaseSync(path.join(dbDir, 'catwaf.db'), { readOnly: true })
  try {
    const row = db.prepare("SELECT ip FROM audit_log WHERE action = 'setup.account-created' ORDER BY ts DESC LIMIT 1").get()
    return row ? row.ip : null
  } finally { db.close() }
}

let pass = 0
let fail = 0
const check = (name, ok, detail) => {
  if (ok) { pass++; console.log(`  ok   ${name}`) }
  else { fail++; console.log(`  FAIL ${name}`, detail !== undefined ? JSON.stringify(detail) : '') }
}

;(async () => {
  console.log('\n== direct deployment ignores forwarded headers by default ==')
  {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-tp-direct-'))
    const env = makeEnv(dir, await pickFreePort()) // no DOMAIN/CATWAF_HTTPS/hops
    const srv = bootServer(env)
    await srv.untilReady
    await probeIp(srv.base)
    const seen = lastProbeIp(env.DB_DIR)
    check('req.ip is the socket peer, not the spoofed XFF chain',
      seen === '127.0.0.1', { seen })
    srv.child.kill('SIGTERM'); liveChildren.delete(srv.child)
  }

  console.log('\n== explicit TRUST_PROXY_HOPS=1 keeps proxied behavior ==')
  {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-tp-proxy-'))
    const env = makeEnv(dir, await pickFreePort(), { TRUST_PROXY_HOPS: '1' })
    const srv = bootServer(env)
    await srv.untilReady
    await probeIp(srv.base)
    const seen = lastProbeIp(env.DB_DIR)
    check('one trusted hop resolves req.ip from X-Forwarded-For (rightmost)',
      seen === '8.8.8.8', { seen })
    srv.child.kill('SIGTERM'); liveChildren.delete(srv.child)
  }

  console.log('\n== DOMAIN deployment defaults to one trusted hop ==')
  {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-tp-domain-'))
    const env = makeEnv(dir, await pickFreePort(), { DOMAIN: 'example.com' })
    const srv = bootServer(env)
    await srv.untilReady
    await probeIp(srv.base)
    const seen = lastProbeIp(env.DB_DIR)
    check('DOMAIN implies a proxy front; XFF is honored one hop deep',
      seen === '8.8.8.8', { seen })
    srv.child.kill('SIGTERM'); liveChildren.delete(srv.child)
  }

  console.log('\n== garbage TRUST_PROXY_HOPS fails safe ==')
  {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-tp-garbage-'))
    const env = makeEnv(dir, await pickFreePort(), { TRUST_PROXY_HOPS: 'yes-please' })
    const srv = bootServer(env)
    await srv.untilReady
    await probeIp(srv.base)
    const seen = lastProbeIp(env.DB_DIR)
    check('an unparsable hops value trusts nothing rather than everything',
      seen === '127.0.0.1', { seen })
    srv.child.kill('SIGTERM'); liveChildren.delete(srv.child)
  }

  console.log(`\n${pass} passed, ${fail} failed`)
  process.exit(fail ? 1 : 0)
})().catch(e => { console.error('\nharness error:', e.stack); process.exit(1) })
