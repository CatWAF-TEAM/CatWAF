// concurrency.test.js — regression tests for the cross-process
// configuration locking introduced after the lost-update audit findings.
//
// These spawn REAL child processes against a shared SQLite database and
// data directory; in-process parallelism cannot reproduce the failure mode
// (two event loops each caching their own copy of the state blob).
const { spawn } = require('child_process')
const fs = require('fs')
const os = require('os')
const path = require('path')

const ROOT = path.join(__dirname, '..')
process.env.DB_DIR = process.env.CATWAF_TEST_DB_DIR || fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-lock-'))
fs.mkdirSync(process.env.DB_DIR, { recursive: true })
process.env.CADDYFILE_PATH = path.join(process.env.DB_DIR, 'Caddyfile')
process.env.CORAZA_AUDIT_LOG = path.join(process.env.DB_DIR, 'audit.json')
// Never let a test talk to a real Caddy.
process.env.CADDY_ADMIN_URL = 'http://127.0.0.1:19917'

fs.writeFileSync(process.env.CADDYFILE_PATH, 'site:80 {\n  respond "test"\n}\n')

let pass = 0
let fail = 0
function check(name, ok, detail) {
  if (ok) { pass++; console.log(`  ok   ${name}`) }
  else { fail++; console.log(`  FAIL ${name}`, detail !== undefined ? JSON.stringify(detail)?.slice(0, 300) : '') }
}

function runChild(mode, tag, count) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [
      path.join(ROOT, 'test', 'fixtures', 'lock-child.js'), mode, process.env.DB_DIR, String(tag), String(count),
    ], { stdio: ['ignore', 'inherit', 'inherit'] })
    child.on('exit', code => resolve(code))
  })
}

;(async () => {
  const state = require(path.join(ROOT, 'backend', 'services', 'state'))
  const configLock = require(path.join(ROOT, 'backend', 'services', 'configLock'))
  const db = require(path.join(ROOT, 'backend', 'services', 'db'))

  console.log('\n== cross-process WAF mutations (lost-update regression) ==')
  {
    // Reused external dirs must start clean or the counts below lie.
    try { fs.unlinkSync(path.join(process.env.DB_DIR, 'shared.log')) } catch {}
    state.updateWAF(w => { w.ip_blacklist = [] })
    // Seed one entry so we can also prove pre-existing data survives.
    state.updateWAF(w => { w.ip_blacklist.push({ ip: '10.0.0.250', note: 'seed', added_at: '', expires_at: null }) })

    const CHILDREN = Number(process.env.CATWAF_TEST_WRITERS || 4)
    const PER_CHILD = Number(process.env.CATWAF_TEST_ITERS || 15)
    // Start all children at once — the whole point is that they race.
    const codes = await Promise.all(
      Array.from({ length: CHILDREN }, (_, i) => runChild('waf', i + 1, PER_CHILD)),
    )
    check('all writer children exited cleanly', codes.every(c => c === 0), codes)

    // The parent's cached copy is stale by design here; read what actually
    // committed.
    const stored = db.getState('waf')
    const ours = (stored.ip_blacklist || []).filter(e => String(e.note).match(/^[1-9]$/))
    check(`no lost updates (${CHILDREN} writers × ${PER_CHILD} mutations)`,
      ours.length === CHILDREN * PER_CHILD, `got ${ours.length}`)
    check('unique entries only (no duplicate commits)',
      new Set(ours.map(e => e.ip)).size === CHILDREN * PER_CHILD)
    check('pre-existing seed entry survived concurrent writers',
      (stored.ip_blacklist || []).some(e => e.note === 'seed'))
    const revNow = db.getState('waf__rev')
    check('revision counter advanced monotonically past every commit',
      Number.isFinite(Number(revNow)) && Number(revNow) >= CHILDREN * PER_CHILD + 1, revNow)
  }

  console.log('\n== lock mutual exclusion under contention ==')
  {
    const logPath = path.join(process.env.DB_DIR, 'shared.log')
    const CHILDREN = 5, PER_CHILD = 12
    // All waiters must recover the same dead holder without unlinking a
    // newly acquired lock belonging to another waiter.
    fs.writeFileSync(configLock.LOCK_PATH, JSON.stringify({ pid: 99999999, id: 'dead-racing-holder', at: 0 }))
    const codes = await Promise.all(
      Array.from({ length: CHILDREN }, (_, i) => runChild('lockfile', i + 1, PER_CHILD)),
    )
    check('all lockfile children exited cleanly', codes.every(c => c === 0), codes)
    const lines = fs.existsSync(logPath) ? fs.readFileSync(logPath, 'utf8').trim().split('\n') : []
    check(`every locked write landed exactly once (${CHILDREN * PER_CHILD} lines)`,
      lines.length === CHILDREN * PER_CHILD, `got ${lines.length}`)
    check('no torn lines (atomic read-modify-write per holder)',
      lines.every(l => /^\d+:\d+$/.test(l)), lines.filter(l => !/^\d+:\d+$/.test(l)).slice(0, 3))
  }

  console.log('\n== stale lock recovery ==')
  {
    // A crashed holder leaves its lock behind with an old timestamp.
    const stalePayload = JSON.stringify({ pid: 999999, id: 'deadbeef', at: Date.now() - 120_000 })
    fs.writeFileSync(configLock.LOCK_PATH, stalePayload)
    const t0 = Date.now()
    let ran = false
    configLock.withConfigLock(() => { ran = true })
    check('a stale lock is broken and acquisition proceeds', ran && Date.now() - t0 < 5000)
    check('the broken lock file is replaced with a live token',
      configLock._internal.lockInfo() === null || configLock._internal.lockInfo().pid === process.pid)
    // Clean up for the next section.
    try { fs.unlinkSync(configLock.LOCK_PATH) } catch {}
  }

  console.log('\n== failure paths release the lock and preserve state ==')
  {
    const revBefore = Number(db.getState('waf__rev'))
    let threw = false
    try {
      state.updateWAF(() => { throw new Error('boom') })
    } catch (e) { threw = e.message === 'boom' }
    check('mutator errors propagate to the caller', threw)
    const lockGone = !fs.existsSync(configLock.LOCK_PATH)
    check('the lock file is removed after a throwing mutation', lockGone,
      lockGone ? undefined : fs.readFileSync(configLock.LOCK_PATH, 'utf8'))
    check('a failed mutation does not bump the revision or persist',
      Number(db.getState('waf__rev')) === revBefore)
    // Lock is usable again afterwards.
    let usable = false
    configLock.withConfigLock(() => { usable = true })
    check('the lock is immediately re-acquirable after a failure', usable)
  }

  console.log('\n== atomic Caddyfile writes leave no debris ==')
  {
    const caddySvc = require(path.join(ROOT, 'backend', 'services', 'caddy'))
    state.updateWAF(w => { w.engine = 'DetectionOnly' }, { label: 'test.render' })
    caddySvc.patchWAFCaddyfile(state.WAF)
    const dirEntries = fs.readdirSync(process.env.DB_DIR)
    check('no temp-file residue beside the Caddyfile',
      !dirEntries.some(f => f.includes('.tmp-')), dirEntries)
    const written = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8')
    check('patched Caddyfile still validates as text with both markers',
      written.includes('@@CATWAF_WAF_START@@') && written.includes('@@CATWAF_WAF_END@@'))
  }

  console.log(`\n${pass} passed, ${fail} failed`)
  process.exit(fail ? 1 : 0)
})().catch(e => {
  console.error('\nharness error:', e.stack)
  process.exit(1)
})
