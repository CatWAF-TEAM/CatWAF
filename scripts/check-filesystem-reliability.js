#!/usr/bin/env node
// Run through check-filesystem-reliability.sh: a private 32 MiB tmpfs and
// an unprivileged process. Errors below come from the kernel or SQLite;
// interception only schedules when the fixture fills its own filesystem.
const fs = require('node:fs'), path = require('node:path'), assert = require('node:assert/strict')
const { spawnSync } = require('node:child_process')
const dir = process.env.CATWAF_FAULT_ROOT
assert(dir && /^\/tmp\/catwaf-fs-fault-[A-Za-z0-9]+$/.test(dir), 'Use the private mount wrapper')
assert(process.getuid() !== 0, 'Permission failures require an unprivileged process')
const stat = fs.statfsSync(dir)
assert.equal(stat.type, 0x01021994, 'Faults must run on tmpfs')
assert(stat.blocks * stat.bsize <= 40 * 1048576, 'Refusing to fill a filesystem larger than 40 MiB')
const root = path.resolve(__dirname, '..'), configDir = path.join(dir, 'config')
fs.mkdirSync(configDir)
Object.assign(process.env, { DB_DIR: dir, DB_PATH: path.join(dir, 'fixture.db'), CADDYFILE_PATH: path.join(configDir, 'Caddyfile'), CORAZA_AUDIT_LOG: path.join(dir, 'audit.json'), CADDY_ADMIN_URL: 'http://127.0.0.1:1', CADDY_ADMIN_SOCKET: '', CATWAF_EDITION: 'lite', JWT_SECRET: 'filesystem-fault-fixture-only-'.repeat(3), XDG_DATA_HOME: dir, XDG_CONFIG_HOME: dir })
fs.writeFileSync(process.env.CADDYFILE_PATH, '{\n admin off\n auto_https off\n}\nhttp://127.0.0.1:19992 {\n respond "fixture"\n}\n')
const db = require('../backend/services/db'), state = require('../backend/services/state')
const lock = require('../backend/services/configLock'), tx = require('../backend/services/configTx')
const caddy = require('../backend/services/caddy'), backup = require('../backend/services/backups')
require('../backend/middleware/auth').addUser({ username: 'owner', password: 'Filesystem-fixture-password', role: 'admin' })
const checks = []
const filler = path.join(dir, 'filler')
function fill() {
  const fd = fs.openSync(filler, 'w'), chunk = Buffer.alloc(4096, 1)
  try { for (;;) fs.writeSync(fd, chunk) } catch (e) { assert.equal(e.code, 'ENOSPC') } finally { fs.closeSync(fd) }
}
function free() { try { fs.unlinkSync(filler) } catch (e) { if (e.code !== 'ENOENT') throw e } }
function snapshot() { return { file: fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8'), waf: db.getState('waf'), settings: state.settings.snapshot() } }
function unchanged(before) { assert.deepEqual(snapshot(), before); assert.equal(db.getDb().prepare('PRAGMA quick_check').get().quick_check, 'ok') }
function check(name, fn) {
  const started = performance.now()
  try { fn(); checks.push({ name, passed: true, durationMs: Math.round(performance.now() - started) }) }
  catch (e) { checks.push({ name, passed: false, error: e.stack }); process.exitCode = 1 }
  finally { free(); fs.chmodSync(configDir, 0o700) }
}
const initial = tx.apply({ label: 'filesystem.fixture', reload: false, mutate: s => { s.WAF.paranoia_level = 1 } })
assert.equal(initial.ok, true, JSON.stringify(initial))
const before = snapshot()

check('ENOSPC during lock payload closes descriptors and permits immediate reacquisition', () => {
  const open = fs.openSync, count = fs.readdirSync('/proc/self/fd').length
  for (let i = 0; i < 3; i++) {
    fs.openSync = function (file, ...args) {
      const fd = open.call(this, file, ...args)
      if (file === lock.LOCK_PATH && args[0] === 'wx') fill()
      return fd
    }
    try { assert.throws(() => lock.withConfigLock(() => assert.fail('must not enter')), { code: 'ENOSPC' }) }
    finally { fs.openSync = open; free() }
    assert.equal(fs.existsSync(lock.LOCK_PATH), false, 'failed acquisition must remove its own empty lock')
    assert.equal(fs.readdirSync('/proc/self/fd').length, count, 'no descriptor leak')
    lock.withConfigLock(() => {})
  }
  unchanged(before)
})
check('unwritable configuration directory refuses publication and rolls back settings', () => {
  fs.chmodSync(configDir, 0o500)
  let result
  try { result = tx.apply({ label: 'filesystem.readonly', reload: false, mutate: s => { s.WAF.paranoia_level = 2 } }) }
  finally { fs.chmodSync(configDir, 0o700) }
  assert.equal(result.ok, false); assert.equal(result.rolledBack, true, JSON.stringify(result)); unchanged(before)
})
check('SQLite SQLITE_FULL preserves committed data and reports a successful rollback', () => {
  const conn = db.getDb(), max = conn.prepare('PRAGMA max_page_count').get().max_page_count
  const pages = conn.prepare('PRAGMA page_count').get().page_count
  conn.exec('PRAGMA max_page_count=' + pages)
  let result
  try { result = tx.apply({ label: 'filesystem.sqlite-full', reload: false, mutate: s => { s.WAF.paranoia_level = 2; db.setState('too_large', 'x'.repeat(2 * 1048576)) } }) }
  finally { conn.exec('PRAGMA max_page_count=' + max) }
  assert.equal(result.ok, false); assert.match(result.error, /full/i)
  assert.equal(result.rolledBack, true, JSON.stringify(result)); assert.equal(db.getState('too_large'), null); unchanged(before)
})
check('ENOSPC when persisting the recovery journal never publishes the candidate', () => {
  const open = fs.openSync
  fs.openSync = function (file, ...args) {
    if (typeof file === 'string' && path.basename(file).startsWith('.config-transaction.json.tmp-')) fill()
    return open.call(this, file, ...args)
  }
  let result
  try { result = tx.apply({ label: 'filesystem.journal-full', reload: false, mutate: s => { s.WAF.paranoia_level = 3 } }) }
  finally { fs.openSync = open; free() }
  assert.equal(result.ok, false); assert.match(result.error, /ENOSPC/)
  assert.equal(result.rolledBack, true, JSON.stringify(result)); unchanged(before)
  assert.equal(fs.existsSync(tx.journalPath()), false)
})
check('SIGKILL immediately after publication recovers old configuration and SQLite data', () => {
  const code = `const fs=require('fs'),t=require('./backend/services/configTx');const rename=fs.renameSync;fs.renameSync=function(a,b){const r=rename(a,b);if(b===process.env.CADDYFILE_PATH)process.kill(process.pid,'SIGKILL');return r};t.apply({label:'kill',reload:false,mutate:s=>{s.WAF.paranoia_level=4}})`
  const child = spawnSync(process.execPath, ['-e', code], { cwd: root, encoding: 'utf8', timeout: 30000 })
  assert.equal(child.signal, 'SIGKILL', child.stderr)
  assert.equal(fs.existsSync(tx.journalPath()), true)
  assert.equal(tx.recover().committed, false); unchanged(before)
})
check('invalid recovery journal fails closed without changing live data', () => {
  fs.writeFileSync(tx.journalPath(), '{broken')
  try { assert.throws(() => tx.recover(), SyntaxError); unchanged(before) }
  finally { fs.unlinkSync(tx.journalPath()) }
})
check('truncated SQLite backup is rejected without changing the database', () => {
  const file = path.join(dir, 'broken.db'); fs.writeFileSync(file, 'SQLite format 3\0truncated')
  const result = backup.confirmDatabaseRestore(file)
  assert.equal(result.ok, false); unchanged(before)
})
check('ENOSPC in the audit rotation journal leaves the active log and configuration intact', () => {
  const audit = require('../backend/services/auditLog'), open = fs.openSync
  fs.openSync = function (file, ...args) {
    if (typeof file === 'string' && path.basename(file).includes('.catwaf-audit-state.json.tmp-')) fill()
    return open.call(this, file, ...args)
  }
  let result
  try { result = audit.rotate() } finally { fs.openSync = open; free() }
  assert.equal(result.ok, false); assert.match(result.error, /journal/)
  assert.equal(fs.existsSync(audit.stateFileFor(process.env.CORAZA_AUDIT_LOG)), false)
  assert(fs.existsSync(process.env.CORAZA_AUDIT_LOG)); unchanged(before)
})
check('healthy transaction succeeds after all storage and crash failures', () => {
  const result = tx.apply({ label: 'filesystem.recovered', reload: false, mutate: s => { s.WAF.paranoia_level = 2 } })
  assert.equal(result.ok, true, JSON.stringify(result)); assert.equal(db.getState('waf').paranoia_level, 2)
  assert.equal(fs.existsSync(tx.journalPath()), false)
  assert.equal(caddy.readCaddyfile().includes('paranoia_level=2'), true)
})
console.log(JSON.stringify({ status: checks.every(c => c.passed) ? 'passed' : 'failed', filesystem: 'private 32 MiB tmpfs', checks }, null, 2))
