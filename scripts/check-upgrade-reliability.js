#!/usr/bin/env node
// Run against a real exported previous release, never a fabricated schema.
// CATWAF_PREVIOUS_SOURCE points to that release; only private fixture data
// is opened. Old code is not exposed to the network.
const fs = require('node:fs'), path = require('node:path'), os = require('node:os')
const assert = require('node:assert/strict'), { spawnSync } = require('node:child_process')
const { DatabaseSync } = require('node:sqlite')
const root = path.resolve(__dirname, '..'), old = path.resolve(process.env.CATWAF_PREVIOUS_SOURCE || '')
assert(old !== root && fs.existsSync(path.join(old, 'backend/services/db.js')), 'provide CATWAF_PREVIOUS_SOURCE')
const previousVersion = JSON.parse(fs.readFileSync(path.join(old, 'package.json'))).version
const results = []
for (const edition of ['lite', 'full']) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-upgrade-'))
  const env = { ...process.env, NODE_PATH: path.join(root, 'node_modules'), DB_DIR: dir, DB_PATH: path.join(dir, 'live.db'), CADDYFILE_PATH: path.join(dir, 'Caddyfile'), CORAZA_AUDIT_LOG: path.join(dir, 'audit.json'), CADDY_ADMIN_SOCKET: '', CADDY_ADMIN_URL: 'http://127.0.0.1:1', JWT_SECRET: 'upgrade-fixture-secret-'.repeat(3), CATWAF_EDITION: edition, XDG_CONFIG_HOME: path.join(dir, 'config'), XDG_DATA_HOME: path.join(dir, 'data') }
  const run = (cwd, args, expected = 0) => {
    const result = spawnSync(process.execPath, args, { cwd, env, encoding: 'utf8', timeout: 60000, maxBuffer: 8 * 1024 * 1024 })
    assert.equal(result.status, expected, result.stdout + result.stderr)
    return result.stdout
  }
  const inspect = () => {
    const db = new DatabaseSync(env.DB_PATH, { readOnly: true })
    try { return { marker: JSON.parse(db.prepare("SELECT value FROM waf_state WHERE key='upgrade_marker'").get().value), users: JSON.parse(db.prepare("SELECT value FROM waf_state WHERE key='users'").get().value), check: db.prepare('PRAGMA integrity_check').get().integrity_check } } finally { db.close() }
  }
  try {
    fs.writeFileSync(env.CADDYFILE_PATH, ':19990 {\n respond "upgrade fixture"\n}\n')
    run(old, ['-e', `const fs=require('fs'),path=require('path'),d=require('./backend/services/db'),s=require('./backend/services/state');
      require('./backend/middleware/auth').addUser({username:'owner',password:'upgrade-fixture-password',role:'admin'});
      s.WAF.paranoia_level=2;s.saveWAF();d.setState('upgrade_marker',{version:'previous',edition:process.env.CATWAF_EDITION});
      fs.writeFileSync(path.join(process.env.DB_DIR,'before.json'),JSON.stringify({waf:s.WAF,settings:s.settings?.snapshot?.(),caddyfile:fs.readFileSync(process.env.CADDYFILE_PATH,'utf8')}));
      d.getDb().prepare('VACUUM INTO ?').run(path.join(process.env.DB_DIR,'before.db'));`])
    const before = inspect(), beforeConfig = fs.readFileSync(env.CADDYFILE_PATH, 'utf8')
    assert.equal(before.check, 'ok')
    // Upgrade performs the real current migrations and configuration commit.
    run(root, ['-e', `const a=require('node:assert/strict'),d=require('./backend/services/db'),s=require('./backend/services/state'),tx=require('./backend/services/configTx');
      a.equal(s.WAF.paranoia_level,2);a.equal(d.getState('upgrade_marker').version,'previous');
      a(d.getDb().prepare("SELECT name FROM sqlite_master WHERE name='request_nonces'").get());
      const result=tx.apply({label:'upgrade-test',reload:false,mutate:s=>{s.WAF.paranoia_level=3}});a.equal(result.ok,true,JSON.stringify(result));
      d.setState('upgrade_marker',{version:'current',edition:process.env.CATWAF_EDITION});`])
    const upgraded = inspect(); assert.equal(upgraded.check, 'ok'); assert.deepEqual(upgraded.users, before.users)
    assert.match(fs.readFileSync(env.CADDYFILE_PATH, 'utf8'), /SecRuleEngine On/)
    // Reopen twice to prove migrations and recovery are idempotent.
    for (let i = 0; i < 2; i++) run(root, ['-e', `const a=require('node:assert/strict'),d=require('./backend/services/db'),tx=require('./backend/services/configTx');tx.recover();tx.assertReady();a.equal(d.getState('upgrade_marker').version,'current')`])
    // Supported rollback restores the matching pre-upgrade data and config
    // while stopped, then starts the previous release on its own data.
    const restoreStarted = Math.floor(Date.now() / 1000)
    const restored = JSON.parse(run(root, ['bin/catwaf.js', 'backup', 'restore', path.join(dir, 'before.json'), '--db', '--confirm-db-restore', '--json']))
    assert.equal(restored.ok, true); assert.equal(restored.database.sessions_revoked, true)
    assert.equal(inspect().marker.version, 'previous')
    const restoredUsers = inspect().users
    assert.deepEqual(restoredUsers.map(({ tokens_valid_after, ...account }) => account), before.users.map(({ tokens_valid_after, ...account }) => account))
    for (const user of restoredUsers) assert(user.tokens_valid_after >= restoreStarted, 'restoring must revoke old tokens')
    run(old, ['-e', `const a=require('node:assert/strict'),d=require('./backend/services/db'),s=require('./backend/services/state');a.equal(s.WAF.paranoia_level,2);a.equal(d.getState('upgrade_marker').version,'previous');a.equal(d.getDb().prepare('PRAGMA integrity_check').get().integrity_check,'ok')`])
    // Upgrade the restored data again: no one-way migration damage.
    run(root, ['-e', `const a=require('node:assert/strict'),s=require('./backend/services/state'),tx=require('./backend/services/configTx');a.equal(s.WAF.paranoia_level,2);a.equal(tx.apply({label:'upgrade-again',reload:false,mutate:()=>{}}).ok,true)`])
    // Corruption must be rejected without changing either live state.
    const snapshot = inspect(), config = fs.readFileSync(env.CADDYFILE_PATH, 'utf8')
    const damaged = path.join(dir, 'damaged.json')
    fs.copyFileSync(path.join(dir, 'before.json'), damaged)
    fs.writeFileSync(path.join(dir, 'damaged.db'), fs.readFileSync(path.join(dir, 'before.db')).subarray(0, 128))
    const failed = JSON.parse(run(root, ['bin/catwaf.js', 'backup', 'restore', damaged, '--db', '--confirm-db-restore', '--json'], 1))
    assert.equal(failed.ok, false); assert.deepEqual(inspect(), snapshot); assert.equal(fs.readFileSync(env.CADDYFILE_PATH, 'utf8'), config)
    results.push({ previousVersion, edition, upgrade: 'passed', reopen: 'passed', offlineRollback: 'passed', reupgrade: 'passed', corruptBackupRejected: true, originalConfigBytes: Buffer.byteLength(beforeConfig) })
  } finally { fs.rmSync(dir, { recursive: true, force: true }) }
}
console.log(JSON.stringify({ status: 'passed', results }, null, 2))
