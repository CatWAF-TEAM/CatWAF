const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs'), os = require('node:os'), path = require('node:path')
const { spawn, spawnSync, execFileSync } = require('node:child_process')
const { DatabaseSync } = require('node:sqlite')
const root = path.resolve(__dirname, '..')
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-recovery-'))
Object.assign(process.env, { DB_DIR: dir, DB_PATH: path.join(dir, 'live.db'), CADDYFILE_PATH: path.join(dir, 'Caddyfile'), CORAZA_AUDIT_LOG: path.join(dir, 'audit.log'), CADDY_ADMIN_URL: 'http://127.0.0.1:1', CADDY_ADMIN_SOCKET: '', JWT_SECRET: 'recovery-tests-only-root-secret-1234567890', CATWAF_EDITION: 'full' })
fs.writeFileSync(process.env.CADDYFILE_PATH, ':19992 {\n respond "fixture"\n}\n')
const db = require('../backend/services/db'), state = require('../backend/services/state')
const caddy = require('../backend/services/caddy'), tx = require('../backend/services/configTx')
const assets = require('../backend/services/render/util'), backups = require('../backend/services/backups')
const actualRender = caddy.renderCaddyfile, actualValidate = tx.validateCaddyfile
const actualReload = caddy.reloadCaddy, actualReachable = caddy.isAdminReachable
function fixtureRender() { return ':19992 {\n respond "fixture"\n}\n# asset ' + assets.writeAsset('errors/403.html', 'page-' + state.WAF.paranoia_level) + '\n' }
function snapshot() { return { file: fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8'), waf: db.getState('waf'), settings: state.settings.snapshot() } }
function assertRestored(before, result) {
  assert.equal(result.ok, false)
  assert.equal(result.rolledBack, true, JSON.stringify(result))
  assert.equal(fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8'), before.file)
  assert.deepEqual(db.getState('waf'), before.waf)
  assert.deepEqual(state.settings.snapshot(), before.settings)
  const oldAsset = before.file.match(/# asset (.+)/)[1]
  assert.equal(fs.readFileSync(oldAsset, 'utf8'), 'page-' + before.waf.paranoia_level)
  assert.equal(fs.existsSync(tx.journalPath()), false)
}

test('configuration activation and offline restore regressions', async t => {
  caddy.renderCaddyfile = fixtureRender
  caddy.isAdminReachable = () => true
  caddy.reloadCaddy = () => ({ reloaded: true })
  tx.validateCaddyfile = () => ({ ok: true })
  t.after(() => { caddy.renderCaddyfile = actualRender; caddy.reloadCaddy = actualReload; caddy.isAdminReachable = actualReachable; tx.validateCaddyfile = actualValidate })
  assert.equal(tx.apply({ label: 'fixture', mutate: s => { s.WAF.paranoia_level = 1 } }).ok, true)
  const before = snapshot()

  await t.test('throwing mutation and validator roll back database writes', () => {
    for (const fault of ['mutation', 'validator']) {
      const result = tx.apply({ label: fault, mutate: s => {
        s.WAF.paranoia_level = 3; s.settings.set('error_pages', { enabled: true })
        if (fault === 'mutation') throw new Error('mutation fault')
      }, validate: () => { throw new Error('validation fault') } })
      assertRestored(before, result)
    }
  })
  await t.test('separate readers never observe uncommitted candidate settings', () => {
    const result = tx.apply({ label: 'reader', mutate: s => {
      s.settings.set('error_pages', { enabled: true })
      const script = `const {DatabaseSync}=require('node:sqlite');const d=new DatabaseSync(process.env.DB_PATH,{readOnly:true});console.log(JSON.stringify(d.prepare("SELECT value FROM waf_state WHERE key='ext:error_pages'").get()||null));d.close()`
      const row = JSON.parse(execFileSync(process.execPath, ['-e', script], { encoding: 'utf8', windowsHide: true }))
      assert.equal(row ? JSON.parse(row.value).enabled : false, before.settings.error_pages.enabled)
      throw new Error('abort after read')
    } })
    assertRestored(before, result)
  })
  await t.test('failed Caddy validation never replaces active assets or Caddyfile', () => {
    tx.validateCaddyfile = () => ({ ok: false, error: 'invalid candidate' })
    try { assertRestored(before, tx.apply({ label: 'invalid', mutate: s => { s.WAF.paranoia_level = 3 } })) }
    finally { tx.validateCaddyfile = () => ({ ok: true }) }
  })
  await t.test('WAF API and CatAI mutation entry points also roll back rejected changes', () => {
    tx.validateCaddyfile = () => ({ ok: false, error: 'reject configuration' })
    try {
      assert.throws(() => state.updateWAF(w => { w.engine = 'Off' }, { syncCaddy: true }), /Configuration update failed/)
      assert.deepEqual(snapshot(), before)
      const result = require('../backend/services/catai/actions').apply('geo.block', { cc: 'US' }, null)
      assertRestored(before, result)
    } finally { tx.validateCaddyfile = () => ({ ok: true }) }
  })
  await t.test('failed reload and failed commit restore previous configuration and assets', () => {
    let calls = 0
    caddy.reloadCaddy = () => (++calls === 1 ? { reloaded: false, error: 'reload fault' } : { reloaded: true })
    assertRestored(before, tx.apply({ label: 'reload', mutate: s => { s.WAF.paranoia_level = 3 } }))
    assert.equal(calls, 2)
    caddy.reloadCaddy = () => ({ reloaded: true })
    const conn = db.getDb(), exec = conn.exec
    conn.exec = function (sql) { if (sql === 'COMMIT') throw new Error('commit fault'); return exec.call(this, sql) }
    try { assertRestored(before, tx.apply({ label: 'commit', mutate: s => { s.WAF.paranoia_level = 3 } })) }
    finally { conn.exec = exec }
  })
  await t.test('rollback failures are reported and retained for recovery', () => {
    caddy.reloadCaddy = () => ({ reloaded: false, error: 'unavailable' })
    const result = tx.apply({ label: 'rollback-fails', mutate: s => { s.WAF.paranoia_level = 3 } })
    assert.equal(result.ok, false); assert.equal(result.rolledBack, false); assert.equal(result.recoveryRequired, true)
    assert.equal(fs.existsSync(tx.journalPath()), true)
    caddy.reloadCaddy = () => ({ reloaded: true })
    assert.equal(tx.recover().committed, false)
    assert.deepEqual(snapshot(), before)
  })
  await t.test('crash before SQLite commit restores old files; crash after commit retains new files', () => {
    for (const afterCommit of [false, true]) {
      const script = `const fs=require('fs');const c=require('./backend/services/caddy');const t=require('./backend/services/configTx');const d=require('./backend/services/db');c.isAdminReachable=()=>false;t.validateCaddyfile=()=>({ok:true});
      ${afterCommit ? `const exec=d.getDb().exec;d.getDb().exec=function(s){const r=exec.call(this,s);if(s==='COMMIT')process.exit(73);return r};` : `const rename=fs.renameSync;fs.renameSync=function(a,b){const r=rename(a,b);if(b===process.env.CADDYFILE_PATH)process.exit(73);return r};`}
      t.apply({label:'crash',reload:false,mutate:s=>{s.WAF.paranoia_level=${afterCommit ? 4 : 3};s.settings.set('error_pages',{enabled:true,pages:[{status:403,html:'crash-test'}]})}})`
      const child = spawnSync(process.execPath, ['-e', script], { cwd: root, windowsHide: true, encoding: 'utf8' })
      assert.equal(child.status, 73, child.stderr)
      assert.equal(fs.existsSync(tx.journalPath()), true)
      const result = tx.recover()
      assert.equal(result.committed, afterCommit)
      assert.equal(state.WAF.paranoia_level, afterCommit ? 4 : 1)
      if (!afterCommit) assert.equal(fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8'), before.file)
    }
  })
  await t.test('requesting DB restore cannot apply a manifest before confirmation', () => {
    const manifest = path.join(dir, 'manifest.json')
    fs.writeFileSync(manifest, JSON.stringify({ waf: { ...state.WAF, paranoia_level: 2 } }))
    const saved = snapshot()
    const result = backups.restoreFromFile(manifest, { restoreDatabase: true })
    assert.equal(result.ok, false); assert.equal(result.database.requires_stopped_services, true)
    assert.deepEqual(snapshot(), saved)
  })
  const backup = path.join(dir, 'restore.db')
  caddy.isAdminReachable = () => false
  require('../backend/middleware/auth').addUser({ username: 'owner', password: 'restore-test-password', role: 'admin' })
  db.setState('restore_marker', 'backup')
  db.setState('admin_sessions', { historical: { username: 'owner' } })
  db.getDb().prepare('VACUUM INTO ?').run(backup)
  db.setState('restore_marker', 'live')
  await t.test('an idle process blocks restore even with old or empty WAL', async () => {
    const child = spawn(process.execPath, ['-e', "require('./backend/services/db');console.log('ready');setInterval(()=>{},1000)"], { cwd: root, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] })
    await new Promise((resolve, reject) => { child.stdout.once('data', resolve); child.once('error', reject); child.once('exit', code => reject(new Error('child exited ' + code))) })
    try {
      const result = backups.confirmDatabaseRestore(backup)
      assert.equal(result.ok, false); assert.match(result.error, /Another CatWAF process/)
      assert.equal(db.getState('restore_marker'), 'live')
    } finally { child.kill(); await new Promise(resolve => child.once('exit', resolve)) }
  })
  await t.test('SQLite restore preserves inode, protects prior data and revokes historical sessions', () => {
    const inode = fs.statSync(db.DB_PATH).ino
    const observer = new DatabaseSync(db.DB_PATH)
    try {
      const result = backups.confirmDatabaseRestore(backup)
      assert.equal(result.ok, true, JSON.stringify(result))
      assert.equal(fs.statSync(db.DB_PATH).ino, inode)
      assert.equal(db.getState('restore_marker'), 'backup')
      assert.equal(JSON.parse(observer.prepare("SELECT value FROM waf_state WHERE key='restore_marker'").get().value), 'backup')
      assert.deepEqual(db.getState('admin_sessions'), {})
      assert.throws(() => tx.assertReady(), /restore is incomplete/)
      assert.ok(db.getState('users')[0].tokens_valid_after > 0)
      const old = new DatabaseSync(result.recoveryCopy, { readOnly: true })
      try { assert.equal(JSON.parse(old.prepare("SELECT value FROM waf_state WHERE key='restore_marker'").get().value), 'live') } finally { old.close() }
    } finally { observer.close() }
  })
  await t.test('invalid backup is refused without modifying live data', () => {
    const broken = path.join(dir, 'broken.db'); fs.writeFileSync(broken, 'not a database')
    assert.equal(backups.confirmDatabaseRestore(broken).ok, false)
    assert.equal(db.getState('restore_marker'), 'backup')
  })
  await t.test('incompatible schema is refused before modifying the live database', () => {
    const wrong = path.join(dir, 'wrong-schema.db')
    const source = new DatabaseSync(wrong)
    source.exec('CREATE TABLE waf_state (key TEXT PRIMARY KEY, value TEXT NOT NULL, extra TEXT)')
    source.close()
    const result = backups.confirmDatabaseRestore(wrong)
    assert.equal(result.ok, false); assert.match(result.error, /Unknown columns/)
    assert.equal(db.getState('restore_marker'), 'backup')
  })
  await t.test('only a successful manifest apply clears the incomplete-restore guard', () => {
    const manifest = path.join(dir, 'complete.json')
    fs.writeFileSync(manifest, JSON.stringify({ waf: state.WAF }))
    tx.validateCaddyfile = () => ({ ok: false, error: 'invalid manifest configuration' })
    assert.equal(backups.restoreFromFile(manifest).ok, false)
    assert.throws(() => tx.assertReady(), /restore is incomplete/)
    tx.validateCaddyfile = () => ({ ok: true })
    assert.equal(backups.restoreFromFile(manifest).ok, true)
    assert.doesNotThrow(() => tx.assertReady())
  })
  await t.test('Caddy installer rejects known-vulnerable compiler and HTTP dependencies', () => {
    const { meetsSecurityBaseline } = require('../scripts/ensure-caddy')
    const valid = 'go\tgo1.26.9\ndep\tgithub.com/caddyserver/caddy/v2\tv2.11.7\ndep\tgithub.com/corazawaf/coraza-caddy/v2\tv2.6.2\ndep\tgolang.org/x/net\tv0.61.0\n'
    assert.equal(meetsSecurityBaseline(valid), true)
    assert.equal(meetsSecurityBaseline(valid.replace('go1.26.9', 'go1.26.7')), false)
    assert.equal(meetsSecurityBaseline(valid.replace('v0.61.0', 'v0.59.0')), false)
    assert.equal(meetsSecurityBaseline(''), false)
  })
  await t.test('the documented default header limit survives backup validation', () => {
    const settings = require('../backend/services/settings')
    const { defaultsFor } = require('../backend/services/settings/schema')
    assert.equal(defaultsFor('access').max_header_size_kb, 0)
    assert.equal(settings.validate('access', defaultsFor('access'), { merge: false }).ok, true)
    assert.equal(settings.validate('access', { max_header_size_kb: -1 }).ok, false)
    assert.equal(settings.validate('access', { max_header_size_kb: 1025 }).ok, false)
  })
  await t.test('CLI confirmation reports active-process refusal as failure', () => {
    const manifest = path.join(dir, 'restore.json')
    fs.writeFileSync(manifest, JSON.stringify({ waf: state.WAF }))
    const child = spawnSync(process.execPath, ['bin/catwaf.js', 'backup', 'restore', manifest, '--db', '--confirm-db-restore', '--json'], { cwd: root, encoding: 'utf8', windowsHide: true })
    assert.equal(child.status, 1, child.stdout + child.stderr)
    assert.match(child.stdout + child.stderr, /Another CatWAF process/)
  })
})
