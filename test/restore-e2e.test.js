// A real offline restore through the CLI, SQLite and Caddy validator.
const test = require('node:test'), assert = require('node:assert/strict')
const fs = require('node:fs'), os = require('node:os'), path = require('node:path')
const { spawnSync } = require('node:child_process')
const { DatabaseSync } = require('node:sqlite')
const root = path.resolve(__dirname, '..')
const available = spawnSync('caddy', ['list-modules'], { encoding: 'utf8', windowsHide: true })
test('offline CLI restores database and validated configuration together', { skip: available.status !== 0 || !available.stdout.includes('http.handlers.waf') }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-restore-e2e-'))
  const env = { ...process.env, DB_DIR: dir, DB_PATH: path.join(dir, 'catwaf.db'), CADDYFILE_PATH: path.join(dir, 'Caddyfile'), CORAZA_AUDIT_LOG: path.join(dir, 'audit.json'), CADDY_ADMIN_URL: 'http://127.0.0.1:1', CADDY_ADMIN_SOCKET: '', JWT_SECRET: 'offline-restore-fixture-secret-1234567890', CATWAF_EDITION: 'full' }
  const run = args => spawnSync(process.execPath, args, { cwd: root, env, encoding: 'utf8', timeout: 60000, windowsHide: true })
  try {
    fs.writeFileSync(env.CADDYFILE_PATH, ':19993 {\n respond "restore fixture"\n}\n')
    const setup = run(['-e', `const fs=require('fs'),path=require('path'),d=require('./backend/services/db'),s=require('./backend/services/state');
      require('./backend/middleware/auth').addUser({username:'owner',password:'offline-fixture-password',role:'admin'});
      d.setState('restore_marker','backup'); d.setState('admin_sessions',{old:{username:'owner'}});
      fs.writeFileSync(path.join(process.env.DB_DIR,'restore.json'),JSON.stringify({waf:s.WAF,caddyfile:fs.readFileSync(process.env.CADDYFILE_PATH,'utf8')}));
      d.getDb().prepare('VACUUM INTO ?').run(path.join(process.env.DB_DIR,'restore.db')); d.setState('restore_marker','live');`])
    assert.equal(setup.status, 0, setup.stderr)
    const result = run(['bin/catwaf.js', 'backup', 'restore', path.join(dir, 'restore.json'), '--db', '--confirm-db-restore', '--json'])
    assert.equal(result.status, 0, result.stdout + result.stderr)
    const restored = JSON.parse(result.stdout)
    assert.equal(restored.ok, true)
    assert.equal(restored.database.sessions_revoked, true)
    assert.equal(restored.database.requires_config_apply, false)
    assert.equal(fs.existsSync(restored.database.recoveryCopy), true)
    const db = new DatabaseSync(env.DB_PATH, { readOnly: true })
    const read = key => JSON.parse(db.prepare('SELECT value FROM waf_state WHERE key=?').get(key).value)
    try {
      assert.equal(read('restore_marker'), 'backup')
      assert.deepEqual(read('admin_sessions'), {})
      assert.equal(read('database_restore_pending'), null)
    } finally { db.close() }
    assert.match(fs.readFileSync(env.CADDYFILE_PATH, 'utf8'), /SecRuleEngine On/)
  } finally { fs.rmSync(dir, { recursive: true, force: true }) }
})
