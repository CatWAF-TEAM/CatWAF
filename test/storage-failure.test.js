const test = require('node:test'), assert = require('node:assert/strict')
const fs = require('node:fs'), os = require('node:os'), path = require('node:path')
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-storage-failure-'))
Object.assign(process.env, { DB_DIR: dir, DB_PATH: path.join(dir, 'fixture.db'), CATWAF_EDITION: 'lite', CADDYFILE_PATH: path.join(dir, 'Caddyfile'), CORAZA_AUDIT_LOG: path.join(dir, 'audit.json'), CADDY_ADMIN_URL: 'http://127.0.0.1:1', CADDY_ADMIN_SOCKET: '' })
const db = require('../backend/services/db'), settings = require('../backend/services/settings')
test('settings storage failures never publish stale or incomplete policy', async t => {
  const conn = db.getDb()
  assert.equal(settings.set('tools_fingerprint', { enabled: true }).ok, true)
  const before = db.getState('ext:tools_fingerprint'), rev = db.getState('ext:__rev')
  await t.test('a rejected revision write rolls back the group and its cache', () => {
    conn.exec("CREATE TRIGGER reject_revision BEFORE INSERT ON waf_state WHEN NEW.key='ext:__rev' BEGIN SELECT RAISE(ABORT, 'revision unavailable'); END")
    try {
      for (const write of [() => settings.set('tools_fingerprint', { enabled: false }), () => settings.reset('tools_fingerprint'), () => settings.replace('tools_fingerprint', { enabled: false })]) {
        assert.throws(write, /revision unavailable/)
        assert.deepEqual(db.getState('ext:tools_fingerprint'), before)
        assert.equal(db.getState('ext:__rev'), rev)
        assert.equal(settings.get('tools_fingerprint').enabled, true)
      }
    } finally { conn.exec('DROP TRIGGER reject_revision') }
  })
  await t.test('invalid stored JSON does not silently disable protection', () => {
    for (const value of ['{broken', 'null', '[]', 'false']) {
      conn.prepare("UPDATE waf_state SET value=? WHERE key='ext:tools_fingerprint'").run(value)
      settings.reload()
      assert.throws(() => settings.get('tools_fingerprint'))
    }
    db.setState('ext:tools_fingerprint', before); settings.reload()
  })
  await t.test('a damaged revision does not serve cache or defer the next check', () => {
    conn.prepare("UPDATE waf_state SET value=? WHERE key='ext:__rev'").run('{broken')
    settings.reload()
    assert.throws(() => settings.get('tools_fingerprint'))
    assert.throws(() => settings.get('tools_fingerprint'))
    db.setState('ext:__rev', rev); settings.reload()
    assert.equal(settings.get('tools_fingerprint').enabled, true)
  })
  await t.test('a settings savepoint respects the surrounding configuration transaction', () => {
    conn.exec('BEGIN IMMEDIATE')
    try {
      assert.equal(settings.set('tools_fingerprint', { enabled: false }).ok, true)
      assert.equal(settings.get('tools_fingerprint').enabled, false)
    } finally { conn.exec('ROLLBACK'); settings.reload() }
    assert.deepEqual(db.getState('ext:tools_fingerprint'), before)
    assert.equal(db.getState('ext:__rev'), rev)
  })
})
test('audit rotation retains recovery evidence after storage failure', async t => {
  const audit = require('../backend/services/auditLog'), requestLog = require('../backend/services/requestLog')
  const base = process.env.CORAZA_AUDIT_LOG, file = process.env.CADDYFILE_PATH, sidecar = audit.stateFileFor(base)
  const next = path.join(dir, 'coraza-audit-20260101T000000Z.json')
  fs.writeFileSync(base, 'retired log\n'); fs.writeFileSync(next, 'current log\n')
  fs.writeFileSync(file, `SecAuditLog ${next}\n`)
  await t.test('an unresolved configuration rollback preserves both log paths and its marker', () => {
    const tx = require('../backend/services/configTx'), apply = tx.apply, recover = tx.recover
    fs.writeFileSync(file, `SecAuditLog ${base}\n`)
    tx.apply = () => ({ ok: false, error: 'rollback reload failed', rolledBack: false, recoveryRequired: true })
    let candidate
    try {
      const result = audit.rotate()
      candidate = result.to
      assert.equal(result.ok, false); assert.equal(result.rolledBack, false)
      assert.equal(result.pendingRetry, true); assert.equal(result.recoveryRequired, true)
      assert(fs.existsSync(base)); assert(fs.existsSync(candidate))
      const pending = audit.readState(base)
      assert.equal(pending.pending.to, candidate)
      tx.recover = () => { throw new Error('proxy recovery unavailable') }
      const retry = audit.maintain({ force: true })
      assert.equal(retry.ok, false); assert.match(retry.error, /proxy recovery unavailable/)
      assert.deepEqual(audit.readState(base), pending)
      assert(fs.existsSync(candidate))
    } finally {
      tx.apply = apply; tx.recover = recover
      if (candidate) fs.unlinkSync(candidate)
      if (fs.existsSync(sidecar)) fs.unlinkSync(sidecar)
      fs.writeFileSync(file, `SecAuditLog ${next}\n`)
    }
  })
  await t.test('failed ingestion cannot be overwritten by a second rotation', () => {
    const pending = { active: base, pending: { from: base, to: next, startedAt: new Date().toISOString() } }
    assert.equal(audit.writeState(base, pending), true)
    const drain = requestLog.drainFile
    requestLog.drainFile = () => ({ ingested: 0, error: 'storage unavailable' })
    try {
      const result = audit.maintain({ force: true })
      assert.equal(result.ok, false); assert.equal(result.pendingRetry, true)
      assert.deepEqual(audit.readState(base), pending)
      assert(fs.existsSync(base)); assert(fs.existsSync(next))
    } finally { requestLog.drainFile = drain; fs.unlinkSync(sidecar) }
  })
  await t.test('corrupt rotation metadata cannot authorize archive deletion', () => {
    fs.writeFileSync(sidecar, '{broken')
    try {
      assert.equal(audit.maintain({ force: true }).ok, false)
      assert(fs.existsSync(base)); assert(fs.existsSync(next))
    } finally { fs.unlinkSync(sidecar) }
  })
  await t.test('pruning protects the live Caddyfile log even when the sidecar is stale', () => {
    fs.utimesSync(next, new Date(0), new Date(0))
    assert.equal(audit.writeState(base, { active: base }), true)
    audit.prune({ CATWAF_AUDIT_RETENTION_DAYS: '1', CATWAF_AUDIT_MAX_FILES: '1' })
    assert(fs.existsSync(next), 'the configured active log must never be pruned')
    fs.unlinkSync(sidecar)
  })
})
