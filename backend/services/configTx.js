const fs = require('fs')
const path = require('path')
const { execFileSync } = require('child_process')

const state = require('./state')
const caddySvc = require('./caddy')
const configLock = require('./configLock')
const auditSvc = require('./audit')
const db = require('./db')

const MAX_BACKUPS = 20

function backupDir() {
  const dir = path.join(path.dirname(db.DB_PATH), 'backups')
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
  return dir
}

function pruneBackups() {
  try {
    const dir = backupDir()
    const files = fs.readdirSync(dir)
      .filter(f => f.startsWith('Caddyfile.'))
      .map(f => ({ f, t: fs.statSync(path.join(dir, f)).mtimeMs }))
      .sort((a, b) => b.t - a.t)
    for (const extra of files.slice(MAX_BACKUPS)) {
      try { fs.unlinkSync(path.join(dir, extra.f)) } catch {}
    }
  } catch {}
}

function backupCaddyfile() {
  const src = caddySvc.CADDYFILE_PATH
  if (!fs.existsSync(src)) return null
  const stamp = new Date().toISOString().replace(/[:.]/g, '-')
  const dest = path.join(backupDir(), `Caddyfile.${stamp}`)
  fs.writeFileSync(dest, fs.readFileSync(src), { mode: 0o600, flag: 'wx' })
  pruneBackups()
  return dest
}

function validateCaddyfile(filePath) {
  try {
    execFileSync('caddy', ['validate', '--config', filePath, '--adapter', 'caddyfile'], {
      timeout: 25000,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    return { ok: true, error: null }
  } catch (e) {
    const out = [e.stderr?.toString(), e.stdout?.toString(), e.message].filter(Boolean).join('\n')
    if (/ENOENT/.test(out) || e.code === 'ENOENT') return { ok: true, error: null, skipped: 'caddy binary not available' }
    const line = out.split('\n').map(l => l.trim()).find(l => /^Error:|error:/i.test(l) || /"level":"error"/.test(l))
    return { ok: false, error: line || out.split('\n')[0] || 'validation failed' }
  }
}

function snapshotWaf() {
  return JSON.parse(JSON.stringify({
    WAF: state.WAF,
    RULE_CATEGORIES: state.RULE_CATEGORIES,
    // The extended settings groups (services/settings) render into the same
    // Caddyfile, so a rollback that restored only state.WAF would leave a
    // half-applied configuration behind.
    SETTINGS: state.settings.snapshot(),
  }))
}

// Keys that must never be copied back onto a live object: a persisted
// snapshot carrying an own "__proto__" property would survive the JSON
// round-trip above, and Object.assign's [[Set]] semantics would turn it into
// an actual prototype change on state.WAF.
const UNSAFE_RESTORE_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

function safeAssign(target, source) {
  for (const [key, value] of Object.entries(source)) {
    if (UNSAFE_RESTORE_KEYS.has(key)) continue
    target[key] = value
  }
  return target
}

function restoreWaf(snap) {
  for (const key of Object.keys(state.WAF)) delete state.WAF[key]
  safeAssign(state.WAF, snap.WAF)
  for (const key of Object.keys(state.RULE_CATEGORIES)) delete state.RULE_CATEGORIES[key]
  safeAssign(state.RULE_CATEGORIES, snap.RULE_CATEGORIES)
  if (snap.SETTINGS) state.settings.restore(snap.SETTINGS)
  db.setState('waf', state.WAF)
  db.setState('rule_categories', state.RULE_CATEGORIES)
}


const assets = require('./render/util')
const crypto = require('crypto')
function journalPath() { return path.join(path.dirname(db.DB_PATH), 'config-transaction.json') }
function syncDirectory(dir) {
  if (process.platform === 'win32') return
  const fd = fs.openSync(dir, 'r')
  try { fs.fsyncSync(fd) } finally { fs.closeSync(fd) }
}
function removeJournal() {
  fs.unlinkSync(journalPath())
  syncDirectory(path.dirname(journalPath()))
}
function restoreFile(journal) {
  if (journal.previous === null) {
    if (fs.existsSync(caddySvc.CADDYFILE_PATH)) fs.unlinkSync(caddySvc.CADDYFILE_PATH)
  } else configLock.atomicWriteFileSync(caddySvc.CADDYFILE_PATH, journal.previous, { mode: 0o640 })
  syncDirectory(path.dirname(caddySvc.CADDYFILE_PATH))
}

// The marker is committed in the SAME SQLite transaction as the settings.
// A crash before commit restores the prior Caddyfile; after commit retains
// the new one. Old assets are immutable and remain available for rollback.
function recoverLocked() {
  if (!fs.existsSync(journalPath())) return { recovered: false }
  const journal = JSON.parse(fs.readFileSync(journalPath(), 'utf8'))
  if (journal.version !== 1 || !/^[a-f0-9-]{36}$/.test(journal.id) || journal.caddyfile !== caddySvc.CADDYFILE_PATH || !(journal.previous === null || typeof journal.previous === 'string')) {
    throw new Error('Invalid configuration recovery journal; refusing to change configuration')
  }
  const committed = db.getState('config_tx_commit') === journal.id
  if (!committed) {
    restoreFile(journal)
    if (journal.wasRunning) {
      const result = caddySvc.reloadCaddy()
      if (!result.reloaded) throw new Error('Configuration recovery needs a successful reload of the previous configuration: ' + result.error)
    }
    assets.discardGeneration(journal.id)
  }
  removeJournal()
  state.reloadAllFromDb()
  return { recovered: true, committed }
}
function recover() { return configLock.withConfigLock(recoverLocked) }
function assertReady() {
  if (db.getState('database_restore_pending')) throw new Error('Database restore is incomplete. Apply the matching backup manifest with catwaf backup restore <backup.json> before starting services.')
}

function apply({ label, req = null, mutate, validate = null, reload = true, caddyfile = null, render = true, completeDatabaseRestore = false }) {
  return configLock.withConfigLock(() => {
    recoverLocked()
    if (!completeDatabaseRestore) assertReady()
    state.reloadAllFromDb()
    const auditLog = caddySvc.ensureAuditLog()
    if (!auditLog.ok) return { ok: false, phase: 'audit-log', error: auditLog.error }
    const file = caddySvc.CADDYFILE_PATH
    const previous = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : null
    let backup
    try { backup = backupCaddyfile() }
    catch (error) { return { ok: false, phase: 'backup', error: error.message } }
    const id = crypto.randomUUID()
    const candidate = path.join(path.dirname(file), '.catwaf-candidate-' + id)
    const conn = db.getDb()
    const synchronous = conn.prepare('PRAGMA synchronous').get().synchronous
    let phase = 'begin', published = false, reloadAttempted = false, transaction = false, journalWritten = false
    let wasRunning = false
    try {
      conn.exec('PRAGMA synchronous = FULL; BEGIN IMMEDIATE')
      transaction = true
      phase = 'mutate'
      const result = mutate(state)
      if (result && typeof result.then === 'function') throw new Error('Configuration mutations must be synchronous')
      phase = 'validate'
      const checked = validate ? validate(state) : null
      if (checked && checked.ok === false) throw new Error(checked.error || 'validation failed')
      phase = 'persist'
      state.saveWAF(true)
      db.setState('rule_categories', state.RULE_CATEGORIES)
      phase = 'render'
      const source = caddyfile === null ? (previous || '') : caddyfile
      const content = render ? assets.withAssetGeneration(() => caddySvc.renderCaddyfile(source, state.WAF), id) : source
      assets.syncGeneration(id)
      configLock.atomicWriteFileSync(candidate, content, { mode: 0o640 })
      phase = 'caddy-validate'
      const validation = module.exports.validateCaddyfile(candidate)
      if (!validation.ok) throw new Error(validation.error)
      if (completeDatabaseRestore && db.getState('database_restore_pending') && validation.skipped) throw new Error('Finishing a database restore requires a local Caddy/Coraza binary to validate the restored configuration.')
      wasRunning = reload && caddySvc.isAdminReachable()
      const journal = { version: 1, id, caddyfile: file, previous, wasRunning }
      phase = 'journal'
      configLock.atomicWriteFileSync(journalPath(), JSON.stringify(journal), { mode: 0o600 })
      syncDirectory(path.dirname(journalPath()))
      journalWritten = true
      phase = 'publish'
      configLock.atomicWriteFileSync(file, content, { mode: 0o640 })
      published = true
      syncDirectory(path.dirname(file))
      phase = 'reload'
      let loaded = { reloaded: false, error: null }
      if (reload) {
        reloadAttempted = true
        loaded = caddySvc.reloadCaddy()
        if (!loaded.reloaded && wasRunning) throw new Error(loaded.error || 'Caddy reload failed')
      }
      phase = 'commit'
      db.setState('config_tx_commit', id)
      if (completeDatabaseRestore) db.setState('database_restore_pending', null)
      conn.exec('COMMIT')
      transaction = false
      // Failure to remove the journal after commit is recoverable: the
      // committed marker prevents a later startup undoing this success.
      let cleanupWarning = null
      try { removeJournal(); journalWritten = false } catch (error) { cleanupWarning = error.message }
      try { auditSvc.audit(req, label, '', { reloaded: !!loaded.reloaded, engine: state.WAF.engine, paranoia_level: state.WAF.paranoia_level }) } catch {}
      return { ok: true, reloaded: !!loaded.reloaded, reloadError: loaded.error || null, backup, result, validationSkipped: validation.skipped || null, cleanupWarning }
    } catch (error) {
      const rollbackErrors = []
      if (transaction) {
        try {
          // SQLITE_FULL and some I/O failures automatically abort SQLite's
          // transaction. Consult autocommit state before issuing ROLLBACK;
          // an already completed rollback is not a recovery failure.
          if (conn.isTransaction) conn.exec('ROLLBACK')
          transaction = false
        } catch (e) { rollbackErrors.push('database: ' + e.message) }
      }
      try { state.reloadAllFromDb() } catch (e) { rollbackErrors.push('state cache: ' + e.message) }
      if (published) {
        try { restoreFile({ previous }) } catch (e) { rollbackErrors.push('Caddyfile: ' + e.message) }
      }
      if (reloadAttempted && wasRunning) {
        try {
          const restored = caddySvc.reloadCaddy()
          if (!restored.reloaded) throw new Error(restored.error || 'reload failed')
        } catch (e) { rollbackErrors.push('Caddy reload: ' + e.message) }
      }
      if (!rollbackErrors.length) {
        try { assets.discardGeneration(id) } catch (e) { rollbackErrors.push('candidate assets: ' + e.message) }
      }
      if (journalWritten && !rollbackErrors.length) {
        try { removeJournal() } catch (e) { rollbackErrors.push('recovery journal: ' + e.message) }
      }
      try { auditSvc.audit(req, label + '.rollback', '', { reason: error.message, rollbackErrors }) } catch {}
      return { ok: false, phase, error: error.message, rolledBack: rollbackErrors.length === 0, rollbackErrors, recoveryRequired: rollbackErrors.length > 0, backup }
    } finally {
      try { fs.unlinkSync(candidate) } catch {}
      if (!transaction) conn.exec('PRAGMA synchronous = ' + Number(synchronous))
    }
  })
}

module.exports = { apply, recover, assertReady, backupCaddyfile, validateCaddyfile, snapshotWaf, restoreWaf, backupDir, journalPath }
