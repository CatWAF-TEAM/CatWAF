// backups.js — scheduled off-box backups (idea #45).
//
// snapshots.js already covers "undo my last change": in-place, in the same
// database, on the same disk. That is the wrong tool for the failure it does
// not cover — if the disk or the whole server is lost, every snapshot goes
// with it. This copies the configuration somewhere else, on a schedule,
// with bounded retention.
//
// Reuses snapshots.js's redaction so a backup file cannot become the place
// where API tokens and password hashes leak; the redacted copy is what is
// written, and restore() is explicit that secrets have to be re-entered.

const fs = require('fs')
const { execFileSync } = require('child_process')
const path = require('path')
const crypto = require('crypto')

const db = require('./db')
const state = require('./state')
const settings = require('./settings')
const configLock = require('./configLock')
const caddySvc = require('./caddy')
const snapshots = require('./snapshots')
const logger = require('./logger')
const { version: pkgVersion } = require('../../package.json')

const log = logger.child('backups')
const FILE_RE = /^catwaf-backup-(\d{8}T\d{6})\.json$/

function stamp(date = new Date()) {
  return date.toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, '').replace('T', 'T')
}

function assertDestination(dir) {
  if (!dir) throw new Error('No backup destination is configured.')
  if (!path.isAbsolute(dir)) throw new Error('The backup destination must be an absolute path.')
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
  fs.accessSync(dir, fs.constants.W_OK)
  return dir
}

function buildPayload({ redact = true } = {}) {
  const cfg = settings.get('backups')
  const payload = {
    catwaf_version: pkgVersion,
    created_at: new Date().toISOString(),
    redacted: redact,
    waf: state.WAF,
    rule_categories: state.RULE_CATEGORIES,
    settings: redact ? settings.getAllRedacted() : settings.getAll(),
  }
  if (cfg.include_caddyfile) {
    try {
      const text = caddySvc.readCaddyfile()
      payload.caddyfile = redact ? caddySvc.redactCaddyfile(text) : text
    } catch (e) { payload.caddyfile_error = e.message }
  }
  return redact ? snapshots.redactSecrets(payload) : payload
}

// A caller-supplied destination must resolve inside the configured backup
// root. Without this containment, an authenticated write-enabled request
// could point backups.run() at any writable absolute directory and have
// CatWAF stage a 0600 copy of the entire SQLite database there — plus prune()
// would delete any pre-existing "catwaf-backup-*" files in that directory.
function containedDestination(candidate, configuredRoot) {
  const requested = path.resolve(String(candidate))
  if (!configuredRoot) {
    // No configured root: fall back to CatWAF's own data directory so the
    // feature still works on a fresh install where nothing was configured.
    return { ok: true, dir: path.resolve(db.DB_DIR) }
  }
  const root = path.resolve(configuredRoot)
  const rel = path.relative(root, requested)
  if (rel === '' || (rel && !rel.startsWith('..') && !path.isAbsolute(rel))) {
    return { ok: true, dir: requested }
  }
  return {
    ok: false,
    error: `Backup destinations must live under the configured backup directory (${root}). Set a new destination in Settings → Backups first.`,
  }
}

function run({ dryRun = false, destination = null } = {}) {
  const cfg = settings.get('backups')
  if (!cfg.enabled && !destination) return { ok: true, skipped: 'disabled', changed: false }

  let dir
  if (destination) {
    const check = containedDestination(destination, cfg.destination)
    if (!check.ok) throw new Error(check.error)
    dir = assertDestination(check.dir)
  } else {
    dir = assertDestination(cfg.destination)
  }
  const payload = buildPayload({ redact: cfg.redact_secrets })
  const name = `catwaf-backup-${stamp()}.json`
  const target = path.join(dir, name)

  if (dryRun) {
    return { ok: true, dryRun: true, would_write: target + (settings.get('backups').encrypt ? '.enc' : ''), bytes: Buffer.byteLength(JSON.stringify(payload)) }
  }

  // Write plaintext to a temp file, then either rename it into place or
  // encrypt it there and destroy the plaintext — an interrupted backup
  // never leaves a truncated file that looks complete, and with encryption
  // on the plaintext only ever exists inside this directory for milliseconds.
  const tmpPlain = `${target}.partial`
  const plain = Buffer.from(JSON.stringify(payload, null, 2), 'utf8')
  let finalTarget = target
  try {
    if (cfg.encrypt) {
      encryptBufferToFile(plain, finalTarget + '.enc')
    } else {
      configLock.atomicWriteFileSync(target, plain, { mode: 0o600 })
    }
  } catch (e) {
    try { fs.unlinkSync(tmpPlain) } catch {}
    try { fs.unlinkSync(finalTarget + '.enc') } catch {}
    throw e
  }
  if (cfg.encrypt) finalTarget = finalTarget + '.enc'

  let dbCopy = null
  if (cfg.include_database) {
    const stampDb = name.replace(/\.json$/, '')
    try {
      // VACUUM INTO takes a consistent SQLite snapshot, including committed
      // WAL pages. A checkpoint followed by a file copy races active writers.
      const stage = path.join(dir, `${stampDb}.${crypto.randomBytes(8).toString('hex')}.db.partial`)
      try {
        fs.closeSync(fs.openSync(stage, 'wx', 0o600))
        db.getDb().prepare('VACUUM INTO ?').run(stage)
        if (cfg.encrypt) {
          dbCopy = path.join(dir, `${stampDb}.db.enc`)
          // Plaintext exists only for this copy+encrypt window; any failure
          // destroys it rather than leaving a readable database behind.
          try {
            encryptBufferToFile(fs.readFileSync(stage), dbCopy)
            fs.unlinkSync(stage)
          } catch (e) {
            try { fs.unlinkSync(stage) } catch {}
            throw e
          }
        } else {
          dbCopy = path.join(dir, `${stampDb}.db`)
          fs.renameSync(stage, dbCopy)
          fs.chmodSync(dbCopy, 0o600)
        }
      } catch (e) {
        try { fs.unlinkSync(stage) } catch {}
        dbCopy = null
        log.error('Could not copy the database into the backup', { error: e.message })
      }
    } catch (e) {
      dbCopy = null
      log.error('Could not copy the database into the backup', { error: e.message })
    }
  }

  const pruned = prune(dir, cfg.retain)
  log.info('Backup written', { target: finalTarget, database: !!dbCopy, pruned: pruned.removed })
  return { ok: true, file: finalTarget, encrypted: cfg.encrypt, database: dbCopy, pruned: pruned.removed, changed: true }
}

function prune(dir, retain) {
  const keep = Math.max(1, retain)
  const removed = []
  try {
    const files = fs.readdirSync(dir)
      .filter(f => f.startsWith('catwaf-backup-'))
      .map(f => ({ f, t: fs.statSync(path.join(dir, f)).mtimeMs }))
      .sort((a, b) => b.t - a.t)

    // Retention counts manifests (plain or .enc); each manifest's database
    // sibling — plain or encrypted — is pruned with it so they never drift.
    const manifests = files.filter(x => /\.json(\.enc)?$/.test(x.f))
    for (const extra of manifests.slice(keep)) {
      try { fs.unlinkSync(path.join(dir, extra.f)); removed.push(extra.f) } catch {}
      const base = extra.f.replace(/\.json(\.enc)?$/, '')
      for (const sibling of [base + '.db', base + '.db.enc']) {
        try { fs.unlinkSync(path.join(dir, sibling)); removed.push(path.basename(sibling)) } catch {}
      }
    }
  } catch (e) {
    return { removed: removed.length, error: e.message }
  }
  return { removed: removed.length, files: removed }
}

function list() {
  const cfg = settings.get('backups')
  if (!cfg.destination) return { ok: true, destination: null, backups: [] }
  try {
    const ARTIFACT_RE = /^catwaf-backup-\d{8}T\d{6}\.json(\.enc)?$/
    const entries = fs.readdirSync(cfg.destination)
      .filter(f => ARTIFACT_RE.test(f) || FILE_RE.test(f))
      .map(f => {
        const st = fs.statSync(path.join(cfg.destination, f))
        const base = f.replace(/\.json(\.enc)?$/, '')
        const dbSibling = [base + '.db', base + '.db.enc'].map(s => path.join(cfg.destination, s)).find(p => fs.existsSync(p))
        return {
          name: f,
          size_bytes: st.size,
          created_at: st.mtime.toISOString(),
          has_database: !!dbSibling,
          encrypted: f.endsWith('.enc'),
        }
      })
      .sort((a, b) => b.created_at.localeCompare(a.created_at))
    return { ok: true, destination: cfg.destination, backups: entries, retain: cfg.retain }
  } catch (e) {
    return { ok: false, destination: cfg.destination, error: e.message, backups: [] }
  }
}

function verifyDestination(destination) {
  try {
    const cfg = settings.get('backups')
    const check = containedDestination(destination || cfg.destination, cfg.destination)
    if (!check.ok) return { ok: false, error: check.error }
    const dir = assertDestination(check.dir)
    const probe = path.join(dir, `.catwaf-write-test-${crypto.randomBytes(12).toString('hex')}`)
    fs.writeFileSync(probe, 'ok', { mode: 0o600, flag: 'wx' })
    fs.unlinkSync(probe)
    return { ok: true, destination: dir }
  } catch (e) {
    return { ok: false, error: e.message }
  }
}

// ── Restore ─────────────────────────────────────────────────────────────
//
// The write half of backups existed for a long time; this is the read half.
// Restoring is deliberately stricter than writing: a backup is an arbitrary
// file the operator points at, so everything it contains is re-validated
// before any of it touches live state.

function restoreFromFile(filePath, { restoreDatabase = false, allowRedacted = false } = {}) {
  const resolved = path.resolve(String(filePath || ''))
  if (!fs.existsSync(resolved)) return { ok: false, error: `No such file: ${resolved}` }

  let rawText
  if (isEncrypted(resolved)) {
    try {
      rawText = decryptFileToBuffer(resolved).toString('utf8')
    } catch (e) {
      return { ok: false, error: `Could not decrypt this backup: ${e.message}` }
    }
  } else {
    try { rawText = fs.readFileSync(resolved, 'utf8') } catch (e) {
      return { ok: false, error: `Cannot read ${resolved}: ${e.message}` }
    }
  }

  let manifest
  try {
    manifest = JSON.parse(rawText)
  } catch (e) {
    return { ok: false, error: `Not a readable CatWAF backup (JSON parse failed): ${e.message}` }
  }
  if (!manifest || typeof manifest !== 'object' || !manifest.waf) {
    return { ok: false, error: 'This file does not look like a CatWAF backup (missing the "waf" section).' }
  }
  if (manifest.redacted && !allowRedacted) {
    return {
      ok: false,
      error: 'This backup was written with secrets redacted. Restoring it would erase every stored secret. Re-run with --allow-redacted if that is genuinely what you want.',
      code: 'REDACTED',
    }
  }

  // Validate the WAF section exactly as a live write would.
  const sanitize = require('./sanitize')
  const check = sanitize.validateWafState(manifest.waf)
  if (!check.valid) return { ok: false, error: `Backup WAF state failed validation: ${check.errors.join('; ')}` }
  const restoredSettings = {}
  if (manifest.settings != null) {
    if (!manifest.settings || typeof manifest.settings !== 'object' || Array.isArray(manifest.settings)) return { ok: false, error: 'Backup settings must be an object.' }
    for (const [group, value] of Object.entries(manifest.settings)) {
      if (!settings.isGroup(group)) return { ok: false, error: `Unknown backup settings group: ${group}` }
      if (!value || typeof value !== 'object' || Array.isArray(value)) return { ok: false, error: `Invalid backup settings group: ${group}` }
      const patch = { ...value }
      for (const [field, spec] of Object.entries(settings.SCHEMA[group].fields)) {
        if (spec.writeOnly) delete patch[`${field}_set`]
      }
      const validated = settings.validate(group, patch, { merge: false })
      if (!validated.ok) return { ok: false, error: `Backup settings failed validation: ${group}: ${validated.error}` }
      restoredSettings[group] = validated.value
    }
  }

  // A database restore is a separate offline operation. Never partially
  // apply the manifest before asking for the explicit offline action.
  if (restoreDatabase) {
    return { ok: false, error: 'Database restore requires stopped services and --confirm-db-restore.',
      database: { ok: false, requires_stopped_services: true, instruction: 'Stop every CatWAF process, then repeat with --db --confirm-db-restore.' } }
  }
  const configTx = require('./configTx')
  const hadCaddyfile = fs.existsSync(caddySvc.CADDYFILE_PATH)
  let previousCaddyfile = null
  try { previousCaddyfile = hadCaddyfile ? fs.readFileSync(caddySvc.CADDYFILE_PATH, 'utf8') : null } catch {}

  // Config restore goes through the transaction pipeline: snapshot → apply
  // → render → validate → reload, rolling back both state and file on any
  // failure — identical guarantees to every other configuration change.
  const tx = configTx.apply({
    label: 'backup.restore',
    completeDatabaseRestore: true,
    caddyfile: typeof manifest.caddyfile === 'string' && manifest.caddyfile.trim() ? manifest.caddyfile : null,
    mutate: (s) => {
      // Merge over defaults like every loader does: a minimal or older
      // backup must not amputate fields added since it was written.
      const merged = { ...state.DEFAULT_WAF, ...check.sanitized }
      for (const key of Object.keys(s.WAF)) delete s.WAF[key]
      Object.assign(s.WAF, merged)
      if (manifest.rule_categories && typeof manifest.rule_categories === 'object') {
        for (const key of Object.keys(s.RULE_CATEGORIES)) delete s.RULE_CATEGORIES[key]
        Object.assign(s.RULE_CATEGORIES, require('./sanitize').stripUnsafeKeys(manifest.rule_categories))
      }
      if (manifest.settings && typeof manifest.settings === 'object') {
        for (const [group, value] of Object.entries(restoredSettings)) {
          settings.replace(group, value)
        }
      }
      return { from: path.basename(resolved), redacted: !!manifest.redacted }
    },
    validate: (s) => {
      // A redacted caddyfile section in the source means the restored file
      // may contain «redacted» placeholders — refuse before Caddy sees it.
      if (manifest.redacted && typeof manifest.caddyfile === 'string' && manifest.caddyfile.includes('«redacted»')) {
        return { ok: false, error: 'The backed-up Caddyfile was redacted and cannot be restored.' }
      }
      return { ok: true }
    },
  })

  if (!tx.ok) {
    return { ok: false, error: tx.error || 'restore failed', phase: tx.phase, rolledBack: tx.rolledBack, recoveryRequired: tx.recoveryRequired, rollbackErrors: tx.rollbackErrors }
  }

  const result = { ok: true, restored_from: resolved, waf: true, rule_categories: !!manifest.rule_categories, settings_groups: manifest.settings ? Object.keys(manifest.settings).filter(g => settings.isGroup(g)) : [], caddyfile_replaced: typeof manifest.caddyfile === 'string', reloaded: !!tx.reloaded, reload_error: tx.reloadError || null, previous_caddyfile_backup: previousCaddyfile !== null }

  return result
}


function sqliteCopy(source, target) {
  // Precreate private: the backup API must never create a world-readable DB.
  fs.closeSync(fs.openSync(target, 'a', 0o600))
  fs.chmodSync(target, 0o600)
  execFileSync(process.execPath, [path.join(__dirname, '../../scripts/sqlite-backup.js'), source, target], {
    stdio: ['ignore', 'pipe', 'pipe'], timeout: 120000, windowsHide: true,
  })
}

function confirmDatabaseRestore(filePath) {
  const resolved = path.resolve(String(filePath || ''))
  const plain = resolved.replace(/\.json(\.enc)?$/, '.db')
  const source = resolved.endsWith('.json.enc') && fs.existsSync(plain + '.enc') ? plain + '.enc' : fs.existsSync(plain) ? plain : plain + '.enc'
  const target = db.DB_PATH
  if (!fs.existsSync(source)) return { ok: false, error: 'No database backup at ' + plain + ' or ' + plain + '.enc' }
  if (fs.realpathSync(source) === fs.realpathSync(target)) return { ok: false, error: 'Cannot restore the live database onto itself' }
  const stage = path.join(path.dirname(target), '.restore-' + crypto.randomUUID() + '.db')
  let recoveryCopy = null
  try {
    return configLock.withConfigLock(() => {
      require('./configTx').recover()
      if (caddySvc.isAdminReachable()) throw new Error('Stop Caddy before restoring its database and configuration.')
      const expected = new Map(db.getDb().prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'").all().map(({ name }) => [name, db.getDb().prepare('PRAGMA table_info("' + name.replaceAll('"', '""') + '")').all()]))
      const result = db.withOfflineAccess(() => {
        // Freeze and validate the source before touching the destination.
        if (isEncrypted(source)) fs.writeFileSync(stage, decryptFileToBuffer(source), { mode: 0o600, flag: 'wx' })
        else sqliteCopy(source, stage)
        const { DatabaseSync } = require('node:sqlite')
        const candidate = new DatabaseSync(stage)
        try {
          candidate.exec('PRAGMA trusted_schema=OFF')
          if (candidate.prepare('PRAGMA quick_check').get().quick_check !== 'ok') throw new Error('Database integrity check failed')
          const schema = candidate.prepare("SELECT type, name, sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'").all()
          if (schema.some(item => !['table', 'index'].includes(item.type) || /CREATE\s+VIRTUAL\s+TABLE/i.test(item.sql || ''))) throw new Error('Backup contains unsupported schema objects')
          for (const table of schema.filter(item => item.type === 'table')) {
            const required = expected.get(table.name)
            if (!required) throw new Error('Unknown backup table: ' + table.name)
            const columns = candidate.prepare('PRAGMA table_info("' + table.name.replaceAll('"', '""') + '")').all()
            for (const column of required) {
              const found = columns.find(item => item.name === column.name)
              const migratable = table.name === 'request_log' && ['severity', 'reason', 'matched_var', 'country_code', 'city', 'lat', 'lon'].includes(column.name)
              if ((!found && !migratable) || (found && (found.type !== column.type || found.pk !== column.pk || found.notnull !== column.notnull))) throw new Error('Incompatible backup column: ' + table.name + '.' + column.name)
            }
            if (columns.some(column => !required.some(item => item.name === column.name))) throw new Error('Unknown columns in backup table: ' + table.name)
          }
          candidate.prepare('SELECT key, value FROM waf_state LIMIT 1').get()
          // Restoring a historical snapshot must not resurrect revoked JWTs.
          const row = candidate.prepare("SELECT value FROM waf_state WHERE key='users'").get()
          if (row) {
            const users = JSON.parse(row.value)
            if (!Array.isArray(users) || !users.length || users.some(user => !user || typeof user.id !== 'string' || typeof user.username !== 'string' || typeof user.password_hash !== 'string' || !['admin', 'viewer'].includes(user.role))) throw new Error('Invalid account state in backup')
            for (const user of users) user.tokens_valid_after = Math.max(Number(user.tokens_valid_after) || 0, Math.floor(Date.now() / 1000))
            candidate.prepare("UPDATE waf_state SET value=? WHERE key='users'").run(JSON.stringify(users))
          }
          candidate.prepare('INSERT OR REPLACE INTO waf_state (key,value) VALUES (?,?)').run('admin_sessions', '{}')
          candidate.prepare('INSERT OR REPLACE INTO waf_state (key,value) VALUES (?,?)').run('admin_sessions_revoked', '{}')
          candidate.prepare("DELETE FROM waf_state WHERE key='config_tx_commit'").run()
          candidate.prepare('INSERT OR REPLACE INTO waf_state (key,value) VALUES (?,?)').run('database_restore_pending', JSON.stringify({ restoredAt: new Date().toISOString(), manifest: path.basename(resolved) }))
          if (schema.some(item => item.name === 'request_nonces')) candidate.exec('DELETE FROM request_nonces')
        } finally { candidate.close() }
        const dir = path.join(path.dirname(target), 'backups')
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
        recoveryCopy = path.join(dir, 'pre-restore-' + crypto.randomUUID() + '.db')
        sqliteCopy(target, recoveryCopy)
        try { sqliteCopy(stage, target) }
        catch (error) {
          // The backup API rolls back interrupted destination writes itself.
          // Keep the recovery copy regardless, and report failure honestly.
          return { ok: false, error: 'SQLite restore failed: ' + (error.stderr?.toString().trim() || error.message), recoveryCopy }
        }
        return { ok: true, restored: target, recoveryCopy, sessions_revoked: true, requires_config_apply: true,
          instruction: 'Database restored with services stopped. Apply the matching manifest without --db to validate and regenerate Caddy configuration, then restart services.' }
      })
      state.reloadAllFromDb()
      return result
    })
  } catch (error) {
    return { ok: false, error: error.stderr?.toString().trim() || error.message, recoveryCopy }
  } finally {
    // Only our private staging files; never remove the live DB or sidecars.
    for (const suffix of ['', '-wal', '-shm', '-journal']) {
      try { fs.unlinkSync(stage + suffix) } catch (error) { if (error.code !== 'ENOENT') log.warn('Restore staging cleanup failed', { error: error.message }) }
    }
  }
}

// ── Backup encryption ───────────────────────────────────────────────────
//
// New backups use authenticated AES-256-GCM. Legacy OpenSSL CBC files are
// read-only compatibility inputs. The passphrase comes from CATWAF_BACKUP_PASSPHRASE in
// .env — it is deliberately NOT stored in the database, because a backup
// that can be decrypted by the same database it protects is not encrypted
// in any meaningful sense.
const SALT_MAGIC = 'Salted__'
const GCM_MAGIC = 'CWBACK02'

function passphrase() {
  const p = process.env.CATWAF_BACKUP_PASSPHRASE
  return (p && p.length >= 8) ? p : null
}

function requirePassphrase() {
  const p = passphrase()
  if (!p) {
    throw new Error('CATWAF_BACKUP_PASSPHRASE is not set (or shorter than 8 characters). Add it to .env — backups must be decryptable by something other than the database they protect.')
  }
  return p
}

function opensslEnc(args, input) {
  return execFileSync('openssl', ['enc', '-aes-256-cbc', '-pbkdf2', '-iter', '200000', ...args],
    { input, stdio: ['pipe', 'pipe', 'pipe'], timeout: 60_000, env: { ...process.env, CATWAF_BACKUP_PASSPHRASE: requirePassphrase() }, maxBuffer: 512 * 1024 * 1024 })
}

function encryptBufferToFile(plainBuf, destPath) {
  const salt = crypto.randomBytes(16)
  const iv = crypto.randomBytes(12)
  const key = crypto.pbkdf2Sync(requirePassphrase(), salt, 310000, 32, 'sha256')
  const header = Buffer.concat([Buffer.from(GCM_MAGIC), salt, iv])
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 })
  cipher.setAAD(header)
  const ciphertext = Buffer.concat([cipher.update(plainBuf), cipher.final()])
  configLock.atomicWriteFileSync(destPath, Buffer.concat([header, cipher.getAuthTag(), ciphertext]), { mode: 0o600 })
}

function decryptFileToBuffer(encPath) {
  const raw = fs.readFileSync(encPath)
  if (raw.subarray(0, 8).toString('latin1') === GCM_MAGIC) {
    if (raw.length < 52) throw new Error('Truncated encrypted backup')
    const key = crypto.pbkdf2Sync(requirePassphrase(), raw.subarray(8, 24), 310000, 32, 'sha256')
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, raw.subarray(24, 36), { authTagLength: 16 })
    decipher.setAAD(raw.subarray(0, 36))
    decipher.setAuthTag(raw.subarray(36, 52))
    return Buffer.concat([decipher.update(raw.subarray(52)), decipher.final()])
  }
  if (raw.subarray(0, 8).toString('latin1') !== SALT_MAGIC) {
    throw new Error('File is not an OpenSSL-encrypted backup.')
  }
  return opensslEnc(['-d', '-pass', 'env:CATWAF_BACKUP_PASSPHRASE'], raw)
}

function isEncrypted(filePath) {
  try {
    const fd = fs.openSync(filePath, 'r')
    const head = Buffer.alloc(8)
    fs.readSync(fd, head, 0, 8, 0)
    fs.closeSync(fd)
    return [SALT_MAGIC, GCM_MAGIC].includes(head.toString('latin1'))
  } catch { return false }
}

module.exports = { run, list, prune, buildPayload, verifyDestination, restoreFromFile, confirmDatabaseRestore, encryptBufferToFile, decryptFileToBuffer, isEncrypted, FILE_RE }
