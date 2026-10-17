// auditLog.js — retention and rotation for the Coraza audit log.
//
// Coraza appends to the audit log forever; nothing else prunes it. On a busy
// site that fills the disk, which takes the WAF down. This rotates it.
//
// ── Why rotation works the way it does ────────────────────────────────
// Coraza caches its audit writer by PATH. Measured behaviour:
//
//   rename the file          -> Coraza keeps writing to the moved inode
//   `caddy reload`           -> no reopen (config unchanged is a no-op)
//   `caddy reload --force`   -> still no reopen; the writer is cached
//   change the configured path + reload -> Coraza opens the NEW path
//
// So the only way to retire a log file without truncating it or restarting
// Caddy is to point `SecAuditLog` at a new file. That is what rotation does:
//
//   1. pick the next active path
//   2. repoint SecAuditLog at it, validated, backed up, reloaded
//   3. ingest the previous file and keep following its late writes
//   4. prune only after proving no proxy descriptor can still write to it
//
// Nothing is ever truncated, and the file being retired is fully ingested
// before it can be pruned. The active file is never a deletion candidate.
//
// ── Restart / crash safety ────────────────────────────────────────────
// The active path and any in-flight rotation live in a sidecar JSON file
// beside the logs (not the database) so services/caddy.js can read it with
// nothing but `fs`, and so it works identically for a host install and for
// a container sharing the log volume.
//
// A crash mid-rotation leaves a `pending` marker. The next call finishes or
// reverts it, whichever matches what the Caddyfile actually says. Ingestion
// ids are content-derived (see requestLog.js), so redoing a drain can never
// duplicate events.

const fs = require('fs')
const path = require('path')

const caddySvc = require('./caddy')
const configLock = require('./configLock')
const configTx = require('./configTx')

const STATE_FILE = '.catwaf-audit-state.json'

// Rotation writes generated paths into the Caddyfile, so they are validated
// like any other untrusted path before being used.
const SAFE_PATH_RE = /^\/[A-Za-z0-9._\-/]*$/

function num(value, fallback, min, max) {
  const n = Number(value)
  if (!Number.isFinite(n)) return fallback
  return Math.min(max, Math.max(min, Math.trunc(n)))
}

// Defaults are the documented ones; every value is clamped because these
// come from the environment and a nonsense value must not disable rotation
// or make it delete everything.
function config(env = process.env) {
  return {
    retentionDays: num(env.CATWAF_AUDIT_RETENTION_DAYS, 30, 1, 3650),
    maxSizeMb: num(env.CATWAF_AUDIT_MAX_SIZE_MB, 100, 1, 1024 * 100),
    maxFiles: num(env.CATWAF_AUDIT_MAX_FILES, 10, 1, 1000),
  }
}

// ── sidecar state ─────────────────────────────────────────────────────

function stateFileFor(basePath) {
  return path.join(path.dirname(basePath), STATE_FILE)
}

function readState(basePath) {
  try {
    const raw = fs.readFileSync(stateFileFor(basePath), 'utf8')
    const parsed = JSON.parse(raw)
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Invalid audit rotation state')
    return parsed
  } catch (error) { if (error.code === 'ENOENT') return {}; throw error }
}

function writeState(basePath, next) {
  const file = stateFileFor(basePath)
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true })
    configLock.atomicWriteFileSync(file, JSON.stringify(next, null, 2), { mode: 0o640 })
    if (process.platform !== 'win32') {
      const fd = fs.openSync(path.dirname(file), 'r')
      try { fs.fsyncSync(fd) } finally { fs.closeSync(fd) }
    }
    return true
  } catch {
    return false
  }
}

// The path Coraza is currently configured to write to. Falls back to the
// base path when there has never been a rotation. Read by services/caddy.js,
// which is why it must not require anything beyond `fs`.
function activePath(basePath = caddySvc.DEFAULT_ACTIVE_AUDIT_LOG || null) {
  const base = basePath || caddySvc.baseAuditLogPath()
  const st = readState(base)
  if (typeof st.active === 'string' && SAFE_PATH_RE.test(st.active) && path.dirname(st.active) === path.dirname(base)) {
    return st.active
  }
  return base
}

// When the current active file started being written. Recorded by rotation;
// lazily initialised for an install that has never rotated, so age-based
// rotation works from first use rather than only after the first rotation.
function activeSince(basePath, active = activePath(basePath)) {
  const st = readState(basePath)
  const recorded = Date.parse(st.activeSince || '')
  if (Number.isFinite(recorded)) return recorded

  let stat
  try { stat = fs.statSync(active) } catch { return null }
  const birth = Number.isFinite(stat.birthtimeMs) && stat.birthtimeMs > 0 ? stat.birthtimeMs : stat.mtimeMs
  // Persist it so the value is stable from here on.
  writeState(basePath, { ...st, activeSince: new Date(birth).toISOString() })
  return birth
}

// ── archive naming ────────────────────────────────────────────────────

function stemOf(basePath) {
  const b = path.basename(basePath)
  const ext = path.extname(b)
  return { dir: path.dirname(basePath), stem: b.slice(0, b.length - ext.length), ext: ext || '.json' }
}

function nextActivePath(basePath, when = new Date()) {
  const { dir, stem, ext } = stemOf(basePath)
  const stamp = when.toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z')
  return path.join(dir, `${stem}-${stamp}${ext}`)
}

// Every file that belongs to this audit log's rotation set, newest first.
function listFiles(basePath) {
  const { dir, stem, ext } = stemOf(basePath)
  const re = new RegExp(`^${stem.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(-\\d{8}T\\d{6}Z)?${ext.replace('.', '\\.')}$`)
  let names = []
  try { names = fs.readdirSync(dir) } catch { return [] }
  return names
    .filter(n => re.test(n))
    .map(n => {
      const p = path.join(dir, n)
      try { const st = fs.statSync(p); return { path: p, name: n, size: st.size, mtime: st.mtimeMs } }
      catch { return null }
    })
    .filter(Boolean)
    .sort((a, b) => b.mtime - a.mtime)
}

// ── status ────────────────────────────────────────────────────────────

function status(env = process.env) {
  const base = caddySvc.baseAuditLogPath()
  const active = activePath(base)
  const cfg = config(env)
  const files = listFiles(base)
  const activeEntry = files.find(f => f.path === active)
  const archives = files.filter(f => f.path !== active)

  let writable = false
  try { fs.accessSync(path.dirname(active), fs.constants.W_OK); writable = true } catch {}

  const sizeBytes = activeEntry ? activeEntry.size : 0
  const maxBytes = cfg.maxSizeMb * 1024 * 1024
  return {
    activePath: active,
    basePath: base,
    exists: !!activeEntry,
    sizeBytes,
    maxSizeBytes: maxBytes,
    percentOfMax: maxBytes ? Math.round((sizeBytes / maxBytes) * 100) : 0,
    rotatedFiles: archives.length,
    archives: archives.map(a => ({ name: a.name, size: a.size, mtime: new Date(a.mtime).toISOString() })),
    totalBytes: files.reduce((n, f) => n + f.size, 0),
    retention: cfg,
    writable,
    rotationPending: !!readState(base).pending,
  }
}

function needsRotation(env = process.env) {
  const s = status(env)
  if (!s.exists) return { rotate: false }
  if (s.sizeBytes >= s.maxSizeBytes) {
    return { rotate: true, reason: `size ${Math.round(s.sizeBytes / 1024 / 1024)}MB reached the ${s.retention.maxSizeMb}MB limit` }
  }
  const oldestAllowed = Date.now() - s.retention.retentionDays * 86400000
  // Age is measured from when the active file STARTED being used, so a log
  // that never reaches the size limit still rolls over eventually. mtime is
  // useless for this (it tracks the last append) and birthtime is not
  // available on every filesystem, so rotation records it explicitly and
  // those two are only fallbacks.
  const since = activeSince(s.basePath, s.activePath)
  if (since && since < oldestAllowed) {
    return { rotate: true, reason: `active log is older than the ${s.retention.retentionDays}-day retention window` }
  }
  return { rotate: false }
}

// ── the Caddyfile repoint ─────────────────────────────────────────────

// Swaps every `SecAuditLog <from>` for `<to>` in CatWAF's generated blocks,
// then validates and applies it through the same backup/validate/rollback
// path every other configuration change uses.
function repointCaddyfile(from, to) {
  // The read-replace-validate-rename cycle must not interleave with another
  // process patching the Caddyfile; the lock is re-entrant with configTx.
  return configLock.withConfigLock(() => repointCaddyfileLocked(from, to))
}

function repointCaddyfileLocked(from, to) {
  let content
  try { content = caddySvc.readCaddyfile() } catch (e) { return { ok: false, error: e.message } }

  const needle = `SecAuditLog ${from}`
  if (!content.includes(needle)) {
    return { ok: false, error: `The Caddyfile does not reference ${from}; refusing to guess.` }
  }
  const next = content.split(needle).join(`SecAuditLog ${to}`)

  return configTx.apply({ label: 'audit-log.repoint', caddyfile: next, render: false, mutate: () => {} })
}

// ── rotation ──────────────────────────────────────────────────────────

function drain(filePath) {
  // Required lazily: requestLog requires caddy, and this module is reached
  // from CLI paths that must not pull the database in until it is needed.
  try { return require('./requestLog').drainFile(filePath) }
  catch (e) { return { ingested: 0, error: e.message } }
}

// Finishes or reverts a rotation that was interrupted. Decided by what the
// Caddyfile actually says, not by what we intended.
function recover(basePath = caddySvc.baseAuditLogPath()) {
  return configLock.withConfigLock(() => recoverLocked(basePath))
}
function recoverLocked(basePath) {
  const st = readState(basePath)
  if (!st.pending) return { recovered: false }

  // A failed configuration rollback can leave the proxy and disk on different
  // generations. Resolve that journal before using the Caddyfile as evidence
  // that a log is safe to retire or remove.
  try { configTx.recover() }
  catch (error) { return { recovered: false, outcome: 'deferred', error: error.message } }

  // State-file values are plain JSON beside the logs; treat them like any
  // other path input rather than trusting them blindly.
  const { from, to } = st.pending
  const contained = p => typeof p === 'string' && SAFE_PATH_RE.test(p)
    && path.dirname(p) === path.dirname(activePath(basePath))
  if ((from && !contained(from)) || (to && !contained(to))) {
    writeState(basePath, { active: activePath(basePath) })
    return { recovered: false, error: 'Ignoring a pending-rotation marker with out-of-tree paths.' }
  }

  let caddyfileMentionsTo = false
  try { caddyfileMentionsTo = caddySvc.readCaddyfile().includes(`SecAuditLog ${to}`) } catch {}

  if (caddyfileMentionsTo) {
    // The repoint landed. Keep the old file available for late writes;
    // completion of this journal does not establish writer retirement.
    const drained = from ? drain(from) : { ok: true }
    if (drained && drained.error) {
      // Could not ingest the retired log yet. Keep the pending marker so
      // the next maintain() tries again; clearing it now would let prune()
      // delete a log whose contents never reached the database.
      return { recovered: false, outcome: 'deferred', error: drained.error }
    }
    if (!writeState(basePath, { active: to, rotatedAt: st.pending.startedAt || new Date().toISOString(), activeSince: new Date().toISOString() })) return { recovered: false, error: 'Cannot persist completed audit rotation; recovery is still pending.' }
    return { recovered: true, outcome: 'completed' }
  }

  // The repoint never landed: keep writing where we were.
  try {
    if (to && fs.existsSync(to) && fs.statSync(to).size === 0) fs.unlinkSync(to)
  } catch {}
  if (!writeState(basePath, { active: from || basePath, activeSince: readState(basePath).activeSince })) return { recovered: false, error: 'Cannot persist reverted audit rotation; recovery is still pending.' }
  return { recovered: true, outcome: 'reverted' }
}

// Deletes archives beyond the retention window or the file-count limit.
// The active log is never a candidate, and a file that has not been fully
// ingested is kept regardless.
function prune(env = process.env) {
  return configLock.withConfigLock(() => pruneLocked(env))
}
function pruneLocked(env) {
  const base = caddySvc.baseAuditLogPath()
  const active = activePath(base)
  const cfg = config(env)
  const cutoff = Date.now() - cfg.retentionDays * 86400000

  // A file still referenced by a pending rotation marker has not been
  // confirmed ingested — deleting it would lose those audit events.
  let pendingPaths = []
  try {
    const st = readState(base)
    if (st.pending) pendingPaths = [st.pending.from, st.pending.to].filter(Boolean)
  } catch {}

  // The live Caddyfile remains authoritative even if a sidecar update failed.
  const referenced = new Set([...caddySvc.readCaddyfile().matchAll(/\bSecAuditLog\s+(\S+)/g)].map(m => m[1]))
  const archives = listFiles(base).filter(f => f.path !== active && !referenced.has(f.path))
  const deleted = []
  const failed = []
  const deferred = []
  let writers

  archives.forEach((f, index) => {
    if (pendingPaths.includes(f.path)) return
    const tooOld = f.mtime < cutoff
    // index is 0-based over archives only, so maxFiles counts archives kept
    // alongside the active log.
    const tooMany = index >= cfg.maxFiles
    if (!tooOld && !tooMany) return
    try {
      writers ||= require('./auditWriters').snapshot()
      if (!writers.ok) { deferred.push({ name: f.name, reason: writers.error }); return }
      const stat = fs.statSync(f.path, { bigint: true })
      if (writers.writers.has(require('./auditWriters').identity(stat))) {
        deferred.push({ name: f.name, reason: 'Proxy still holds an audit writer' }); return
      }
      const drained = drain(f.path)
      if (drained.error) throw new Error(drained.error)
      if (!drained.complete) { deferred.push({ name: f.name, reason: 'Audit record is incomplete or drain budget is exhausted' }); return }
      fs.unlinkSync(f.path)
      deleted.push({ name: f.name, reason: tooOld ? 'older than retention' : 'beyond max files' })
    } catch (e) {
      failed.push({ name: f.name, error: e.code || e.message })
    }
  })

  return { deleted, failed, deferred, kept: archives.length - deleted.length }
}

// Rotate now. Safe to call when rotation is not needed — callers decide.
function rotate(options = {}) {
  return configLock.withConfigLock(() => rotateLocked(options))
}
function rotateLocked({ env = process.env, reason = 'manual' } = {}) {
  const base = caddySvc.baseAuditLogPath()
  const recovered = recover(base)
  if (recovered.error || readState(base).pending) return { ok: false, pendingRetry: true, error: recovered.error || 'Previous audit rotation is still pending.' }

  const from = activePath(base)
  const to = nextActivePath(base)

  if (!SAFE_PATH_RE.test(to) || !SAFE_PATH_RE.test(from)) {
    return { ok: false, error: 'Refusing to rotate: the audit log path is not a plain absolute path.' }
  }
  if (fs.existsSync(to)) {
    return { ok: false, error: `Refusing to rotate onto an existing file (${to}).` }
  }

  // Create the new active file first so Coraza has something to open the
  // moment the reload lands.
  try {
    fs.mkdirSync(path.dirname(to), { recursive: true, mode: 0o750 })
    const fd = fs.openSync(to, 'wx', 0o660)
    try {
      // Creation mode is filtered by umask. The separate proxy UID needs the
      // shared group's write bit before validation opens this new generation.
      fs.fchmodSync(fd, 0o660)
    } finally { fs.closeSync(fd) }
  } catch (e) {
    return { ok: false, error: `Cannot create the next audit log (${to}): ${e.code || e.message}` }
  }

  // Marker first: a crash from here on is recoverable either way.
  if (!writeState(base, { active: from, pending: { from, to, startedAt: new Date().toISOString(), reason } })) {
    try { fs.unlinkSync(to) } catch {}
    return { ok: false, error: 'Cannot persist audit rotation journal; the active log was not changed.' }
  }

  const repoint = repointCaddyfile(from, to)
  if (!repoint.ok) {
    if (repoint.recoveryRequired || repoint.rolledBack === false) {
      return { ok: false, from, to, error: repoint.error, rolledBack: false, recoveryRequired: true, pendingRetry: true }
    }
    try { fs.unlinkSync(to) } catch {}
    const saved = writeState(base, { active: from })
    return { ok: false, error: repoint.error, rolledBack: true, pendingRetry: !saved }
  }

  if (!repoint.reloaded) {
    // Coraza is still writing to `from` — the switch has not taken effect,
    // so put the configuration back rather than leave a split state.
    const back = repointCaddyfile(to, from)
    if (!back.ok) {
      return { ok: false, from, to, error: back.error || 'Cannot restore the previous audit log configuration.', rolledBack: false, recoveryRequired: true, pendingRetry: true }
    }
    try { fs.unlinkSync(to) } catch {}
    const saved = writeState(base, { active: from })
    return {
      ok: false,
      error: `The proxy did not reload (${repoint.reloadError || 'unknown'}), so the audit log was not rotated.`,
      rolledBack: back.ok,
      pendingRetry: !saved,
    }
  }

  // Reload acknowledgement does not retire in-flight writers. Ingest what is
  // available now; requestLog follows late appends and prune proves retirement.
  const drained = drain(from)
  if (drained && drained.error) {
    // Ingestion failed (e.g. database unavailable). Leave the pending
    // marker in place — recover() on the next maintain() will re-drain the
    // retired file — and skip pruning this cycle so the not-yet-ingested
    // log cannot be deleted.
    return {
      ok: true,
      from,
      to,
      reason,
      ingested: 0,
      ingestError: drained.error,
      pendingRetry: true,
      backup: repoint.backup || null,
      pruned: [],
      pruneFailures: [],
    }
  }
  if (!writeState(base, { active: to, rotatedAt: new Date().toISOString(), activeSince: new Date().toISOString() })) return { ok: false, pendingRetry: true, from, to, error: 'Cannot persist completed audit rotation; recovery is still pending.' }

  const pruned = prune(env)
  return {
    ok: true,
    from,
    to,
    reason,
    ingested: drained.ingested || 0,
    backup: repoint.backup || null,
    pruned: pruned.deleted,
    pruneFailures: pruned.failed,
  }
}

// The entry point callers use: recover, rotate if needed, prune. Never
// throws — audit-log housekeeping must not take down the caller.
function maintain({ env = process.env, force = false } = {}) {
  try {
    return configLock.withConfigLock(() => {
    const base = caddySvc.baseAuditLogPath()
    const recovered = recover(base)
    if (recovered.error || readState(base).pending) return { ok: false, rotated: false, pendingRetry: true, recovered, error: recovered.error || 'Previous audit rotation is still pending.' }
    const need = force ? { rotate: true, reason: 'forced' } : needsRotation(env)
    if (!need.rotate) {
      const pruned = prune(env)
      return { ok: true, rotated: false, recovered, pruned: pruned.deleted, pruneFailures: pruned.failed }
    }
    const result = rotate({ env, reason: need.reason })
    return { ok: result.ok, rotated: result.ok, recovered, ...result }
    })
  } catch (e) {
    return { ok: false, rotated: false, error: e.message }
  }
}

module.exports = {
  config, status, needsRotation, activePath, activeSince, listFiles,
  nextActivePath, readState, writeState, stateFileFor, repointCaddyfile,
  rotate, prune, recover, maintain,
  SAFE_PATH_RE,
}
