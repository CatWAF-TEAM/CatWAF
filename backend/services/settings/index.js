// settings/index.js — read/write access to the extended settings groups.
//
// Storage is one `waf_state` row per group (`ext:<group>`), which means the
// whole namespace is covered by the same snapshot/restore machinery
// configTx.js already applies to `state.WAF`: a group is mutated inside a
// transaction, and if `caddy validate` or the reload fails, it is restored
// alongside everything else.
//
// Secret fields (`writeOnly` in the schema) are never returned by the API
// reads — only a "is it set" flag — and a write that sends the redaction
// placeholder back is treated as "leave unchanged" rather than "clear it".

const db = require('../db')
const configLock = require('../configLock')
const { SCHEMA, defaultsFor, GROUP_NAMES } = require('./schema')
const { validateField } = require('./types')
const { stripUnsafeKeys } = require('../sanitize')

const KEY_PREFIX = 'ext:'
const REDACTED = '__catwaf_unchanged__'

// Cached per group so the hot request path (challenge gate, list checks)
// does not hit SQLite on every request. Invalidated on every write and by
// reloadAllFromDb(), which configTx's rollback path calls.
const cache = new Map()

// CatWAF is not one process. The CLI (`catwaf settings upload_scan
// enabled=true`), the API server and any job runner each hold their own copy
// of this cache, and a write in one of them used to be invisible to the
// others until they restarted — so enabling upload scanning from the CLI
// rendered the gate into the Caddyfile while the running backend went on
// believing the feature was off and forwarded malware to the origin.
//
// Every write bumps a revision counter in the same SQLite table the settings
// live in. Readers re-check that single row at most once a second and drop
// the whole cache when it moves. That keeps the hot path to one tiny indexed
// read per second instead of one per group per request, and bounds
// cross-process staleness to REV_CHECK_MS.
const REV_KEY = KEY_PREFIX + '__rev'
const REV_CHECK_MS = 1000
let seenRev
let lastRevCheck = 0

function storageKey(group) { return KEY_PREFIX + group }

function isGroup(group) {
  return typeof group === 'string' && Object.hasOwn(SCHEMA, group)
}

// A settings write and its revision must commit together. Otherwise another
// process may indefinitely keep a stale (potentially less restrictive) policy.
function persist(group, value) {
  const conn = db.getDb()
  conn.exec('SAVEPOINT catwaf_settings')
  try {
    const revision = (Number(db.getStateStrict(REV_KEY)) || 0) + 1
    db.setState(storageKey(group), value)
    db.setState(REV_KEY, revision)
    conn.exec('RELEASE catwaf_settings')
    cache.set(group, value)
    seenRev = revision
    lastRevCheck = Date.now()
  } catch (error) {
    try {
      if (conn.isTransaction) conn.exec('ROLLBACK TO catwaf_settings; RELEASE catwaf_settings')
    } finally { reloadAllFromDb() }
    throw error
  }
}

function syncRev() {
  const now = Date.now()
  if (now - lastRevCheck < REV_CHECK_MS) return
  // Do not serve cached policy after a failed read or postpone the next read.
  const rev = db.getStateStrict(REV_KEY)
  lastRevCheck = now
  if (rev !== seenRev) {
    seenRev = rev
    cache.clear()
  }
}

function get(group) {
  if (!isGroup(group)) throw new Error(`Unknown settings group "${group}"`)
  syncRev()
  if (cache.has(group)) return cache.get(group)
  const stored = db.getStateStrict(storageKey(group))
  if (stored !== null && (typeof stored !== 'object' || Array.isArray(stored))) throw new Error(`Invalid stored settings group "${group}"`)
  const value = { ...defaultsFor(group), ...(stored && typeof stored === 'object' && !Array.isArray(stored) ? stripUnsafeKeys(stored) : {}) }
  cache.set(group, value)
  return value
}

function getAll() {
  const out = {}
  for (const group of GROUP_NAMES) out[group] = get(group)
  return out
}

// Same shape as get(), with every writeOnly field replaced by a boolean
// `<field>_set`. Safe to return over the API and to write into a snapshot
// export or a backup archive.
function redact(group, value = get(group)) {
  const def = SCHEMA[group]
  const out = {}
  for (const [name, spec] of Object.entries(def.fields)) {
    if (spec.writeOnly) {
      out[name] = ''
      out[`${name}_set`] = !!(value[name] && String(value[name]).length)
    } else {
      out[name] = value[name]
      // Legacy Redis URLs could embed credentials in a non-writeOnly field.
      if (group === 'cluster' && name === 'url' && out[name]) {
        try { const url = new URL(out[name]); url.username = ''; url.password = ''; out[name] = url.toString() } catch { out[name] = '' }
      }
    }
  }
  return out
}

function getRedacted(group) { return redact(group) }

function getAllRedacted() {
  const out = {}
  for (const group of GROUP_NAMES) out[group] = redact(group)
  return out
}

// Validates a partial update against the group schema. Returns
// { ok, value } or { ok: false, error }. Does not persist.
function validate(group, patch, { merge = true } = {}) {
  if (!isGroup(group)) return { ok: false, error: `Unknown settings group "${group}"` }
  if (!patch || typeof patch !== 'object' || Array.isArray(patch)) {
    return { ok: false, error: 'Settings update must be an object' }
  }

  const def = SCHEMA[group]
  const current = get(group)
  const unknown = Object.keys(patch).filter(k => !Object.hasOwn(def.fields, k))
  if (unknown.length) {
    return { ok: false, error: `Unknown field(s) for ${group}: ${unknown.join(', ')}` }
  }

  const next = merge ? { ...current } : { ...defaultsFor(group) }
  for (const [name, spec] of Object.entries(def.fields)) {
    if (!Object.hasOwn(patch, name)) continue
    // A secret echoed back unchanged from a redacted read must not wipe the
    // stored value — the UI never receives it and therefore cannot resend it.
    if (spec.writeOnly && patch[name] === REDACTED) continue
    const r = validateField(spec, patch[name], `${group}.${name}`)
    if (r.error) return { ok: false, error: r.error }
    next[name] = r.value
  }

  return { ok: true, value: next }
}

function set(group, patch, { merge = true } = {}) {
  // Serialized with every other config writer; safe to call inside an
  // open configTx (the lock is re-entrant).
  return configLock.withConfigLock(() => {
    const v = validate(group, patch, { merge })
    if (!v.ok) return v
    persist(group, v.value)
    return { ok: true, value: v.value, redacted: redact(group, v.value) }
  })
}

// Direct write with no validation. Only for restore paths, which are
// replaying values that were already validated when they were first set.
function replace(group, value) {
  if (!isGroup(group)) return
  configLock.withConfigLock(() => {
    const merged = { ...defaultsFor(group), ...(value && typeof value === 'object' ? stripUnsafeKeys(value) : {}) }
    persist(group, merged)
  })
}

function reset(group) {
  if (!isGroup(group)) return { ok: false, error: `Unknown settings group "${group}"` }
  return configLock.withConfigLock(() => {
    const value = defaultsFor(group)
    persist(group, value)
    return { ok: true, value, redacted: redact(group, value) }
  })
}

function snapshot() {
  return JSON.parse(JSON.stringify(getAll()))
}

function restore(snap) {
  if (!snap || typeof snap !== 'object') return
  for (const group of GROUP_NAMES) {
    if (Object.hasOwn(snap, group)) replace(group, snap[group])
  }
}

function reloadAllFromDb() { cache.clear(); seenRev = undefined; lastRevCheck = 0 }

// Schema shipped to the dashboard so controls, help text and validation
// messages all come from the same definition the backend enforces.
function describe() {
  const out = {}
  for (const [group, def] of Object.entries(SCHEMA)) {
    out[group] = {
      label: def.label,
      summary: def.summary,
      idea: def.idea || [],
      advanced: !!def.advanced,
      secret: !!def.secret,
      fields: Object.entries(def.fields).map(([name, spec]) => ({
        name,
        type: spec.type,
        label: spec.label || name,
        help: spec.help || null,
        default: spec.default,
        values: spec.values || null,
        item: spec.item || null,
        min: spec.min ?? null,
        max: spec.max ?? null,
        write_only: !!spec.writeOnly,
        fields: spec.fields
          ? Object.entries(spec.fields).map(([n, s]) => ({ name: n, type: s.type, values: s.values || null, item: s.item || null, default: s.default }))
          : null,
      })),
    }
  }
  return out
}

// Convenience for feature modules: `enabled(group)` reads the conventional
// on/off field without every caller repeating the same guard.
function enabled(group) {
  if (!isGroup(group)) return false
  const v = get(group)
  return Object.hasOwn(v, 'enabled') ? !!v.enabled : true
}

module.exports = {
  SCHEMA, GROUP_NAMES, REDACTED,
  get, getAll, getRedacted, getAllRedacted, redact,
  validate, set, replace, reset, reload: reloadAllFromDb, reloadAllFromDb,
  snapshot, restore, describe, isGroup, enabled, defaultsFor,
}
