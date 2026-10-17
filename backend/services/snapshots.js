const state = require('./state')
const auditSvc = require('./audit')
const configTx = require('./configTx')

const SECRET_KEY_RE = /(secret|token|password|passwd|api[_-]?key|apikey|webhook|credential|private[_-]?key)/i

const SNAPSHOT_ID_RE = /^[a-f0-9]{4,32}$/i

function isValidSnapshotId(id) {
  return typeof id === 'string' && SNAPSHOT_ID_RE.test(id)
}

function redactSecrets(value, keyPath = '') {
  if (Array.isArray(value)) return value.map((v, i) => redactSecrets(v, `${keyPath}[${i}]`))
  if (value && typeof value === 'object') {
    const out = {}
    for (const [k, v] of Object.entries(value)) {
      if (SECRET_KEY_RE.test(k)) {
        out[k] = (v === '' || v == null) ? v : '[REDACTED]'
        continue
      }
      out[k] = redactSecrets(v, keyPath ? `${keyPath}.${k}` : k)
    }
    return out
  }
  // A credential-bearing URL is a secret even if its field is named "url".
  if (typeof value === 'string' && /^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
    try {
      const url = new URL(value)
      if (url.username || url.password) { url.username = ''; url.password = ''; return url.toString() }
    } catch { /* preserve non-URL text */ }
  }
  return value
}

function create({ req = null, label = 'manual' } = {}) {
  const safeLabel = String(label || 'manual').slice(0, 64).replace(/[^\w .:-]/g, '')
  const snap = auditSvc.snapshot(req, safeLabel || 'manual')
  return {
    ok: true,
    id: snap.id,
    timestamp: snap.ts,
    label: snap.label,
    created_by: snap.username,
  }
}

function list() {
  return auditSvc.getSnapshots().map(s => ({
    id: s.id,
    timestamp: s.ts,
    label: s.label,
    created_by: s.username,
  }))
}

function get(id) {
  if (!isValidSnapshotId(id)) return null
  const row = auditSvc.getSnapshot(id)
  if (!row) return null
  return {
    id: row.id,
    timestamp: row.ts,
    label: row.label,
    created_by: row.username,
    state: row.state,
  }
}

function view(id) {
  const snap = get(id)
  if (!snap) return { ok: false, error: `No snapshot found with ID "${id}".` }
  return { ok: true, ...snap, state: redactSecrets(snap.state) }
}

function flatten(obj, prefix = '', out = {}) {
  if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
    for (const [k, v] of Object.entries(obj)) flatten(v, prefix ? `${prefix}.${k}` : k, out)
    return out
  }
  out[prefix] = obj
  return out
}

function describeValue(key, value) {
  if (SECRET_KEY_RE.test(key)) return value == null || value === '' ? String(value) : '[REDACTED]'
  if (Array.isArray(value)) return value.length <= 6 ? JSON.stringify(value) : `[${value.length} items]`
  if (value && typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

function diff(id, { against = null } = {}) {
  const snap = get(id)
  if (!snap) return { ok: false, error: `No snapshot found with ID "${id}".` }

  let target = state.WAF
  let targetLabel = 'current configuration'
  if (against) {
    const other = get(against)
    if (!other) return { ok: false, error: `No snapshot found with ID "${against}".` }
    target = other.state
    targetLabel = `snapshot ${other.id}`
  }

  const a = flatten(snap.state)
  const b = flatten(target)
  const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])].sort()

  const changes = []
  for (const k of keys) {
    const av = a[k]
    const bv = b[k]
    const same = JSON.stringify(av) === JSON.stringify(bv)
    if (same) continue
    changes.push({
      key: k,
      from: k in a ? describeValue(k, av) : null,
      to: k in b ? describeValue(k, bv) : null,
      kind: !(k in a) ? 'added' : !(k in b) ? 'removed' : 'changed',
      secret: SECRET_KEY_RE.test(k),
    })
  }

  return {
    ok: true,
    from: { id: snap.id, timestamp: snap.timestamp, label: snap.label },
    to: { label: targetLabel },
    changed: changes.length,
    changes,
  }
}

function restore(id, { req = null, reload = true } = {}) {
  const snap = get(id)
  if (!snap) return { ok: false, error: `No snapshot found with ID "${id}".` }

  const restored = snap.state
  if (!restored || typeof restored !== 'object' || !restored.engine) {
    return { ok: false, error: `Snapshot "${id}" does not contain a usable WAF configuration.` }
  }

  const preRestore = auditSvc.snapshot(req, `pre-restore-${id}`)

  const tx = configTx.apply({
    label: `config.restore.${id}`,
    req,
    reload,
    mutate: (s) => {
      // Same __proto__ hygiene as configTx.restoreWaf(): a tampered or
      // hand-edited snapshot must not be able to change Object.prototype
      // through Object.assign's [[Set]] semantics.
      const clean = {}
      for (const [k, v] of Object.entries(JSON.parse(JSON.stringify(restored)))) {
        if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue
        clean[k] = v
      }
      for (const key of Object.keys(s.WAF)) delete s.WAF[key]
      Object.assign(s.WAF, clean)
      for (const [k, v] of Object.entries(state.DEFAULT_WAF)) {
        if (!(k in s.WAF)) s.WAF[k] = JSON.parse(JSON.stringify(v))
      }
      return { restored_from: id }
    },
    validate: (s) => {
      if (!['On', 'DetectionOnly', 'Off'].includes(s.WAF.engine)) {
        return { ok: false, error: `Snapshot contains an invalid engine mode "${s.WAF.engine}".` }
      }
      const pl = Number(s.WAF.paranoia_level)
      if (!Number.isInteger(pl) || pl < 1 || pl > 4) {
        return { ok: false, error: `Snapshot contains an invalid paranoia level "${s.WAF.paranoia_level}".` }
      }
      if (Number(s.WAF.executing_paranoia_level) < pl) {
        return { ok: false, error: 'Snapshot has a detection paranoia level below its blocking level.' }
      }
      return { ok: true }
    },
  })

  if (!tx.ok) {
    return { ok: false, ...tx, safety_snapshot: preRestore.id }
  }

  return {
    ok: true,
    restored_from: id,
    snapshot_timestamp: snap.timestamp,
    safety_snapshot: preRestore.id,
    reloaded: tx.reloaded,
    reloadError: tx.reloadError,
    backup: tx.backup,
  }
}

module.exports = { create, list, get, view, diff, restore, isValidSnapshotId, redactSecrets, SECRET_KEY_RE }
