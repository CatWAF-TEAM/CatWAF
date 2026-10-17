// Durable session records are the authority: deleting one revokes access.
const crypto = require('crypto')
const db = require('./db')
const settings = require('./settings')
const { withConfigLock } = require('./configLock')
const { normalizeClientIp } = require('./sanitize')
const STORE_KEY = 'admin_sessions'
const MAX_TRACKED = 500
const MAX_LIFETIME_MS = 43200 * 60_000
function load(key = STORE_KEY) {
  const stored = db.getStateStrict(key)
  if (stored === null) return Object.create(null)
  if (typeof stored !== 'object' || Array.isArray(stored)) throw new Error('Invalid session store')
  return Object.assign(Object.create(null), stored)
}
function persist(sessions) { db.setState(STORE_KEY, sessions) }
function fingerprint(req) {
  const cfg = settings.get('session')
  const parts = []
  if (cfg.bind_ip) parts.push(normalizeClientIp(req?.ip || ''))
  if (cfg.bind_user_agent) parts.push(String(req?.headers?.['user-agent'] || '').slice(0, 300))
  return parts.length ? crypto.createHash('sha256').update(parts.join('|')).digest('hex').slice(0, 24) : null
}
function expiry(entry) {
  // Legacy records have no JWT expiry. JWT verification still enforces exp;
  // retain those records for at most the maximum supported token lifetime.
  return entry?.expires_at ?? (Date.parse(entry?.created_at) + MAX_LIFETIME_MS)
}
function prune(sessions) {
  for (const [jti, entry] of Object.entries(sessions)) {
    if (!Number.isFinite(expiry(entry)) || expiry(entry) <= Date.now()) delete sessions[jti]
  }
  return sessions
}
function open({ jti, user, req, expiresAt }) {
  if (!jti) throw new Error('A session ID is required')
  return withConfigLock(() => {
    const cfg = settings.get('session')
    const sessions = prune(load())
    const oldest = Object.keys(sessions).sort((a, b) => sessions[a].created_at.localeCompare(sessions[b].created_at))
    if (cfg.max_concurrent > 0) {
      const mine = oldest.filter(id => sessions[id].username === user.username)
      for (const id of mine.slice(0, Math.max(0, mine.length - cfg.max_concurrent + 1))) delete sessions[id]
    }
    for (const id of oldest) {
      if (Object.keys(sessions).length < MAX_TRACKED) break
      delete sessions[id]
    }
    const now = new Date().toISOString()
    sessions[jti] = {
      username: user.username, role: user.role, created_at: now, last_seen: now,
      expires_at: expiresAt ?? Date.now() + Math.max(5, cfg.absolute_max_age_min) * 60_000,
      binding: fingerprint(req), ip_hint: normalizeClientIp(req?.ip || '').replace(/\.\d+$/, '.x'),
    }
    persist(sessions)
    return sessions[jti]
  })
}
const denied = (code, detail) => ({ ok: false, code, detail })
function touch(jti, req) {
  if (!jti) return denied('SESSION_UNKNOWN', 'Log in again.')
  return withConfigLock(() => {
    const sessions = load()
    const entry = sessions[jti]
    const revoked = load('admin_sessions_revoked')[jti]
    if (!entry || (Number.isFinite(revoked) && revoked > Date.now())) {
      return denied('SESSION_REVOKED', 'This session is no longer active. Log in again.')
    }
    let failure = null
    if (!Number.isFinite(expiry(entry)) || expiry(entry) <= Date.now()) failure = denied('SESSION_EXPIRED', 'This session expired. Log in again.')
    if (req?.user && entry.username !== req.user.username) failure = denied('SESSION_UNKNOWN', 'Log in again.')
    const cfg = settings.get('session')
    const current = fingerprint(req)
    if (current && entry.binding && current !== entry.binding) failure = denied('SESSION_BINDING', 'This session was started from a different client. Log in again.')
    const idleMs = Date.now() - Date.parse(entry.last_seen)
    if (!Number.isFinite(idleMs) || (cfg.idle_timeout_min > 0 && idleMs > cfg.idle_timeout_min * 60_000)) failure = denied('SESSION_IDLE', 'This session was idle too long. Log in again.')
    if (failure) {
      delete sessions[jti]
      persist(sessions)
      return failure
    }
    const adoptBinding = current && !entry.binding
    if (adoptBinding) entry.binding = current
    if (idleMs > 30_000 || adoptBinding) {
      entry.last_seen = new Date().toISOString()
      // An idle refresh never extends the absolute JWT expiry.
      persist(sessions)
    }
    return { ok: true }
  })
}
function close(jti) {
  return withConfigLock(() => {
    const sessions = load()
    delete sessions[jti]
    persist(sessions)
    return { ok: true }
  })
}
function closeAllFor(username) {
  return withConfigLock(() => {
    const sessions = load()
    let removed = 0
    for (const [jti, entry] of Object.entries(sessions)) {
      if (entry.username === username) { delete sessions[jti]; removed++ }
    }
    persist(sessions)
    return { ok: true, removed }
  })
}
function list() {
  return Object.entries(prune(load())).map(([jti, entry]) => ({
    id: jti.slice(0, 8), username: entry.username, role: entry.role,
    created_at: entry.created_at, last_seen: entry.last_seen, ip_hint: entry.ip_hint, bound: !!entry.binding,
  })).sort((a, b) => b.last_seen.localeCompare(a.last_seen))
}
function status() {
  const cfg = settings.get('session')
  return { ...cfg, active_sessions: list().length, effective: {
    token_lifetime_min: cfg.absolute_max_age_min,
    idle_timeout: cfg.idle_timeout_min > 0 ? `${cfg.idle_timeout_min} minutes` : 'off',
    bindings: [cfg.bind_ip && 'client IP', cfg.bind_user_agent && 'browser'].filter(Boolean),
  } }
}
module.exports = { open, touch, close, closeAllFor, list, status, fingerprint, STORE_KEY }
