
const crypto = require('crypto')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')

const secrets = require('../services/secrets')
const configLock = require('../services/configLock')
const JWT_SECRET = secrets.JWT_SECRET

const BCRYPT_COST = 12
const db = require('../services/db')

const DEFAULT_USERS = []

function loadUsers() {
  const stored = db.getStateStrict('users')
  if (stored === null) {
    if (db.getStateStrict('auth_initialized')) throw new Error('Account store is missing')
    return DEFAULT_USERS
  }
  if (!Array.isArray(stored) || !stored.length || stored.some(u => !u || typeof u.id !== 'string' || typeof u.username !== 'string' || typeof u.password_hash !== 'string' || !['admin', 'viewer'].includes(u.role))) {
    throw new Error('Account store is invalid')
  }
  return stored
}

// The account list was read once at module load and never again, so it went
// stale the moment another process touched it — and CatWAF is routinely more
// than one process. `catwaf user add` while the API was running left the API
// still answering "No account has been created yet"; `catwaf user passwd` and
// `catwaf user remove` did not affect the running API at all, which matters
// because those are the commands an operator reaches for to revoke access.
//
// CLI/list reads are cached for at most a second. Authentication and the
// post-password-comparison check force a fresh SQLite read so resets and role
// changes from another process take effect at the next authentication check.
const USER_REVALIDATE_MS = 1000
let _usersReadAt = 0

function refreshUsers(force = false) {
  const now = Date.now()
  if (!force && now - _usersReadAt < USER_REVALIDATE_MS) return
  const fresh = loadUsers()
  // loadUsers fails closed on missing or damaged initialized account state.
  _users = fresh
  _usersReadAt = now
}

function needsBootstrap() { refreshUsers(); return _users.length === 0 }
function saveUsers(users) {
  db.setState('users', users)
  db.setState('auth_initialized', true)
  _usersReadAt = Date.now()
}

let _users = loadUsers()
if (_users.length) db.setState('auth_initialized', true)
const USERS = new Proxy([], {
  get(_, prop) { refreshUsers(); return Reflect.get(_users, prop, _users) },
  set(_, prop, value) { return Reflect.set(_users, prop, value, _users) },
  has(_, prop) { return Reflect.has(_users, prop) },
  ownKeys() { return Reflect.ownKeys(_users) },
  deleteProperty(_, prop) { return Reflect.deleteProperty(_users, prop) },
  getOwnPropertyDescriptor(_, prop) {
    const d = Reflect.getOwnPropertyDescriptor(_users, prop)
    return d ? { ...d, configurable: true } : undefined
  },
})

const VALID_ROLES = ['admin', 'viewer']
const MIN_PASSWORD_LENGTH = 8

// Every mutator re-reads the committed user list inside the lock: a
// `catwaf user add` in the CLI and a dashboard role change can no longer
// whole-blob-overwrite each other.
function addUser({ username, password, role = 'viewer', bootstrap = false }) {
  return configLock.withConfigLock(() => {
  _usersReadAt = 0 // force the freshest read inside the lock
  refreshUsers()
  if (bootstrap && _users.length) throw new Error('Setup has already completed')
  if (typeof username !== 'string' || !/^[A-Za-z0-9._-]{2,32}$/.test(username) || ['__proto__', 'constructor', 'prototype', 'guest'].includes(username)) throw new Error('Invalid or reserved username')
  if (_users.find(u => u.username === username)) throw new Error(`User "${username}" already exists`)
  if (!VALID_ROLES.includes(role)) throw new Error(`Role must be one of: ${VALID_ROLES.join(', ')}`)
  validatePassword(password)
  const user = { id: 'u_' + crypto.randomBytes(6).toString('hex'), username, password_hash: bcrypt.hashSync(password, BCRYPT_COST), role, created_at: new Date().toISOString() }
  _users = [..._users, user]
  saveUsers(_users)
  return user
  })
}
function setPassword(username, password) {
  return configLock.withConfigLock(() => {
  _usersReadAt = 0
  refreshUsers()
  const u = _users.find(x => x.username === username)
  if (!u) throw new Error(`User "${username}" not found`)
  validatePassword(password)
  u.password_hash = bcrypt.hashSync(password, BCRYPT_COST)
  // Every token issued up to and including this second is dead: softAuth
  // compares with <=, and routes/auth.js refuses to mint a token whose iat
  // would land on this same second. Second granularity is all a JWT iat
  // carries, so the boundary has to be inclusive on both sides or a token
  // minted in the reset second survives the reset that was meant to kill it.
  u.tokens_valid_after = Math.floor(Date.now() / 1000)
  saveUsers(_users)
  // Belt and braces, and the part that shows up in the session list: revoke
  // the tracked sessions by jti as well, so an operator can see that the
  // reset ended them. Required lazily and tolerantly for the same reason
  // authRequired does it — the CLI paths never load the settings namespace,
  // and the tokens_valid_after stamp above is the authoritative control.
  try { require('../services/session').closeAllFor(username) } catch {}
  return u
  })
}

function listUsers() {
  refreshUsers()
  return _users.map(u => ({ id: u.id, username: u.username, role: u.role, created_at: u.created_at || null }))
}

function findUser(username, { fresh = false } = {}) {
  refreshUsers(fresh)
  return _users.find(u => u.username === username) || null
}

function removeUser(username) {
  return configLock.withConfigLock(() => {
  _usersReadAt = 0
  refreshUsers()
  const target = _users.find(u => u.username === username)
  if (!target) throw new Error(`User "${username}" not found`)
  if (target.role === 'admin' && _users.filter(u => u.role === 'admin').length === 1) {
    throw new Error('Cannot remove the last admin account — CatWAF would become unadministrable.')
  }
  _users = _users.filter(u => u.username !== username)
  saveUsers(_users)
  return { username }
  })
}

function setRole(username, role) {
  return configLock.withConfigLock(() => {
  _usersReadAt = 0
  refreshUsers()
  if (!VALID_ROLES.includes(role)) throw new Error(`Role must be one of: ${VALID_ROLES.join(', ')}`)
  const u = _users.find(x => x.username === username)
  if (!u) throw new Error(`User "${username}" not found`)
  if (u.role === 'admin' && role !== 'admin' && _users.filter(x => x.role === 'admin').length === 1) {
    throw new Error('Cannot demote the last admin account — CatWAF would become unadministrable.')
  }
  u.role = role
  saveUsers(_users)
  return { username, role }
  })
}

function verifyPassword(username, password) {
  refreshUsers()
  const u = _users.find(x => x.username === username)
  if (!u || !u.password_hash) return false
  return bcrypt.compareSync(String(password || ''), u.password_hash)
}

function validatePassword(password) {
  if (typeof password !== 'string' || password.length < MIN_PASSWORD_LENGTH || Buffer.byteLength(password, 'utf8') > 72) {
    throw new Error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters and at most 72 UTF-8 bytes`)
  }
}

const JWT_ISSUER = 'catwaf-free'
const JWT_AUDIENCE = 'catwaf-dashboard'

function softAuth(req, res, next) {
  const h = req.headers.authorization || ''
  const bearer = h.startsWith('Bearer ') ? h.slice(7) : ''
  if (bearer) {
    try {
      const claims = jwt.verify(bearer, JWT_SECRET, {
        algorithms: ['HS256'],
        issuer: JWT_ISSUER,
        audience: JWT_AUDIENCE,
      })
      refreshUsers(true)
      const live = _users.find(u => u.id === claims.id)
      // Inclusive: a JWT iat is whole seconds, so a token minted in the same
      // second as the reset carries iat === tokens_valid_after. Treating that
      // as fresh left a one-second window in which an already-issued token
      // survived the password change. Legitimate logins are not caught by the
      // wider comparison because routes/auth.js pushes a new token's iat past
      // tokens_valid_after when the two would collide.
      const staleAfterReset = live && live.tokens_valid_after && claims.iat != null
        && claims.iat <= live.tokens_valid_after
      if (live && !staleAfterReset) {
        req.user = { ...claims, username: live.username, role: live.role }
      }
    } catch {}
  }
  if (!req.user) req.user = { username: 'guest', role: 'viewer' }
  next()
}

function authRequired(req, res, next) {
  if (!req.user || !req.user.jti || req.user.username === 'guest') {
    return res.status(401).json({ detail: 'Authentication required.', code: 'AUTH_REQUIRED' })
  }
  // Idle timeout and IP/browser binding (idea #25). Required lazily so the
  // middleware stays usable in the CLI paths that never load the settings
  // namespace. An unreadable session store must reject access.
  try {
    const check = require('../services/session').touch(req.user.jti, req)
    if (!check || check.ok !== true) {
      return res.status(401).json({ detail: check?.detail || 'Session could not be verified.', code: check?.code || 'SESSION_UNVERIFIED' })
    }
  } catch {
    return res.status(401).json({ detail: 'Session could not be verified. Log in again.', code: 'SESSION_UNVERIFIED' })
  }
  next()
}

function writeRequired(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ detail: 'Read-only role. Log in as admin to modify.' })
  next()
}

const LOGIN_ATTEMPTS = new Map()
const LOGIN_WINDOW_MS = 5 * 60 * 1000
const LOGIN_MAX_ATTEMPTS = 10

function attemptKey(req) {
  const username = typeof req.body?.username === 'string' ? req.body.username : ''
  return `${req.ip}:${username.toLowerCase().slice(0, 64)}`
}

// Second counter keyed on the username alone. The per-ip:user key above can
// be rotated at will by a client that controls its X-Forwarded-For (direct
// exposure, TRUST_PROXY_HOPS=1), so without this a brute-force campaign
// against one account faces no cumulative limit. NAT offices share the
// budget below — 30 password tries per account per 5 minutes is far more
// than any human needs.
const LOGIN_MAX_ATTEMPTS_PER_USER = 30
const USER_ATTEMPTS = new Map()

function loginRateLimit(req, res, next) {
  const key = attemptKey(req)
  const now = Date.now()
  const entry = LOGIN_ATTEMPTS.get(key)
  if (entry && now - entry.firstAttemptAt < LOGIN_WINDOW_MS) {
    if (entry.count >= LOGIN_MAX_ATTEMPTS) {
      const retryAfterSec = Math.ceil((LOGIN_WINDOW_MS - (now - entry.firstAttemptAt)) / 1000)
      res.set('Retry-After', String(retryAfterSec))
      return res.status(429).json({ detail: 'Too many login attempts. Try again later.' })
    }
    entry.count++
  } else {
    LOGIN_ATTEMPTS.set(key, { count: 1, firstAttemptAt: now })
  }

  const username = typeof req.body?.username === 'string' ? req.body.username.toLowerCase().slice(0, 64) : null
  if (username) {
    const userEntry = USER_ATTEMPTS.get(username)
    if (userEntry && now - userEntry.firstAttemptAt < LOGIN_WINDOW_MS) {
      if (userEntry.count >= LOGIN_MAX_ATTEMPTS_PER_USER) {
        res.set('Retry-After', String(Math.ceil((LOGIN_WINDOW_MS - (now - userEntry.firstAttemptAt)) / 1000)))
        return res.status(429).json({ detail: 'Too many login attempts for this account. Try again later.' })
      }
      userEntry.count++
    } else {
      USER_ATTEMPTS.set(username, { count: 1, firstAttemptAt: now })
    }
  }

  if (LOGIN_ATTEMPTS.size > 5000) {
    for (const [k, v] of LOGIN_ATTEMPTS) if (now - v.firstAttemptAt > LOGIN_WINDOW_MS) LOGIN_ATTEMPTS.delete(k)
  }
  // Hard ceiling independent of age: a flood of unique ip:username keys
  // within one window must not grow the map without bound just because its
  // entries have not expired yet.
  while (LOGIN_ATTEMPTS.size > 10000) {
    LOGIN_ATTEMPTS.delete(LOGIN_ATTEMPTS.keys().next().value)
  }
  while (USER_ATTEMPTS.size > 5000) {
    for (const [k, v] of USER_ATTEMPTS) if (now - v.firstAttemptAt > LOGIN_WINDOW_MS) USER_ATTEMPTS.delete(k)
    while (USER_ATTEMPTS.size > 5000) USER_ATTEMPTS.delete(USER_ATTEMPTS.keys().next().value)
  }
  next()
}
function clearLoginAttempts(req) {
  LOGIN_ATTEMPTS.delete(attemptKey(req))
  const username = typeof req.body?.username === 'string' ? req.body.username.toLowerCase().slice(0, 64) : null
  if (username) USER_ATTEMPTS.delete(username)
}

module.exports = { JWT_SECRET, JWT_ISSUER, JWT_AUDIENCE, USERS, softAuth, authRequired, writeRequired, loginRateLimit, clearLoginAttempts, addUser, setPassword, needsBootstrap, listUsers, findUser, removeUser, setRole, verifyPassword, VALID_ROLES, BCRYPT_COST, MIN_PASSWORD_LENGTH }
