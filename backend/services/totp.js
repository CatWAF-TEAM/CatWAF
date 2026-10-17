// totp.js — RFC 6238 time-based one-time passwords for admin login
// (idea #49).
//
// CatWAF Free is explicitly single-admin: that one account is the entire
// attack surface for taking over the WAF protecting the site. 2FA is the
// best-understood hardening step available for exactly that shape, and
// CatWAF did not have it — its own security score has been reporting the gap
// as a permanent `fail`.
//
// No new crypto and no new dependency: TOTP is HMAC-SHA1 over a time counter
// (RFC 6238 on top of RFC 4226), and base32 is a twenty-line encoder. Both
// are implemented here against the spec rather than pulled in.

const crypto = require('crypto')

const db = require('./db')
const secrets = require('./secrets')
const { withConfigLock } = require('./configLock')

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
const STORE_KEY = 'totp'
const DIGITS = 6
const PERIOD = 30
// One step either side absorbs ordinary clock drift between the phone and
// the server. Wider windows meaningfully weaken the factor.
const DEFAULT_WINDOW = 1
const RECOVERY_CODE_COUNT = 10

function base32Encode(buffer) {
  let bits = 0
  let value = 0
  let out = ''
  for (const byte of buffer) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31]
  return out
}

function base32Decode(input) {
  const clean = String(input || '').toUpperCase().replace(/[\s=-]/g, '')
  let bits = 0
  let value = 0
  const bytes = []
  for (const char of clean) {
    const idx = BASE32_ALPHABET.indexOf(char)
    if (idx === -1) throw new Error('Not a valid base32 secret')
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  return Buffer.from(bytes)
}

function counterBuffer(counter) {
  const buf = Buffer.alloc(8)
  buf.writeBigUInt64BE(BigInt(counter))
  return buf
}

// RFC 4226 §5.3 dynamic truncation.
function hotp(secretBuffer, counter, digits = DIGITS) {
  const hmac = crypto.createHmac('sha1', secretBuffer).update(counterBuffer(counter)).digest()
  const offset = hmac[hmac.length - 1] & 0x0f
  const code = ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff)
  return String(code % 10 ** digits).padStart(digits, '0')
}

function totp(secretBase32, { at = Date.now(), period = PERIOD, digits = DIGITS } = {}) {
  return hotp(base32Decode(secretBase32), Math.floor(at / 1000 / period), digits)
}

function verifyCode(secretBase32, code, { at = Date.now(), window = DEFAULT_WINDOW, period = PERIOD } = {}) {
  const submitted = String(code || '').replace(/\s/g, '')
  if (!/^\d{6,8}$/.test(submitted)) return { valid: false, reason: 'A code is six digits.' }
  const secretBuffer = base32Decode(secretBase32)
  const counter = Math.floor(at / 1000 / period)
  for (let drift = -window; drift <= window; drift++) {
    const expected = hotp(secretBuffer, counter + drift, submitted.length)
    const a = Buffer.from(expected)
    const b = Buffer.from(submitted)
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) return { valid: true, drift }
  }
  return { valid: false, reason: 'That code is not valid right now.' }
}

// ─── Enrollment state ───────────────────────────────────────────────────
//
// Secrets and recovery codes are stored encrypted with a key derived from
// the instance root secret, so a stolen database file alone does not hand
// over the second factor.

function encryptionKey() {
  return crypto.createHash('sha256').update(secrets.derive('totp-store')).digest()
}

function seal(plaintext) {
  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(), iv, { authTagLength: 16 })
  const enc = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()])
  return `${iv.toString('base64')}.${cipher.getAuthTag().toString('base64')}.${enc.toString('base64')}`
}

function unseal(sealed) {
  const [ivB64, tagB64, dataB64] = String(sealed || '').split('.')
  if (!ivB64 || !tagB64 || !dataB64) throw new Error('Stored value is not in the expected format')
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey(), Buffer.from(ivB64, 'base64'), { authTagLength: 16 })
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'))
  return Buffer.concat([decipher.update(Buffer.from(dataB64, 'base64')), decipher.final()]).toString('utf8')
}

function loadStore() {
  const stored = db.getStateStrict(STORE_KEY)
  if (stored === null) return Object.create(null)
  if (typeof stored !== 'object' || Array.isArray(stored)) throw new Error('Invalid second-factor store')
  for (const entry of Object.values(stored)) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry) || typeof entry.enabled !== 'boolean' || typeof entry.secret !== 'string' || !Array.isArray(entry.recovery)) throw new Error('Invalid second-factor record')
  }
  return Object.assign(Object.create(null), stored)
}

function saveStore(store) { db.setState(STORE_KEY, store) }

function hashRecoveryCode(code) {
  return crypto.createHmac('sha256', secrets.derive('totp-recovery')).update(String(code).toUpperCase()).digest('hex')
}

function generateRecoveryCodes(count = RECOVERY_CODE_COUNT) {
  const codes = []
  for (let i = 0; i < count; i++) {
    const raw = crypto.randomBytes(5).toString('hex').toUpperCase()
    codes.push(`${raw.slice(0, 5)}-${raw.slice(5)}`)
  }
  return codes
}

function isEnabled(username) {
  const entry = loadStore()[username]
  return !!(entry && entry.enabled)
}

function status(username) {
  const entry = loadStore()[username]
  if (!entry) return { enrolled: false, enabled: false, pending: false }
  return {
    enrolled: true,
    enabled: !!entry.enabled,
    pending: !entry.enabled,
    enrolled_at: entry.enrolled_at || null,
    confirmed_at: entry.confirmed_at || null,
    recovery_codes_remaining: (entry.recovery || []).length,
  }
}

// Step one: generate a secret and the otpauth:// URI the authenticator app
// scans. Nothing is enforced until confirm() proves the app is working —
// enrolling without that check is how people lock themselves out.
function beginEnrollment(username, { issuer = 'CatWAF', account = null } = {}) {
  const secret = base32Encode(crypto.randomBytes(20))
  const store = loadStore()
  if (store[username]?.enabled) throw new Error('Two-factor authentication is already enabled')
  store[username] = {
    secret: seal(secret),
    enabled: false,
    enrolled_at: new Date().toISOString(),
    recovery: [],
  }
  saveStore(store)

  const label = encodeURIComponent(`${issuer}:${account || username}`)
  const uri = `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=${DIGITS}&period=${PERIOD}`
  return { secret, uri, digits: DIGITS, period: PERIOD }
}

function confirmEnrollment(username, code) {
  const store = loadStore()
  const entry = store[username]
  if (!entry) return { ok: false, error: 'Start enrollment before confirming it.' }
  if (entry.enabled) return { ok: false, error: 'Two-factor authentication is already enabled for this account.' }

  let secret
  try { secret = unseal(entry.secret) } catch { return { ok: false, error: 'The stored secret could not be read. Start enrollment again.' } }

  const check = verifyCode(secret, code)
  if (!check.valid) return { ok: false, error: check.reason }

  const recoveryCodes = generateRecoveryCodes()
  entry.enabled = true
  entry.confirmed_at = new Date().toISOString()
  entry.recovery = recoveryCodes.map(hashRecoveryCode)
  // The confirming code counts as used, exactly as a login code does.
  // Without this the code just typed here stays valid for the rest of its
  // window — an observer who saw it during enrollment could log in with it.
  entry.last_counter = Math.floor(Date.now() / 1000 / PERIOD) + (check.drift || 0)
  saveStore(store)

  // The only time the plaintext recovery codes exist. They are stored as
  // HMACs, so this response cannot be reproduced later.
  return { ok: true, recovery_codes: recoveryCodes }
}

function verify(username, code) {
  const store = loadStore()
  const entry = store[username]
  if (!entry || !entry.enabled) return { ok: true, skipped: 'not enrolled' }

  let secret
  try { secret = unseal(entry.secret) } catch { return { ok: false, error: 'The stored second factor could not be read.' } }

  const submitted = String(code || '').trim().toUpperCase()

  // A recovery code is single-use: it is removed the moment it works.
  if (/^[A-F0-9]{5}-[A-F0-9]{5}$/.test(submitted)) {
    const hashed = hashRecoveryCode(submitted)
    const idx = entry.recovery.indexOf(hashed)
    if (idx === -1) return { ok: false, error: 'That recovery code is not valid.' }
    entry.recovery.splice(idx, 1)
    saveStore(store)
    return { ok: true, used_recovery_code: true, recovery_codes_remaining: entry.recovery.length }
  }

  const check = verifyCode(secret, submitted)
  if (!check.valid) return { ok: false, error: check.reason }

  // Replaying a code inside its 30-second window would otherwise be valid;
  // remembering the last accepted counter closes that.
  const counter = Math.floor(Date.now() / 1000 / PERIOD) + (check.drift || 0)
  if (entry.last_counter && counter <= entry.last_counter) {
    return { ok: false, error: 'That code has already been used. Wait for the next one.' }
  }
  entry.last_counter = counter
  saveStore(store)
  return { ok: true, drift: check.drift }
}

function disable(username) {
  const store = loadStore()
  if (!store[username]) return { ok: false, error: 'Two-factor authentication is not enrolled for this account.' }
  delete store[username]
  saveStore(store)
  return { ok: true }
}

function regenerateRecoveryCodes(username) {
  const store = loadStore()
  const entry = store[username]
  if (!entry || !entry.enabled) return { ok: false, error: 'Two-factor authentication is not enabled for this account.' }
  const codes = generateRecoveryCodes()
  entry.recovery = codes.map(hashRecoveryCode)
  saveStore(store)
  return { ok: true, recovery_codes: codes }
}

function anyEnabled() {
  return Object.values(loadStore()).some(e => e && e.enabled)
}

module.exports = {
  ...Object.fromEntries(Object.entries({ beginEnrollment, confirmEnrollment, verify, disable, regenerateRecoveryCodes })
    .map(([name, fn]) => [name, (...args) => withConfigLock(() => fn(...args))])),
  status, isEnabled, anyEnabled, totp, hotp, verifyCode, base32Encode, base32Decode,
  DIGITS, PERIOD, STORE_KEY,
}
