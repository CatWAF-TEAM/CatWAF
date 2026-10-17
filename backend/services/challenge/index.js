// challenge/index.js — the challenge gate (ideas #1, #2, #3, #4).
//
// CatWAF's only two answers today are 200 and 403. A challenge is the useful
// tier between them: a visitor who looks suspicious but is not clearly
// hostile gets asked to prove it is a browser, which stops essentially all
// low-effort scripted traffic — scanners, scrapers, credential stuffing —
// without touching anomaly scoring or adding any false-positive risk for a
// real browser.
//
// The proof is a signed, short-lived cookie. Signing reuses the HMAC
// derivation in services/secrets.js rather than introducing a second key
// scheme, so a solved challenge cannot be forged and cannot outlive its
// window.

const crypto = require('crypto')

const settings = require('../settings')
const secrets = require('../secrets')
const captcha = require('./captcha')
const providers = require('./providers')
const page = require('./page')
const { ipCoveredBy, normalizeClientIp } = require('../sanitize')

const COOKIE_NAME = 'catwaf_ch'
const PENDING_COOKIE = 'catwaf_chid'
const TOKEN_VERSION = 'v1'

// Pending challenges live in memory only: they are worth seconds, are
// worthless after being solved, and persisting them would mean writing a row
// per unsolved bot request.
const pending = new Map()
const attempts = new Map()

const MAX_PENDING = 20000
// Failure counters are keyed per address. The address is now Caddy-asserted,
// but a flood of distinct real (or proxy-spoofed) addresses must still not
// grow this map without bound: entries expire on their own, and this cap
// drops the oldest beyond it.
const MAX_ATTEMPTS_ENTRIES = 10000

function key(label, input = '') { return secrets.derive(`challenge/${label}`, input) }

function sweep() {
  const now = Date.now()
  for (const [id, entry] of pending) if (entry.expires <= now) pending.delete(id)
  for (const [ip, entry] of attempts) if (entry.expires <= now) attempts.delete(ip)
}

// ─── Token minting and verification ─────────────────────────────────────

function bindingFor(ip, userAgent) {
  const cfg = settings.get('challenge')
  // The token is bound to the address it was issued to when a session-level
  // binding is configured; otherwise a solved token could simply be handed
  // around between bots.
  return crypto.createHash('sha256')
    .update(`${normalizeClientIp(ip || '')}|${cfg.mode === 'off' ? '' : String(userAgent || '').slice(0, 200)}`)
    .digest('hex').slice(0, 16)
}

function mintToken({ ip, userAgent, minutes }) {
  const exp = Date.now() + Math.max(1, minutes) * 60_000
  const nonce = crypto.randomBytes(8).toString('hex')
  const binding = bindingFor(ip, userAgent)
  const payload = `${TOKEN_VERSION}.${exp}.${nonce}.${binding}`
  const sig = crypto.createHmac('sha256', key('token')).update(payload).digest('hex').slice(0, 32)
  return `${payload}.${sig}`
}

function verifyToken(token, { ip, userAgent }) {
  if (typeof token !== 'string' || token.length > 256) return { valid: false, reason: 'malformed' }
  const parts = token.split('.')
  if (parts.length !== 5 || parts[0] !== TOKEN_VERSION) return { valid: false, reason: 'malformed' }
  const [, expRaw, nonce, binding, sig] = parts

  const expected = crypto.createHmac('sha256', key('token'))
    .update(`${TOKEN_VERSION}.${expRaw}.${nonce}.${binding}`).digest('hex').slice(0, 32)
  const a = Buffer.from(sig)
  const b = Buffer.from(expected)
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return { valid: false, reason: 'bad signature' }

  const exp = Number(expRaw)
  if (!Number.isFinite(exp) || exp <= Date.now()) return { valid: false, reason: 'expired' }
  if (binding !== bindingFor(ip, userAgent)) return { valid: false, reason: 'issued to a different client' }
  return { valid: true, expires: new Date(exp).toISOString() }
}

function parseCookies(header) {
  const out = {}
  for (const part of String(header || '').split(';')) {
    const idx = part.indexOf('=')
    if (idx === -1) continue
    const name = part.slice(0, idx).trim()
    const raw = part.slice(idx + 1).trim()
    // A malformed escape (e.g. "catwaf_ch=%") must not throw: this runs on
    // every request carrying a Cookie header, including the pre-auth
    // challenge endpoints and Caddy's forward_auth hop — an exception here
    // would 500 the challenge page or hang enforcement for that visitor.
    let value = raw
    try { value = decodeURIComponent(raw) } catch {}
    if (name) out[name] = value
  }
  return out
}

function isVerified(req) {
  const cfg = settings.get('challenge')
  if (cfg.mode === 'off') return true
  const cookies = parseCookies(req.headers?.cookie)
  const token = cookies[COOKIE_NAME]
  if (!token) return false
  return verifyToken(token, { ip: clientIp(req), userAgent: req.headers?.['user-agent'] }).valid
}

function clientIp(req) {
  // Mirrors routes/gateway.js forwardedIp(): the rendered Caddy config
  // overwrites X-Real-IP with the real connection address on every hop into
  // CatWAF, so it is authoritative here. X-Forwarded-For is deliberately not
  // consulted — its first entry is visitor-controlled, and trusting it let a
  // banned or rate-limited client rotate identity per request.
  return require('../gatewayIdentity').clientIp(req)
}

// ─── Scoping (#4) ───────────────────────────────────────────────────────
//
// Reuses the same CIDR/country/user-agent primitives the allow and block
// lists already use, rather than inventing a second matching language.

function matchesPath(uri, patterns) {
  const path = String(uri || '/').split('?')[0]
  return patterns.some(p => (p.endsWith('*') ? path.startsWith(p.slice(0, -1)) : path === p))
}

function isExempt({ ip, uri, userAgent, asn, rdns, country }) {
  const cfg = settings.get('challenge')
  if (matchesPath(uri, cfg.exempt_paths)) return { exempt: true, why: 'path' }
  for (const cidr of cfg.exempt_ips) if (ipCoveredBy(ip, cidr)) return { exempt: true, why: `IP ${cidr}` }
  if (asn && cfg.exempt_asns.includes(asn)) return { exempt: true, why: `ASN ${asn}` }
  if (rdns) {
    for (const suffix of cfg.exempt_rdns) {
      const bare = suffix.replace(/^\./, '')
      if (rdns === bare || rdns.endsWith(`.${bare}`)) return { exempt: true, why: `reverse DNS ${suffix}` }
    }
  }
  if (userAgent) {
    const lower = String(userAgent).toLowerCase()
    for (const pattern of cfg.exempt_user_agents) {
      if (lower.includes(String(pattern).toLowerCase())) return { exempt: true, why: 'user agent' }
    }
  }
  if (cfg.trigger === 'countries') {
    if (!country || !cfg.challenge_countries.includes(country)) return { exempt: true, why: 'country not in the challenge list' }
  }
  return { exempt: false }
}

// `suspicious` is supplied by the enforcement pipeline — a flag raised by
// any other signal (greylist miss, DNSBL, bad behaviour, threat feed).
function shouldChallenge(ctx) {
  const cfg = settings.get('challenge')
  if (cfg.mode === 'off') return { challenge: false }
  const exempt = isExempt(ctx)
  if (exempt.exempt) return { challenge: false, reason: `exempt: ${exempt.why}` }
  // Under-attack mode overrides the trigger selector: every non-exempt
  // visitor proves they run JavaScript until the switch is turned off.
  try {
    if (require('../settings').get('ddos').emergency) {
      return { challenge: true, mode: cfg.mode, reason: 'emergency mode' }
    }
  } catch { /* ddos group not present in old state — fall through */ }
  if (cfg.trigger === 'suspicious' && !ctx.suspicious) return { challenge: false, reason: 'not flagged by any other signal' }
  return { challenge: true, mode: cfg.mode }
}

// ─── Issuing and solving ────────────────────────────────────────────────

function issue({ ip, userAgent, returnTo, error = null }) {
  sweep()
  const cfg = settings.get('challenge')
  if (pending.size >= MAX_PENDING) {
    // Under a flood, stop minting new state rather than growing without
    // bound; existing challenges still resolve.
    const oldest = pending.keys().next().value
    if (oldest !== undefined) pending.delete(oldest)
  }

  const id = crypto.randomBytes(16).toString('hex')
  const entry = {
    id,
    ip: normalizeClientIp(ip || ''),
    userAgent: String(userAgent || '').slice(0, 200),
    mode: cfg.mode,
    expires: Date.now() + Math.max(10, cfg.resolve_seconds) * 1000,
    answer: null,
  }

  let captchaSvg = null
  if (cfg.mode === 'captcha') {
    const generated = captcha.create(cfg.captcha_length)
    entry.answer = generated.answer
    captchaSvg = generated.svg
  }
  pending.set(id, entry)

  const html = page.build({
    mode: cfg.mode,
    provider: cfg.provider,
    siteKey: cfg.site_key,
    token: '',
    returnTo: safeReturnTo(returnTo),
    error,
    captchaSvg,
    challengeId: id,
  })
  return { id, html, mode: cfg.mode, expiresIn: cfg.resolve_seconds }
}

// A challenge must never become an open redirect: only a same-site path is
// ever returned to.
//
// Prefix checks alone are not enough. To the WHATWG URL parser a backslash is
// a path separator for special schemes, so a browser reads `/\evil.com` as
// `//evil.com` and leaves the site — and express does not encode the
// backslash away, because encodeurl's allowed range covers 0x5C. Rather than
// enumerate the tricks, the value is resolved against a placeholder origin
// and accepted only if it is still on that origin; anything that moved
// off-origin (or that we could not parse at all) collapses to `/`.
const RETURN_TO_ORIGIN_HOST = 'catwaf.invalid'

function safeReturnTo(value) {
  const raw = String(value == null ? '/' : value)
  if (!raw || raw.length > 2048) return '/'
  // Control characters are stripped or rewritten by browsers before the URL
  // is parsed, so a value that looks same-origin here could still change
  // meaning on the client.
  if (/[\x00-\x1F\x7F]/.test(raw)) return '/'
  if (!raw.startsWith('/')) return '/'
  // Redundant with the origin check below, but stated explicitly so the
  // reason a backslash is refused is visible at the point of refusal.
  if (raw.includes('\\')) return '/'

  let parsed
  try { parsed = new URL(raw, `http://${RETURN_TO_ORIGIN_HOST}`) } catch { return '/' }
  if (parsed.protocol !== 'http:' || parsed.host !== RETURN_TO_ORIGIN_HOST) return '/'

  const out = `${parsed.pathname}${parsed.search}${parsed.hash}`
  if (!out.startsWith('/') || out.startsWith('//')) return '/'
  return out
}

function recordAttempt(ip) {
  const cfg = settings.get('challenge')
  const clean = normalizeClientIp(ip || '')
  const entry = attempts.get(clean) || { count: 0, expires: Date.now() + cfg.resolve_seconds * 1000 * 4 }
  entry.count++
  attempts.set(clean, entry)
  if (attempts.size > MAX_ATTEMPTS_ENTRIES) {
    for (const [ipKey, e] of attempts) {
      if (attempts.size <= MAX_ATTEMPTS_ENTRIES) break
      if (e.expires <= Date.now()) attempts.delete(ipKey)
    }
    while (attempts.size > MAX_ATTEMPTS_ENTRIES) {
      attempts.delete(attempts.keys().next().value)
    }
  }
  return entry.count
}

function clearAttempts(ip) { attempts.delete(normalizeClientIp(ip || '')) }

async function solve({ id, ip, userAgent, answer, proof, providerToken }) {
  sweep()
  const cfg = settings.get('challenge')
  const entry = pending.get(id)
  if (!entry) return { ok: false, error: 'This challenge has expired. Please try again.' }
  if (entry.expires <= Date.now()) { pending.delete(id); return { ok: false, error: 'This challenge has expired. Please try again.' } }
  if (entry.ip && entry.ip !== normalizeClientIp(ip || '')) {
    return { ok: false, error: 'This challenge was issued to a different connection.' }
  }

  const count = recordAttempt(ip)
  if (count > cfg.max_attempts) {
    pending.delete(id)
    return { ok: false, banned: true, error: 'Too many failed attempts.' }
  }

  let solved = false
  let detail = null

  if (entry.mode === 'cookie') {
    solved = true
  } else if (entry.mode === 'javascript') {
    solved = verifyProof(id, proof)
    if (!solved) detail = 'The browser check did not complete.'
  } else if (entry.mode === 'captcha') {
    solved = captcha.matches(entry.answer, answer)
    if (!solved) detail = 'Those characters did not match. Please try again.'
  } else if (entry.mode === 'provider') {
    const result = await providers.verify(cfg.provider, providerToken, cfg, ip)
    solved = result.ok
    if (!solved) detail = result.error
  }

  if (!solved) return { ok: false, error: detail || 'Verification failed.', attemptsLeft: Math.max(0, cfg.max_attempts - count) }

  pending.delete(id)
  clearAttempts(ip)
  return {
    ok: true,
    token: mintToken({ ip, userAgent, minutes: cfg.valid_minutes }),
    maxAge: cfg.valid_minutes * 60,
  }
}

// Mirrors the client-side loop in challenge/page.js: find n such that
// djb2(id + n) % 4096 === 0. Cheap to check, non-trivial to produce, and
// impossible for a client that does not execute JavaScript.
function verifyProof(id, proof) {
  const n = Number(proof)
  if (!Number.isInteger(n) || n < 0 || n > 5_000_000) return false
  let hash = 5381
  const input = `${id}${n}`
  for (let i = 0; i < input.length; i++) hash = ((hash << 5) + hash + input.charCodeAt(i)) >>> 0
  return hash % 4096 === 0
}

function cookieHeader(token, maxAge, { secure = true } = {}) {
  const parts = [
    `${COOKIE_NAME}=${encodeURIComponent(token)}`,
    'Path=/',
    `Max-Age=${Math.max(0, Math.trunc(maxAge))}`,
    'HttpOnly',
    'SameSite=Lax',
  ]
  if (secure) parts.push('Secure')
  return parts.join('; ')
}

function status() {
  sweep()
  const cfg = settings.get('challenge')
  return {
    mode: cfg.mode,
    provider: cfg.provider,
    trigger: cfg.trigger,
    pending: pending.size,
    tracked_failures: attempts.size,
    providers: providers.list(),
    site_key_set: !!cfg.site_key,
    secret_key_set: !!cfg.secret_key,
  }
}

function reset() { pending.clear(); attempts.clear() }

module.exports = {
  COOKIE_NAME, PENDING_COOKIE,
  isVerified, shouldChallenge, isExempt, issue, solve, status, reset,
  mintToken, verifyToken, cookieHeader, clientIp, parseCookies, safeReturnTo,
  recordAttempt, clearAttempts, verifyProof,
}
