// routes/gateway.js — the endpoints that live OUTSIDE CatWAF's rotating
// admin path, because something other than the dashboard has to reach them
// at a fixed URL:
//
//   /api/enforce        Caddy's forward_auth hop into the classification
//                       pipeline (ideas #1-#13).
//   /api/upload-gate    the inline malware scan for upload paths.
//   /catwaf-challenge   the interstitial a challenged visitor is sent to.
//   /metrics            the Prometheus scrape endpoint (idea #46).
//
// Being outside the gate makes each of these its own trust boundary, so each
// carries its own authentication:
//   * /api/enforce requires a shared key derived from the instance secret and
//     rendered into the Caddyfile, so only this install's own Caddy can call it.
//   * /api/upload-gate requires its own derived key, distinct from the
//     enforcement one so the two cannot be used interchangeably.
//   * /metrics requires a bearer token and a source-CIDR allowlist.
//   * /catwaf-challenge is deliberately public — it is served to unverified
//     visitors — and holds no state beyond a short-lived signed token.
//
// An enabled enforcement gate is a security dependency. Individual optional
// feeds can explicitly fail open; an unexpected pipeline failure cannot
// bypass configured bans or challenges.

const express = require('express')
const crypto = require('crypto')
const rateLimit = require('express-rate-limit')

const router = express.Router()

const enforce = require('../services/enforce')
const challenge = require('../services/challenge')
const settings = require('../services/settings')
const secrets = require('../services/secrets')
const bans = require('../services/bans')
const metricsSvc = require('../services/metrics')
const logger = require('../services/logger')
const { ipCoveredBy, normalizeClientIp } = require('../services/sanitize')

const log = logger.child('gateway')

// The challenge endpoints sit before the shared /api limiter (they have to
// be reachable pre-auth), so they carry their own. Without one, an anonymous
// flood of challenge pages pays SVG+HTML generation and grows server state
// per request.
const clientKey = req => require('../services/gatewayIdentity').clientIp(req) || 'unknown'
const challengeGetLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: clientKey,
  message: { detail: 'Too many requests — slow down.' },
})
const challengeVerifyLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: clientKey,
  message: { detail: 'Too many verification attempts — slow down.' },
})

function safeIsVerified(req) {
  try { return challenge.isVerified(req) } catch { return false }
}

function timingSafeEquals(a, b) {
  const bufA = Buffer.from(String(a || ''))
  const bufB = Buffer.from(String(b || ''))
  if (bufA.length === 0 || bufA.length !== bufB.length) return false
  return crypto.timingSafeEqual(bufA, bufB)
}

function forwardedIp(req) {
  // These two headers are only trusted because the rendered Caddyfile
  // overwrites them with `{http.request.remote.host}` on every hop into
  // CatWAF (enforce, challenge, upload gate). Sniffing X-Forwarded-For here
  // was removed deliberately: its leftmost entry is attacker-chosen, and a
  // visitor could rotate it per request to defeat bans and attempt counters.
  return require('../services/gatewayIdentity').clientIp(req)
}

function forwardedUri(req) {
  return String(req.headers['x-forwarded-uri'] || req.query.uri || '/').slice(0, 2048)
}

// Just the header *names* the visitor sent — not values, so nothing like a
// cookie or auth token ends up flowing into fingerprint scoring. Caddy's
// forward_auth proxies the full original request, so req.headers here is
// the visitor's own header set, not something CatWAF invented.
function forwardedHeaderNames(req) {
  return Object.keys(req.headers || {}).slice(0, 100)
}

// ─── /api/enforce ───────────────────────────────────────────────────────

router.all('/api/enforce', async (req, res) => {
  if (!timingSafeEquals(req.headers['x-catwaf-enforce-key'], secrets.derive('enforce-key'))) {
    // A wrong key is a misconfiguration or a probe, not a reason to break
    // the site — but it must not be treated as an authenticated call either.
    return res.status(404).json({ detail: 'Not found' })
  }

  const ip = forwardedIp(req)
  const uri = forwardedUri(req)
  const userAgent = String(req.headers['user-agent'] || '').slice(0, 512)
  const headers = forwardedHeaderNames(req)

  let verdict
  try {
    verdict = await enforce.evaluate({ ip, uri, userAgent, headers })
  } catch (e) {
    log.error('Enforcement pipeline failed', { error: e.message, ip })
    res.set('X-CatWAF-Verdict', 'unavailable')
    return res.status(503).json({ detail: 'Security verification unavailable' })
  }

  if (verdict.action === 'block') {
    const access = settings.get('access')
    res.set('X-CatWAF-Verdict', 'block')
    res.set('X-CatWAF-Reason', String(verdict.reason || '').replace(/[\r\n]/g, ' ').slice(0, 200))
    if (access.block_response_mode === 'silent') {
      // No body and an immediate socket destroy is the closest an Express
      // handler can get to Coraza's `drop`.
      res.status(access.blocked_status_code)
      return req.socket.destroy()
    }
    return res.status(access.blocked_status_code).json({ detail: 'Forbidden' })
  }

  if (verdict.action === 'challenge' && !safeIsVerified(req)) {
    res.set('X-CatWAF-Verdict', 'challenge')
    return res.redirect(302, `/catwaf-challenge?return_to=${encodeURIComponent(uri)}`)
  }

  res.set('X-CatWAF-Verdict', verdict.greylisted ? 'greylist' : 'allow')
  return res.status(200).json({ action: 'allow', cached: verdict.cached })
})

// ─── /api/upload-gate ───────────────────────────────────────────────────
//
// Malware scanning needs the request *body*, and forward_auth only ever
// forwards headers. So for the upload paths the operator nominates — and
// only those — Caddy proxies the request to CatWAF instead of to the origin,
// and CatWAF forwards it onward once the body has been scanned. CatWAF is
// therefore in the data path for uploads alone; everything else keeps going
// straight to the origin as before.
//
// The upstream to forward to arrives in a header set by Caddy, which makes it
// attacker-controlled input the moment anyone can reach this port directly.
// Two independent checks contain that: the shared key below, and an allowlist
// check that the named upstream is one this Caddyfile actually proxies to —
// so even with the key, this cannot be turned into a general-purpose proxy.

const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
])

function uploadUpstreamAllowed(target) {
  const caddySvc = require('../services/caddy')
  let known = []
  try {
    known = [...(caddySvc.currentSiteContext().upstreams || []), ...require('../services/managedRoutes').allRoutes().map(r => r.upstream)]
  } catch { known = [] }
  // Return the configured scheme, not the caller's version: old rendered
  // headers omitted https:// and must never silently downgrade to HTTP.
  return known.find(u => String(u) === target || String(u).replace(/^https?:\/\//, '') === target) || null
}

// Only the headers the visitor sent travel onward; CatWAF's own control
// headers are stripped so the origin never sees them.
function forwardableHeaders(req, upstream) {
  const out = {}
  const connectionHeaders = new Set(String(req.headers.connection || '').toLowerCase().split(',').map(s => s.trim()))
  for (const [name, value] of Object.entries(req.headers || {})) {
    const lower = name.toLowerCase()
    if (HOP_BY_HOP.has(lower) || connectionHeaders.has(lower)) continue
    if (lower.startsWith('x-catwaf-')) continue
    if (lower === 'content-length' || lower === 'host') continue
    out[name] = value
  }
  out.host = upstream
  return out
}

// Buffers at most `cap` bytes. If the body is larger, buffering stops there
// and the socket is left paused with the remainder unread, so an upload of
// any size costs a bounded amount of memory — the scanner's size limit is
// also the memory limit.
function readBounded(req, cap) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let total = 0
    const onData = chunk => {
      total += chunk.length
      if (total > cap) {
        req.off('data', onData)
        req.pause()
        chunks.push(chunk)
        return resolve({ buffer: Buffer.concat(chunks), truncated: true })
      }
      chunks.push(chunk)
    }
    req.on('data', onData)
    req.once('end', () => resolve({ buffer: Buffer.concat(chunks), truncated: false }))
    req.once('error', reject)
    req.once('aborted', () => reject(new Error('Upload aborted')))
  })
}

router.all('/api/upload-gate', async (req, res) => {
  if (!timingSafeEquals(req.headers['x-catwaf-upload-key'], secrets.derive('upload-gate-key'))) {
    return res.status(404).json({ detail: 'Not found' })
  }

  const cfg = settings.get('upload_scan')
  const clamav = require('../services/clamav')

  const upstream = String(req.headers['x-catwaf-upload-upstream'] || '').trim().slice(0, 256)
  const originalUri = String(req.headers['x-catwaf-upload-path'] || '/').slice(0, 2048)
  const ip = forwardedIp(req)

  const configuredUpstream = upstream && uploadUpstreamAllowed(upstream)
  if (!configuredUpstream || /^h2c:/i.test(configuredUpstream)) {
    log.error('Upload gate called with an upstream this instance does not proxy to', { upstream, ip })
    return res.status(502).json({ detail: 'Bad gateway' })
  }

  let body
  let truncated
  try {
    ({ buffer: body, truncated } = await readBounded(req, cfg.max_scan_bytes))
  } catch (e) {
    log.error('Reading an upload failed', { error: e.message, ip })
    return res.status(400).json({ detail: 'Could not read the request body' })
  }

  let verdict = { clean: true, virus: null, error: null }
  let scanned = false

  if (!cfg.enabled) {
    // Nothing to scan, but the request still has to reach the origin.
  } else if (truncated) {
    // Too large to scan within the configured bound.
    if (cfg.oversize_action === 'block') {
      log.warn('Refusing an upload too large to scan', { limit: cfg.max_scan_bytes, ip })
      return res.status(413).json({ detail: 'Upload too large to scan' })
    }
    log.warn('Forwarding an upload that was too large to scan', { limit: cfg.max_scan_bytes, ip })
  } else {
    // This handler is async: an uncaught rejection here would never answer
    // Caddy, so the visitor's upload hangs until timeout. Contain it.
    try {
      verdict = await clamav.scanBuffer(body, cfg, cfg.timeout_ms)
      scanned = true
    } catch (e) {
      log.error('Upload scan threw', { error: e.message, ip })
      verdict = { clean: null, virus: null, error: e.message }
      scanned = true
    }
  }

  if (scanned && verdict.clean === false) {
    log.warn('Malware found in an upload', { virus: verdict.virus, ip, uri: originalUri })
    if (cfg.ban_seconds > 0) {
      try {
        bans.ban({
          target: ip,
          source: 'upload_malware',
          reason: `Uploaded a file containing ${verdict.virus}`,
          seconds: cfg.ban_seconds,
        })
      } catch (e) { log.error('Could not ban an uploader', { error: e.message }) }
    }
    if (cfg.action === 'block') {
      res.set('X-CatWAF-Verdict', 'upload-malware')
      return res.status(403).json({ detail: 'Forbidden', reason: `Upload rejected: ${verdict.virus}` })
    }
  }

  // A scan that could not complete is not a verdict. Which way that falls is
  // the operator's call, because "uploads stop working when clamd is down"
  // and "unscanned uploads reach the origin" are both real risks.
  if (scanned && verdict.clean === null) {
    log.error('Upload could not be scanned', { error: verdict.error, ip, failOpen: cfg.fail_open })
    if (!cfg.fail_open) {
      res.set('X-CatWAF-Verdict', 'upload-scan-failed')
      return res.status(503).json({ detail: 'Upload scanning is unavailable' })
    }
  }

  // Allowed through — forward to the origin and stream the response back.
  // A truncated body means the rest is still unread on the socket, so the
  // original framing headers are preserved and the remainder is piped.
  let destination
  try { destination = new URL(/^https?:\/\//.test(configuredUpstream) ? configuredUpstream : `http://${configuredUpstream}`) }
  catch { return res.status(502).json({ detail: 'Bad gateway' }) }
  if (!originalUri.startsWith('/') || /[\r\n\0]/.test(originalUri)) return res.status(400).json({ detail: 'Invalid upload path' })
  const transport = destination.protocol === 'https:' ? require('https') : require('http')
  const headers = forwardableHeaders(req, destination.host)
  if (truncated) {
    if (req.headers['content-length']) headers['content-length'] = req.headers['content-length']
  } else {
    headers['content-length'] = String(body.length)
  }

  const proxied = transport.request({
    host: destination.hostname.replace(/^\[|\]$/g, ''),
    port: Number(destination.port) || (destination.protocol === 'https:' ? 443 : 80),
    method: req.method,
    path: originalUri,
    headers,
    timeout: 120_000,
  }, origin => {
    res.status(origin.statusCode || 502)
    const connectionHeaders = new Set(String(origin.headers.connection || '').toLowerCase().split(',').map(s => s.trim()))
    for (const [name, value] of Object.entries(origin.headers || {})) {
      if (!HOP_BY_HOP.has(name.toLowerCase()) && !connectionHeaders.has(name.toLowerCase()) && value !== undefined) res.set(name, value)
    }
    if (scanned) res.set('X-CatWAF-Verdict', 'upload-clean')
    origin.pipe(res)
    origin.on('error', () => res.destroy())
  })

  proxied.on('timeout', () => proxied.destroy(new Error('origin timed out')))
  proxied.on('error', e => {
    log.error('Could not forward a scanned upload to the origin', { error: e.message, upstream })
    if (!res.headersSent) res.status(502).json({ detail: 'Bad gateway' })
    else res.destroy()
  })
  res.on('close', () => { if (!res.writableFinished) proxied.destroy() })

  if (truncated) {
    proxied.write(body)
    req.pipe(proxied)
  } else {
    proxied.end(body)
  }
})

// ─── /catwaf-challenge ──────────────────────────────────────────────────

const challengeBody = express.urlencoded({ extended: false, limit: '16kb' })

function isSecureRequest(req) {
  return req.secure || String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https'
}

// The global helmet policy (default-src 'none', script-src 'self') blocks
// the challenge page's own inline proof-of-work script and every provider
// widget, so the page would render but never complete — a challenged visitor
// loops forever. This page-specific policy allows exactly what the page
// needs and nothing more; it is only sent with challenge HTML.
function challengeCsp(cfg) {
  const sources = require('../services/challenge/providers').cspSources(cfg.provider, cfg)
  const list = () => (sources.length ? sources.join(' ') : "'none'")
  return [
    "default-src 'none'",
    `script-src 'self' 'unsafe-inline'${sources.length ? ' ' + sources.join(' ') : ''}`,
    `frame-src ${list()}`,
    "style-src 'self' 'unsafe-inline'",
    `img-src 'self' data: ${sources.join(' ')}`,
    `connect-src 'self'${sources.length ? ' ' + sources.join(' ') : ''}`,
    "font-src 'self' data:",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
  ].join('; ')
}

router.get('/catwaf-challenge', challengeGetLimiter, (req, res) => {
  const cfg = settings.get('challenge')
  if (cfg.mode === 'off') return res.redirect(302, challenge.safeReturnTo(req.query.return_to))
  if (safeIsVerified(req)) return res.redirect(302, challenge.safeReturnTo(req.query.return_to))

  const issued = challenge.issue({
    ip: forwardedIp(req),
    userAgent: req.headers['user-agent'],
    returnTo: req.query.return_to,
  })
  res.set('Cache-Control', 'no-store, private')
  res.set('X-Robots-Tag', 'noindex, nofollow')
  res.set('Set-Cookie', challenge.pendingCookieHeader(issued.id, issued.expiresIn, { secure: isSecureRequest(req) }))
  res.set('Content-Security-Policy', challengeCsp(cfg))
  res.type('html').status(503).send(issued.html)
})

router.get('/catwaf-challenge/status', challengeGetLimiter, (req, res) => {
  res.set('Cache-Control', 'no-store').json({
    verified: safeIsVerified(req),
    mode: settings.get('challenge').mode,
  })
})

router.post('/catwaf-challenge/verify', challengeVerifyLimiter, challengeBody, async (req, res) => {
  const cfg = settings.get('challenge')
  if (cfg.mode === 'off') return res.redirect(302, '/')

  const ip = forwardedIp(req)
  const body = req.body || {}
  const providerToken = body[`g-recaptcha-response`] || body['h-captcha-response'] || body['cf-turnstile-response'] || body['mcaptcha__token'] || body.token

  let result
  try {
    result = await challenge.solve({
      id: String(body.challenge_id || ''),
      ip,
      userAgent: req.headers['user-agent'],
      answer: body.answer,
      proof: body.proof,
      providerToken,
      cookieId: challenge.parseCookies(req.headers.cookie)[challenge.PENDING_COOKIE],
      hostname: req.hostname,
    })
  } catch (e) {
    log.error('Challenge verification failed', { error: e.message })
    result = { ok: false, error: 'Verification could not be completed. Please try again.' }
  }

  const returnTo = challenge.safeReturnTo(body.return_to)

  if (result.banned) {
    bans.ban({
      target: ip,
      source: 'challenge',
      seconds: 3600,
      reason: `Failed the challenge ${cfg.max_attempts} times.`,
    })
    res.set('Content-Security-Policy', challengeCsp(cfg))
    return res.status(429).type('html').send(
      require('../services/challenge/page').build({
        mode: cfg.mode, provider: cfg.provider, siteKey: cfg.site_key,
        token: '', returnTo, error: 'Too many failed attempts. Try again later.', challengeId: '',
      })
    )
  }

  if (!result.ok) {
    const reissued = challenge.issue({ ip, userAgent: req.headers['user-agent'], returnTo, error: result.error })
    res.set('Cache-Control', 'no-store, private')
    res.set('Set-Cookie', challenge.pendingCookieHeader(reissued.id, reissued.expiresIn, { secure: isSecureRequest(req) }))
    res.set('Content-Security-Policy', challengeCsp(cfg))
    return res.status(403).type('html').send(reissued.html)
  }

  res.set('Set-Cookie', [
    challenge.cookieHeader(result.token, result.maxAge, { secure: isSecureRequest(req) }),
    challenge.pendingCookieHeader('', 0, { secure: isSecureRequest(req) }),
  ])
  res.set('Cache-Control', 'no-store, private')
  return res.redirect(303, returnTo)
})

// ─── /metrics (idea #46) ────────────────────────────────────────────────

function metricsAllowed(req) {
  const cfg = settings.get('metrics')
  if (!cfg.enabled) return { ok: false, status: 404, detail: 'Not found' }

  const ip = normalizeClientIp(req.ip || '')
  if (cfg.allow_cidrs.length && !cfg.allow_cidrs.some(cidr => ipCoveredBy(ip, cidr))) {
    return { ok: false, status: 403, detail: 'Metrics are not exposed to this address.' }
  }

  if (cfg.require_token) {
    const header = String(req.headers.authorization || '')
    const bearer = header.startsWith('Bearer ') ? header.slice(7) : ''
    if (!cfg.token || !timingSafeEquals(bearer, cfg.token)) {
      return { ok: false, status: 401, detail: 'A bearer token is required to scrape metrics.' }
    }
  }
  return { ok: true }
}

router.get('/metrics', (req, res) => {
  const check = metricsAllowed(req)
  if (!check.ok) return res.status(check.status).json({ detail: check.detail })
  res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
  res.set('Cache-Control', 'no-store')
  res.send(metricsSvc.render())
})

// The path is configurable, so the configured one is also served when it
// differs from the default.
router.get(/^\/[A-Za-z0-9._~/-]{1,120}$/, (req, res, next) => {
  const cfg = settings.get('metrics')
  if (!cfg.enabled || cfg.path === '/metrics' || req.path !== cfg.path) return next()
  const check = metricsAllowed(req)
  if (!check.ok) return res.status(check.status).json({ detail: check.detail })
  res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
  res.set('Cache-Control', 'no-store')
  res.send(metricsSvc.render())
})

module.exports = router
