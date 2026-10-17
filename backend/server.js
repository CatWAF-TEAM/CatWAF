
require('./services/env').load()

const express = require('express')
const cors = require('cors')
const helmet = require('helmet')
const rateLimit = require('express-rate-limit')
const path = require('path')
const fs = require('fs')
const { version: pkgVersion } = require('../package.json')

const { softAuth, authRequired, needsBootstrap } = require('./middleware/auth')
const requestLogger = require('./middleware/requestLogger')
const { notFoundHandler, errorHandler, decoyNotFound } = require('./middleware/errorHandler')
const { unwrapDynamicPath, requireDynamicPath } = require('./middleware/dynamicPath')
const { verifySignature, recordSignedPath, captureRawBody } = require('./middleware/signing')
const db = require('./services/db')
const auditSvc = require('./services/audit')
const caddySvc = require('./services/caddy')
const logger = require('./services/logger')
const log = logger.child('server')

process.on('uncaughtException', (err) => {
  log.error('Uncaught exception — process will exit', { error: err.message, stack: err.stack })
  process.exit(1)
})
process.on('unhandledRejection', (reason) => {
  const err = reason instanceof Error ? reason : new Error(String(reason))
  log.error('Unhandled promise rejection', { error: err.message, stack: err.stack })
})

// CORS_ORIGIN lists origins OTHER than this server that may call the API —
// the Vite dev server, or a dashboard deployed on a separate host. It is not
// needed for the normal deployment, where this process serves the dashboard
// and every call is same-origin (see isSameOrigin below).
let CORS_ORIGIN = process.env.CORS_ORIGIN
if (!CORS_ORIGIN) {
  CORS_ORIGIN = process.env.NODE_ENV === 'production' ? '' : 'http://localhost:8081'
  console.warn(`[CatWAF] CORS_ORIGIN is not set — allowing same-origin requests${CORS_ORIGIN ? ' and http://localhost:8081 for development' : ' only'}.`)
}
const allowedOrigins = CORS_ORIGIN.split(',').map(o => o.trim()).filter(Boolean)

const app = express()

// ─── Reverse-proxy trust ────────────────────────────────────────────────
// `trust proxy` decides whether X-Forwarded-For/X-Forwarded-Proto may
// influence req.ip and req.secure. Trusting one hop is correct when a proxy
// we control (Caddy, the provisioned nginx) actually sits in front — that is
// exactly the DOMAIN / HTTPS deployments. When neither signal is present,
// the API is being reached directly (localhost:8000, a bare LAN port), and
// trusting a hop would hand every client control of req.ip: rate-limit keys,
// login throttling and CIDR checks would all key off a header the client
// invented. Default to trusting NOTHING on direct deployments; operators who
// front the API with their own proxy set TRUST_PROXY_HOPS explicitly.
function parseTrustProxyHops() {
  const raw = process.env.TRUST_PROXY_HOPS
  const inferred = !!(process.env.DOMAIN || process.env.CATWAF_HTTPS === 'true')
  if (raw === undefined || raw === '') {
    const hops = inferred ? 1 : 0
    console.warn(`[CatWAF] TRUST_PROXY_HOPS not set — defaulting to ${hops} (${inferred ? 'domain/HTTPS deployment: trusting 1 reverse-proxy hop' : 'direct deployment: forwarded IP headers are ignored'}). Set it explicitly if that is wrong.`)
    return hops
  }
  const n = Number(raw)
  if (!Number.isInteger(n) || n < 0 || n > 8) {
    console.warn(`[CatWAF] TRUST_PROXY_HOPS="${raw}" is not an integer between 0 and 8 — ignoring forwarded headers entirely (0).`)
    return 0
  }
  return n
}
app.set('trust proxy', parseTrustProxyHops())
app.disable('x-powered-by')
app.disable('etag')

const connectSrc = ["'self'"]
if (process.env.DOMAIN) connectSrc.push(`https://api.catwaf.${process.env.DOMAIN}`)
for (const extra of (process.env.CATWAF_CONNECT_SRC || '').split(',').map(s => s.trim()).filter(Boolean)) {
  connectSrc.push(extra)
}
for (const origin of allowedOrigins) {
  if (/^https?:\/\//.test(origin) && !connectSrc.includes(origin)) connectSrc.push(origin)
}

// Is this install expected to be reached over HTTPS?
//
// This gates two headers that are correct for a public HTTPS deployment and
// actively break a plain-HTTP one:
//
//   upgrade-insecure-requests — rewrites the page's own http:// requests to
//     https://. Browsers exempt localhost and 127.0.0.1 as "potentially
//     trustworthy", but NOT a LAN address: on http://192.168.x.y:8000 every
//     asset and API call was upgraded to https:// against a server speaking
//     plain HTTP, so the dashboard could not even finish loading. That is
//     why CatWAF appeared to work on localhost and fail on an IP address.
//
//   Strict-Transport-Security — pins the *host* to HTTPS in the browser for
//     two years. Sent over plain HTTP it is ignored by browsers, but sending
//     it from a LAN address the moment a proxy ever terminates TLS would
//     strand that address. Only meaningful where HTTPS is real.
//
// Set CATWAF_HTTPS=true to force it on for a deployment behind a TLS
// terminator that this process cannot detect.
const EXPECTS_HTTPS = process.env.CATWAF_HTTPS === 'true'
  || (process.env.CATWAF_HTTPS !== 'false' && !!process.env.DOMAIN)

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      defaultSrc: ["'none'"],
      connectSrc,
      scriptSrc: ["'self'"],
      // Kept explicitly: `useDefaults: false` above drops helmet's defaults,
      // and this one blocks inline event-handler attributes.
      scriptSrcAttr: ["'none'"],
      styleSrc: ["'self'", 'https:', "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      fontSrc: ["'self'", 'https:', 'data:'],
      frameAncestors: ["'none'"],
      baseUri: ["'none'"],
      formAction: ["'self'"],
      objectSrc: ["'none'"],
      ...(EXPECTS_HTTPS ? { upgradeInsecureRequests: [] } : {}),
    },
  },
  hsts: EXPECTS_HTTPS ? { maxAge: 63072000, includeSubDomains: true, preload: true } : false,
  referrerPolicy: { policy: 'no-referrer' },
  crossOriginResourcePolicy: { policy: 'same-site' },
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  noSniff: true,
  frameguard: { action: 'deny' },
}))

// A request whose Origin is the very server that answered it is not a
// cross-origin request, whatever CORS_ORIGIN happens to say. In the normal
// single-port deployment the dashboard is served by this process, so the
// browser sends `Origin: http://<whatever-address-you-typed>` — localhost,
// 127.0.0.1, the LAN address, a hostname. Refusing those made CatWAF appear
// to work only from the exact URL recorded at setup time, and the failure
// surfaced in the browser as an unexplained network error during login.
//
// This does not widen anything: the response was already going to be sent to
// that origin, because that origin is this server. CORS_ORIGIN still governs
// genuinely cross-origin callers (a dashboard on a separate host, the
// `api.catwaf.<domain>` split deployment, the Vite dev server).
function isSameOrigin(req, origin) {
  const host = req.headers.host
  if (!host || !origin) return false
  // `x-forwarded-proto` is only trusted as far as trust proxy is configured,
  // and either way both candidates are compared — a proxy that terminates TLS
  // gives the browser https:// while this process sees http://.
  return origin === `${req.protocol}://${host}`
}

app.use(cors((req, cb) => {
  const origin = req.headers.origin
  cb(null, {
    origin: !origin || isSameOrigin(req, origin) || allowedOrigins.includes(origin),
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CatWAF-Ts', 'X-CatWAF-Nonce', 'X-CatWAF-Sig'],
    maxAge: 600,
  })
}))

app.get('/healthz', (req, res) => res.json({ ok: true }))
app.use((req, res, next) => {
  if (/^\/(?:api|g)(?:\/|$)/i.test(req.path)) res.set('Cache-Control', 'no-store')
  next()
})

// Routes that have to live at a fixed URL, outside the rotating admin path:
// Caddy's enforcement hop, the visitor-facing challenge page, the metrics
// scrape endpoint, and the first-run wizard. Each carries its own
// authentication (see routes/gateway.js) because none of them can rely on
// the dashboard's gate. Mounted before the gate so a forward_auth call is
// never answered by the 404 decoy — which forward_auth would read as "deny"
// and use to take the protected site down.
// Both routers parse their own bodies: the shared express.json below is
// paired with the request-signing raw-body capture, which these pre-gate
// routes are deliberately not part of.
app.use(require('./routes/gateway'))
app.use(require('./routes/setup'))

const ungatedLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { detail: 'Too many requests — slow down.' },
})
const gatedLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 600,
  standardHeaders: true,
  legacyHeaders: false,
  message: { detail: 'Too many requests — slow down.' },
})

app.use(unwrapDynamicPath)
app.use(recordSignedPath)
app.use('/api', softAuth)
app.use('/api', (req, res, next) => (req.viaDynamicPath ? gatedLimiter : ungatedLimiter)(req, res, next))
app.use(requireDynamicPath(decoyNotFound))
app.use(express.json({ limit: '2mb', verify: captureRawBody }))
app.use('/api', verifySignature)
app.use('/api', (req, res, next) => (req.viaDynamicPath ? authRequired(req, res, next) : next()))
app.use(requestLogger)

app.use(require('./routes/auth'))
app.use(require('./routes/dashboard'))
app.use(require('./routes/waf'))
app.use(require('./routes/network'))
app.use(require('./routes/alerts'))
app.use(require('./routes/sensitive'))
app.use(require('./routes/health'))
app.use(require('./routes/cloudflare'))
app.use(require('./routes/caddy'))
app.use(require('./routes/scanner'))
app.use(require('./routes/security'))
app.use(require('./routes/users'))
app.use(require('./routes/waftools'))
app.use(require('./routes/catai'))
app.use(require('./routes/settings'))
app.use(require('./routes/protect'))
app.use(require('./routes/apps'))
app.use(require('./routes/ops'))

// Express 4 does not forward rejected route promises. Apply one boundary
// to all mounted handlers, including the pre-gate routers, so a failed
// storage read or asynchronous integration produces an error response.
function containAsyncErrors(stack) {
  for (const layer of stack) {
    if (layer.route) containAsyncErrors(layer.route.stack)
    else if (layer.handle?.stack) containAsyncErrors(layer.handle.stack)
    else if (layer.handle.length < 4) {
      const handler = layer.handle
      layer.handle = function containedHandler(req, res, next) {
        try {
          const result = handler(req, res, next)
          if (result && typeof result.catch === 'function') result.catch(next)
        } catch (error) { next(error) }
      }
    }
  }
}
containAsyncErrors(app._router.stack)

const DIST = path.join(__dirname, '..', 'frontend', 'dist')
if (fs.existsSync(path.join(DIST, 'index.html'))) {
  app.use(express.static(DIST, {
    index: false,
    setHeaders: (res, filePath) => {
      res.setHeader('Cache-Control', /[\\/]assets[\\/]/.test(filePath) ? 'public, max-age=31536000, immutable' : 'no-store')
    },
  }))
  app.get(/^\/assets\//, (req, res) => {
    res.setHeader('Cache-Control', 'no-store')
    res.status(404).json({ detail: 'Asset not found. Reload the page to pick up the current build.' })
  })

  app.get(/^(?!\/api|\/g\/|\/healthz).*/, (req, res) => {
    res.setHeader('Cache-Control', 'no-store')
    res.sendFile(path.join(DIST, 'index.html'))
  })
} else {
  app.get('/', (req, res) => res.json({ status: 'CatWAF Free API running', version: pkgVersion }))
}

app.use(notFoundHandler)
app.use(errorHandler)

const PORT = Number(process.env.PORT || 8000)
const HOST = process.env.HOST || '127.0.0.1'
const requestLogSvc = require('./services/requestLog')
const state = require('./services/state')

function start() {
  require('./services/configTx').recover()
  require('./services/configTx').assertReady()
  if (auditSvc.getSnapshots().length === 0) auditSvc.snapshot({ user: { username: 'system' } }, 'initial')

  // SQLite pragmas that are configurable rather than hardcoded.
  try {
    const tuning = require('./services/dbTuning').apply()
    if (tuning.failures.length) log.warn('Some database settings could not be applied', { failures: tuning.failures })
  } catch (e) { log.error('Database tuning failed', { error: e.message }) }

  // Everything time-based registers into one scheduler rather than growing
  // its own timer.
  try {
    const jobs = require('./services/jobs')
    const count = require('./services/jobRegistry').registerAll()
    jobs.start()
    log.info(`Scheduler started with ${count} job(s)`)
  } catch (e) { log.error('Could not start the job scheduler', { error: e.message }) }

  const ingestResult = requestLogSvc.ingestNewEntries()
  if (ingestResult.reason) log.info(`Request log ingestion: ${ingestResult.reason}`)
  const ingestTimer = setInterval(() => {
    try { requestLogSvc.ingestNewEntries() }
    catch (e) { log.error('Request log ingestion failed', { error: e.message }) }
  }, 5000)
  ingestTimer.unref()

  try { requestLogSvc.purgeOldEntries(state.WAF.retention_days) }
  catch (e) { log.error('Request log purge failed', { error: e.message }) }
  const purgeTimer = setInterval(() => {
    try { requestLogSvc.purgeOldEntries(state.WAF.retention_days) }
    catch (e) { log.error('Request log purge failed', { error: e.message }) }
  }, 6 * 60 * 60 * 1000)
  purgeTimer.unref()

  // Coraza never prunes its own audit log. Without this it grows until the
  // disk fills and the WAF stops. maintain() recovers any interrupted
  // rotation, rotates on size/age, and prunes archives; it never throws.
  const auditLogSvc = require('./services/auditLog')
  const runAuditMaintenance = () => {
    const r = auditLogSvc.maintain()
    if (r.rotated) log.info('Audit log rotated', { from: r.from, to: r.to, reason: r.reason, ingested: r.ingested })
    else if (r.ok === false && r.error) log.error('Audit log maintenance failed', { error: r.error })
    for (const f of r.pruneFailures || []) log.error('Could not prune a rotated audit log', { file: f.name, error: f.error })
  }
  runAuditMaintenance()
  const auditTimer = setInterval(runAuditMaintenance, 10 * 60 * 1000)
  auditTimer.unref()

  const server = app.listen(PORT, HOST, () => {
    log.info(`CatWAF Free API listening on http://${HOST}:${PORT}`, { port: PORT, db: db.DB_PATH, version: pkgVersion })
    console.log(`[CatWAF] API    http://${HOST}:${PORT}`)
    console.log(`[CatWAF] Data   ${db.DB_PATH}`)
    console.log(`[CatWAF] Caddy  ${caddySvc.CADDYFILE_PATH}${caddySvc.CADDYFILE_SOURCE === 'auto-detected' ? ' (auto-detected)' : ''}`)
    try {
      fs.accessSync(caddySvc.CADDYFILE_PATH, fs.constants.W_OK)
    } catch {
      console.log('[CatWAF]        ⚠ not writable by this user — WAF changes will fail until that is fixed.')
      console.log('[CatWAF]          Set CADDYFILE_PATH to a Caddyfile you can write, or run as a user that can.')
    }
    if (needsBootstrap()) {
      console.log('[CatWAF] No admin account yet — run `catwaf --setup` to create one.')
    }
  })

  server.headersTimeout = 20000
  server.requestTimeout = 60000
  server.keepAliveTimeout = 10000

  for (const sig of ['SIGTERM', 'SIGINT']) {
    process.on(sig, () => {
      log.info(`Received ${sig} — shutting down`)
      server.close(() => process.exit(0))
      setTimeout(() => process.exit(0), 5000).unref()
    })
  }
}

if (require.main === module) start()

module.exports = { app, start }
