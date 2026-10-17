// routes/setup.js — the browser-based first-run wizard (idea #52).
//
// This does not replace `catwaf --setup`; the shell installer stays the
// primary path and is the only one that can do privileged work. This is a
// second on-ramp for the case the installer cannot cover: CatWAF is already
// running (a one-click host image, a container someone else started) and the
// first admin account still has to be created without touching a terminal.
//
// It is a bootstrap path, not a feature surface. Every route here 404s the
// moment an admin account exists — the same response an unknown path gets —
// so it cannot be probed for later, and it is rate limited because it is one
// of the few endpoints reachable before authentication.

const express = require('express')
const crypto = require('crypto')
const rateLimit = require('express-rate-limit')
const router = express.Router()

const { addUser, needsBootstrap, MIN_PASSWORD_LENGTH } = require('../middleware/auth')
const auditSvc = require('../services/audit')
const settings = require('../services/settings')
const sites = require('../services/sites')
const totp = require('../services/totp')
const caddySvc = require('../services/caddy')
const secrets = require('../services/secrets')
const edition = require('../services/edition')
const logger = require('../services/logger')

const log = logger.child('setup')

const setupLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { detail: 'Too many setup attempts. Try again later.' },
})

// The gate. Once an account exists this router behaves as if it does not
// exist at all, which is why every route below can assume bootstrap state.
function bootstrapOnly(req, res, next) {
  if (!needsBootstrap()) return res.status(404).json({ detail: 'Not found' })
  // Binding to loopback is insufficient: a reverse proxy can make a remote
  // request appear local. Web bootstrap is explicitly enabled with a secret.
  const expected = process.env.CATWAF_SETUP_TOKEN || ''
  const provided = req.get('X-CatWAF-Setup-Token') || ''
  const a = Buffer.from(expected), b = Buffer.from(provided)
  if (a.length < 32 || a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(404).json({ detail: 'Not found' })
  }
  next()
}

// This router is mounted ahead of the shared JSON parser (which is paired
// with request-signing's raw-body capture), so it parses its own bodies.
router.use('/api/setup', setupLimiter, bootstrapOnly, express.json({ limit: '64kb' }))

router.get('/api/setup/status', (req, res) => {
  res.json({
    needs_setup: true,
    edition: edition.current(),
    min_password_length: MIN_PASSWORD_LENGTH,
    // Everything the wizard should warn about before it starts, gathered up
    // front so the first screen can be honest about what will and will not
    // work on this machine.
    environment: {
      caddyfile: caddySvc.CADDYFILE_PATH,
      caddyfile_writable: (() => {
        try { require('fs').accessSync(caddySvc.CADDYFILE_PATH, require('fs').constants.W_OK); return true } catch { return false }
      })(),
      caddy_running: caddySvc.isCaddyRunning(),
      audit_log: caddySvc.auditLogStatus(),
      jwt_secret_persistent: !secrets.isEphemeral(),
      domain: process.env.DOMAIN || null,
    },
    steps: ['account', 'two-factor', 'site', 'done'],
  })
})

router.post('/api/setup/account', (req, res) => {
  const { username, password, confirm } = req.body || {}

  if (typeof username !== 'string' || !/^[A-Za-z0-9._-]{3,32}$/.test(username)) {
    return res.status(400).json({ detail: 'Username must be 3-32 characters: letters, numbers and . _ -' })
  }
  if (typeof password !== 'string' || password.length < MIN_PASSWORD_LENGTH) {
    return res.status(400).json({ detail: `Password must be at least ${MIN_PASSWORD_LENGTH} characters.` })
  }
  if (confirm !== undefined && confirm !== password) {
    return res.status(400).json({ detail: 'The two passwords do not match.' })
  }

  try {
    const user = addUser({ username, password, role: 'admin', bootstrap: true })
    auditSvc.audit({ user: { username }, ip: req.ip }, 'setup.account-created', username, { via: 'web-wizard' })
    log.info('Admin account created through the web setup wizard', { username })
    res.json({
      ok: true,
      user: { id: user.id, username: user.username, role: user.role },
      next: 'two-factor',
      // The wizard is now closed. Say so, because the next request to any
      // /api/setup route will 404 and that should not look like a bug.
      note: 'Setup is now complete for account creation — these setup endpoints are no longer reachable. Log in to continue.',
      warnings: secrets.isEphemeral()
        ? ['JWT_SECRET is not set, so every restart will log you out. Set it in .env before relying on this install.']
        : [],
    })
  } catch (e) {
    res.status(400).json({ detail: e.message })
  }
})

// Offered during the wizard so the site's hostname can be recorded before
// the first login — it is what the unknown-Host rejection and security.txt
// both key off.
router.post('/api/setup/site', (req, res) => {
  const { primary_host = '', aliases = [] } = req.body || {}
  const result = settings.set('sites', { primary_host, aliases })
  if (!result.ok) return res.status(400).json({ detail: result.error })
  res.json({ ok: true, sites: sites.describe(), next: 'done' })
})

router.get('/api/setup/discover', async (req, res) => {
  // Discovery only reads local container and process metadata, and this
  // route is bootstrap-only, so it cannot be used to fingerprint a
  // configured install.
  try {
    const discovery = require('../services/discovery')
    // The wizard only needs names and ports to show "we found these apps",
    // and it runs before any account exists — so it takes the cheap pass and
    // skips the per-port HTTP probes. (`quick` was never an option discover()
    // understood, so this previously did the full probing pass.)
    const result = await discovery.discover({ skipHttpProbe: true })
    res.json({
      ok: true,
      apps: (result?.webApps || []).map(app => ({
        name: app.name,
        runtime: app.runtime?.label || null,
        port: app.web?.port || null,
        published: !!app.web?.published,
        framework: app.php?.framework || null,
      })),
    })
  } catch (e) {
    res.json({ ok: false, error: e.message, apps: [] })
  }
})

module.exports = router
