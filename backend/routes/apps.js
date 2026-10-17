// routes/apps.js — the HTTP surface for CatWAF's application pipeline:
//
//     DISCOVER -> GENERATE -> APPLY -> VERIFY
//
// Every step here is the same code `catwaf auto` runs. This router adds no
// discovery, no generation and no verification of its own — it is a thin
// transport over backend/services/discovery/ and backend/services/proxy/, so
// the dashboard and the CLI can never disagree about whether a site is
// protected.
//
// The one rule this file exists to enforce: a route is reported as protected
// only when proxy/verify.js proved it with real requests — a benign request
// that was served and an inert CRS payload that was refused. A generated
// config, a successful apply and a clean reload are all reported as exactly
// what they are, and never as protection.

const express = require('express')
const router = express.Router()

const protectSvc = require('../services/proxy/protect')
const verifySvc = require('../services/proxy/verify')
const inventory = require('../services/proxy/inventory')
const discovery = require('../services/discovery')
const { summarizeContainer, evidenceFor } = require('../services/discovery/summary')
const caddySvc = require('../services/caddy')
const state = require('../services/state')
const db = require('../services/db')
const auditSvc = require('../services/audit')
const logger = require('../services/logger')
const { authRequired, writeRequired } = require('../middleware/auth')

const log = logger.child('apps')

// Discovery inspects containers and probes ports; protect additionally
// rewrites the Caddyfile and reloads. Neither is safe to run concurrently
// with itself — two protect runs would race on the same generated region —
// so the pipeline is serialised here rather than relying on the caller.
let inFlight = null

function serialise(label, fn) {
  if (inFlight) {
    return Promise.reject(Object.assign(
      new Error(`CatWAF is already running ${inFlight}. Wait for it to finish and try again.`),
      { status: 409 },
    ))
  }
  inFlight = label
  return Promise.resolve()
    .then(fn)
    .finally(() => { inFlight = null })
}

function fail(res, e) {
  const status = e.status || 500
  if (status >= 500) log.error('Application pipeline failed', { error: e.message })
  return res.status(status).json({ detail: e.message })
}

// The projection of a protect() result that is safe and useful to a client.
// `protected` is derived from the verification result alone.
function projectResult(result, { dryRun = false } = {}) {
  const verification = result.verification || null
  return {
    ok: result.ok !== false,
    stage: result.stage,
    dry_run: dryRun,
    error: result.error || null,
    message: result.message || null,
    containers: (result.containers || []).map(summarizeContainer),
    web_apps: (result.webApps || []).map(summarizeContainer),
    routes: result.routes || [],
    skipped: result.skipped || [],
    proxy: result.proxy || null,
    backup: result.backup || null,
    reloaded: result.reloaded ?? null,
    reload_error: result.reloadError || null,
    proxy_started: result.proxyStarted || null,
    verification,
    // Never inferred from "we wrote a config". Only verification sets this.
    protected: !!verification?.allProtected,
  }
}

// ─── Inventory ──────────────────────────────────────────────────────────

// What is applied right now, read back out of the live Caddyfile. Cheap and
// side-effect free, so the dashboard can poll it.
router.get('/api/apps', authRequired, (req, res) => {
  const applied = inventory.read()
  res.json({
    ...applied,
    caddy_running: caddySvc.isCaddyRunning(),
    busy: inFlight,
    // Verification is a live network operation, so this endpoint reports only
    // what is configured. Clients must call /api/apps/verify for the verdict.
    note: 'Lists the routes CatWAF has applied. Applied is not the same as protected — call POST /api/apps/verify for a verified verdict.',
  })
})

// ─── Discover ───────────────────────────────────────────────────────────

// OBSERVE -> CORRELATE -> CLASSIFY, with nothing written.
router.post('/api/apps/discover', authRequired, writeRequired, async (req, res) => {
  try {
    const report = await serialise('a discovery scan', () => discovery.discover({
      // Probing each candidate port with a real HTTP request is what
      // separates "something is listening" from "something serves HTTP", so
      // it is on by default; a caller can opt out when it only needs the
      // container inventory quickly.
      skipHttpProbe: req.body?.skip_http_probe === true,
    }))

    if (!report.ok) {
      return res.status(200).json({
        ok: false,
        code: report.code,
        detail: report.message,
        containers: [],
        web_apps: [],
      })
    }

    res.json({
      ok: true,
      containers: report.containers.map(c => ({ ...summarizeContainer(c), evidence: evidenceFor(c) })),
      web_apps: report.webApps.map(c => ({ ...summarizeContainer(c), evidence: evidenceFor(c) })),
      errors: report.errors || [],
    })
  } catch (e) { fail(res, e) }
})

// ─── Preview (GENERATE, nothing applied) ────────────────────────────────

// The exact routes a protect run would create, with no file written, no
// reload and no port assignment persisted.
router.post('/api/apps/preview', authRequired, writeRequired, async (req, res) => {
  try {
    const result = await serialise('a configuration preview', () => protectSvc.protect({
      state, db, dryRun: true,
    }))
    res.json(projectResult(result, { dryRun: true }))
  } catch (e) { fail(res, e) }
})

// ─── Protect (APPLY + VERIFY) ───────────────────────────────────────────

// Rewrites CatWAF's generated region, reloads, and then proves the result
// with real traffic. Changes the request path for live sites, so it is
// admin-only and audited.
router.post('/api/apps/protect', authRequired, writeRequired, async (req, res) => {
  const skipVerify = req.body?.skip_verify === true
  try {
    const result = await serialise('a protect run', () => protectSvc.protect({
      state,
      db,
      dryRun: false,
      skipVerify,
      // Starting the proxy is a privileged, host-level action. The CLI
      // injects it because it runs as the operator; the API deliberately
      // does not, and reports "the configuration is not live yet" instead
      // of trying to start services on the operator's behalf.
      startProxy: null,
    }))

    const payload = projectResult(result)
    auditSvc.audit(req, 'apps.protect', (result.routes || []).map(r => r.name).join(', ') || 'none', {
      stage: result.stage,
      routes: (result.routes || []).length,
      verified: payload.protected,
      skip_verify: skipVerify,
    })
    res.json(payload)
  } catch (e) { fail(res, e) }
})

// ─── Verify ─────────────────────────────────────────────────────────────

// Re-runs the two real requests against what is applied right now. This is
// the only endpoint whose answer may be presented to a user as "protected".
router.post('/api/apps/verify', authRequired, writeRequired, async (req, res) => {
  const applied = inventory.read()
  if (!applied.ok) return res.status(500).json({ detail: applied.error })
  if (!applied.routes.length) {
    return res.json({
      ok: true,
      routes: [],
      verification: { results: [], protectedCount: 0, allProtected: false },
      detail: 'CatWAF has not applied any application routes yet, so there is nothing to verify.',
    })
  }

  try {
    const verification = await serialise('a verification run', () => verifySvc.verifyRoutes(
      applied.routes,
      // Nothing is being reloaded here, so there is no listener to wait for.
      // A handful of quick attempts is enough to ride out a busy moment.
      { attempts: 4, delayMs: 250 },
    ))
    res.json({ ok: true, routes: applied.routes, verification })
  } catch (e) { fail(res, e) }
})

module.exports = router
