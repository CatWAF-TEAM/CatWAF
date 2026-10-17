// routes/ops.js — the operational surface added alongside the new settings:
// scheduled jobs (#44), backups (#45), telemetry (#47), reports (#51),
// templates (#64), plugins (#53), cache housekeeping (#63), autoconf (#66),
// the site registry (#65), shared state (#67), database tuning (#68),
// certificates (#20-#23), sessions and two-factor login (#25, #49).

const express = require('express')
const router = express.Router()

const jobs = require('../services/jobs')
const backups = require('../services/backups')
const telemetry = require('../services/telemetry')
const reports = require('../services/reports')
const templates = require('../services/templates')
const plugins = require('../services/plugins')
const caches = require('../services/caches')
const autoconf = require('../services/autoconf')
const sites = require('../services/sites')
const sharedState = require('../services/sharedState')
const dbTuning = require('../services/dbTuning')
const certs = require('../services/certs')
const sessionSvc = require('../services/session')
const totp = require('../services/totp')
const settings = require('../services/settings')
const auditSvc = require('../services/audit')
const caddyModules = require('../services/caddyModules')
const { authRequired, writeRequired, verifyPassword } = require('../middleware/auth')

function bad(res, detail, code = 400) { return res.status(code).json({ detail }) }

// ─── Scheduled jobs (#44) ───────────────────────────────────────────────

router.get('/api/jobs', authRequired, (req, res) => {
  res.json({ jobs: jobs.list(), settings: settings.get('jobs') })
})

router.post('/api/jobs/:name/run', authRequired, writeRequired, async (req, res) => {
  if (!jobs.has(req.params.name)) return bad(res, `No job named "${req.params.name}"`, 404)
  const result = await jobs.runJob(req.params.name, { manual: true })
  auditSvc.audit(req, 'job.run', req.params.name, { ok: result.ok })
  res.status(result.ok ? 200 : 500).json(result)
})

// ─── Backups (#45) ──────────────────────────────────────────────────────

router.get('/api/backups', authRequired, (req, res) => res.json(backups.list()))

router.post('/api/backups/run', authRequired, writeRequired, (req, res) => {
  try {
    const result = backups.run({ dryRun: req.body?.dry_run === true, destination: req.body?.destination || null })
    if (!result.dryRun) auditSvc.audit(req, 'backup.run', result.file || '')
    res.json(result)
  } catch (e) {
    bad(res, e.message)
  }
})

router.post('/api/backups/verify', authRequired, writeRequired, (req, res) => {
  res.json(backups.verifyDestination(req.body?.destination || settings.get('backups').destination))
})

// ─── Telemetry (#47) ────────────────────────────────────────────────────

router.get('/api/telemetry', authRequired, (req, res) => res.json(telemetry.status()))

router.post('/api/telemetry/send', authRequired, writeRequired, async (req, res) => {
  try {
    res.json(await telemetry.send({ dryRun: req.body?.dry_run !== false }))
  } catch (e) {
    bad(res, e.message, 502)
  }
})

// ─── Reports (#51) ──────────────────────────────────────────────────────

router.get('/api/reports', authRequired, (req, res) => {
  const format = ['json', 'csv', 'html', 'events-csv'].includes(req.query.format) ? req.query.format : 'json'
  const result = reports.generate({ from: req.query.from, to: req.query.to, format })
  if (!result.ok) return bad(res, result.error)
  if (format === 'json') return res.json(result.report)

  auditSvc.audit(req, 'report.export', format, { from: req.query.from || null, to: req.query.to || null })
  res.set('Content-Type', result.contentType)
  res.set('Content-Disposition', `attachment; filename="${result.filename}"`)
  res.send(result.body)
})

// ─── Templates (#64) ────────────────────────────────────────────────────

router.get('/api/templates', authRequired, (req, res) => res.json({ templates: templates.list() }))

router.get('/api/templates/:id', authRequired, (req, res) => {
  const template = templates.get(req.params.id)
  if (!template) return bad(res, 'No such template.', 404)
  res.json(template)
})

router.post('/api/templates', authRequired, writeRequired, (req, res) => {
  const { name, groups = null, include_waf = true, description = '' } = req.body || {}
  const result = templates.save(name, { groups, includeWaf: include_waf, description, req })
  if (!result.ok) return bad(res, result.error)
  auditSvc.audit(req, 'template.save', result.template.id)
  res.json(result)
})

router.post('/api/templates/:id/apply', authRequired, writeRequired, (req, res) => {
  const result = templates.apply(req.params.id, { req, dryRun: req.body?.dry_run === true })
  if (!result.ok) return bad(res, result.error || result.detail)
  if (!result.dryRun) auditSvc.audit(req, 'template.apply', req.params.id, { changes: result.changes?.length })
  res.json(result)
})

router.delete('/api/templates/:id', authRequired, writeRequired, (req, res) => {
  const result = templates.remove(req.params.id)
  if (!result.ok) return bad(res, result.error)
  auditSvc.audit(req, 'template.remove', req.params.id)
  res.json(result)
})

router.get('/api/templates/:id/export', authRequired, (req, res) => {
  const result = templates.exportTemplate(req.params.id)
  if (!result.ok) return bad(res, result.error, 404)
  res.set('Content-Disposition', `attachment; filename="catwaf-template-${req.params.id}.json"`)
  res.json(result.payload)
})

router.post('/api/templates/import', authRequired, writeRequired, (req, res) => {
  const result = templates.importTemplate(req.body, { req })
  if (!result.ok) return bad(res, result.error)
  auditSvc.audit(req, 'template.import', result.template.id)
  res.json(result)
})

// ─── Plugins (#53) ──────────────────────────────────────────────────────

router.get('/api/plugins', authRequired, (req, res) => {
  res.json({
    plugins: plugins.list(),
    // Stated up front rather than buried in docs: this format is data only,
    // and there is no code path that would run a plugin.
    policy: {
      data_only: true,
      forbidden_fields: plugins.FORBIDDEN_FIELDS,
      contexts: plugins.VALID_CONTEXTS,
      note: 'CatWAF plugins declare settings defaults, knowledge entries and constrained Caddy directive templates. They cannot ship or reference executable code, and installing from a URL requires a signature from a trusted key.',
    },
  })
})

router.post('/api/plugins', authRequired, writeRequired, (req, res) => {
  const result = plugins.install(req.body, { source: 'dashboard' })
  if (!result.ok) return bad(res, result.error)
  auditSvc.audit(req, 'plugin.install', result.plugin.id, { signed: result.plugin.signed, trusted: result.plugin.trusted })
  res.json(result)
})

router.post('/api/plugins/from-url', authRequired, writeRequired, async (req, res) => {
  try {
    const result = await plugins.installFromUrl(String(req.body?.url || ''))
    if (!result.ok) return bad(res, result.error)
    auditSvc.audit(req, 'plugin.install-url', result.plugin.id, { url: req.body.url })
    res.json(result)
  } catch (e) {
    bad(res, e.message, 502)
  }
})

router.post('/api/plugins/:id/enabled', authRequired, writeRequired, (req, res) => {
  const result = plugins.setEnabled(req.params.id, !!req.body?.enabled)
  if (!result.ok) return bad(res, result.error, 404)
  auditSvc.audit(req, 'plugin.toggle', req.params.id, { enabled: !!req.body?.enabled })
  res.json(result)
})

router.post('/api/plugins/:id/apply-defaults', authRequired, writeRequired, (req, res) => {
  const result = plugins.applyDefaults(req.params.id)
  if (!result.ok) return bad(res, result.error)
  auditSvc.audit(req, 'plugin.apply-defaults', req.params.id, { groups: result.applied })
  res.json(result)
})

router.delete('/api/plugins/:id', authRequired, writeRequired, (req, res) => {
  const result = plugins.remove(req.params.id)
  if (!result.ok) return bad(res, result.error, 404)
  auditSvc.audit(req, 'plugin.remove', req.params.id)
  res.json(result)
})

// ─── Caches (#63) ───────────────────────────────────────────────────────

router.get('/api/caches', authRequired, (req, res) => res.json(caches.overview()))

router.post('/api/caches/:id/clear', authRequired, writeRequired, (req, res) => {
  const result = caches.clear(req.params.id)
  if (!result.ok) return bad(res, result.error, 404)
  auditSvc.audit(req, 'cache.clear', req.params.id)
  res.json(result)
})

router.post('/api/caches/:id/refresh', authRequired, writeRequired, async (req, res) => {
  const result = await caches.refresh(req.params.id)
  if (!result.ok) return bad(res, result.error)
  auditSvc.audit(req, 'cache.refresh', req.params.id)
  res.json(result)
})

// ─── Autoconf (#66) ─────────────────────────────────────────────────────

router.get('/api/autoconf', authRequired, (req, res) => res.json(autoconf.describe()))

router.post('/api/autoconf/scan', authRequired, writeRequired, async (req, res) => {
  const result = await autoconf.scan({ dryRun: req.body?.dry_run !== false })
  if (!result.ok) return bad(res, result.error)
  if (!result.dryRun && !result.skipped) auditSvc.audit(req, 'autoconf.apply', '', { routes: result.routes?.length })
  res.json(result)
})

// ─── Sites (#65) ────────────────────────────────────────────────────────
router.get('/api/kubernetes', authRequired, (req, res) => {
  res.json(require('../services/kubernetes').describe())
})

router.post('/api/kubernetes/scan', authRequired, writeRequired, async (req, res) => {
  const result = await require('../services/kubernetes').scan({ dryRun: req.body?.dry_run !== false })
  if (!result.ok) return bad(res, result.error)
  if (!result.dryRun) auditSvc.audit(req, 'kubernetes.apply', '', { routes: result.routes?.length })
  res.json(result)
})


router.get('/api/sites', authRequired, (req, res) => res.json(sites.describe()))

// ─── Shared state (#67) and database (#68) ──────────────────────────────

router.get('/api/cluster', authRequired, (req, res) => res.json(sharedState.status()))

router.post('/api/cluster/test', authRequired, writeRequired, async (req, res) => {
  res.json(await sharedState.test())
})

router.get('/api/database', authRequired, (req, res) => res.json(dbTuning.status()))

router.post('/api/database/vacuum', authRequired, writeRequired, (req, res) => {
  const result = dbTuning.vacuum()
  auditSvc.audit(req, 'database.vacuum', '', { reclaimed: result.reclaimed_bytes })
  res.json(result)
})

router.post('/api/database/apply-tuning', authRequired, writeRequired, (req, res) => {
  const result = dbTuning.apply()
  auditSvc.audit(req, 'database.tuning', '', result.applied)
  res.json(result)
})

// ─── Certificates (#20-#23) ─────────────────────────────────────────────

router.get('/api/tls/status', authRequired, (req, res) => {
  res.json({ ...certs.status(), advice: certs.acmeAdvice(), caddy: caddyModules.summary() })
})

router.post('/api/tls/validate', authRequired, writeRequired, (req, res) => {
  const { certificate, key, ca } = req.body || {}
  if (ca) return res.json(certs.validateChain(ca))
  if (!certificate) return bad(res, 'Supply a certificate to inspect.')
  res.json(key ? certs.validatePair(certificate, key) : certs.inspect(certificate))
})

// ─── Sessions (#25) ─────────────────────────────────────────────────────

router.get('/api/sessions', authRequired, (req, res) => {
  res.json({ ...sessionSvc.status(), sessions: sessionSvc.list() })
})

router.post('/api/sessions/revoke-all', authRequired, writeRequired, (req, res) => {
  const result = sessionSvc.closeAllFor(req.user.username)
  auditSvc.audit(req, 'session.revoke-all', req.user.username, { removed: result.removed })
  res.json(result)
})

// ─── Two-factor login (#49) ─────────────────────────────────────────────

router.get('/api/auth/2fa', authRequired, (req, res) => {
  res.json(totp.status(req.user.username))
})

router.post('/api/auth/2fa/enroll', authRequired, writeRequired, (req, res) => {
  const current = totp.status(req.user.username)
  if (current.enabled) return bad(res, 'Two-factor authentication is already enabled. Disable it before enrolling again.')
  const enrollment = totp.beginEnrollment(req.user.username, { account: req.user.username })
  auditSvc.audit(req, '2fa.enroll-started', req.user.username)
  res.json({
    ...enrollment,
    next: 'Scan the QR code (or type the secret) into your authenticator app, then confirm with a code. Two-factor login is not enforced until you confirm.',
  })
})

router.post('/api/auth/2fa/confirm', authRequired, writeRequired, (req, res) => {
  const result = totp.confirmEnrollment(req.user.username, String(req.body?.code || ''))
  if (!result.ok) return bad(res, result.error)
  auditSvc.audit(req, '2fa.enabled', req.user.username)
  res.json({
    ...result,
    warning: 'These recovery codes are shown once. Store them somewhere safe — they are the only way back in if you lose the authenticator.',
  })
})

router.post('/api/auth/2fa/disable', authRequired, writeRequired, async (req, res) => {
  // Disabling a second factor is exactly the action a stolen session would
  // want, so it re-checks the password.
  const password = String(req.body?.password || '')
  if (!password || !verifyPassword(req.user.username, password)) {
    return res.status(401).json({ detail: 'Confirm your password to disable two-factor authentication.' })
  }
  const result = totp.disable(req.user.username)
  if (!result.ok) return bad(res, result.error)
  auditSvc.audit(req, '2fa.disabled', req.user.username)
  res.json(result)
})

router.post('/api/auth/2fa/recovery-codes', authRequired, writeRequired, (req, res) => {
  const password = String(req.body?.password || '')
  if (!password || !verifyPassword(req.user.username, password)) {
    return res.status(401).json({ detail: 'Confirm your password to regenerate recovery codes.' })
  }
  const result = totp.regenerateRecoveryCodes(req.user.username)
  if (!result.ok) return bad(res, result.error)
  auditSvc.audit(req, '2fa.recovery-regenerated', req.user.username)
  res.json(result)
})

module.exports = router
