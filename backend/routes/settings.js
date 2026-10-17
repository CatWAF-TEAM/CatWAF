// routes/settings.js — one generic API over every extended settings group.
//
// Because the schema is declarative (services/settings/schema.js), a new
// setting does not need a new endpoint: it gets validation, reads, writes,
// preview, reset and snapshot coverage from the routes here automatically.
// Writes go through configTx, so a setting that produces an invalid
// Caddyfile is rolled back exactly like any other configuration change.

const express = require('express')
const router = express.Router()

const settings = require('../services/settings')
const configTx = require('../services/configTx')
const previewSvc = require('../services/preview')
const caddySvc = require('../services/caddy')
const caddyModules = require('../services/caddyModules')
const wellknown = require('../services/wellknown')
const bcrypt = require('bcryptjs')
const sanitizeSvc = require('../services/sanitize')
const { authRequired, writeRequired, BCRYPT_COST } = require('../middleware/auth')

function bad(res, detail, code = 400) { return res.status(code).json({ detail }) }

router.get('/api/settings/schema', authRequired, (req, res) => {
  res.json({ groups: settings.describe() })
})

router.get('/api/settings', authRequired, (req, res) => {
  res.json({
    settings: settings.getAllRedacted(),
    render_report: caddySvc.lastRenderReport(),
    caddy: caddyModules.summary(),
  })
})

router.get('/api/settings/:group', authRequired, (req, res) => {
  if (!settings.isGroup(req.params.group)) return bad(res, `Unknown settings group "${req.params.group}"`, 404)
  res.json({
    group: req.params.group,
    schema: settings.describe()[req.params.group],
    values: settings.getRedacted(req.params.group),
  })
})

// Some fields need transforming before they are stored — a basic-auth
// password must never reach the database or the generated Caddyfile in
// plaintext. Handled here rather than in the schema so the stored shape
// stays exactly what the renderer needs.
function transformPatch(group, patch) {
  if (group !== 'basic_auth') return { ok: true, patch }
  const next = { ...patch }
  if (typeof next.password === 'string' && next.password) {
    if (next.password.length < 8) return { ok: false, error: 'The basic-auth password must be at least 8 characters.' }
    next.password_hash = bcrypt.hashSync(next.password, BCRYPT_COST)
  }
  delete next.password
  return { ok: true, patch: next }
}

function applyGroupUpdate(req, res, { reload }) {
  const group = req.params.group
  if (!settings.isGroup(group)) return bad(res, `Unknown settings group "${group}"`, 404)

  const transformed = transformPatch(group, req.body || {})
  if (!transformed.ok) return bad(res, transformed.error)

  const check = settings.validate(group, transformed.patch)
  if (!check.ok) return bad(res, check.error)

  const tx = configTx.apply({
    label: `settings.${group}`,
    req,
    reload,
    mutate: () => {
      const result = settings.set(group, transformed.patch)
      if (!result.ok) throw new Error(result.error)
      return { group, fields: Object.keys(transformed.patch) }
    },
  })

  if (!tx.ok) {
    return res.status(400).json({
      detail: tx.error,
      phase: tx.phase,
      rolled_back: !!tx.rolledBack,
      message: tx.message || 'The change was not applied and the previous configuration was kept.',
    })
  }

  res.json({
    message: 'Updated',
    group,
    values: settings.getRedacted(group),
    reloaded: tx.reloaded,
    reload_error: tx.reloadError,
    render_report: caddySvc.lastRenderReport(),
  })
}

router.patch('/api/settings/:group', authRequired, writeRequired, (req, res) => applyGroupUpdate(req, res, { reload: true }))
router.post('/api/settings/:group', authRequired, writeRequired, (req, res) => applyGroupUpdate(req, res, { reload: true }))

router.post('/api/settings/:group/reset', authRequired, writeRequired, (req, res) => {
  const group = req.params.group
  if (!settings.isGroup(group)) return bad(res, `Unknown settings group "${group}"`, 404)

  const tx = configTx.apply({
    label: `settings.${group}.reset`,
    req,
    mutate: () => {
      const result = settings.reset(group)
      if (!result.ok) throw new Error(result.error)
      return { group }
    },
  })
  if (!tx.ok) return res.status(400).json({ detail: tx.error, phase: tx.phase })
  res.json({ message: `${group} reset to defaults`, values: settings.getRedacted(group), reloaded: tx.reloaded })
})

// ─── Draft preview (idea #50) ───────────────────────────────────────────

router.post('/api/settings/:group/preview', authRequired, writeRequired, (req, res) => {
  const group = req.params.group
  if (!settings.isGroup(group)) return bad(res, `Unknown settings group "${group}"`, 404)
  const transformed = transformPatch(group, req.body || {})
  if (!transformed.ok) return bad(res, transformed.error)

  const result = previewSvc.previewSettings(group, transformed.patch)
  if (!result.ok) return bad(res, result.error)
  res.json(result)
})

router.post('/api/config/preview', authRequired, writeRequired, (req, res) => {
  const { waf = null, settings: groups = null } = req.body || {}
  if (!waf && !groups) return bad(res, 'Supply a "waf" object, a "settings" object, or both.')

  // Same validation a real apply would run — preview must not be a way to
  // render values that could never be saved.
  let wafPatch = null
  if (waf) {
    const check = sanitizeSvc.validateWafState(waf)
    if (!check.valid) return bad(res, check.errors.join('; '))
    wafPatch = check.sanitized
  }

  for (const [group, patch] of Object.entries(groups || {})) {
    if (!settings.isGroup(group)) return bad(res, `Unknown settings group "${group}"`)
    const check = settings.validate(group, patch)
    if (!check.ok) return bad(res, check.error)
  }

  const result = previewSvc.preview({
    label: 'config',
    mutate: (s) => {
      for (const [key, value] of Object.entries(wafPatch || {})) {
        if (Object.hasOwn(s.WAF, key)) s.WAF[key] = value
      }
      for (const [group, patch] of Object.entries(groups || {})) {
        const r = settings.set(group, patch)
        if (!r.ok) throw new Error(`${group}: ${r.error}`)
      }
      return { waf: Object.keys(wafPatch || {}), settings: Object.keys(groups || {}) }
    },
  })
  if (!result.ok) return bad(res, result.error)
  res.json({ ...result, unified: previewSvc.toUnifiedText(result) })
})

// What the current configuration renders to, and anything that could not be
// rendered — the answer to "I turned this on, why is nothing happening?".
router.get('/api/config/render-report', authRequired, (req, res) => {
  const state = require('../services/state')
  let rendered = null
  let error = null
  try {
    rendered = require('../services/render/util').withoutAssetWrites(() => caddySvc.renderCaddyfile(caddySvc.readCaddyfile(), state.WAF))
  } catch (e) {
    error = e.message
  }
  res.json({
    report: caddySvc.lastRenderReport(),
    caddy: caddyModules.summary(),
    rendered_bytes: rendered ? Buffer.byteLength(rendered) : null,
    error,
  })
})

// ─── Generated file previews (#40, #41) ─────────────────────────────────

router.get('/api/wellknown/robots.txt', authRequired, (req, res) => {
  const body = wellknown.buildRobotsTxt()
  res.type('text/plain').send(body || '# robots.txt generation is switched off.\n')
})

router.get('/api/wellknown/security.txt', authRequired, (req, res) => {
  const check = wellknown.validateSecurityTxt()
  const body = wellknown.buildSecurityTxt()
  res.json({
    valid: check.ok,
    errors: check.errors,
    body: body || null,
  })
})

module.exports = router
