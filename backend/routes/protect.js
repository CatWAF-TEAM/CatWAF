// routes/protect.js — the admin API for the live protection layer: active
// bans (#61), threat intelligence (#7-#13), the challenge gate (#1-#5) and
// behavioural banning (#6).

const express = require('express')
const router = express.Router()

const bans = require('../services/bans')
const behavior = require('../services/behavior')
const enforce = require('../services/enforce')
const challenge = require('../services/challenge')
const providers = require('../services/challenge/providers')
const asn = require('../services/intel/asn')
const rdns = require('../services/intel/rdns')
const dnsbl = require('../services/intel/dnsbl')
const lists = require('../services/intel/lists')
const threatFeed = require('../services/intel/threatFeed')
const threatNetwork = require('../services/intel/network')
const probe = require('../services/intel/probe')
const settings = require('../services/settings')
const toolsFingerprint = require('../services/toolsFingerprint')
const auditSvc = require('../services/audit')
const jobs = require('../services/jobs')
const { authRequired, writeRequired } = require('../middleware/auth')
const { isValidIpOrCidr, normalizeClientIp, ipCoveredBy } = require('../services/sanitize')

function bad(res, detail, code = 400) { return res.status(code).json({ detail }) }

// ─── Active bans (#61) ──────────────────────────────────────────────────

router.get('/api/bans', authRequired, (req, res) => {
  const source = typeof req.query.source === 'string' ? req.query.source : null
  if (source && !Object.hasOwn(bans.SOURCES, source)) return bad(res, `Unknown ban source "${source}"`)
  res.json({
    bans: bans.list({
      source,
      limit: Math.min(Number(req.query.limit) || 200, 1000),
      offset: Math.max(Number(req.query.offset) || 0, 0),
      includeExpired: req.query.include_expired === 'true',
    }),
    stats: bans.stats(),
  })
})

router.get('/api/bans/stats', authRequired, (req, res) => res.json(bans.stats()))

router.post('/api/bans', authRequired, writeRequired, (req, res) => {
  const { target, seconds = null, reason = '', source = 'manual' } = req.body || {}
  if (!isValidIpOrCidr(String(target || '').trim())) return bad(res, 'target must be a valid IP address or CIDR range')

  // The same self-lockout guard the IP blocklist already applies: an
  // administrator banning the range they are connected from would lose the
  // dashboard along with it.
  if (ipCoveredBy(req.ip, String(target).trim())) {
    return res.status(400).json({
      detail: `"${target}" covers your own address (${normalizeClientIp(req.ip)}) — banning it would lock you out of CatWAF.`,
      code: 'SELF_BLOCK',
    })
  }
  if (seconds !== null && (!Number.isInteger(seconds) || seconds < 1)) return bad(res, 'seconds must be a positive whole number, or null for a permanent ban')

  const result = bans.addManual({ target, seconds, reason: String(reason).slice(0, 300) })
  if (!result.ok) return bad(res, result.error)
  enforce.invalidate(target)
  auditSvc.audit(req, 'ban.add', target, { seconds, reason })
  res.json(result)
})

router.delete('/api/bans/:id', authRequired, writeRequired, (req, res) => {
  const result = bans.lift(req.params.id, { by: req.user?.username })
  if (!result.ok) return bad(res, result.error, 404)
  enforce.invalidate(result.lifted.target)
  auditSvc.audit(req, 'ban.lift', result.lifted.target, { source: result.lifted.source })
  res.json(result)
})

router.post('/api/bans/lift', authRequired, writeRequired, (req, res) => {
  const { target, source = null } = req.body || {}
  if (!target) return bad(res, 'target is required')
  const result = bans.liftTarget(target, { source })
  enforce.invalidate(target)
  auditSvc.audit(req, 'ban.lift-target', String(target), { source, removed: result.removed })
  res.json(result)
})

router.post('/api/bans/clear', authRequired, writeRequired, (req, res) => {
  bans.clearAll()
  enforce.invalidate()
  auditSvc.audit(req, 'ban.clear-all', '')
  res.json({ ok: true, message: 'All automatic bans lifted. Your manual IP blocklist is unchanged.' })
})

// ─── Enforcement pipeline ───────────────────────────────────────────────

router.get('/api/protect/status', authRequired, (req, res) => {
  const edgeCfg = settings.get('edge_bans')
  let edge = null
  if (edgeCfg.enabled) {
    const targets = (() => { try { return require('../services/edgeBans').collectTargets({ maxRules: edgeCfg.max_rules, includeCidrs: edgeCfg.include_cidrs }) } catch { return [] } })()
    edge = { enabled: true, rendered: targets.length, max_rules: edgeCfg.max_rules, refresh_seconds: edgeCfg.refresh_seconds }
  } else {
    edge = { enabled: false }
  }
  const kernel = (() => { try { return require('../services/kernelBans').status() } catch { return null } })()
  res.json({
    ...enforce.status(),
    ddos: settings.get('ddos'),
    canary: settings.get('canary'),
    edge_bans: edge,
    kernel_bans: kernel ? { enabled: kernel.enabled, env_enabled: kernel.env_enabled, preflight_ok: kernel.preflight.ok, problems: kernel.preflight.problems, entries: kernel.last_applied_entries } : null,
    alerts_delivery: require('../services/alertDispatch').status(),
    challenge: challenge.status(),
    community_lists: lists.summary(),
  })
})

// "Why would this address be treated the way it is?" — runs the real
// pipeline against a supplied address without it having to visit the site.
// Admin-only and dry-run: classify() is invoked with dryRun so a test can
// never write a real ban or make live probe connections against an
// operator-chosen address (which, with a CIDR supplied, could otherwise
// block every visitor — or the admin's own address).
router.post('/api/protect/test', authRequired, writeRequired, async (req, res) => {
  const { ip, uri = '/', user_agent = '', headers: rawHeaders = [] } = req.body || {}
  if (!isValidIpOrCidr(String(ip || '').trim())) return bad(res, 'ip must be a valid IP address')
  const headers = Array.isArray(rawHeaders) ? rawHeaders.filter(h => typeof h === 'string').slice(0, 100) : []
  try {
    const verdict = await enforce.classify({ ip, uri, userAgent: user_agent, headers }, { dryRun: true })
    const fingerprint = toolsFingerprint.fingerprint({
      userAgent: user_agent,
      headers,
    }, { closeThreshold: settings.get('tools_fingerprint').close_threshold / 100 })
    res.json({ ip, verdict, fingerprint })
  } catch (e) {
    res.status(500).json({ detail: e.message })
  }
})

// ─── Threat intelligence lookups (#7, #8, #11) ──────────────────────────

router.get('/api/intel/asn/:ip', authRequired, async (req, res) => {
  if (!isValidIpOrCidr(req.params.ip)) return bad(res, 'Not a valid IP address')
  const info = await asn.lookup(req.params.ip, { withName: true })
  res.json({ ip: req.params.ip, asn: info, availability: asn.available() })
})

router.get('/api/intel/rdns/:ip', authRequired, async (req, res) => {
  if (!isValidIpOrCidr(req.params.ip)) return bad(res, 'Not a valid IP address')
  res.json({ ip: req.params.ip, rdns: await rdns.lookup(req.params.ip) })
})

router.get('/api/intel/dnsbl/:ip', authRequired, async (req, res) => {
  if (!isValidIpOrCidr(req.params.ip)) return bad(res, 'Not a valid IP address')
  res.json({ ip: req.params.ip, dnsbl: await dnsbl.lookup(req.params.ip) })
})

// ─── Upload malware scanning ────────────────────────────────────────────
//
// ClamAV is an optional dependency CatWAF never installs, so "is it there"
// is a question the dashboard and `catwaf doctor` both have to be able to
// ask. Reported as an availability fact rather than an error: not having a
// scanner installed is a normal state, not a fault.
router.get('/api/upload-scan/status', authRequired, async (req, res) => {
  const clamav = require('../services/clamav')
  const cfg = settings.get('upload_scan')
  const health = await clamav.available({ force: req.query.refresh === 'true', cfg })
  res.json({
    enabled: cfg.enabled,
    scanner: health,
    paths: cfg.paths,
    methods: cfg.methods,
    action: cfg.action,
    fail_open: cfg.fail_open,
    max_scan_bytes: cfg.max_scan_bytes,
  })
})

// Scans an operator-supplied sample. The point is to prove the daemon is
// wired up correctly — EICAR through this endpoint should come back FOUND.
router.post('/api/upload-scan/test', authRequired, writeRequired, async (req, res) => {
  const clamav = require('../services/clamav')
  const { content } = req.body || {}
  if (typeof content !== 'string') return bad(res, 'content must be a string')
  if (content.length > 1024 * 1024) return bad(res, 'content must be 1 MiB or less')
  auditSvc.audit(req, 'upload_scan.test', `${content.length} bytes`)
  const cfg = settings.get('upload_scan')
  res.json({ result: await clamav.scanBuffer(Buffer.from(content, 'utf8'), cfg, cfg.timeout_ms) })
})

router.post('/api/intel/probe', authRequired, writeRequired, async (req, res) => {
  const { ip } = req.body || {}
  if (!isValidIpOrCidr(String(ip || '').trim())) return bad(res, 'ip must be a valid IP address')
  auditSvc.audit(req, 'intel.probe', ip)
  res.json({ ip, result: await probe.probe(ip), tradeoffs: probe.TRADEOFFS })
})

router.get('/api/intel/probe/tradeoffs', authRequired, (req, res) => {
  res.json({ tradeoffs: probe.TRADEOFFS, enabled: settings.get('client_probe').enabled })
})

// ─── Community lists (#10) ──────────────────────────────────────────────

router.get('/api/intel/lists', authRequired, (req, res) => res.json(lists.summary()))

router.post('/api/intel/lists/refresh', authRequired, writeRequired, async (req, res) => {
  try {
    const result = req.body?.source_id
      ? await lists.refreshSource(settings.get('community_lists').sources.find(s => s.id === req.body.source_id))
      : await lists.refreshAll()
    auditSvc.audit(req, 'intel.lists.refresh', req.body?.source_id || 'all')
    res.json(result)
  } catch (e) {
    res.status(502).json({ detail: e.message })
  }
})

router.delete('/api/intel/lists/:sourceId', authRequired, writeRequired, (req, res) => {
  const result = lists.clearSource(req.params.sourceId)
  auditSvc.audit(req, 'intel.lists.clear', req.params.sourceId)
  res.json(result)
})

// ─── Threat feed + shared network (#12, #13) ────────────────────────────

router.get('/api/intel/feed/test', authRequired, async (req, res) => {
  res.json(await threatFeed.testConnection())
})

router.get('/api/intel/network', authRequired, (req, res) => res.json(threatNetwork.status()))

router.post('/api/intel/network/submit', authRequired, writeRequired, async (req, res) => {
  try {
    const result = await threatNetwork.submit({ dryRun: req.body?.dry_run !== false })
    res.json(result)
  } catch (e) {
    res.status(502).json({ detail: e.message })
  }
})

// ─── Behavioural banning (#6) ───────────────────────────────────────────

router.get('/api/protect/behavior', authRequired, (req, res) => res.json(behavior.preview()))

router.post('/api/protect/behavior/run', authRequired, writeRequired, async (req, res) => {
  const result = behavior.sweep({ dryRun: req.body?.dry_run === true })
  if (!result.dryRun) auditSvc.audit(req, 'behavior.sweep', '', { banned: result.banned })
  res.json(result)
})

// ─── Challenge gate (#1-#4) ─────────────────────────────────────────────

router.get('/api/challenge/status', authRequired, (req, res) => {
  res.json({ ...challenge.status(), providers: providers.list() })
})

router.post('/api/challenge/reset', authRequired, writeRequired, (req, res) => {
  challenge.reset()
  auditSvc.audit(req, 'challenge.reset', '')
  res.json({ ok: true, message: 'Pending challenges and failure counters cleared.' })
})

// Renders a real challenge so an admin can see exactly what a visitor gets
// before turning it on for live traffic.
router.get('/api/challenge/preview', authRequired, (req, res) => {
  const cfg = settings.get('challenge')
  if (cfg.mode === 'off') return bad(res, 'The challenge gate is switched off, so there is nothing to preview.')
  const issued = challenge.issue({ ip: req.ip, userAgent: req.headers['user-agent'], returnTo: '/' })
  res.type('html').send(issued.html)
})

router.post('/api/challenge/scope-test', authRequired, (req, res) => {
  const { ip = '', uri = '/', user_agent = '', asn: asnNumber = null, rdns: rdnsName = null, country = null } = req.body || {}
  res.json({
    exempt: challenge.isExempt({ ip, uri, userAgent: user_agent, asn: asnNumber, rdns: rdnsName, country }),
    decision: challenge.shouldChallenge({ ip, uri, userAgent: user_agent, asn: asnNumber, rdns: rdnsName, country, suspicious: !!req.body?.suspicious }),
  })
})

module.exports = router
