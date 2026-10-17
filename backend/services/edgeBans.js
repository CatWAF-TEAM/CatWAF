// edgeBans.js — render the newest active bans straight into the Caddyfile
// as a remote_ip matcher with an `abort` handler.
//
// Why: a ban enforced only through the forward_auth hop still costs the
// banned client a full TCP+TLS handshake, Caddy route evaluation and a hop
// to this API before it is refused. Rendered at the edge, the connection is
// dropped by Caddy's matcher before any of that — which is what "banned"
// should mean.
//
// Mechanics: the region lives between its own marker comments inside the
// primary site block (same insertion strategy as the Cloudflare origin
// lock), so neither the WAF renderer nor operator edits collide with it.
// Refreshes are content-hashed — nothing is rewritten unless the active set
// actually changed — and every write goes through the config lock and the
// atomic rename, like every other Caddyfile writer.

const crypto = require('crypto')
const fs = require('fs')
const path = require('path')

const settings = require('./settings')
const state = require('./state')
const caddySvc = require('./caddy')
const configLock = require('./configLock')
const logger = require('./logger')

const log = logger.child('edge-bans')

const MARKER_START = '# @@CATWAF_EDGE_BANS_START@@'
const MARKER_END = '# @@CATWAF_EDGE_BANS_END@@'
const LAST_KEY = 'edge_bans_last_render'

function enabled() {
  const cfg = settings.get('edge_bans')
  return !!cfg.enabled
}

// Allowlisted addresses must never be edge-dropped even if something banned
// them — the allowlist beats every automatic signal by contract.
// Both directions matter: a banned single IP inside an allowlisted range,
// AND a banned range that would swallow an allowlisted address. Either one
// means the target cannot be enforced at this tier.
function allowlistConflict(target) {
  const { ipCoveredBy } = require('./sanitize')
  for (const entry of state.WAF.ip_whitelist || []) {
    if (!entry?.ip) continue
    if (ipCoveredBy(target, entry.ip)) return true   // target sits inside the safe range
    if (ipCoveredBy(entry.ip, target)) return true   // target range swallows a safe address
  }
  return false
}

function collectTargets({ maxRules, includeCidrs }) {
  const bans = require('./bans')
  const targets = []
  for (const raw of bans.listActiveTargets({ limit: maxRules * 3 })) {
    if (allowlistConflict(raw)) continue
    const isCidr = raw.includes('/')
    if (isCidr && !includeCidrs) continue
    targets.push(raw)
    if (targets.length >= maxRules) break
  }
  return targets
}

// Pure builder — exported for tests.
function buildBlock(targets) {
  const lines = [MARKER_START]
  if (targets.length) {
    // remote_ip accepts plain addresses and CIDRs, v4 and v6, space-
    // separated. Targets are validated at ban time and re-checked here.
    const { isValidIpOrCidr } = require('./sanitize')
    const safe = targets.filter(t => isValidIpOrCidr(t))
    if (safe.length) {
      lines.push(`  @catwaf_edge_bans remote_ip ${safe.join(' ')}`)
      lines.push('  handle @catwaf_edge_bans {')
      lines.push('    abort')
      lines.push('  }')
    }
  }
  lines.push(MARKER_END)
  return lines.join('\n')
}

function patchRegion(content, block) {
  const startIdx = content.indexOf(MARKER_START)
  const endIdx = content.indexOf(MARKER_END)
  if (startIdx !== -1 && endIdx !== -1 && endIdx > startIdx) {
    return content.slice(0, startIdx) + block + content.slice(endIdx + MARKER_END.length)
  }
  if (startIdx === -1 && endIdx === -1) {
    const idx = caddySvc.lastSiteBlockClose(content)
    if (idx === -1) throw new Error('No site block to insert edge bans into.')
    return content.slice(0, idx) + block + '\n' + content.slice(idx)
  }
  throw new Error('Edge-ban markers are inconsistent (one present, one missing) — fix the Caddyfile manually.')
}

// Returns { ok, changed, rendered, reason? }. Safe to call on a machine
// with no Caddyfile: reads fail → clean skip.
function refresh({ force = false } = {}) {
  const cfg = settings.get('edge_bans')
  if (!cfg.enabled) return { ok: true, skipped: 'disabled' }

  let targets = []
  try { targets = collectTargets({ maxRules: cfg.max_rules, includeCidrs: cfg.include_cidrs }) } catch (e) {
    return { ok: false, error: e.message }
  }

  const hash = crypto.createHash('sha256').update(JSON.stringify(targets)).digest('hex')
  const last = db_get(LAST_KEY)
  // { hash, needsReload } — a written-but-unreloaded region retries on the
  // next tick even though its content is unchanged.
  if (!force && last && last.hash === hash && !last.needsReload) {
    return { ok: true, changed: false, rendered: targets.length }
  }

  return configLock.withConfigLock(() => {
    let content
    try { content = caddySvc.readCaddyfile() } catch (e) {
      return { ok: true, skipped: `cannot read the Caddyfile (${e.message})` }
    }

    // Re-collect under the lock: a ban could have landed while we waited.
    targets = collectTargets({ maxRules: cfg.max_rules, includeCidrs: cfg.include_cidrs })
    const hash2 = crypto.createHash('sha256').update(JSON.stringify(targets)).digest('hex')

    let next
    try { next = patchRegion(content, buildBlock(targets)) } catch (e) {
      return { ok: false, error: e.message }
    }

    const tx = require('./configTx').apply({ label: 'edge-bans.refresh', caddyfile: next, render: false, mutate: () => {} })
    if (!tx.ok) return tx
    const reload = { reloaded: tx.reloaded, error: tx.reloadError }
    // The content is committed either way; whether it is ENFORCED decides
    // if the next tick may short-circuit.
    db_set(LAST_KEY, { hash: hash2, needsReload: !reload.reloaded })
    log.info(`Edge ban list refreshed`, { rendered: targets.length, reloaded: !!reload.reloaded })
    return { ok: true, changed: true, rendered: targets.length, reloaded: !!reload.reloaded, reloadError: reload.reloaded ? null : (reload.error || null) }
  })
}

// tiny db helpers kept local so the module can be loaded by CLI paths that
// never opened the settings namespace
function db_get(key) {
  try { return require('./db').getState(key) } catch { return null }
}
function db_set(key, value) {
  try { require('./db').setState(key, value) } catch {}
}

module.exports = { refresh, buildBlock, collectTargets, MARKER_START, MARKER_END, enabled }
