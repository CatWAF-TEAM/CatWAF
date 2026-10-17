// intel/threatFeed.js — optional integration with a host-local behavioural
// daemon that exposes a bouncer-style decisions API (idea #13).
//
// CatWAF only ever sees traffic to the site it protects. A daemon watching
// the whole host — failed SSH logins, other services being probed — can flag
// an attacker before they have touched the protected site at all.
//
// This is an integration, not a dependency: it is disabled by default, and
// `fail_open` means an unreachable or slow feed degrades to "no additional
// signal" rather than to blocking every visitor. That default is deliberate.

const cache = require('./cache')
const settings = require('../settings')
const netGuard = require('../netGuard')
const crypto = require('crypto')
const { normalizeClientIp, ipCoveredBy, isValidIpOrCidr } = require('../sanitize')

const NS = 'threat-feed'

function endpointFor(cfg, ip) {
  const base = String(cfg.url || '').replace(/\/+$/, '')
  const path = String(cfg.decision_path || '/v1/decisions').replace(/^\/*/, '/')
  const url = new URL(base + path)
  url.searchParams.set('ip', ip)
  return url.toString()
}

// Bouncer APIs answer with either `null`/`[]` (no decision) or a list of
// decision objects. Both shapes are accepted so this works against more than
// one daemon without needing a per-vendor adapter.
function parseDecisions(payload) {
  if (payload === null) return []
  const items = Array.isArray(payload) ? payload : (Array.isArray(payload?.decisions) ? payload.decisions : null)
  if (!items || items.length > 10000) throw new Error('Invalid or oversized decisions response')
  if (items.some(d => !d || Array.isArray(d) || typeof d !== 'object' || typeof (d.type || d.action) !== 'string' || typeof (d.value || d.ip) !== 'string' || typeof d.duration !== 'string')) throw new Error('Invalid decision record')
  return items
    .map(d => ({
      type: String(d.type || d.action || '').toLowerCase(),
      scope: String(d.scope || 'ip').toLowerCase(),
      value: String(d.value || d.ip || ''),
      duration: String(d.duration || ''),
      scenario: String(d.scenario || d.reason || '').slice(0, 200),
      origin: String(d.origin || '').slice(0, 64),
    }))
}

// Native CrowdSec duration strings. Negative values are already expired;
// malformed values use the caller's explicit fallback, never "forever".
function durationSeconds(text, fallback) {
  if (typeof text !== 'string' || !text) return fallback
  if (/^-(?:\d+(?:\.\d+)?[smhd])+$/.test(text)) return 0
  if (!/^(?:\d+(?:\.\d+)?[smhd])+$/.test(text)) return fallback
  const re = /(\d+(?:\.\d+)?)\s*([smhd])/gi
  let total = 0
  let m
  while ((m = re.exec(text)) !== null) {
    const n = Number(m[1])
    const unit = m[2].toLowerCase()
    total += n * (unit === 's' ? 1 : unit === 'm' ? 60 : unit === 'h' ? 3600 : 86400)
  }
  return Number.isFinite(total) && total >= 0 ? Math.min(2592000, total) : fallback
}

async function query(ip, opts = {}) {
  const cfg = { ...settings.get('threat_feed'), ...opts }
  const addr = normalizeClientIp(String(ip || '').trim())
  if (!cfg.enabled || !cfg.url || !addr) return { decisions: [], skipped: true }

  const namespace = crypto.createHash('sha256').update(JSON.stringify([cfg.url, cfg.decision_path, cfg.api_key, cfg.header_name, cfg.cache_seconds])).digest('hex')
  const cacheKey = namespace + ':' + addr
  const hit = cache.get(NS, cacheKey)
  if (hit && hit.expires > Date.now()) return { decisions: hit.decisions.filter(d => d.expires > Date.now()) }
  const headers = { Accept: 'application/json' }
  if (cfg.api_key) headers[cfg.header_name || 'X-Api-Key'] = cfg.api_key
  try {
    const { response } = await netGuard.guardedFetch(endpointFor(cfg, addr), { timeoutMs: cfg.timeout_ms, headers, allowLoopback: true })
    if (!response.ok) return { decisions: [], error: `feed returned ${response.status}` }
    const payload = await response.json()
    const decisions = parseDecisions(payload).filter(d =>
      ['ban', 'block', 'captcha', 'challenge'].includes(d.type) &&
      ['ip', 'range'].includes(d.scope) && isValidIpOrCidr(d.value) && ipCoveredBy(addr, d.value)
    ).map(d => {
      const seconds = durationSeconds(d.duration, NaN)
      if (!Number.isFinite(seconds)) throw new Error('Invalid decision duration')
      return { ...d, expires: Date.now() + seconds * 1000 }
    })
      .filter(d => d.expires > Date.now())
    const ttl = Math.min(cfg.cache_seconds * 1000, ...decisions.map(d => d.expires - Date.now()))
    const value = { decisions, expires: Date.now() + ttl }
    cache.set(NS, cacheKey, value, ttl)
    return value
  } catch (e) {
    return { decisions: [], error: e.message }
  }
}

async function evaluate(ip) {
  const cfg = settings.get('threat_feed')
  if (!cfg.enabled || !cfg.url) return null

  let result
  try {
    result = await query(ip)
  } catch (e) {
    result = { decisions: [], error: e.message }
  }

  if (result.error) {
    // An optional signal that cannot be reached must not become a block.
    if (cfg.fail_open) return { decision: 'unavailable', source: 'threat_feed', unavailable: true, reason: 'CrowdSec is unavailable; configured fail-open policy applies.' }
    return { decision: 'block', source: 'threat_feed', reason: `Local threat feed unreachable (${result.error}) and fail-open is off.` }
  }

  const ban = result.decisions.find(d => d.type === 'ban' || d.type === 'block')
  if (ban) {
    return {
      decision: cfg.action === 'challenge' ? 'challenge' : cfg.action === 'flag' ? 'flag' : 'block',
      source: 'threat_feed',
      banSeconds: Math.max(0, Math.floor((ban.expires - Date.now()) / 1000)),
      reason: `Local threat feed decision: ${ban.scenario || 'ban'}${ban.origin ? ` (${ban.origin})` : ''}.`,
    }
  }
  const captcha = result.decisions.find(d => d.type === 'captcha' || d.type === 'challenge')
  if (captcha) {
    const mode = settings.get('challenge').mode
    return { decision: ['captcha', 'provider'].includes(mode) ? 'challenge' : 'block', required: true, source: 'threat_feed', reason: 'CrowdSec requires a CAPTCHA. A CAPTCHA or provider challenge must be enabled.' }
  }
  return null
}

async function testConnection() {
  const cfg = settings.get('threat_feed')
  if (!cfg.url) return { ok: false, error: 'No bouncer URL configured.' }
  const started = Date.now()
  try {
    const headers = { Accept: 'application/json' }
    if (cfg.api_key) headers[cfg.header_name || 'X-Api-Key'] = cfg.api_key
    const { response } = await netGuard.guardedFetch(endpointFor(cfg, '127.0.0.2'), { timeoutMs: cfg.timeout_ms, headers, allowLoopback: true })
    return {
      ok: response.ok,
      status: response.status,
      latency_ms: Date.now() - started,
      error: response.ok ? null : `Feed returned ${response.status}${response.status === 403 ? ' — check the API key' : ''}`,
    }
  } catch (e) {
    return { ok: false, error: e.message, latency_ms: Date.now() - started }
  }
}

module.exports = { query, evaluate, testConnection, parseDecisions, durationSeconds, NS }
