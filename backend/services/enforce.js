// enforce.js — the single request-classification pass that every runtime
// signal feeds into.
//
// Coraza cannot call out to CatWAF, so the ideas that need a live decision
// (challenge gate #1-#4, greylist #9, ASN #7, rDNS #8, DNSBL #11, community
// lists #10, threat feed #13, shared network #12, relay probing #5, and the
// bans that behavioural analysis #6 produces) are evaluated here and reached
// from Caddy with a `forward_auth` hop into CatWAF's own API. That hop is
// only rendered when at least one of these features is switched on, so an
// install that uses none of them pays nothing.
//
// Two properties this pass has to hold:
//
//   * Bounded latency. Everything network-bound runs in parallel under one
//     deadline. Individual intelligence sources cache their own results;
//     request-dependent final verdicts are recomputed on every request.
//   * Fail open. If a signal errors or times out, it contributes nothing.
//     These are advisory signals layered on top of the WAF; none of them is
//     load-bearing enough to justify refusing traffic when it breaks.

const cache = require('./intel/cache')
const bans = require('./bans')
const settings = require('./settings')
const state = require('./state')
const challenge = require('./challenge')
const toolsFingerprint = require('./toolsFingerprint')
const asn = require('./intel/asn')
const rdns = require('./intel/rdns')
const dnsbl = require('./intel/dnsbl')
const lists = require('./intel/lists')
const threatFeed = require('./intel/threatFeed')
const threatNetwork = require('./intel/network')
const probe = require('./intel/probe')
const geoip = require('./geoip')
const logger = require('./logger')
const { ipCoveredBy, normalizeClientIp } = require('./sanitize')

const log = logger.child('enforce')
const counters = require('./counters')
const NS = 'verdict'
const DEADLINE_MS = 2500

// Which settings groups, when on, mean the forward_auth hop is worth
// rendering at all. Kept next to the pipeline so the renderer and the
// pipeline can never disagree about whether enforcement is active.
const RUNTIME_GROUPS = [
  'challenge', 'greylist', 'asn_lists', 'rdns_lists', 'dnsbl',
  'community_lists', 'threat_feed', 'threat_network', 'client_probe', 'bad_behavior',
  'tools_fingerprint', 'canary',
]

// Canary paths are intent, not traffic: no legitimate visitor ever requests
// them, so the first hit earns an escalating ban before Coraza even sees a
// payload. Purely local — same tier as tool fingerprinting.
function canaryMatches(uri) {
  const cfg = settings.get('canary')
  if (!cfg.enabled || !cfg.paths.length) return false
  const path = String(uri || '/').split('?')[0]
  return cfg.paths.some(p => (p.endsWith('*') ? path.startsWith(p.slice(0, -1)) : path === p))
}

function isActive() {
  for (const group of RUNTIME_GROUPS) {
    const cfg = settings.get(group)
    if (group === 'challenge') { if (cfg.mode !== 'off') return true; continue }
    if (cfg.enabled) return true
  }
  return false
}

function activeFeatures() {
  return RUNTIME_GROUPS.filter(group => {
    const cfg = settings.get(group)
    return group === 'challenge' ? cfg.mode !== 'off' : !!cfg.enabled
  })
}

function isAllowlisted(ip) {
  for (const entry of state.WAF.ip_whitelist || []) {
    if (entry?.ip && ipCoveredBy(ip, entry.ip)) return entry.ip
  }
  return null
}

// Runs the network-bound signals in parallel under one shared deadline. A
// signal that has not answered by then simply does not contribute.
async function gather(tasks) {
  const deadline = new Promise(resolve => setTimeout(() => resolve('__deadline__'), DEADLINE_MS).unref?.())
  const results = await Promise.all(tasks.map(async ({ name, run }) => {
    try {
      const value = await Promise.race([run(), deadline])
      if (value === '__deadline__') return { name, timedOut: true }
      return { name, value }
    } catch (e) {
      return { name, error: e.message }
    }
  }))
  return results
}

async function classify(request, { dryRun = false } = {}) {
  const ip = normalizeClientIp(request.ip || '')
  const uri = String(request.uri || '/')
  const userAgent = request.userAgent || ''
  const signals = []

  if (!ip) return { action: 'allow', reason: 'No client address to evaluate.', signals }

  // 1. A human's explicit allow beats every automatic signal.
  const allowlisted = isAllowlisted(ip)
  if (allowlisted) {
    return { action: 'allow', reason: `Address is on the IP allowlist (${allowlisted}).`, signals: [{ source: 'allowlist', decision: 'allow' }] }
  }

  // 2. An existing ban is a local lookup, so it comes before anything that
  //    costs a round-trip.
  const existingBan = bans.check(ip)
  if (existingBan) {
    return {
      action: 'block',
      reason: existingBan.reason,
      ban: existingBan,
      signals: [{ source: existingBan.source, decision: 'block', reason: existingBan.reason }],
    }
  }

  // In dry-run mode ("why would this address be treated this way?") the
  // pipeline reports what it *would* do without writing any ban or making
  // outbound probe connections — a test must never punish the subject it is
  // testing, whoever is asking.
  const wouldBan = []
  const recordWouldBan = (source, seconds, reason) => {
    wouldBan.push({ source, seconds, reason })
    signals.push({ source, decision: 'ban', reason })
  }

  // 2.5. Tool fingerprinting is local/synchronous — no round trip — so it
  //      runs before anything network-bound, same as the ban lookup above.
  //      An exact signature match is high-confidence enough to ban outright;
  //      a close-but-uncertain match only asks for a challenge (idea #1-#4),
  //      since fuzzy matching carries real false-positive risk.
  const fpCfg = settings.get('tools_fingerprint')
  if (fpCfg.enabled) {
    const fp = toolsFingerprint.fingerprint(
      { userAgent, headers: request.headers },
      { closeThreshold: fpCfg.close_threshold / 100 }
    )
    if (fp && fp.tier === 'exact') {
      if (dryRun) {
        recordWouldBan('tools_fingerprint', fpCfg.ban_seconds, `Fingerprinted as ${fp.tool} (exact match).`)
      } else {
        bans.ban({
          target: ip,
          source: 'tools_fingerprint',
          reason: `Fingerprinted as ${fp.tool} (exact match).`,
          seconds: fpCfg.ban_seconds,
          escalateRepeat: fpCfg.escalate,
        })
      }
      return {
        action: 'block',
        reason: `Detected as ${fp.tool}.`,
        signals: [{ source: 'tools_fingerprint', decision: 'block', tool: fp.tool }],
        ...(dryRun ? { would_ban: wouldBan } : {}),
      }
    }
    if (fp && fp.tier === 'close') {
      signals.push({
        source: 'tools_fingerprint',
        decision: 'challenge',
        reason: `Resembles ${fp.tool} (score ${fp.score.toFixed(2)}) — not certain enough to ban outright.`,
        tool: fp.tool,
      })
    }
  }

  // 2.75. Canary probe → immediate ban. Runs before anything network-bound.
  if (canaryMatches(uri)) {
    const cfg = settings.get('canary')
    const reason = `Requested a canary path (${uri.split('?')[0]})`
    if (dryRun) {
      // recordWouldBan already appends the signal — pushing twice would
      // duplicate it in the response.
      recordWouldBan('canary', cfg.ban_seconds, reason)
      return { action: 'block', reason, signals, would_ban: wouldBan }
    }
    counters.incr('canary_hits_total')
    bans.ban({ target: ip, source: 'canary', reason, seconds: cfg.ban_seconds, escalateRepeat: cfg.escalate })
    return { action: 'block', reason, signals: [{ source: 'canary', decision: 'block', reason }] }
  }

  const country = request.country || geoip.lookup(ip)?.country_code || null

  // 3. Everything else, in parallel and under one deadline.
  const tasks = []
  if (settings.get('asn_lists').enabled) tasks.push({ name: 'asn', run: () => asn.evaluate(ip) })
  if (settings.get('rdns_lists').enabled) tasks.push({ name: 'rdns', run: () => rdns.evaluate(ip) })
  if (settings.get('dnsbl').enabled) tasks.push({ name: 'dnsbl', run: () => dnsbl.evaluate(ip) })
  if (settings.get('threat_feed').enabled) tasks.push({ name: 'threat_feed', run: () => threatFeed.evaluate(ip) })
  if (settings.get('threat_network').enabled) tasks.push({ name: 'threat_network', run: () => threatNetwork.evaluate(ip) })

  const gathered = await gather(tasks)

  let asnNumber = null
  let rdnsName = null
  for (const entry of gathered) {
    if (entry.timedOut) { signals.push({ source: entry.name, decision: 'unavailable', reason: 'Timed out — not counted.' }); continue }
    if (entry.error) { signals.push({ source: entry.name, decision: 'unavailable', reason: entry.error }); continue }
    if (!entry.value) continue
    if (entry.name === 'asn' && entry.value.asn) asnNumber = entry.value.asn
    if (entry.name === 'rdns' && entry.value.rdns) rdnsName = entry.value.rdns
    signals.push({ source: entry.name, ...entry.value })
  }

  // Community lists are a local index lookup, so they run after the ASN and
  // rDNS answers are in and can therefore match on them too.
  if (settings.get('community_lists').enabled) {
    const verdict = await lists.evaluate({ ip, asn: asnNumber, rdns: rdnsName, userAgent, uri })
    if (verdict) signals.push({ source: 'community', ...verdict })
  }

  // A verified crawler or a community allow entry short-circuits the rest.
  const allow = signals.find(s => s.decision === 'allow')
  if (allow) return { action: 'allow', reason: allow.reason, signals, asn: asnNumber, rdns: rdnsName }

  const grey = lists.greylistMatch({ ip, asn: asnNumber, rdns: rdnsName, userAgent, uri })
  if (grey) signals.push({ source: 'greylist', decision: 'greylist', reason: `Greylisted by ${grey.matched}; skipping ${[...grey.skip].join(', ')}.` })

  const block = signals.find(s => s.decision === 'block')
  if (block) return { action: 'block', reason: block.reason, signals, asn: asnNumber, rdns: rdnsName }

  const banSignal = signals.find(s => s.decision === 'ban')
  if (banSignal) {
    if (!dryRun) {
      bans.ban({
        target: ip,
        source: banSignal.source,
        seconds: banSignal.banSeconds || 3600,
        reason: banSignal.reason,
        escalateRepeat: false,
      })
    } else {
      wouldBan.push({ source: banSignal.source, seconds: banSignal.banSeconds || 3600, reason: banSignal.reason })
    }
    return { action: 'block', reason: banSignal.reason, signals, asn: asnNumber, rdns: rdnsName, ...(dryRun ? { would_ban: wouldBan } : {}) }
  }

  const suspicious = signals.some(s => s.decision === 'flag' || s.decision === 'challenge')

  // Relay probing is last and only for an already-suspicious client, so an
  // ordinary visitor never pays its latency (idea #5's stated tradeoff).
  // Skipped entirely in dry-run mode: it makes live outbound connections to
  // the address under test.
  if (!dryRun && settings.get('client_probe').enabled) {
    try {
      const verdict = await probe.evaluate(ip, { suspicious })
      if (verdict) {
        signals.push({ source: 'client_probe', ...verdict })
        if (verdict.decision === 'ban') {
          bans.ban({ target: ip, source: 'client_probe', seconds: verdict.banSeconds, reason: verdict.reason, escalateRepeat: false })
          return { action: 'block', reason: verdict.reason, signals }
        }
      }
    } catch { /* probing is advisory */ }
  }

  const skipChallenge = grey && grey.skip.has('challenge')
  if (!skipChallenge) {
    const decision = challenge.shouldChallenge({
      ip, uri, userAgent, asn: asnNumber, rdns: rdnsName, country,
      suspicious: suspicious || signals.some(s => s.decision === 'challenge'),
    })
    if (decision.challenge) {
      return { action: 'challenge', reason: 'Visitor must complete a challenge before continuing.', mode: decision.mode, signals, asn: asnNumber, rdns: rdnsName }
    }
  }

  return {
    action: 'allow',
    reason: signals.length ? 'No signal asked for a block.' : 'No signal matched.',
    signals,
    asn: asnNumber,
    rdns: rdnsName,
    greylisted: !!grey,
    skip: grey ? [...grey.skip] : [],
  }
}

// The forward_auth entry point evaluates request context on every call.
async function evaluate(request) {
  const ip = normalizeClientIp(request.ip || '')
  if (!ip) return { action: 'allow', reason: 'No client address.', signals: [], cached: false }

  // Final decisions depend on path exemptions, user agent, headers, current
  // bans and current settings. Reusing an IP-only allow bypasses those
  // checks. Network intelligence already has its own bounded TTL caches.
  const verdict = await classify(request)
  return { ...verdict, cached: false }
}

function invalidate(ip) {
  if (!ip) return cache.clear(NS)
  cache.set(NS, normalizeClientIp(ip), undefined, 1)
  return 1
}

function status() {
  return {
    active: isActive(),
    features: activeFeatures(),
    deadline_ms: DEADLINE_MS,
    verdict_cache_ttl_ms: 0,
    caches: cache.stats(),
    bans: bans.stats(),
  }
}

module.exports = { evaluate, classify, isActive, activeFeatures, invalidate, status, RUNTIME_GROUPS, NS }
