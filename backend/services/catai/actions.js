
const state = require('../state')
const caddySvc = require('../caddy')
const auditSvc = require('../audit')
const { isValidIpOrCidr, isValidCountryCode, ipCoveredBy, normalizeClientIp } = require('../sanitize')

let regionDisplayNames
try { regionDisplayNames = new Intl.DisplayNames(['en'], { type: 'region' }) } catch { regionDisplayNames = null }
function countryNameFor(cc) {
  try { return regionDisplayNames ? regionDisplayNames.of(cc) : cc } catch { return cc }
}

const DIRECTION = { STRENGTHEN: 'strengthen', WEAKEN: 'weaken' }

function commit(req, label, target, meta) {
  // apply() owns the transaction, including this audit entry. Action
  // handlers must never persist a partially changed state before validation.
  auditSvc.audit(req, 'catai.apply', target, { action: label, ...meta })
  return {}
}

const TOOL_SCHEMAS = {
  'ip.block': { name: 'ip_block', description: 'Block a specific IP address or CIDR range from reaching the site', params: { ip: { type: 'string', description: 'IPv4/IPv6 address or CIDR, e.g. 203.0.113.9 or 203.0.113.0/24' } }, required: ['ip'] },
  'geo.block': { name: 'geo_block', description: 'Block all traffic from an entire country', params: { country_code: { type: 'string', description: 'Two-letter ISO country code, e.g. CN, RU, BR' } }, required: ['country_code'] },
  'engine.enable': { name: 'engine_enable', description: 'Turn WAF protection on (from Off or Detection Only)', params: {}, required: [] },
  'rate_limit.enable': { name: 'rate_limit_enable', description: 'Enable per-IP rate limiting', params: {}, required: [] },
  'ua.block': { name: 'ua_block', description: 'Block requests carrying a specific User-Agent string', params: { agent: { type: 'string', description: 'the user-agent value or substring to block' } }, required: ['agent'] },
  'paranoia.set': { name: 'set_paranoia_level', description: 'Set the WAF paranoia/strictness level from 1 (lenient) to 4 (strict)', params: { level: { type: 'integer', description: '1, 2, 3 or 4' } }, required: ['level'] },
  'ip.allow': { name: 'ip_allow', description: 'Allow a specific IP through the firewall temporarily, bypassing WAF rules', params: { ip: { type: 'string', description: 'IPv4/IPv6 address or CIDR' } }, required: ['ip'] },
  'ip.unblock': { name: 'ip_unblock', description: 'Remove an IP address from the blocklist', params: { ip: { type: 'string', description: 'IPv4/IPv6 address or CIDR previously blocked' } }, required: ['ip'] },
  'rule.add': { name: 'add_custom_rule', description: 'Add a custom firewall rule that blocks requests containing a given piece of text', params: { target: { type: 'string', description: 'what to inspect: path, query, body, header or user_agent' }, value: { type: 'string', description: 'the text to match and block on' } }, required: ['target', 'value'] },
  'geo.unblock': { name: 'geo_unblock', description: 'Stop blocking a country that is currently geo-blocked', params: { country_code: { type: 'string', description: 'Two-letter ISO country code, e.g. CN, RU, BR' } }, required: ['country_code'] },
  'ua.unblock': { name: 'ua_unblock', description: 'Remove a user agent from the blocked user-agent list', params: { agent: { type: 'string', description: 'the blocked user-agent value to remove' } }, required: ['agent'] },
  'rate_limit.set': { name: 'set_rate_limit', description: 'Set how many requests per minute a single IP may make', params: { requests_per_min: { type: 'integer', description: 'requests per minute per IP, between 10 and 10000' } }, required: ['requests_per_min'] },
  'audit_log.enable': { name: 'enable_audit_log', description: 'Turn on audit logging so blocked requests are recorded', params: {}, required: [] },
  'php_exclusion.enable': { name: 'enable_platform_exclusions', description: 'Relax firewall rules that commonly break a CMS admin area (WordPress, Drupal, Joomla, Laravel, Symfony)', params: { platform: { type: 'string', description: 'wordpress, drupal, joomla, laravel or symfony' } }, required: ['platform'] },
}
const TOOL_NAME_TO_ACTION_ID = Object.fromEntries(Object.entries(TOOL_SCHEMAS).map(([id, s]) => [s.name, id]))

function toolSchemasFor(actionIds) {
  return (actionIds || [])
    .filter(id => TOOL_SCHEMAS[id])
    .map(id => {
      const s = TOOL_SCHEMAS[id]
      return { type: 'function', function: { name: s.name, description: s.description, parameters: { type: 'object', properties: s.params, required: s.required } } }
    })
}

function actionIdForToolName(name) {
  return (typeof name === 'string' && Object.hasOwn(TOOL_NAME_TO_ACTION_ID, name))
    ? TOOL_NAME_TO_ACTION_ID[name]
    : null
}

const ACTION_HINTS = {
  'ip.block': /\b(block|ban|deny|stop)\b/i,
  'ip.allow': /\b(allow|whitelist|let .* (in|through)|unban|bypass)\b/i,
  'ip.unblock': /\b(unblock|un-block|remove|delete|take off|lift)\b/i,
  'geo.block': /\b(block|ban|deny|stop|country|countries|from)\b/i,
  'geo.unblock': /\b(unblock|allow|remove|lift|stop blocking)\b/i,
  'ua.block': /\b(user.?agent|bot|crawler|scraper|block)\b/i,
  'ua.unblock': /\b(user.?agent|bot|crawler|unblock|allow)\b/i,
  'paranoia.set': /\b(paranoia|strict|lenient|level|aggressive|sensitiv)\b/i,
  'engine.enable': /\b(turn on|enable|activate|start|protect|engine|on)\b/i,
  'rate_limit.enable': /\b(rate.?limit|throttle|flood|too many requests|slow.*down)\b/i,
  'rate_limit.set': /\b(rate.?limit|throttle|requests? per|per minute|rpm)\b/i,
  'rule.add': /\b(rule|custom|block.*(path|url|request|contain)|coraza|secrule|match)\b/i,
  'audit_log.enable': /\b(audit|log|logging|record|history)\b/i,
  'php_exclusion.enable': /\b(wordpress|wp-admin|drupal|joomla|laravel|symfony|exclusion|cms|admin.*(break|block))\b/i,
}

const INTENT_RE = /\b(block|ban|deny|allow|unblock|remove|delete|enable|disable|turn|set|add|make|change|stop|limit|throttle|raise|lower|increase|decrease)\b/i

function candidatesFor(message) {
  const msg = String(message || '')
  if (!INTENT_RE.test(msg)) return []
  const hits = Object.entries(ACTION_HINTS).filter(([, re]) => re.test(msg)).map(([id]) => id)
  return hits.slice(0, 4)
}

function normalizeToolArgs(actionId, args) {
  args = args || {}
  switch (actionId) {
    case 'geo.block':
    case 'geo.unblock': {
      const cc = String(args.country_code || '').toUpperCase()
      return { cc, name: countryNameFor(cc) }
    }
    case 'paranoia.set': return { level: Number(args.level) }
    case 'ip.block':
    case 'ip.allow':
    case 'ip.unblock': return { ip: args.ip }
    case 'ua.block':
    case 'ua.unblock': return { agent: args.agent }
    case 'rule.add': return { target: String(args.target || '').toLowerCase().trim(), value: String(args.value || '').trim() }
    case 'rate_limit.set': return { requests_per_min: Number(args.requests_per_min) }
    case 'php_exclusion.enable': return { platform: String(args.platform || '').toLowerCase().trim() }
    default: return {}
  }
}

const ACTIONS = {
  'ip.block': {
    direction: DIRECTION.STRENGTHEN,
    validate: ({ ip }, req) => {
      if (!isValidIpOrCidr(ip)) return 'That does not look like a valid IP address or CIDR range.'
      if (ipCoveredBy(req.ip, ip)) {
        return `"${ip}" covers your own address (${normalizeClientIp(req.ip)}) — blocking it would lock you out of CatWAF.`
      }
      return null
    },
    render: ({ ip }) => `Block ${ip}`,
    describe: ({ ip }) => `${ip} added to the blocklist`,
    apply: (req, { ip }) => {
      const prev = state.WAF.ip_blacklist.slice()
      if (!state.WAF.ip_blacklist.some(e => e.ip === ip)) {
        state.WAF.ip_blacklist.push({ ip, note: 'Added by CatAI', added_at: auditSvc.now(), expires_at: null })
      }
      return { prev: { ip_blacklist: prev }, ...commit(req, 'ip.add', ip, { list: 'blacklist' }) }
    },
  },

  'geo.block': {
    direction: DIRECTION.STRENGTHEN,
    validate: ({ cc }) => (isValidCountryCode(cc) ? null : 'That is not a valid two-letter country code.'),
    render: ({ cc, name }) => `Block ${name ? titleCase(name) : cc} (${cc})`,
    describe: ({ cc, name }) => `${name ? titleCase(name) : cc} (${cc}) added to the geo blocklist`,
    apply: (req, { cc }) => {
      const prev = state.WAF.geo_blocking.slice()
      if (!state.WAF.geo_blocking.includes(cc)) state.WAF.geo_blocking.push(cc)
      return { prev: { geo_blocking: prev }, ...commit(req, 'geo.toggle', cc, {}) }
    },
  },

  'engine.enable': {
    direction: DIRECTION.STRENGTHEN,
    validate: () => (state.WAF.engine === 'On' ? 'Protection is already on.' : null),
    render: () => 'Turn protection on',
    describe: () => 'protection is now On — attacks are blocked, not just logged',
    apply: (req) => {
      const prev = state.WAF.engine
      state.WAF.engine = 'On'
      return { prev: { engine: prev }, ...commit(req, 'engine.set', 'On', { from: prev }) }
    },
  },

  'rate_limit.enable': {
    direction: DIRECTION.STRENGTHEN,
    validate: () => (state.WAF.rate_limit && state.WAF.rate_limit.enabled ? 'Rate limiting is already enabled.' : null),
    render: () => 'Enable rate limiting',
    describe: () => `rate limiting enabled (${(state.WAF.rate_limit || {}).requests_per_min || 120} requests/min per IP)`,
    apply: (req) => {
      const prev = { ...state.WAF.rate_limit }
      state.WAF.rate_limit = { ...state.WAF.rate_limit, enabled: true }
      return { prev: { rate_limit: prev }, ...commit(req, 'ratelimit.set', 'enabled', {}) }
    },
  },

  'ua.block': {
    direction: DIRECTION.STRENGTHEN,
    validate: ({ agent }) => {
      if (typeof agent !== 'string' || agent.length < 2 || agent.length > 128) return 'That user-agent value looks wrong.'
      if (state.WAF.blocked_user_agents.includes(agent.toLowerCase())) return `"${agent}" is already blocked.`
      return null
    },
    render: ({ agent }) => `Block user agent "${agent}"`,
    describe: ({ agent }) => `user agent "${agent}" added to the block list`,
    apply: (req, { agent }) => {
      const prev = state.WAF.blocked_user_agents.slice()
      state.WAF.blocked_user_agents.push(agent.toLowerCase())
      return { prev: { blocked_user_agents: prev }, ...commit(req, 'useragent.block', agent, {}) }
    },
  },

  'paranoia.set': {
    directionFor: ({ level }) => (Number(level) > Number(state.WAF.paranoia_level || 1) ? DIRECTION.STRENGTHEN : DIRECTION.WEAKEN),
    validate: ({ level }) => {
      if (![1, 2, 3, 4].includes(Number(level))) return 'Paranoia level must be 1, 2, 3 or 4.'
      if (Number(level) === Number(state.WAF.paranoia_level)) return `Paranoia is already at level ${level}.`
      return null
    },
    render: ({ level }) => `Set paranoia to level ${level} (currently ${state.WAF.paranoia_level})`,
    describe: ({ level }) => `paranoia level set to ${level}`,
    warn: ({ level }) => (Number(level) < Number(state.WAF.paranoia_level || 1)
      ? 'Lowering paranoia means fewer attack patterns are detected.'
      : null),
    apply: (req, { level }) => {
      const prev = state.WAF.paranoia_level
      state.WAF.paranoia_level = Number(level)
      return { prev: { paranoia_level: prev }, ...commit(req, 'paranoia.set', String(level), { from: prev }) }
    },
  },

  'ip.allow': {
    direction: DIRECTION.WEAKEN,
    validate: ({ ip }) => (isValidIpOrCidr(ip) ? null : 'That does not look like a valid IP address or CIDR range.'),
    render: ({ ip, ttl_minutes }) => `Allow ${ip} for ${formatTtl(ttl_minutes || 60)}`,
    describe: ({ ip, ttl_minutes }) => `${ip} allowed through the firewall for ${formatTtl(ttl_minutes || 60)}`,
    warn: () => 'An allowed address bypasses every WAF rule. It expires automatically.',
    apply: (req, { ip, ttl_minutes }) => {
      const ttl = Number(ttl_minutes) > 0 ? Number(ttl_minutes) : 60
      const prev = state.WAF.ip_whitelist.slice()
      state.WAF.ip_whitelist.push({
        ip, note: 'Added by CatAI', added_at: auditSvc.now(),
        expires_at: new Date(Date.now() + ttl * 60000).toISOString(),
      })
      return { prev: { ip_whitelist: prev }, ...commit(req, 'ip.add', ip, { list: 'whitelist', ttl_minutes: ttl }) }
    },
  },

  'ip.unblock': {
    direction: DIRECTION.WEAKEN,
    validate: ({ ip }) => {
      if (!isValidIpOrCidr(ip)) return 'That does not look like a valid IP address or CIDR range.'
      if (!state.WAF.ip_blacklist.some(e => e.ip === ip)) return `${ip} is not on the blocklist.`
      return null
    },
    render: ({ ip }) => `Remove ${ip} from the blocklist`,
    describe: ({ ip }) => `${ip} removed from the blocklist`,
    warn: () => 'That address will be able to reach your site again (still filtered by the WAF rules).',
    apply: (req, { ip }) => {
      const prev = state.WAF.ip_blacklist.slice()
      state.WAF.ip_blacklist = state.WAF.ip_blacklist.filter(e => e.ip !== ip)
      return { prev: { ip_blacklist: prev }, ...commit(req, 'ip.remove', ip, {}) }
    },
  },

  'rule.add': {
    direction: DIRECTION.STRENGTHEN,
    validate: ({ target, value }) => {
      if (typeof target !== 'string' || !Object.hasOwn(RULE_TARGETS, target)) {
        return `I can write rules that match on ${Object.keys(RULE_TARGETS).map(t => RULE_TARGETS[t].label).join(', ')} — not "${target}".`
      }
      if (typeof value !== 'string' || !value.trim()) return 'A rule needs some text to match on.'
      if (value.length > 120) return 'That match text is too long — keep it under 120 characters.'
      if (/["'\n\r\\]/.test(value)) return 'Match text can\'t contain quotes, backslashes or line breaks.'
      return null
    },
    render: ({ target, value }) => `Block requests where ${RULE_TARGETS[target].label} contains "${value}"`,
    describe: ({ target, value }) => `custom rule added — requests with "${value}" in the ${RULE_TARGETS[target].label} are now blocked`,
    apply: (req, { target, value }) => {
      const prev = (state.WAF.custom_rules || []).slice()
      state.WAF.custom_rules = prev.concat([{
        id: nextCustomRuleId(),
        name: `CatAI: block ${RULE_TARGETS[target].label} containing ${value}`,
        variable: RULE_TARGETS[target].variable,
        operator: 'contains',
        value,
        action: 'deny',
        phase: RULE_TARGETS[target].phase,
        enabled: true,
      }])
      return { prev: { custom_rules: prev }, ...commit(req, 'rule.add', value, { target }) }
    },
  },

  'geo.unblock': {
    direction: DIRECTION.WEAKEN,
    validate: ({ cc }) => {
      if (!isValidCountryCode(cc)) return 'That does not look like a valid country.'
      if (!(state.WAF.geo_blocking || []).includes(cc)) return `${countryNameFor(cc)} is not currently blocked.`
      return null
    },
    render: ({ cc, name }) => `Unblock ${name ? titleCase(name) : cc} (${cc})`,
    describe: ({ cc, name }) => `${name ? titleCase(name) : cc} (${cc}) removed from the geo blocklist`,
    warn: () => 'Traffic from that country will be able to reach your site again.',
    apply: (req, { cc }) => {
      const prev = (state.WAF.geo_blocking || []).slice()
      state.WAF.geo_blocking = prev.filter(c => c !== cc)
      return { prev: { geo_blocking: prev }, ...commit(req, 'geo.remove', cc, {}) }
    },
  },

  'ua.unblock': {
    direction: DIRECTION.WEAKEN,
    validate: ({ agent }) => {
      if (typeof agent !== 'string' || !agent.trim()) return 'I need to know which user agent to unblock.'
      if (!(state.WAF.blocked_user_agents || []).includes(agent)) return `"${agent}" is not on the blocked user-agent list.`
      return null
    },
    render: ({ agent }) => `Remove "${agent}" from the blocked user agents`,
    describe: ({ agent }) => `user agent "${agent}" removed from the block list`,
    warn: () => 'Requests carrying that user agent will be allowed through again.',
    apply: (req, { agent }) => {
      const prev = (state.WAF.blocked_user_agents || []).slice()
      state.WAF.blocked_user_agents = prev.filter(a => a !== agent)
      return { prev: { blocked_user_agents: prev }, ...commit(req, 'ua.remove', agent, {}) }
    },
  },

  'rate_limit.set': {
    directionFor: ({ requests_per_min }) => {
      const cur = (state.WAF.rate_limit || {}).requests_per_min || 120
      return Number(requests_per_min) < cur ? DIRECTION.STRENGTHEN : DIRECTION.WEAKEN
    },
    validate: ({ requests_per_min }) => {
      const n = Number(requests_per_min)
      if (!Number.isInteger(n)) return 'The rate limit needs to be a whole number of requests per minute.'
      if (n < 10 || n > 10000) return 'Pick a rate limit between 10 and 10000 requests per minute.'
      return null
    },
    render: ({ requests_per_min }) => `Set the rate limit to ${requests_per_min} requests/min per IP`,
    describe: ({ requests_per_min }) => `rate limit set to ${requests_per_min} requests/min per IP`,
    warn: () => 'A higher ceiling lets each visitor make more requests before being throttled.',
    apply: (req, { requests_per_min }) => {
      const prev = { ...(state.WAF.rate_limit || {}) }
      state.WAF.rate_limit = { ...prev, enabled: true, requests_per_min: Number(requests_per_min) }
      return { prev: { rate_limit: prev }, ...commit(req, 'rate_limit.set', String(requests_per_min), {}) }
    },
  },

  'audit_log.enable': {
    direction: DIRECTION.STRENGTHEN,
    validate: () => (state.WAF.audit_log ? 'Audit logging is already on.' : null),
    render: () => 'Turn on audit logging',
    describe: () => 'audit logging enabled — blocked requests will now be recorded',
    apply: (req) => {
      const prev = state.WAF.audit_log
      state.WAF.audit_log = true
      return { prev: { audit_log: prev }, ...commit(req, 'audit_log.enable', 'on', {}) }
    },
  },

  'php_exclusion.enable': {
    direction: DIRECTION.WEAKEN,
    validate: ({ platform }) => {
      if (!PHP_PLATFORMS.includes(platform)) return `I can add exclusions for ${PHP_PLATFORMS.join(', ')}.`
      if ((state.WAF.php_exclusions || {})[platform]) return `The ${titleCase(platform)} exclusions are already on.`
      return null
    },
    render: ({ platform }) => `Add ${titleCase(platform)} compatibility exclusions`,
    describe: ({ platform }) => `${titleCase(platform)} exclusions enabled — rules that commonly break its admin pages are relaxed`,
    warn: ({ platform }) => `This relaxes some firewall rules on ${titleCase(platform)}'s own paths so its admin area works. That's a small, targeted reduction in coverage.`,
    apply: (req, { platform }) => {
      const prev = { ...(state.WAF.php_exclusions || {}) }
      state.WAF.php_exclusions = { ...prev, [platform]: true }
      return { prev: { php_exclusions: prev }, ...commit(req, 'php_exclusion.enable', platform, {}) }
    },
  },
}

const RULE_TARGETS = {
  path: { label: 'URL path', variable: 'REQUEST_URI', phase: 1 },
  query: { label: 'query string', variable: 'QUERY_STRING', phase: 1 },
  body: { label: 'request body', variable: 'REQUEST_BODY', phase: 2 },
  header: { label: 'request headers', variable: 'REQUEST_HEADERS', phase: 1 },
  user_agent: { label: 'user agent', variable: 'REQUEST_HEADERS:User-Agent', phase: 1 },
}

const PHP_PLATFORMS = ['wordpress', 'drupal', 'joomla', 'laravel', 'symfony']

function nextCustomRuleId() {
  const used = (state.WAF.custom_rules || []).map(r => Number(r.id) || 0)
  return Math.max(9300, ...used) + 1
}

function titleCase(s) { return String(s).replace(/\b[a-z]/g, c => c.toUpperCase()) }
function formatTtl(min) {
  const n = Number(min)
  if (n % 1440 === 0) return `${n / 1440} day${n / 1440 === 1 ? '' : 's'}`
  if (n % 60 === 0) return `${n / 60} hour${n / 60 === 1 ? '' : 's'}`
  return `${n} minute${n === 1 ? '' : 's'}`
}

function getAction(id) { return ACTIONS[id] || null }

function directionOf(id, params) {
  const a = ACTIONS[id]
  if (!a) return null
  return a.directionFor ? a.directionFor(params || {}) : a.direction
}

function prepare(id, params, req) {
  if (typeof id !== 'string' || !Object.hasOwn(ACTIONS, id)) return { ok: false, error: 'Unknown action.' }
  const action = ACTIONS[id]
  const error = action.validate ? action.validate(params || {}, req) : null
  if (error) return { ok: false, error }
  return {
    ok: true,
    actionId: id,
    params: params || {},
    direction: directionOf(id, params),
    label: action.render(params || {}),
    warn: action.warn ? action.warn(params || {}) : null,
  }
}

function apply(id, params, req) {
  const prepared = prepare(id, params, req)
  if (!prepared.ok) return prepared
  const tx = require('../configTx').apply({ label: 'catai.apply', req, mutate: () => {
    const fresh = prepare(id, params, req)
    if (!fresh.ok) throw new Error(fresh.error)
    return ACTIONS[id].apply(req, params || {})
  } })
  if (!tx.ok) return { ...tx, actionId: id }
  const result = tx.result
  return {
    ok: true,
    actionId: id,
    params: params || {},
    direction: prepared.direction,
    label: prepared.label,
    message: ACTIONS[id].describe(params || {}),
    prev: result.prev,
    caddy_reloaded: tx.reloaded,
    caddy_error: tx.reloadError,
  }
}

function restore(prev, req) {
  if (!prev || typeof prev !== 'object' || Array.isArray(prev) || Object.keys(prev).length === 0) {
    return { ok: false, error: 'Nothing to restore.' }
  }
  const unknown = Object.keys(prev).find(key => !Object.hasOwn(state.WAF, key))
  if (unknown) return { ok: false, error: `Cannot restore unknown field "${unknown}".` }
  const { sync } = state.updateWAF(w => { for (const [key, value] of Object.entries(prev)) w[key] = value },
    { label: 'catai.undo', req, syncCaddy: true })
  auditSvc.audit(req, 'catai.undo', Object.keys(prev).join(','), { caddy_reloaded: sync.reloaded })
  return { ok: true, caddy_reloaded: sync.reloaded }
}

module.exports = {
  ACTIONS, DIRECTION, getAction, directionOf, prepare, apply, restore, formatTtl,
  toolSchemasFor, actionIdForToolName, normalizeToolArgs, candidatesFor,
}
