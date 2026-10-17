
const db = require('./db')
const { stripUnsafeKeys } = require('./sanitize')

const DEFAULT_WAF = {
  engine: 'On',
  paranoia_level: 1,
  executing_paranoia_level: 2,
  inbound_anomaly_threshold: 5,
  outbound_anomaly_threshold: 4,
  allowed_methods: ['GET','POST','HEAD','OPTIONS'],
  allowed_content_types: [
    'application/x-www-form-urlencoded','multipart/form-data','text/xml',
    'application/xml','application/json',
  ],
  max_request_body_size: 13107200,
  max_file_upload_size: 1048576,
  request_body_inspection: true,
  response_body_inspection: false,
  audit_log: true,
  audit_log_parts: ['A','B','E','F','H'],
  enforce_bodyproc_urlencoded: false,
  early_blocking: true,
  sampling_percentage: 100,
  geo_blocking: [],
  ip_whitelist: [],
  ip_blacklist: [],
  custom_rules: [],
  rule_exclusions: [],
  disabled_rules: [],
  php_exclusions: { wordpress: false, drupal: false, joomla: false, laravel: false, symfony: false },
  rate_limit: { enabled: false, requests_per_min: 120, burst: 20, per: 'ip' },
  retention_days: 30,
  alerts: { slack_webhook: '', email_to: '', custom_webhook: '', spike_threshold: 100 },
  blocked_user_agents: ['sqlmap','nikto','nmap','masscan','zgrab','dirbuster','gobuster','wfuzz','hydra','burpsuite'],
  header_rules: [],
}

const DEFAULT_RULE_CATEGORIES = {
  '920': { name: 'Protocol Enforcement', enabled: true, count: 47 },
  '921': { name: 'Protocol Attack', enabled: true, count: 11 },
  '930': { name: 'Local File Inclusion', enabled: true, count: 18 },
  '931': { name: 'Remote File Inclusion', enabled: true, count: 7 },
  '932': { name: 'Remote Command Execution', enabled: true, count: 58 },
  '933': { name: 'PHP Injection', enabled: true, count: 37 },
  '934': { name: 'Node.js Injection', enabled: true, count: 4 },
  '941': { name: 'XSS (Cross-Site Scripting)', enabled: true, count: 62 },
  '942': { name: 'SQL Injection', enabled: true, count: 108 },
  '943': { name: 'Session Fixation', enabled: true, count: 6 },
  '944': { name: 'Java Attack', enabled: true, count: 7 },
  '949': { name: 'Blocking Evaluation', enabled: true, count: 2 },
  '980': { name: 'Anomaly Scoring', enabled: true, count: 2 },
}

// Everything loaded from SQLite passes through stripUnsafeKeys: a persisted
// blob carrying an own "__proto__" key would survive the spread below and,
// on the next Object.assign reload, execute a real prototype change on
// state.WAF — silently re-arming or disarming WAF fields wholesale.
//
// Blob and revision are two rows, so they are read as a PAIR: re-read the
// revision after the blob and retry until both reads agree. Pairing a new
// revision with an older blob here would silently disable every future
// staleness refresh (the compare would keep saying "you are current").
function loadWAFFresh() {
  for (;;) {
    const r0 = currentRev()
    const stored = stripUnsafeKeys(db.getState('waf') || {})
    const r1 = currentRev()
    if (r0 === r1) return { fresh: { ...DEFAULT_WAF, ...stored }, rev: r0 }
  }
}
function loadWAF() { return loadWAFFresh().fresh }
function loadRuleCategories() { return stripUnsafeKeys(db.getState('rule_categories')) || { ...DEFAULT_RULE_CATEGORIES } }

const REV_KEY = 'waf__rev'

function currentRev() {
  const r = db.getState(REV_KEY)
  return Number.isFinite(Number(r)) ? Number(r) : 0
}

// The revision this process believes is loaded. Another process committing
// bumps the stored rev; updateWAF() compares before mutating and refreshes
// from the database first, so a mutation can never land on (and then
// overwrite with) a stale snapshot.
let _loadedRev = null

function replaceInMemory(fresh) {
  for (const key of Object.keys(state.WAF)) delete state.WAF[key]
  Object.assign(state.WAF, fresh)
}

function persistWAFLocked() {
  // Order matters. The revision is the commit barrier: it is bumped only
  // AFTER the blob lands, so a concurrent refresh either sees
  // (oldRev, oldBlob) or (newRev, newBlob) — never (newRev, oldBlob), which
  // would be accepted as a stable pair and silently freeze staleness
  // detection with outdated data.
  db.setState('waf', stripUnsafeKeys(state.WAF))
  _loadedRev = currentRev() + 1
  db.setState(REV_KEY, _loadedRev)
}

const _bootSnapshot = loadWAFFresh()

const state = {
  WAF: _bootSnapshot.fresh,
  RULE_CATEGORIES: loadRuleCategories(),

  DEFAULT_WAF, DEFAULT_RULE_CATEGORIES,

  // Everything added after the original flat WAF blob lives in its own
  // validated, per-group namespace (services/settings). Exposed here so
  // renderers and the transaction pipeline reach all configuration through
  // one object, and so a group participates in snapshot/rollback for free.
  settings: require('./settings'),

  saveWAF(skipCaddy = false) {
    // Persist-only path (used by callers that already ran inside a configTx
    // or config lock). Still bumps the revision so other processes notice.
    persistWAFLocked()
    if (!skipCaddy) {
      setImmediate(() => {
        try {
          const caddy = require('./caddy')
          if (typeof caddy.applyToCaddy === 'function') caddy.applyToCaddy('waf.autosave', null)
        } catch (e) { console.error('[CatWAF] Auto Caddy reload failed:', e.message) }
      })
    }
  },

  // The cross-process-safe mutation entry point. Runs under the config
  // lock, re-reads committed state if any other process changed it since
  // our last load, applies `mutator` to that fresh object, persists with a
  // bumped revision, and — when asked — patches + reloads Caddy while still
  // holding the lock so no other writer can interleave between the state
  // and the file it renders from.
  //
  // Returns { result, sync } where sync mirrors applyToCaddy's
  // { reloaded, error } shape (sync === null when syncCaddy was not set).
  updateWAF(mutator, { label = 'waf.update', req = null, syncCaddy = false } = {}) {
    if (syncCaddy) {
      const tx = require('./configTx').apply({ label, req, mutate: s => mutator(s.WAF) })
      if (!tx.ok) throw Object.assign(new Error('Configuration update failed: ' + tx.error), { configurationTransaction: tx })
      return { result: tx.result, sync: { reloaded: tx.reloaded, error: tx.reloadError } }
    }
    const configLock = require('./configLock')
    return configLock.withConfigLock(() => {
      require('./configTx').assertReady()
      const rev = currentRev()
      if (_loadedRev === null || _loadedRev !== rev) {
        replaceInMemory(loadWAF())
        _loadedRev = rev
      }
      let result
      try { result = mutator(state.WAF) }
      catch (error) { replaceInMemory(loadWAF()); throw error }
      persistWAFLocked()
      return { result, sync: null }
    })
  },
  saveRuleCategories() { db.setState('rule_categories', state.RULE_CATEGORIES) },

  reloadAllFromDb() {
    const configLock = require('./configLock')
    return configLock.withConfigLock(() => {
      replaceInMemory(loadWAF())
      for (const key of Object.keys(state.RULE_CATEGORIES)) delete state.RULE_CATEGORIES[key]
      Object.assign(state.RULE_CATEGORIES, loadRuleCategories())
      state.settings.reloadAllFromDb()
      return { ok: true }
    })
  },
}

module.exports = state

// React to ban-set changes without waiting for the next scheduler tick:
// manual and automatic bans reach the edge within ~2s. The listener is
// registered lazily so CLI paths that never load caddy keep working.
setImmediate(() => {
  try {
    let timer = null
    state.settings && require('./bans').onBanChange((kind) => {
      if (!settings_get('edge_bans').enabled) return
      if (timer) return
      timer = setTimeout(() => {
        timer = null
        try { require('./edgeBans').refresh({}) } catch {}
      }, 2000)
      timer.unref?.()
    })
    require('./bans').onBanChange((kind, detail) => {
      try { require('./alertDispatch').onBanChange(kind, detail) } catch {}
    })
  } catch {}
})

function settings_get(group) {
  try { return state.settings.get(group) } catch { return { enabled: false } }
}

// Record exactly which revision the startup blob came from — taken from the
// same consistent snapshot above, not re-read afterwards.
_loadedRev = _bootSnapshot.rev
