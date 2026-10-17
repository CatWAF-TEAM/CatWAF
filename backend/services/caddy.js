
const fs = require('fs')
const state = require('./state')
const configLock = require('./configLock')
const auditSvc = require('./audit')
const {
  escapeForDirective, isValidIpOrCidr,
  ALLOWED_VARIABLES, ALLOWED_OPERATORS, ALLOWED_ACTIONS, ALLOWED_PHASES,
} = require('./sanitize')

const { execFileSync } = require('child_process')

const path = require('path')
const PROJECT_ROOT = path.join(__dirname, '..', '..')

const WAF_MARKER_START = '# @@CATWAF_WAF_START@@'
const WAF_MARKER_END   = '# @@CATWAF_WAF_END@@'

// Two further managed regions, added alongside the original per-site WAF
// block. Neither could live inside it: global options (listener wrappers,
// trusted proxies, protocol selection, server timeouts) are per-server, not
// per-site, and the reject-unknown-Host catch-all has to be its own
// top-level site block or an unmatched Host would fall through to whichever
// block happens to be first.
const GLOBAL_MARKER_START = '# @@CATWAF_GLOBAL_START@@'
const GLOBAL_MARKER_END   = '# @@CATWAF_GLOBAL_END@@'
const CATCHALL_MARKER_START = '# @@CATWAF_CATCHALL_START@@'
const CATCHALL_MARKER_END   = '# @@CATWAF_CATCHALL_END@@'

function candidatePaths() {
  const out = []

  try {
    const unit = execFileSync('systemctl', ['cat', 'caddy'], { encoding: 'utf8', timeout: 3000, stdio: ['ignore', 'pipe', 'ignore'] })
    const m = /^ExecStart=.*?--config\s+(\S+)/m.exec(unit)
    if (m) out.push(m[1])
  } catch {}

  out.push(
    path.join(PROJECT_ROOT, 'Caddyfile'),
    '/etc/caddy/Caddyfile',
    '/usr/local/etc/caddy/Caddyfile',
    '/opt/homebrew/etc/Caddyfile',
    '/usr/local/etc/Caddyfile',
  )
  return [...new Set(out)]
}

function scorePath(p) {
  let score = 0
  try {
    const body = fs.readFileSync(p, 'utf8')
    score += 10
    if (body.includes(WAF_MARKER_START)) score += 100
  } catch { return 0 }
  try { fs.accessSync(p, fs.constants.W_OK); score += 5 } catch {}
  return score
}

function detectCaddyfilePath() {
  if (process.env.CADDYFILE_PATH) return process.env.CADDYFILE_PATH

  const scored = candidatePaths()
    .map(p => ({ p, score: scorePath(p) }))
    .filter(c => c.score > 0)
    .sort((a, b) => b.score - a.score)

  if (scored.length) return scored[0].p

  return path.join(PROJECT_ROOT, 'Caddyfile')
}

const CADDYFILE_PATH  = detectCaddyfilePath()
const CADDYFILE_SOURCE = process.env.CADDYFILE_PATH ? 'CADDYFILE_PATH' : 'auto-detected'
const CORAZA_LIST_DIR = process.env.CORAZA_LIST_DIR || '/etc/coraza/lists'
const CADDY_ADMIN_URL = (process.env.CADDY_ADMIN_URL || 'http://127.0.0.1:2019').replace(/\/+$/, '')
const CADDY_ADMIN_SOCKET = process.env.CADDY_ADMIN_SOCKET || ''
// Coraza opens SecAuditLog when the config is PROVISIONED, not lazily on the
// first audit entry — so `caddy validate` fails outright if the path is not
// openable. /var/log/coraza is the right default under Docker (compose mounts
// a volume there), but on a host-native install it neither exists nor is
// creatable by an unprivileged CatWAF, which made every apply fail with
// "open /var/log/coraza/audit.json: no such file or directory".
//
// The path is therefore resolved to somewhere CatWAF can actually write,
// preferring the conventional location and falling back to CatWAF's own data
// directory. An explicitly configured CORAZA_AUDIT_LOG is never silently
// relocated — if it cannot be prepared, that is reported as an error.
const DEFAULT_AUDIT_LOG = '/var/log/coraza/audit.json'
const AUDIT_LOG_EXPLICIT = !!process.env.CORAZA_AUDIT_LOG

function dataDir() {
  return process.env.DB_DIR || path.join(PROJECT_ROOT, 'data')
}

// The installer creates `catwaf` as a no-home system account, so Caddy's
// storage root — $XDG_DATA_HOME, else $HOME/.local/share — resolves under a
// /home/catwaf that does not exist. Anything Caddy stores there then fails:
// ACME certificates (re-requested on every restart, straight into the
// provider's rate limits) and the internal CA that `tls internal` provisions,
// which aborts config load outright with "generating root: saving root
// certificate: mkdir /home/catwaf: permission denied".
//
// Resolved at module load, before anything shells out to the caddy binary, so
// every child process inherits one storage root that the service account
// actually owns. An explicit XDG_DATA_HOME is always respected.
;(function ensureCaddyStorageRoot() {
  if (process.env.XDG_DATA_HOME) return
  const home = process.env.HOME
  if (home) {
    try { fs.accessSync(home, fs.constants.W_OK); return } catch {}
  }
  const root = path.join(dataDir(), 'caddy-home')
  try {
    fs.mkdirSync(root, { recursive: true, mode: 0o700 })
    process.env.XDG_DATA_HOME = root
    if (!process.env.XDG_CONFIG_HOME) process.env.XDG_CONFIG_HOME = root
  } catch {}
})()

function auditLogCandidates() {
  if (AUDIT_LOG_EXPLICIT) return [process.env.CORAZA_AUDIT_LOG]
  return [DEFAULT_AUDIT_LOG, path.join(dataDir(), 'logs', 'coraza-audit.json')]
}

function isWritable(p) {
  try { fs.accessSync(p, fs.constants.W_OK); return true } catch { return false }
}

// Can this candidate be used without creating anything? Used by --dry-run,
// which must not touch the filesystem but must still predict a real run.
function auditLogUsable(candidate) {
  if (fs.existsSync(candidate)) return isWritable(candidate)
  const dir = path.dirname(candidate)
  if (fs.existsSync(dir)) return isWritable(dir)
  // the directory would have to be created — is the nearest existing
  // ancestor writable?
  let ancestor = path.dirname(dir)
  while (ancestor && ancestor !== path.dirname(ancestor) && !fs.existsSync(ancestor)) {
    ancestor = path.dirname(ancestor)
  }
  return isWritable(ancestor)
}

// Non-mutating: what would ensureAuditLog() pick?
function auditLogStatus() {
  for (const candidate of auditLogCandidates()) {
    if (auditLogUsable(candidate)) {
      return { ok: true, path: candidate, fellBack: candidate !== (process.env.CORAZA_AUDIT_LOG || DEFAULT_AUDIT_LOG) }
    }
  }
  return { ok: false, attempted: auditLogCandidates() }
}

// Resolved at module load so EVERY process agrees on the effective path —
// including read-only commands like `catwaf audit`, `health` and `doctor`,
// which never call ensureAuditLog(). Without this they read the default
// /var/log path, find nothing, and report zero events while Coraza is
// happily writing to the fallback. Purely inspective: creates nothing.
// The unrotated path: what the audit log is called before rotation renames
// the *active* file. services/auditLog.js derives its archive naming and its
// sidecar state location from this.
function baseAuditLogPath() {
  if (AUDIT_LOG_EXPLICIT) return process.env.CORAZA_AUDIT_LOG
  const candidates = auditLogCandidates()
  const existing = candidates.find(c => { try { return fs.statSync(c).isFile() } catch { return false } })
  if (existing) return existing
  return candidates.find(auditLogUsable) || DEFAULT_AUDIT_LOG
}

// Rotation moves the ACTIVE log to a new path (see services/auditLog.js for
// why it cannot keep one path forever), recording it in a sidecar file next
// to the logs. That file is read here with nothing but `fs` so this module
// stays dependency-free and usable before the database exists.
function rotatedActivePath(basePath) {
  try {
    const st = JSON.parse(fs.readFileSync(path.join(path.dirname(basePath), '.catwaf-audit-state.json'), 'utf8'))
    const active = st && st.active
    if (typeof active !== 'string') return null
    // Must be a plain absolute path in the same directory — never follow a
    // sidecar file into somewhere unexpected.
    if (!/^\/[A-Za-z0-9._\-/]*$/.test(active)) return null
    if (path.dirname(active) !== path.dirname(basePath)) return null
    return active
  } catch { return null }
}

function resolveAuditLogPath() {
  const base = baseAuditLogPath()
  return rotatedActivePath(base) || base
}

let AUDIT_LOG_PATH = resolveAuditLogPath()

// Creates the audit log directory and file so Coraza can open it, and
// updates the effective path. Idempotent — safe to call before every apply.
function ensureAuditLog() {
  const attempted = []
  // The rotated active path (when there is one) comes first: rotation has
  // already pointed Coraza at it, and falling back to the base candidate
  // here would silently undo the rotation.
  const rotated = rotatedActivePath(baseAuditLogPath())
  const candidates = rotated ? [rotated, ...auditLogCandidates()] : auditLogCandidates()
  for (const candidate of candidates) {
    try {
      fs.mkdirSync(path.dirname(candidate), { recursive: true, mode: 0o750 })
      // `a` creates the file if missing and never truncates an existing log.
      fs.closeSync(fs.openSync(candidate, 'a', 0o660))
      if ((fs.statSync(candidate).mode & 0o777) !== 0o660) fs.chmodSync(candidate, 0o660)
      if (!isWritable(candidate)) throw new Error('not writable')

      const fellBack = candidate !== (process.env.CORAZA_AUDIT_LOG || DEFAULT_AUDIT_LOG) && candidate !== rotated
      AUDIT_LOG_PATH = candidate
      module.exports.AUDIT_LOG_PATH = candidate
      return { ok: true, path: candidate, fellBack }
    } catch (e) {
      attempted.push(`${candidate} (${e.code || e.message})`)
    }
  }
  return {
    ok: false,
    attempted,
    error: AUDIT_LOG_EXPLICIT
      ? `CORAZA_AUDIT_LOG is set to ${process.env.CORAZA_AUDIT_LOG} but CatWAF cannot create or write it: ${attempted.join('; ')}.`
      : `CatWAF could not prepare an audit log. Tried: ${attempted.join('; ')}.`,
  }
}

const ADMIN_CLIENT_SCRIPT = `
let body = ''
process.stdin.on('data', c => { body += c })
process.stdin.on('end', async () => {
  const url = process.env.CW_ADMIN_URL + process.env.CW_ADMIN_PATH
  const method = process.env.CW_ADMIN_METHOD
  // Caddy's admin endpoint checks the request origin on every method, not
  // only writes. Sending it just for non-GET made GET /config/ come back
  // 403 "client is not allowed to access from origin ''", which is what
  // isCaddyRunning() probes with — so a perfectly healthy Caddy was reported
  // as down.
  const opts = {
    method,
    signal: AbortSignal.timeout(Number(process.env.CW_ADMIN_TIMEOUT)),
    // Unix sockets are protected by filesystem permissions. Caddy has no
    // TCP origins for a Unix listener and rejects a synthetic TCP Origin.
    // Keep the origin header for configured TCP listeners that require it.
    headers: process.env.CW_ADMIN_SOCKET ? {} : { 'Origin': process.env.CW_ADMIN_URL },
  }
  if (method !== 'GET') {
    opts.headers['Content-Type'] = process.env.CW_ADMIN_CTYPE
    opts.body = body
  }
  try {
    if (process.env.CW_ADMIN_SOCKET) {
      const request = require('http').request({
        socketPath: process.env.CW_ADMIN_SOCKET,
        path: process.env.CW_ADMIN_PATH,
        method,
        headers: opts.headers,
        signal: opts.signal,
      }, res => {
        res.on('data', chunk => process.stdout.write(chunk))
        res.on('end', () => process.exit(res.statusCode >= 200 && res.statusCode < 300 ? 0 : 1))
        res.on('error', error => { process.stderr.write(error.message); process.exit(1) })
      })
      request.on('error', error => { process.stderr.write(error.message); process.exit(1) })
      request.end(method === 'GET' ? undefined : body)
      return
    }
    const res = await fetch(url, opts)
    const text = await res.text()
    process.stdout.write(text)
    process.exit(res.ok ? 0 : 1)
  } catch (e) {
    process.stderr.write(e.message)
    process.exit(1)
  }
})
`

function adminApiRequest(method, apiPath, body = '', contentType = 'application/json', timeoutMs = 10000) {
  const out = execFileSync(process.execPath, ['-e', ADMIN_CLIENT_SCRIPT], {
    input: body,
    timeout: timeoutMs + 2000,
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      CW_ADMIN_URL: CADDY_ADMIN_URL,
      CW_ADMIN_SOCKET: CADDY_ADMIN_SOCKET,
      CW_ADMIN_PATH: apiPath,
      CW_ADMIN_METHOD: method,
      CW_ADMIN_CTYPE: contentType,
      CW_ADMIN_TIMEOUT: String(timeoutMs),
    },
  })
  return out.toString()
}


function num(value, fallback, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const n = typeof value === 'number' ? value : Number(value)
  if (!Number.isFinite(n)) return fallback
  return Math.min(max, Math.max(min, Math.trunc(n)))
}

function oneOf(value, allowed, fallback) {
  return allowed.includes(value) ? value : fallback
}

// Builds just the `coraza_waf { ... }` directive block (no surrounding
// markers) from the current WAF settings — shared by the single managed
// WAF block (buildWAFBlock, below) and by proxy/generator.js, which embeds
// the same protection into every auto-discovered route.
// How a denied request is answered (ideas #19 and #58). `deny,status:<code>`
// is the unchanged default; silent mode uses Coraza's `drop`, which closes
// the connection without writing a status line at all — nothing for an
// attacker's tooling to fingerprint, at the cost of a mistakenly blocked
// visitor getting no explanation either.
function denyAction() {
  try {
    const access = require('./settings').get('access')
    if (access.block_response_mode === 'silent') return 'drop'
    return `deny,status:${num(access.blocked_status_code, 403, { min: 100, max: 599 })}`
  } catch {
    return 'deny,status:403'
  }
}

function extendedSettings(group) {
  try { return require('./settings').get(group) } catch { return null }
}

function buildCorazaSnippet(waf) {
  const lines = []
  const deny = denyAction()
  lines.push('  coraza_waf {')
  lines.push('    load_owasp_crs')
  lines.push('    directives `')
  lines.push('      Include @coraza.conf-recommended')
  lines.push('      Include @crs-setup.conf.example')
  lines.push('      Include @owasp_crs/*.conf')
  const blockingPL = num(waf.paranoia_level, 1, { min: 1, max: 4 })
  const detectionPL = Math.max(blockingPL, num(waf.executing_paranoia_level, 2, { min: 1, max: 4 }))
  const methods = (Array.isArray(waf.allowed_methods) ? waf.allowed_methods : [])
    .filter(m => typeof m === 'string' && /^[A-Za-z]{3,10}$/.test(m))
    .map(m => m.toUpperCase())

  lines.push(`      SecRuleEngine ${oneOf(waf.engine, ['On', 'DetectionOnly', 'Off'], 'On')}`)
  lines.push(`      SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=${blockingPL}"`)
  lines.push(`      SecAction "id:900001,phase:1,pass,t:none,nolog,setvar:tx.detection_paranoia_level=${detectionPL}"`)
  lines.push(`      SecAction "id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=${num(waf.inbound_anomaly_threshold, 5, { min: 1, max: 1000 })},setvar:tx.outbound_anomaly_score_threshold=${num(waf.outbound_anomaly_threshold, 4, { min: 1, max: 1000 })}"`)
  lines.push(`      SecAction "id:900200,phase:1,pass,t:none,nolog,setvar:tx.allowed_methods=${(methods.length ? methods : ['GET', 'POST', 'HEAD', 'OPTIONS']).join(' ')}"`)
  lines.push(`      SecAction "id:900120,phase:1,pass,t:none,nolog,setvar:tx.early_blocking=${waf.early_blocking ? '1' : '0'}"`)
  lines.push(`      SecRequestBodyAccess ${waf.request_body_inspection ? 'On' : 'Off'}`)
  lines.push(`      SecResponseBodyAccess ${waf.response_body_inspection ? 'On' : 'Off'}`)
  lines.push(`      SecRequestBodyLimit ${num(waf.max_request_body_size, 13107200, { min: 1024, max: 1073741824 })}`)

  // CRS carries its own hardcoded 403 in the blocking-evaluation rules, so
  // changing the deny response (#19/#58) means re-pointing those two rules
  // as well as CatWAF's own. Only emitted when the response differs from the
  // default, so an untouched install renders exactly what it did before.
  if (deny !== 'deny,status:403') {
    lines.push(`      SecRuleUpdateActionById 949110 "phase:2,${deny},log,auditlog"`)
    lines.push(`      SecRuleUpdateActionById 959100 "phase:4,${deny},log,auditlog"`)
  }

  let ruleId = 9100
  for (const ip of (waf.ip_blacklist || [])) {
    if (!isValidIpOrCidr(ip.ip)) continue
    lines.push(`      SecRule REMOTE_ADDR "@ipMatch ${ip.ip}" "id:${ruleId++},phase:1,${deny},msg:'CatWAF Blacklisted IP ${ip.ip}'"`)
  }

  ruleId = 9200
  for (const ip of (waf.ip_whitelist || [])) {
    if (!isValidIpOrCidr(ip.ip)) continue
    lines.push(`      SecRule REMOTE_ADDR "@ipMatch ${ip.ip}" "id:${ruleId++},phase:1,allow,msg:'CatWAF Whitelisted IP ${ip.ip}'"`)
  }

  if (waf.geo_blocking && waf.geo_blocking.length > 0) {
    const codes = waf.geo_blocking.filter(cc => /^[A-Z]{2}$/.test(cc))
    if (codes.length > 0) lines.push(`      SecRule GEO:COUNTRY_CODE "@pm ${codes.join(' ')}" "id:9001,phase:1,${deny},msg:'CatWAF Geo Block'"`)
  }

  ruleId = 9300
  for (const r of (waf.custom_rules || [])) {
    if (!r || typeof r !== 'object' || r.enabled === false) continue
    const variable = oneOf(r.variable, [...ALLOWED_VARIABLES], 'ARGS')
    const operator = oneOf(r.operator, [...ALLOWED_OPERATORS], 'contains')
    const action = oneOf(r.action, [...ALLOWED_ACTIONS], 'deny')
    const phase = oneOf(num(r.phase, 2, { min: 1, max: 5 }), [...ALLOWED_PHASES], 2)
    const id = /^\d{1,10}$/.test(String(r.id)) ? String(r.id) : String(ruleId++)
    const value = escapeForDirective(r.value)
    const name = escapeForDirective(r.name)
    lines.push(`      SecRule ${variable} "@${operator} ${value}" "id:${id},phase:${phase},${action},log,msg:'${name}'"`)
  }

  for (const e of (waf.rule_exclusions || [])) {
    if (!e || typeof e !== 'object') continue
    if (!/^\d{1,10}(-\d{1,10})?$/.test(String(e.rule_id))) continue
    lines.push(`      SecRuleUpdateTargetById ${e.rule_id} "!${escapeForDirective(e.target)}:${escapeForDirective(e.value)}"`)
  }

  const RULE_CATS = state.RULE_CATEGORIES
  for (const [id, cat] of Object.entries(RULE_CATS)) {
    if (!cat.enabled) {
      lines.push(`      SecRuleRemoveById ${id}000-${id}999`)
    }
  }

  for (const ruleId of (waf.disabled_rules || [])) {
    if (!/^\d{3,7}$/.test(String(ruleId))) continue
    lines.push(`      SecRuleRemoveById ${ruleId}`)
  }

  if (waf.allowed_content_types && waf.allowed_content_types.length > 0) {
    // CRS 920420 searches for a pipe-delimited MIME token, not a substring.
    // Render the value here; a literal JavaScript .replace expression in a
    // SecLang action is never evaluated and corrupts the last MIME entry.
    const contentTypes = waf.allowed_content_types.map(t => `|${escapeForDirective(String(t))}|`).join(' ')
    lines.push(`      SecAction "id:900006,phase:1,pass,t:none,nolog,setvar:'tx.allowed_request_content_type=${contentTypes}'"`)
  }

  const sampling = num(waf.sampling_percentage, 100, { min: 0, max: 100 })
  if (sampling > 0 && sampling < 100) {
    lines.push(`      SecRule TX:SAMPLING_RNDM "@lt ${100 - sampling}" "id:900500,phase:1,pass,nolog,skipAfter:END_SAMPLING"`)
    lines.push(`      SecMarker END_SAMPLING`)
  }

  const phpExcl = waf.php_exclusions || {}
  let phpRuleId = 9400
  if (phpExcl.wordpress) {
    lines.push(`      SecRule REQUEST_URI "@beginsWith /wp-admin" "id:${phpRuleId++},phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly"`)
    lines.push(`      SecRule REQUEST_URI "@contains /wp-json" "id:${phpRuleId++},phase:1,pass,nolog,ctl:ruleRemoveById=941000-941999"`)
  }
  if (phpExcl.laravel) {
    lines.push(`      SecRule ARGS:_token "@rx ^[A-Za-z0-9+/=]{40}$" "id:${phpRuleId++},phase:2,pass,nolog,ctl:ruleRemoveTargetById=941100;ARGS:_token"`)
  }
  if (phpExcl.drupal) {
    lines.push(`      SecRule REQUEST_URI "@beginsWith /admin/views" "id:${phpRuleId++},phase:1,pass,nolog,ctl:ruleRemoveById=942000-942999"`)
  }
  if (phpExcl.joomla) {
    lines.push(`      SecRule REQUEST_URI "@contains /administrator" "id:${phpRuleId++},phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly"`)
  }

  if (waf.blocked_user_agents && waf.blocked_user_agents.length > 0) {
    const pattern = waf.blocked_user_agents
      .map(u => escapeForDirective(String(u)).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
      .join('|')
    lines.push(`      SecRule REQUEST_HEADERS:User-Agent "@rx (?i)${pattern}" "id:9050,phase:1,${deny},log,msg:'CatWAF Blocked Scanner UA'"`)
  }

  lines.push(`      SecAuditEngine ${waf.audit_log ? 'RelevantOnly' : 'Off'}`)
  // Header/body sections contain cookies, credentials and application data.
  // Keep transaction metadata and rule messages; matched fragments remain
  // sensitive and the audit log still requires restricted access.
  lines.push('      SecAuditLogParts AHZ')
  lines.push('      SecAuditLogType Serial')
  lines.push(`      SecAuditLog ${AUDIT_LOG_PATH}`)
  lines.push('      SecAuditLogFormat JSON')

  // Idea #62 — raw Coraza directives, by insertion context. Still inside the
  // same validate-before-apply transaction as everything else, so a bad
  // snippet fails exactly the way a bad structured setting does.
  const raw = extendedSettings('raw_config')
  if (raw && raw.enabled) {
    for (const [label, body] of [['global', raw.waf_global], ['per-site', raw.waf_per_site]]) {
      if (!body || !body.trim()) continue
      lines.push(`      # ── unmanaged: raw Coraza directives (${label}) ──`)
      for (const line of body.split('\n')) lines.push(`      ${line.replace(/[`\r]/g, '')}`)
    }
  }

  lines.push('    `')
  lines.push('  }')
  return lines.join('\n')
}

// Idea #56 — per-path WAF bypass. Rendered as a matcher on the coraza_waf
// directive itself, so an exempt path never enters inspection at all rather
// than being inspected and then allowed. Only emitted when at least one
// bypass path exists, which keeps the default output byte-identical.
function corazaMatcherLines(access = extendedSettings('access')) {
  const paths = access && Array.isArray(access.waf_bypass_paths) ? access.waf_bypass_paths : []
  const safe = paths.filter(p => typeof p === 'string' && p.startsWith('/') && !/[\s`"'{}\\]/.test(p))
  if (!safe.length) return { matcher: null, lines: [] }
  return {
    matcher: '@catwaf_waf_scope',
    lines: [
      '  # Paths listed here are exempt from WAF inspection (false-positives.md).',
      `  @catwaf_waf_scope not path ${safe.map(p => `"${p}"`).join(' ')}`,
    ],
  }
}

// `opts.backend` overrides the address the site extensions route CatWAF's own
// hops to (the challenge endpoints and the `forward_auth` enforcement hop).
// Passing `null` renders a block with no hop back into CatWAF at all, which is
// what a throwaway sandbox needs: services/simulate.js stands up a private
// Caddy that has no CatWAF API to call, and a hop to an unreachable address
// makes every request 502 before it can reach the sandbox's sink.
// `opts.recordReport === false` keeps such a render out of lastRenderReport(),
// so a simulation cannot overwrite the live configuration's diagnostics.
function buildWAFBlock(waf, opts = {}) {
  const lines = []
  lines.push(WAF_MARKER_START)
  lines.push('# CatWAF WAF Rules — auto-generated, do not edit manually')
  lines.push('')

  const scope = corazaMatcherLines()
  if (scope.matcher) lines.push(...scope.lines, '')

  const snippet = buildCorazaSnippet(waf)
  lines.push(scope.matcher ? snippet.replace('  coraza_waf {', `  coraza_waf ${scope.matcher} {`) : snippet)

  // Everything the extended settings groups contribute to this site block.
  // Rendering failures never throw: a group that cannot be expressed is
  // recorded in lastRenderReport() and simply not emitted, because an
  // invalid directive would fail `caddy validate` for the whole file.
  const extended = renderSiteExtensions(waf, opts)
  if (extended.length) lines.push('', ...extended)

  lines.push('')
  lines.push(WAF_MARKER_END)
  return lines.join('\n')
}

// The most recent render's diagnostics, surfaced by the API so the dashboard
// can explain why a setting that is switched on is not in effect.
let LAST_RENDER = { skipped: [], notes: [], at: null }

function lastRenderReport() { return LAST_RENDER }

function renderSiteExtensions(waf, opts = {}) {
  const record = opts.recordReport !== false
  try {
    const siteRender = require('./render/site')
    const context = currentSiteContext()
    if (Object.hasOwn(opts, 'backend')) context.backend = opts.backend
    const result = siteRender.build({ waf, ...context })
    if (record) {
      LAST_RENDER = {
        skipped: result.skipped,
        notes: result.notes,
        at: new Date().toISOString(),
      }
    }
    return result.lines.map(l => (l === '' ? '' : `  ${l}`))
  } catch (e) {
    if (record) LAST_RENDER = { skipped: [{ feature: 'render', reason: e.message }], notes: [], at: new Date().toISOString() }
    return []
  }
}

// What the renderer needs to know about the block it is being inserted into:
// whether TLS directives make sense there, and which upstreams proxy tuning
// should attach to.
// Set by renderCaddyfile() so a preview reasons about the text being
// rendered rather than whatever is currently on disk.
let RENDER_SOURCE = null

function currentSiteContext() {
  let content = RENDER_SOURCE
  if (content === null) {
    try { content = readCaddyfile() } catch { return { tlsCapable: false, upstreams: [], backend: catwafBackendAddress() } }
  }
  const target = enclosingSiteBlock(content)
  return {
    tlsCapable: target ? target.addresses.some(a => /^https:\/\//.test(a) || /^[A-Za-z0-9*][A-Za-z0-9.*-]*\.[A-Za-z]{2,}(:\d+)?$/.test(a)) : false,
    upstreams: target ? upstreamsIn(target.body) : [],
    backend: catwafBackendAddress(),
  }
}

function catwafBackendAddress() {
  const host = process.env.CATWAF_INTERNAL_HOST || process.env.HOST || '127.0.0.1'
  const port = Number(process.env.PORT || 8000)
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null
  return `${host === '0.0.0.0' ? '127.0.0.1' : host}:${port}`
}

// Every top-level block in the file, with its address list and body. Used to
// find the block CatWAF patches and to reason about what can be rendered
// into it.
function topLevelBlocks(content) {
  const global = globalOptionsRange(content)
  const blocks = []
  let depth = 0
  let openIdx = -1
  for (let i = 0; i < content.length; i++) {
    const ch = content[i]
    if (ch === '#') { while (i < content.length && content[i] !== '\n') i++; continue }
    if (ch === '{') {
      if (depth === 0) openIdx = i
      depth++
    } else if (ch === '}') {
      depth--
      if (depth === 0 && openIdx !== -1) {
        if (!global || openIdx !== global.start) {
          const headStart = content.lastIndexOf('\n', openIdx) + 1
          const head = content.slice(headStart, openIdx).trim()
          blocks.push({
            addresses: head.split(',').map(s => s.trim()).filter(Boolean),
            start: openIdx,
            end: i,
            body: content.slice(openIdx + 1, i),
          })
        }
        openIdx = -1
      }
      if (depth < 0) depth = 0
    }
  }
  return blocks
}

function enclosingSiteBlock(content) {
  const closeIdx = lastSiteBlockClose(content)
  if (closeIdx === -1) return null
  return topLevelBlocks(content).find(b => b.end === closeIdx) || null
}

// Pulls the upstream addresses out of a `reverse_proxy` line so proxy tuning
// (#26-#31, #60) can be attached to the same backends the operator already
// pointed the site at, without CatWAF having to be told them twice.
function upstreamsIn(body) {
  const out = []
  for (const line of String(body || '').split('\n')) {
    const m = /^\s*reverse_proxy\s+([^{#]+)/.exec(line)
    if (!m) continue
    for (const token of m[1].trim().split(/\s+/)) {
      if (!token || token.startsWith('@') || token.includes('=')) continue
      if (/^(?:(?:https?|h2c):\/\/)?(?:[A-Za-z0-9][A-Za-z0-9_.-]*|\[[0-9A-Fa-f:]+\])(?::\d{1,5})?$/.test(token)) out.push(token)
    }
  }
  return [...new Set(out)]
}


const ORDER_DIRECTIVE = 'order coraza_waf first'

function globalOptionsRange(content) {
  const m = content.match(/^(?:[ \t]*(?:#[^\n]*)?\n)*[ \t]*\{/)
  if (!m) return null
  const start = m[0].lastIndexOf('{') + m.index
  let depth = 0
  for (let i = start; i < content.length; i++) {
    const ch = content[i]
    if (ch === '{') depth++
    else if (ch === '}') {
      depth--
      if (depth === 0) return { start, end: i }
    }
  }
  return null
}

function lastSiteBlockClose(content) {
  const global = globalOptionsRange(content)
  let idx = content.lastIndexOf('}')
  while (idx !== -1) {
    if (!global || idx > global.end) return idx
    idx = content.lastIndexOf('}', idx - 1)
  }
  return -1
}

function ensureGlobalOrderDirective(content) {
  const globalBlockMatch = content.match(/^(?:[ \t]*(?:#[^\n]*)?\n)*[ \t]*\{([\s\S]*?)\n\}/)
  if (globalBlockMatch) {
    if (globalBlockMatch[1].includes('order coraza_waf')) return content
    const insertAt = globalBlockMatch.index + globalBlockMatch[0].length - 2
    return content.slice(0, insertAt) + `\n    ${ORDER_DIRECTIVE}` + content.slice(insertAt)
  }
  return `{\n    ${ORDER_DIRECTIVE}\n}\n\n${content}`
}

function replaceRegion(content, startMarker, endMarker, replacement) {
  const startIdx = content.indexOf(startMarker)
  const endIdx = content.indexOf(endMarker)
  if (startIdx === -1 || endIdx === -1 || endIdx < startIdx) return null
  return content.slice(0, startIdx) + replacement + content.slice(endIdx + endMarker.length)
}

// The managed global-options region. Rewritten wholesale on every apply, so
// turning a setting off removes its directive instead of leaving it behind.
function patchGlobalRegion(content) {
  let report = { lines: [], skipped: [], notes: [] }
  try { report = require('./render/global').build() } catch (e) {
    report = { lines: [], skipped: [{ feature: 'global', reason: e.message }], notes: [] }
  }
  mergeRenderReport(report)

  const hasRegion = content.includes(GLOBAL_MARKER_START) && content.includes(GLOBAL_MARKER_END)
  if (!report.lines.length && !hasRegion) return content

  const body = [GLOBAL_MARKER_START, ...report.lines.map(l => (l === '' ? '' : `    ${l}`)), `    ${GLOBAL_MARKER_END}`]
  const region = body.join('\n')

  if (hasRegion) return replaceRegion(content, GLOBAL_MARKER_START, GLOBAL_MARKER_END, region) ?? content

  const global = globalOptionsRange(content)
  if (!global) return content
  const insertAt = global.end
  return content.slice(0, insertAt) + `    ${region}\n` + content.slice(insertAt)
}

// The reject-unknown-Host catch-all (#55), as its own top-level block.
function patchCatchAllRegion(content) {
  let report = { lines: [], skipped: [], notes: [] }
  try { report = require('./render/global').buildCatchAll() } catch (e) {
    report = { lines: [], skipped: [{ feature: 'reject_unknown_host', reason: e.message }], notes: [] }
  }
  mergeRenderReport(report)

  const hasRegion = content.includes(CATCHALL_MARKER_START) && content.includes(CATCHALL_MARKER_END)
  if (!report.lines.length && !hasRegion) return content

  const region = [CATCHALL_MARKER_START, ...report.lines, CATCHALL_MARKER_END].join('\n')
  if (hasRegion) return replaceRegion(content, CATCHALL_MARKER_START, CATCHALL_MARKER_END, region) ?? content

  const global = globalOptionsRange(content)
  const insertAt = global ? global.end + 1 : 0
  return content.slice(0, insertAt) + `\n\n${region}\n` + content.slice(insertAt)
}

function mergeRenderReport(report) {
  LAST_RENDER = {
    skipped: [...(LAST_RENDER.skipped || []), ...(report.skipped || [])],
    notes: [...(LAST_RENDER.notes || []), ...(report.notes || [])],
    at: new Date().toISOString(),
  }
}

// Render into a fresh immutable asset generation. Preview callers wrap this
// in withoutAssetWrites(), which returns virtual paths without writing.
function renderCaddyfile(content, waf) {
  return require('./render/util').withAssetGeneration(() => renderCaddyfileGeneration(content, waf))
}

function renderCaddyfileGeneration(content, waf) {
  LAST_RENDER = { skipped: [], notes: [], at: new Date().toISOString() }
  RENDER_SOURCE = content
  let newBlock
  try { newBlock = buildWAFBlock(waf) } finally { RENDER_SOURCE = null }

  let out
  if (content.includes(WAF_MARKER_START) && content.includes(WAF_MARKER_END)) {
    out = replaceRegion(content, WAF_MARKER_START, WAF_MARKER_END, newBlock)
  } else {
    const insertAt = lastSiteBlockClose(content)
    if (insertAt === -1) {
      throw new Error(
        'This Caddyfile has no site block for CatWAF to protect. ' +
        'Add a site block (for example `:80 { reverse_proxy 127.0.0.1:8082 }`) pointing at the application you want to protect, then apply again.'
      )
    }
    out = content.slice(0, insertAt) + '\n' + newBlock + '\n' + content.slice(insertAt)
  }

  out = ensureGlobalOrderDirective(out)
  out = patchGlobalRegion(out)
  out = require('./managedRoutes').patch(out, waf)
  out = patchCatchAllRegion(out)
  return out
}

function patchWAFCaddyfile(waf) {
  // Serialized against every other Caddyfile writer (CLI, jobs, audit-log
  // rotation, cloudflare origin-lock) and written atomically — see
  // configLock.js for why both halves matter.
  return configLock.withConfigLock(() => {
  const content = renderCaddyfile(readCaddyfile(), waf)

  try {
    configLock.atomicWriteFileSync(CADDYFILE_PATH, content, { mode: 0o640 })
  } catch (e) {
    if (e.code === 'EACCES' || e.code === 'EPERM') {
      throw new Error(
        `Cannot write the Caddyfile at ${CADDYFILE_PATH} (permission denied). ` +
        `CatWAF found this file ${CADDYFILE_SOURCE === 'CADDYFILE_PATH' ? 'via CADDYFILE_PATH' : 'by auto-detection'}, ` +
        `but is not running as a user that can modify it. Either run CatWAF as a user with write access ` +
        `to it, or point CADDYFILE_PATH at a Caddyfile you can write and have Caddy load that one.`
      )
    }
    throw e
  }
  })
}


function applyToCaddy(label, req) {
  const tx = require('./configTx').apply({ label, req, mutate: () => {} })
  return { ...tx, reloaded: !!tx.reloaded, error: tx.ok ? tx.reloadError : tx.error }
}

function readCaddyfile() {
  try { return fs.readFileSync(CADDYFILE_PATH, 'utf8') }
  catch (e) { throw new Error(`Cannot read Caddyfile at ${CADDYFILE_PATH}: ${e.message}`) }
}

function firstLine(msg) {
  return String(msg || '').split('\n').find(l => l.trim()) || String(msg || '').trim()
}

// host:port for `caddy reload --address`, derived from CADDY_ADMIN_URL.
function adminApiAddress() {
  if (CADDY_ADMIN_SOCKET) return `unix/${CADDY_ADMIN_SOCKET}`
  try {
    const u = new URL(CADDY_ADMIN_URL)
    return u.port ? `${u.hostname}:${u.port}` : u.hostname
  } catch { return null }
}

function reloadCaddy() {
  const attempts = []

  try {
    // --address is REQUIRED: without it `caddy reload` always talks to the
    // default admin endpoint 127.0.0.1:2019, regardless of CADDY_ADMIN_URL.
    // That means a CatWAF instance (or a test) configured against a different
    // admin endpoint would hijack whatever Caddy happens to own :2019 and
    // overwrite its live configuration — silently dropping protection.
    const args = ['reload', '--config', CADDYFILE_PATH]
    const adminAddress = adminApiAddress()
    if (adminAddress) args.push('--address', adminAddress)
    execFileSync('caddy', args, { timeout: 10000, stdio: ['ignore', 'pipe', 'pipe'] })
    return { reloaded: true, error: null, method: 'caddy-binary' }
  } catch (e) {
    attempts.push(`local caddy binary: ${firstLine(e.stderr?.toString() || e.message)}`)
  }

  try {
    adminApiRequest('POST', '/load', readCaddyfile(), 'text/caddyfile')
    return { reloaded: true, error: null, method: 'admin-api' }
  } catch (e) {
    attempts.push(`admin api ${CADDY_ADMIN_URL}: ${firstLine(e.stderr?.toString() || e.stdout?.toString() || e.message)}`)
  }

  return { reloaded: false, error: attempts.join(' | '), method: null }
}

// `pgrep` lives in procps, which a minimal Debian or Ubuntu install — and
// every Docker base image — does not ship. Relying on it alone meant that on
// exactly those hosts `catwaf health`, `doctor` and `status` all announced
// "Caddy: not running" while Caddy was serving traffic. /proc is always
// there on Linux; pgrep stays as the path for everything else.
function caddyPidsFromProc() {
  const pids = []
  let entries = []
  try { entries = fs.readdirSync('/proc') } catch { return pids }
  for (const entry of entries) {
    if (!/^\d+$/.test(entry)) continue
    try {
      if (fs.readFileSync(`/proc/${entry}/comm`, 'utf8').trim() === 'caddy') pids.push(Number(entry))
    } catch {}
  }
  return pids
}

function isCaddyRunning() {
  try { adminApiRequest('GET', '/config/', '', 'application/json', 3000); return true } catch {}
  try { execFileSync('pgrep', ['-x', 'caddy'], { timeout: 3000 }); return true } catch {}
  return caddyPidsFromProc().length > 0
}

function isAdminReachable() {
  try { adminApiRequest('GET', '/config/', '', 'application/json', 3000); return true } catch { return false }
}

function getCaddyModules() {
  try { return execFileSync('caddy', ['list-modules'], { timeout: 5000 }).toString() } catch {}
  return ''
}

function getCaddyPid() {
  try {
    const out = execFileSync('pgrep', ['-x', 'caddy'], { timeout: 3000 }).toString().trim()
    const pid = parseInt(out.split('\n')[0], 10)
    if (Number.isFinite(pid)) return pid
  } catch {}
  return caddyPidsFromProc()[0] ?? null
}

// ─── Redaction ──────────────────────────────────────────────────────────
//
// The generated Caddyfile is not secret-free. render/site.js writes the
// derived X-CatWAF-Enforce-Key (the only credential guarding the pre-auth
// /api/enforce endpoint), the ACME dns-01 provider API token and the
// basic-auth password hash into it as plaintext literals. Every other read
// path for configuration goes through settings redact(), which blanks those
// same fields because they are declared writeOnly — so anything that hands
// the raw file text to a client has to blank them too.
const REDACTED = '«redacted»'

// Header names whose value is a credential rather than a routing hint.
const SECRET_HEADER_RE = /(key|token|secret|password|authorization|credential)/i

function redactCaddyfile(text) {
  if (typeof text !== 'string' || !text) return ''
  return text.split('\n').map(line => {
    // header_up / header_down carrying a shared secret, e.g. the enforce key.
    // The name may be preceded by a matcher token (`header_up @m X-Api-Key v`),
    // so the credential header is matched anywhere among the middle tokens.
    let m = line.match(/^(\s*header_(?:up|down)\s+)((?:@\S+\s+)?)(\S+)(\s+)(.+)$/)
    if (m && SECRET_HEADER_RE.test(m[3])) return `${m[1]}${m[2]}${m[3]}${m[4]}"${REDACTED}"`

    // ACME dns-01: `dns <provider> "<api token>"` and the block form
    // `dns <provider> { ... api_token "..." }`. Both carry credentials —
    // the block's inner token lines are caught by the generic key/token
    // rule below.
    m = line.match(/^(\s*dns\s+)(\S+)(\s+)(.+)$/)
    if (m && m[4].trim() !== '{') return `${m[1]}${m[2]}${m[3]}"${REDACTED}"`

    // basic_auth credential line: `"user" "$2a$12$..."` (bcrypt), plus
    // scrypt/argon-style hashes (`$scrypt$…`, `$argon2…`). The username is
    // kept — it is already shown in the settings UI — and only the hash is
    // blanked.
    m = line.match(/^(\s*"?[^"\s]+"?\s+)"?(\$(?:2[aby]|scrypt|argon2(?:id|d|i)?)\$)[^"\s]*"?\s*$/)
    if (m) return `${m[1]}"${REDACTED}"`

    // Catch-all for hash literals or quoted api_token/client_secret values
    // appearing anywhere else on a line (comments included).
    return line
      .replace(/\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}/g, REDACTED)
      .replace(/\$(?:scrypt|argon2(?:id|d|i)?)\$[^\s"']{8,}/g, REDACTED)
      .replace(/\b(api_token|client_secret|api_key|secret)\s+"[^"]+"/gi,
        (_, k) => `${k} "${REDACTED}"`)
  }).join('\n')
}

let reloadQueueTimer = null
let reloadQueuePending = false
function queueCaddyReload() {
  reloadQueuePending = true
  if (reloadQueueTimer) return
  reloadQueueTimer = setTimeout(() => {
    reloadQueueTimer = null
    if (!reloadQueuePending) return
    reloadQueuePending = false
    const result = reloadCaddy()
    if (!result.reloaded) console.error('[CatWAF] Queued reload failed:', result.error)
  }, 800)
}

module.exports = {
  CADDYFILE_PATH, CADDYFILE_SOURCE, CORAZA_LIST_DIR, CADDY_ADMIN_URL, CADDY_ADMIN_SOCKET, AUDIT_LOG_PATH,
  DEFAULT_AUDIT_LOG, ensureAuditLog, auditLogStatus, auditLogCandidates,
  baseAuditLogPath, rotatedActivePath, resolveAuditLogPath,
  WAF_MARKER_START, WAF_MARKER_END,
  GLOBAL_MARKER_START, GLOBAL_MARKER_END, CATCHALL_MARKER_START, CATCHALL_MARKER_END,
  detectCaddyfilePath, candidatePaths, scoreCaddyfilePath: scorePath,
  lastSiteBlockClose, globalOptionsRange, ensureGlobalOrderDirective,
  topLevelBlocks, enclosingSiteBlock, upstreamsIn, currentSiteContext, catwafBackendAddress,
  renderCaddyfile, lastRenderReport, denyAction, corazaMatcherLines,
  buildWAFBlock, buildCorazaSnippet, patchWAFCaddyfile, readCaddyfile, reloadCaddy,
  isCaddyRunning, isAdminReachable, getCaddyModules, getCaddyPid,
  applyToCaddy, queueCaddyReload, redactCaddyfile,
  isReloadPending: () => reloadQueuePending,
}
