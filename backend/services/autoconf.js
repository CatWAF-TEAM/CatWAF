// autoconf.js — Docker-label-driven configuration (idea #66).
//
// services/discovery/ already does the hard part: it inspects running
// containers thoroughly and works out what each one is. What it does not do
// is *act* — every run produces a suggestion for a human to confirm. That is
// the right default, and this does not change it: containers without the
// label prefix keep the existing suggest-only behaviour.
//
// What this adds is an opt-in mode where a container that explicitly asks to
// be managed (`catwaf.enable=true`) has its configuration applied
// automatically on a schedule. Auto-applying configuration has a real blast
// radius, so it is off by default, it only ever touches labelled containers,
// and it has a dry-run mode that reports what it would do without doing it.

const settings = require('./settings')
const logger = require('./logger')

const log = logger.child('autoconf')
let inFlight = false

// Labels are attacker-influenceable if someone can start a container, so
// every value goes through a parser that constrains it to its type rather
// than being trusted because it came from Docker.
const LABEL_SPEC = {
  enable: { type: 'bool' },
  port: { type: 'int', min: 1, max: 65535 },
  host: { type: 'host' },
  network: { type: 'network' },
  tls: { type: 'enum', values: ['off', 'auto'] },
  path: { type: 'uri' },
  protocol: { type: 'enum', values: ['http', 'https', 'grpc'] },
  paranoia: { type: 'int', min: 1, max: 4 },
  waf: { type: 'enum', values: ['on', 'detectiononly', 'off'] },
  bypass: { type: 'list', item: 'uri' },
  methods: { type: 'list', item: 'method' },
  headers: { type: 'enum', values: ['off', 'basic', 'strict'] },
  websockets: { type: 'enum', values: ['allow', 'deny'] },
}

function parseLabelValue(spec, raw) {
  const value = String(raw ?? '').trim()
  switch (spec.type) {
    case 'bool':
      if (/^(true|1|yes|on)$/i.test(value)) return true
      if (/^(false|0|no|off)$/i.test(value)) return false
      return null
    case 'int': {
      const n = Number(value)
      if (!Number.isInteger(n) || n < spec.min || n > spec.max) return null
      return n
    }
    case 'enum':
      return spec.values.includes(value.toLowerCase()) ? value.toLowerCase() : null
    case 'host':
      return require('./managedRoutes').hostname(value.toLowerCase()) ? value.toLowerCase() : null
    case 'network':
      return /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(value) ? value : null
    case 'uri':
      return value.startsWith('/') && value.length <= 512 && !/[\s`"'{}\\\x00-\x1f\x7f]/.test(value) ? value : null
    case 'list': {
      const items = value.split(/[\s,]+/).filter(Boolean)
      const parsed = items.map(item => parseLabelValue({ type: spec.item === 'method' ? 'enum' : 'uri', values: ['get', 'post', 'put', 'patch', 'delete', 'head', 'options'] }, item))
      return parsed.every(Boolean) ? parsed : null
    }
    default:
      return null
  }
}

function readLabels(container, prefix) {
  const labels = container?.labels || container?.Labels || {}
  const out = {}
  const rejected = []
  for (const [key, raw] of Object.entries(labels)) {
    if (!key.startsWith(`${prefix}.`)) continue
    const name = key.slice(prefix.length + 1)
    const spec = LABEL_SPEC[name]
    if (!spec) { rejected.push({ label: key, reason: 'unknown label' }); continue }
    const value = parseLabelValue(spec, raw)
    if (value === null) { rejected.push({ label: key, reason: `"${raw}" is not a valid value for ${name}` }); continue }
    out[name] = value
  }
  return { labels: out, rejected }
}

// Turns parsed labels into the settings patches they imply. Returns patches
// rather than applying them, so the same function backs both dry-run and the
// real thing.
function planFor(labelled) {
  const patches = {}
  const waf = {}

  if (labelled.paranoia) {
    waf.paranoia_level = labelled.paranoia
    waf.executing_paranoia_level = Math.max(labelled.paranoia, 2)
  }
  if (labelled.waf) {
    waf.engine = labelled.waf === 'on' ? 'On' : labelled.waf === 'detectiononly' ? 'DetectionOnly' : 'Off'
  }
  if (labelled.methods) {
    patches.access = { ...(patches.access || {}), enforce_method_allowlist: true, allowed_methods: labelled.methods.map(m => m.toUpperCase()) }
  }
  if (labelled.bypass) {
    patches.access = { ...(patches.access || {}), waf_bypass_paths: labelled.bypass }
  }
  if (labelled.headers) {
    patches.headers = { preset: labelled.headers }
  }
  if (labelled.protocol) {
    patches.proxy = { ...(patches.proxy || {}), protocol: labelled.protocol }
    if (labelled.protocol === 'https') patches.proxy.upstream_tls_verify = true
  }
  if (labelled.websockets) {
    patches.proxy = { ...(patches.proxy || {}), websockets: labelled.websockets }
  }
  if (labelled.host) {
    patches.sites = { primary_host: labelled.host }
  }

  return { patches, waf }
}

async function scan({ dryRun = null, containers = null } = {}) {
  const cfg = settings.get('autoconf')
  if (!cfg.enabled) return { ok: true, skipped: 'disabled', changed: false }
  if (inFlight) return { ok: false, error: 'Docker reconciliation is already running', changed: false }
  inFlight = true
  try {
    const inventory = containers || await require('./dockerSource').list()
    const routes = [], ignored = [], problems = []
    for (const container of inventory) {
      const { labels, rejected } = readLabels(container, cfg.label_prefix)
      if (!container.running || labels.enable === false || (cfg.require_enable_label && labels.enable !== true) || !Object.keys(labels).length) {
        ignored.push(container.name); continue
      }
      if (rejected.length) { problems.push(...rejected.map(r => ({ container: container.name, ...r }))); continue }
      if (!labels.host || !labels.port) { problems.push({ container: container.name, reason: 'Both host and port labels are required' }); continue }
      const networks = container.networks || {}
      const network = labels.network || cfg.network || (Object.keys(networks).length === 1 ? Object.keys(networks)[0] : '')
      const address = networks[network]?.IPAddress || networks[network]?.GlobalIPv6Address
      const family = require('net').isIP(address || '')
      if (!family) { problems.push({ container: container.name, reason: 'Choose a network shared with the CatWAF proxy' }); continue }
      const upstream = (labels.protocol === 'https' ? 'https://' : labels.protocol === 'grpc' ? 'h2c://' : '') + (family === 6 ? '[' + address + ']' : address) + ':' + labels.port
      const plan = planFor(labels)
      delete plan.patches.sites
      routes.push({ id: container.id, host: labels.host, path: labels.path || '/', pathType: 'Prefix', upstream, tls: labels.tls || 'off', policy: plan })
    }
    if (problems.length) return { ok: false, changed: false, error: 'Invalid container labels; previous routes retained.', problems, ignored }
    if (JSON.stringify(cfg) !== JSON.stringify(settings.get('autoconf'))) throw new Error('Docker settings changed during discovery; retry with the current settings')
    const result = require('./managedRoutes').reconcile('docker', routes, { dryRun: dryRun === null ? cfg.dry_run : dryRun, removeOrphans: cfg.remove_orphans })
    return { ...result, managed: routes.length, ignored, problems }
  } catch (e) { return { ok: false, changed: false, error: e.message } }
  finally { inFlight = false }
}
function describe() {
  const cfg = settings.get('autoconf')
  return {
    enabled: cfg.enabled,
    prefix: cfg.label_prefix,
    dry_run: cfg.dry_run,
    routes: require('./managedRoutes').read().docker?.routes || [],
    labels: Object.entries(LABEL_SPEC).map(([name, spec]) => ({
      label: `${cfg.label_prefix}.${name}`,
      type: spec.type,
      values: spec.values || null,
      range: spec.min !== undefined ? `${spec.min}-${spec.max}` : null,
    })),
    example: [
      'services:',
      '  app:',
      '    image: my-app',
      '    labels:',
      `      ${cfg.label_prefix}.enable: "true"`,
      `      ${cfg.label_prefix}.port: "3000"`,
      `      ${cfg.label_prefix}.host: "app.example.com"`,
      `      ${cfg.label_prefix}.network: "catwaf"`,
      `      ${cfg.label_prefix}.paranoia: "2"`,
      `      ${cfg.label_prefix}.headers: "strict"`,
      `      ${cfg.label_prefix}.bypass: "/webhooks/*"`,
    ].join('\n'),
  }
}

module.exports = { scan, describe, readLabels, planFor, parseLabelValue, LABEL_SPEC }
