// templates.js — named bundles of settings that can be applied in one step
// (idea #64).
//
// CatWAF already had this idea in miniature: modes.js applies a named bundle
// (normal / lockdown / learning / maintenance), but only over WAF strictness.
// This is the same mechanism widened — a bundle can now carry any settings
// group as well as WAF fields — so protecting a second similar site, or
// rebuilding after a restore, does not mean re-entering the same twenty
// choices by hand.
//
// Application goes through configTx, so a template is validated and rolled
// back exactly like any other configuration change.

const crypto = require('crypto')

const db = require('./db')
const state = require('./state')
const settings = require('./settings')
const configTx = require('./configTx')
const snapshots = require('./snapshots')

const STORE_KEY = 'settings_templates'
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/

// WAF fields a template may carry. Deliberately a list rather than "all of
// state.WAF": the IP lists, custom rules and alert destinations are per-site
// operational data, not configuration you would want copied by a template.
const WAF_FIELDS = [
  'engine', 'paranoia_level', 'executing_paranoia_level',
  'inbound_anomaly_threshold', 'outbound_anomaly_threshold',
  'allowed_methods', 'allowed_content_types', 'max_request_body_size',
  'request_body_inspection', 'response_body_inspection', 'audit_log',
  'early_blocking', 'sampling_percentage', 'blocked_user_agents',
  'rate_limit', 'php_exclusions', 'retention_days',
]

const BUILT_IN = {
  'hardened-public-site': {
    label: 'Hardened public site',
    description: 'Strict security headers, HSTS, compression, a method allowlist, unknown-Host rejection and behavioural banning. A sensible target state for a normal public website.',
    waf: { engine: 'On', paranoia_level: 2, executing_paranoia_level: 3, inbound_anomaly_threshold: 5 },
    settings: {
      headers: { preset: 'strict', hsts_max_age: 31536000, hsts_include_subdomains: true },
      access: { reject_unknown_host: true, enforce_method_allowlist: true, allowed_methods: ['GET', 'POST', 'HEAD', 'OPTIONS'] },
      compression: { enabled: true },
      client_cache: { enabled: true },
      cookies: { enabled: true, secure: 'auto', http_only: true, same_site: 'Lax' },
      bad_behavior: { enabled: true },
      robots: { enabled: true, block_known_bad_bots: true },
      tls: { profile: 'intermediate' },
    },
  },
  'internal-tool': {
    label: 'Internal tool',
    description: 'Locked to client certificates with a basic-auth fallback path, no crawling, no caching. For an admin panel or internal service that should never be reachable by the public.',
    waf: { engine: 'On', paranoia_level: 3, executing_paranoia_level: 4, inbound_anomaly_threshold: 4 },
    settings: {
      mtls: { mode: 'require_and_verify' },
      access: { reject_unknown_host: true, enforce_method_allowlist: true, blocked_status_code: 404 },
      headers: { preset: 'strict', x_frame_options: 'DENY' },
      robots: { enabled: true, mode: 'disallow-all' },
      client_cache: { enabled: false },
      bad_behavior: { enabled: true, threshold: 10, ban_seconds: 7200 },
    },
  },
  'static-site': {
    label: 'Static site',
    description: 'CatWAF serves a folder directly — no origin server needed — with long-lived asset caching and compression.',
    waf: { engine: 'On', paranoia_level: 2, executing_paranoia_level: 2 },
    settings: {
      origin: { type: 'static-folder' },
      compression: { enabled: true },
      client_cache: { enabled: true, etag: true },
      headers: { preset: 'strict' },
      access: { enforce_method_allowlist: true, allowed_methods: ['GET', 'HEAD', 'OPTIONS'] },
    },
  },
  'api-backend': {
    label: 'API backend',
    description: 'CORS managed at the WAF layer, no HTML concerns, greylisting available for webhook clients, and a per-path WAF bypass ready for raw-body endpoints.',
    waf: { engine: 'On', paranoia_level: 1, executing_paranoia_level: 2, allowed_content_types: ['application/json'] },
    settings: {
      cors: { enabled: true, allow_methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'] },
      headers: { preset: 'basic', x_frame_options: 'DENY' },
      compression: { enabled: true },
      greylist: { enabled: true },
      robots: { enabled: true, mode: 'disallow-all' },
      client_cache: { enabled: false },
    },
  },
}

function load() {
  const stored = db.getState(STORE_KEY)
  return stored && typeof stored === 'object' && !Array.isArray(stored) ? stored : {}
}

function persist(all) { db.setState(STORE_KEY, all) }

function slugify(name) {
  return String(name).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 64)
}

function capture({ groups = null, includeWaf = true } = {}) {
  const chosen = groups && groups.length ? groups.filter(g => settings.isGroup(g)) : settings.GROUP_NAMES
  const captured = {}
  for (const group of chosen) {
    // Secrets are never captured: a template is meant to be exported and
    // re-applied, and a bundle carrying an API token would leak it the first
    // time someone shared one.
    captured[group] = snapshots.redactSecrets(settings.get(group))
    for (const [field, spec] of Object.entries(settings.SCHEMA[group].fields)) {
      if (spec.writeOnly) delete captured[group][field]
    }
  }
  const waf = {}
  if (includeWaf) for (const field of WAF_FIELDS) waf[field] = state.WAF[field]
  return { settings: captured, waf }
}

function save(name, { groups = null, includeWaf = true, description = '', req = null } = {}) {
  if (!NAME_RE.test(String(name || ''))) {
    return { ok: false, error: 'A template name may use letters, numbers, spaces and . _ - (max 64 characters).' }
  }
  const id = slugify(name)
  if (!id) return { ok: false, error: 'That name does not produce a usable identifier.' }
  if (Object.hasOwn(BUILT_IN, id)) return { ok: false, error: `"${id}" is a built-in template name — choose another.` }

  const all = load()
  const captured = capture({ groups, includeWaf })
  all[id] = {
    id,
    label: String(name).slice(0, 64),
    description: String(description || '').slice(0, 512),
    created_at: new Date().toISOString(),
    created_by: req?.user?.username || 'cli',
    groups: Object.keys(captured.settings),
    includes_waf: includeWaf,
    ...captured,
  }
  persist(all)
  return { ok: true, template: all[id] }
}

function get(id) {
  if (Object.hasOwn(BUILT_IN, id)) return { id, built_in: true, ...BUILT_IN[id] }
  const all = load()
  if (!Object.hasOwn(all, id)) return null
  // Older releases allowed imported secrets. Redact on read as well so an
  // upgrade cannot expose existing imports through viewer/export endpoints.
  const template = snapshots.redactSecrets(all[id])
  for (const [group, values] of Object.entries(template.settings || {})) {
    if (!settings.isGroup(group)) { delete template.settings[group]; continue }
    for (const [field, spec] of Object.entries(settings.SCHEMA[group].fields)) {
      if (spec.writeOnly) delete values[field]
    }
    if (group === 'cluster' && values.url) values.url = settings.redact(group, values).url
  }
  return template
}

function list() {
  const custom = Object.values(load())
  const builtIn = Object.entries(BUILT_IN).map(([id, t]) => ({
    id, built_in: true, label: t.label, description: t.description,
    groups: Object.keys(t.settings), includes_waf: !!t.waf,
  }))
  return [
    ...builtIn,
    ...custom.map(t => ({ ...t, built_in: false, settings: undefined, waf: undefined })),
  ]
}

function remove(id) {
  if (Object.hasOwn(BUILT_IN, id)) return { ok: false, error: 'Built-in templates cannot be deleted.' }
  const all = load()
  if (!all[id]) return { ok: false, error: 'No such template.' }
  delete all[id]
  persist(all)
  return { ok: true, removed: id }
}

function apply(id, { req = null, reload = true, dryRun = false } = {}) {
  const template = get(id)
  if (!template) return { ok: false, error: `No template named "${id}".` }

  const wouldChange = []
  for (const [group, values] of Object.entries(template.settings || {})) {
    if (!settings.isGroup(group)) continue
    const current = settings.get(group)
    for (const [field, value] of Object.entries(values)) {
      if (JSON.stringify(current[field]) !== JSON.stringify(value)) {
        wouldChange.push({ group, field, from: current[field], to: value })
      }
    }
  }
  for (const [field, value] of Object.entries(template.waf || {})) {
    if (JSON.stringify(state.WAF[field]) !== JSON.stringify(value)) {
      wouldChange.push({ group: 'waf', field, from: state.WAF[field], to: value })
    }
  }

  if (dryRun) return { ok: true, dryRun: true, template: template.id, changes: wouldChange }

  const tx = configTx.apply({
    label: `template.apply.${id}`,
    req,
    reload,
    mutate: (s) => {
      const errors = []
      for (const [group, values] of Object.entries(template.settings || {})) {
        if (!settings.isGroup(group)) continue
        const result = settings.set(group, values)
        if (!result.ok) errors.push(`${group}: ${result.error}`)
      }
      for (const [field, value] of Object.entries(template.waf || {})) {
        if (WAF_FIELDS.includes(field)) s.WAF[field] = value
      }
      if (errors.length) throw new Error(errors.join('; '))
      return { template: id, changed: wouldChange.length }
    },
  })

  if (!tx.ok) return { ok: false, ...tx }
  return { ok: true, template: template.id, label: template.label, changes: wouldChange, reloaded: tx.reloaded, backup: tx.backup }
}

function exportTemplate(id) {
  const template = get(id)
  if (!template) return { ok: false, error: 'No such template.' }
  return {
    ok: true,
    payload: {
      catwaf_template: 1,
      id: template.id,
      label: template.label,
      description: template.description || '',
      settings: template.settings || {},
      waf: template.waf || {},
      exported_at: new Date().toISOString(),
    },
  }
}

function importTemplate(payload, { req = null } = {}) {
  if (!payload || payload.catwaf_template !== 1) return { ok: false, error: 'Not a CatWAF template export.' }
  if (!NAME_RE.test(String(payload.label || payload.id || ''))) return { ok: false, error: 'The template has no usable name.' }

  // An imported bundle is untrusted input, so every group is validated
  // against the schema before it is stored — not when it is applied.
  const cleanSettings = {}
  for (const [group, values] of Object.entries(payload.settings || {})) {
    if (!settings.isGroup(group)) return { ok: false, error: `Unknown settings group "${group}" in the import.` }
    const check = settings.validate(group, values)
    if (!check.ok) return { ok: false, error: `${group}: ${check.error}` }
    // Imports have the same secret-free contract as captured templates.
    cleanSettings[group] = snapshots.redactSecrets(Object.fromEntries(Object.keys(values).map(k => [k, check.value[k]])))
    for (const [field, spec] of Object.entries(settings.SCHEMA[group].fields)) {
      if (spec.writeOnly) delete cleanSettings[group][field]
    }
  }
  const cleanWaf = {}
  for (const [field, value] of Object.entries(payload.waf || {})) {
    if (WAF_FIELDS.includes(field)) cleanWaf[field] = value
  }

  const id = slugify(payload.label || payload.id)
  const all = load()
  all[id] = {
    id,
    label: String(payload.label || id).slice(0, 64),
    description: String(payload.description || '').slice(0, 512),
    created_at: new Date().toISOString(),
    created_by: req?.user?.username || 'import',
    imported: true,
    groups: Object.keys(cleanSettings),
    includes_waf: Object.keys(cleanWaf).length > 0,
    settings: cleanSettings,
    waf: cleanWaf,
  }
  persist(all)
  return { ok: true, template: all[id] }
}

module.exports = {
  save, get, list, remove, apply, capture, slugify,
  exportTemplate, importTemplate, BUILT_IN, WAF_FIELDS, STORE_KEY,
}
