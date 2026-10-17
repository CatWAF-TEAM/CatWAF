// proxy/apply.js — generate -> validate -> back up -> apply atomically ->
// reload, with an automatic rollback path, for the auto-discovered routes
// region of the Caddyfile.
//
// Safety properties (see docs/reverse-proxy.md and provision.js for the
// established pattern this follows):
//   1. The merged configuration is validated with the real `caddy validate`
//      binary in a temp file BEFORE the live Caddyfile is ever touched.
//   2. If validation fails, the live Caddyfile is untouched — there is
//      nothing to roll back because nothing was written.
//   3. On success, a timestamped backup is still taken (via configTx, the
//      same backup store `catwaf config restore` reads from) before the
//      atomic rename, so there is always a manual rollback path.
//   4. The temp-file-then-rename swap is atomic on the same filesystem.

const fs = require('fs')

const caddySvc = require('../caddy')
const configTx = require('../configTx')
const configLock = require('../configLock')
const generator = require('./generator')

function mergeIntoCaddyfile(content, generatedRegion) {
  const { AUTO_MARKER_START, AUTO_MARKER_END } = generator
  if (content.includes(AUTO_MARKER_START) && content.includes(AUTO_MARKER_END)) {
    const start = content.indexOf(AUTO_MARKER_START)
    const end = content.indexOf(AUTO_MARKER_END)
    return content.slice(0, start) + generatedRegion + content.slice(end + AUTO_MARKER_END.length)
  }
  const sep = content.length === 0 ? '' : (content.endsWith('\n') ? '\n' : '\n\n')
  return content + sep + generatedRegion + '\n'
}

// Re-render CatWAF's OTHER managed region — the `@@CATWAF_WAF_START@@` block
// that `catwaf setup` and the dashboard write.
//
// Caddy provisions EVERY block in the file, so a stale directive anywhere
// fails the whole validation. A Caddyfile written before the audit-log path
// was resolved still carries `SecAuditLog /var/log/coraza/audit.json`, and
// that alone made `catwaf auto` fail with
//   "invalid WAF config from audit log: open /var/log/coraza/audit.json"
// even though the freshly generated auto routes were perfectly correct.
//
// This region is explicitly CatWAF-managed ("auto-generated, do not edit
// manually"), so regenerating it from current settings is safe — and it is
// still validated in a temp file before anything is replaced. User-authored
// configuration outside the markers is never touched.
function refreshManagedWafBlock(content, waf) {
  const START = caddySvc.WAF_MARKER_START
  const END = caddySvc.WAF_MARKER_END
  const start = content.indexOf(START)
  const end = content.indexOf(END)
  if (start === -1 || end === -1 || end < start) return content
  return content.slice(0, start) + caddySvc.buildWAFBlock(waf) + content.slice(end + END.length)
}

function apply(options) {
  // Whole read→merge→validate→rename cycle serialized against every other
  // Caddyfile writer (the lock is re-entrant with configTx's own).
  return configLock.withConfigLock(() => applyLocked(options))
}

function applyLocked({ routes, waf, dryRun = false } = {}) {
  // Coraza opens the audit log at provision time, so it must exist BEFORE
  // `caddy validate` runs or validation fails on a clean install. Do this
  // first, since it can also change the path the generated config refers to.
  let auditLog = null
  if (!dryRun) {
    auditLog = caddySvc.ensureAuditLog()
    if (!auditLog.ok) {
      return {
        ok: false,
        error: 'CatWAF could not prepare the WAF audit log.',
        message: `${auditLog.error}\nSet CORAZA_AUDIT_LOG to a path CatWAF can write, or run it as a user that can create the default location.`,
        routes,
      }
    }
  } else {
    // --dry-run must not create anything, but it must still predict a real
    // run — otherwise it would report success for a config that cannot apply.
    const status = caddySvc.auditLogStatus()
    if (!status.ok) {
      return {
        ok: false,
        error: 'CatWAF could not prepare the WAF audit log.',
        message: `No writable audit log location. Tried: ${(status.attempted || []).join('; ')}.\nSet CORAZA_AUDIT_LOG to a path CatWAF can write.`,
        routes,
      }
    }
    auditLog = status
  }

  const generated = generator.buildAutoRegion(routes, waf)
  if (!generated) {
    return { ok: true, noop: true, message: 'No web applications discovered — nothing to protect.' }
  }

  let previous
  let hadFile = true
  try {
    previous = caddySvc.readCaddyfile()
  } catch {
    previous = ''
    hadFile = false
  }

  // Refresh CatWAF's legacy managed block too, so a stale audit-log path
  // written before this run cannot fail validation for the whole file.
  const withFreshWafBlock = refreshManagedWafBlock(previous, waf)
  const merged = caddySvc.ensureGlobalOrderDirective(mergeIntoCaddyfile(withFreshWafBlock, generated))

  if (dryRun) {
    return { ok: true, dryRun: true, config: generated, merged, routes, auditLog }
  }

  const tx = configTx.apply({ label: 'apps.protect', caddyfile: merged, render: false, mutate: () => {} })
  if (!tx.ok && tx.phase === 'caddy-validate') tx.error = 'Configuration validation failed: ' + tx.error
  return { ...tx, auditLog, routes, config: generated }
}

module.exports = { apply, mergeIntoCaddyfile, refreshManagedWafBlock }
