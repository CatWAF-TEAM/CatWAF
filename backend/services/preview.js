// preview.js — see the configuration change before committing it (idea #50).
//
// Run mutate + render without publishing settings or generated files. Diff
// the two configurations, roll back the SQLite savepoint and restore caches.
// Full configuration apply has separate rollback behavior in configTx; it
// is not an atomic commit across SQLite, generated assets and Caddy.

const state = require('./state')
const caddySvc = require('./caddy')
const configTx = require('./configTx')
const settings = require('./settings')
const configLock = require('./configLock')
const db = require('./db')
const { withoutAssetWrites } = require('./render/util')

const MAX_DIFF_LINES = 4000

// Standard Myers-style LCS over lines. Files here are hundreds of lines, so
// the quadratic table is fine and produces a much more readable diff than a
// naive line-by-line comparison would.
function lcsLengths(a, b) {
  const table = Array.from({ length: a.length + 1 }, () => new Uint32Array(b.length + 1))
  for (let i = a.length - 1; i >= 0; i--) {
    for (let j = b.length - 1; j >= 0; j--) {
      table[i][j] = a[i] === b[j] ? table[i + 1][j + 1] + 1 : Math.max(table[i + 1][j], table[i][j + 1])
    }
  }
  return table
}

function diffLines(beforeText, afterText) {
  const a = String(beforeText).split('\n')
  const b = String(afterText).split('\n')

  if (a.length + b.length > MAX_DIFF_LINES * 2) {
    return [{ type: 'note', text: 'The configuration is too large to diff line by line; showing a summary only.' }]
  }

  const table = lcsLengths(a, b)
  const out = []
  let i = 0
  let j = 0
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) { out.push({ type: 'context', text: a[i], before: i + 1, after: j + 1 }); i++; j++ }
    else if (table[i + 1][j] >= table[i][j + 1]) { out.push({ type: 'remove', text: a[i], before: i + 1 }); i++ }
    else { out.push({ type: 'add', text: b[j], after: j + 1 }); j++ }
  }
  while (i < a.length) { out.push({ type: 'remove', text: a[i], before: i + 1 }); i++ }
  while (j < b.length) { out.push({ type: 'add', text: b[j], after: j + 1 }); j++ }
  return out
}

// Drops runs of unchanged lines, keeping a few for orientation — the same
// thing `diff -u` does, and the reason a diff is readable at all.
function toHunks(lines, contextLines = 3) {
  const keep = new Array(lines.length).fill(false)
  for (const [idx, line] of lines.entries()) {
    if (line.type === 'context') continue
    for (let k = Math.max(0, idx - contextLines); k <= Math.min(lines.length - 1, idx + contextLines); k++) keep[k] = true
  }
  const hunks = []
  let current = null
  for (const [idx, line] of lines.entries()) {
    if (!keep[idx]) { current = null; continue }
    if (!current) { current = { start_before: line.before ?? null, start_after: line.after ?? null, lines: [] }; hunks.push(current) }
    current.lines.push(line)
  }
  return hunks
}

function summarize(lines) {
  return {
    added: lines.filter(l => l.type === 'add').length,
    removed: lines.filter(l => l.type === 'remove').length,
    unchanged: lines.filter(l => l.type === 'context').length,
  }
}

// Runs `mutate` against live state, renders, then restores. The restore runs
// in a finally so a throwing mutation cannot leave the process holding
// half-applied settings.
function preview({ mutate, label = 'preview' } = {}) {
  return configLock.withConfigLock(() => withoutAssetWrites(() => {
    // Other processes must never observe temporary preview settings. The
    // savepoint also rolls back writes made by the normal settings setters.
    const conn = db.getDb()
    conn.exec('SAVEPOINT catwaf_preview')
    try { return previewLocked({ mutate, label }) }
    finally {
      conn.exec('ROLLBACK TO catwaf_preview; RELEASE catwaf_preview')
      state.reloadAllFromDb()
      settings.reload()
    }
  }))
}

function previewLocked({ mutate, label }) {
  let beforeText
  try {
    beforeText = caddySvc.readCaddyfile()
  } catch (e) {
    return { ok: false, error: `Cannot read the current configuration: ${e.message}` }
  }

  const snapshot = configTx.snapshotWaf()
  let beforeRendered
  try {
    beforeRendered = caddySvc.renderCaddyfile(beforeText, state.WAF)
  } catch (e) {
    return { ok: false, error: `The current configuration could not be rendered: ${e.message}` }
  }
  const beforeReport = caddySvc.lastRenderReport()

  let afterRendered
  let mutateResult
  let error = null
  try {
    mutateResult = mutate(state)
    afterRendered = caddySvc.renderCaddyfile(beforeText, state.WAF)
  } catch (e) {
    error = e.message
  } finally {
    // Nothing was written to the Caddyfile; this puts the in-memory and
    // stored state back so the preview has no lasting effect.
    configTx.restoreWaf(snapshot)
    settings.reload()
  }

  if (error) return { ok: false, phase: 'mutate', error }

  const afterReport = caddySvc.lastRenderReport()
  const lines = diffLines(beforeRendered, afterRendered)
  const summary = summarize(lines)

  return {
    ok: true,
    label,
    changed: summary.added > 0 || summary.removed > 0,
    summary,
    hunks: toHunks(lines),
    result: mutateResult,
    // What the change would mean operationally, not just textually.
    render_report: {
      before: beforeReport,
      after: afterReport,
      newly_skipped: (afterReport.skipped || []).filter(
        s => !(beforeReport.skipped || []).some(b => b.feature === s.feature && b.reason === s.reason)
      ),
    },
  }
}

// Convenience wrapper for the common case: previewing a settings-group edit.
function previewSettings(group, patch) {
  const check = settings.validate(group, patch)
  if (!check.ok) return { ok: false, phase: 'validate', error: check.error }
  return preview({
    label: `settings.${group}`,
    mutate: () => {
      const result = settings.set(group, patch)
      if (!result.ok) throw new Error(result.error)
      return { group, fields: Object.keys(patch) }
    },
  })
}

function previewWaf(patch) {
  // Same validation a real apply runs — a preview must not render values
  // that could never be saved.
  const check = require('./sanitize').validateWafState(patch || {})
  if (!check.valid) return { ok: false, phase: 'validate', error: check.errors.join('; ') }
  const clean = check.sanitized
  return preview({
    label: 'waf',
    mutate: (s) => {
      for (const [key, value] of Object.entries(clean)) {
        if (Object.hasOwn(s.WAF, key)) s.WAF[key] = value
      }
      return { fields: Object.keys(clean) }
    },
  })
}

// The unified-diff text form, for the CLI and for copy/paste into a ticket.
function toUnifiedText(result) {
  if (!result.ok) return `error: ${result.error}`
  if (!result.changed) return 'No change to the generated configuration.'
  const out = ['--- current Caddyfile', '+++ proposed Caddyfile']
  for (const hunk of result.hunks) {
    out.push(`@@ -${hunk.start_before ?? 0} +${hunk.start_after ?? 0} @@`)
    for (const line of hunk.lines) {
      out.push(`${line.type === 'add' ? '+' : line.type === 'remove' ? '-' : ' '}${line.text}`)
    }
  }
  return out.join('\n')
}

module.exports = { preview, previewSettings, previewWaf, diffLines, toHunks, toUnifiedText, summarize }
