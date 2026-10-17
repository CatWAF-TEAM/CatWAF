
const fs = require('fs')
const path = require('path')
const db = require('./db')
const caddy = require('./caddy')
const auditSvc = require('./audit')
const { isValidCaddyPath } = require('./sanitize')
const configLock = require('./configLock')

const MARKER_START = '# @@CATWAF_SENSITIVE_START@@'
const MARKER_END   = '# @@CATWAF_SENSITIVE_END@@'

const WORDLIST_DIR = path.join(__dirname, '..', '..', 'frontend', 'public', 'wordlists')

// How many paths from any one level's list actually reach the Caddyfile.
// SFL1's list holds ~62k paths; a matcher with 62k entries is not something to
// hand Caddy, so the list is truncated. That truncation is real and material —
// "SFL1 is on" does not mean all 61,882 paths are blocked — so `describeLevels`
// reports the cap alongside the totals rather than letting a client imply
// otherwise.
const PATHS_PER_LEVEL_CAP = 500

function getSensitiveState() {
  return db.getState('sensitive') || { sfl_level: 0, blocked: [] }
}
function saveSensitiveState(s) { db.setState('sensitive', s) }

function loadWordlistFile(level) {
  const listFile = path.join(WORDLIST_DIR, `sfl${level}.txt`)
  try {
    return fs.readFileSync(listFile, 'utf8')
      .split('\n')
      .map(l => l.trim())
      .filter(l => l && !l.startsWith('#'))
      .map(l => l.startsWith('/') ? l : '/' + l)
      .slice(0, PATHS_PER_LEVEL_CAP)
  } catch {
    return []
  }
}

// Higher levels include every path blocked by all lower levels:
// SFL2 ⊇ SFL1, SFL3 ⊇ SFL2, SFL4 ⊇ SFL3.
function cumulativeSflPaths(level) {
  const seen = new Set()
  for (let lvl = 1; lvl <= level; lvl++) {
    for (const p of loadWordlistFile(lvl)) seen.add(p)
  }
  return [...seen]
}

function buildSensitiveBlock(state) {
  const { sfl_level } = state
  const blocked = (state.blocked || []).filter(isValidCaddyPath)

  if (sfl_level === 0 && blocked.length === 0) return ''

  const lines = []
  lines.push(MARKER_START)
  lines.push('# CatWAF Sensitive File Protection — auto-generated, do not edit manually')
  lines.push('')

  if (sfl_level >= 1 && sfl_level <= 3) {
    const allPaths = [...new Set([...cumulativeSflPaths(sfl_level), ...blocked])]

    if (allPaths.length > 0) {
      lines.push(`  # SFL${sfl_level} — blocking ${allPaths.length} sensitive paths`)
      lines.push(`  @catwaf_sensitive {`)
      lines.push(`    path ${allPaths.join(' ')}`)
      lines.push(`  }`)
      lines.push(`  handle @catwaf_sensitive {`)
      lines.push(`    respond "You have been blocked by CatWAF" 403`)
      lines.push(`  }`)
    }
  }

  if (sfl_level === 4) {
    const serverListPath = path.join(caddy.CORAZA_LIST_DIR, 'sfl4.txt')

    try {
      if (!fs.existsSync(caddy.CORAZA_LIST_DIR)) fs.mkdirSync(caddy.CORAZA_LIST_DIR, { recursive: true })
      fs.copyFileSync(path.join(WORDLIST_DIR, 'sfl4.txt'), serverListPath)
    } catch (e) {
      console.warn(`[CatWAF] Could not write SFL4 list to ${serverListPath}: ${e.message}`)
    }

    const allSfl4 = [...new Set([...cumulativeSflPaths(4), ...blocked])]
    lines.push(`  # SFL4 — MAXIMUM — blocking ${allSfl4.length} sensitive paths (all levels)`)
    lines.push(`  @catwaf_sfl4 path ${allSfl4.join(' ')}`)
    lines.push(`  handle @catwaf_sfl4 {`)
    lines.push(`    respond "You have been blocked by CatWAF" 403`)
    lines.push(`  }`)
  }

  if (blocked.length > 0 && sfl_level === 0) {
    lines.push(`  # Manual blocks only (SFL off)`)
    lines.push(`  @catwaf_manual path ${blocked.join(' ')}`)
    lines.push(`  handle @catwaf_manual {`)
    lines.push(`    respond "You have been blocked by CatWAF" 403`)
    lines.push(`  }`)
  }

  lines.push('')
  lines.push(MARKER_END)
  return lines.join('\n')
}

function patchCaddyfile(state) {
  // Same cross-process discipline as caddy.patchWAFCaddyfile (the lock is
  // re-entrant for callers that already hold it).
  return configLock.withConfigLock(() => {
  let content = caddy.readCaddyfile()
  const newBlock = buildSensitiveBlock(state)

  const hasMarkers = content.includes(MARKER_START)

  if (hasMarkers) {
    const startIdx = content.indexOf(MARKER_START)
    const endIdx   = content.indexOf(MARKER_END)
    if (endIdx === -1) throw new Error('Caddyfile has START marker but no END marker — fix manually')
    const before = content.slice(0, startIdx)
    const after  = content.slice(endIdx + MARKER_END.length)
    content = newBlock ? before + newBlock + after : before.trimEnd() + '\n' + after.trimStart()
  } else if (newBlock) {
    const lastBrace = content.lastIndexOf('}')
    if (lastBrace === -1) throw new Error('Caddyfile has no closing brace — cannot inject rules')
    content = content.slice(0, lastBrace) + '\n' + newBlock + '\n' + content.slice(lastBrace)
  }

  configLock.atomicWriteFileSync(caddy.CADDYFILE_PATH, content, { mode: 0o640 })
  })
}


function applyToCoraza(state, label, req) {
  let caddyResult = { reloaded: false, error: 'skipped' }
  try {
    patchCaddyfile(state)
    caddyResult = caddy.reloadCaddy()
    auditSvc.audit(req, label, `SFL${state.sfl_level}`, { reloaded: caddyResult.reloaded, blocks: state.blocked.length })
  } catch (e) {
    caddyResult = { reloaded: false, error: e.message }
    auditSvc.audit(req, label + '.error', e.message)
  }
  return caddyResult
}

/**
 * What each Sensitive File Level actually is, read from the wordlists on disk.
 *
 * Every field here is measured, not described: the name comes from the list's
 * own header, the totals from counting its lines, and the sample from its
 * first few entries. A client showing this is showing what the server would
 * really block, which is the only version worth showing on a security console.
 *
 * `enforced_paths` is deliberately separate from `list_paths`. The first is
 * what selecting this level really puts in the Caddyfile — cumulative over
 * every lower level, and capped at PATHS_PER_LEVEL_CAP entries each. The
 * second is the size of this level's own list. On SFL1 they are 500 and
 * 61,882, and reporting only the larger would overstate what is enforced.
 */
function describeLevels() {
  const levels = [{
    level: 0,
    name: 'Off',
    list_paths: 0,
    enforced_paths: 0,
    truncated: false,
    sample: [],
  }]

  for (let level = 1; level <= 4; level++) {
    const file = path.join(WORDLIST_DIR, `sfl${level}.txt`)
    let name = `Level ${level}`
    let all = []
    try {
      const text = fs.readFileSync(file, 'utf8')
      // "# CatWAF — Paranoia Level 2: Medium Sensitive" → "Medium Sensitive"
      const header = text.split('\n', 1)[0] || ''
      const match = header.match(/:\s*(.+?)\s*$/)
      if (match) name = match[1]
      all = text.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'))
    } catch {
      // A missing list is reported as an empty level rather than an error: the
      // firewall still runs, it just has nothing to add at this level.
    }

    const cumulative = cumulativeSflPaths(level)
    levels.push({
      level,
      name,
      // This level's own list…
      list_paths: all.length,
      // …versus what selecting it actually puts in the Caddyfile, which is
      // cumulative over every level below it and capped per level.
      enforced_paths: cumulative.length,
      truncated: all.length > PATHS_PER_LEVEL_CAP,
      sample: all.slice(0, 8).map(l => (l.startsWith('/') ? l : '/' + l)),
    })
  }

  return { cap_per_level: PATHS_PER_LEVEL_CAP, levels }
}

module.exports = {
  MARKER_START, MARKER_END, WORDLIST_DIR, PATHS_PER_LEVEL_CAP,
  describeLevels,
  getSensitiveState, saveSensitiveState,
  buildSensitiveBlock, patchCaddyfile, applyToCoraza,
  cumulativeSflPaths,
}
