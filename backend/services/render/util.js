// render/util.js — shared helpers for turning validated settings into
// Caddyfile text.
//
// Two rules everything here follows:
//
//  1. Tokens are always quoted. settings/types.js has already refused any
//     value containing a quote, brace, backtick, backslash or newline, so a
//     double-quoted token cannot escape its own directive.
//  2. Anything multi-line — HTML, PEM, a raw config blob — is written to a
//     file under the CatWAF data directory and referenced by path, never
//     inlined. That keeps the generated Caddyfile free of any construct
//     whose termination depends on user content.

const fs = require('fs')
const path = require('path')

const db = require('../db')
let previewDepth = 0
let generation = null

// Each render writes to an immutable generation. A rejected candidate can
// never overwrite files still referenced by the running Caddy instance.
function withAssetGeneration(fn, id = require('crypto').randomUUID()) {
  if (generation) return fn()
  generation = id
  try { return fn() } finally { generation = null }
}

function generationDir(id) {
  if (!/^[a-zA-Z0-9-]+$/.test(id)) throw new Error('Invalid asset generation')
  return path.join(path.dirname(db.DB_PATH), 'caddy', 'generations', id)
}

function discardGeneration(id) {
  const dir = generationDir(id)
  // id is a single validated path component under the fixed generation root.
  fs.rmSync(dir, { recursive: true, force: true })
}

function syncGeneration(id) {
  if (process.platform === 'win32' || previewDepth) return
  const dir = generationDir(id)
  if (!fs.existsSync(dir)) return
  function syncTree(current) {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      if (entry.isDirectory()) syncTree(path.join(current, entry.name))
    }
    const fd = fs.openSync(current, 'r')
    try { fs.fsyncSync(fd) } finally { fs.closeSync(fd) }
  }
  syncTree(dir)
  for (const current of [path.dirname(dir), path.dirname(path.dirname(dir)), path.dirname(db.DB_PATH)]) {
    const fd = fs.openSync(current, 'r')
    try { fs.fsyncSync(fd) } finally { fs.closeSync(fd) }
  }
}

function withoutAssetWrites(fn) {
  previewDepth++
  try { return fn() } finally { previewDepth-- }
}

function q(value) {
  return `"${String(value)}"`
}

function indent(lines, level = 1) {
  const pad = '    '.repeat(level)
  return lines.map(l => (l === '' ? '' : pad + l))
}

function dur(seconds) {
  const n = Math.max(0, Math.trunc(Number(seconds) || 0))
  if (n === 0) return '0s'
  if (n % 86400 === 0) return `${n / 86400}d`
  if (n % 3600 === 0) return `${n / 3600}h`
  if (n % 60 === 0) return `${n / 60}m`
  return `${n}s`
}

function assetDir(...parts) {
  // The runtime cache is mutable state, not a generated configuration asset.
  const base = parts[0] === 'cache' || !generation
    ? path.join(path.dirname(db.DB_PATH), 'caddy')
    : generationDir(previewDepth ? 'preview' : generation)
  const dir = path.join(base, ...parts)
  if (!previewDepth) fs.mkdirSync(dir, { recursive: true, mode: 0o750 })
  return dir
}

// Writes a generated asset and returns its absolute path, or null when there
// is nothing to write. Content is compared first so an unchanged asset does
// not churn its mtime on every reload.
function writeAsset(relPath, content, { mode = 0o640 } = {}) {
  if (content == null || content === '') return null
  const parts = relPath.split('/')
  const name = parts.pop()
  const dir = assetDir(...parts)
  const full = path.join(dir, name)
  if (previewDepth) return full
  try {
    if (fs.readFileSync(full, 'utf8') === content) return full
  } catch { /* not written yet */ }
  require('../configLock').atomicWriteFileSync(full, content, { mode })
  return full
}

function removeAsset(relPath) {
  if (previewDepth) return
  try { fs.unlinkSync(path.join(assetDir(...relPath.split('/').slice(0, -1)), relPath.split('/').pop())) } catch {}
}

// Escapes a string for use inside a Caddy path/header *matcher* regexp.
function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

// Caddy placeholder syntax uses {...}; a literal brace in emitted content
// would be interpreted as one. Settings validation already refuses braces in
// tokens, so this only guards generated text (robots.txt, security.txt).
function stripBraces(value) {
  return String(value).replace(/[{}]/g, '')
}

// Every matcher CatWAF emits is namespaced so it can never collide with one
// the operator wrote by hand in the same site block.
function m(name) {
  return `@catwaf_${name}`
}

// A block of directives, rendered only when it has content.
function block(header, lines, level = 0) {
  const body = lines.filter(l => l !== null && l !== undefined)
  if (!body.length) return []
  return [`${header} {`, ...indent(body, 1), '}'].map(l => '    '.repeat(level) + l)
}

module.exports = { q, indent, dur, assetDir, writeAsset, removeAsset, escapeRegex, stripBraces, m, block, withoutAssetWrites, withAssetGeneration, generationDir, discardGeneration, syncGeneration }
