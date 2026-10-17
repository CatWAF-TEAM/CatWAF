// Self-hosted image CAPTCHA: PNG pixels embedded in SVG, generated with
// Node built-ins. The answer is kept server-side, never emitted as text.
// Automated image solvers can still solve it; it is not proof of humanity.

const crypto = require('crypto')

// No 0/O/1/I/l — an ambiguous glyph turns a solvable challenge into a
// coin-flip for a human while costing an OCR engine nothing.
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'

function randomInt(max) {
  return crypto.randomInt(0, max)
}

function generateAnswer(length = 5) {
  let out = ''
  for (let i = 0; i < length; i++) out += ALPHABET[randomInt(ALPHABET.length)]
  return out
}

function renderSvg(answer) {
  const data = require('./raster').png(answer).toString('base64')
  const width = 30 + answer.length * 34
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="76" role="img" aria-label="Verification characters"><image width="${width}" height="76" href="data:image/png;base64,${data}"/></svg>`
}
function create(length = 5) {
  const answer = generateAnswer(Math.max(4, Math.min(8, length)))
  return { answer, svg: renderSvg(answer) }
}

// Case-insensitive and constant-time: a captcha answer is short enough that
// a timing difference is measurable, and letter case is never the point.
function matches(expected, submitted) {
  const a = Buffer.from(String(expected || '').toUpperCase())
  const b = Buffer.from(String(submitted || '').trim().toUpperCase())
  if (a.length === 0 || a.length !== b.length) return false
  return crypto.timingSafeEqual(a, b)
}

module.exports = { create, matches, generateAnswer, renderSvg, ALPHABET }
