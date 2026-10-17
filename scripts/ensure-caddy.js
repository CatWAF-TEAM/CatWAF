#!/usr/bin/env node
//
// Downloads a Caddy build with the Coraza WAF module baked in.
//
// Trust model (honest version): caddyserver.com's download API serves
// freshly compiled binaries and publishes NO checksums or signatures for
// them, so a download cannot be verified against upstream the way a release
// artifact can. What this script does instead, in order of strength:
//
//   1. Pin Caddy and Coraza versions and inspect the received binary's
//      compiler/dependency security baseline before installation.
//      Upstream downloads do not lock all transitive dependencies.
//   2. Never follows redirects off the download host.
//   3. Trust-on-first-use pinning: after a successful install the binary's
//      SHA-256 is recorded in data/caddy-pin.json. Every later reinstall of
//      the SAME pin must reproduce that hash, or the install aborts — so a
//      one-time compromise cannot silently persist, and an operator who
//      records the hash out-of-band can detect any substitution.
//   4. Sanity-checks the result: it must be a real ELF/Mach-O binary and
//      must answer `caddy list-modules` with the Coraza handler.

const fs = require('fs')
const os = require('os')
const path = require('path')
const https = require('https')
const zlib = require('zlib')
const crypto = require('crypto')
const { execFileSync } = require('child_process')

const PROJECT_ROOT = path.join(__dirname, '..')
const LOCAL_BIN_DIR = path.join(PROJECT_ROOT, 'bin', 'vendor')
const LOCAL_CADDY = path.join(LOCAL_BIN_DIR, 'caddy')
const PIN_FILE = path.join(PROJECT_ROOT, 'data', 'caddy-pin.json')
const DOWNLOAD_HOST = 'caddyserver.com'
// Security updates to the existing upstream proxy dependency.
const CADDY_VERSION = 'v2.11.7'
const CORAZA_CADDY_VERSION = 'v2.6.2'
const MAX_DOWNLOAD_BYTES = 160 * 1024 * 1024

function log(msg) { console.log(`[ensure-caddy] ${msg}`) }

function sha256(buf) { return crypto.createHash('sha256').update(buf).digest('hex') }

function hasWorkingCoraza(bin) {
  try {
    const out = execFileSync(bin, ['list-modules'], { timeout: 5000 }).toString()
    return out.includes('http.handlers.waf') && meetsSecurityBaseline(execFileSync(bin, ['build-info'], { timeout: 5000, encoding: 'utf8' }))
  } catch { return false }
}

function atLeast(value, required) {
  const match = /^(?:go|v)?(\d+)\.(\d+)\.(\d+)$/.exec(value || '')
  if (!match) return false
  const parts = match.slice(1).map(Number)
  for (let i = 0; i < 3; i++) {
    if (parts[i] !== required[i]) return parts[i] > required[i]
  }
  return true
}
function meetsSecurityBaseline(info) {
  const rows = info.split('\n').map(line => line.trim().split(/\s+/))
  const moduleVersion = name => rows.find(row => row[0] === 'dep' && row[1] === name)?.[2]
  return atLeast(rows.find(row => row[0] === 'go')?.[1], [1, 26, 9]) &&
    atLeast(moduleVersion('github.com/caddyserver/caddy/v2'), [2, 11, 7]) &&
    atLeast(moduleVersion('github.com/corazawaf/coraza-caddy/v2'), [2, 6, 2]) &&
    atLeast(moduleVersion('golang.org/x/net'), [0, 60, 0])
}

function findExistingCaddy() {
  for (const candidate of ['caddy', LOCAL_CADDY]) {
    if (hasWorkingCoraza(candidate)) return candidate
  }
  return null
}

function platformTarget() {
  const platform = os.platform()
  const archMap = { x64: 'amd64', arm64: 'arm64' }
  const arch = archMap[os.arch()]
  if (!arch || (platform !== 'linux' && platform !== 'darwin')) return null
  return { os: platform, arch }
}

// Redirects are followed only within the download host — a redirect to
// another origin would silently change who we are trusting.
function download(url, redirects = 5) {
  return new Promise((resolve, reject) => {
    const request = https.get(url, { headers: { 'User-Agent': 'catwaf-setup' }, signal: AbortSignal.timeout(120000) }, (res) => {
      if ([301, 302, 307, 308].includes(res.statusCode) && res.headers.location && redirects > 0) {
        res.resume()
        const next = new URL(res.headers.location, url)
        if (next.protocol !== 'https:' || next.host !== DOWNLOAD_HOST || next.username || next.password) {
          return reject(new Error(`Download redirected off ${DOWNLOAD_HOST} (to ${next.host}) — refusing.`))
        }
        return resolve(download(next.toString(), redirects - 1))
      }
      if (res.statusCode !== 200) {
        res.resume()
        return reject(new Error(`HTTP ${res.statusCode} fetching ${url}`))
      }
      const chunks = []
      let size = 0
      res.on('data', (c) => {
        size += c.length
        if (size > MAX_DOWNLOAD_BYTES) { request.destroy(new Error('Caddy download exceeds size limit')); return }
        chunks.push(c)
      })
      res.on('end', () => resolve(Buffer.concat(chunks)))
      res.on('error', reject)
    }).on('error', reject)
  })
}

async function fetchCaddyWithCoraza(target) {
  let url = `https://${DOWNLOAD_HOST}/api/download?os=${target.os}&arch=${target.arch}&p=${encodeURIComponent('github.com/corazawaf/coraza-caddy/v2@' + CORAZA_CADDY_VERSION)}`
  if (CADDY_VERSION) url += `&version=${encodeURIComponent(CADDY_VERSION)}`
  log(`Downloading a Caddy${CADDY_VERSION ? ` ${CADDY_VERSION}` : ''} build with the Coraza module for ${target.os}/${target.arch}…`)
  const body = await download(url)
  const isGzip = body[0] === 0x1f && body[1] === 0x8b
  return isGzip ? zlib.gunzipSync(body, { maxOutputLength: 256 * 1024 * 1024 }) : body
}

// A substituted payload is usually not even a valid executable for this
// platform. This is a sanity gate, NOT verification — the hash pin below is
// what actually detects substitution across installs.
function looksLikeExecutable(bytes) {
  if (bytes.length < 4) return false
  const magic = bytes.subarray(0, 4)
  const elf = magic[0] === 0x7f && magic[1] === 0x45 && magic[2] === 0x4c && magic[3] === 0x46 // ELF
  const macho64 = magic.readUInt32BE(0) === 0xfeedfacf
  const machoUni = bytes.length > 8 && magic.readUInt32BE(0) === 0xcafebabe
  return elf || macho64 || machoUni
}

function readPin() {
  try { return JSON.parse(fs.readFileSync(PIN_FILE, 'utf8')) } catch { return null }
}

function writePin(pin) {
  fs.mkdirSync(path.dirname(PIN_FILE), { recursive: true })
  fs.writeFileSync(PIN_FILE, JSON.stringify(pin, null, 2), { mode: 0o644 })
}

// Trust-on-first-use: the first successful install for a given os/arch pair
// records its hash. Re-installing the SAME combination must
// produce the same hash unless the operator explicitly allows a new one
// (upstream rebuilds are possible, so this is deliberate, visible, and
// logged rather than silent).
function checkPin(bytes, target) {
  const key = `${target.os}-${target.arch}`
  const hash = sha256(bytes)
  const expected = process.env.CATWAF_CADDY_SHA256
  if (expected && (!/^[a-f0-9]{64}$/i.test(expected) || expected.toLowerCase() !== hash)) {
    return { ok: false, error: 'The downloaded build does not match CATWAF_CADDY_SHA256.' }
  }
  const pin = readPin()
  if (!pin || pin.target !== key || pin.version !== CADDY_VERSION || !pin.sha256) {
    return { ok: true, hash, tofu: true }
  }
  if (pin.sha256 === hash) return { ok: true, hash, tofu: false }
  if (String(process.env.CATWAF_CADDY_ALLOW_NEW_BUILD) === '1') {
    log(`Build hash changed for ${key} (${pin.sha256.slice(0, 12)}… → ${hash.slice(0, 12)}…) — CATWAF_CADDY_ALLOW_NEW_BUILD=1 set, accepting and re-pinning.`)
    return { ok: true, hash, tofu: true }
  }
  return {
    ok: false,
    error: `The downloaded build does not match the hash recorded on this machine (${pin.sha256.slice(0, 16)}…). If you expected upstream to publish a new build for this version, re-run with CATWAF_CADDY_ALLOW_NEW_BUILD=1 to accept and re-pin it.`,
  }
}

function installTo(dir, bytes) {
  fs.mkdirSync(dir, { recursive: true })
  const dest = path.join(dir, 'caddy')
  // Atomic replace: never leave a truncated binary at the target path.
  const tmp = `${dest}.tmp-${process.pid}`
  fs.writeFileSync(tmp, bytes, { mode: 0o755, flag: 'wx' })
  fs.renameSync(tmp, dest)
  return dest
}

function canWriteSystemBin() {
  try { fs.accessSync('/usr/local/bin', fs.constants.W_OK); return true } catch { return false }
}

async function main() {
  if (findExistingCaddy()) {
    log('Caddy with the Coraza module is already available — nothing to do.')
    return
  }

  const target = platformTarget()
  if (!target) {
    log(`Unsupported platform (${os.platform()}/${os.arch()}) for automatic install.`)
    log('Use the existing Docker integration or install an upstream Caddy build with Coraza.')
    log('(see docs/installation.md) — `catwaf --setup` will tell you if it\'s still missing.')
    return
  }

  try {
    const bytes = await fetchCaddyWithCoraza(target)
    if (!looksLikeExecutable(bytes)) {
      throw new Error('the response is not a valid executable image for this platform')
    }
    const pinCheck = checkPin(bytes, target)
    if (!pinCheck.ok) throw new Error(pinCheck.error)

    // Validate before replacing any installed binary. A rejected download
    // must never become the executable selected on the next service start.
    const checkDir = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-caddy-check-'))
    try {
      const candidate = installTo(checkDir, bytes)
      if (!hasWorkingCoraza(candidate)) throw new Error('Upstream Caddy build fails the security baseline (Go >= 1.26.9, Caddy >= 2.11.7, Coraza-Caddy >= 2.6.2, x/net >= 0.60.0). Use the pinned Docker integration or a verified upstream build.')
    } finally { fs.rmSync(checkDir, { recursive: true, force: true }) }
    const dest = canWriteSystemBin()
      ? installTo('/usr/local/bin', bytes)
      : installTo(LOCAL_BIN_DIR, bytes)

    if (!hasWorkingCoraza(dest)) {
      log(`Downloaded a binary to ${dest} but it doesn't report the Coraza module — treating this as a failed install.`)
      log('Use the pinned Docker integration or a verified upstream build (see docs/installation.md).')
      return
    }

    writePin({ target: `${target.os}-${target.arch}`, sha256: pinCheck.hash, recordedAt: new Date().toISOString(), version: CADDY_VERSION || null })
    log(`✓ Installed Caddy (with Coraza) to ${dest}`)
    log(`  Build SHA-256 pinned locally: ${pinCheck.hash}`)
    log('  Upstream build accepted with a local trust-on-first-use hash; upstream publishes no signed checksums.')
    if (dest === LOCAL_CADDY) {
      log(`/usr/local/bin isn't writable without root — add ${LOCAL_BIN_DIR} to PATH,`)
      log('or re-run this install with sudo/root to install it system-wide instead.')
    }
  } catch (e) {
    log(`Could not auto-install Caddy: ${e.message}`)
    process.exitCode = 1
    log('Caddy was not installed; the setup checks will report it as unavailable:')
    log('  use the pinned Docker integration or a verified upstream build (see docs/installation.md)')
  }
}

if (require.main === module) main().catch((e) => { log(`Unexpected error: ${e.message}`); process.exitCode = 1 })
module.exports = { atLeast, meetsSecurityBaseline, hasWorkingCoraza }
