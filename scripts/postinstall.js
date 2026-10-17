#!/usr/bin/env node

const fs = require('fs')
const path = require('path')
const { spawnSync } = require('child_process')

const PROJECT_ROOT = path.join(__dirname, '..')
const FRONTEND = path.join(PROJECT_ROOT, 'frontend')

function log(msg) { console.log(`[catwaf] ${msg}`) }

function editionFromEnvFile() {
  try {
    const env = require(path.join(PROJECT_ROOT, 'backend', 'services', 'env.js'))
    return env.parse(fs.readFileSync(path.join(PROJECT_ROOT, '.env'), 'utf8')).CATWAF_EDITION || null
  } catch { return null }
}

function resolveEdition() {
  const candidates = [process.env.CATWAF_EDITION, editionFromEnvFile()]
  for (const c of candidates) {
    const v = String(c || '').trim().toLowerCase()
    if (v === 'lite' || v === 'full') return v
  }
  return fs.existsSync(path.join(FRONTEND, 'dist', 'index.html')) ? 'full' : 'lite'
}

function main() {
  if (process.env.CATWAF_SKIP_CADDY_DOWNLOAD === '1') {
    log('Skipping the Caddy check (CATWAF_SKIP_CADDY_DOWNLOAD=1).')
  } else {
    try {
      spawnSync(process.execPath, [path.join(__dirname, 'ensure-caddy.js')], { stdio: 'inherit' })
    } catch (e) {
      log(`Caddy check skipped: ${e.message}`)
    }
  }

  const edition = resolveEdition()

  if (edition === 'lite') {
    log('Edition: lite — skipping frontend dependencies (no dashboard, no Vite).')
    log('Add the dashboard any time with: catwaf setup --full')
    return
  }

  if (!fs.existsSync(path.join(FRONTEND, 'package.json'))) {
    log('Edition: full, but frontend/ is not present — skipping dashboard dependencies.')
    return
  }

  log('Edition: full — installing dashboard dependencies…')
  const env = { ...process.env }
  delete env.npm_config_omit
  delete env.npm_config_only
  delete env.npm_config_production

  const npmArgs = ['ci', '--include=dev']
  // npm supplies its CLI path during lifecycle scripts. Executing it with
  // Node also avoids relying on a shell to launch npm.cmd on Windows.
  const command = process.env.npm_execpath ? process.execPath : 'npm'
  const args = process.env.npm_execpath ? [process.env.npm_execpath, ...npmArgs] : npmArgs
  const r = spawnSync(command, args, {
    cwd: FRONTEND, stdio: 'inherit', shell: false, env,
  })
  if (r.status !== 0) {
    log('Dashboard dependency install failed. The WAF and CLI still work.')
    log('Retry with: npm --prefix frontend ci --include=dev && npm run build')
  }
}

main()
