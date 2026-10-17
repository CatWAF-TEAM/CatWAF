#!/usr/bin/env node

const fs = require('fs')
const os = require('os')
const path = require('path')
const { spawn, execFileSync } = require('child_process')

const ROOT = path.join(__dirname, '..')
const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-fe-'))
const PORT = Number(process.env.FE_TEST_PORT || 18500)
const BASE = `http://127.0.0.1:${PORT}`
const ADMIN = 'smoketest_admin'
const PASSWORD = 'SmokeTestPass123'

let pass = 0, fail = 0
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  ok   ' + name) }
  else { fail++; console.log('  FAIL ' + name, extra !== undefined ? JSON.stringify(extra) : '') }
}
function section(t) { console.log('\n== ' + t + ' ==') }

function resolvePlaywright() {
  const candidates = [
    process.env.PLAYWRIGHT_CORE,
    path.join(os.homedir(), '.local/pw/node_modules/playwright-core'),
    path.join(ROOT, 'node_modules/playwright-core'),
  ].filter(Boolean)
  for (const p of candidates) {
    try { return require(p) } catch {}
  }
  return null
}

function resolveChrome() {
  if (process.env.PW_CHROME && fs.existsSync(process.env.PW_CHROME)) return process.env.PW_CHROME
  const roots = [path.join(os.homedir(), '.cache/ms-playwright')]
  for (const root of roots) {
    let entries = []
    try { entries = fs.readdirSync(root) } catch { continue }
    for (const e of entries) {
      for (const rel of ['chrome-linux64/chrome', 'chrome-linux/chrome', 'chrome-headless-shell-linux64/chrome-headless-shell']) {
        const p = path.join(root, e, rel)
        if (fs.existsSync(p)) return p
      }
    }
  }
  return null
}

let server = null
function cleanup() {
  try { if (server) server.kill('SIGKILL') } catch {}
  try { fs.rmSync(WORK, { recursive: true, force: true }) } catch {}
}
process.on('exit', cleanup)
process.on('SIGINT', () => { cleanup(); process.exit(130) })

async function waitForHttp(url, attempts = 60, delayMs = 250) {
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(2000) })
      if (res.ok) return true
    } catch {}
    await new Promise(r => setTimeout(r, delayMs))
  }
  return false
}

;(async () => {
  section('prerequisites')

  const distIndex = path.join(ROOT, 'frontend', 'dist', 'index.html')
  if (!fs.existsSync(distIndex)) {
    console.log('  SKIP  dashboard is not built — run `npm run build` first.')
    console.log('\n0 passed, 0 failed, SKIPPED (no dashboard build)')
    process.exit(0)
  }
  check('dashboard build exists', true)

  const playwright = resolvePlaywright()
  const chrome = resolveChrome()
  if (!playwright || !chrome) {
    console.log('  SKIP  playwright-core and/or a Chromium build are unavailable.')
    console.log('        These smoke tests drive a real browser and cannot be faked.')
    console.log('\n0 passed, 0 failed, SKIPPED (no browser)')
    process.exit(0)
  }
  check('playwright-core and Chromium available', true)

  const env = {
    ...process.env,
    PORT: String(PORT),
    HOST: '127.0.0.1',
    DB_DIR: path.join(WORK, 'db'),
    JWT_SECRET: 'f'.repeat(64),
    CORS_ORIGIN: BASE,
    CADDYFILE_PATH: path.join(WORK, 'Caddyfile'),
    CORAZA_AUDIT_LOG: path.join(WORK, 'audit.json'),
    CATAI_ENABLED: 'false',
  }
  fs.mkdirSync(env.DB_DIR, { recursive: true })
  fs.writeFileSync(env.CADDYFILE_PATH, '{\n    order coraza_waf first\n}\n\n:9700 {\n    respond "x" 200\n}\n')

  execFileSync(process.execPath, [path.join(ROOT, 'bin', 'catwaf.js'), 'user', 'add', ADMIN, '--role', 'admin'], {
    env: { ...env, CATWAF_USER_PASSWORD: PASSWORD },
    stdio: 'ignore',
    timeout: 20000,
  })
  check('admin account created for the test', true)

  server = spawn(process.execPath, [path.join(ROOT, 'backend', 'server.js')], { env, stdio: 'ignore' })
  const up = await waitForHttp(`${BASE}/healthz`)
  check('backend is serving the dashboard build', up)
  if (!up) { console.log(`\n${pass} passed, ${fail + 1} failed`); process.exit(1) }

  const browser = await playwright.chromium.launch({ executablePath: chrome, args: ['--no-sandbox'] })
  const context = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  const page = await context.newPage()

  const pageErrors = []
  page.on('pageerror', e => pageErrors.push(e.message))

  try {
    section('login')
    await page.goto(BASE, { waitUntil: 'networkidle' })
    await page.waitForTimeout(1200)

    const passwordField = page.locator('input[type="password"]')
    check('login screen is shown to an unauthenticated visitor', await passwordField.count() > 0)

    await page.locator('input').nth(0).fill(ADMIN)
    await passwordField.fill(PASSWORD)
    await page.locator('button').filter({ hasText: /sign in/i }).first().click()
    await page.waitForTimeout(3000)

    const loggedIn = await page.locator('input[type="password"]').count() === 0
    check('valid credentials log in', loggedIn)
    if (!loggedIn) {
      const err = await page.locator('body').innerText()
      console.log('    page said:', err.slice(0, 200).replace(/\n/g, ' '))
    }

    const skip = page.locator('button:has-text("Skip Tour")')
    if (await skip.count()) { await skip.click(); await page.waitForTimeout(700) }

    section('dashboard')
    const dashText = await page.locator('.main-content').innerText()
    check('dashboard renders content', dashText.trim().length > 100, dashText.length)
    check('dashboard shows protection state', /paranoia|protection|blocked|requests/i.test(dashText))

    section('navigation')
    const ROUTES = [
      ['/security-score', /score|security/i],
      ['/analytics', /analytic|traffic|attack/i],
      ['/engine', /engine|blocking|detection/i],
      ['/paranoia', /paranoia|level/i],
      ['/protection/sensitive-files', /sensitive|file/i],
      ['/ip/blacklist', /ip|block/i],
      ['/geo', /countr|geo/i],
      ['/alerts', /alert|webhook|notif/i],
      ['/diagnostics', /diagnos|check|caddy/i],
      ['/settings', /setting|theme|appearance/i],
      ['/attack-map', /attack map|location|blocked|no attack activity/i],
      ['/threats', /threat|attack|severity|block/i],
      ['/logs', /log|request|method|status/i],
      ['/rules', /rule|crs|paranoia|id/i],

      ['/protection/bans', /ban|refus|nothing is banned/i],
      ['/protection/challenge', /challenge|visitor|gate/i],
      ['/protection/threat-intel', /threat|intel|asn|reverse dns/i],
      ['/protection/behavior', /behaviour|behavior|threshold|error/i],

      ['/config/access', /access|host|method|deny/i],
      ['/config/headers', /header|cors|cookie|compress/i],
      ['/config/tls', /tls|certificate|acme/i],
      ['/config/proxy', /proxy|origin|upstream/i],
      ['/config/network', /network|address|proxy/i],
      ['/config/advanced', /advanced|raw|plugin/i],

      ['/system/jobs', /job|schedul|interval/i],
      ['/system/orchestration', /Docker.*Kubernetes|Kubernetes.*ingress/i],
      ['/system/caches', /cache|entries|clear/i],
      ['/system/templates', /template|configuration|apply/i],
      ['/system/reports', /report|export|range|request/i],
      ['/system/backups', /backup|destination|snapshot/i],
      ['/system/2fa', /two-factor|authenticat|password/i],
      ['/system/telemetry', /telemetry|payload|collect/i],
    ]

    for (const [route, expect] of ROUTES) {
      await page.goto(BASE + route, { waitUntil: 'networkidle' })
      await page.waitForTimeout(route === '/attack-map' ? 3000 : 900)
      const body = await page.locator('.main-content').innerText().catch(() => '')
      const rendered = body.trim().length > 40
      const matched = expect.test(body)
      check(`${route} renders`, rendered && matched, { len: body.trim().length, matched })
    }

    section('attack map with no geolocated data')
    await page.goto(BASE + '/attack-map', { waitUntil: 'networkidle' })
    await page.waitForTimeout(3000)
    const mapText = await page.locator('.main-content').innerText().catch(() => '')
    check('attack map states the empty case honestly',
      /no attack activity|no geolocated/i.test(mapText) || /\d+ blocked requests? across/i.test(mapText),
      mapText.slice(0, 160))

    section('client-side errors')
    const realErrors = pageErrors.filter(e => !/ResizeObserver|Non-Error promise/i.test(e))
    check('no uncaught JavaScript errors during navigation', realErrors.length === 0, realErrors.slice(0, 3))

    section('server-side authorization is not client-only')
    const unauth = await page.evaluate(async (base) => {
      const res = await fetch(base + '/api/users', { headers: { 'Content-Type': 'application/json' } })
      return { status: res.status }
    }, BASE)
    check('unauthenticated /api/users is refused by the server', unauth.status === 401 || unauth.status === 404, unauth)

    const unauthWaf = await page.evaluate(async (base) => {
      const res = await fetch(base + '/api/waf/engine', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'Off' }),
      })
      return { status: res.status }
    }, BASE)
    check('unauthenticated WAF change is refused by the server', unauthWaf.status >= 400, unauthWaf)

    section('logout leaves no authenticated surface')
    await page.goto(BASE, { waitUntil: 'networkidle' })
    await context.clearCookies()
    await page.evaluate(() => { try { localStorage.clear(); sessionStorage.clear() } catch {} })
    await page.goto(BASE, { waitUntil: 'networkidle' })
    await page.waitForTimeout(1500)
    check('clearing credentials returns to the login screen', await page.locator('input[type="password"]').count() > 0)

  } finally {
    await browser.close().catch(() => {})
  }

  console.log(`\n${pass} passed, ${fail} failed`)
  cleanup()
  process.exit(fail ? 1 : 0)
})().catch(e => {
  console.error('\nfrontend smoke harness error:', e.message)
  cleanup()
  process.exit(1)
})
