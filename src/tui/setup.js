
const path = require('path')
const fs = require('fs')
const crypto = require('crypto')
const { execFileSync, spawnSync } = require('child_process')
const tk = require('./lib/ansi')

const PROJECT_ROOT = path.join(__dirname, '..', '..')
const BACKEND_DIR = path.join(PROJECT_ROOT, 'backend')

const ENV_PATH = process.env.CATWAF_ENV_FILE || path.join(PROJECT_ROOT, '.env')

function resolveCaddyfilePath() {
  if (process.env.CADDYFILE_PATH) return process.env.CADDYFILE_PATH
  const fromEnvFile = readEnvFile().CADDYFILE_PATH
  if (fromEnvFile) return fromEnvFile
  return path.join(PROJECT_ROOT, 'Caddyfile')
}

const FLAG_ALIASES = { minimal: 'lite', standard: 'full' }

function editionFromFlags(flags) {
  if (flags.lite && flags.full) return { error: 'Pass either --lite or --full, not both.' }
  if (flags.lite) return { edition: 'lite' }
  if (flags.full) return { edition: 'full' }
  for (const [legacy, edition] of Object.entries(FLAG_ALIASES)) {
    if (flags[legacy]) return { edition, legacy }
  }
  return { edition: null }
}

async function run(flags = {}) {
  const picked = editionFromFlags(flags)
  if (picked.error) {
    console.error(picked.error)
    return 2
  }
  if (picked.legacy) {
    console.log(`Note: --${picked.legacy} is now --${picked.edition}. Continuing as CatWAF ${picked.edition}.`)
  }

  const nonInteractive = !!(picked.edition || flags.yes) && !flags.custom
  if (nonInteractive) return await runNonInteractive(picked.edition || 'full', flags)

  tk.clearScreen()
  tk.hideCursor()

  try {
    ensureJwtSecret()
    await welcomeScreen()
    const envOk = await checkEnvironment()
    if (!envOk) {
      await tk.waitForKey(tk.color('\nSetup stopped — fix the issue above and re-run: catwaf --setup', tk.colors.yellow))
      return 1
    }
    const edition = picked.edition || await chooseEdition()
    if (!edition) return 1
    await checkCaddyCoraza()
    const domainInfo = await configureDomain()
    await createAdminUser()
    const spec = EDITIONS[edition]
    if (spec.dashboard) await buildDashboard()
    if (spec.catai) await configureCatAI()
    writeEnvFile({ CATWAF_EDITION: edition })
    await startService(domainInfo)
    await finishScreen({ ...domainInfo, edition })
    return 0
  } finally {
    tk.showCursor()
  }
}

async function chooseEdition() {
  const choice = await tk.menu({
    title: 'Choose your CatWAF edition',
    items: [
      { label: 'CatWAF Lite  — WAF + CLI only. No dashboard, no API server, no AI.', value: 'lite' },
      { label: 'CatWAF Full  — everything: dashboard, API, Attack Map, CatAI.',      value: 'full' },
    ],
    hint: '↑↓ navigate · ↵ select · you can switch later with `catwaf setup --full`',
  })
  return choice
}

async function buildDashboard() {
  tk.renderFrame({ header: 'Dashboard', body: ['', 'Installing frontend dependencies and building the dashboard…', ''] })
  const install = spawnSync('npm', ['install'], { cwd: path.join(PROJECT_ROOT, 'frontend'), stdio: 'pipe', shell: false })
  if (install.status !== 0) {
    tk.renderFrame({ header: 'Dashboard', body: ['', tk.color('✗ Frontend dependency install failed.', tk.colors.red), ''] })
    await tk.waitForKey('')
    return false
  }
  const build = spawnSync('npm', ['run', 'build'], { cwd: PROJECT_ROOT, stdio: 'pipe', shell: false })
  const ok = build.status === 0 && fs.existsSync(path.join(PROJECT_ROOT, 'frontend', 'dist', 'index.html'))
  tk.renderFrame({
    header: 'Dashboard',
    body: ['', ok ? tk.color('✓ Dashboard built', tk.colors.green) : tk.color('✗ Dashboard build failed', tk.colors.red), ''],
  })
  await tk.waitForKey('')
  return ok
}

async function welcomeScreen() {
  const { cols } = tk.termSize()
  const body = [
    '',
    tk.center(tk.color('🐱  CatWAF Setup', tk.colors.bold, tk.colors.cyan), cols),
    '',
    tk.center('This will check your environment, configure your domain,', cols),
    tk.center('create an admin login, and start the dashboard.', cols),
    '',
    tk.center(tk.color('Takes about a minute.', tk.colors.dim), cols),
  ]
  tk.renderFrame({ header: 'CatWAF First-Run Setup', body, footer: 'any key to begin · ctrl+c to cancel' })
  await tk.waitForKey('')
}

async function checkEnvironment() {
  const body = ['Checking environment…', '']
  tk.renderFrame({ header: 'Step 1 / 6 — Environment', body })

  const results = []
  let allOk = true

  const nodeMajor = parseInt(process.version.slice(1).split('.')[0], 10)
  const nodeOk = nodeMajor >= 22
  results.push([nodeOk, `Node.js ${process.version}`, nodeOk ? '' : 'CatWAF requires Node 22+ (uses node:sqlite)'])
  if (!nodeOk) allOk = false

  let dbOk = false, dbDetail = ''
  try {
    const db = require(path.join(BACKEND_DIR, 'services', 'db.js'))
    db.getDb().prepare('SELECT 1').get()
    dbOk = true
    dbDetail = db.DB_PATH
  } catch (e) {
    dbDetail = e.message
  }
  results.push([dbOk, 'Database', dbOk ? dbDetail : dbDetail])
  if (!dbOk) allOk = false

  const body2 = results.map(([ok, label, detail]) =>
    (ok ? tk.color('✓ ', tk.colors.green) : tk.color('✗ ', tk.colors.red)) + label +
    (detail ? tk.color('  — ' + detail, tk.colors.dim) : '')
  )
  tk.renderFrame({ header: 'Step 1 / 6 — Environment', body: ['', ...body2, ''] })
  await tk.waitForKey(allOk ? 'Looks good — ' : tk.color('Fix the above and re-run setup — ', tk.colors.yellow))
  return allOk
}

async function checkCaddyCoraza() {
  const caddy = require(path.join(BACKEND_DIR, 'services', 'caddy.js'))
  tk.renderFrame({ header: 'Step 2 / 6 — Caddy & Coraza', body: ['Checking Caddy and the Coraza module…'] })

  const running = caddy.isCaddyRunning()
  const modules = caddy.getCaddyModules()
  const corazaLoaded = modules.includes('http.handlers.waf')

  const lines = [
    '',
    (running ? tk.color('✓ ', tk.colors.green) : tk.color('✗ ', tk.colors.red)) + 'Caddy running' +
      (running ? '' : tk.color('  — not detected locally or in the caddy container', tk.colors.dim)),
    (corazaLoaded ? tk.color('✓ ', tk.colors.green) : tk.color('✗ ', tk.colors.red)) + 'Coraza module (http.handlers.waf)' +
      (corazaLoaded ? '' : tk.color('  — build Caddy with github.com/corazawaf/coraza-caddy/v2', tk.colors.dim)),
    '',
  ]
  if (!running || !corazaLoaded) {
    lines.push(tk.color('CatWAF\'s dashboard still starts without this —', tk.colors.yellow))
    lines.push(tk.color('you just won\'t have live traffic blocking until Caddy/Coraza are up.', tk.colors.yellow))
  }
  tk.renderFrame({ header: 'Step 2 / 6 — Caddy & Coraza', body: lines })
  await tk.waitForKey('')
}

function readEnvFile() {
  try { return require(path.join(BACKEND_DIR, 'services', 'env.js')).parse(fs.readFileSync(ENV_PATH, 'utf8')) }
  catch { return {} }
}
function writeEnvFile(updates) {
  const current = readEnvFile()
  const merged = { ...current, ...updates }
  const lines = Object.entries(merged).map(([k, v]) => `${k}=${v}`)
  fs.writeFileSync(ENV_PATH, lines.join('\n') + '\n', { mode: 0o600 })
  // Node applies `mode` only at file creation. An existing .env that was
  // once group/world-readable would stay loose through every rewrite —
  // force the mode on every write, matching setup.sh.
  try { fs.chmodSync(ENV_PATH, 0o600) } catch {}
}

function ensureJwtSecret() {
  const existing = readEnvFile()
  if (existing.JWT_SECRET && existing.JWT_SECRET.length >= 32) {
    if (!process.env.JWT_SECRET) process.env.JWT_SECRET = existing.JWT_SECRET
    return
  }
  const secret = crypto.randomBytes(32).toString('hex')
  writeEnvFile({ JWT_SECRET: secret })
  process.env.JWT_SECRET = secret
}

function domainIsValid(d) {
  return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(d)
}

async function configureDomain() {
  const existing = readEnvFile()
  if (existing.DOMAIN) {
    if (!domainIsValid(existing.DOMAIN)) {
      tk.renderFrame({
        header: 'Step 3 / 6 — Domain',
        body: [
          '',
          tk.color(`✗ DOMAIN in .env is not a valid domain: "${existing.DOMAIN}"`, tk.colors.yellow),
          '',
          `Fix it in .env and re-run setup. Continuing locally on ${localDomainInfo().dashboardUrl}.`,
        ],
      })
      await tk.waitForKey('')
      return localDomainInfo()
    }
    tk.renderFrame({
      header: 'Step 3 / 6 — Domain',
      body: ['', tk.color(`✓ Domain already configured: ${existing.DOMAIN}`, tk.colors.green), '', 'Skipping — change DOMAIN in .env and re-run setup to reconfigure.'],
    })
    await tk.waitForKey('')
    return domainInfoFor(existing.DOMAIN)
  }

  tk.showCursor()
  tk.renderFrame({
    header: 'Step 3 / 6 — Domain',
    body: [
      'CatWAF splits the dashboard and its API across two subdomains of',
      'whatever domain you give it, so the admin API never sits at a',
      'fixed, guessable address on your main site:',
      '',
      tk.color('  catwaf.<your-domain>      — the dashboard', tk.colors.cyan),
      tk.color('  api.catwaf.<your-domain>  — the API', tk.colors.cyan),
      '',
      'Point both as A/AAAA (or CNAME) records at this server before',
      'continuing — Caddy will request certificates for them automatically.',
      '',
      tk.color(`Leave blank to run locally without a real domain (${localDomainInfo().dashboardUrl}).`, tk.colors.dim),
      '',
    ],
  })

  let domain = await tk.prompt('Domain (e.g. example.com)', { defaultValue: '' })
  domain = domain.trim().toLowerCase()
  if (domain && !domainIsValid(domain)) {
    tk.renderFrame({ header: 'Step 3 / 6 — Domain', body: ['', tk.color(`✗ "${domain}" doesn't look like a valid domain — skipping, running locally instead.`, tk.colors.yellow)] })
    await tk.waitForKey('')
    domain = ''
  }
  tk.hideCursor()

  const info = domainIsValid(domain) ? domainInfoFor(domain) : localDomainInfo()

  const caddyfilePath = resolveCaddyfilePath()
  const envUpdates = { DOMAIN: domain, CORS_ORIGIN: info.dashboardUrl, CADDYFILE_PATH: caddyfilePath }

  writeEnvFile(envUpdates)
  writeFrontendEnv(info)
  writeCaddyfile(info)
  buildFrontend()

  tk.renderFrame({
    header: 'Step 3 / 6 — Domain',
    body: info.local
      ? ['', tk.color(`✓ Configured for ${info.dashboardUrl}`, tk.colors.green), tk.color('  Running locally — the backend serves the dashboard and API itself, no Caddy needed to front it.', tk.colors.dim), tk.color(`  WAF changes are still written to ${caddyfilePath}.`, tk.colors.dim)]
      : ['', tk.color(`✓ Configured for ${info.dashboardUrl}`, tk.colors.green), tk.color(`  Caddyfile: ${caddyfilePath}`, tk.colors.dim)],
  })
  await tk.waitForKey('')
  return info
}

function domainInfoFor(domain) {
  return {
    domain,
    dashboardHost: `catwaf.${domain}`,
    apiHost: `api.catwaf.${domain}`,
    dashboardUrl: `https://catwaf.${domain}`,
    apiUrl: `https://api.catwaf.${domain}`,
    local: false,
  }
}
function localDomainInfo() {
  // Locally the backend serves the dashboard AND the API on one origin, so
  // both URLs are the same port. `localhost:8081` is the Vite dev server, not
  // anything a local install actually listens on — reporting it here sent
  // people to a dead port and wrote a CORS_ORIGIN that matched no real origin.
  const port = process.env.PORT || 8000
  const url = `http://localhost:${port}`
  return { domain: '', dashboardHost: `localhost:${port}`, apiHost: `localhost:${port}`, dashboardUrl: url, apiUrl: url, local: true }
}

function writeFrontendEnv(info) {
  const p = path.join(PROJECT_ROOT, 'frontend', '.env.production')
  fs.writeFileSync(p, info.local ? '' : `VITE_API_BASE=${info.apiUrl}\n`)
}

function writeCaddyfile(info) {
  const CADDYFILE_PATH = resolveCaddyfilePath()
  try { fs.mkdirSync(path.dirname(CADDYFILE_PATH), { recursive: true }) } catch {}

  // Coraza refuses to start its WAF handler when the audit log's directory is
  // missing ("invalid WAF config from audit log"). Every config *apply* calls
  // ensureAuditLog(), but a fresh install applies nothing, so doctor and
  // health failed straight after a successful setup. Done here rather than at
  // one call site because both the interactive wizard and the non-interactive
  // path come through this function — and before the early return below, so
  // re-running setup against an existing Caddyfile still repairs it.
  // Idempotent: it opens the log with 'a' and never truncates.
  try { require(path.join(BACKEND_DIR, 'services', 'caddy.js')).ensureAuditLog() } catch {}

  if (fs.existsSync(CADDYFILE_PATH)) return
  const distPath = path.join(PROJECT_ROOT, 'frontend', 'dist')
  const port = process.env.PORT || 8000

  // With a domain, Caddy fronts the control panel on two subdomains and
  // terminates TLS for both.
  //
  // Without one, it must not: the backend already listens on PORT and serves
  // the dashboard itself, so a `http://localhost:PORT { reverse_proxy
  // 127.0.0.1:PORT }` block is both a proxy loop and a port CatWAF has
  // already taken — Caddy died on startup with "listen tcp :8000: bind:
  // address already in use", leaving the WAF down entirely. A local install
  // therefore gets a Caddyfile that describes only the sites being protected.
  const controlPanel = info.local
    ? `# CatWAF's own control panel is NOT configured here. Without a domain the
# backend serves the dashboard and the API directly on http://localhost:${port},
# so Caddy must not bind that port as well.
#
# Add the site you want to protect below, for example:
#
#     :80 {
#         reverse_proxy 127.0.0.1:8082
#     }
#
# then apply any WAF setting (\`catwaf paranoia 2\`, or an Apply in the
# dashboard) and CatWAF inserts and manages its WAF directives inside it.
`
    : `${info.dashboardHost} {\n    handle {\n        root * ${distPath}\n        try_files {path} /index.html\n        file_server\n    }\n}\n
${info.apiHost} {\n    reverse_proxy 127.0.0.1:${port}\n}\n`

  const content = `# Caddyfile — generated by \`catwaf --setup\`. Safe to hand-edit; setup
# will never overwrite an existing one.
#
# With a domain, two blocks serve CatWAF's own control panel (dashboard + API,
# split across subdomains — see middleware/dynamicPath.js for why the API is
# also unreachable at any fixed path within its own block). Add your protected
# site(s) below as their own blocks; CatWAF inserts/manages its own WAF
# directives inside whichever block you point it at from the dashboard's
# Cloudflare/reverse-proxy pages.

${controlPanel}`

  require('../../backend/services/configLock').atomicWriteFileSync(CADDYFILE_PATH, content, { mode: 0o640 })
}

function buildFrontend() {
  spawnSync('npm', ['run', 'build'], { cwd: PROJECT_ROOT, stdio: 'inherit', shell: false })
}

async function createAdminUser() {
  const auth = require(path.join(BACKEND_DIR, 'middleware', 'auth.js'))
  const db = require(path.join(BACKEND_DIR, 'services', 'db.js'))

  tk.clearScreen()
  if (!auth.needsBootstrap()) {
    tk.renderFrame({
      header: 'Step 4 / 6 — Admin Account',
      body: ['', tk.color('✓ ', tk.colors.green) + 'An admin account already exists.', '', 'Skipping — use the existing login.'],
    })
    await tk.waitForKey('')
    return
  }

  tk.showCursor()
  tk.renderFrame({
    header: 'Step 4 / 6 — Admin Account',
    body: [
      'No account exists yet — CatWAF Free ships with none by design.',
      tk.color('Create your admin login now. This is required to finish setup.', tk.colors.yellow),
      '',
    ],
  })

  const username = await tk.prompt('Admin username', { defaultValue: 'admin' })
  let password = ''
  while (password.length < auth.MIN_PASSWORD_LENGTH) {
    password = await tk.prompt(`Admin password (min ${auth.MIN_PASSWORD_LENGTH} chars)`, { mask: true })
    if (password.length < auth.MIN_PASSWORD_LENGTH) console.log(tk.color('Too short — try again.', tk.colors.yellow))
  }
  tk.hideCursor()

  try {
    auth.addUser({ username, password, role: 'admin' })
    tk.renderFrame({ header: 'Step 4 / 6 — Admin Account', body: ['', tk.color(`✓ Admin account "${username}" is ready.`, tk.colors.green)] })
  } catch (e) {
    tk.renderFrame({ header: 'Step 4 / 6 — Admin Account', body: ['', tk.color(`✗ ${e.message}`, tk.colors.red)] })
  }
  await tk.waitForKey('')
  db.setState('setup_completed', true)
}

function pickCatAITier() {
  const cores = require('os').cpus().length
  const totalGB = require('os').totalmem() / (1024 ** 3)
  return (cores <= 1 || totalGB <= 1.2)
    ? { model: 'qwen3:0.6b', reason: `${cores} core(s), ${totalGB.toFixed(1)}GB RAM — using the smaller, faster model` }
    : { model: 'qwen3:1.7b', reason: `${cores} cores, ${totalGB.toFixed(1)}GB RAM — this comfortably fits the better model` }
}

function ollamaReachable(url) {
  let probe
  try {
    const u = new URL(url)
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return false
    probe = new URL('/api/tags', u).toString()
  } catch { return false }
  try { execFileSync('curl', ['-sf', '-m', '2', '--', probe], { stdio: 'ignore' }); return true }
  catch { return false }
}

async function configureCatAI() {
  tk.clearScreen()
  const existing = readEnvFile()
  if (existing.CATAI_ENABLED === 'true') {
    tk.renderFrame({
      header: 'Step 5 / 6 — CatAI Assistant',
      body: ['', tk.color('✓ ', tk.colors.green) + `CatAI is already enabled (model: ${existing.CATAI_MODEL || 'qwen3:1.7b'}).`, '', 'Skipping — change CATAI_MODEL in .env to switch models.'],
    })
    await tk.waitForKey('')
    return
  }

  const ollamaUrl = existing.OLLAMA_URL || 'http://127.0.0.1:11434'
  const hasOllama = ollamaReachable(ollamaUrl)
  const tier = pickCatAITier()

  tk.renderFrame({
    header: 'Step 5 / 6 — CatAI Assistant (optional)',
    body: [
      'CatAI is a small local assistant built into the dashboard — it answers',
      'from CatWAF\'s own docs, can see your real settings, and can carry out',
      'requests like "block traffic from China" or "set paranoia to 2".',
      '',
      'It runs entirely on this machine via Ollama — nothing is sent anywhere.',
      '',
      hasOllama
        ? tk.color('✓ Ollama detected at ' + ollamaUrl, tk.colors.green)
        : tk.color('✗ Ollama not detected at ' + ollamaUrl, tk.colors.yellow),
      tk.color(`  Recommended model: ${tier.model} (${tier.reason})`, tk.colors.dim),
      '',
      tk.color('This is entirely optional — skipping leaves everything else unchanged.', tk.colors.dim),
      '',
    ],
  })

  if (!hasOllama) {
    tk.renderFrame({
      header: 'Step 5 / 6 — CatAI Assistant (optional)',
      body: [
        '', tk.color('Ollama isn\'t installed or isn\'t running.', tk.colors.yellow), '',
        'Install it yourself later and re-run setup to enable CatAI', '',
        '(download first, read it — never pipe a remote script into a shell):', '',
        tk.color('  curl -fsSL https://ollama.com/install.sh -o /tmp/ollama-install.sh', tk.colors.cyan),
        tk.color('  less /tmp/ollama-install.sh && sh /tmp/ollama-install.sh', tk.colors.cyan),
        tk.color(`  ollama pull ${tier.model}`, tk.colors.cyan),
        '',
      ],
    })
    await tk.waitForKey('')
    return
  }

  const wantsCatAI = await tk.confirm(`Install ${tier.model} (CatAI)? (~${tier.model.includes('0.6b') ? '0.4' : '1.4'}GB download)`, false)
  if (!wantsCatAI) {
    tk.renderFrame({ header: 'Step 5 / 6 — CatAI Assistant (optional)', body: ['', 'Skipped — run `catwaf --setup` again anytime to enable it.'] })
    await tk.waitForKey('')
    return
  }

  tk.renderFrame({ header: 'Step 5 / 6 — CatAI Assistant (optional)', body: ['', `Pulling ${tier.model} — this can take a few minutes…`, ''] })
  tk.showCursor()
  const pull = spawnSync('ollama', ['pull', tier.model], { stdio: 'inherit' })
  tk.hideCursor()

  if (pull.status !== 0) {
    tk.renderFrame({
      header: 'Step 5 / 6 — CatAI Assistant (optional)',
      body: ['', tk.color('✗ Could not pull the model.', tk.colors.red), '', `Try it yourself later: ollama pull ${tier.model}`],
    })
    await tk.waitForKey('')
    return
  }

  writeEnvFile({ CATAI_ENABLED: 'true', CATAI_MODEL: tier.model, OLLAMA_URL: ollamaUrl })
  tk.renderFrame({
    header: 'Step 5 / 6 — CatAI Assistant (optional)',
    body: ['', tk.color(`✓ CatAI enabled with ${tier.model}.`, tk.colors.green), tk.color('  Look for the cat icon in the bottom-right of the dashboard.', tk.colors.dim)],
  })
  await tk.waitForKey('')
}

function hasSystemd() {
  try { execFileSync('which', ['systemctl'], { stdio: 'ignore' }); return process.getuid && process.getuid() === 0 } catch { return false }
}

async function startService(info) {
  tk.clearScreen()
  tk.renderFrame({ header: 'Step 6 / 6 — Start CatWAF', body: ['Installing the CatWAF service…'] })

  if (hasSystemd()) {
    // Mirror the hardened unit setup.sh installs: same sandbox, and the
    // dedicated service account when it exists. The previous unit here ran
    // as root with no hardening at all — re-running interactive setup after
    // the installer silently downgraded a hardened install to root.
    const hasServiceUser = (() => {
      try { execFileSync('id', ['-u', 'catwaf'], { stdio: 'ignore' }); return true } catch { return false }
    })()
    if (hasServiceUser) {
      // The service account must be able to read its own tree (including
      // the 0600 .env) or the unit starts without any secrets loaded.
      try { execFileSync('chown', ['-R', 'catwaf:catwaf', PROJECT_ROOT], { stdio: 'ignore' }) } catch {}
    }
    // ProtectHome=true makes /home and /root *inaccessible*, which
    // ReadWritePaths cannot carve back open — so when this checkout lives
    // under either, degrade to read-only (which ReadWritePaths can).
    const protectHome = /^\/(home|root)(\/|$)/.test(PROJECT_ROOT) ? 'read-only' : 'true'
    const userLines = hasServiceUser
      ? `User=catwaf
Group=catwaf
EnvironmentFile=${PROJECT_ROOT}/.env
`
      : ''
    // The sqlite flag is applied inside scripts/start.js (execArgv on the
    // backend spawn) — flags here would only decorate the supervisor.
    const unit = `[Unit]
Description=CatWAF API and dashboard
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
${userLines}WorkingDirectory=${PROJECT_ROOT}
ExecStart=${process.execPath} scripts/start.js
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=${protectHome}
ReadWritePaths=${PROJECT_ROOT} ${PROJECT_ROOT}/data
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictNamespaces=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
`
    try {
      fs.writeFileSync('/etc/systemd/system/catwaf.service', unit)
      execFileSync('systemctl', ['daemon-reload'])
      execFileSync('systemctl', ['enable', '--now', 'catwaf'])
      tk.renderFrame({ header: 'Step 6 / 6 — Start CatWAF', body: ['', tk.color('✓ Installed and started as a systemd service (catwaf.service).', tk.colors.green)] })
    } catch (e) {
      tk.renderFrame({ header: 'Step 6 / 6 — Start CatWAF', body: ['', tk.color(`✗ Could not install the systemd service: ${e.message}`, tk.colors.red), '', `Start it by hand instead: ${tk.color('npm start', tk.colors.cyan)}`] })
    }
  } else {
    tk.renderFrame({
      header: 'Step 6 / 6 — Start CatWAF',
      body: [
        '', 'No systemd detected (or not running as root) — start CatWAF by hand:', '',
        tk.color(`  cd ${PROJECT_ROOT} && npm start`, tk.colors.cyan), '',
        'or run it under your own process manager / container restart policy.',
      ],
    })
  }
  await tk.waitForKey('')
}

async function finishScreen(info) {
  const { cols } = tk.termSize()
  const lite = info.edition === 'lite'
  const body = [
    '',
    tk.center(tk.color('✓ Setup complete', tk.colors.bold, tk.colors.green), cols),
    '',
    tk.center(`Edition:   ${tk.color(lite ? 'CatWAF Lite' : 'CatWAF Full', tk.colors.cyan)}`, cols),
    ...(lite
      ? [
          '',
          tk.center('No web dashboard in Lite — everything runs from the CLI.', cols),
          tk.center('Add it later with ' + tk.color('catwaf setup --full', tk.colors.cyan), cols),
        ]
      : [
          tk.center(`Dashboard: ${tk.color(info.dashboardUrl, tk.colors.cyan)}`, cols),
          tk.center(`API:       ${tk.color(info.apiUrl, tk.colors.cyan)}`, cols),
        ]),
    '',
    tk.center('Run ' + tk.color('catwaf status', tk.colors.cyan) + ' any time for a health summary.', cols),
    '',
  ]
  tk.renderFrame({ header: 'Done', body, footer: 'any key to exit' })
  await tk.waitForKey('')
}


const EDITIONS = {
  lite: { dashboard: false, catai: false, api: false, label: 'CatWAF Lite  (WAF + CLI)' },
  full: { dashboard: true,  catai: true,  api: true,  label: 'CatWAF Full  (WAF + CLI + dashboard + API)' },
}

const MODES = { minimal: EDITIONS.lite, standard: EDITIONS.full }

function say(sym, msg) { console.log(`${sym} ${msg}`) }
const OKM = '\u2713', FAILM = '\u2717', WARNM = '!'

async function runNonInteractive(edition, flags) {
  const spec = EDITIONS[edition] || EDITIONS.full
  const editionName = EDITIONS[edition] ? edition : 'full'
  console.log(`\nCatWAF Setup - ${spec.label}\n`)

  const nodeMajor = parseInt(process.version.slice(1).split('.')[0], 10)
  if (nodeMajor < 22) {
    say(FAILM, `Node ${process.version} is too old - CatWAF needs Node 22+ (node:sqlite).`)
    return 1
  }
  say(OKM, `Node ${process.version}`)

  const existing = readEnvFile()
  const alreadyInstalled = !!(existing.DOMAIN || existing.JWT_SECRET)
  if (alreadyInstalled && !flags.force) {
    say(WARNM, 'An existing CatWAF configuration was found (.env).')
    console.log('  Existing values are preserved. Pass --force to overwrite domain settings.')
  }

  ensureJwtSecret()
  say(OKM, 'JWT secret present')

  const domain = typeof flags.domain === 'string' ? flags.domain : (existing.DOMAIN || '')
  if (domain && !domainIsValid(domain)) {
    say(FAILM, `"${domain}" is not a valid domain.`)
    return 1
  }
  const info = domain ? domainInfoFor(domain) : localDomainInfo()

  const caddyfilePath = resolveCaddyfilePath()
  const envUpdates = { CADDYFILE_PATH: caddyfilePath, CATWAF_EDITION: editionName }
  if (domain && (!existing.DOMAIN || flags.force)) {
    envUpdates.DOMAIN = domain
    envUpdates.CORS_ORIGIN = info.dashboardUrl
  }
  writeEnvFile(envUpdates)
  say(OKM, `Configuration written (.env, mode 600)`)
  if (existing.CATWAF_EDITION && existing.CATWAF_EDITION !== editionName) {
    say(OKM, `Edition changed: ${existing.CATWAF_EDITION} → ${editionName} (data, rules and accounts preserved)`)
  } else {
    say(OKM, `Edition: ${editionName}`)
  }

  const caddyfileExisted = fs.existsSync(caddyfilePath)
  writeCaddyfile(info)
  say(OKM, caddyfileExisted ? `Caddyfile kept (already exists): ${caddyfilePath}` : `Caddyfile generated: ${caddyfilePath}`)

  const caddy = require(path.join(BACKEND_DIR, 'services', 'caddy.js'))

  // Coraza refuses to start its WAF handler when the audit log's directory
  // does not exist ("invalid WAF config from audit log"). Every config *apply*
  // calls ensureAuditLog(), but a fresh install applies nothing — so without
  // this, `catwaf doctor` and `catwaf health` failed immediately after a
  // successful setup, on a directory setup could perfectly well have created.
  const auditLog = caddy.ensureAuditLog()
  if (auditLog.ok) {
    say(OKM, `Audit log ready: ${auditLog.path}`)
  } else {
    say(WARNM, auditLog.error || 'Could not prepare the Coraza audit log directory.')
  }

  const mods = caddy.getCaddyModules()
  if (!mods) {
    say(WARNM, 'Caddy not found on PATH - the dashboard and API still run, but nothing is filtered.')
  } else if (!mods.includes('http.handlers.waf')) {
    say(FAILM, 'Caddy is installed WITHOUT the Coraza module - the WAF cannot run.')
    console.log('  Rebuild: xcaddy build --with github.com/corazawaf/coraza-caddy/v2')
    return 1
  } else {
    say(OKM, 'Caddy with Coraza module detected')
  }

  if (fs.existsSync(caddyfilePath) && mods) {
    const { spawnSync: sp } = require('child_process')
    const v = sp('caddy', ['validate', '--config', caddyfilePath, '--adapter', 'caddyfile'], { timeout: 20000 })
    if (v.status !== 0) {
      say(FAILM, 'Configuration validation failed.')
      const err = (v.stderr || '').toString().split('\n').filter(l => /error/i.test(l))[0]
      if (err) console.log('  ' + err.trim())
      console.log('\n  CatWAF did not activate the new configuration.')
      console.log('  Previous configuration has been preserved.')
      return 1
    }
    say(OKM, 'Configuration valid')
  }

  const auth = require(path.join(BACKEND_DIR, 'middleware', 'auth.js'))
  const adminUser = typeof flags['admin-user'] === 'string' ? flags['admin-user'] : null
  const adminPass = process.env.CATWAF_ADMIN_PASSWORD || (typeof flags['admin-pass'] === 'string' ? flags['admin-pass'] : null)

  if (auth.needsBootstrap()) {
    if (!adminUser || !adminPass) {
      say(FAILM, 'No admin account exists and none was provided.')
      console.log('  Non-interactive setup cannot prompt. Provide both:')
      console.log('    --admin-user <name>  and  CATWAF_ADMIN_PASSWORD=<password>')
      console.log('  (or run `catwaf setup` interactively)')
      return 1
    }
    try {
      auth.addUser({ username: adminUser, password: adminPass, role: 'admin' })
      say(OKM, `Admin account "${adminUser}" created`)
    } catch (e) {
      say(FAILM, `Could not create admin account: ${e.message}`)
      return 1
    }
  } else {
    say(OKM, `Admin account already exists (${auth.listUsers().length} account(s))`)
  }

  if (spec.dashboard) {
    const distIndex = path.join(PROJECT_ROOT, 'frontend', 'dist', 'index.html')
    if (fs.existsSync(distIndex) && !flags.rebuild) {
      say(OKM, 'Dashboard already built')
    } else {
      if (!fs.existsSync(path.join(PROJECT_ROOT, 'frontend', 'node_modules'))) {
        console.log('  Installing dashboard dependencies...')
        const dep = spawnSync('npm', ['install'], { cwd: path.join(PROJECT_ROOT, 'frontend'), stdio: 'pipe', shell: false })
        if (dep.status !== 0) {
          say(FAILM, 'Frontend dependency install failed.')
          const tail = (dep.stderr || '').toString().trim().split('\n').slice(-4).join('\n  ')
          if (tail) console.log('  ' + tail)
          return 1
        }
      }
      console.log('  Building dashboard (this takes a moment)...')
      const r = spawnSync('npm', ['run', 'build'], { cwd: PROJECT_ROOT, stdio: 'pipe', shell: false })
      if (r.status !== 0 || !fs.existsSync(distIndex)) {
        say(FAILM, 'Dashboard build failed.')
        const tail = (r.stderr || '').toString().trim().split('\n').slice(-4).join('\n  ')
        if (tail) console.log('  ' + tail)
        return 1
      }
      say(OKM, 'Dashboard built')
    }
  } else {
    say(OKM, 'Dashboard skipped (Lite — no frontend dependencies installed)')
  }

  if (!spec.catai || flags['no-ai']) {
    say(OKM, spec.catai ? 'CatAI skipped (--no-ai)' : 'CatAI skipped (Lite)')
  } else if (process.env.CATAI_ENABLED === 'true') {
    say(OKM, 'CatAI is enabled in .env - it will load on next start')
  } else {
    say(OKM, 'CatAI not configured (optional — CatWAF Full runs fine without it)')
  }

  console.log('')
  say(OKM, 'Setup complete')
  console.log('')
  console.log('  Next:')
  console.log('    catwaf doctor     # verify this environment')
  console.log('    catwaf status     # version, edition and component health')
  console.log('    catwaf start      # start CatWAF')
  if (spec.dashboard) {
    const boundHost = process.env.HOST || '127.0.0.1'
    const port = process.env.PORT || '8000'
    if (!info.local) {
      console.log(`    ${info.dashboardUrl}`)
    } else if (boundHost === '127.0.0.1' || boundHost === 'localhost') {
      console.log(`    http://localhost:${port}   (this machine only)`)
      console.log(`    From another device? Set HOST=0.0.0.0 in .env, restart,`)
      console.log(`    then open http://<this-server-ip>:${port} — plain HTTP, see SECURITY.md.`)
    } else {
      console.log(`    http://<this-server-ip>:${port}   (bound to ${boundHost})`)
      console.log(`    Plain HTTP — a domain + TLS is recommended before exposing this publicly.`)
    }
  } else {
    console.log('')
    console.log('  Lite has no web dashboard. Investigate from the CLI:')
    console.log('    catwaf audit      # traffic and attack summary')
    console.log('    catwaf explain --last')
    console.log('  Add the dashboard later with: catwaf setup --full')
  }
  console.log('')
  return 0
}

module.exports = {
  run, runNonInteractive, EDITIONS, MODES, editionFromFlags,
  domainIsValid, domainInfoFor, localDomainInfo,
}
