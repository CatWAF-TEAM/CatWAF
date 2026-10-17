const fs = require('fs')
const os = require('os')
const path = require('path')
const { execFileSync } = require('child_process')
const configLock = require('./configLock')

const PROJECT_ROOT = path.join(__dirname, '..', '..')
const DASHBOARD_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self' https: 'unsafe-inline'; img-src 'self' data:; font-src 'self' https: data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'",
}

const DOMAIN_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i

function validateHostname(host) {
  if (typeof host !== 'string') return 'Hostname must be a string.'
  const h = host.trim()
  if (!h) return 'Hostname is required.'
  if (h.length > 253) return 'Hostname is too long.'
  if (!DOMAIN_RE.test(h)) return `"${h}" is not a valid hostname.`
  return null
}

function dashboardHostFor(baseDomain) {
  return `catwaf.${baseDomain}`
}

function caddyConfig({ dashboardHost, apiPort, distPath }) {
  return [
    `${dashboardHost} {`,
    '    header {',
    ...Object.entries(DASHBOARD_HEADERS).map(([name, value]) => `        ${name} "${value}"`),
    '    }',
    `    handle /api/* {`,
    `        reverse_proxy 127.0.0.1:${apiPort}`,
    `    }`,
    `    handle /g/* {`,
    `        reverse_proxy 127.0.0.1:${apiPort}`,
    `    }`,
    `    handle {`,
    `        root * ${distPath}`,
    `        try_files {path} /index.html`,
    `        file_server`,
    `    }`,
    `}`,
    '',
  ].join('\n')
}

function nginxConfig({ dashboardHost, apiPort, distPath }) {
  return [
    `server {`,
    `    listen 80;`,
    `    listen [::]:80;`,
    `    server_name ${dashboardHost};`,
    ...Object.entries(DASHBOARD_HEADERS).map(([name, value]) => `    add_header ${name} "${value}" always;`),
    ``,
    `    root ${distPath};`,
    `    index index.html;`,
    ``,
    `    location /api/ {`,
    `        proxy_pass http://127.0.0.1:${apiPort};`,
    `        proxy_http_version 1.1;`,
    `        proxy_set_header Host $host;`,
    `        proxy_set_header X-Real-IP $remote_addr;`,
    `        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`,
    `        proxy_set_header X-Forwarded-Proto $scheme;`,
    `        proxy_buffering off;`,
    `    }`,
    ``,
    `    location /g/ {`,
    `        proxy_pass http://127.0.0.1:${apiPort};`,
    `        proxy_http_version 1.1;`,
    `        proxy_set_header Host $host;`,
    `        proxy_set_header X-Real-IP $remote_addr;`,
    `        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`,
    `        proxy_set_header X-Forwarded-Proto $scheme;`,
    `        proxy_buffering off;`,
    `    }`,
    ``,
    `    location / {`,
    `        try_files $uri $uri/ /index.html;`,
    `    }`,
    `}`,
    '',
  ].join('\n')
}

function apacheConfig({ dashboardHost, apiPort, distPath }) {
  return [
    `<VirtualHost *:80>`,
    `    ServerName ${dashboardHost}`,
    ...Object.entries(DASHBOARD_HEADERS).map(([name, value]) => `    Header always set ${name} "${value}"`),
    ``,
    `    DocumentRoot ${distPath}`,
    ``,
    `    ProxyPreserveHost On`,
    `    ProxyPass        /api/ http://127.0.0.1:${apiPort}/api/`,
    `    ProxyPassReverse /api/ http://127.0.0.1:${apiPort}/api/`,
    `    ProxyPass        /g/   http://127.0.0.1:${apiPort}/g/`,
    `    ProxyPassReverse /g/   http://127.0.0.1:${apiPort}/g/`,
    ``,
    `    <Directory ${distPath}>`,
    `        Require all granted`,
    `        FallbackResource /index.html`,
    `    </Directory>`,
    `</VirtualHost>`,
    '',
  ].join('\n')
}

const TARGETS = {
  caddy: {
    label: 'Caddy',
    automatable: true,
    render: caddyConfig,
    destination: () => {
      const caddySvc = require('./caddy')
      return caddySvc.CADDYFILE_PATH
    },
    mode: 'append',
    reload: () => {
      const caddySvc = require('./caddy')
      return caddySvc.reloadCaddy()
    },
    validate: (filePath) => {
      try {
        execFileSync('caddy', ['validate', '--config', filePath, '--adapter', 'caddyfile'], { timeout: 20000, stdio: ['ignore', 'pipe', 'pipe'] })
        return { ok: true, error: null }
      } catch (e) {
        return { ok: false, error: (e.stderr?.toString() || e.message || '').split('\n').filter(l => /error/i.test(l))[0] || 'validation failed' }
      }
    },
    httpsNote: 'Caddy obtains and renews HTTPS certificates automatically once the hostname resolves to this server.',
  },
  nginx: {
    label: 'nginx',
    automatable: true,
    render: nginxConfig,
    destination: () => {
      const dirs = ['/etc/nginx/sites-available', '/etc/nginx/conf.d', '/opt/homebrew/etc/nginx/servers']
      const dir = dirs.find(d => { try { fs.accessSync(d); return true } catch { return false } })
      if (!dir) return null
      return path.join(dir, dir.endsWith('sites-available') ? 'catwaf' : 'catwaf.conf')
    },
    mode: 'write',
    reload: () => {
      try {
        execFileSync('nginx', ['-s', 'reload'], { timeout: 10000, stdio: ['ignore', 'pipe', 'pipe'] })
        return { reloaded: true, error: null }
      } catch (e) {
        return { reloaded: false, error: (e.stderr?.toString() || e.message || '').split('\n')[0] }
      }
    },
    validate: () => {
      try {
        execFileSync('nginx', ['-t'], { timeout: 15000, stdio: ['ignore', 'pipe', 'pipe'] })
        return { ok: true, error: null }
      } catch (e) {
        return { ok: false, error: (e.stderr?.toString() || e.message || '').split('\n').filter(l => /error|fail/i.test(l))[0] || 'nginx -t failed' }
      }
    },
    httpsNote: 'HTTPS is not configured by this snippet. Run `certbot --nginx -d <host>` (or your usual ACME client) afterwards.',
  },
  apache: {
    label: 'Apache',
    automatable: true,
    render: apacheConfig,
    destination: () => {
      const dirs = ['/etc/apache2/sites-available', '/etc/httpd/conf.d']
      const dir = dirs.find(d => { try { fs.accessSync(d); return true } catch { return false } })
      if (!dir) return null
      return path.join(dir, dir.includes('sites-available') ? 'catwaf.conf' : 'catwaf.conf')
    },
    mode: 'write',
    reload: () => {
      for (const cmd of [['apache2ctl', ['graceful']], ['apachectl', ['graceful']], ['systemctl', ['reload', 'httpd']]]) {
        try { execFileSync(cmd[0], cmd[1], { timeout: 15000, stdio: ['ignore', 'pipe', 'pipe'] }); return { reloaded: true, error: null } } catch {}
      }
      return { reloaded: false, error: 'could not reload Apache — reload it manually' }
    },
    validate: () => {
      for (const cmd of [['apache2ctl', ['configtest']], ['apachectl', ['configtest']]]) {
        try { execFileSync(cmd[0], cmd[1], { timeout: 15000, stdio: ['ignore', 'pipe', 'pipe'] }); return { ok: true, error: null } } catch (e) {
          const out = (e.stderr?.toString() || '')
          if (out) return { ok: false, error: out.split('\n').filter(l => /error|fail/i.test(l))[0] || 'configtest failed' }
        }
      }
      return { ok: true, error: null }
    },
    httpsNote: 'HTTPS is not configured by this snippet. Also ensure mod_proxy and mod_proxy_http are enabled (`a2enmod proxy proxy_http`).',
  },
  cpanel: {
    label: 'cPanel',
    automatable: false,
    render: nginxConfig,
    destination: () => null,
    mode: null,
    reload: () => ({ reloaded: false, error: 'not supported' }),
    validate: () => ({ ok: true, error: null }),
    unsupportedReason: [
      'CatWAF automatic cPanel integration: NOT AVAILABLE.',
      '',
      'cPanel owns and regenerates its Apache/nginx virtual hosts, so a file written',
      'directly would be overwritten on the next rebuild, and editing cPanel-managed',
      'configuration out from under it can break hosting for every account on the box.',
      '',
      'Do this instead, in cPanel/WHM:',
      '  1. Create a subdomain "catwaf" on your chosen domain.',
      '  2. Point it at the CatWAF dashboard build directory, or',
      '     use WHM > Apache Configuration > Include Editor to add a reverse',
      '     proxy to 127.0.0.1:<api port> for that subdomain only.',
      '  3. Issue SSL for the subdomain via AutoSSL.',
      '',
      'The generated snippet below is reference material for step 2 — CatWAF will',
      'not install it for you.',
    ].join('\n'),
    httpsNote: 'Use cPanel AutoSSL for the catwaf subdomain.',
  },
}

function plan({ env, baseDomain, apiPort, distPath, target }) {
  const chosenTarget = target || env.primaryWebServer
  const spec = TARGETS[chosenTarget]

  const base = baseDomain || env.baseDomain
  if (!base) {
    return { ok: false, error: 'No domain could be detected. Pass one explicitly (e.g. --domain example.com).' }
  }
  const hostErr = validateHostname(base)
  if (hostErr) return { ok: false, error: hostErr }

  if (!spec) {
    return {
      ok: false,
      error: `No supported web server detected (looked for Caddy, nginx, Apache, cPanel). Detected: ${chosenTarget}.`,
      dashboardHost: dashboardHostFor(base),
    }
  }

  const dashboardHost = dashboardHostFor(base)
  const resolvedDist = distPath || path.join(PROJECT_ROOT, 'frontend', 'dist')
  const port = apiPort || Number(process.env.PORT || 8000)
  const config = spec.render({ dashboardHost, apiPort: port, distPath: resolvedDist })
  const destination = spec.destination ? spec.destination() : null

  return {
    ok: true,
    target: chosenTarget,
    targetLabel: spec.label,
    automatable: spec.automatable && !!destination,
    unsupportedReason: spec.unsupportedReason || null,
    dashboardHost,
    baseDomain: base,
    apiPort: port,
    distPath: resolvedDist,
    destination,
    mode: spec.mode,
    config,
    httpsNote: spec.httpsNote,
    dnsHint: `Point an A/AAAA record for ${dashboardHost} at this server's public IP before requesting certificates.`,
    distExists: fs.existsSync(path.join(resolvedDist, 'index.html')),
  }
}

function backupFile(filePath) {
  if (!fs.existsSync(filePath)) return null
  const stamp = new Date().toISOString().replace(/[:.]/g, '-')
  const backup = `${filePath}.catwaf-backup-${stamp}`
  fs.writeFileSync(backup, fs.readFileSync(filePath), { mode: 0o600, flag: 'wx' })
  return backup
}

function apply(planResult) {
  return configLock.withConfigLock(() => applyLocked(planResult))
}

function applyLocked(planResult) {
  if (!planResult || !planResult.ok) return { ok: false, error: planResult?.error || 'no plan' }
  if (!planResult.automatable) {
    return { ok: false, error: 'This target does not support automatic configuration.', unsupportedReason: planResult.unsupportedReason }
  }

  const spec = TARGETS[planResult.target]
  const dest = planResult.destination
  const marker = `# @@CATWAF_DASHBOARD_START@@ ${planResult.dashboardHost}`
  const endMarker = '# @@CATWAF_DASHBOARD_END@@'

  let backup = null
  let previous = null
  try {
    backup = backupFile(dest)
    previous = fs.existsSync(dest) ? fs.readFileSync(dest, 'utf8') : null

    let next
    if (planResult.mode === 'append') {
      const body = previous || ''
      const start = body.indexOf(marker)
      const block = `${marker}\n${planResult.config}${endMarker}\n`
      if (start !== -1) {
        const end = body.indexOf(endMarker, start)
        next = end === -1
          ? body + '\n' + block
          : body.slice(0, start) + block + body.slice(end + endMarker.length + 1)
      } else {
        next = body.replace(/\s*$/, '\n\n') + block
      }
    } else {
      next = `${marker}\n${planResult.config}${endMarker}\n`
    }

    fs.mkdirSync(path.dirname(dest), { recursive: true })
    configLock.atomicWriteFileSync(dest, next, { mode: 0o640 })

    const validation = spec.validate(dest)
    if (!validation.ok) {
      if (previous === null) { try { fs.unlinkSync(dest) } catch {} }
      else configLock.atomicWriteFileSync(dest, previous, { mode: 0o640 })
      return {
        ok: false,
        error: `Configuration validation failed: ${validation.error}`,
        rolledBack: true,
        backup,
        destination: dest,
      }
    }

    const reload = spec.reload()
    return {
      ok: true,
      destination: dest,
      backup,
      validated: true,
      reloaded: !!reload.reloaded,
      reloadError: reload.reloaded ? null : (reload.error || null),
      dashboardHost: planResult.dashboardHost,
    }
  } catch (e) {
    if (previous !== null) { try { configLock.atomicWriteFileSync(dest, previous, { mode: 0o640 }) } catch {} }
    return { ok: false, error: e.message, rolledBack: previous !== null, backup, destination: dest }
  }
}

function enableNginxSite(destination) {
  if (!destination || !destination.includes('sites-available')) return { ok: true, linked: false }
  const enabledDir = '/etc/nginx/sites-enabled'
  try { fs.accessSync(enabledDir) } catch { return { ok: true, linked: false } }
  const link = path.join(enabledDir, path.basename(destination))
  try {
    if (!fs.existsSync(link)) fs.symlinkSync(destination, link)
    return { ok: true, linked: true, link }
  } catch (e) {
    return { ok: false, linked: false, error: e.message }
  }
}

module.exports = {
  plan, apply, enableNginxSite,
  validateHostname, dashboardHostFor,
  caddyConfig, nginxConfig, apacheConfig,
  TARGETS,
}
