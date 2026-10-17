
const express = require('express')
const fs = require('fs')
const path = require('path')
const { execFileSync } = require('child_process')
const netGuard = require('../services/netGuard')
const router = express.Router()
const auditSvc = require('../services/audit')
const cloudflareSvc = require('../services/cloudflare')
const caddySvc = require('../services/caddy')
const configLock = require('../services/configLock')
const { writeRequired } = require('../middleware/auth')

const ZONE_ID_RE = /^[a-f0-9]{32}$/i
function isValidZoneId(id) { return typeof id === 'string' && ZONE_ID_RE.test(id) }
function isValidRecordId(id) { return typeof id === 'string' && ZONE_ID_RE.test(id) }

const HOSTNAME_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i
function isValidHostname(h) { return typeof h === 'string' && h.length <= 253 && HOSTNAME_RE.test(h) }

router.post('/api/cloudflare/zones', writeRequired, async (req, res) => {
  const { token } = req.body || {}
  if (!token) return res.status(400).json({ detail: 'token required' })
  try {
    await cloudflareSvc.cfFetch('/user/tokens/verify', token)
    const data = await cloudflareSvc.cfFetch('/zones?per_page=50', token)
    cloudflareSvc.CF_STORE.token = token
    auditSvc.audit(req, 'cloudflare.zones.list', '', { count: data.result?.length || 0 })
    res.json({
      zones: (data.result || []).map(z => ({
        id: z.id, name: z.name, status: z.status,
        plan: z.plan?.name, nameservers: z.name_servers,
      })),
    })
  } catch (e) {
    res.status(e.status === 403 || e.status === 401 ? 401 : 500).json({ detail: e.message })
  }
})

router.post('/api/cloudflare/verify-dns', writeRequired, async (req, res) => {
  const { token, zone_id } = req.body || {}
  if (!token || !zone_id) return res.status(400).json({ detail: 'token and zone_id required' })
  if (!isValidZoneId(zone_id)) return res.status(400).json({ detail: 'zone_id must be a valid Cloudflare zone ID' })
  try {
    const data = await cloudflareSvc.cfFetch(`/zones/${zone_id}/dns_records?type=A&per_page=50`, token)
    const records = (data.result || []).map(r => ({
      id: r.id, type: r.type, name: r.name, content: r.content, proxied: r.proxied,
    }))
    if (records.length) cloudflareSvc.CF_STORE.record_id = records[0].id
    auditSvc.audit(req, 'cloudflare.verify-dns', zone_id, { found: records.length })
    res.json({
      message: records.length ? `Found ${records.length} A record(s)` : 'No A records found — add one in Cloudflare DNS first',
      records,
    })
  } catch (e) { res.status(500).json({ detail: e.message }) }
})

router.post('/api/cloudflare/enable-proxy', writeRequired, async (req, res) => {
  const { token, zone_id, record_id } = req.body || {}
  const rid = record_id || cloudflareSvc.CF_STORE.record_id
  if (!token || !zone_id) return res.status(400).json({ detail: 'token and zone_id required' })
  if (!isValidZoneId(zone_id)) return res.status(400).json({ detail: 'zone_id must be a valid Cloudflare zone ID' })
  if (!rid) return res.status(400).json({ detail: 'No DNS record found — run "Verify DNS" first' })
  if (!isValidRecordId(rid)) return res.status(400).json({ detail: 'record_id must be a valid Cloudflare record ID' })
  try {
    const data = await cloudflareSvc.cfFetch(`/zones/${zone_id}/dns_records/${rid}`, token, {
      method: 'PATCH',
      body: JSON.stringify({ proxied: true }),
    })
    cloudflareSvc.CF_STORE.zone_id = zone_id
    auditSvc.audit(req, 'cloudflare.enable-proxy', zone_id, { record: rid })
    res.json({ message: 'Orange cloud proxy enabled — your origin IP is now hidden', record: data.result })
  } catch (e) { res.status(500).json({ detail: e.message }) }
})

router.post('/api/cloudflare/ssl-strict', writeRequired, async (req, res) => {
  const { token, zone_id } = req.body || {}
  if (!token || !zone_id) return res.status(400).json({ detail: 'token and zone_id required' })
  if (!isValidZoneId(zone_id)) return res.status(400).json({ detail: 'zone_id must be a valid Cloudflare zone ID' })
  try {
    const data = await cloudflareSvc.cfFetch(`/zones/${zone_id}/settings/ssl`, token, {
      method: 'PATCH',
      body: JSON.stringify({ value: 'strict' }),
    })
    auditSvc.audit(req, 'cloudflare.ssl-strict', zone_id)
    res.json({ message: 'SSL mode set to Full (Strict)', value: data.result?.value })
  } catch (e) { res.status(500).json({ detail: e.message }) }
})

router.post('/api/cloudflare/gen-cert', writeRequired, async (req, res) => {
  const { token, zone_id, hostnames } = req.body || {}
  if (!token || !zone_id) return res.status(400).json({ detail: 'token and zone_id required' })
  if (!isValidZoneId(zone_id)) return res.status(400).json({ detail: 'zone_id must be a valid Cloudflare zone ID' })
  try {
    const zone = await cloudflareSvc.cfFetch(`/zones/${zone_id}`, token)
    const domain = zone.result?.name
    if (!isValidHostname(domain)) return res.status(502).json({ detail: 'Cloudflare returned an unexpected zone name.' })
    const requested = Array.isArray(hostnames) ? hostnames.filter(h => typeof h === 'string') : []
    for (const h of requested) {
      if (!isValidHostname(h.replace(/^\*\./, ''))) return res.status(400).json({ detail: `"${h}" is not a valid hostname.` })
    }
    const hosts = requested.length ? requested : [domain, `*.${domain}`]

    const fs = require('fs')
    const certDir = path.join(require('../services/db').DB_DIR, 'certs')
    fs.mkdirSync(certDir, { recursive: true, mode: 0o700 })
    // Unique names prevent concurrent requests from pairing a certificate
    // with a different private key. Reserve the key with restrictive mode.
    const certName = `${zone_id}-${require('crypto').randomBytes(12).toString('hex')}`
    const keyPath = path.join(certDir, `${certName}.key`)
    const csrPath = path.join(certDir, `${certName}.csr`)
    fs.closeSync(fs.openSync(keyPath, 'wx', 0o600))
    execFileSync('openssl', [
      'req', '-new', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', keyPath,
      '-subj', `/CN=${domain}`,
      '-out', csrPath,
    ], { stdio: 'pipe', timeout: 15000 })
    const csr = fs.readFileSync(csrPath, 'utf8')

    const data = await cloudflareSvc.cfFetch('/certificates', token, {
      method: 'POST',
      body: JSON.stringify({
        hostnames: hosts,
        requested_validity: 5475,
        request_type: 'origin-rsa',
        csr,
      }),
    })

    const certPath = path.join(certDir, `${certName}.pem`)
    // Private-key material must not be world-readable regardless of umask.
    fs.writeFileSync(certPath, data.result.certificate, { mode: 0o644 })
    try { fs.chmodSync(keyPath, 0o600) } catch {}
    auditSvc.audit(req, 'cloudflare.gen-cert', zone_id, { hostnames: hosts })
    res.json({
      message: 'Origin certificate generated and saved to data/certs/',
      cert_path: certPath, key_path: keyPath,
      expires_on: data.result.expires_on,
    })
  } catch (e) { res.status(500).json({ detail: e.message }) }
})

router.post('/api/cloudflare/lock-origin', writeRequired, async (req, res) => {
  const { token } = req.body || {}
  try {
    const fs = require('fs')
    const [v4, v6] = await Promise.all([
      fetch('https://www.cloudflare.com/ips-v4', { signal: AbortSignal.timeout(10000) }).then(r => r.text()),
      fetch('https://www.cloudflare.com/ips-v6', { signal: AbortSignal.timeout(10000) }).then(r => r.text()),
    ])
    // These lists come from the network and land verbatim inside a Caddy
    // matcher. A hijacked or manipulated response containing newlines,
    // quotes or braces would inject arbitrary Caddy directives into the
    // live config — so every entry must be exactly an IP or CIDR, or the
    // whole lock is refused.
    const { isValidIpOrCidr } = require('../services/sanitize')
    const ranges = [...v4.trim().split('\n'), ...v6.trim().split('\n')]
      .map(l => l.trim()).filter(Boolean)
    if (!ranges.length) return res.status(502).json({ detail: 'Cloudflare returned no IP ranges — refusing to build an empty origin lock.' })
    if (!ranges.every(r => isValidIpOrCidr(r))) {
      return res.status(502).json({ detail: 'Cloudflare returned a malformed IP range — refusing to write it into the Caddyfile.' })
    }

    const block = [
      '# @@CATWAF_CF_LOCK_START@@',
      `  @not_cloudflare not remote_ip ${ranges.join(' ')}`,
      '  handle @not_cloudflare {',
      '    respond "Direct access denied — use the proxied domain" 403',
      '  }',
      '# @@CATWAF_CF_LOCK_END@@',
    ].join('\n')

    const outcome = configLock.withConfigLock(() => {
    let content = fs.readFileSync(caddySvc.CADDYFILE_PATH, 'utf8')
    if (content.includes('@@CATWAF_CF_LOCK_START@@')) {
      content = content.replace(/# @@CATWAF_CF_LOCK_START@@[\s\S]*?# @@CATWAF_CF_LOCK_END@@/, block)
    } else {
      // Anchor on the last site block's closing brace, the same way
      // services/caddy.js places the WAF block — so the origin lock always
      // lands in the site CatWAF is protecting. The old code searched for the
      // literal string ':8081', which was only ever the starter Caddyfile's
      // own port: any other port made indexOf() return -1 (and a negative
      // fromIndex is clamped to 0, silently anchoring at the top of the
      // file), and now that :8081 is the admin dashboard it would have
      // matched the control panel's block instead of the protected site's.
      const idx = caddySvc.lastSiteBlockClose(content)
      if (idx === -1) {
        return res.status(400).json({
          detail: 'This Caddyfile has no site block to lock — add the block for the site you are protecting first.',
        })
      }
      content = content.slice(0, idx) + block + '\n' + content.slice(idx)
    }
    // The read-modify-write above and the reload below run under the same
    // config lock every other Caddyfile writer uses, and the write itself is
    // atomic — a concurrent CLI patch can no longer be clobbered here.
    const tx = require('../services/configTx').apply({ label: 'cloudflare.lock-origin', req, caddyfile: content, render: false, mutate: () => {} })
    if (!tx.ok) return res.status(500).json({ detail: tx.error, rolledBack: tx.rolledBack, recoveryRequired: tx.recoveryRequired })
    const { reloaded, reloadError: reloadErr } = tx

    auditSvc.audit(req, 'cloudflare.lock-origin', '', { ranges: ranges.length, reloaded })
    res.json({
      message: reloaded
        ? `Origin firewall updated — only ${ranges.length} Cloudflare IP ranges allowed`
        : 'Caddyfile updated but reload failed — run "caddy reload" manually',
      ranges_applied: ranges.length, reloaded, reload_error: reloadErr,
    })
    })
    return outcome
  } catch (e) { res.status(500).json({ detail: e.message }) }
})

router.post('/api/cloudflare/test', writeRequired, async (req, res) => {
  const { token, zone_id } = req.body || {}
  if (zone_id && !isValidZoneId(zone_id)) return res.status(400).json({ detail: 'zone_id must be a valid Cloudflare zone ID' })
  const checks = {}
  try {
    let domain = null
    if (token && zone_id) {
      try { const z = await cloudflareSvc.cfFetch(`/zones/${zone_id}`, token); domain = z.result?.name } catch {}
    }

    if (domain && !isValidHostname(domain)) domain = null

    if (domain) {
      try {
        const { response: r } = await netGuard.guardedFetch(`https://${domain}`, { method: 'HEAD', timeoutMs: 8000 })
        checks['Domain reachable over HTTPS'] = r.ok || r.status < 500
        checks['Served by Cloudflare'] = (r.headers.get('server') || '').toLowerCase().includes('cloudflare')
      } catch { checks['Domain reachable over HTTPS'] = false; checks['Served by Cloudflare'] = false }

      try {
        const dns = await cloudflareSvc.cfFetch(`/zones/${zone_id}/dns_records?type=A&per_page=1`, token)
        checks['DNS proxy (orange cloud) enabled'] = !!dns.result?.[0]?.proxied
      } catch { checks['DNS proxy (orange cloud) enabled'] = false }

      try {
        const ssl = await cloudflareSvc.cfFetch(`/zones/${zone_id}/settings/ssl`, token)
        checks['SSL mode is Full/Strict'] = ['full', 'strict'].includes(ssl.result?.value)
      } catch { checks['SSL mode is Full/Strict'] = false }
    } else {
      checks['Cloudflare token/zone provided'] = false
    }

    checks['Origin firewall rule active'] = (() => {
      try { return require('fs').readFileSync(caddySvc.CADDYFILE_PATH, 'utf8').includes('@@CATWAF_CF_LOCK_START@@') }
      catch { return false }
    })()

    auditSvc.audit(req, 'cloudflare.test', zone_id || '', checks)
    const allPass = Object.values(checks).every(Boolean)
    res.json({ message: allPass ? 'All checks passed' : 'Some checks failed — review below', checks })
  } catch (e) { res.status(500).json({ detail: e.message }) }
})

module.exports = router
