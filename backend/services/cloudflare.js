
const CF_BASE = 'https://api.cloudflare.com/client/v4'
const CF_STORE = { token: null, zone_id: null, record_id: null }

async function cfFetch(path, token, opts = {}) {
  const res = await fetch(`${CF_BASE}${path}`, {
    ...opts,
    redirect: 'error',
    signal: opts.signal || AbortSignal.timeout(15000),
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
      ...(opts.headers || {}),
    },
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok || data.success === false) {
    const msg = data?.errors?.[0]?.message || `Cloudflare API error (${res.status})`
    const err = new Error(msg)
    err.status = res.status
    err.cfErrors = data?.errors
    throw err
  }
  return data
}

// Cloudflare's published edge ranges. CatWAF's Cloudflare integration used
// to be the only place that knew traffic could legitimately arrive from
// somewhere other than the real client — the real-IP setting (idea #16)
// generalises that, and treats Cloudflare as one preset of the general
// "trusted upstream proxy" mechanism rather than a special case.
//
// Shipped statically so the preset works before any Cloudflare credentials
// are configured; refreshRanges() replaces them from the published list when
// the network is reachable.
const CF_STATIC_RANGES = [
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
  '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
  '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
  '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
  '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
  '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
]

let cfRanges = null

function edgeRanges() {
  return cfRanges || CF_STATIC_RANGES
}

async function refreshRanges({ timeoutMs = 8000 } = {}) {
  const { isValidIpOrCidr } = require('./sanitize')
  const out = []
  for (const url of ['https://www.cloudflare.com/ips-v4', 'https://www.cloudflare.com/ips-v6']) {
    const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) })
    if (!res.ok) throw new Error(`Cloudflare returned ${res.status} for ${url}`)
    const body = await res.text()
    for (const line of body.split('\n')) {
      const cidr = line.trim()
      if (cidr && isValidIpOrCidr(cidr)) out.push(cidr)
    }
  }
  if (!out.length) throw new Error('Cloudflare returned an empty range list')
  cfRanges = out
  return { ok: true, count: out.length, ranges: out }
}

module.exports = { CF_BASE, CF_STORE, cfFetch, edgeRanges, refreshRanges, CF_STATIC_RANGES }
