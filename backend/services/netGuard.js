
const net = require('net')
const dns = require('dns').promises
const dnsCb = require('dns')

const V4_BLOCKED = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
]

function v4ToInt(ip) {
  return ip.split('.').reduce((acc, o) => ((acc << 8) + Number(o)) >>> 0, 0) >>> 0
}

function v4InBlock(ip, network, bits) {
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0
  return (v4ToInt(ip) & mask) === (v4ToInt(network) & mask)
}

function v6Groups(ip) {
  let addr = ip.split('%')[0]
  addr = addr.replace(/(\d{1,3}(?:\.\d{1,3}){3})$/, v4 => {
    const n = v4ToInt(v4)
    return `${(n >>> 16).toString(16)}:${(n & 0xffff).toString(16)}`
  })
  const [head, tail] = addr.includes('::') ? addr.split('::') : [addr, null]
  const headParts = head ? head.split(':').filter(Boolean) : []
  const tailParts = tail ? tail.split(':').filter(Boolean) : []
  const fill = 8 - headParts.length - tailParts.length
  if (fill < 0) return null
  const parts = [...headParts, ...Array(tail === null ? 0 : fill).fill('0'), ...tailParts]
  if (parts.length !== 8) return null
  return parts.map(p => parseInt(p, 16) & 0xffff)
}

function v6InBlock(groups, prefixHex, bits) {
  const target = v6Groups(prefixHex)
  if (!target) return false
  let remaining = bits
  for (let i = 0; i < 8 && remaining > 0; i++) {
    const take = Math.min(16, remaining)
    const mask = take === 0 ? 0 : (0xffff << (16 - take)) & 0xffff
    if ((groups[i] & mask) !== (target[i] & mask)) return false
    remaining -= take
  }
  return true
}

const V6_BLOCKED = [
  ['::', 96],
  ['::', 128],
  ['::1', 128],
  ['64:ff9b::', 96],
  ['64:ff9b:1::', 48],
  ['100::', 64],
  ['2001:db8::', 32],
  ['2001::', 32],
  ['2002::', 16],
  ['fc00::', 7],
  ['fe80::', 10],
  ['fec0::', 10],
  ['ff00::', 8],
]

// ::ffff:<hex>:<hex> is an IPv4-mapped address in hex dress (::ffff:a00:1 IS
// 10.0.0.1). Only the dotted-tail spelling was unwrapped below, so the hex
// spelling passed every reserved-range check and reached private hosts.
const MAPPED_V4_DOTTED = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i
const MAPPED_V4_HEX = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i

function reasonNotPublic(ip) {
  const family = net.isIP(ip)
  if (family === 0) return 'not a valid IP address'

  if (family === 4) {
    for (const [network, bits] of V4_BLOCKED) {
      if (v4InBlock(ip, network, bits)) return `${ip} is in the reserved range ${network}/${bits}`
    }
    return null
  }

  // An IPv4-mapped literal is judged by its embedded IPv4 address, whatever
  // spelling the tail arrived in.
  const mappedDotted = MAPPED_V4_DOTTED.exec(ip)
  if (mappedDotted) return reasonNotPublic(mappedDotted[1])
  const mappedHex = MAPPED_V4_HEX.exec(ip)
  if (mappedHex) {
    const hi = parseInt(mappedHex[1], 16)
    const lo = parseInt(mappedHex[2], 16)
    return reasonNotPublic(`${(hi >> 8) & 255}.${hi & 255}.${(lo >> 8) & 255}.${lo & 255}`)
  }

  const embedded = /(\d{1,3}(?:\.\d{1,3}){3})$/.exec(ip)
  if (embedded && net.isIP(embedded[1]) === 4) {
    const why = reasonNotPublic(embedded[1])
    if (why) return why
  }

  const groups = v6Groups(ip)
  if (!groups) return `${ip} could not be parsed`
  // Judge the numeric address, not just the compressed ::ffff spelling.
  if (groups.slice(0, 5).every(g => g === 0) && groups[5] === 0xffff) {
    return reasonNotPublic(`${groups[6] >>> 8}.${groups[6] & 255}.${groups[7] >>> 8}.${groups[7] & 255}`)
  }
  for (const [prefix, bits] of V6_BLOCKED) {
    if (v6InBlock(groups, prefix, bits)) return `${ip} is in the reserved range ${prefix}/${bits}`
  }
  return null
}

function isPubliclyRoutable(ip) {
  return reasonNotPublic(ip) === null
}

async function resolvePublicAddresses(hostname) {
  if (typeof hostname !== 'string' || hostname.length === 0 || hostname.length > 253) {
    throw Object.assign(new Error('Invalid hostname.'), { status: 400 })
  }
  if (net.isIP(hostname) !== 0) {
    const why = reasonNotPublic(hostname)
    if (why) throw Object.assign(new Error(`Refusing to connect: ${why}.`), { status: 400 })
    return [hostname]
  }

  let addrs
  try {
    addrs = await dns.lookup(hostname, { all: true, verbatim: true })
  } catch {
    throw Object.assign(new Error(`Could not resolve ${hostname}.`), { status: 400 })
  }
  if (!addrs.length) throw Object.assign(new Error(`Could not resolve ${hostname}.`), { status: 400 })

  for (const { address } of addrs) {
    const why = reasonNotPublic(address)
    if (why) throw Object.assign(new Error(`Refusing to connect: ${hostname} resolves to ${address}, which is not publicly routable.`), { status: 400 })
  }
  return addrs.map(a => a.address)
}

const MAX_REDIRECTS = 3
const ALLOWED_PROTOCOLS = new Set(['https:', 'http:'])

const http = require('http')
const https = require('https')
const zlib = require('zlib')

// ── Anti-rebinding transport ────────────────────────────────────────────
//
// The previous implementation validated DNS and then handed the *hostname*
// to fetch(), which resolved it a second time inside undici — a TOCTOU: DNS
// answering the validation with a public address and the connection with
// 127.0.0.1 would win both halves. The fix is to do ONE resolution through
// our own `lookup` function, validate what came back, and hand only
// validated addresses to the socket. node:http/https call `lookup` exactly
// once per connection, so the validated address is byte-for-byte the
// connected address. TLS SNI and the Host header stay pointed at the
// original hostname.

// Short-lived pin so every hop of a redirect chain re-uses one verdict for
// the same hostname instead of re-resolving (and re-attacking) it.
const PIN_TTL_MS = 10_000
const pinnedCache = new Map() // `${mode}|${hostname}` → { addrs, at }

function resolvePinned(hostname, { allowLoopback }) {
  const key = `${allowLoopback ? 'open' : 'strict'}|${hostname}`
  const hit = pinnedCache.get(key)
  if (hit && Date.now() - hit.at < PIN_TTL_MS) return Promise.resolve(hit.addrs)

  const promise = new Promise((resolve, reject) => {
    // Callback-form lookup (dnsCb, not the promises API) — this function is
    // consumed by net.connect's `lookup` option.
    dnsCb.lookup(hostname, { all: true, verbatim: true }, (err, addrs) => {
      if (err || !addrs || !addrs.length) {
        return reject(Object.assign(new Error(`Could not resolve ${hostname}.`), { status: 400 }))
      }
      if (!allowLoopback) {
        for (const { address } of addrs) {
          const why = reasonNotPublic(address)
          if (why) {
            return reject(Object.assign(new Error(`Refusing to connect: ${hostname} resolves to ${address}, which is not publicly routable.`), { status: 400 }))
          }
        }
      }
      resolve(addrs.map(a => ({ address: a.address, family: a.family })))
    })
  })
  promise.then(
    addrs => {
      if (pinnedCache.size >= 1000) pinnedCache.delete(pinnedCache.keys().next().value)
      pinnedCache.set(key, { addrs, at: Date.now() })
    },
    () => {},
  )
  return promise
}

function makePinnedLookup({ allowLoopback }) {
  return function pinnedLookup(hostname, options, callback) {
    resolvePinned(hostname, { allowLoopback }).then(
      (addrs) => {
        // dns.lookup({all:true}) returns numeric families (4/6), never the
        // 'IPv6' string — labeling an IPv6 address as family 4 makes
        // net.connect fail with EINVAL exactly when the target is
        // AAAA-reachable.
        const norm = addrs.map(a => ({ address: a.address, family: Number(a.family) === 6 ? 6 : 4 }))
        if (options && options.all) callback(null, norm)
        else process.nextTick(callback, null, norm[0].address, norm[0].family)
      },
      err => process.nextTick(callback, err),
    )
  }
}

function readBody(res, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let total = 0
    res.on('data', (chunk) => {
      total += chunk.length
      if (total > maxBytes) {
        res.destroy()
        return reject(Object.assign(new Error(`Response body exceeded ${maxBytes} bytes.`), { status: 502 }))
      }
      chunks.push(chunk)
    })
    res.on('end', () => resolve(Buffer.concat(chunks)))
    res.on('error', reject)
  })
}

const MAX_INFLATED_BYTES = 64 * 1024 * 1024

function maybeDecompress(buf, encoding) {
  const enc = String(encoding || '').toLowerCase()
  const opts = { maxOutputLength: MAX_INFLATED_BYTES }
  try {
    if (enc === 'gzip') return zlib.gunzipSync(buf, opts)
    if (enc === 'deflate') {
      // Servers disagree on what "deflate" means: try zlib-wrapped first,
      // then the raw stream many of them actually send.
      try { return zlib.inflateSync(buf, opts) } catch { return zlib.inflateRawSync(buf, opts) }
    }
    if (enc === 'br') return zlib.brotliDecompressSync(buf, opts)
  } catch (e) {
    // A bomb or corrupt stream must not balloon memory or crash the caller:
    // give back nothing rather than compressed garbage dressed as text.
    if (/output length|unexpected/i.test(e.message)) {
      throw Object.assign(new Error(`Compressed response exceeded ${MAX_INFLATED_BYTES} bytes.`), { status: 502 })
    }
    return buf
  }
  return buf
}

// Minimal Response surface: every guardedFetch consumer uses only
// ok/status/headers.get/text()/json(). Content-encoding is handled here
// because node:http does not auto-decompress the way undici does.
function shimResponse(status, resHeaders, bodyBuf) {
  const headerMap = new Map()
  for (const [name, value] of Object.entries(resHeaders)) {
    headerMap.set(String(name).toLowerCase(), Array.isArray(value) ? value.join(', ') : String(value))
  }
  const text = () => Promise.resolve(maybeDecompress(bodyBuf, headerMap.get('content-encoding')).toString('utf8'))
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: name => headerMap.get(String(name).toLowerCase()) ?? null },
    text,
    json: async () => {
      const raw = (await text()).trim()
      if (!raw) throw new Error('Empty response body.')
      return JSON.parse(raw)
    },
  }
}

function requestOnce(urlObj, { method, headers, body, timeoutMs, allowLoopback }) {
  return new Promise((resolve, reject) => {
    const isTls = urlObj.protocol === 'https:'
    const sendHeaders = { ...headers }
    let payload = null
    if (body != null) {
      payload = Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8')
      if (!Object.keys(sendHeaders).some(k => k.toLowerCase() === 'content-length')) {
        sendHeaders['content-length'] = String(payload.length)
      }
    }
    if (!Object.keys(sendHeaders).some(k => k.toLowerCase() === 'host')) {
      sendHeaders.host = urlObj.host
    }

    const req = (isTls ? https : http).request({
      host: urlObj.hostname.replace(/^\[|\]$/g, ''),
      port: urlObj.port || (isTls ? 443 : 80),
      path: `${urlObj.pathname}${urlObj.search}`,
      method,
      headers: sendHeaders,
      servername: isTls ? urlObj.hostname : undefined,
      lookup: makePinnedLookup({ allowLoopback }),
      signal: AbortSignal.timeout(timeoutMs),
    }, (res) => {
      // Buffer immediately so redirect hops can drain-and-discard while the
      // final caller receives the full body.
      resolve({ res, bufferPromise: readBody(res, 64 * 1024 * 1024) })
    })

    req.on('error', err => reject(err))
    if (payload != null) req.write(payload)
    req.end()
  })
}

async function guardedFetch(rawUrl, { timeoutMs = 8000, method = 'GET', headers = {}, body = null, allowLoopback = false } = {}) {
  let url
  try { url = new URL(rawUrl) } catch { throw Object.assign(new Error('Invalid URL.'), { status: 400 }) }

  // Integrations whose documented target is a host-local daemon (the local
  // threat-feed bouncer API, self-hosted mCaptcha) are unreachable under the
  // private-range guard — and "publish your internal service publicly to
  // make this work" is worse than the risk being prevented. allowLoopback
  // opts in per request: resolution happens normally but results are not
  // rejected for being private or reserved. That is an explicit operator
  // trust decision about one configured endpoint — only point it at a daemon
  // you control. Callers without the flag keep full strictness.

  // Redirects can change the method out from under us, so both travel
  // through the hop loop together rather than being captured once.
  let sendMethod = method
  let sendBody = body
  let sendHeaders = headers

  const visited = []
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    if (!ALLOWED_PROTOCOLS.has(url.protocol)) {
      throw Object.assign(new Error(`Refusing to follow a ${url.protocol} URL.`), { status: 400 })
    }
    visited.push(url.toString())

    // One resolution, one verdict, one connection. The lookup passed to the
    // request returns only addresses this module has already judged, so the
    // socket cannot land anywhere else even if DNS changes between here and
    // connect().
    if (url.username || url.password) throw Object.assign(new Error('URL credentials are not supported.'), { status: 400 })
    await resolvePinned(url.hostname.replace(/^\[|\]$/g, ''), { allowLoopback })

    const { res, bufferPromise } = await requestOnce(url, {
      method: sendMethod,
      headers: sendHeaders,
      body: sendBody,
      timeoutMs,
      allowLoopback,
    })

    const location = res.headers.location
    if (![301, 302, 303, 307, 308].includes(res.statusCode) || !location) {
      const buffered = await bufferPromise
      res.destroy()
      return { response: shimResponse(res.statusCode, res.headers, buffered), chain: visited }
    }
    // Redirect bodies are never used — discard the stream outright so a
    // huge redirect payload cannot pin memory across the hop, and swallow
    // the abandoned read's rejection.
    bufferPromise.catch(() => {})
    res.destroy()
    const previous = url
    try { url = new URL(location, url) } catch {
      throw Object.assign(new Error('Redirect target is not a valid URL.'), { status: 400 })
    }

    if (previous.protocol === 'https:' && url.protocol !== 'https:') {
      throw Object.assign(new Error('Refusing an HTTPS downgrade redirect.'), { status: 400 })
    }
    if (url.origin !== previous.origin) {
      const publicHeaders = new Set(['accept', 'accept-encoding', 'user-agent'])
      if (allowLoopback || sendBody != null || Object.keys(sendHeaders).some(k => !publicHeaders.has(k.toLowerCase()))) {
        throw Object.assign(new Error('Refusing to forward an integration request to another origin.'), { status: 400 })
      }
      sendHeaders = Object.fromEntries(Object.entries(sendHeaders).filter(([k]) => publicHeaders.has(k.toLowerCase())))
    }

    // 307/308 preserve the method and body; 301/302/303 degrade to a bodyless
    // GET, which is what browsers do and what keeps a secret-bearing POST body
    // from being replayed to a redirect target.
    if (res.statusCode !== 307 && res.statusCode !== 308) {
      sendMethod = 'GET'
      if (sendBody != null) {
        sendBody = null
        sendHeaders = Object.fromEntries(
          Object.entries(sendHeaders).filter(([k]) => !['content-type', 'content-length', 'transfer-encoding'].includes(k.toLowerCase())),
        )
      }
    }
  }
  throw Object.assign(new Error(`Too many redirects (more than ${MAX_REDIRECTS}).`), { status: 400 })
}

module.exports = {
  isPubliclyRoutable,
  reasonNotPublic,
  resolvePublicAddresses,
  guardedFetch,
  MAX_REDIRECTS,
  // Test-only surface: lets the suite drive the pinned lookup directly to
  // prove it never delivers an unjudged address.
  _test: { makePinnedLookup },
}
