// render/site.js — everything CatWAF emits *inside* a protected site block.
//
// Ordering note: Caddy sorts most directives by its own fixed order, not by
// file order, with one exception that matters here — `handle` blocks are
// mutually exclusive and evaluated top to bottom. So every interception
// CatWAF performs (method rejection, the challenge endpoints, robots.txt,
// a static/PHP origin) is expressed as a `handle`, emitted in priority
// order, which also means a non-matching request still falls through to
// whatever `reverse_proxy` the operator wrote by hand.
//
// A renderer that cannot emit its directive (missing Caddy module, missing
// prerequisite) pushes onto `skipped` rather than emitting something the
// binary would reject: `caddy validate` fails the entire file, so one
// unavailable optional feature must never be able to take the site down.

const caddyModules = require('../caddyModules')
const wellknown = require('../wellknown')
const { q, indent, dur, writeAsset, escapeRegex, m, block } = require('./util')

const TLS_PROFILES = {
  modern: {
    protocols: ['tls1.3'],
    ciphers: [],
    curves: ['x25519', 'secp384r1'],
  },
  intermediate: {
    protocols: ['tls1.2', 'tls1.3'],
    ciphers: [
      'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
      'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
      'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
      'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
      'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305',
      'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305',
    ],
    curves: ['x25519', 'secp256r1', 'secp384r1'],
  },
  compatible: {
    protocols: ['tls1.2', 'tls1.3'],
    ciphers: [],
    curves: ['x25519', 'secp256r1', 'secp384r1'],
  },
}

const ACME_DIRECTORIES = {
  letsencrypt: 'https://acme-v02.api.letsencrypt.org/directory',
  zerossl: 'https://acme.zerossl.com/v2/DV90',
}

function ctxOf(overrides = {}) {
  const settings = overrides.settings || require('../settings')
  return {
    get: group => settings.get(group),
    upstreams: overrides.upstreams || [],
    tlsCapable: overrides.tlsCapable !== false,
    backend: overrides.backend || null,
    waf: overrides.waf || null,
  }
}

// ─── #57 method allowlist ───────────────────────────────────────────────
function methodGuard(ctx, out) {
  const a = ctx.get('access')
  if (!a.enforce_method_allowlist || !a.allowed_methods.length) return
  out.matchers.push(`${m('method_denied')} not method ${a.allowed_methods.join(' ')}`)
  out.handles.push({
    priority: 10,
    lines: block(`handle ${m('method_denied')}`, [`error ${a.method_reject_status}`]),
  })
  out.notes.push(`Only ${a.allowed_methods.join(', ')} are accepted; anything else gets ${a.method_reject_status}.`)
}

// ─── #1-#4 challenge gate endpoints ─────────────────────────────────────
function challengeRoutes(ctx, out) {
  const c = ctx.get('challenge')
  if (c.mode === 'off') return
  if (!ctx.backend) {
    out.skipped.push({ feature: 'challenge', reason: 'CatWAF\'s own API address is unknown, so the challenge endpoints cannot be routed.' })
    return
  }
  out.handles.push({
    priority: 20,
    lines: block('handle /catwaf-challenge*', [
      `reverse_proxy ${q(ctx.backend)} {`,
      ...indent([
        'header_up X-CatWAF-Challenge 1',
        `header_up X-CatWAF-Challenge-Key ${q(require('../secrets').derive('challenge-key'))}`,
        // The backend keys challenges, attempt counters and solved-token
        // bindings to the address these headers carry. Both are overwritten
        // here because a visitor can set either freely — trusting them
        // unedited would let a banned visitor rotate identity per request.
        'header_up X-Real-IP {http.request.remote.host}',
        'header_up X-CatWAF-Client-IP {http.request.remote.host}',
      ], 1),
      '}',
    ]),
  })
  out.notes.push(`Unverified visitors are redirected to /catwaf-challenge (${c.mode}).`)
}

// ─── Runtime enforcement hop (ideas #1-#13) ─────────────────────────────
//
// Coraza cannot call out to CatWAF, so the signals that need a live decision
// reach the request path through a `forward_auth` hop into CatWAF's own API.
// Rendered only when at least one of those features is switched on, so an
// install using none of them adds no hop and no latency.
function enforcementGate(ctx, out) {
  const enforce = require('../enforce')
  if (!enforce.isActive()) return
  if (!ctx.backend) {
    out.skipped.push({ feature: 'enforcement', reason: 'CatWAF\'s own API address is unknown, so live threat-intel enforcement cannot be wired into the request path.' })
    return
  }

  const secrets = require('../secrets')
  const lines = [
    `uri ${q('/api/enforce')}`,
    // Shared secret so the enforcement endpoint is only usable by this
    // instance's own Caddy, not by anything else that can reach the port.
    `header_up X-CatWAF-Enforce-Key ${q(secrets.derive('enforce-key'))}`,
    // forward_auth proxies the visitor's original request, original headers
    // included — and X-Real-IP / X-CatWAF-Client-IP are visitor-settable.
    // Overwrite both with the real connection address or every ban,
    // allowlist hit and fingerprint decision below keys off an address the
    // visitor chose (and bans land on whoever the visitor named).
    `header_up X-Real-IP {http.request.remote.host}`,
    `header_up X-CatWAF-Client-IP {http.request.remote.host}`,
    `copy_headers ${q('X-CatWAF-Verdict')}`,
    // Classification has a 2.5s signal deadline. Bound the transport too:
    // a stopped or wedged API must not leave visitor requests waiting for
    // Caddy's otherwise unbounded response-header timeout. Keep failures
    // closed so an outage cannot silently bypass an enabled challenge/ban.
    ...block('transport http', [
      'dial_timeout 1s',
      'response_header_timeout 5s',
      // Let the response-header deadline fire first. Equal read/header
      // deadlines can turn a reused-connection read timeout into a retry
      // inside Go's HTTP transport, doubling the visitor's wait.
      'read_timeout 6s',
      'write_timeout 5s',
    ]),
  ]
  // The challenge endpoints must not themselves be gated, or a challenged
  // visitor could never reach the page that would clear the challenge.
  out.matchers.push(`${m('enforce')} not path ${q('/catwaf-challenge*')}`)
  out.directives.push(...block(`forward_auth ${m('enforce')} ${q(ctx.backend)}`, lines))
  out.notes.push(`Live enforcement is active for: ${enforce.activeFeatures().join(', ')}.`)
}

// ─── Upload malware scanning ────────────────────────────────────────────
//
// Scanning needs the request body, and the forward_auth hop above only
// carries headers. So for the nominated upload paths — and only those —
// Caddy proxies to CatWAF, which scans the body and forwards it onward to
// the same upstream the site would have used. Every other request still goes
// straight to the origin, so the data-path cost is confined to uploads.
function uploadScanGate(ctx, out) {
  const cfg = ctx.get('upload_scan')
  if (!cfg.enabled) return
  if (!cfg.paths.length || !cfg.methods.length) return

  if (!ctx.backend) {
    out.skipped.push({ feature: 'upload_scan', reason: 'CatWAF\'s own API address is unknown, so uploads cannot be routed through the scanner.' })
    return
  }
  // The scanner has to hand the request on to somewhere; with no upstream in
  // the block there is nothing to forward to, and emitting the gate anyway
  // would black-hole every upload.
  if (!ctx.upstreams.length) {
    out.skipped.push({ feature: 'upload_scan', reason: 'No reverse_proxy upstream was found in the protected site block, so scanned uploads would have nowhere to go.' })
    return
  }

  const secrets = require('../secrets')
  const upstream = String(ctx.upstreams[0]).replace(/^[a-z0-9]+:\/\//, '')

  out.matchers.push(...block(m('uploadscan'), [
    `path ${cfg.paths.map(q).join(' ')}`,
    `method ${cfg.methods.map(p => String(p).toUpperCase()).join(' ')}`,
  ]))

  out.handles.push({
    priority: 45,
    lines: block(`handle ${m('uploadscan')}`, block(`reverse_proxy ${q(ctx.backend)}`, [
      `header_up X-CatWAF-Upload-Key ${q(secrets.derive('upload-gate-key'))}`,
      `header_up X-CatWAF-Upload-Upstream ${q(upstream)}`,
      'header_up X-CatWAF-Upload-Path {http.request.uri}',
      // Bans raised by the upload scanner key off the client address these
      // headers carry — overwrite them so a visitor cannot aim a malware
      // ban at someone else's address.
      'header_up X-Real-IP {http.request.remote.host}',
      'header_up X-CatWAF-Client-IP {http.request.remote.host}',
      // The gate lives at a fixed path, so the original URI travels in the
      // header above and is restored when the request is forwarded on.
      `rewrite ${q('/api/upload-gate')}`,
      // Uploads are large and the scan is synchronous, so this hop needs a
      // longer read window than a normal proxied request.
      ...block('transport http', [
        'dial_timeout 10s',
        'read_timeout 180s',
        'write_timeout 180s',
      ]),
    ])),
  })
  out.notes.push(`Uploads to ${cfg.paths.join(', ')} are scanned for malware before reaching ${upstream}.`)
}

// ─── #40 robots.txt / #41 security.txt ──────────────────────────────────
function wellKnownFiles(ctx, out) {
  const robots = wellknown.buildRobotsTxt()
  if (robots) {
    const path = writeAsset('www/robots.txt', robots, { mode: 0o644 })
    out.handles.push({
      priority: 30,
      lines: block('handle /robots.txt', [`root * ${q(require('path').dirname(path))}`, 'file_server']),
    })
  }

  const check = wellknown.validateSecurityTxt()
  const security = wellknown.buildSecurityTxt()
  if (security) {
    const path = writeAsset('www/.well-known/security.txt', security, { mode: 0o644 })
    const root = require('path').dirname(require('path').dirname(path))
    out.handles.push({
      priority: 31,
      lines: block('handle /.well-known/security.txt', [`root * ${q(root)}`, 'file_server']),
    })
  } else if (ctx.get('security_txt').enabled && !check.ok) {
    out.skipped.push({ feature: 'security_txt', reason: check.errors.join(' ') })
  }
}

// ─── #35 CORS ───────────────────────────────────────────────────────────
function cors(ctx, out) {
  const c = ctx.get('cors')
  if (!c.enabled) return
  if (!c.allow_any_origin && !c.allow_origins.length) {
    out.skipped.push({ feature: 'cors', reason: 'No allowed origins configured.' })
    return
  }
  if (c.allow_any_origin && c.allow_credentials) {
    out.skipped.push({ feature: 'cors', reason: 'Browsers reject "allow any origin" combined with credentials — pick one.' })
    return
  }

  const headerLines = []
  if (c.allow_any_origin) {
    headerLines.push(`Access-Control-Allow-Origin ${q('*')}`)
  } else {
    // Echo the request's own Origin so the response is valid for whichever
    // allowed origin actually made the call, and vary on it so a shared
    // cache cannot serve one origin's response to another.
    headerLines.push(`Access-Control-Allow-Origin ${q('{http.request.header.Origin}')}`)
    headerLines.push(`Vary ${q('Origin')}`)
  }
  headerLines.push(`Access-Control-Allow-Methods ${q(c.allow_methods.join(', '))}`)
  if (c.allow_headers.length) headerLines.push(`Access-Control-Allow-Headers ${q(c.allow_headers.join(', '))}`)
  if (c.expose_headers.length) headerLines.push(`Access-Control-Expose-Headers ${q(c.expose_headers.join(', '))}`)
  if (c.allow_credentials) headerLines.push(`Access-Control-Allow-Credentials ${q('true')}`)
  headerLines.push(`Access-Control-Max-Age ${q(String(c.max_age_sec))}`)

  if (c.allow_any_origin) {
    out.directives.push(...block('header', headerLines))
  } else {
    out.matchers.push(`${m('cors_ok')} {`)
    for (const origin of c.allow_origins) out.matchers.push(`    header Origin ${q(origin)}`)
    out.matchers.push('}')
    out.directives.push(...block(`header ${m('cors_ok')}`, headerLines))

    if (c.on_failure === 'deny') {
      out.matchers.push(`${m('cors_bad')} {`)
      out.matchers.push(`    header Origin ${q('*')}`)
      for (const origin of c.allow_origins) out.matchers.push(`    not header Origin ${q(origin)}`)
      out.matchers.push('}')
      out.handles.push({
        priority: 40,
        lines: block(`handle ${m('cors_bad')}`, [`error ${ctx.get('access').blocked_status_code}`]),
      })
    }
  }

  // Preflights must be answered by the edge, not forwarded to a backend
  // that may not implement OPTIONS at all.
  out.matchers.push(`${m('cors_preflight')} method OPTIONS`)
  out.handles.push({ priority: 41, lines: block(`handle ${m('cors_preflight')}`, ['respond 204']) })
}

// ─── #34 security headers ───────────────────────────────────────────────
function securityHeaders(ctx, out) {
  const h = ctx.get('headers')
  if (h.preset === 'off') return

  const lines = []
  const set = (name, value) => { if (value !== '' && value != null) lines.push(`${name} ${q(value)}`) }

  const strict = h.preset === 'strict'

  if (h.hsts_max_age > 0) {
    let hsts = `max-age=${h.hsts_max_age}`
    if (h.hsts_include_subdomains) hsts += '; includeSubDomains'
    if (h.hsts_preload) hsts += '; preload'
    set('Strict-Transport-Security', hsts)
  }
  if (h.x_content_type_options) set('X-Content-Type-Options', 'nosniff')
  set('X-Frame-Options', h.x_frame_options)
  set('Referrer-Policy', h.referrer_policy)
  set('X-DNS-Prefetch-Control', h.x_dns_prefetch_control)
  set('Permissions-Policy', h.permissions_policy || (strict ? 'geolocation=(), microphone=(), camera=(), payment=()' : ''))
  set('Content-Security-Policy', h.csp || (strict ? "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'" : ''))
  set('Content-Security-Policy-Report-Only', h.csp_report_only)
  set('Cross-Origin-Opener-Policy', h.coop || (strict ? 'same-origin' : ''))
  set('Cross-Origin-Embedder-Policy', h.coep)
  set('Cross-Origin-Resource-Policy', h.corp || (strict ? 'same-origin' : ''))

  for (const custom of h.custom) {
    if (!custom.name) continue
    lines.push(`${custom.replace ? '' : '+'}${custom.name} ${q(custom.value)}`)
  }
  for (const name of h.remove_headers) lines.push(`-${name}`)

  out.directives.push(...block('header', lines))
  if (lines.length) out.notes.push(`${lines.length} response header rule(s) applied (${h.preset} preset).`)
}

// ─── #36 cookie flags ───────────────────────────────────────────────────
function cookieFlags(ctx, out) {
  const c = ctx.get('cookies')
  if (!c.enabled) return

  const flags = []
  if (c.secure === 'always') flags.push('Secure')
  else if (c.secure === 'auto') flags.push('Secure') // only rendered on the TLS-serving site
  if (c.http_only) flags.push('HttpOnly')
  if (c.same_site) flags.push(`SameSite=${c.same_site}`)
  if (!flags.length) return

  const suffix = `; ${flags.join('; ')}`
  const lines = [
    // Strip any flag the backend already set, so a cookie cannot end up with
    // the same attribute twice with conflicting values.
    `Set-Cookie ${q('(?i);\\s*(?:Secure|HttpOnly|SameSite=(?:Strict|Lax|None))\\b')} ${q('')}`,
    `Set-Cookie ${q('^(.*)$')} ${q(`$1${suffix}`)}`,
  ]
  // Excluded cookies get the exact suffix we just appended removed again —
  // exact because we generated it, which is what makes this reliable
  // without lookahead (Go's regexp engine has none).
  for (const name of c.exclude) {
    lines.push(`Set-Cookie ${q(`^(${escapeRegex(name)}=.*)${escapeRegex(suffix)}$`)} ${q('$1')}`)
  }
  out.directives.push(...block('header', lines))
  out.notes.push(`Cookies are normalised to ${flags.join(' + ')}${c.exclude.length ? ` (${c.exclude.length} excluded)` : ''}.`)
}

// ─── #37 compression ────────────────────────────────────────────────────
function compression(ctx, out) {
  const c = ctx.get('compression')
  if (!c.enabled) return
  const algos = c.algorithms.filter(a => ['zstd', 'gzip', 'br'].includes(a))
  if (!algos.length) return

  const opts = []
  if (c.min_length > 0) opts.push(`minimum_length ${c.min_length}`)
  if (c.content_types.length) {
    // Caddy's response matcher takes one value per line and ORs repeats of
    // the same field — a single line with several values is rejected.
    opts.push('match {')
    for (const t of c.content_types) opts.push(`    header Content-Type ${q(t.endsWith('/*') ? `${t.slice(0, -1)}*` : `${t}*`)}`)
    opts.push('}')
  }
  out.directives.push(...(opts.length ? block(`encode ${algos.join(' ')}`, opts) : [`encode ${algos.join(' ')}`]))
}

// ─── #38 client caching ─────────────────────────────────────────────────
function clientCache(ctx, out) {
  const c = ctx.get('client_cache')
  if (!c.enabled) return

  const byTtl = new Map()
  for (const [ext, ttl] of Object.entries(c.by_extension)) {
    const immutable = c.immutable_extensions.includes(ext)
    const key = `${ttl}:${immutable}`
    if (!byTtl.has(key)) byTtl.set(key, { ttl, immutable, exts: [] })
    byTtl.get(key).exts.push(ext)
  }

  let i = 0
  for (const { ttl, immutable, exts } of byTtl.values()) {
    const name = m(`cache_${i++}`)
    out.matchers.push(`${name} path ${exts.map(e => q(`*${e}`)).join(' ')}`)
    const value = `public, max-age=${ttl}${immutable ? ', immutable' : ''}`
    out.directives.push(`header ${name} Cache-Control ${q(value)}`)
  }

  if (c.no_store_paths.length) {
    const name = m('cache_never')
    out.matchers.push(`${name} path ${c.no_store_paths.map(q).join(' ')}`)
    out.directives.push(`header ${name} Cache-Control ${q('no-store, no-cache, must-revalidate')}`)
  }

  if (!c.etag) out.directives.push('header -ETag')
}

// ─── #39 HTML injection ─────────────────────────────────────────────────
function htmlInjection(ctx, out) {
  const c = ctx.get('html_injection')
  if (!c.enabled) return
  if (!c.head_snippet && !c.body_snippet) return

  const feature = caddyModules.checkFeature('replace_response')
  if (!feature.ok) { out.skipped.push({ feature: 'html_injection', reason: feature.hint, module: feature.module }); return }

  const DELIM = 'CATWAF_HTML'
  const pairs = []
  const add = (anchor, snippet) => {
    if (!snippet) return
    if (new RegExp(`^\\s*${DELIM}\\s*$`, 'm').test(snippet)) {
      out.skipped.push({ feature: 'html_injection', reason: `The snippet contains a line reading "${DELIM}", which would terminate the generated block.` })
      return
    }
    pairs.push({ anchor, snippet })
  }
  add('</head>', c.head_snippet)
  add('</body>', c.body_snippet)
  if (!pairs.length) return

  const lines = ['stream']
  for (const { anchor, snippet } of pairs) {
    lines.push(`${q(anchor)} <<${DELIM}`)
    lines.push(...snippet.split('\n'))
    lines.push(anchor)
    lines.push(DELIM)
  }

  if (c.exclude_paths.length) {
    const name = m('inject')
    out.matchers.push(`${name} not path ${c.exclude_paths.map(q).join(' ')}`)
    out.directives.push(...block(`replace ${name}`, lines))
  } else {
    out.directives.push(...block('replace', lines))
  }
}

// ─── #43 redirects ──────────────────────────────────────────────────────
function redirects(ctx, out) {
  const r = ctx.get('redirects')
  if (!r.enabled) return
  let i = 0
  for (const rule of r.rules) {
    if (!rule.enabled || !rule.to) continue
    const name = m(`redir_${i++}`)
    if (rule.match_host) {
      out.matchers.push(`${name} {`)
      out.matchers.push(`    host ${q(rule.match_host)}`)
      out.matchers.push(`    path ${q(rule.from)}`)
      out.matchers.push('}')
    } else {
      out.matchers.push(`${name} path ${q(rule.from)}`)
    }
    out.directives.push(`redir ${name} ${q(rule.to)} ${rule.status}`)
  }
  if (i) out.notes.push(`${i} redirect rule(s) evaluated before the origin.`)
}

// ─── #15 basic auth ─────────────────────────────────────────────────────
function basicAuth(ctx, out) {
  const b = ctx.get('basic_auth')
  if (!b.enabled) return
  if (!b.username || !b.password_hash) {
    out.skipped.push({ feature: 'basic_auth', reason: 'A username and password must both be set before the gate can be enabled.' })
    return
  }
  const directive = caddyModules.basicAuthDirective()
  const scope = b.path && b.path !== '/*' ? ` ${q(b.path)}` : ''
  out.directives.push(...block(`${directive}${scope}`, [`${q(b.username)} ${q(b.password_hash)}`]))
  out.notes.push(`Basic auth protects ${b.path || '/*'} as "${b.username}".`)
}

// ─── #29 forward auth ───────────────────────────────────────────────────
function forwardAuth(ctx, out) {
  const p = ctx.get('proxy')
  if (!p.auth_request_enabled) return
  if (!p.auth_request_url) {
    out.skipped.push({ feature: 'auth_request', reason: 'No auth service address configured.' })
    return
  }
  const lines = [`uri ${q(p.auth_request_uri || '/auth')}`]
  if (p.auth_request_copy_headers.length) lines.push(`copy_headers ${p.auth_request_copy_headers.map(q).join(' ')}`)
  if (p.auth_request_signin_url) {
    lines.push('@catwaf_auth_denied status 401 403')
    lines.push(`handle_response @catwaf_auth_denied {`)
    lines.push(`    redir * ${q(p.auth_request_signin_url)} 302`)
    lines.push('}')
  }
  out.directives.push(...block(`forward_auth ${q(p.auth_request_url)}`, lines))
  out.notes.push(`Every request is authorised by ${p.auth_request_url}${p.auth_request_uri} before the origin sees it.`)
}

// ─── #48 request body limit ─────────────────────────────────────────────
function requestLimits(ctx, out) {
  const a = ctx.get('access')
  if (a.max_body_size_mb > 0) {
    out.directives.push(...block('request_body', [`max_size ${a.max_body_size_mb}MB`]))
  }
}

// ─── #42 error pages ────────────────────────────────────────────────────
function errorPages(ctx, out) {
  const e = ctx.get('error_pages')
  if (!e.enabled) return
  const written = []
  for (const page of e.pages) {
    if (!page.html) continue
    writeAsset(`errors/${page.status}.html`, page.html, { mode: 0o644 })
    written.push(page.status)
  }
  if (e.fallback_html) writeAsset('errors/fallback.html', e.fallback_html, { mode: 0o644 })
  if (!written.length && !e.fallback_html) return

  const dir = require('path').dirname(writeAsset('errors/.keep', '#\n', { mode: 0o644 }))
  const lines = [`root * ${q(dir)}`]
  if (written.length) {
    lines.push(`@catwaf_err_known expression {err.status_code} in [${written.join(', ')}]`)
    lines.push(`rewrite @catwaf_err_known /{err.status_code}.html`)
  }
  if (e.fallback_html) {
    lines.push(written.length ? '@catwaf_err_other not expression {err.status_code} in [' + written.join(', ') + ']' : '@catwaf_err_other path *')
    lines.push('rewrite @catwaf_err_other /fallback.html')
  }
  lines.push('file_server')
  out.errorHandlers.push(...block('handle_errors', lines))
  out.notes.push(`Custom error pages for ${written.length ? written.join(', ') : 'all statuses'}.`)
}

// ─── #14 mTLS / #20-#24 TLS ─────────────────────────────────────────────
function tls(ctx, out) {
  const t = ctx.get('tls')
  const mt = ctx.get('mtls')
  const usingMtls = mt.mode !== 'off'
  const nonDefaultTls = t.cert_source !== 'acme' || t.profile !== 'intermediate' ||
    t.acme_provider !== 'letsencrypt' || t.acme_challenge !== 'http-01' ||
    !!t.acme_email || !t.ocsp_stapling

  if (!usingMtls && !nonDefaultTls) return
  if (!ctx.tlsCapable) {
    out.skipped.push({
      feature: 'tls',
      reason: 'The protected site block listens on a bare port, not a hostname, so Caddy serves it over plain HTTP and TLS settings do not apply. Provision a domain first.',
    })
    return
  }

  let args = ''
  const lines = []

  if (t.cert_source === 'self-signed') {
    args = ' internal'
  } else if (t.cert_source === 'custom') {
    if (!t.custom_cert_pem || !t.custom_key_pem) {
      out.skipped.push({ feature: 'tls', reason: 'Certificate source is "custom" but the certificate or key is missing.' })
      return
    }
    const cert = writeAsset('certs/site-cert.pem', t.custom_cert_pem, { mode: 0o640 })
    // Caddy runs separately and reads generated files through the restricted
    // shared group. The database itself remains owner-only.
    const key = writeAsset('certs/site-key.pem', t.custom_key_pem, { mode: 0o640 })
    args = ` ${q(cert)} ${q(key)}`
  } else if (t.acme_email) {
    args = ` ${q(t.acme_email)}`
  }

  const profile = TLS_PROFILES[t.profile] || TLS_PROFILES.intermediate
  if (profile.protocols.length) lines.push(`protocols ${profile.protocols.join(' ')}`)
  if (profile.ciphers.length) lines.push(`ciphers ${profile.ciphers.join(' ')}`)
  if (profile.curves.length) lines.push(`curves ${profile.curves.join(' ')}`)

  if (t.cert_source === 'acme') {
    if (t.acme_challenge === 'dns-01') {
      const dns = caddyModules.checkDnsProvider(t.dns_provider)
      if (!dns.ok) {
        out.skipped.push({ feature: 'dns-01', reason: dns.hint, module: dns.module })
      } else if (!t.dns_api_token) {
        out.skipped.push({ feature: 'dns-01', reason: 'No API token configured for the selected DNS provider.' })
      } else {
        lines.push(`dns ${t.dns_provider} ${q(t.dns_api_token)}`)
        lines.push('resolvers 1.1.1.1 8.8.8.8')
      }
    } else if (t.acme_challenge === 'tls-alpn-01') {
      lines.push('issuer acme {')
      lines.push('    disable_http_challenge')
      lines.push('}')
    }

    const issuers = []
    if (t.acme_provider === 'custom' && t.acme_ca_url) issuers.push(t.acme_ca_url)
    else if (ACME_DIRECTORIES[t.acme_provider]) issuers.push(ACME_DIRECTORIES[t.acme_provider])
    if (t.acme_fallback) {
      const other = t.acme_provider === 'zerossl' ? ACME_DIRECTORIES.letsencrypt : ACME_DIRECTORIES.zerossl
      if (!issuers.includes(other)) issuers.push(other)
    }
    // Only emit explicit issuers when they differ from Caddy's own default
    // pair — otherwise the default (Let's Encrypt then ZeroSSL) is already
    // what we want and an explicit list only adds a way to get it wrong.
    if (t.acme_provider !== 'letsencrypt' || t.acme_fallback || t.acme_ca_url) {
      for (const dir of issuers) {
        lines.push('issuer acme {')
        lines.push(`    dir ${q(dir)}`)
        if (t.acme_email) lines.push(`    email ${q(t.acme_email)}`)
        lines.push('}')
      }
    }
  }

  if (!t.ocsp_stapling) lines.push('must_staple off')

  if (usingMtls) {
    const clientAuth = [`mode ${mt.mode}`]
    if (mt.ca_pem) {
      const ca = writeAsset('certs/mtls-ca.pem', mt.ca_pem, { mode: 0o640 })
      clientAuth.push(`trusted_ca_cert_file ${q(ca)}`)
    } else if (mt.mode === 'require_and_verify') {
      out.skipped.push({ feature: 'mtls', reason: 'require_and_verify needs a trusted CA certificate — without one no client could ever connect.' })
      return
    }
    if (mt.crl_pem) {
      writeAsset('certs/mtls-crl.pem', mt.crl_pem, { mode: 0o640 })
      out.notes.push('A CRL is stored; Caddy checks revocation via OCSP/CRL when the client certificate carries the distribution points.')
    }
    if (mt.verify_depth !== 1) {
      out.skipped.push({
        feature: 'mtls_depth',
        reason: 'Caddy verifies the whole client-certificate chain against the trusted CA and exposes no depth limit, so this value is recorded but has no directive to render.',
      })
    }
    lines.push(...block('client_auth', clientAuth))
    out.notes.push(`Client certificates are ${mt.mode === 'request' ? 'requested' : 'required'}.`)
  }

  out.directives.push(...(lines.length ? block(`tls${args}`, lines) : [`tls${args.trim() ? args.trimStart() : ''}`.trim()]))
}

// ─── #26-#31, #60 reverse proxy behaviour ───────────────────────────────
function proxyBehaviour(ctx, out) {
  const p = ctx.get('proxy')
  const origin = ctx.get('origin')
  if (origin.type !== 'reverse-proxy') return

  const opts = proxyOptions(p, out)
  if (!opts.length) return

  if (!ctx.upstreams.length) {
    out.skipped.push({
      feature: 'proxy',
      reason: 'CatWAF could not find a reverse_proxy upstream in the protected site block, so proxy tuning has nothing to attach to.',
    })
    return
  }

  if (p.websockets === 'deny') {
    out.matchers.push(`${m('websocket')} header Connection *Upgrade*`)
    out.handles.push({ priority: 50, lines: block(`handle ${m('websocket')}`, [`error ${ctx.get('access').blocked_status_code}`]) })
    out.notes.push('WebSocket upgrade requests are rejected.')
  }

  const upstreams = ctx.upstreams.map(u => (p.protocol === 'grpc' && !/^[a-z0-9]+:\/\//.test(u) ? `h2c://${u}` : u))
  out.handles.push({
    priority: 90,
    lines: block(`handle`, block(`reverse_proxy ${upstreams.map(q).join(' ')}`, opts)),
  })
  out.notes.push(`Proxy tuning applied to ${upstreams.join(', ')}.`)
}

// The option lines shared by the managed site block and the auto-discovered
// route generator (proxy/generator.js), so both express the same settings.
function proxyOptions(p, out = { skipped: [], notes: [] }) {
  const opts = []

  if (p.lb_policy && p.lb_policy !== 'round_robin') opts.push(`lb_policy ${p.lb_policy}`)
  if (p.max_retries > 0) opts.push(`lb_retries ${p.max_retries}`)
  if (p.retry_timeout_sec > 0) opts.push(`lb_try_duration ${dur(p.retry_timeout_sec)}`)
  if (p.fail_duration_sec > 0) opts.push(`fail_duration ${dur(p.fail_duration_sec)}`)

  // Caddy already retries a connection-level failure; a *status*-based
  // failover is expressed as passive health checking — the upstream is
  // marked unhealthy on those statuses and the next one is tried.
  const statusRetry = p.retry_on.filter(c => /^\d{3}$/.test(c) || /^\dxx$/.test(c))
  if (statusRetry.length) opts.push(`unhealthy_status ${statusRetry.join(' ')}`)

  if (p.protocol === 'grpc') {
    opts.push('transport http {')
    opts.push('    versions h2c 2')
    opts.push('}')
  } else if (p.protocol === 'https' || p.upstream_tls_verify) {
    const t = ['tls']
    if (p.upstream_server_name) t.push(`tls_server_name ${q(p.upstream_server_name)}`)
    if (p.upstream_tls_verify) {
      if (p.upstream_ca_pem) {
        const ca = writeAsset('certs/upstream-ca.pem', p.upstream_ca_pem, { mode: 0o640 })
        t.push(`tls_trusted_ca_certs ${q(ca)}`)
      }
    } else {
      t.push('tls_insecure_skip_verify')
    }
    opts.push(...block('transport http', t))
  }

  return opts
}

// ─── #28 upstream response caching ──────────────────────────────────────
function upstreamCache(ctx, out) {
  const p = ctx.get('proxy')
  if (!p.cache_enabled) return
  const feature = caddyModules.checkFeature('cache')
  if (!feature.ok) { out.skipped.push({ feature: 'cache', reason: feature.hint, module: feature.module }); return }

  const lines = [`ttl ${dur(p.cache_ttl_sec)}`, `allowed_http_verbs ${p.cache_methods.join(' ')}`]
  if (p.cache_max_size_mb > 0) lines.push(...block('badger', [`path ${q(require('./util').assetDir('cache'))}`]))
  // Per-status TTLs are driven by the origin's own Cache-Control in the
  // cache handler's model, so CatWAF surfaces the configured values rather
  // than pretending to render a directive that does not exist.
  for (const rule of p.cache_status_ttl) {
    out.notes.push(`Status ${rule.status} is configured for ${dur(rule.ttl_sec)} — set Cache-Control on that response at the origin for the cache to honour it.`)
  }
  if (p.cache_bypass_paths.length) {
    const name = m('nocache')
    out.matchers.push(`${name} path ${p.cache_bypass_paths.map(q).join(' ')}`)
    out.directives.push(...block(`cache ${name}`, ['mode bypass']))
  }
  out.directives.push(...block('cache', lines))
  out.notes.push(`Upstream responses are cached for ${dur(p.cache_ttl_sec)}.`)
}

// ─── #32/#33 static and PHP origins ─────────────────────────────────────
function originHandlers(ctx, out) {
  const o = ctx.get('origin')
  if (o.type === 'reverse-proxy') return
  if (!o.root) {
    out.skipped.push({ feature: 'origin', reason: `Origin type "${o.type}" needs a document root.` })
    return
  }

  const lines = [`root * ${q(o.root)}`]

  if (o.type === 'php-fpm') {
    if (!o.php_upstream) {
      out.skipped.push({ feature: 'origin', reason: 'PHP-FPM origin needs a socket or host:port address.' })
      return
    }
    const php = [`index ${q(o.php_index || 'index.php')}`]
    if (!o.try_files) php.push('try_files {path}')
    lines.push(...block(`php_fastcgi ${q(o.php_upstream)}`, php))
    lines.push('file_server')
    out.notes.push(`Serving ${o.root} through PHP-FPM at ${o.php_upstream}.`)
  } else {
    if (o.index_files.length) lines.push(`try_files {path} {path}/ ${o.index_files.map(f => `/${f}`).join(' ')}`)
    lines.push(...(o.browse ? block('file_server', ['browse']) : ['file_server']))
    out.notes.push(`Serving ${o.root} directly — no origin server needed.`)
  }

  out.handles.push({ priority: 95, lines: block('handle', lines) })
}

// ─── #62 raw per-site injection ─────────────────────────────────────────
function rawConfig(ctx, out) {
  const r = ctx.get('raw_config')
  if (!r.enabled || !r.per_site.trim()) return
  out.raw.push('# ── unmanaged: raw per-site directives ──')
  out.raw.push(...r.per_site.split('\n'))
}

function build(overrides = {}) {
  const ctx = ctxOf(overrides)
  const out = { matchers: [], handles: [], directives: [], errorHandlers: [], raw: [], skipped: [], notes: [] }

  methodGuard(ctx, out)
  challengeRoutes(ctx, out)
  enforcementGate(ctx, out)
  uploadScanGate(ctx, out)
  wellKnownFiles(ctx, out)
  cors(ctx, out)
  securityHeaders(ctx, out)
  cookieFlags(ctx, out)
  compression(ctx, out)
  clientCache(ctx, out)
  htmlInjection(ctx, out)
  redirects(ctx, out)
  basicAuth(ctx, out)
  forwardAuth(ctx, out)
  requestLimits(ctx, out)
  errorPages(ctx, out)
  tls(ctx, out)
  proxyBehaviour(ctx, out)
  upstreamCache(ctx, out)
  originHandlers(ctx, out)
  rawConfig(ctx, out)

  const lines = []
  if (out.matchers.length) lines.push(...out.matchers, '')
  for (const h of out.handles.sort((a, b) => a.priority - b.priority)) lines.push(...h.lines)
  if (out.handles.length) lines.push('')
  lines.push(...out.directives)
  if (out.errorHandlers.length) lines.push('', ...out.errorHandlers)
  if (out.raw.length) lines.push('', ...out.raw)

  return { lines: lines.filter((l, i, arr) => !(l === '' && arr[i - 1] === '')), skipped: out.skipped, notes: out.notes }
}

module.exports = { build, proxyOptions, TLS_PROFILES, ACME_DIRECTORIES }
