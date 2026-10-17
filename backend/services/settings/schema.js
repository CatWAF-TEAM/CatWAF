// settings/schema.js — the declarative definition of every CatWAF setting
// that lives outside the original `state.WAF` blob.
//
// One entry per group. Each group is stored as a single row in `waf_state`
// under `ext:<group>`, validated field-by-field by settings/types.js, and
// rendered into the Caddyfile by services/render/*.js. Adding a setting is
// therefore: add a field here, render it there, and it automatically gets a
// validated API, CLI access, snapshot/rollback coverage and a UI control.
//
// `idea` on each group is the design-brief number the group implements, so a
// control in the UI can be traced back to the requirement it came from.

const HTML_SNIPPET_MAX = 16 * 1024

const SCHEMA = {

  // ─── Access control ───────────────────────────────────────────────────
  access: {
    label: 'Access control',
    idea: [55, 56, 57, 19, 58, 59, 48],
    summary: 'Host matching, method allowlist, deny behaviour and protocol limits.',
    fields: {
      // #55 — the mechanical fix for docs/knowledge origin-exposure.md
      reject_unknown_host: {
        type: 'bool', default: false,
        label: 'Reject unknown Host/SNI',
        help: 'Serve a catch-all block that refuses any request whose Host header does not match a site CatWAF knows about. Closes the "reach the origin by IP" bypass.',
      },
      known_hosts: {
        type: 'list', item: 'host', max: 100, default: [],
        label: 'Known hostnames',
        help: 'Hostnames considered legitimate. Leave empty to derive from DOMAIN and the sites CatWAF has provisioned.',
      },
      unknown_host_action: {
        type: 'enum', values: ['abort', 'status'], default: 'abort',
        label: 'Unknown-host response',
        help: '"abort" closes the connection without a response; "status" returns the configured blocked status code.',
      },

      // #57
      enforce_method_allowlist: {
        type: 'bool', default: false,
        label: 'Enforce HTTP method allowlist',
        help: 'Reject any method not on the list before the request is routed. Off by default so existing installs are unchanged.',
      },
      allowed_methods: {
        type: 'list', item: 'method', max: 20, default: ['GET', 'POST', 'HEAD', 'OPTIONS'],
        label: 'Allowed methods',
      },
      method_reject_status: {
        type: 'int', min: 400, max: 599, default: 405,
        label: 'Method rejection status',
      },

      // #19 / #58
      blocked_status_code: {
        type: 'int', min: 100, max: 599, default: 403,
        label: 'Blocked request status code',
        help: 'What a denied request receives. 403 is the default; 404 hides the fact that a WAF is present.',
      },
      block_response_mode: {
        type: 'enum', values: ['status', 'silent'], default: 'status',
        label: 'Blocked request response mode',
        help: '"silent" closes the connection without any response at all — invisible to fingerprinting tools, but a mistakenly blocked visitor also gets no explanation, which makes false positives much harder to diagnose.',
      },

      // #59
      disable_plain_http: {
        type: 'bool', default: false,
        label: 'Disable plaintext HTTP entirely',
        help: 'Do not listen on :80 at all, rather than listening and redirecting. A closed port is a smaller attack surface, but visitors typing http:// get a connection error instead of a redirect.',
      },

      // #56 — the mechanical fix for docs/knowledge false-positives.md
      waf_bypass_paths: {
        type: 'list', item: 'uri', max: 50, default: [],
        label: 'Paths exempt from WAF inspection',
        help: 'Requests matching these URI patterns skip Coraza/CRS inspection entirely — for webhook and upload endpoints that must receive raw bytes. Everything else stays protected.',
      },

      // #48
      max_header_size_kb: {
        type: 'int', min: 0, max: 1024, default: 0,
        label: 'Max request header size (KB)',
        help: '0 leaves Caddy at its built-in default.',
      },
      max_body_size_mb: {
        type: 'int', min: 0, max: 10240, default: 0,
        label: 'Max request body size (MB)',
        help: '0 leaves the limit unset. Applies at the HTTP layer, before the WAF body limit.',
      },
      file_cache_size: {
        type: 'int', min: 0, max: 100000, default: 0,
        label: 'Open-file cache entries',
        help: 'Only relevant when CatWAF serves files directly (static or PHP-FPM origin). 0 disables the cache.',
      },
    },
  },

  // ─── HTTP Basic Auth gate (#15) ───────────────────────────────────────
  basic_auth: {
    label: 'Basic auth gate',
    idea: [15],
    summary: 'Password-gate a site or path independently of the application.',
    secret: true,
    fields: {
      enabled: { type: 'bool', default: false, label: 'Enabled' },
      path: {
        type: 'str', item: 'uri', default: '/*', maxLen: 512,
        label: 'Path scope', help: 'Which paths require the password. /* covers the whole site.',
      },
      username: {
        type: 'str', default: '', maxLen: 64,
        pattern: /^[A-Za-z0-9._@-]*$/, patternMessage: 'Username may only contain letters, numbers and . _ @ -',
        label: 'Username',
      },
      // Stored already hashed — the plaintext never reaches the database or
      // the generated Caddyfile. The API hashes on write.
      password_hash: { type: 'str', default: '', maxLen: 128, label: 'Password (bcrypt hash)', writeOnly: true },
      realm: { type: 'str', default: 'Restricted', maxLen: 64, label: 'Realm' },
    },
  },

  // ─── Mutual TLS (#14) ─────────────────────────────────────────────────
  mtls: {
    label: 'Mutual TLS',
    idea: [14],
    summary: 'Require a client certificate signed by your CA before serving anything.',
    fields: {
      mode: {
        type: 'enum', values: ['off', 'request', 'require', 'require_and_verify'], default: 'off',
        label: 'Client certificate mode',
        help: '"require_and_verify" is real access control; "request" only asks for a certificate and still serves clients that do not present one.',
      },
      ca_pem: { type: 'text', pem: ['CERTIFICATE'], maxLen: 256 * 1024, default: '', label: 'Trusted CA certificate (PEM)' },
      verify_depth: { type: 'int', min: 0, max: 10, default: 1, label: 'Verification chain depth' },
      crl_pem: { type: 'text', pem: ['X509 CRL'], maxLen: 256 * 1024, default: '', label: 'Certificate revocation list (PEM)' },
    },
  },

  // ─── Real client IP (#16, #17) ────────────────────────────────────────
  real_ip: {
    label: 'Real client IP',
    idea: [16, 17],
    summary: 'How CatWAF determines the client address when it sits behind another proxy.',
    fields: {
      enabled: { type: 'bool', default: false, label: 'Trust an upstream proxy for the client IP' },
      preset: {
        type: 'enum', values: ['custom', 'cloudflare', 'private'], default: 'custom',
        label: 'Trusted range preset',
        help: '"cloudflare" fills the trusted list from the Cloudflare edge ranges CatWAF already tracks; "private" trusts RFC1918 ranges.',
      },
      trusted_proxies: { type: 'list', item: 'cidr', max: 200, default: [], label: 'Trusted proxy CIDRs' },
      header: {
        type: 'enum', values: ['X-Forwarded-For', 'X-Real-IP', 'CF-Connecting-IP', 'True-Client-IP', 'Forwarded'],
        default: 'X-Forwarded-For', label: 'Client IP header',
      },
      recursive: { type: 'bool', default: true, label: 'Resolve recursively through multiple hops' },
      proxy_protocol: {
        type: 'bool', default: false, label: 'Accept the PROXY protocol',
        help: 'For an L4/TCP load balancer in front of CatWAF that cannot set HTTP headers. Enabling this when nothing sends the PROXY header breaks every connection.',
      },
      proxy_protocol_allow: { type: 'list', item: 'cidr', max: 200, default: [], label: 'PROXY protocol source CIDRs' },
    },
  },

  // ─── Connection limits (#18) ──────────────────────────────────────────
  connections: {
    label: 'Connection limits',
    idea: [18],
    summary: 'Cap concurrent connections and HTTP/2 streams per client, not just request rate.',
    fields: {
      enabled: { type: 'bool', default: false, label: 'Enabled' },
      max_per_ip: { type: 'int', min: 1, max: 100000, default: 100, label: 'Max concurrent connections per IP' },
      max_h2_streams: { type: 'int', min: 1, max: 10000, default: 250, label: 'Max concurrent HTTP/2 streams per connection' },
      idle_timeout_sec: { type: 'int', min: 1, max: 3600, default: 120, label: 'Idle connection timeout (seconds)' },
      read_timeout_sec: { type: 'int', min: 0, max: 3600, default: 0, label: 'Read timeout (seconds, 0 = default)' },
      write_timeout_sec: { type: 'int', min: 0, max: 3600, default: 0, label: 'Write timeout (seconds, 0 = default)' },
    },
  },

  // ─── TLS & certificates (#20-#24) ─────────────────────────────────────
  tls: {
    label: 'TLS & certificates',
    idea: [20, 21, 22, 23, 24],
    summary: 'Certificate source, ACME behaviour and protocol/cipher strictness.',
    secret: true,
    fields: {
      profile: {
        type: 'enum', values: ['modern', 'intermediate', 'compatible'], default: 'intermediate',
        label: 'TLS profile',
        help: '"modern" is TLS 1.3 only; "compatible" allows TLS 1.2 with a wider cipher list for legacy clients.',
      },
      cert_source: {
        type: 'enum', values: ['acme', 'self-signed', 'custom'], default: 'acme',
        label: 'Certificate source',
      },
      self_signed_fallback: {
        type: 'bool', default: true,
        label: 'Self-signed fallback during setup',
        help: 'Serve a locally-issued certificate while DNS propagates, so the site is on HTTPS from the first request instead of plaintext or broken TLS.',
      },
      custom_cert_pem: { type: 'text', pem: ['CERTIFICATE'], maxLen: 256 * 1024, default: '', label: 'Certificate (PEM)' },
      custom_key_pem: {
        type: 'text', pem: ['PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY'], maxLen: 256 * 1024, default: '',
        label: 'Private key (PEM)', writeOnly: true,
      },
      acme_provider: {
        type: 'enum', values: ['letsencrypt', 'zerossl', 'custom'], default: 'letsencrypt',
        label: 'ACME provider',
      },
      acme_fallback: {
        type: 'bool', default: false, label: 'Fall back to a second ACME provider',
        help: 'If the primary provider fails or is rate-limited, try the other one before giving up.',
      },
      acme_ca_url: { type: 'str', item: 'url', default: '', maxLen: 512, label: 'Custom ACME directory URL' },
      acme_email: {
        type: 'str', default: '', maxLen: 254,
        pattern: /^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$/, patternMessage: 'Must be a valid email address',
        label: 'ACME account email',
      },
      acme_challenge: {
        type: 'enum', values: ['http-01', 'tls-alpn-01', 'dns-01'], default: 'http-01',
        label: 'ACME challenge type',
        help: 'dns-01 is required for wildcard certificates and for origins that cannot be reached on :80.',
      },
      dns_provider: {
        type: 'enum',
        values: ['none', 'cloudflare', 'route53', 'digitalocean', 'googleclouddns', 'azure', 'namecheap', 'gandi', 'porkbun', 'hetzner', 'linode', 'vultr', 'ovh', 'desec'],
        default: 'none', label: 'DNS provider (for dns-01)',
      },
      dns_api_token: { type: 'str', default: '', maxLen: 512, label: 'DNS provider API token', writeOnly: true },
      wildcard: { type: 'bool', default: false, label: 'Request a wildcard certificate' },
      acme_retries: { type: 'int', min: 0, max: 10, default: 3, label: 'Issuance retry attempts' },
      acme_retry_delay_sec: { type: 'int', min: 1, max: 3600, default: 30, label: 'Delay between retries (seconds)' },
      ocsp_stapling: { type: 'bool', default: true, label: 'OCSP stapling' },
    },
  },

  // ─── Admin session security (#25) ─────────────────────────────────────
  session: {
    label: 'Admin session security',
    idea: [25],
    summary: 'Lifetime and binding rules for CatWAF\'s own admin sessions.',
    fields: {
      absolute_max_age_min: { type: 'int', min: 5, max: 43200, default: 720, label: 'Absolute session lifetime (minutes)' },
      idle_timeout_min: { type: 'int', min: 0, max: 10080, default: 0, label: 'Idle timeout (minutes, 0 = off)' },
      rolling: { type: 'bool', default: false, label: 'Extend the session on each request' },
      bind_ip: {
        type: 'bool', default: false, label: 'Bind a session to the client IP',
        help: 'A stolen token stops working from another address — at the cost of logging users out when their address changes (mobile networks, VPNs).',
      },
      bind_user_agent: { type: 'bool', default: false, label: 'Bind a session to the browser user-agent' },
      max_concurrent: { type: 'int', min: 0, max: 100, default: 0, label: 'Max concurrent sessions per user (0 = unlimited)' },
    },
  },

  // ─── Origin type (#32, #33) ───────────────────────────────────────────
  origin: {
    label: 'Origin type',
    idea: [32, 33],
    summary: 'What CatWAF puts behind the WAF: a proxied app, a folder, or PHP-FPM.',
    fields: {
      type: {
        type: 'enum', values: ['reverse-proxy', 'static-folder', 'php-fpm'], default: 'reverse-proxy',
        label: 'Origin type',
      },
      root: {
        type: 'str', default: '', maxLen: 512,
        pattern: /^\/[^\s]*$/, patternMessage: 'Root must be an absolute path',
        label: 'Document root',
      },
      index_files: { type: 'list', item: 'token', max: 10, default: ['index.html', 'index.htm'], label: 'Index files' },
      browse: { type: 'bool', default: false, label: 'Allow directory listing' },
      php_upstream: {
        type: 'str', item: 'upstream', default: '', maxLen: 256,
        label: 'PHP-FPM address', help: 'unix//run/php/php-fpm.sock or 127.0.0.1:9000.',
      },
      php_index: { type: 'str', default: 'index.php', maxLen: 64, label: 'PHP front controller' },
      try_files: { type: 'bool', default: true, label: 'Try static files before PHP' },
    },
  },

  // ─── Reverse-proxy behaviour (#26-#31, #60) ───────────────────────────
  proxy: {
    label: 'Reverse proxy',
    idea: [26, 27, 28, 29, 30, 31, 60],
    summary: 'Protocol support, upstream verification, failover and caching.',
    fields: {
      // #26
      websockets: {
        type: 'enum', values: ['allow', 'deny'], default: 'allow',
        label: 'WebSocket upgrades',
        help: 'Set to "deny" for a site that has no real-time features — an unexpected upgrade request is then rejected instead of tunnelled to the backend.',
      },
      // #27
      protocol: {
        type: 'enum', values: ['http', 'https', 'grpc'], default: 'http',
        label: 'Upstream protocol',
      },
      // #60
      upstream_tls_verify: {
        type: 'bool', default: false,
        label: 'Verify the upstream TLS certificate',
        help: 'Off by default so existing self-signed backends keep working. Turn it on whenever the backend has a real certificate — otherwise a spoofed backend on the internal network is undetectable.',
      },
      upstream_ca_pem: { type: 'text', pem: ['CERTIFICATE'], maxLen: 256 * 1024, default: '', label: 'Upstream CA bundle (PEM)' },
      upstream_server_name: { type: 'str', item: 'host', default: '', maxLen: 253, label: 'Expected upstream server name (SNI)' },

      // #30
      lb_policy: {
        type: 'enum', values: ['round_robin', 'least_conn', 'first', 'ip_hash', 'random'], default: 'round_robin',
        label: 'Load-balancing policy',
      },
      // These four default to "leave Caddy alone" (0 / empty) rather than to
      // a value, so a site that never opens this page keeps whatever Caddy
      // does today instead of quietly acquiring CatWAF's opinion.
      retry_on: {
        type: 'list', item: 'token', max: 10, default: [],
        label: 'Retry conditions',
        help: 'Upstream response statuses that mark a backend unhealthy so the next one is tried: 5xx, 502, 503, 504.',
      },
      max_retries: { type: 'int', min: 0, max: 20, default: 0, label: 'Max retries (0 = Caddy default)' },
      retry_timeout_sec: { type: 'int', min: 0, max: 300, default: 0, label: 'Total retry budget (seconds, 0 = Caddy default)' },
      fail_duration_sec: { type: 'int', min: 0, max: 3600, default: 0, label: 'Mark an upstream down for (seconds, 0 = off)' },

      // #31
      http2: { type: 'bool', default: true, label: 'HTTP/2' },
      http3: {
        type: 'bool', default: false, label: 'HTTP/3 (QUIC)',
        help: 'Needs UDP on the same port to be open. Some corporate proxies mishandle HTTP/3, which is why this is opt-in.',
      },
      alt_svc_port: { type: 'int', min: 0, max: 65535, default: 0, label: 'Alt-Svc advertised port (0 = same port)' },

      // #29
      auth_request_enabled: { type: 'bool', default: false, label: 'Delegate authorization to an external service' },
      auth_request_url: { type: 'str', item: 'upstream', default: '', maxLen: 256, label: 'Auth service address' },
      auth_request_uri: { type: 'str', item: 'uri', default: '/auth', maxLen: 512, label: 'Auth service URI' },
      auth_request_signin_url: { type: 'str', item: 'url', default: '', maxLen: 2048, label: 'Sign-in redirect URL' },
      auth_request_copy_headers: {
        type: 'list', item: 'header', max: 20, default: ['Remote-User', 'Remote-Email'],
        label: 'Headers to copy from the auth response',
      },

      // #28
      cache_enabled: { type: 'bool', default: false, label: 'Cache upstream responses' },
      cache_ttl_sec: { type: 'int', min: 1, max: 2592000, default: 300, label: 'Default cache TTL (seconds)' },
      cache_methods: { type: 'list', item: 'method', max: 5, default: ['GET', 'HEAD'], label: 'Cacheable methods' },
      cache_status_ttl: {
        type: 'records', max: 20, default: [],
        fields: {
          status: { type: 'int', min: 100, max: 599, default: 200 },
          ttl_sec: { type: 'int', min: 0, max: 2592000, default: 300 },
        },
        label: 'Per-status cache TTL',
      },
      cache_bypass_paths: { type: 'list', item: 'uri', max: 50, default: [], label: 'Never cache these paths' },
      cache_max_size_mb: { type: 'int', min: 1, max: 102400, default: 512, label: 'Cache size cap (MB)' },
    },
  },

  // ─── Security headers (#34) ───────────────────────────────────────────
  headers: {
    label: 'Security headers',
    idea: [34],
    summary: 'Response header policy, as named presets with per-header overrides.',
    fields: {
      preset: {
        type: 'enum', values: ['off', 'basic', 'strict', 'custom'], default: 'off',
        label: 'Header preset',
        help: '"basic" sets the widely-safe headers; "strict" adds CSP and cross-origin isolation, which can break sites embedding third-party content.',
      },
      hsts_max_age: { type: 'int', min: 0, max: 63072000, default: 31536000, label: 'HSTS max-age (seconds)' },
      hsts_include_subdomains: { type: 'bool', default: true, label: 'HSTS includeSubDomains' },
      hsts_preload: { type: 'bool', default: false, label: 'HSTS preload' },
      csp: { type: 'str', default: '', maxLen: 2048, label: 'Content-Security-Policy' },
      csp_report_only: { type: 'str', default: '', maxLen: 2048, label: 'Content-Security-Policy-Report-Only' },
      permissions_policy: { type: 'str', default: '', maxLen: 1024, label: 'Permissions-Policy' },
      referrer_policy: {
        type: 'enum',
        values: ['', 'no-referrer', 'no-referrer-when-downgrade', 'same-origin', 'origin', 'strict-origin', 'strict-origin-when-cross-origin', 'unsafe-url'],
        default: 'strict-origin-when-cross-origin', label: 'Referrer-Policy',
      },
      x_frame_options: { type: 'enum', values: ['', 'DENY', 'SAMEORIGIN'], default: 'SAMEORIGIN', label: 'X-Frame-Options' },
      x_content_type_options: { type: 'bool', default: true, label: 'X-Content-Type-Options: nosniff' },
      x_dns_prefetch_control: { type: 'enum', values: ['', 'on', 'off'], default: '', label: 'X-DNS-Prefetch-Control' },
      coop: { type: 'enum', values: ['', 'unsafe-none', 'same-origin-allow-popups', 'same-origin'], default: '', label: 'Cross-Origin-Opener-Policy' },
      coep: { type: 'enum', values: ['', 'unsafe-none', 'require-corp', 'credentialless'], default: '', label: 'Cross-Origin-Embedder-Policy' },
      corp: { type: 'enum', values: ['', 'same-site', 'same-origin', 'cross-origin'], default: '', label: 'Cross-Origin-Resource-Policy' },
      remove_headers: {
        type: 'list', item: 'header', max: 20, default: ['Server', 'X-Powered-By'],
        label: 'Headers to strip from responses',
      },
      custom: {
        type: 'records', max: 40, default: [],
        fields: {
          name: { type: 'str', item: 'header', default: '' },
          value: { type: 'str', default: '', maxLen: 1024 },
          replace: { type: 'bool', default: true },
        },
        label: 'Custom response headers',
      },
    },
  },

  // ─── CORS (#35) ───────────────────────────────────────────────────────
  cors: {
    label: 'CORS policy',
    idea: [35],
    summary: 'Cross-origin request rules applied at the WAF layer.',
    fields: {
      enabled: { type: 'bool', default: false, label: 'Enabled' },
      allow_origins: { type: 'list', item: 'url', max: 50, default: [], label: 'Allowed origins' },
      allow_any_origin: {
        type: 'bool', default: false, label: 'Allow any origin',
        help: 'Cannot be combined with credentials — the browser rejects "*" plus Allow-Credentials.',
      },
      allow_methods: { type: 'list', item: 'method', max: 15, default: ['GET', 'POST', 'OPTIONS'], label: 'Allowed methods' },
      allow_headers: { type: 'list', item: 'header', max: 40, default: ['Content-Type', 'Authorization'], label: 'Allowed request headers' },
      expose_headers: { type: 'list', item: 'header', max: 40, default: [], label: 'Exposed response headers' },
      allow_credentials: { type: 'bool', default: false, label: 'Allow credentials' },
      max_age_sec: { type: 'int', min: 0, max: 86400, default: 600, label: 'Preflight cache (seconds)' },
      on_failure: {
        type: 'enum', values: ['pass', 'deny'], default: 'pass',
        label: 'Request from a disallowed origin',
        help: '"pass" serves the request without CORS headers (the browser blocks it); "deny" refuses it outright at the edge.',
      },
    },
  },

  // ─── Cookie flags (#36) ───────────────────────────────────────────────
  cookies: {
    label: 'Cookie flags',
    idea: [36],
    summary: 'Add missing Secure/HttpOnly/SameSite flags to backend cookies.',
    fields: {
      enabled: { type: 'bool', default: false, label: 'Enabled' },
      secure: { type: 'enum', values: ['off', 'auto', 'always'], default: 'auto', label: 'Secure flag', help: '"auto" adds Secure only on HTTPS connections.' },
      http_only: { type: 'bool', default: true, label: 'Add HttpOnly' },
      same_site: { type: 'enum', values: ['', 'Lax', 'Strict', 'None'], default: 'Lax', label: 'SameSite' },
      exclude: { type: 'list', item: 'token', max: 30, default: [], label: 'Cookie names to leave untouched' },
    },
  },

  // ─── Compression (#37) ────────────────────────────────────────────────
  compression: {
    label: 'Compression',
    idea: [37],
    summary: 'gzip/zstd response compression, tradeable against CPU.',
    fields: {
      // Off by default: Caddy does not compress unless told to, so defaulting
      // this on would silently change every existing install's behaviour the
      // first time it applied any unrelated setting.
      enabled: { type: 'bool', default: false, label: 'Enabled' },
      algorithms: { type: 'list', item: 'token', max: 4, default: ['zstd', 'gzip'], label: 'Algorithms in preference order' },
      min_length: { type: 'int', min: 0, max: 1048576, default: 512, label: 'Minimum response size (bytes)' },
      level: { type: 'int', min: 1, max: 11, default: 5, label: 'Compression level' },
      content_types: {
        type: 'list', item: 'mime', max: 50,
        default: ['text/*', 'application/json', 'application/javascript', 'application/xml', 'image/svg+xml'],
        label: 'Content types to compress',
      },
    },
  },

  // ─── Client caching (#38) ─────────────────────────────────────────────
  client_cache: {
    label: 'Client caching',
    idea: [38],
    summary: 'Cache-Control and ETag policy for static assets.',
    fields: {
      enabled: { type: 'bool', default: false, label: 'Enabled' },
      etag: { type: 'bool', default: true, label: 'Send ETag headers' },
      default_max_age_sec: { type: 'int', min: 0, max: 31536000, default: 3600, label: 'Default max-age (seconds)' },
      by_extension: {
        type: 'map', key: 'ext', max: 50,
        value: { type: 'int', min: 0, max: 31536000, default: 3600 },
        default: { '.css': 604800, '.js': 604800, '.png': 2592000, '.jpg': 2592000, '.svg': 2592000, '.woff2': 31536000 },
        label: 'Per-extension max-age (seconds)',
      },
      immutable_extensions: { type: 'list', item: 'ext', max: 30, default: ['.woff2'], label: 'Extensions marked immutable' },
      no_store_paths: { type: 'list', item: 'uri', max: 30, default: [], label: 'Never-cached paths' },
    },
  },

  // ─── HTML injection (#39) ─────────────────────────────────────────────
  html_injection: {
    label: 'HTML injection',
    idea: [39],
    summary: 'Insert a snippet into every HTML page without touching the app.',
    fields: {
      enabled: { type: 'bool', default: false, label: 'Enabled' },
      head_snippet: { type: 'text', maxLen: HTML_SNIPPET_MAX, default: '', label: 'Injected before </head>' },
      body_snippet: { type: 'text', maxLen: HTML_SNIPPET_MAX, default: '', label: 'Injected before </body>' },
      exclude_paths: { type: 'list', item: 'uri', max: 30, default: [], label: 'Paths to leave untouched' },
    },
  },

  // ─── robots.txt (#40) ─────────────────────────────────────────────────
  robots: {
    label: 'robots.txt',
    idea: [40],
    summary: 'Generate /robots.txt from your bot policy.',
    fields: {
      enabled: { type: 'bool', default: false, label: 'Serve a generated robots.txt' },
      mode: {
        type: 'enum', values: ['allow-all', 'disallow-all', 'custom'], default: 'allow-all',
        label: 'Base policy',
      },
      disallow_paths: { type: 'list', item: 'uri', max: 100, default: [], label: 'Disallowed paths (all crawlers)' },
      allow_paths: { type: 'list', item: 'uri', max: 100, default: [], label: 'Explicitly allowed paths' },
      block_known_bad_bots: {
        type: 'bool', default: true,
        label: 'Disallow the user agents CatWAF already blocks',
        help: 'Mirrors the blocked user-agent list into robots.txt so well-behaved crawlers stay away and the WAF only has to stop the ones that ignore it.',
      },
      crawl_delay: { type: 'int', min: 0, max: 3600, default: 0, label: 'Crawl-delay (seconds, 0 = omit)' },
      sitemap_url: { type: 'str', item: 'url', default: '', maxLen: 2048, label: 'Sitemap URL' },
      extra_rules: {
        type: 'records', max: 50, default: [],
        fields: {
          user_agent: { type: 'str', item: 'ua', default: '*' },
          directive: { type: 'enum', values: ['Allow', 'Disallow'], default: 'Disallow' },
          path: { type: 'str', item: 'uri', default: '/' },
        },
        label: 'Per-crawler rules',
      },
    },
  },

  // ─── security.txt (#41) ───────────────────────────────────────────────
  security_txt: {
    label: 'security.txt',
    idea: [41],
    summary: 'Publish RFC 9116 vulnerability-reporting contact details.',
    fields: {
      enabled: { type: 'bool', default: false, label: 'Serve /.well-known/security.txt' },
      contact: {
        type: 'list', item: 'token', max: 10, default: [],
        label: 'Contact (required)',
        help: 'A mailto: or https: URL. RFC 9116 requires at least one.',
      },
      expires: {
        type: 'str', default: '', maxLen: 32,
        pattern: /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}Z)?$/, patternMessage: 'Expires must be an ISO date (YYYY-MM-DD)',
        label: 'Expires (required)',
      },
      encryption: { type: 'str', item: 'url', default: '', maxLen: 2048, label: 'Encryption key URL' },
      policy: { type: 'str', item: 'url', default: '', maxLen: 2048, label: 'Policy URL' },
      acknowledgments: { type: 'str', item: 'url', default: '', maxLen: 2048, label: 'Acknowledgments URL' },
      preferred_languages: { type: 'list', item: 'token', max: 10, default: [], label: 'Preferred languages' },
      canonical: { type: 'str', item: 'url', default: '', maxLen: 2048, label: 'Canonical URL' },
      hiring: { type: 'str', item: 'url', default: '', maxLen: 2048, label: 'Hiring URL' },
    },
  },

  // ─── Error pages (#42) ────────────────────────────────────────────────
  error_pages: {
    label: 'Error pages',
    idea: [42],
    summary: 'Replace the default error body for chosen status codes.',
    fields: {
      enabled: { type: 'bool', default: false, label: 'Enabled' },
      pages: {
        type: 'records', max: 20, default: [],
        fields: {
          status: { type: 'int', min: 400, max: 599, default: 404 },
          html: { type: 'text', maxLen: HTML_SNIPPET_MAX, default: '' },
        },
        label: 'Custom pages',
      },
      fallback_html: { type: 'text', maxLen: HTML_SNIPPET_MAX, default: '', label: 'Fallback page for other errors' },
    },
  },

  // ─── Redirects (#43) ──────────────────────────────────────────────────
  redirects: {
    label: 'Redirect rules',
    idea: [43],
    summary: 'Ordered redirect rules evaluated before the proxy target.',
    fields: {
      enabled: { type: 'bool', default: false, label: 'Enabled' },
      rules: {
        type: 'records', max: 100, default: [],
        fields: {
          match_host: { type: 'str', item: 'host', default: '' },
          from: { type: 'str', item: 'uri', default: '/' },
          to: { type: 'str', default: '', maxLen: 2048 },
          status: { type: 'enum', values: [301, 302, 307, 308], default: 301 },
          enabled: { type: 'bool', default: true },
        },
        label: 'Rules',
      },
    },
  },

  // ─── Challenge gate (#1-#4) ───────────────────────────────────────────
  challenge: {
    label: 'Challenge gate',
    idea: [1, 2, 3, 4],
    summary: 'Make ambiguous visitors prove they are a browser before passing them through.',
    secret: true,
    fields: {
      mode: {
        type: 'enum', values: ['off', 'cookie', 'javascript', 'captcha', 'provider'], default: 'off',
        label: 'Challenge type',
        help: '"cookie" is the lightest tier; "captcha" is CatWAF\'s own generated image challenge; "provider" uses a third-party service.',
      },
      provider: {
        type: 'enum', values: ['none', 'recaptcha', 'hcaptcha', 'turnstile', 'mcaptcha'], default: 'none',
        label: 'Third-party provider',
      },
      site_key: { type: 'str', default: '', maxLen: 256, label: 'Provider site key' },
      secret_key: { type: 'str', default: '', maxLen: 256, label: 'Provider secret key', writeOnly: true },
      provider_verify_url: { type: 'str', item: 'url', default: '', maxLen: 2048, label: 'Provider verify URL (mCaptcha/self-hosted)' },
      valid_minutes: { type: 'int', min: 1, max: 10080, default: 1440, label: 'Solved challenge stays valid for (minutes)' },
      resolve_seconds: { type: 'int', min: 10, max: 3600, default: 300, label: 'Time allowed to solve (seconds)' },
      trigger: {
        type: 'enum', values: ['all', 'suspicious', 'countries'], default: 'suspicious',
        label: 'Who gets challenged',
        help: '"suspicious" challenges only visitors already flagged by another signal (greylist, DNSBL, bad behaviour).',
      },
      challenge_countries: { type: 'list', item: 'country', max: 250, default: [], label: 'Countries to challenge' },
      exempt_paths: { type: 'list', item: 'uri', max: 50, default: ['/api/*', '/.well-known/*'], label: 'Exempt paths' },
      exempt_ips: { type: 'list', item: 'cidr', max: 200, default: [], label: 'Exempt IPs/CIDRs' },
      exempt_asns: { type: 'list', item: 'asn', max: 100, default: [], label: 'Exempt ASNs' },
      exempt_rdns: { type: 'list', item: 'dnssuffix', max: 50, default: [], label: 'Exempt reverse-DNS suffixes' },
      exempt_user_agents: { type: 'list', item: 'ua', max: 100, default: [], label: 'Exempt user agents' },
      captcha_length: { type: 'int', min: 4, max: 8, default: 5, label: 'Generated captcha length' },
      max_attempts: { type: 'int', min: 1, max: 20, default: 5, label: 'Attempts before the visitor is banned' },
    },
  },

  // ─── Behavioural banning (#6) ─────────────────────────────────────────
  bad_behavior: {
    label: 'Behavioural banning',
    idea: [6],
    summary: 'Ban an IP that generates too many error responses, even when no WAF rule fires.',
    fields: {
      enabled: { type: 'bool', default: false, label: 'Enabled' },
      window_sec: { type: 'int', min: 10, max: 86400, default: 60, label: 'Counting window (seconds)' },
      threshold: { type: 'int', min: 1, max: 10000, default: 20, label: 'Bad responses before a ban' },
      ban_seconds: { type: 'int', min: 30, max: 2592000, default: 3600, label: 'Ban duration (seconds)' },
      status_codes: {
        type: 'list', item: 'token', max: 30, default: ['400', '401', '403', '404', '405', '429', '500'],
        label: 'Status codes that count as bad',
      },
      count_waf_blocks: { type: 'bool', default: true, label: 'Count WAF blocks too' },
      escalate: {
        type: 'bool', default: true, label: 'Lengthen repeat bans',
        help: 'Each subsequent ban for the same address doubles, up to the maximum below.',
      },
      max_ban_seconds: { type: 'int', min: 60, max: 31536000, default: 86400, label: 'Maximum ban length (seconds)' },
    },
  },

  // ─── Client port probing (#5) ─────────────────────────────────────────
  client_probe: {
    label: 'Client relay detection',
    idea: [5],
    summary: 'Check whether a suspicious client is itself an open proxy or relay.',
    fields: {
      enabled: {
        type: 'bool', default: false, label: 'Enabled',
        help: 'Off by default on purpose: probing a client address costs request latency and can generate abuse reports against your server. Read the tradeoff before enabling.',
      },
      ports: {
        type: 'list', item: 'token', max: 20, default: ['3128', '8080', '1080', '9050', '8888'],
        label: 'Ports to probe',
      },
      timeout_ms: { type: 'int', min: 50, max: 5000, default: 400, label: 'Per-port timeout (ms)' },
      cache_minutes: { type: 'int', min: 1, max: 10080, default: 1440, label: 'Cache a verdict for (minutes)' },
      action: { type: 'enum', values: ['flag', 'challenge', 'ban'], default: 'flag', label: 'Action on a positive result' },
      only_suspicious: { type: 'bool', default: true, label: 'Only probe already-suspicious clients' },
    },
  },

  // ─── Scanner tool fingerprinting ──────────────────────────────────────
  //
  // Ships DISABLED, and that default is load-bearing rather than timid.
  //
  // Every runtime-enforcement group in enforce.RUNTIME_GROUPS causes a
  // `forward_auth` hop from Caddy into CatWAF's own API to be rendered into
  // the protected site. The hop fails open for every error CatWAF can
  // *answer* — but it cannot answer at all if the API process is stopped, and
  // Caddy reads a failed dial as a denial. One enabled group is enough, so
  // enabling this by default made every default install's website depend on
  // the CatWAF admin API staying up: kill the API, and visitors get 502.
  //
  // Turning it off costs no baseline scanner detection. A default install
  // already refuses known scanner user-agents twice over, both inside Caddy
  // with no network hop: CatWAF's own rule id 9050 (sqlmap, nikto, nmap,
  // masscan, zgrab, dirbuster, gobuster, wfuzz, hydra, burpsuite) and the
  // OWASP CRS 913 "Scanner Detection" group. test/waf-e2e.test.js proves a
  // scanner user-agent is blocked 403 with this setting off.
  //
  // What this group adds on top is similarity scoring for user-agents that
  // are *close to* a known tool, and automatic banning of the address. That
  // is a real improvement and it remains one command away — but it is an
  // opt-in that trades an availability dependency for extra detection, and
  // that trade should be made deliberately, not inherited from a default.
  //
  //   catwaf settings tools_fingerprint enabled=true
  //
  // See docs/protection.md.
  tools_fingerprint: {
    label: 'Scanner tool fingerprinting',
    summary: 'Score requests against known offensive tool signatures (sqlmap, nmap, nikto, gobuster, ...): an exact match bans the address, a close-but-uncertain match is challenged instead. Off by default — enabling it adds a runtime hop into CatWAF\'s API, which the protected site then depends on.',
    fields: {
      enabled: { type: 'bool', default: false, label: 'Enabled' },
      close_threshold: { type: 'int', min: 0, max: 100, default: 55, label: 'Similarity score (0-100) that counts as a close match' },
      ban_seconds: { type: 'int', min: 60, max: 2592000, default: 86400, label: 'Ban duration for an exact match (seconds)' },
      escalate: {
        type: 'bool', default: true, label: 'Lengthen repeat bans',
        help: 'Each subsequent exact-match ban for the same address doubles, same as behavioural banning.',
      },
    },
  },

  // ─── ASN lists (#7) ───────────────────────────────────────────────────
  asn_lists: {
    label: 'ASN lists',
    idea: [7],
    summary: 'Allow or block whole origin networks by AS number.',
    fields: {
      enabled: { type: 'bool', default: false, label: 'Enabled' },
      allow: { type: 'list', item: 'asn', max: 500, default: [], label: 'Allowed ASNs' },
      block: { type: 'list', item: 'asn', max: 500, default: [], label: 'Blocked ASNs' },
      mode: {
        type: 'enum', values: ['blocklist', 'allowlist'], default: 'blocklist',
        label: 'Mode',
        help: '"allowlist" refuses every network except the allowed ones — very strict, and it will lock out any visitor whose ASN cannot be resolved.',
      },
    },
  },

  // ─── Reverse-DNS lists (#8) ───────────────────────────────────────────
  rdns_lists: {
    label: 'Reverse-DNS lists',
    idea: [8],
    summary: 'Verify a crawler really belongs to the network it claims.',
    fields: {
      enabled: { type: 'bool', default: false, label: 'Enabled' },
      allow_suffixes: {
        type: 'list', item: 'dnssuffix', max: 100,
        default: ['.googlebot.com', '.search.msn.com'],
        label: 'Allowed rDNS suffixes',
      },
      block_suffixes: { type: 'list', item: 'dnssuffix', max: 100, default: [], label: 'Blocked rDNS suffixes' },
      global_only: {
        type: 'bool', default: true, label: 'Only look up publicly routable addresses',
        help: 'Skips the DNS round-trip for private and CGNAT ranges, which never have a useful PTR record.',
      },
      forward_confirm: {
        type: 'bool', default: true, label: 'Forward-confirm the PTR record',
        help: 'Resolve the PTR name back to an address and require it to match. Without this, anyone controlling their own reverse DNS can claim to be Googlebot.',
      },
      cache_minutes: { type: 'int', min: 1, max: 10080, default: 240, label: 'Cache a lookup for (minutes)' },
      timeout_ms: { type: 'int', min: 100, max: 10000, default: 1500, label: 'Lookup timeout (ms)' },
    },
  },

  // ─── Greylist (#9) ────────────────────────────────────────────────────
  greylist: {
    label: 'Greylist',
    idea: [9],
    summary: 'Skip rate limiting and challenges for a known client, but keep the WAF watching it.',
    fields: {
      enabled: { type: 'bool', default: false, label: 'Enabled' },
      ips: { type: 'list', item: 'cidr', max: 500, default: [], label: 'Greylisted IPs/CIDRs' },
      asns: { type: 'list', item: 'asn', max: 200, default: [], label: 'Greylisted ASNs' },
      rdns_suffixes: { type: 'list', item: 'dnssuffix', max: 100, default: [], label: 'Greylisted rDNS suffixes' },
      user_agents: { type: 'list', item: 'ua', max: 100, default: [], label: 'Greylisted user agents' },
      uris: { type: 'list', item: 'uri', max: 100, default: [], label: 'Greylisted URIs' },
      skip_checks: {
        type: 'list', item: 'token', max: 10,
        default: ['rate_limit', 'challenge', 'bad_behavior'],
        label: 'Checks a greylist hit skips',
        help: 'Coraza/CRS inspection is never skipped — that is the whole difference between a greylist and an allowlist.',
      },
    },
  },

  // ─── Community blocklists (#10) ───────────────────────────────────────
  community_lists: {
    label: 'Community blocklists',
    idea: [10],
    summary: 'Subscribe to maintained external lists and refresh them on a schedule.',
    fields: {
      enabled: { type: 'bool', default: false, label: 'Enabled' },
      refresh_hours: { type: 'int', min: 1, max: 720, default: 24, label: 'Refresh interval (hours)' },
      max_entries_per_source: { type: 'int', min: 100, max: 500000, default: 50000, label: 'Max entries per source' },
      sources: {
        type: 'records', max: 30, default: [],
        fields: {
          id: { type: 'str', default: '', maxLen: 64 },
          name: { type: 'str', default: '', maxLen: 128 },
          url: { type: 'str', item: 'url', default: '' },
          kind: { type: 'enum', values: ['ip', 'user_agent', 'uri', 'asn', 'rdns'], default: 'ip' },
          list: { type: 'enum', values: ['block', 'greylist', 'allow'], default: 'block' },
          enabled: { type: 'bool', default: true },
        },
        label: 'Subscribed sources',
      },
    },
  },

  // ─── DNSBL (#11) ──────────────────────────────────────────────────────
  dnsbl: {
    label: 'DNS blackhole lists',
    idea: [11],
    summary: 'Check the client address against public abuse-source zones.',
    fields: {
      enabled: { type: 'bool', default: false, label: 'Enabled' },
      zones: {
        type: 'list', item: 'dnssuffix', max: 20,
        default: ['bl.blocklist.de', 'sbl.spamhaus.org'],
        label: 'DNSBL zones',
      },
      action: { type: 'enum', values: ['flag', 'challenge', 'ban'], default: 'flag', label: 'Action on a listed address' },
      ban_seconds: { type: 'int', min: 60, max: 2592000, default: 3600, label: 'Ban duration when action is ban' },
      cache_minutes: { type: 'int', min: 1, max: 10080, default: 120, label: 'Cache a verdict for (minutes)' },
      timeout_ms: { type: 'int', min: 100, max: 10000, default: 1200, label: 'Lookup timeout (ms)' },
      global_only: { type: 'bool', default: true, label: 'Only look up publicly routable addresses' },
    },
  },

  // ─── Upload malware scanning ──────────────────────────────────────────
  upload_scan: {
    label: 'Upload malware scanning',
    summary: 'Scan uploaded files with a local ClamAV daemon and refuse infected ones.',
    fields: {
      enabled: {
        type: 'bool', default: false, label: 'Enabled',
        help: 'Requires a local clamd daemon. CatWAF does not install or bundle one; if it is missing, this feature reports itself unavailable.',
      },
      paths: {
        type: 'list', item: 'uri', max: 50, default: ['/upload*'],
        label: 'Paths that accept uploads',
        help: 'Only these paths are routed through the scanner, so ordinary traffic is unaffected.',
      },
      methods: {
        type: 'list', item: 'method', max: 6, default: ['POST', 'PUT', 'PATCH'],
        label: 'Methods to scan',
      },
      max_scan_bytes: {
        type: 'int', min: 1024, max: 1073741824, default: 26214400,
        label: 'Largest body to scan (bytes)',
        help: 'Bodies above this are handled by the oversize action rather than scanned, since buffering is bounded.',
      },
      oversize_action: {
        type: 'enum', values: ['pass', 'block'], default: 'pass',
        label: 'Action for bodies too large to scan',
      },
      action: { type: 'enum', values: ['block', 'flag'], default: 'block', label: 'Action when malware is found' },
      fail_open: {
        type: 'bool', default: true, label: 'Allow uploads through if the scanner is unavailable',
        help: 'On by default: a stopped clamd should not take uploads down. Turn off to refuse uploads that could not be scanned.',
      },
      timeout_ms: { type: 'int', min: 500, max: 120000, default: 10000, label: 'Scan timeout (ms)' },
      socket_path: { type: 'str', default: '', maxLen: 512, label: 'clamd socket path (blank = autodetect)' },
      host: { type: 'str', default: '', maxLen: 256, label: 'clamd TCP host (blank = use the socket)' },
      port: { type: 'int', min: 1, max: 65535, default: 3310, label: 'clamd TCP port' },
      ban_seconds: {
        type: 'int', min: 0, max: 2592000, default: 0,
        label: 'Ban the uploader for (seconds, 0 = do not ban)',
      },
    },
  },

  // ─── Shared threat network (#12) ──────────────────────────────────────
  threat_network: {
    label: 'Shared threat network',
    idea: [12],
    summary: 'Opt in to exchanging anonymised attacker signals with other CatWAF instances.',
    secret: true,
    fields: {
      enabled: {
        type: 'bool', default: false, label: 'Participate',
        help: 'Off unless you turn it on. See the data policy below for exactly what would leave this machine.',
      },
      endpoint: { type: 'str', item: 'url', default: '', maxLen: 2048, label: 'Network endpoint' },
      api_key: { type: 'str', default: '', maxLen: 256, label: 'API key', writeOnly: true },
      share: { type: 'bool', default: false, label: 'Submit signals from this instance' },
      consume: { type: 'bool', default: false, label: 'Consult the network before blocking' },
      submit_interval_min: { type: 'int', min: 5, max: 1440, default: 60, label: 'Submission interval (minutes)' },
      min_confidence: { type: 'int', min: 1, max: 100, default: 50, label: 'Minimum score to act on a consulted verdict' },
      consume_action: { type: 'enum', values: ['flag', 'challenge', 'ban'], default: 'challenge', label: 'Action on a network hit' },
    },
  },

  // ─── Local threat feed (#13) ──────────────────────────────────────────
  threat_feed: {
    label: 'Local threat feed',
    idea: [13],
    summary: 'Consult a host-local behavioural daemon (CrowdSec-style bouncer API).',
    secret: true,
    fields: {
      enabled: { type: 'bool', default: false, label: 'Enabled' },
      url: { type: 'str', item: 'url', default: 'http://127.0.0.1:8080', maxLen: 2048, label: 'Bouncer API base URL' },
      api_key: { type: 'str', default: '', maxLen: 256, label: 'API key', writeOnly: true },
      header_name: { type: 'str', item: 'header', default: 'X-Api-Key', maxLen: 64, label: 'API key header' },
      decision_path: { type: 'str', item: 'uri', default: '/v1/decisions', maxLen: 256, label: 'Decisions endpoint path' },
      timeout_ms: { type: 'int', min: 100, max: 10000, default: 1000, label: 'Request timeout (ms)' },
      cache_seconds: { type: 'int', min: 5, max: 86400, default: 60, label: 'Cache a verdict for (seconds)' },
      fail_open: {
        type: 'bool', default: true, label: 'Allow traffic when the feed is unreachable',
        help: 'On by default: an unreachable optional feed should degrade to "no extra signal", not to blocking every visitor.',
      },
      action: { type: 'enum', values: ['flag', 'challenge', 'ban'], default: 'ban', label: 'Action on a positive decision' },
    },
  },

  // ─── Scheduled jobs (#44) ─────────────────────────────────────────────
  jobs: {
    label: 'Scheduled jobs',
    idea: [44],
    summary: 'The internal scheduler every time-based feature registers into.',
    fields: {
      enabled: { type: 'bool', default: true, label: 'Run scheduled jobs' },
      jitter_percent: { type: 'int', min: 0, max: 50, default: 10, label: 'Schedule jitter (%)' },
      disabled_jobs: { type: 'list', item: 'token', max: 50, default: [], label: 'Individually disabled jobs' },
    },
  },

  // ─── Backups (#45) ────────────────────────────────────────────────────
  backups: {
    label: 'Scheduled backups',
    idea: [45],
    summary: 'Copy configuration and data off the box on a schedule.',
    fields: {
      enabled: { type: 'bool', default: false, label: 'Enabled' },
      destination: {
        type: 'str', default: '', maxLen: 512,
        pattern: /^\/[^\s]*$/, patternMessage: 'Destination must be an absolute path',
        label: 'Destination directory',
      },
      interval_hours: { type: 'int', min: 1, max: 720, default: 24, label: 'Interval (hours)' },
      retain: { type: 'int', min: 1, max: 365, default: 7, label: 'Backups to keep' },
      include_database: { type: 'bool', default: true, label: 'Include the SQLite database' },
      include_caddyfile: { type: 'bool', default: true, label: 'Include the Caddyfile' },
      encrypt: { type: 'bool', default: false, label: 'Encrypt backups (AES-256-CBC; requires CATWAF_BACKUP_PASSPHRASE in .env)' },
      redact_secrets: {
        type: 'bool', default: true, label: 'Redact secrets',
        help: 'Uses the same redaction the snapshot export already applies, so API tokens and password hashes never land in a backup file.',
      },
    },
  },

  // ─── Metrics (#46) ────────────────────────────────────────────────────
  metrics: {
    label: 'Metrics export',
    idea: [46],
    summary: 'Prometheus-compatible scrape endpoint.',
    secret: true,
    fields: {
      enabled: { type: 'bool', default: false, label: 'Enabled' },
      path: { type: 'str', item: 'uri', default: '/metrics', maxLen: 128, label: 'Endpoint path' },
      require_token: { type: 'bool', default: true, label: 'Require a bearer token' },
      token: { type: 'str', default: '', maxLen: 128, label: 'Scrape token', writeOnly: true },
      allow_cidrs: { type: 'list', item: 'cidr', max: 50, default: ['127.0.0.1/32', '::1/128'], label: 'Allowed scrape sources' },
      prefix: {
        type: 'str', default: 'catwaf', maxLen: 32,
        pattern: /^[a-z][a-z0-9_]*$/, patternMessage: 'Prefix must be lowercase letters, digits and underscores',
        label: 'Metric name prefix',
      },
      include_geo: { type: 'bool', default: false, label: 'Include per-country series' },
    },
  },

  // ─── Telemetry (#47) ──────────────────────────────────────────────────
  telemetry: {
    label: 'Anonymous usage statistics',
    idea: [47],
    summary: 'Off unless you turn it on. Nothing is collected while this is disabled.',
    fields: {
      enabled: { type: 'bool', default: false, label: 'Send anonymous usage statistics' },
      endpoint: { type: 'str', item: 'url', default: '', maxLen: 2048, label: 'Collector endpoint' },
      interval_hours: { type: 'int', min: 1, max: 720, default: 168, label: 'Send interval (hours)' },
      include_version: { type: 'bool', default: true, label: 'Include CatWAF and platform versions' },
      include_feature_flags: { type: 'bool', default: true, label: 'Include which features are enabled' },
      include_counts: { type: 'bool', default: false, label: 'Include coarse traffic volume buckets' },
    },
  },

  // ─── Raw config injection (#54, #62) ──────────────────────────────────
  raw_config: {
    label: 'Raw configuration',
    idea: [54, 62],
    summary: 'Escape hatch for directives CatWAF does not model, by insertion context.',
    advanced: true,
    fields: {
      enabled: { type: 'bool', default: false, label: 'Enabled' },
      global_http: { type: 'text', maxLen: 32 * 1024, default: '', label: 'Global options block' },
      per_site: { type: 'text', maxLen: 32 * 1024, default: '', label: 'Inside the protected site block' },
      catch_all: { type: 'text', maxLen: 32 * 1024, default: '', label: 'Inside the catch-all site block' },
      waf_global: { type: 'text', maxLen: 32 * 1024, default: '', label: 'Coraza directives (global)' },
      waf_per_site: { type: 'text', maxLen: 32 * 1024, default: '', label: 'Coraza directives (per site)' },
    },
  },

  // ─── Docker label autoconfiguration (#66) ─────────────────────────────
  autoconf: {
    label: 'Docker label autoconfiguration',
    idea: [66],
    summary: 'Continuously apply configuration derived from container labels.',
    fields: {
      enabled: {
        type: 'bool', default: false, label: 'Enabled',
        help: 'Strictly opt-in: this applies configuration changes without a human confirming them. Containers without the label prefix keep the existing suggest-only behaviour.',
      },
      label_prefix: {
        type: 'str', default: 'catwaf', maxLen: 32,
        pattern: /^[a-z][a-z0-9._-]*$/, patternMessage: 'Prefix must be lowercase letters, digits and . _ -',
        label: 'Label prefix',
      },
      interval_sec: { type: 'int', min: 30, max: 86400, default: 300, label: 'Scan interval (seconds)' },
      require_enable_label: { type: 'bool', default: true, label: 'Require an explicit catwaf.enable=true label' },
      remove_orphans: { type: 'bool', default: false, label: 'Remove routes for containers that disappeared' },
      dry_run: { type: 'bool', default: false, label: 'Log what would change without applying it' },
    },
  },

  // ─── Multi-site (#65) ─────────────────────────────────────────────────
  sites: {
    label: 'Protected sites',
    idea: [65],
    summary: 'CatWAF Free protects one site. The registry exists so features stay single-site-safe as they grow.',
    fields: {
      // Free's edition boundary, expressed as a number rather than as an
      // assumption scattered through the code. Raising it in Free is refused
      // by the sites service; it is here so a future tier flips one value.
      max_sites: { type: 'int', min: 1, max: 1, default: 1, label: 'Maximum protected sites' },
      primary_host: { type: 'str', item: 'host', default: '', maxLen: 253, label: 'Primary hostname' },
      aliases: { type: 'list', item: 'host', max: 20, default: [], label: 'Additional hostnames for the same site' },
    },
  },

  // ─── Shared state (#67) ───────────────────────────────────────────────
  cluster: {
    label: 'Shared state',
    idea: [67],
    summary: 'Optional external store for counters that must be consistent across nodes.',
    secret: true,
    advanced: true,
    fields: {
      backend: {
        type: 'enum', values: ['memory', 'redis'], default: 'memory',
        label: 'Counter backend',
        help: 'Only counters (rate limits, ban expiry, challenge tokens) move. SQLite stays the source of truth for configuration.',
      },
      url: {
        type: 'str', default: '', maxLen: 512,
        pattern: /^rediss?:\/\/(?:\[[a-fA-F0-9:]+\]|[A-Za-z0-9.-]+)(?::\d{1,5})?(?:\/\d+)?$/, patternMessage: 'Use redis:// or rediss://host:port/db without credentials; use the Password field',
        label: 'Redis URL',
      },
      password: { type: 'str', default: '', maxLen: 256, label: 'Password', writeOnly: true },
      key_prefix: { type: 'str', default: 'catwaf:', maxLen: 64, label: 'Key prefix' },
      sentinel_master: { type: 'str', default: '', maxLen: 64, label: 'Sentinel master name' },
      sentinels: { type: 'list', item: 'upstream', max: 10, default: [], label: 'Sentinel addresses' },
      timeout_ms: { type: 'int', min: 50, max: 10000, default: 500, label: 'Operation timeout (ms)' },
      fail_open: { type: 'bool', default: true, label: 'Fall back to in-memory counters if unreachable' },
    },
  },

  // ─── Database engine (#68) ────────────────────────────────────────────
  database: {
    label: 'Database',
    idea: [68],
    summary: 'Engine choice and pool tuning. SQLite is the right answer at Free\'s scale.',
    advanced: true,
    fields: {
      engine: { type: 'enum', values: ['sqlite'], default: 'sqlite', label: 'Engine' },
      pool_size: { type: 'int', min: 1, max: 256, default: 5, label: 'Connection pool size' },
      max_overflow: { type: 'int', min: 0, max: 256, default: 10, label: 'Pool overflow' },
      recycle_sec: { type: 'int', min: 0, max: 86400, default: 1800, label: 'Recycle connections after (seconds)' },
      pre_ping: { type: 'bool', default: true, label: 'Check liveness before using a pooled connection' },
      retry_attempts: { type: 'int', min: 0, max: 20, default: 3, label: 'Connection retry attempts' },
      retry_delay_ms: { type: 'int', min: 10, max: 60000, default: 500, label: 'Retry delay (ms)' },
      busy_timeout_ms: { type: 'int', min: 0, max: 120000, default: 5000, label: 'SQLite busy timeout (ms)' },
      journal_mode: { type: 'enum', values: ['WAL', 'DELETE', 'TRUNCATE', 'PERSIST', 'MEMORY'], default: 'WAL', label: 'SQLite journal mode' },
      synchronous: { type: 'enum', values: ['OFF', 'NORMAL', 'FULL', 'EXTRA'], default: 'NORMAL', label: 'SQLite synchronous mode' },
    },
  },

  // ─── Canary auto-ban ─────────────────────────────────────────────────
  canary: {
    label: 'Canary auto-ban',
    summary: 'Paths no legitimate visitor requests. Touching one is intent — probe it and the address is banned outright, before any payload is even evaluated.',
    fields: {
      enabled: { type: 'bool', default: false, label: 'Enabled' },
      paths: { type: 'list', item: 'uri', max: 25, default: ['/.env', '/.git/config', '/.git/HEAD', '/.htpasswd', '/.aws/credentials', '/wp-config.php.bak'], label: 'Canary paths' },
      ban_seconds: { type: 'int', min: 300, max: 2592000, default: 86400, label: 'Ban duration (seconds)' },
      escalate: { type: 'bool', default: true, label: 'Escalate repeat offenders' },
    },
  },

  // ─── Edge ban enforcement ────────────────────────────────────────────
  edge_bans: {
    label: 'Edge ban enforcement',
    advanced: true,
    summary: 'Render the newest active bans directly into the Caddyfile so banned addresses are dropped by Caddy itself — no forward_auth hop, no WAF evaluation, no bytes to the origin.',
    fields: {
      enabled: { type: 'bool', default: false, label: 'Enabled' },
      max_rules: { type: 'int', min: 50, max: 2000, default: 500, label: 'Maximum rules rendered (newest first)' },
      include_cidrs: { type: 'bool', default: true, label: 'Include CIDR-range bans' },
      refresh_seconds: { type: 'int', min: 15, max: 600, default: 30, label: 'Refresh interval (seconds)' },
    },
  },

  // ─── Kernel-level drops (nftables, opt-in) ───────────────────────────
  kernel_bans: {
    label: 'Kernel-level drops',
    advanced: true,
    summary: 'Mirror active bans into an nftables set so banned addresses die at SYN, before Caddy. Requires CATWAF_KERNEL_BANS=1 in .env, root, nftables, and a one-time firewall rule you add yourself (catwaf kernel-bans print-rules). Host installs only.',
    fields: {
      enabled: { type: 'bool', default: false, label: 'Enabled' },
      max_entries: { type: 'int', min: 100, max: 262144, default: 65536, label: 'Maximum set entries' },
    },
  },

  // ─── Anti-DDoS (#75) ─────────────────────────────────────────────────
  ddos: {
    label: 'Anti-DDoS',
    summary: 'Under-attack switch: challenges every visitor (JavaScript proof), shortens cached verdicts to seconds, and keeps canary/edge/kernel enforcement at their most responsive. Connection timeouts live under Connections.',
    fields: {
      emergency: { type: 'bool', default: false, label: 'UNDER-ATTACK MODE' },
      verdict_ttl_seconds: { type: 'int', min: 1, max: 20, default: 2, label: 'Verdict cache TTL while under attack (seconds)' },
    },
  },

  // ─── SIEM event stream (#76) ─────────────────────────────────────────
  siem: {
    label: 'SIEM event stream',
    advanced: true,
    summary: 'Append every blocked request as JSON lines to data/siem.jsonl (rotated) and optionally POST batches to an HTTP collector.',
    fields: {
      enabled: { type: 'bool', default: false, label: 'Enabled' },
      include_allowed: { type: 'bool', default: false, label: 'Include allowed requests too' },
      http_url: { type: 'str', item: 'url', default: '', maxLen: 2048, label: 'Optional HTTP collector URL (POSTs JSONL)' },
      batch_max: { type: 'int', min: 50, max: 5000, default: 500, label: 'Max events per poll/batch' },
    },
  },

  // ─── Alert delivery (#74) ────────────────────────────────────────────
  alert_dispatch: {
    label: 'Alert delivery',
    secret: true,
    summary: 'Actually send the alerts configured on the Alerts page: attack spikes, new bans and engine changes delivered to your webhooks or Telegram.',
    fields: {
      enabled: { type: 'bool', default: false, label: 'Enabled' },
      spike_window_min: { type: 'int', min: 1, max: 60, default: 5, label: 'Spike window (minutes)' },
      cooldown_min: { type: 'int', min: 1, max: 1440, default: 15, label: 'Per-alert cooldown (minutes)' },
      on_spike: { type: 'bool', default: true, label: 'Alert on blocked-request spikes' },
      on_new_ban: { type: 'bool', default: false, label: 'Alert on every new automatic ban' },
      on_engine_change: { type: 'bool', default: true, label: 'Alert on engine/mode changes' },
    },
  },
}

function defaultsFor(group) {
  const def = SCHEMA[group]
  if (!def) return null
  const out = {}
  for (const [name, spec] of Object.entries(def.fields)) {
    out[name] = spec.default && typeof spec.default === 'object'
      ? JSON.parse(JSON.stringify(spec.default))
      : spec.default
  }
  return out
}

module.exports = { SCHEMA, defaultsFor, GROUP_NAMES: Object.keys(SCHEMA) }
