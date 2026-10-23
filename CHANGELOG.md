# Changelog

All notable changes to this project are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

**A note on version numbers.** Public CatWAF releases use a single `1.x` line. Earlier
entries in this file carried numbers from two superseded schemes — an internal `3.x-dev`
line that was never published, and a short-lived `2.x` line that ran on top of the first
public release. Those entries are preserved below under the release they belong to; the
numbers themselves were retired, not the history. Nothing here has been deleted or
rewritten, only re-filed.

## Unreleased — 2026-10-24

- CatWAF Free returns to the MIT License. Use, modification, redistribution, and commercial operation are permitted under `LICENSE`. CatWAF Pro remains separate; the CatWAF name and logo remain governed by `TRADEMARKS.md`.

**1.0.2 security update — 2026-10-17.** This update hardens configuration and
database rollback, backup restore, authentication, API contracts, audit rotation,
and the Node.js control plane without adding Go application code. The
[security recheck](docs/security-recheck-2026-10-17.md) records the test evidence.
Release validation remains blocked by reload connection resets and an
unsuppressed upstream Go module advisory. These
checks remain enabled; this update is not a clean release-gate result.

## Audit and Kubernetes fixes — 2026-10-17

- Follow late audit writes across log generations with persistent inode-bound
  cursors. Prune only after proving writer retirement and successful ingestion.
- Add a private Node.js writer observer to the Caddy image; preserve separate
  backend/proxy users and avoid PID namespace sharing or added capabilities.
- Preserve shared audit-file permissions under restrictive umasks, and treat
  unreadable files as failures rather than successful drains.
- Remove Kubernetes Secret API permission. Read explicitly mounted TLS Secrets
  from one kubelet generation; restrict the projected API token to the backend.
- Remove inherited Caddy file capabilities so hardened Kubernetes Pods can start.
- Add a real kind cluster integration check and CI job. See the
  [follow-up validation](docs/reliability-followup-2026-10-17.md).

## Free integrations update — 2026-10-17

See the [feature validation report](docs/feature-validation-2026-10-17.md)
for passing checks, deployment limits and unsuppressed findings.

- Implement Docker host/path autoconfiguration and namespace-scoped Kubernetes
  v1 Ingress reconciliation in Node.js, with TLS Secrets and transactional rollback.
- Add the Docker & Kubernetes dashboard, optional restricted metadata bridge,
  Kubernetes manifests, API documentation and CatAI knowledge.
- Fix cookie challenge round trips, CAPTCHA answer exposure, provider hostname /
  freshness checks, mCaptcha verification and concurrent token replay.
- Enforce CrowdSec IP/Range decision expiry and explicit outage policy without
  creating stale permanent bans; enforce mandatory CAPTCHA before exemptions.
- Activate runtime enforcement transactionally for the first manual ban. Return
  503 on unexpected enforcement exceptions; report controller job failures.
- Permit configurable Free site capacity up to 1000. This is a resource ceiling,
  not a tested capacity or an HA promise. Existing release blockers remain.

## [Unreleased] — 2026-08-24 — Edge enforcement & alert delivery

### New: edge ban enforcement
Banned addresses are now rendered directly into the Caddyfile (`remote_ip` matcher +
`abort`, refreshed on its own scheduler tick and within ~2s of any ban change) so a
banned client's connection is dropped by Caddy itself — no forward_auth hop, no WAF
evaluation, no bytes to the origin. Allowlist coverage is enforced in BOTH directions
(a banned IP inside an allowlisted range AND a banned range swallowing an allowlisted
IP are both excluded), content-hash short-circuits skip unchanged rewrites, failed
reloads retry on the next tick, and every write goes through the config lock atomically.
New `edge_bans` settings group; `test/features.test.js` covers rendering, allowlist
exemption, idempotence and failure paths.

### New: canary auto-ban
Paths like `/.env`, `/.git/config`, `/.htpasswd` are intent, not traffic: the first hit
now earns an immediate escalating ban (new `canary` ban source) instead of a plain 403.
Dry-run (`/api/protect/test`) reports what it would do without writing; canary requests
deliberately bypass the per-IP verdict cache so an allow earned elsewhere never excuses
them.

### New: kernel-level drops (opt-in)
`services/kernelBans.js` mirrors active bans into a dedicated `catwaf_edge` nftables
table (interval sets, v4+v6) for drops at SYN. Gated behind `kernel_bans.enabled` AND
`CATWAF_KERNEL_BANS=1`, root, nftables presence, and a non-container host; CatWAF
manages only its own table, replaced atomically each refresh (expired/lifted bans truly
leave the set), every element re-validated before it reaches nft syntax, allowlist
conflicts excluded in both directions. The one-time forwarding rule is operator-applied:
`catwaf kernel-bans print-rules`.

### New: alert delivery (#74) — alerts actually send now
The webhook URLs and thresholds on the Alerts page were stored but nothing ever sent
them. `services/alertDispatch.js` delivers to Slack/Discord/custom webhooks and
Telegram on three triggers: blocked-request spikes (threshold + window configurable),
new automatic bans, and engine changes — with cross-process-safe per-kind cooldowns,
refund-on-total-delivery-failure, and per-channel fault isolation. New `alert_dispatch`
settings group; wired into the job scheduler.

### New: backup restore path
`catwaf backup restore <file> [--db] [--allow-redacted] [--confirm-db-restore]` — config
restores run through the same validate-and-rollback transaction pipeline as live edits;
redacted backups refuse unless forced; out-of-range values fail validation untouched;
database restore refuses while the server appears to be writing and stages via temp+
rename with WAL sidecar handling.

### Also
* GeoIP database age surfaced in `/api/diagnostics` with update guidance (the bundled
  MaxMind data is static and degrades silently otherwise).
* OpenAPI drift test (`openapi-drift.test.js`) fails CI when Express routes and
  openapi.yaml diverge; 102 legacy undocumented endpoints catalogued with hygiene
  warnings.
* Docker stack hardened: `cap_drop ALL` on backend, `NET_BIND_SERVICE`-only for Caddy,
  log rotation, tmpfs /tmp.

### Docs: how you actually reach the dashboard

The default install binds `127.0.0.1:8000` and serves everything itself —
no `catwaf.<domain>` exists unless you configure one. README, installation
guide and `.env.example` now say so explicitly: a *Where is my dashboard?*
table covers all three shapes (this machine / another device via
`HOST=0.0.0.0` / a domain with TLS), the domain section is marked optional,
the setup wizard prints LAN-access instructions when it detects a
non-loopback bind, and the previously undocumented `HOST`/`PORT` are now in
`.env.example`.

### Attack Map rework (dashboard)

Attack markers were large dark spheres that read as black blobs on the
globe. They are now small soft-glow points in the red family, each beating
on its own phase so an active region shimmers rather than throbs; size
growth with request volume is hard-capped. Severity shifts the hue slightly
(never to near-black), and the legend matches.

Hovering a dot opens a cursor-following tooltip with attack totals for that
location across 24 hours / 5 days / 7 days / 30 days (fetched lazily,
60s-cached). The paint-window selector gained Live / 5-day / 30-day options
alongside the existing ones.

## [Unreleased] — 2026-08-24 — Anti-DDoS, update checks & operations

### New: anti-DDoS layer (#75)
UNDER-ATTACK MODE: one switch challenges every non-exempt visitor (JavaScript proof)
and drops cached verdicts to seconds. Slowloris-resistant connection timeouts were
already rendered under Connections — now documented as the deliberate single source.

### New: `catwaf update` (#77)
Asks GitHub (`agugusgeyehe-dot/catwaf` releases) whether a newer version exists,
cached daily, surfaced in CLI + diagnostics. Read-only by design — no auto-install.
Handles "no releases published yet" gracefully.

### New: SIEM event stream (#76)
Every blocked request (optionally all requests) appended as JSON lines to
data/siem.jsonl with size rotation, exactly-once cursor across restarts, optional
HTTP collector POSTs. Settings group `siem`.

### Improvements
* Edge/kernel ban lists order permanent bans first — scanner churn can no longer push
  a permanent manual ban out of the rendered set.
* Prometheus metrics for the new tiers: edge_bans_active, kernel_bans_active,
  canary_hits_total, alerts_delivered_total{kind} (+ runtime counter flush job).
* `/api/protect/status` exposes ddos/canary/edge_bans/kernel_bans/alert delivery state;
  dashboard Protection page shows an enforcement card and the Alerts page gains the
  delivery toggle.
* Backups can be encrypted at rest (AES-256-CBC/PBKDF2 via openssl; passphrase lives in
  CATWAF_BACKUP_PASSPHRASE, deliberately NOT in the database). list/prune/restore all
  understand encrypted manifests and database copies.
* `test/edge-e2e.test.js`: real-Caddy proof that a banned source address is aborted at
  the edge and un-banning propagates over admin-API reload.
* `scripts/bench.js` + docs/performance.md: reproducible throughput harness with sample
  numbers (edge region ≈ free on loopback).
* Docs: settings reference regenerated (canary/edge_bans/kernel_bans/ddos/siem/
  alert_dispatch), protection.md sections for every new tier, cli.md additions.

## [Unreleased] — 2026-08-24 — Architecture remediation pass

Follow-up to the security audit: the five "remaining concerns" were
re-verified from scratch and remediated at the architecture level where
needed. Every change preserves observable behavior; the full test suite
(21 suites) passes unchanged plus new regression tests.

### Cross-process configuration races — FIXED (architectural)

CatWAF runs as several processes (API server, `catwaf` CLI, scheduled jobs)
that all read-modify-write the same state blob and the same Caddyfile with
no coordination: concurrent writers silently overwrote each other and
interleaved Caddyfile edits could corrupt marker regions.

New `services/configLock.js`: an O_EXCL lock file in the data directory with
holder tokens, dead-pid/age-based stale breaking (a crashed holder cannot
pin it forever), re-entrancy for nested callers, and a conservative rule —
an unparseable or mid-write lock file is treated as LIVE, never broken.
Every Caddyfile writer now takes this lock (`configTx.apply`, the WAF and
sensitive-file patchers, audit-log rotation's SecAuditLog repoint,
`catwaf auto` proxy apply, the Cloudflare origin lock), and every write is
temp-file + `rename` atomic, so readers on other processes never see a torn
file.

State gained a revision counter (`waf__rev`) and `state.updateWAF()`, the
cross-process-safe mutation entry point: under the lock it re-reads
committed state if any other process moved since our last load, applies the
mutator to that fresh object, persists, and optionally patches+reloads
Caddy while still holding the lock. All legacy direct-writer routes (engine,
paranoia, anomaly thresholds, WAF settings, IP lists, geo toggling, alerts,
performance presets), CatAI actions/undo and autoconf scans migrated to it;
user management mutators serialize through the same lock with forced-fresh
reads.

Three subtle bugs were found and fixed while building this — each one is
covered by a regression test:

* boot-time torn read pairing a new revision with an old blob (refresh
  would then never fire again);
* revision written BEFORE the blob let a refresher accept `(newRev,
  oldBlob)` as a stable pair — the commit barrier is now the revision,
  written last;
* the stale-lock breaker could fire on a live holder's not-yet-written
  token file; unparseable files are now judged by age, and holders verify
  ownership after writing.

`test/concurrency.test.js` spawns real child processes against a shared
database: 8 writers × 25 mutations lose nothing, locked file writes land
exactly once, stale locks recover, throwing mutations release the lock and
persist nothing, atomic writes leave no debris.

### DNS rebinding TOCTOU in outbound fetches — FIXED

`netGuard.guardedFetch` validated DNS and then handed the *hostname* to
`fetch`, which resolved it a second time inside undici — DNS answering the
validation with a public address and the connection with 127.0.0.1 won both
halves. The transport is rewritten on node:http/https with a pinned lookup:
one resolution, judged against the reserved-range table, and only the
judged addresses are handed to the socket, so connect cannot land anywhere
else. SNI and Host keep pointing at the original hostname; redirect hops
re-pin per host; responses are size-capped and content-encoding-aware
(gzip/deflate/raw-deflate/brotli, with decompression-bomb limits). A new
regression test drives a real local server through redirects/method/body
semantics and proves a private DNS answer is refused before connecting.

### TRUST_PROXY_HOPS footgun — MITIGATED

Trusting one forwarded hop was unconditional, so any bare-port deployment
let clients forge `req.ip` (and with it rate-limit keys and CIDR checks).
The default is now inferred: 1 hop when DOMAIN or CATWAF_HTTPS says a proxy
fronts the API, 0 (trust nothing) otherwise; explicit values 0–8 are
validated, garbage fails safe to 0, and the effective choice is announced
at boot. `test/trust-proxy.test.js` boots real servers in all four
configurations and checks which address the server attributes.

### Installer supply-chain integrity — MITIGATED (honest limits)

Node itself installs from the NodeSource apt/rpm repository whose metadata
is GPG-signed — the distro verifies every package; only the one-time
bootstrap script rides on TLS trust alone (now documented in-place). The
Ollama installer is saved to disk before running (never piped), runs with
output visible instead of discarded, and honors an operator-supplied
`CATWAF_OLLAMA_INSTALL_SHA256` pin. The caddyserver.com download API
publishes no checksums for its builds, so nothing can be verified the way a
release artifact can; `ensure-caddy.js` now pins a version, refuses
off-host redirects, sanity-checks the binary image, records the build's
SHA-256 on first install (trust-on-first-use, `data/caddy-pin.json`) and
requires the SAME hash on reinstalls unless
`CATWAF_CADDY_ALLOW_NEW_BUILD=1` says otherwise. The remaining boundary —
first-install trust of the build service — is stated in the script output
rather than hidden.

### geoip-lite advisory (GHSA-mwp4-54f8-5fhr) — FIXED via upstream

geoip-lite updated to ^2.0.3, which depends on ip-address 10.x: `npm audit`
is clean. As defense-in-depth, `services/geoip.js` now only forwards
canonical addresses (strict dotted-quad or plain hex IPv6) to the bundled
parser — non-canonical spellings can never reach the vulnerable parsing
path at all.

## [Unreleased] — 2026-08-24 — Security audit hardening

A full-pass security audit of the repository. Every fix below is minimal and
behaviour-preserving unless stated; the existing test suite passes unchanged
except where a test asserted the insecure behaviour being removed.

### Fixed — request-path integrity

- **Client-IP spoofing against the enforcement plane (high).** Caddy's
  `forward_auth` hop proxies the visitor's *original* headers, so a visitor
  could set `X-Real-IP` or `X-CatWAF-Client-IP` freely and every ban,
  allowlist hit, challenge decision, attempt counter and tool-fingerprint
  ban keyed off an address the visitor chose — banning whoever they named,
  or rotating identity per request to evade bans. The rendered config now
  overwrites both headers with `{http.request.remote.host}` on the enforce,
  challenge and upload-scan hops (`render/site.js`), and `forwardedIp()` /
  `challenge.clientIp()` no longer sniff raw `X-Forwarded-For` at all.
- **`POST /api/protect/test` could write real bans (high).** The endpoint was
  reachable by viewer-role accounts, accepted CIDRs with no self-lockout
  guard, and drove the live pipeline: a viewer could ban any address —
  including `0.0.0.0/0`, blocking every visitor — and use relay probing as a
  port-scan-for-hire. It is now admin-only and runs the pipeline in a new
  dry-run mode: it reports what *would* happen (including `would_ban`) while
  writing no bans and making no outbound probe connections.
- **Malformed cookie could hang enforcement (high).** `Cookie: catwaf_ch=%`
  threw inside `decodeURIComponent`; on `/api/enforce` (an async handler in
  Express 4) that meant no response at all, so forward_auth waited until
  timeout for any visitor sending that header. Cookie parsing is now
  throw-safe and the gateway wraps verification fail-closed.

### Fixed — access control

- **Webhook URLs were readable by viewer-role accounts.** `GET /api/alerts`
  returned Slack/Discord webhook URLs and Telegram bot tokens verbatim, and
  `GET /api/diagnostics/export` dumped all of `state.WAF` plus recent audit
  entries to any logged-in session. Alerts reads/saves now redact
  secret-shaped fields for non-admins, the diagnostics export is admin-only
  and redacted, `/api/caddy/status` hides the server path from viewers, and
  app discovery/verification are admin-only (they probe host containers and
  fire attack-shaped requests at upstreams).
- **`/api/alerts` accepted arbitrary keys into persisted config.** The only
  schema-less write path left in the API now has a field allowlist. Unknown
  keys are dropped (and reported as `ignored`) rather than rejected, so
  legacy rows cannot brick the dashboard's save button. `POST
  /api/alerts/test` also actually delivers now — Slack/Discord/custom
  webhooks receive a real POST through the SSRF-guarded fetch, instead of
  the old unconditional "sent!" fiction.
- **Prototype-pollution sinks closed.** A persisted JSON blob carrying an
  own `"__proto__"` key survived spread merges and fired a real prototype
  change at every `Object.assign(state.WAF, …)` restore/load site
  (`configTx.restoreWaf`, snapshot restore, `state.reloadAllFromDb`,
  settings load). All loads/restores/persists now strip
  `__proto__`/`constructor`/`prototype` keys.

### Fixed — validation and injection hardening

- **IPv6 input validation.** `isValidIpOrCidr` accepted junk such as `::::`
  or prefixes beyond `/128`. Such an entry persisted to state and then broke
  every subsequent Caddyfile render — freezing all configuration changes
  until the row was removed by hand. Validation now fully parses the address
  and prefix length.
- **Cloudflare origin-lock IP list is validated before splicing.** The
  ranges fetched from cloudflare.com went into the Caddyfile verbatim; a
  manipulated response containing newlines or braces could inject arbitrary
  Caddy directives. Every entry must now be exactly an IP/CIDR or the lock
  is refused. Origin private keys are chmod 0600 after generation, and the
  outbound list fetches have timeouts.
- **SSRF guard: IPv4-mapped IPv6 in hex dress.** `::ffff:a00:1` is
  10.0.0.1, but only the dotted spelling was unwrapped by
  `netGuard.reasonNotPublic` — the origin scanner could be aimed at internal
  hosts. Mapped literals are now normalised to their IPv4 address before the
  reserved-range checks.
- **Coraza rule escaping.** `escapeForDirective` neutralised backticks and
  double quotes but not single quotes, while custom-rule names land inside
  `msg:'…'` — a `'` could inject additional Coraza actions
  (`ctl:ruleEngine=Off`). Single quotes are escaped now.
- **Innocent user agents were auto-banned.** The nmap fingerprint's
  unanchored `/nmap|nse/i` matched the substring "nse" ("Onset…",
  "U…nse…en") — and an exact-tier hit is an automatic site-wide ban. The
  alternative is word-bounded; real nmap still matches exactly.

### Fixed — denial of service and resource limits

- Challenge failure counters are capped (oldest-evicted), and the public
  challenge endpoints carry their own rate limits — they sit before the
  shared limiter by design, so previously nothing throttled them.
- The bcrypt worker pool rejects work beyond a small queue bound instead of
  accepting an unbounded login flood; saturation answers 429 rather than a
  misleading 500.
- Login throttling adds a per-account budget (30 attempts / 5 min) that
  survives `X-Forwarded-For` rotation on directly exposed deployments, plus
  a hard map-size ceiling.
- The webroot scan walks with depth/entry bounds instead of blocking the
  event loop on arbitrarily large trees; simulations cap concurrent Caddy
  sandboxes at two; ClamAV replies are byte-capped and the daemon is never
  auto-discovered under world-writable `/tmp`.
- Analytics windows are clamped to one year, keeping `?window=100000w` from
  turning every chart query into a full-table scan.

### Fixed — availability of protection features

- **The challenge page's own scripts were blocked by CatWAF's CSP.**
  `default-src 'none'; script-src 'self'` meant the proof-of-work never ran
  and provider widgets never loaded — enabling javascript/provider challenge
  modes put flagged visitors into an infinite 503 loop. The page now ships a
  purpose-built CSP (provider origins via the previously-dead
  `cspSources()`, inline script allowed for this one interstitial).
- Host-local integrations work again: the SSRF guard's private-range block
  made the default local threat-feed URL (`http://127.0.0.1:8080`) and
  self-hosted mCaptcha permanently unreachable. Those two callers opt into
  `allowLoopback` explicitly; everything else keeps full DNS validation.

### Fixed — deployment surface

- `scripts/start.js` no longer hands `caddy run --config $CADDYFILE_PATH` to
  `concurrently`, which executes command strings through a shell — anyone
  who could write `.env` could run arbitrary commands as the service user at
  next start. Both processes spawn argv-array direct now, with proper
  sibling teardown and error handling, and `--experimental-sqlite` reaches
  the backend process via `execArgv`.
- Interactive `catwaf setup` installs the same hardened systemd unit the
  shell installer does (sandboxing directives, dedicated service account
  when present, `.env` chowned accordingly) instead of silently replacing a
  hardened install with an unhardened root unit. `.env` is forced to 0600 on
  every rewrite, not just creation.
- The backend container drops privileges to the `node` user.
- Backup destinations must resolve inside the configured backup directory —
  previously any writable absolute path would do, staging a 0600 copy of the
  entire SQLite database there and pruning `catwaf-backup-*` files in it.
- Audit-log rotation keeps its integrity promise: a failed ingest no longer
  marks rotation complete (the pending marker retries next cycle), prune
  never deletes a file still referenced by a pending marker, recovery
  validates state-file paths against directory escape, and PID-file stops
  verify `/proc/<pid>/cmdline` before signalling (PID-reuse guard).

### Fixed — CLI and misc

- `environment.which()` scans `PATH` in-process instead of interpolating its
  argument into a `sh -c` string (a latent command-injection primitive).
- TUI log/explain rendering strips every ANSI/C0/C1 control byte from
  attacker-shaped fields (URI, user agent, IP) — terminal escape sequences
  planted in blocked requests could steer an operator's terminal.
- Frontend: the gate path from localStorage/handshake is validated against
  the exact `/g/<32-hex>` shape before any authenticated call prepends it,
  so a poisoned value cannot redirect Bearer-token traffic cross-origin.
  CatAI apply confirms weakening actions server-side (`confirm_weaken`).
- Tests: `auth-flow` binds loopback unless `CATWAF_TEST_LAN=1`, suites pin
  `CADDY_ADMIN_URL` unconditionally away from a live instance, and SIGTERM
  cleanup gaps were reviewed.

## [1.0.2] — 2026-08-13 — Upload scanning, the configuration and protection layer, and release hardening

Three bodies of work land together here. They are kept as separate sections
below because they were built separately and each stands on its own.

### Upload scanning and outbound-request fixes

#### Added

- **Optional upload malware scanning.** Files posted to the paths you nominate
  are scanned by a local ClamAV daemon before they reach your origin. This is
  the only feature that puts CatWAF in the request *data* path, and only for
  those paths — everything else still goes straight to the origin. Off by
  default. CatWAF neither bundles nor installs an AV engine: with no local
  `clamd`, `GET /api/upload-scan/status` reports the scanner unavailable rather
  than failing requests, and `fail_open` (on by default) decides what happens to
  an upload that could not be scanned. Buffering is bounded by
  `max_scan_bytes`, so an upload of any size costs a fixed amount of memory.
  `setup.sh --with-clamav` installs the daemon; the feature still stays off
  until enabled in Settings. New `upload_scan` settings group, new
  `POST /api/upload-scan/test` (send EICAR through it to prove the wiring), and
  a new `upload_malware` ban source. See
  [`docs/protection.md`](docs/protection.md#upload-malware-scanning).
- **`GET /api/sensitive/levels`** reports what each Sensitive File Level
  actually is, measured from the wordlists on disk rather than described. It
  reports the enforced path count separately from the list size, because only
  the first 500 paths of each level reach the Caddyfile — "SFL1 is on" has never
  meant all 61,882 of its paths are blocked, and the API now says so.

#### Fixed

- **Every outbound POST CatWAF made was sent with an empty body.**
  `netGuard.guardedFetch` rebuilt the request options it passed to `fetch` and
  never carried `body` across, so captcha verification, telemetry submission and
  threat-network signals all transmitted nothing. The visible consequence was
  the serious one: a challenge provider cannot verify a token it was never sent,
  so every visitor failed the captcha and a site with the challenge gate enabled
  locked out its own legitimate traffic. The body is now forwarded, and
  `test/attack.test.js` asserts it — including that a 307 preserves the method
  and body while a 302 does not replay a secret-bearing body as a GET.
- **CatAI claimed a memory it does not have.** Asked to remember something for
  later, it would agree. Each question is answered fresh, so it now says that
  plainly instead. The prompt and the knowledge base agree on this.

#### Security

- **`js-yaml` upgraded to 4.3.1** (GHSA-5p4m-2wfm-xmqj, quadratic CPU consumption
  in `!!omap`) and **`nanoid` to 3.3.18**. Neither was reachable with hostile
  input — the only `yaml.load()` parses knowledge-base frontmatter shipped in the
  repository — but both fixes were non-breaking, so they were taken rather than
  documented. The two remaining advisories (`geoip-lite`/`ip-address` and
  `react-router`) are unchanged and re-assessed in
  [SECURITY.md](SECURITY.md#dependency-posture); in both cases the offered fix is
  a downgrade or a major upgrade.
- **CatAI no longer logs the prompt it built.** The debug line recorded the whole
  prompt, which carries the operator's question and the live configuration
  retrieved for it. It now records the size only.

#### Changed

- The CatAI dock's header and footer act as a drag handle, so the whole chat
  panel can be repositioned rather than only the toggle button.
- `test/edition.test.js` asserts that `catwaf version` prints a bare semver
  matching `package.json`, instead of a hardcoded literal that had to be
  hand-edited every release.

### Release hardening

Fixes for the problems that stopped CatWAF from being installable and usable by
someone who is not the person who wrote it: signing in, reaching the dashboard
from an address other than the one it was set up on, and a default that made
every protected site depend on the CatWAF admin process.

#### Security

- **Signing out did not end the session.** `session.close()` deleted the session
  record, but `touch()` treats a missing record as valid — deliberately, so a
  token that predates the store or survived a restart is not mistaken for an
  attack. The result was that the JWT stayed usable for its full lifetime after
  the operator pressed *Sign out*, so anyone holding a copy kept their access.
  Explicit revocation is now recorded separately from session tracking and
  checked before anything else, including `/api/sessions/revoke-all`. Entries
  expire when the token would have anyway, so the list cannot grow unbounded.
- **The dashboard never called `POST /api/auth/logout`.** It cleared its own
  localStorage and stopped there — so even with the fix above, nothing was
  revoked. It now calls the endpoint, and still clears local state if the call
  fails, because a logout must not be blocked by an unreachable server.
- **`tools_fingerprint` now ships disabled.** Any enabled runtime-enforcement
  feature renders a `forward_auth` hop from Caddy into CatWAF's API, and Caddy
  reads a failed dial as a denial — so with this on by default, stopping the
  CatWAF API returned **502 to every visitor of every protected site**. The
  documented "fails open" guarantee only ever covered errors CatWAF could
  *answer*. Turning it off costs no baseline detection: a default install still
  refuses known scanner user-agents twice inside Caddy, via CatWAF rule `9050`
  and the OWASP CRS `913` group. It remains one command away
  (`catwaf settings tools_fingerprint enabled=true`), which is now a deliberate
  trade rather than an inherited one. Guarded by `test/render.test.js` and
  `test/waf-e2e.test.js`; verified manually — with the API stopped, protected
  sites still serve 200 and still block 403.

#### Fixed

- **The login loop.** `AuthProvider.login()` dispatched `catwaf-auth-changed`,
  whose handler re-verified the session it had just created. Every failure of
  that check — including one that never reached the server — ran through a
  single `.catch(() => setUser(null))`, discarding the session and returning to
  the login screen. Only a real rejection from the server (401/403) ends a
  session now; a transport failure leaves it intact and surfaces the reason.
- **`ECONNREFUSED` shown as "Failed to fetch".** Every call in the API client
  goes through one wrapper that turns a transport failure into
  `CatWAF API is unavailable. Check that the CatWAF backend is running
  (\`catwaf status\`), then try again.` with the code `API_UNREACHABLE`. When a
  signed-in operator's backend goes away they get a screen that says so and
  offers a retry, rather than a login form that cannot succeed.
- **The dashboard only worked from the exact URL recorded at setup.** Two
  independent causes, both fixed:
  - CORS refused any origin not in `CORS_ORIGIN`, including the server's *own*
    address. A request whose `Origin` is the server that answered it is not a
    cross-origin request and is now always allowed; `CORS_ORIGIN` still governs
    genuinely cross-origin callers.
  - The CSP sent `upgrade-insecure-requests` unconditionally. Browsers exempt
    `localhost` and `127.0.0.1` as trustworthy origins but **not** a LAN
    address, so on `http://192.168.x.y:8000` every asset and API call was
    upgraded to `https://` against a plain-HTTP server and the dashboard could
    not finish loading. That directive and HSTS are now sent only where HTTPS
    is real (`DOMAIN` set, or `CATWAF_HTTPS=true`).
- **`catwaf start` reported success before CatWAF was up.** It returned as soon
  as the process was spawned, so a server that died a second later — port in
  use, unwritable database directory, missing `JWT_SECRET` — still printed
  `✓ CatWAF started`, and the next thing the operator saw was the dashboard
  failing to connect. `start` and `restart` now wait for `/healthz`, print the
  dashboard URL on success, and on failure print the reason and the tail of the
  CatWAF log. `catwaf status` no longer needs to be run to find out.
- **A failed login tore down the app around the login form.** Any 401 cleared
  the session and fired `catwaf-auth-changed`; that now excludes the login
  endpoint itself, where a 401 just means the password was wrong.
- **Simulation reported benign requests as unserved.** The sandbox in
  `services/simulate.js` embedded the live WAF block, including the
  `forward_auth` hop. The sandbox has no CatWAF behind it, so Caddy answered
  502 and `upstreamReached` was always false. `buildWAFBlock()` takes a
  `backend` override and the sandbox renders with no hop.
- **`npm run test:e2e` could not start Caddy** for the same reason — the test
  proving Coraza is in the request path was failing.
- **A detected PHP application's evidence rendered as `[object Object]`.** The
  PHP detector emits scoring objects where the other detectors emit strings.
- **The first-run wizard passed `{ quick: true }`**, an option `discover()`
  never had, so it ran the full HTTP-probing pass instead of the quick one.

#### Added

- **`/api/apps` — the application pipeline over HTTP.** `discover`, `preview`,
  `protect` and `verify` were reachable only from `catwaf auto` and the test
  suite. A thin transport over the existing `backend/services/discovery/` and
  `backend/services/proxy/` — no second implementation, so the CLI and the API
  cannot disagree about whether a site is protected. Protect is admin-only and
  audited; runs are serialised so two cannot race the same generated region.
  Documented in `openapi.yaml`.
- **`test/auth-flow.test.js`** — 29 checks driving a real browser against a real
  backend: signing in over `127.0.0.1`, `localhost` and the machine's LAN
  address; staying signed in; surviving a reload and a backend restart; the
  API-unavailable screen; invalid credentials; and a signed-out token being
  refused when replayed.
- **`test/apps-api.test.js`** — 37 checks over the new API, including that a
  preview never reports protection.
- **CI** (`.github/workflows/ci.yml`): the dashboard builds, the settings
  reference is checked against the schema, and the unit and API suites run on
  every push. Plus issue templates and a private security-reporting link.

#### Changed

- `README`, `CHANGELOG`, `CONTRIBUTING`, `SECURITY`, `ROADMAP` and `TRADEMARKS`
  are back at the repository root, where GitHub renders them and where the
  README's own relative links already pointed. `docs/` keeps the technical
  documentation.
- `.gitignore` now covers `data/backups/`, `data/logs/` and rotated Coraza
  audit logs.
- `CATWAF_HTTPS` is a new environment variable: `true` forces HSTS and
  `upgrade-insecure-requests` on for a deployment behind a TLS terminator
  CatWAF cannot detect, `false` forces them off.

### The configuration and protection layer

CatWAF gains a declarative settings layer covering roughly 300 switches across 40
groups, a runtime protection layer that decides about a *client* before the rule
engine inspects the *request*, and the operational surface to run both.

Everything new is **opt-in**. A default install renders a byte-identical Caddyfile to
the one it rendered before, which `test/render.test.js` guards directly.

#### Added

- **Settings layer.** One declarative schema drives validation, the API, the CLI, the
  dashboard controls, preview, and snapshot/rollback. Adding a setting is a schema entry
  and a renderer line; everything else follows. Field validators are the Caddyfile
  injection boundary and *refuse* quotes, braces, backticks and newlines rather than
  escaping them. See [`docs/settings.md`](docs/settings.md), generated from the schema.
- **Preview before apply.** `PATCH /api/settings/<group>` has a `/preview` sibling, and
  `catwaf settings <group> --preview field=value` prints a `diff -u` of the generated
  Caddyfile. Nothing is written.
- **Protection layer** — the challenge gate (cookie, JavaScript proof-of-work, a
  self-hosted SVG captcha, or reCAPTCHA/hCaptcha/Turnstile/mCaptcha), behavioural
  banning, ASN and forward-confirmed rDNS rules, a greylist tier, subscribed community
  blocklists, DNSBL, a CrowdSec-style bouncer client, a shared threat network, and
  optional active client probing. All off by default.
  See [`docs/protection.md`](docs/protection.md).
- **Unified ban store.** Every feature that can stop an address writes to one place, so
  "why is this visitor blocked and how do I let them back in" has one answer.
  `catwaf bans`, and **Protection → Active Bans** in the dashboard.
- **Network and access control** — mTLS, basic auth, general real-IP/trusted-proxy
  handling (Cloudflare is now one preset of it rather than a special case), PROXY
  protocol, connection limits, and a configurable deny status.
- **TLS** — self-signed fallback so a site is on HTTPS from the first request, validated
  custom certificate upload, DNS-01 and wildcards, ACME fallback and retry, three
  protocol profiles. See [`docs/tls.md`](docs/tls.md).
- **Reverse proxy and origin** — WebSocket policy, gRPC, response caching, forward auth,
  failover, HTTP/2 and HTTP/3, and static-folder or PHP-FPM origins, so CatWAF can serve
  a site itself rather than needing something to sit in front of.
- **Content and headers** — header presets, CORS, cookie-flag rewriting, compression,
  client caching, HTML injection, generated `robots.txt` and `security.txt`, error pages
  and redirects. These feed the security score.
- **Operations** — one scheduler for every timed task (`catwaf jobs`), backups
  (`catwaf backup`), a Prometheus endpoint ([`docs/metrics.md`](docs/metrics.md)),
  opt-in telemetry that shows you the exact payload it would send, configuration
  templates (`catwaf template`), cache housekeeping (`catwaf cache`) and CSV/HTML
  reports (`catwaf report`).
- **Two-factor login.** RFC 6238 TOTP implemented directly rather than added as a
  dependency, with single-use recovery codes and replay protection. `catwaf 2fa`, and
  **System → Two-Factor** in the dashboard, which renders the enrollment QR code from a
  QR encoder written in-tree for the same reason.
- **Data-only plugins.** A manifest may declare settings defaults, knowledge entries and
  constrained Caddy directive templates. It may not declare code, and a manifest that
  tries is *refused* rather than ignored. See [`docs/plugins.md`](docs/plugins.md).
- **`catwaf doctor` reports Caddy's real capabilities** — which optional modules the
  installed build has, and anything switched on that could not be rendered because of a
  missing one. This is the fastest answer to "I enabled it, why is nothing happening?".
- Dashboard pages for all of the above, plus the two-factor step the login form now
  needs.
- `test/protection-units.test.js` (TOTP against RFC 6238's published vectors, feed
  parsing, ban CIDR matching and escalation, diff correctness, the plugin validator,
  challenge proof-of-work and token binding), `test/qr.test.js` (decodes the encoder's
  own output and checks the Reed-Solomon syndromes), `test/extensions.test.js` and
  `test/render.test.js` (six configurations validated by the real `caddy` binary).

#### Fixed

- **A CIDR ban was not enforced until its cache expired.** Range bans are served from a
  short-lived cache that writes did not invalidate, so for up to five seconds an address
  CatWAF had just decided to refuse still got through. Adding, extending or lifting a
  range ban now drops that cache immediately.
- **The TOTP code used to confirm enrollment could be replayed to log in** for the
  remainder of its 30-second window. Confirmation now spends the code, as a login does.

#### Changed

- Three new SQLite tables (`active_bans`, `ban_history`, `list_entries`), created on
  open — an existing database upgrades on first boot with no migration step.
- `/api/enforce` and `/catwaf-challenge` are mounted outside the rotating admin path,
  because Caddy and unverified visitors need a fixed URL. Each carries its own
  authentication. `/api/enforce` **fails open**: every error path answers allow, because
  `forward_auth` reads a non-2xx as "deny" and would otherwise take the protected site
  down on any operational hiccup.
- The knowledge base now points at the switches that fix the problems it describes —
  `access.reject_unknown_host` for origin exposure, `access.waf_bypass_paths` for an
  endpoint that a CRS rule keeps flagging.
- New optional environment variables, all documented in `.env.example`:
  `CATWAF_EXTRA_HOSTS`, `CATWAF_ASN_MAP`, `CATWAF_PLUGIN_KEYS`, `CATWAF_INTERNAL_HOST`.

#### Notes

- `mtls.verify_depth` and `access.file_cache_size` are recorded but not renderable —
  Caddy exposes no equivalent. They report themselves as skipped rather than silently
  doing nothing.
- Features needing an optional Caddy module (response caching, HTML injection, per-IP
  connection limiting, DNS-01) render only when the installed build has it. Otherwise
  they appear in the skipped report with a fix hint, which the dashboard and
  `catwaf doctor` both surface.

## [1.0.1] — 2026-07-30 — Editions, installer, and a security pass

CatWAF now ships in two editions, gains the installer the README has always pointed at,
and completes a security review of every file in the repository.

### Added

- **CatWAF Lite and CatWAF Full.** The edition is chosen at install time, written to
  `.env` as `CATWAF_EDITION`, and enforced at runtime — it is a real property of the
  installation, not a label.
  - **Lite** — Caddy + Coraza + the OWASP CRS, the full `catwaf` CLI, and the SQLite
    event store. It installs **no frontend dependencies at all**: no React, no Vite, no
    `frontend/node_modules`. `catwaf start` brings up the WAF and does not launch an HTTP
    server, because Lite does not have one.
  - **Full** — everything in Lite plus the HTTP API, the built dashboard (including the
    Attack Map), and CatAI where configured.
  - Converting is `catwaf setup --full` (or `--lite`). It is safe to re-run and preserves
    WAF configuration, the database, rules, event history, domain settings and admin
    accounts.
- **`setup.sh`** — the repository-root installer. It has been referenced by the README
  since the first public release but was never actually committed, so the documented
  one-line install pointed at a 404. It detects Debian/Ubuntu, Fedora, RHEL/Rocky/Alma
  and Alpine; installs Node 22+ and Caddy-with-Coraza when missing; offers a Lite/Full
  menu; creates a dedicated non-root `catwaf` service account; and is idempotent — an
  existing installation is detected and updated in place, and a non-empty directory that
  is not a CatWAF checkout is never overwritten.
- **`catwaf docker <up|down|restart|status|ps|logs|build>`** — manages the stack in
  `docker-compose.yml`. Full only. Subcommands are matched against a fixed allowlist and
  the argument vector is assembled from constants, so no user input reaches a command
  line; no shell is used.
- **`catwaf edition`** — prints the installed edition.
- `catwaf status` now reports version, edition, and per-component state (API server,
  dashboard, CatAI, GeoIP). Full-only components on a Lite box are shown as
  "not installed (Lite)" rather than as failures.
- **Attack Map** — a 2D/3D world view of blocked requests, built from real GeoIP data
  attached to request-log rows at ingest. Locations that cannot be resolved are omitted;
  the map states that it has no data rather than inventing markers.
- New pages: **Threats**, **Logs** (searchable and filterable), and **Rules**; plus a
  command palette (`⌘K` / `Ctrl-K`) and a redesigned dashboard with configurable panels.
- `GET /api/attack-map` and `GET /api/logs`; `country_code`, `city`, `lat` and `lon`
  columns on `request_log` (migrated automatically).
- `scripts/postinstall.js` — an edition-aware install step, and
  `CATWAF_SKIP_CADDY_DOWNLOAD=1` for images and CI that supply Caddy separately.
- `SECURITY.md` — secret handling, network exposure, installer trust model, GeoIP data
  licensing, and how to report a vulnerability.

### Security

- **JWTs are no longer accepted in query strings.** `softAuth` fell back to `?token=`
  when no `Authorization` header was present. Tokens in URLs leak into access logs,
  `Referer` headers and browser history. The only consumer was a `streamEvents()` helper
  in the frontend that was never imported by anything, so both are gone.
- **Removed a signature exemption for a route that does not exist.**
  `/api/traffic/stream` was listed in `SIGNATURE_EXEMPT_PATHS`. Nothing served it today,
  but the entry meant that whoever added that path later would have got an unsigned
  endpoint without knowing it.
- **Dashboard preferences are validated before use.** Every preference is now checked
  against an allowlist on read and on write. `accentCustom` is written into a CSS custom
  property and is now required to match `#rrggbb`; previously any string in
  `localStorage` reached the stylesheet unchecked.
- GeoIP lookups can no longer be made against private space through an IPv4-mapped IPv6
  address — see Fixed below.
- Reviewed and documented, with no change required: SQL parameterisation across every
  query; `writeRequired` coverage on all state-changing routes; absence of `shell: true`,
  `eval`, `innerHTML` and `dangerouslySetInnerHTML` anywhere in the tree; hostname
  validation on the one outbound `fetch` built from an API-supplied value.

### Fixed

- **`geoip.isPrivateIp()` tested the address before normalising it.** `::ffff:10.0.0.1`
  and every other IPv4-mapped private address was therefore classified as public and sent
  to a geolocation lookup. The mapped prefix is now stripped first, and the reserved-range
  list was completed: link-local (169.254/16), CGNAT (100.64/10), "this network" (0/8),
  benchmarking (198.18/15), multicast and reserved space, and IPv6 ULA, link-local,
  multicast and unspecified. `199.18.0.0/16`, which is ordinary public space, is no longer
  swept up with the RFC 2544 range.
- **GeoIP failures could take down request-log ingestion.** `geoip-lite` is now loaded
  defensively and every lookup is wrapped; a missing or corrupt database degrades to "no
  location" instead of throwing inside the ingest loop. `catwaf status` reports whether
  the database is available.
- **Coordinates are validated before they are stored.** A lookup must return two finite
  numbers within latitude ±90 and longitude ±180, or it is discarded. Unknown IPs store
  `NULL` and never appear on the map.
- **`npm install` always installed the React toolchain**, including for installs that
  never render a page, and including in the backend Docker image where `frontend/` is
  deliberately not part of the build context. `postinstall` is now edition-aware.
- **The dashboard crashed at startup where `localStorage` is unavailable** (private
  browsing modes, sandboxed frames). Preference reads and writes are now guarded.
- `setup.sh` argument parsing: a trailing option with no value (`--dir` as the last
  argument) aborted with a raw `unbound variable` from `set -u` instead of a usable
  message. `--lite --full` together silently took whichever came last; it is now an error.
- Removed dead code: `streamEvents()` in the frontend API client and `genTx()` in the
  traffic service, neither of which had a caller.

### Changed

- `catwaf setup --minimal` and `--standard` are now `--lite` and `--full`. The old flags
  still work, map to exactly the same editions, and print a one-line note saying so.
- Version numbering normalised to a single public `1.x` line. `package.json`,
  `frontend/package.json`, the README badge, `openapi.yaml` and the Docker image labels
  now all report **1.0.1**; before this release they said 2.2.0, 1.0.0, 2.0.0 and
  3.1.0-dev respectively.
- CLI exit codes are now consistent: `0` success, `1` runtime failure, `2` invalid
  arguments, `3` missing dependency, `4` permission denied, `5` wrong edition.
  `catwaf health` keeps its documented `0`/`1`/`2` (healthy/degraded/unhealthy).
- The generated systemd unit runs as a dedicated non-root `catwaf` account with
  `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, and write access limited to
  the data directory. Lite installs no API unit at all, and an existing one is removed on
  conversion to Lite rather than left to fail on every boot.
- Docker images carry OCI metadata labels, and the backend image no longer downloads a
  Caddy binary it never executes.

### Testing

- New `test/edition.test.js`: 164 checks covering edition resolution and enforcement, the
  CLI surface (every advertised command dispatches and every dispatched command is
  advertised), exit codes, the `catwaf docker` allowlist against injection- and
  traversal-shaped input, GeoIP behaviour across private/mapped/malformed/unknown
  addresses, edition-aware installation, and `setup.sh` input validation.
- `test/frontend-smoke.test.js` now covers `/attack-map`, `/threats`, `/logs` and
  `/rules`, and asserts the Attack Map states an empty result rather than rendering
  fabricated points.
- Suite total: **584 checks** across seven suites.

### Known limitations

- `catwaf docker` was verified for dispatch, allowlist enforcement and exit codes, but
  the containers themselves were not started — Docker is not installed in the environment
  this release was prepared in.
- `setup.sh` was verified for syntax, argument parsing and input validation. A full
  root install on each supported distribution was not performed.
- `geoip-lite` bundles roughly 150 MB of GeoLite2 data, which is the bulk of a Lite
  install's disk footprint. See `SECURITY.md` for its licensing requirements.

## [1.0.0] — 2026-07-29 — First public release

CatWAF Free's first public release, and the increments that followed it before the
version numbering was normalised. This entry consolidates what shipped as
`1.0.0-public`, `2.0.0`, `2.1.0` and `2.2.0`; each is preserved below as its own
subsection with its original date. The `2.x` numbers were retired in 1.0.1 — the work
they describe is part of this release line and is unchanged.

### First public release — 2026-07-29

CatWAF Free's first public release. The version resets from the internal `3.x-dev` line to `1.0.0-public`: the pre-release numbering tracked an internal development history that never shipped, and starting a public project at 3.1 would imply two major releases nobody outside this repo ever saw.

#### Added
- **CatAI** — a local AI assistant, off by default (`CATAI_ENABLED`). Runs entirely on-box via Ollama (`qwen3:1.7b`), answers from a bundled 27-doc knowledge base, reads your real configuration and statistics, and carries out changes on request. Strengthening changes (blocking a country, raising paranoia, adding a rule) apply immediately with one-click undo; anything that reduces protection requires an explicit confirmation. Actions that could lock you out or disable protection outright are absent from its catalog entirely rather than merely gated.
- CatAI loads and warms automatically on `npm run dev` / `npm start`, pulling the model on first run if it isn't present, so the assistant is ready the moment the dashboard opens.
- Collapsible control panel — the sidebar slides to a compact icon rail, remembered across reloads.
- Author credit on the About page.

#### Fixed
- Self-lockout guard on `POST /api/ip/add`: blacklisting your own address (directly or via a CIDR containing it) was previously possible and would lock you out of the dashboard.
- Local (no-domain) installs never set `CADDYFILE_PATH`, so every WAF directive write silently fell back to an unwritable `/etc/caddy/Caddyfile`. Geo blocks, IP blocks, paranoia changes and engine mode had nowhere real to land.
- **The Geo Blocking page couldn't be loaded directly or refreshed in development.** The Vite dev-server proxy matched the authenticated gate by the string prefix `/g`, which also captured the app's own `/geo` route — the request was proxied to the backend, which answered with its production `index.html`, whose asset URLs 404 against the dev server. The result was a blank white page. The rule is now anchored to `^/g/`.
- **Clicking the toggle switch on a Geo Blocking country did nothing.** The switch is a `<button>` and sat inside another `<button>` that toggled the same value, so a click fired the handler twice and cancelled itself. Clicking the surrounding card worked, which made it look intermittent. The row is no longer a nested button, and `Toggle` now stops propagation.
- The welcome tour walked new users through 16 pages that don't exist in this edition, leaving them on blank screens. It now covers the 16 pages that do, plus CatAI.
- Removed a hardcoded "CatWAF v2" version string from the welcome screen, and `geo_blocked_countries`-style internal field names from CatAI's answers.

#### Changed
- **The Caddyfile is now located automatically.** `CADDYFILE_PATH` previously fell back to a hardcoded `/etc/caddy/Caddyfile` — wrong on any machine where Caddy lives elsewhere (Homebrew, BSD layouts, a `--config` override in the systemd unit), and unwritable on any install not running as root. With it unset, CatWAF now checks Caddy's own systemd unit, then any Caddyfile already carrying its markers, then the conventional locations for each platform, and falls back to a project-local file it creates on first write. An explicit `CADDYFILE_PATH` still wins outright.
- The chosen Caddyfile is printed at startup, with an explicit warning if it isn't writable by the current user — and a write that fails on permissions now explains what to do instead of surfacing a bare `EACCES`.

#### Installer
- Creates `/etc/caddy/Caddyfile` after installing Caddy, with the dashboard site block and `order coraza_waf first` already in place, and pins `CADDYFILE_PATH` to it so the backend, the wizard, and Caddy all agree on one file. An existing Caddyfile is never overwritten — CatWAF patches between its own markers.
- Creates the Coraza audit-log directory. Without it Caddy refuses to provision the WAF handler at all (`invalid WAF config from audit log`) and the whole site fails to load, which reads as a CatWAF bug rather than a missing directory.
- Fixed: `patchWAFCaddyfile` only recognised an existing global options block when it started at byte zero, so any Caddyfile with a comment header got a **second** global block prepended — a config Caddy refuses to load, since it permits exactly one. It now skips leading comments and merges into the existing block, preserving its other settings.
- `catwaf --setup` no longer forces `CADDYFILE_PATH` back to a project-local file on re-run, which silently repointed installs configured against `/etc/caddy/Caddyfile`.
- `setup.sh` now **builds the dashboard**. It never did, and `frontend/dist/` is gitignored — so the one-line installer produced a panel that answered every request with a 404. This was the single biggest gap between "the installer finished" and "CatWAF works".
- `catwaf` is installed as a real system command (a wrapper in `/usr/local/bin`), so `catwaf --setup` and `catwaf --status` work from anywhere. Previously the installer ran `node bin/catwaf.js` directly and left nothing behind.
- Optionally installs Ollama so the CatAI step in the wizard has something to detect. The wizard can pull a model but can't install the runtime, which needs root.
- The wizard is launched with stdin reattached to `/dev/tty`. Under `curl … | sudo bash`, stdin is the downloaded script — every prompt read EOF and the interactive wizard raced through itself.
- Added `--yes`, `--with-ai`, `--no-ai`, `--no-wizard`, `--dir` and `--repo` flags for non-interactive installs, and a single clearly-marked `REPO_URL` at the top of the file for forks.

#### Documentation
- Every documented API endpoint and dashboard page was checked against what actually ships. `docs/rules.md` described 13 endpoints of which 11 no longer existed; `docs/architecture.md` documented services that had been removed; `docs/installation.md` told people to log in with `admin`/`admin` when no default accounts exist at all.
- New [docs/catai.md](docs/catai.md). README install commands no longer contain `YOUR-USERNAME` placeholders.

### License change: source available, not open source — 2026-07-29

**Breaking change, license only — no functional changes to the license switch itself.** CatWAF moves from MIT to the [PolyForm Internal Use License 1.0.0](LICENSE), plus an additional permission for personal, noncommercial use by individuals. Running CatWAF to protect your own site is fully covered, including public-facing production use. Not covered: redistributing CatWAF, or operating it as a managed service for third parties — see [README.md](README.md#license) and [TRADEMARKS.md](TRADEMARKS.md).

The last MIT-licensed commit is tagged `mit-final`.

#### Added
- `NOTICE` — required attribution for the Apache-2.0-licensed upstreams (Caddy, Coraza, OWASP CRS) this project depends on and, in its Docker image, bundles a compiled build of.
- `TRADEMARKS.md` — the CatWAF name and logo are trademarks, not covered by the software license.

#### Security
- `POST /api/scanner/origin-exposure` now requires an explicit `authorized: true` before scanning an `origin_ip` — it makes a real outbound TCP connection to whatever host is supplied, and previously did so with no ownership check at all. The dashboard's scanner page gates the same way with a required checkbox.
- Request log retention is now enforced. `state.WAF.retention_days` has been a real, validated setting since the schema was defined, but nothing ever deleted old rows — the log grew forever regardless of what the setting said. Purged on boot and every 6 hours.

#### Fixed
- Verified the Cloudflare API token never appears in application logs: `requestLogger.js` logs method/path/status/duration only and never captures `req.body` (where the token travels), and no audit-log call includes it. No change was needed, but this was checked directly rather than assumed.

### Hardening, real WAF proof, and honest environment support — 2026-07-30

#### Security

- **Removed the Docker socket dependency entirely.** `docker-compose.yml` no longer mounts `/var/run/docker.sock`, and `backend/services/caddy.js` contains no Docker calls at all. CatWAF now reloads Caddy either via the local `caddy reload` binary (host installs) or by `POST /load` on Caddy's admin API (containers). Port 2019 stays on the internal compose network and is never published. Socket access was effectively root-equivalent access to the host — the wrong trade for a security product. A test asserts the dependency stays gone.
- **The dashboard was unusable whenever the backend served it.** Helmet emitted `default-src 'none'` with no `connect-src`, so every API call from the built dashboard was blocked by CSP. Scripts and styles had explicit directives so the page rendered and looked fine — only the API calls failed. Development went through Vite, which does not apply this CSP, so it was never seen. Fixed with explicit `connect-src`/`script-src`/`style-src`/`img-src`/`font-src`.
- `record_id` on the Cloudflare proxy endpoint was user-controlled and interpolated into an API path without validation; now validated like `zone_id`. Zone names returned by the Cloudflare API are hostname-validated before being used in an outbound `fetch`, and that request now has a timeout.
- Schema migrations validate table/column identifiers and column types against allowlists instead of interpolating them raw.
- Removed the last `shell: true` subprocess invocation.

#### Fixed

- **Blocked requests were recorded as allowed.** The Coraza audit-log parser was written against a guessed schema: it looked for `tx.interruption` (real field: `tx.is_interrupted`), read rule IDs from `m.details.ruleId` (real location: an `[id "…"]` field inside `m.error_message`), and read `User-Agent` with the wrong case from a value that is an array. Every blocked attack landed in the database as `action: "pass"` with no rule IDs, no attack type, and no severity.
- **Timestamps broke every time-window query.** Coraza writes `2026/07/30 02:34:14`, which is not ISO-8601, so `getCounts()`, `getAttackTypeCounts()` and the retention purge all compared it against ISO strings and matched nothing. Now normalized to ISO on ingest.
- `severity` and `reason` are captured and stored (new columns, migrated automatically), and the anomaly score is parsed from the CRS scoring message.
- Scanner Detection (913xxx), Protocol Attack, Java Attack and Method Enforcement rule ranges were unclassified and showed as `null` attack type.
- **`USERS.filter()` silently returned nothing.** The `USERS` proxy had no `has` trap, so hole-skipping array methods (`filter`, `map`, `some`, `every`, `forEach`) checked `"0" in []` against the empty proxy target and skipped every element. `find` was unaffected, which is why login worked and this stayed hidden. `catwaf doctor` reported "0 admin" for a system with an admin.
- `catwaf status` claimed "Coraza RUNNING" while also reporting Caddy not running. It now distinguishes module-available from actually-active.
- `writeCaddyfile` failed when the target directory did not exist.

#### Added

- **`test/waf-e2e.test.js`** — the real chain, end to end: a local-only vulnerable app behind real Caddy + Coraza, proving normal traffic reaches the app (200), that SQLi/XSS/scanner traffic is blocked (403) and never reaches it, and that each event lands in CatWAF's database with the right action, status, rule IDs, severity, classification and ISO timestamp. Skips cleanly if Caddy+Coraza is absent rather than faking a pass.
- **`test/testapp/server.js`** — an intentionally vulnerable, clearly labelled test app. Binds to loopback; in Docker it has no published ports and is reachable only through Caddy + Coraza.
- **`test/platform.test.js`** — environment detection, nginx/cPanel parsing, generated web-server configs, provisioning apply/rollback, the user lifecycle, and security regressions.
- **`test/frontend-smoke.test.js`** — a real browser logs in, loads the dashboard, walks ten routes, and confirms authorization is enforced server-side. This is what caught the CSP bug.
- **`catwaf doctor`** — read-only diagnosis of OS, runtime, Caddy/Coraza, Caddyfile syntax and writability, audit-log pipeline, database and schema, authentication, ports, other web servers and control panels. Exits 0 when healthy, non-zero otherwise; `--json` for automation.
- **`backend/services/environment.js`** — one reusable detection layer (Linux/macOS, Docker, systemd, Caddy, nginx, Apache, cPanel/Plesk/DirectAdmin, ports, existing install) instead of detection scattered through the installer.
- **`catwaf provision`** — detects the host web server and generates the config to serve the dashboard at `catwaf.<domain>`. `--apply` backs up, validates, and rolls back automatically if validation fails. Caddy/nginx/Apache are automated; control panels are **detection only** and print the config to use instead of editing panel-managed files.
- **Installer modes** — `catwaf setup --minimal | --standard | --custom`, plus fully non-interactive setup that never prompts and fails clearly when required input is missing. Minimal is genuinely minimal: no dashboard build, no CatAI.
- **User management** — `catwaf user list|add|remove|passwd|role` and `/api/users` endpoints, with server-side authorization, bcrypt hashing, and last-admin protection.
- **Service management** — `catwaf start|stop|restart|status|logs`, systemd when available and a managed PID-tracked process otherwise. Idempotent: starting twice does not create a second process.
- `catwaf config` (never prints secrets) and `catwaf uninstall` (stops CatWAF, removes its unit/shim/WAF block, keeps data and backups unless asked).

#### Documentation

- README covers installation modes, the full CLI, provisioning, diagnostics, and the local demo.
- **Performance section states plainly that no CatWAF benchmark has been run**, and that Coraza's characteristics are not automatically CatWAF's. No numbers are claimed.
- `docs/screenshots/README.md` lists exactly what to capture and how to produce a real system to capture it from. No fabricated images are committed.
- Architecture doc shows the real request path and states that nothing uses the Docker socket.

### Operator tooling: explain, simulate, replay, rules, modes, snapshots — 2026-07-30

Ten new operator-facing capabilities, all built on one atomic-change primitive
so backup/validate/rollback behaviour is implemented once rather than per
feature.

#### Added

- **`catwaf explain <event-id> | --last`** — why a request was blocked: matched CRS rules with descriptions, paranoia level, anomaly score against the threshold, severity, the request component that actually matched, and remediation naming the decisive rule. Sensitive query parameters are redacted; bodies, cookies and `Authorization` headers were never stored and cannot appear.
- **`catwaf simulate --url | --request`** — runs a request through a throwaway Caddy + Coraza instance using the current configuration, against a local sink. The real upstream is never contacted. `--url` is parsed for method/path/query/headers and deliberately **not** fetched, so the feature cannot be used as an SSRF primitive. Only http/https are accepted.
- **`catwaf replay <event-id>`** — rebuilds a stored attack from sanitized fields, runs it through the same sandbox, and reports whether the current configuration still blocks it. Warns explicitly on a regression (was blocked, now allowed) and lists which rules stopped matching.
- **`catwaf rules list|search|show|enable|disable`** — a real CRS rule index built from CRS `.conf` files (env override, Go module cache, common system paths), falling back to rules observed in real traffic when none are found. Disabling writes a real `SecRuleRemoveById` directive; verified live that a disabled rule stops matching in Coraza and returns on re-enable.
- **`catwaf audit`** — traffic and attack summary with `--last`, `--attack`, `--severity` filters and stable `--json`. Totals, block rate, top attack types, top CRS rules, severity distribution, anomaly-score statistics and recent events.
- **`catwaf mode normal|lockdown|learning|maintenance`** — named bundles of real WAF settings. `learning` is DetectionOnly and is labelled as blocking nothing, with confirmation required; `maintenance` reduces logging without weakening protection. Drift from a declared mode is detected and reported.
- **`catwaf paranoia [1-4]`** — extends the existing paranoia system with a CLI. Writes the real CRS `tx.blocking_paranoia_level`, raises the detection level to satisfy CRS's detection >= blocking rule, and confirms before raising to 3 or 4.
- **`catwaf config snapshot|snapshots|show|diff|restore`** — built on the existing `audit.js` snapshot table. Restore is validated before activation, takes a safety snapshot first, and rolls back on failure. Secrets are redacted in output.
- **`catwaf health [--watch]`** — runtime component health with healthy/degraded/unhealthy and exit codes 0/1/2. `--watch` refreshes on a timer with proper signal cleanup.
- **`catwaf security-test`** — CatWAF's own deployment posture by severity: bind addresses, admin-API exposure, Docker socket, privileged containers, secret strength, file permissions, CORS, security headers, proxy trust, WAF interception and bypass risk, disabled rules, rate limiting. Explicitly does not claim the protected application is secure.
- **`catwaf diff`** — what changed since the last snapshot, across config, rules and mode.
- **`backend/services/configTx.js`** — the atomic primitive behind all of the above: snapshot state, back up the Caddyfile, mutate, validate, render, `caddy validate`, reload, and on any failure restore both state and file. A test feeds deliberately invalid config and asserts the Caddyfile is restored byte-for-byte.
- **20 new API endpoints** under `/api/rules`, `/api/mode`, `/api/events/*`, `/api/audit/summary`, `/api/simulate`, `/api/config/snapshots/*`, `/api/waf/health`, `/api/waf/security-test`, `/api/waf/paranoia-levels`. All require authentication; all state-changing ones require the admin role.
- `matched_var` column on `request_log` (migrated automatically), recording the CRS variable that matched — the name only, never the value.

#### Fixed

- **`patchWAFCaddyfile` could corrupt a Caddyfile.** It injected the WAF block before the last `}` in the file. With a Caddyfile containing only a global options block, that put the WAF block *inside* global options, producing config Caddy refuses to load. It now targets the last site block and, when there is none, fails with an actionable message instead of writing broken config.
- **Attack classification picked the wrong category.** `classifyRuleIds` returned the first matching CRS range, so a SQL-injection request that also tripped one RCE heuristic was labelled `RCE`. It now picks the dominant category by match count.
- `explain` chose the first known rule as "decisive" and suggested disabling it — often an incidental rule like a Host-header check rather than the rule that actually characterised the attack. It now prefers a rule matching the event's classification, then highest severity.
- The matched request component was inferred from a rule's declared scope (often listing cookies first) rather than what actually matched. It now uses the real matched variable from the audit log.
- `ollamaReachable` interpolated a URL into `curl` arguments; a value beginning with `-` would have been parsed as a flag. The scheme is now validated and `--` terminates option parsing.

#### Testing

- New `test/waftools.test.js`: 167 checks covering the rule index and ID validation (including traversal and injection attempts), enable/disable changing real configuration, automatic rollback, Caddyfile site-block targeting, all four modes, every paranoia level writing the real CRS directive, snapshots/diff/restore with secret redaction, explain and its redaction, audit windows and filters, simulate input validation (scheme rejection, oversized input, malformed requests), replay validation, health, the security self-test, and live Coraza simulation with regression detection.
- Suite total: **408 checks** across six suites.

## Pre-release history

The entries below come from the internal `3.x-dev` line that preceded the first public
release. They were never published under those numbers and are kept for provenance —
they document how CatWAF reached 1.0.0, not releases anyone installed.

### [3.1.0-dev] — 2026-07-11 — Real data everywhere: no more simulated traffic, metrics, or fleet status

The single biggest known limitation in this project (`ROADMAP.md`'s long-standing "replace the synthetic traffic generator" item) is done. Every number the Dashboard, Live Traffic, Attack Monitor, Logs, the TUI, and the API show is now either genuinely real or an honest `null`/zero — nothing is `Math.random()` dressed up as telemetry anymore. Honeypot/deception decoy content is intentionally unchanged — showing attackers fake `.env` files and fake AWS keys is the entire point of that system, not something this pass touches.

#### Added

- **`services/requestLog.js`** — real request/attack log. Parses Coraza's own JSON audit log (one object per line) into a new `request_log` SQLite table: real IP, method, URI, status, block/pass action, and an attack-type classification based on real OWASP CRS rule-ID ranges (942xxx = SQLi, 941xxx = XSS, etc. — the same boundaries CRS itself uses, not a guess). Tracks its own read offset so restarts don't double-ingest and a log rotation doesn't break it. `server.js` now runs this on a 5-second interval from startup.
- **`services/caddy.js` now configures Coraza's real audit logging** (`SecAuditEngine`, `SecAuditLog`, `SecAuditLogFormat JSON`) — without this, Coraza never wrote anything for CatWAF to ingest in the first place; this is the actual foundation everything else in this change depends on.
- **`services/ipIntel.js`** — real IP intelligence. Tor exit-node membership and cloud-provider IP ranges (AWS/GCP/Cloudflare) come from each provider's own real, freely-published, no-API-key-needed data, cached and periodically refreshed. Abuse scoring and full geolocation genuinely require a paid/licensed data source (there's no free public equivalent) — these call the real ipinfo.io/AbuseIPDB APIs when `IPINFO_API_KEY`/`ABUSEIPDB_API_KEY` are configured, and are honestly `null` (with the missing key named) when they aren't, rather than estimated.
- **A real node heartbeat** (`POST /api/nodes/:id/heartbeat`) — a second CatWAF instance can now actually report its own status in. `GET /api/nodes` reports `unknown` for a node that's never checked in and `unreachable` for one whose last heartbeat is stale, instead of a random status flip.

#### Changed — from fabricated to real

- **`services/traffic.js`** — was a `Math.random()` generator; now reads from `services/requestLog.js`. Same exported function names/signatures (`genTraffic`, `genTx`), so `routes/dashboard.js` and `routes/hunting.js` didn't need to change, but nothing it returns is invented anymore. A fresh install with no real traffic yet correctly returns empty arrays, not a populated demo feed.
- **`routes/dashboard.js`**: `/api/stats` (total/blocked/passed requests, false-positive count, top attack type, avg anomaly score), `/api/traffic/chart` (24h hourly breakdown), `/api/traffic/attacks` (per-category counts), and `/api/traffic/top-ips` all now query `request_log` for real instead of generating random numbers in the requested shape.
- **`services/systemMetrics.js`**: `disk_pct` (real, via `df`), `connections` (real, via `ss`/`netstat` against the backend's actual listening port), `rps`/`bpm` (real, computed from the last real 60 seconds of `request_log`), and `caddy_pid` (real, via a new `getCaddyPid()` in `services/caddy.js`, same docker-exec-first pattern as the existing Caddy checks) replace their `Math.random()` predecessors. `avg_latency_ms` stays honestly `null` — Coraza's audit log, in the parts this project enables, doesn't carry a per-request duration field; getting a real value would need Caddy's own access log joined in, not something to fabricate in the meantime. `coraza_version`/`crs_version` are now explicitly flagged as "expected, not detected" (`versions_are_expected_not_detected: true`) rather than presented with the same confidence as the fields above them.
- **`routes/rules.js`**'s rule heatmap — was a deterministic hash of each rule ID's character codes labeled "score frequency from recent traffic" (it wasn't derived from any traffic at all). Now counts how often each rule ID genuinely appears in real ingested `request_log` rows.
- **`routes/threatintel.js`** — the mock enrichment endpoint now delegates entirely to `services/ipIntel.js`, described above.
- **`routes/nodes.js`** — status is now heartbeat-derived instead of a random flip (see Added, above).

#### Fixed

- **A third instance of the "config change never actually applies to Caddy" bug** (same class as the panic-mode and config-import fixes from the previous session): `routes/testing.js`'s false-positive exclusion apply called `state.saveWAF(true)` — skip the Caddy push — and nothing else in that handler ever called `applyToCaddy()`. Marking something a false positive and applying the suggested exclusion is supposed to actually stop that pattern from being blocked; it silently never did. Fixed the same way as before: `saveWAF()` plus an explicit `applyToCaddy()` call, with the real reload result returned to the caller.
- Frontend: `pages/NewPages.jsx`'s node table read a `last_seen` field that no longer exists (renamed to the more accurate `last_heartbeat`) and only distinguished 2 of the now 4 real status values (`healthy`/`degraded`/`unreachable`/`unknown`) — fixed both, plus handles a node that's never heartbeated without showing "Invalid Date".
- `pages/Dashboard.jsx`'s "Avg Anomaly Score" stat now shows `—` instead of a blank space when there's genuinely no real scored-request data yet.

#### Known follow-ups (see `ROADMAP.md`)

- Request body / cookie capture for threat-hunting search still isn't wired in — Coraza's audit log needs its `B` part enabled for that, which means logging real request bodies. Left as a deliberate choice to make (retention/PII implications) rather than turned on silently as part of this change.
- `/api/false-positives/mark`'s suggested-exclusion fields aren't run through the `isValidExclusion` check the dedicated rule-exclusion route enforces — not a new gap introduced here, and build-time Caddyfile escaping already prevents it from being an injection vector, but worth closing for consistency.
- GreyNoise integration isn't built — would follow the exact same configured-key-or-null pattern as ipinfo.io/AbuseIPDB above.

### [3.1.0-dev] — 2026-07-09 — Full terminal security console

Expanded the single-screen `catwaf --tui` dashboard into a full multi-screen interactive console, plus single-shot CLI flags for scripting. Same architecture as before (zero npm dependencies for the TUI — raw ANSI + Node's built-in `readline`, direct `require()` of `backend/services/*.js` rather than HTTP calls, so this works standalone over plain SSH with no server necessarily running).

#### Added

- **`src/tui/` structure**: `lib/ansi.js` (extended terminal primitives), `components/` (Panel, Table, StatusBadge, LogViewer, ProgressBar, Menu — reusable building blocks every screen composes with instead of each hand-rolling its own formatting), `screens/` (one file per screen).
- **New screens**: Attack Monitor (category breakdown from the simulated traffic feed — honestly marks "Scanner Detection"/"Bad Bots"/"Rate Limit Violations" as *not modeled* rather than showing a fabricated zero, since `services/traffic.js` has no concept of any of those three), Logs (offers both the real audit trail and the labeled-synthetic security events feed — these are two different real things and conflating them would misrepresent one as the other), Settings (Panic Mode, Maintenance Mode, Configuration Signing, manual Caddy reload — real, previously-unexposed backend features, not new ones invented for this).
- **Migrated screens**: Dashboard, Live Traffic, WAF Engine, Rule Management, IP Management, Honeypot, Configuration Linter, Security Score, System Status — same logic as the original single-screen dashboard, restructured onto the new component library and enhanced to match the requested layouts (boxed header, threat overview, `ProgressBar` gauge for the score, Rule ID/Category/Status/Severity detail view, etc).
- **`catwaf --cli`** as the interactive console's primary name (`--tui` kept working identically — nothing about it needed to change to also answer to the new name).
- **Single-shot CLI flags** for scripting: `--status`, `--logs`, `--traffic`, `--rules`, `--reload`, `--lint`, `--score`, `--honeypot`, `--version` — each prints once and exits, calling the exact same backend services the interactive screens and web API use.
- **`backend/services/systemMetrics.js`** — extracted the real CPU/RAM/uptime/DB-size calculation out of `routes/health.js` so the TUI calls the same real logic in-process instead of a second, divergent copy (same reasoning as the earlier security-score consolidation). Clearly documents which of its fields are real vs. still-synthetic (`disk_pct`, `connections`, `rps`, etc. — pre-existing `Math.random()` placeholders, not something this extraction invented).

#### Fixed

- **Panic Mode's activate/deactivate never actually applied to the live Caddyfile.** `routes/modes.js` called `state.saveWAF(true)` — `skipCaddy: true` — for both, and nothing else in either handler ever called `applyToCaddy()`. Activating panic mode changed the *reported* WAF state (paranoia to PL4, engine to On, thresholds tightened) but the live Coraza WAF kept running whatever was configured before, until some unrelated later action happened to trigger a real apply. For a feature whose entire point is "lock down immediately," that's the one failure mode that can't be quiet. Found while building the Settings screen's Panic Mode control, which needed to understand this code correctly to expose it — fixed at the source (`routes/modes.js`) rather than just worked around in the TUI, so the HTTP route and web dashboard get the fix too, not just this console.
- **The original IP Management screen pushed whatever string was typed directly into `state.WAF.ip_blacklist`/`ip_whitelist` with no validation**, bypassing the `isValidIpOrCidr` check the HTTP route (`routes/network.js`) has enforced since the v3.0.1 security patch. Not an injection risk — `buildWAFBlock()`'s build-time escaping already filters invalid entries before they'd reach the Caddyfile — but a malformed entry would be silently stored and silently never take effect, with no error shown. The new `ips.js` screen validates at entry, same as the API, and tells you why if it's rejected.

### [3.1.0-dev] — 2026-07-08 — `catwaf` CLI: setup wizard, terminal dashboard, and a real fix to user accounts

Added the `catwaf` command (`bin/catwaf.js`) with three modes: `--setup` (first-run wizard), `--tui` (a live terminal dashboard for managing CatWAF over plain SSH, no browser needed), and `--ui` (starts the existing web dashboard via the same `npm run dev` script — not a second implementation of it). Built with zero new npm dependencies (`bin/tui/toolkit.js` is a small ANSI/readline-based renderer) specifically so this is guaranteed to run on whatever bare server someone SSHes into, with no install step or version drift between what was tested here and what ships.

#### Fixed — found while building the setup wizard's "create admin account" step

- **There was no way, from anywhere — web UI, API, or this new CLI — to actually create or change an admin account.** `middleware/auth.js`'s `USERS` was a static array seeded once at module load from a hardcoded `admin/admin` + `viewer/viewer` pair and never persisted; every deployment ran with those same two public default credentials forever, with no path to change that short of editing source and restarting. The setup wizard's first draft of this step wrote to a DB key the real login route never read from — it would have silently done nothing while login kept accepting only the defaults. Fixed at the source: `USERS` now persists through the same `services/db.js` every other piece of state already lives in, falling back to the original two default accounts only when nothing has been stored yet (so every existing deployment behaves identically unless it opts into changing this). Verified with a real create → simulated process restart → still-there test, not just checked in the same process it was created in. `routes/auth.js`'s existing `USERS.find(...)` calls needed no changes — the replacement is a `Proxy` wrapping the live array, and array methods/iteration/reassignment-visibility through it were each tested directly before relying on the pattern.
- **The persona choice `catwaf --setup` sets on the server had no way to reach a browser's session** — the web dashboard's onboarding stores its choice in browser `localStorage`, which has no server-side equivalent at all. Added `GET /api/persona/default` (reads the same value the CLI's persona step writes) and a one-time client-side check on a *fresh* browser session (no existing `localStorage` value) to adopt it. This is explicitly not a full unification of the two storage locations — an existing browser session's choice is never overridden, and there's a brief, harmless flash of the full onboarding screen on a first-ever session while the check resolves — documented inline as a known, low-priority cosmetic gap rather than silently left unmentioned.

#### Verified

Every `backend/services/*.js` function the TUI calls was checked against its real signature and return shape before use, not assumed — this caught two real mistakes before they shipped: `services/securityScore.js`'s `getSecurityScore()` is `async` and returns `{ score, grade, checks, by_category, ... }`, not the sync `{ total, categories: [...] }` shape the first draft of the TUI's Security Score screen was written against (would have rendered `[object Promise]` or thrown). Loaded and exercised every touched service (`state`, `caddy`, `traffic`, `lint`, `honeypot`, `securityScore`) directly with real calls and inspected output, not just `node --check` syntax validation — including `caddy.js`'s Caddy/Docker-not-present fallback paths, since this sandbox has neither installed, which is exactly the "Caddy not detected" state a fresh SSH session running `--tui` before infrastructure is up would actually see.

### [3.1.0-dev] — 2026-07-07 — Realistic honeypot content library

Confirmed via re-review: the 12 (now 13) honeypot decoy routes in `routes/honeypot.js` were real route traps, but every single one funneled into the same generic 404 (or, with tarpit on, the same generic loading-filler bytes) regardless of which path was hit. The routing existed; nothing about what came back actually looked like the thing being impersonated. `services/deception.js`'s separate 25-item catalog already had realistic, dynamically-generated content for a *different* set of paths (`/robots.txt`, `/graphql`, `/.npmrc`, fake AWS/K8s secrets, etc.) with zero overlap — this closes the same gap for the honeypot's own 12 paths, using that same established convention rather than a second, inconsistent one.

#### Added

- **`services/honeypotContent.js`** — one realistic content generator per decoy: fake `.env`/`.env.backup` (Laravel/Node-style, randomized DB/AWS/Stripe/Redis credentials), a valid empty ZIP file for `admin-backup.zip` (real ZIP magic bytes, not text with a `.zip` name), a phpMyAdmin-styled login page, a fake `.git/config` with a believable internal remote, a fake `config.php.bak`, fake internal debug JSON, an Apache `mod_status`-style page, fake `.aws/credentials`, WordPress's real one-line `xmlrpc.php` GET response plus a fake XML-RPC fault for POST, Spring Boot Actuator's real JSON response shape populated with fake values, and WordPress-styled install/login pages. All built on `services/deception.js`'s existing `FAKE_NAMES`/`FAKE_DOMAINS`/`randHex`/`randB64` helpers rather than a second set, so nothing looks copy-pasted between the two systems and content varies slightly per hit instead of being static.
- **`/wp-login.php`** — a natural companion to the existing `/wp-admin/install.php` decoy that didn't exist as a route at all before. Added to `HONEYPOT_DEFAULTS` in `services/state.js` (so it's toggleable from the dashboard like every other decoy — nothing hardcoded outside the normal path list) and registered in `routes/honeypot.js`.
- `services/honeypot.js`'s `sendDecoyContent()` dispatches on `req.path` (and, for `xmlrpc.php`, method) to the right generator. All of the *existing* tracking — the catch log, fingerprint correlation, auto-blacklist, audit trail, and the tarpit path — runs exactly as it did before; only what finally gets sent back when tarpit is off has changed.

#### On the WordPress-specific decoys

WordPress core is GPL-licensed; this project is MIT-licensed. Embedding actual WordPress source (`install.php`, `wp-login.php`) would be a real licensing mismatch, not a formality — and the real pages aren't static markup anyway, they're PHP backed by WordPress's full core and a PHP runtime, neither of which belongs in a Node/Express handler. What a honeypot needs is a response that *looks* right to whatever's looking at it, so these are original HTML recreating the real pages' visual structure and wording, not copies of GPL source. The one verbatim exception is `xmlrpc.php`'s GET response (`"XML-RPC server accepts POST requests only."`) — WordPress's own real, standard, one-line status string, already publicly shown by every real WP install at this exact path, with nothing substantive to license in it.

#### Verified

Ran every generator directly (checked for exceptions and sane output), then exercised the real `honeypotHandler` end-to-end through mock `req`/`res` objects for all 13 paths (14 cases counting `xmlrpc.php`'s GET/POST split) — confirmed every one returns non-empty, correctly-content-typed output instead of falling through to 404. Separately confirmed the disabled-honeypot short-circuit and the tarpit code path are both unaffected by this change.

### [3.1.0-dev] — 2026-07-07 — Honeypot silently not applying to the protected site

Investigated a report that honeypot decoy paths (e.g. a fake `robots.txt`) don't get caught on the protected site even when the honeypot toggle is on and general WAF protection is clearly working. Found three real, compounding bugs in `services/honeypot.js` / `services/caddy.js` — two confirmed directly by reproducing them against real Caddyfile content, one closing a gap between this project's own docs and its actual code. Ranked by how confident I am each one is a real contributor, not just a theoretical one.

#### Fixed — confirmed via direct reproduction

- **`writeHoneypotCaddyBlock()` found where to insert the honeypot's Caddy directives by searching for the literal string `:8081`** — the port this project's own example Caddyfile happens to use — instead of the marker-based approach every *other* Caddyfile-writer in this codebase already uses correctly (`patchWAFCaddyfile`, `services/sensitive.js`). Two ways this breaks: a protected site on any other port makes `content.indexOf(':8081')` return `-1`, and a negative `fromIndex` on the next call isn't "not found" — it's clamped to 0, silently searching from the start of the entire file and landing the honeypot block in whatever site happens to close first (typically the dashboard's own, not the protected one). And even on a deployment that genuinely uses `:8081`, once the WAF's own block has already been applied (the normal case), the first `\n}` after the site's opening line is the WAF's own closing brace, not the site's — landing the honeypot matcher in the wrong place regardless of port. Reproduced both failure modes directly (fresh Docker starter Caddyfile, and a realistic one with the WAF block already applied) before and after the fix. Now uses the same `lastIndexOf('}')` fallback as everywhere else, so honeypot and the WAF block are guaranteed to land in the same site.
- **`patchWAFCaddyfile()` — the function that actually works — had its own latent bug that this investigation surfaced: its marker detection can be fooled by prose.** `docker/Caddyfile`'s own explanatory comment (added last session, describing how the marker system works) contained the literal marker text formatted exactly like a real marker line — which `indexOf` can't distinguish from an actual previously-applied block. Confirmed by direct reproduction that this **corrupted the Caddyfile on the second WAF settings change**: the comment's incidental mention got paired with the real block's end marker, and everything between them — including the protected site's own opening `{` — got deleted, leaving unbalanced braces. Caddy would refuse to load a config that broken, meaning **the very first two config changes on a fresh Docker deployment would leave Caddy permanently stuck on its last-known-good config, unable to reload ever again**, regardless of what's toggled in the dashboard afterward. This is a strong candidate for the actual root cause of "it's on but does nothing." Fixed in three places: `patchWAFCaddyfile` now requires both markers present before treating anything as an existing block (falls through safely instead of throwing), and the literal marker text was removed from the human-written comments in `docker/Caddyfile`, `docs/docker.md`, and (defensively) `docs/reverse-proxy.md` that could cause the same collision — comments now describe the mechanism in words instead of showing the exact token text. Verified with three successive WAF applies plus a honeypot apply on top; braces stay balanced and content survives every time now.

#### Fixed — closes a docs/code mismatch, worth having, can't fully verify without a live Caddy instance

- **`docs/reverse-proxy.md` has always shown `order coraza_waf first` as part of the Caddyfile CatWAF generates — the actual code never emitted it.** Caddy's directive execution order is a fixed internal sequence, not the textual order things are written in, unless explicitly overridden — and a third-party directive like `coraza_waf` only gets a defined position in that sequence if something registers one. Without an explicit `order` directive, whether Coraza reliably runs before the honeypot's own `handle` block (or anything else in the same site) isn't something this code was actually guaranteeing, just implying via outdated documentation. Added `ensureGlobalOrderDirective()` to `services/caddy.js`, which adds `order coraza_waf first` to the Caddyfile's global options block (creating one if it doesn't exist yet, merging into it correctly if one already exists for another reason — both paths tested, including a real bug in my first attempt at the merge path that put the new directive on the same line as an existing one with no separating newline, caught by testing before it shipped). The general Caddy global-options mechanism this relies on is stable, well-documented core behavior; whether this specific ordering gap was actually contributing to any particular honeypot failure is the one piece of this investigation that would need confirming against a real running Caddy + coraza-caddy instance to know for certain.

### [3.1.0-dev] — 2026-07-06 — Full bug/vulnerability sweep

A systematic pass across every file not covered by the earlier v3.0.1 security patch (mostly newer route/service files added since). Nine real issues found and fixed, ranked by severity.

#### Fixed — Critical

- **`POST /api/config/import` and `POST /api/config/history/rollback` had the exact same mass-assignment hole the v3.0.1 patch fixed in `/api/waf/settings` — reachable via a completely different, previously-unaudited route.** Both wrote an entire externally-supplied object onto `state.WAF` with zero field validation, bypassing every check in `routes/rules.js`/`routes/network.js`/`routes/waf.js`. Worse, the build-time escaping added in v3.0.1 only covers `value`/`name` on custom rules — `variable`, `operator`, `action`, and `phase` were never escaped there, so a malicious import could still smuggle a Caddyfile-breakout payload through those fields. Compounding this: `state.saveWAF(true)` — `true` here means *skip* the Caddy apply step — meant the escaping layer wasn't even reachable at the moment of import. Fixed with a new shared `services/sanitize.js` validator (`validateWafState`) that every list/rule/setting field passes through before anything is written, used by both routes plus the manual snapshot rollback endpoint (same pattern, hadn't been hit yet but fixed for consistency). Verified against the exact injection payload from the original audit (correctly rejected) and a full legitimate round-trip of real production state (correctly accepted, all 27 fields) — the first version of the validator I wrote actually failed the legitimate case (three fields' types were guessed wrong instead of checked), caught by testing before shipping it.
- **The config-import feature was also completely non-functional** — the frontend posts `{ content, mode }` (a raw file's text plus merge/replace choice), but the backend read `req.body.state`, so every real import 400'd immediately. This is also why the vulnerability above was reachable only via direct API calls, not through the app's own UI. Rewrote the route to match what the frontend actually sends, added JSON parsing with a clear error, and implemented merge vs. replace mode properly. Also fixed: the toast message has always said "Caddy reloading…" after a successful import, but `saveWAF(true)` meant that never actually happened — it does now.

#### Fixed — High

- **`routes/health.js` called `execSync` in two endpoints (`/api/diagnostics`, `/api/security/advisories`) with no import of it anywhere in the file** — a pre-existing `ReferenceError` on every single call to either endpoint, since before this fix. Fixed as a side effect of the next item, which moves these checks into `services/caddy.js` (which does import it correctly).
- **Four separate places shelled out to the `caddy` binary directly against the local machine, with no Docker-container fallback**: `routes/caddy.js`'s manual reload button, `routes/cloudflare.js`'s post-DNS-verify reload, `routes/health.js`'s two Caddy-running/module checks, and `services/caddy.js`'s own `queueCaddyReload()` (the debounced reload honeypot path changes trigger). Under `docker-compose.yml` (this project's own Docker setup, added last session), Caddy runs in a separate container from the backend — none of these could ever succeed there: manual reload would always fail, health checks would always false-negative report Caddy as down, and honeypot path changes would silently never take live effect. Added `isCaddyRunning()`/`getCaddyModules()` to `services/caddy.js`, mirroring `reloadCaddy()`'s existing docker-exec-first-then-local-fallback pattern, and pointed all four call sites at the shared, correct implementations instead of each reimplementing it (three of them incorrectly).
- **`routes/caddy.js`'s `GET /api/caddy/status`** returns the full raw Caddyfile contents (WAF rules, IP lists, honeypot decoy paths, internal upstream targets) — checked against the app's own established access model (every other config-reading GET route, e.g. `/api/rules/custom`, `/api/ip/blacklist`, `/api/config/export`, is intentionally viewer-readable without additional gating) and left as-is for consistency rather than singled out, since it isn't meaningfully more exposed than the sum of those already-public routes.

#### Fixed — Medium

- **`POST /api/nodes` let a client silently overwrite an existing node** by setting `id` to a value that collides with one already in storage (`saveNode()` is `INSERT OR REPLACE` keyed by `id`) — the generated default was spread-overridable by `req.body`. `id` is now always server-generated and applied after the spread, not before.
- **`GET /api/nodes` persisted a random status flip to every node on every single call** — a read endpoint with a write side effect, invoked on whatever interval the dashboard polls at. The simulated status (fleet health here isn't backed by a real per-node agent — a known, already-disclosed limitation, same as `/api/stats`) is now computed in-memory for the response only; a GET shouldn't write regardless of whether what it's returning is real or simulated.
- `frontend/src/utils/api.js`'s generic error handling only ever surfaced a response's top-level `detail`, silently dropping the new `errors: [...]` array added above — so a rejected config import would show "has errors" with no indication of which fields failed. Folded both into the thrown error message at the shared API-client level, since this benefits every route using this response shape, not just this one.
- The config-import upload UI advertised accepting `.conf`/`.txt` (raw Coraza config) in addition to `.json` — no parser for that format exists anywhere in the backend, so this never worked and never will until that's actually built. Restricted the dropzone to `.json` and updated its copy to match what the fixed route actually supports, rather than advertising a capability that isn't there.

### [3.1.0-dev] — 2026-07-05 — Branding, default theme, and a real click-swallowing bug

#### Fixed

- **The theme picker in the top header didn't work — every click on a theme option silently did nothing.** Root cause: `<header>` had its own `zIndex: 30`, which (combined with `position: relative`) created a stacking context that capped every element inside it — including the theme dropdown's own `zIndex: 999`, two levels down — at that ceiling. The dropdown's click-outside overlay is a *sibling* of `<header>` at `zIndex: 998`, so the entire header (dropdown included) was actually rendering, and hit-testing, *below* that overlay. Every click meant for a theme option was being intercepted by the invisible overlay instead. Confirmed both the failure and the fix against a real Chromium engine (via Playwright) rather than by inspection alone — this exact failure mode is easy to misdiagnose. Fixed by removing the unnecessary `zIndex` from `<header>` (`position: relative` alone doesn't create a stacking context, so this is a one-line, side-effect-free fix). The Settings page's own theme picker was never affected — it's a plain button grid with no overlay involved.

#### Changed

- **Default theme is now "Pure Black" (monochrome black/white), not "Dark" (blue-accented).** `black` was already CatWAF's genuinely achromatic theme (`--cat-accent: #ffffff` on a black background, no color at all) — this makes it the default instead of adding a new one. Also split `:root`'s bare fallback away from sharing a rule with `[data-theme="dark"]` and pointed it at the black theme's values instead, so the page doesn't flash blue-dark for a frame before React mounts and applies the real stored preference.
- **Every 🐱 emoji in the frontend replaced with the actual CatWAF logo** (`logo/catwaf-icon-256.png`, copied into `frontend/public/` so Vite serves it) — sidebar header, both login-screen logo placements, the welcome tour's two logo moments, persona onboarding, the About page, and the "Replay Tour" button. `favicon.ico` and `apple-touch-icon.png` were already wired correctly and untouched.
- The two backend uses of 🐱 (a `console.log` at startup, a Discord alert's message text) are plain-text contexts — a terminal and a webhook `content` field can't render an image file. Replaced with the `[CatWAF]` text prefix already used elsewhere in backend logs, rather than leaving these as the only remaining non-logo branding.
- Fixed a stale version string on the About page (`v1.0.0` → `v3.1.0-dev`), noticed while editing that file.

#### Correction

- The previous entry in this file claimed the old `SecurityScorePage` stub called a backend route that "was never implemented." That was wrong — `GET /api/security-score` already existed in `routes/health.js`, running its own simpler, independent scoring logic. It was missed during that session because `health.js` wasn't checked before concluding the route didn't exist anywhere. The actual (still real) problem was two different security-score implementations existing in parallel with no relationship to each other. Fixed properly this time: `routes/health.js`'s `/api/security-score` now delegates to the same `services/securityScore.js` used by `/api/security/score`, instead of running separate logic — one real implementation, two URLs for backward compatibility, rather than two competing ones.

### [3.1.0-dev] — 2026-07-05 — Stabilization pass: logging, error handling, Security page

Two things, done properly rather than five things done quickly: centralized logging/error handling, and a real "Security" score page — plus a dead-code find along the way.

#### Added

- **`services/logger.js`** — small structured logger (debug/info/warn/error), zero new dependencies (matches this project's existing 4-dependency footprint). Writes human-readable lines to the console and JSON-lines to a daily-rotating file under `data/logs/`. Configurable via `LOG_LEVEL`.
- **`middleware/requestLogger.js`** — logs every request (method, path, status, duration, user) once it finishes.
- **`middleware/errorHandler.js`** — centralized error handling: `asyncHandler()` wraps a route so a rejected promise reaches the error handler instead of vanishing or crashing the process; `notFoundHandler` gives unmatched routes a consistent JSON 404 instead of Express's default HTML page; `errorHandler` logs the full error (with stack trace) centrally but only ever sends the client a message + status code — 500s are masked to a generic message, 4xx messages pass through since those are normal validation feedback, not internals.
- **`process.on('uncaughtException'/'unhandledRejection')`** guards in `server.js` — errors outside a request (background jobs, timers) are now logged to `data/logs/` before the process exits, instead of only ever showing up as whatever scrolled past in a terminal that's since been closed.
- **The "Security" page** (`/security-score`) — an overall posture score (0-100, letter grade) computed live from CatWAF's actual configuration: WAF engine state, paranoia level, rate limiting, scanner blocking, honeypot status, config signing, Cloudflare connection + live TLS/SSL mode check, default-credentials status, JWT secret configuration, and security-header presence. Each check is either a real read of current state or explicitly marked `unknown` when CatWAF genuinely can't verify it yet (e.g. origin TLS without a Cloudflare connection) — nothing is fabricated to make the number look better. New backend: `services/securityScore.js` + `routes/security.js` (`GET /api/security/score`). New frontend: `pages/SecurityScorePage.jsx`.
- **`Dockerfile`** (backend) and **`docker/Caddy.Dockerfile`** (multi-stage: builds the frontend, builds Caddy with the Coraza module via `xcaddy`, assembles the runtime image) + **`docker-compose.yml`** wiring both together with a placeholder `demo-app` service so `docker compose up --build` gives a fully working, protectable stack immediately. New `docs/docker.md` covers the architecture, how to point it at your real application, and — worth actually reading — the Docker-socket tradeoff the backend container currently needs in order to reload Caddy (`services/caddy.js` shells out via `docker exec`). Tracked as a follow-up in `ROADMAP.md`: switching that to Caddy's HTTP Admin API removes the need for socket access entirely.
- **`openapi.yaml`** — a hand-written (not auto-generated) OpenAPI 3.0 spec covering the core endpoint groups in real depth: auth, WAF engine/settings, custom rules, IP/geo lists, the security score, honeypots, sensitive files, and operational modes. Honestly scoped in its own description as covering the core, not all ~150 routes. Served interactively at `/api/docs` via `swagger-ui-express`, raw spec also at `/api/openapi.json`. New dependencies: `js-yaml` and `swagger-ui-express` — two additions to a previously 4-dependency project, both single-purpose.
- `.dockerignore` — keeps `.env`, `node_modules`, and local data/logs out of built images.

#### Fixed

- **`SecurityScorePage` already existed as a dead stub in `pages/V2Pages.jsx`, calling `GET /api/security-score` — a route that was never implemented on the backend.** The page has presumably shown its loading skeleton forever for anyone who clicked into it. Removed the stub (along with its now-duplicate route registration and sidebar entry) in favor of the one working implementation above, reachable at the same `/security-score` path the persona config already expected.
- `.env.example` and `docs/installation.md` still described the old hardcoded JWT fallback from before the v3.0.1 security patch. Updated both to match actual current behavior (random secret generated at boot when unset).

#### Notes for the next pass

- The Security page is intentionally honest about two things this app can't currently fix from a settings screen: **default credentials** (no user-management/password-change feature exists yet — `middleware/auth.js` ships fixed `admin`/`viewer` accounts) and **no 2FA**. Both show as real, unscored-away failures rather than being hidden. Real user management is the natural next backend milestone.
- Centralized logging/error handling is wired in `server.js` and available to every route via `require('../middleware/errorHandler')` and `require('../services/logger')`, but existing route handlers weren't individually retrofitted to use `asyncHandler()` in this pass — most already have their own try/catch. Worth a follow-up sweep.

### [3.0.1] — 2026-07-04 — Security patch

A focused pass looking for real, exploitable bugs in how user input flows through the app — not a style pass. Nine issues found and fixed; nothing here is theoretical, each one has a working proof-of-concept payload that's now neutralized (see the notes on `services/sanitize.js` for the exact attacks tested).

#### Fixed — Critical

- **`PATCH`/`POST /api/waf/settings` accepted any key present on `state.WAF`, not just the 12 keys it was documented and displayed as supporting.** It checked `if (k in state.WAF)` instead of validating against its own `SETTING_KEYS` list, so a single request to this one endpoint could silently overwrite `paranoia_level`, `engine`, `custom_rules`, `ip_blacklist` — anything — completely bypassing the bounds-checking every other dedicated route enforces (the `[1,2,3,4]` paranoia check, the `On`/`DetectionOnly`/`Off` engine enum, the HTTP-method allow-list, custom-rule shape validation). Fixed by validating both the key (allow-list) and the value (per-field type/shape checks) before writing anything.
- **Config-injection into the live Caddyfile via four separate features**: custom rules, rule exclusions, and IP/geo lists (`services/caddy.js`), sensitive-file manual blocks (`services/sensitive.js`), and custom honeypot decoy paths (`services/honeypot.js`) all wrote user-submitted strings directly into Coraza directive text or Caddy path matchers with no escaping. A value containing a backtick, double quote, brace, or newline could terminate the intended string/block early and get the remainder parsed as new Caddy config — up to and including a new `handle {}` block, on a config file that gets live-reloaded. Fixed in two layers: input is now validated/rejected at the API boundary (new `services/sanitize.js`), and every write site also escapes defensively in case state was ever populated another way (a restored snapshot, a direct DB edit).
- **`POST /api/db/switch`'s path-traversal guard was bypassable.** It checked `resolved.startsWith(path.resolve(DB_DIR))` — a plain string comparison, so a sibling directory like `data-evil/x.db` passed too, since the string `"data-evil"` starts with `"data"`. Fixed to require an exact match or a real path-separator boundary.

#### Fixed — High

- **The JWT signing secret's fallback was a string literal committed to source** (`'catwaf-dev-secret-change-me'`). Since this is a public repo, that string is public — any deployment that forgot to set `JWT_SECRET` was signing admin tokens with a secret anyone could find and use to forge their own. Now generates a random secret at boot when the env var is absent, with a loud startup warning instead of a silent fallback.
- **No rate limiting on `/api/auth/login`**, so the admin panel's own login was brute-forceable with no friction — a rough look for a WAF that ships DoS/rate-limiting as a headline feature for *other* traffic. Added a simple in-memory limiter (10 attempts / 5 min, keyed by IP+username).

#### Fixed — Medium

- Bumped `bcrypt` cost factor from 8 to 12 — 8 is fast enough on current hardware that an offline attack against a leaked hash was easier than it should be.
- `services/correlation.js` trusted the client-supplied `X-Forwarded-For` header unconditionally when logging fingerprint/honeypot events, letting any visitor put an arbitrary IP into the audit trail. Now only honored when `TRUST_PROXY=true` is explicitly set; falls back to the real connection address otherwise.
- `POST /api/cloudflare/gen-cert` built its `openssl` invocation as a shell command string via `execSync`, with a Cloudflare-API-supplied domain name interpolated into it. Switched to `execFileSync` with an argument array, so no shell is involved and no string can be interpreted as shell syntax regardless of content. Also added zone-ID shape validation (`zone_id` was used unchecked both as an API path segment and as a local certificate filename).

#### Added

- `backend/services/sanitize.js` — shared validation/escaping used by every route and service above: `isValidIpOrCidr`, `isValidCountryCode`, `isValidCaddyPath`, `isValidCustomRule`, `isValidExclusion`, `isValidMethodList`, `isValidUserAgentList`, `escapeForDirective`.

### [3.0.0] — 2026-07-04

The milestone release: the backend went from a single 3,057-line `server.js` to a proper `routes/` + `services/` structure, several real bugs got fixed along the way, and the project got the repo polish it needed to be usable by someone other than its author.

#### Changed — Backend architecture

- **Split `server.js` (3,057 lines, ~150 routes) into 23 domain route files and 12 service modules.** `server.js` is now ~70 lines: create the app, apply middleware, mount routers, listen. See `docs/architecture.md`.
- **Removed duplicated logic.** The old `server.js` had its own complete, independent copy of database/state/audit-log logic, even though `backend/services/db.js`, `state.js`, and `audit.js` already existed with the same (in some cases more complete) logic — they just weren't wired in. Everything now goes through one copy.

#### Fixed

- **`POST /api/lint/validate-and-apply` never actually applied anything.** It referenced a function, `applyToCaddy`, that was never defined anywhere in the codebase — the `typeof applyToCaddy === 'function'` guard was always false, so the endpoint silently fell back to "Validated (Caddy apply not available)" on every call. It's now wired to a real apply function and will actually apply a validated config.
- **`POST /api/db/switch` only reloaded part of the app's state.** After switching databases, only `WAF` and rule categories were refreshed — honeypot config, the deception catalog, panic mode, maintenance mode, IOC list, and the fingerprint correlation log all kept showing data from the *previous* database until the process restarted. It now reloads everything.
- **`blocked_user_agents` had a weaker default in one code path than the rest of the app.** The (previously unused) `services/state.js` defaulted this list to empty, while the running server and the frontend's own fallback both expected a real starter list of known scanner tools. Corrected so the default matches what was actually shipping.
- Fixed a state-reload helper (`reloadAllFromDb`) that refreshed six of the app's seven persisted state slices but missed the fingerprint/correlation log.
- Three different hardcoded version strings (`2.2.0`, `2.7.0`, `4.1.0`) existed across the support bundle, diagnostics export, and root endpoint — none of which matched `package.json` (`2.8.0`) or each other. All three now read from `package.json`, so this can't drift again.
- `.gitignore` excluded `.env*.local` but not `.env` itself — meaning a real `.env` with a JWT secret or Cloudflare token in it wasn't actually protected from being committed. Fixed.
- `app.listen()` was called from the middle of the old file, with roughly half the routes registered afterward. Harmless in Express (the router stack is checked per-request, not at listen time) but a clear sign of how the file had grown by repeated appending. It's now called once, after every router is mounted.

#### Removed

- Dead route: `POST /api/waf/settings-post`, a leftover handler that did nothing but call `next()` with nothing registered after it.
- Dead state fields `cms_wordpress` / `cms_laravel` / `cms_drupal` / `cms_joomla` — initialized on every WAF state object but never read or written anywhere in the backend or frontend. (PHP/CMS exclusions are handled by the separate, actually-used `php_exclusions` object.)

#### Added

- `LICENSE` file (MIT) — the README has said MIT since v1, but no license file existed in the repo.
- `.env.example` documenting every environment variable the backend reads.
- `docs/` — installation, reverse proxy setup, Cloudflare integration, rule management, honeypots & deception, threat hunting, and architecture guides.
- `CONTRIBUTING.md`, `ROADMAP.md`, this changelog.
- New logo variants: transparent-background PNG, standalone icon crop, and favicon sizes, under `logo/`.
- A Mermaid architecture diagram in the README (renders natively on GitHub).

#### Notes for upgraders

No API paths, request/response shapes, or database schemas changed — this is a structural refactor, not a behavior change, aside from the bug fixes listed above. If you're running an existing `catwaf.db`, it will continue to work as-is.

---

### Earlier still

Work before the internal `3.0.0` refactor (an internal `2.x` line — Cloudflare wizard, threat intel, honeypots, deception library, correlation, debugger/rule lab, panic mode) was developed without a changelog. Tracking starts at the `3.0.0` entry above. None of these numbers were ever published; they are unrelated to the `2.x` entries consolidated into [1.0.0](#100--2026-07-29--first-public-release).
