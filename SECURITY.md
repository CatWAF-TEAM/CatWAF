# Security

CatWAF is a security product, so this document describes what it actually protects, what
it does not, and how it handles the sensitive material you give it. It avoids claims that
cannot be backed up.

Security validation and release reliability are separate gates. See the current
[reliability baseline](docs/reliability-baseline.md) and
[2026-10-17 recheck](docs/security-recheck-2026-10-17.md) for current results,
the reload connection-reset blocker and the unsuppressed dependency advisory.

## What CatWAF protects, and what it does not

CatWAF inspects HTTP requests to your site through Coraza running the OWASP Core Rule Set,
and blocks what matches. That is the whole of the protection it provides.

It does **not** make the application behind it secure. A WAF is a filter in front of your
code, not a substitute for fixing your code. `catwaf security-test` assesses *CatWAF's own*
deployment posture — bind addresses, secret strength, file permissions, proxy trust — and
says nothing about the application it is protecting.

## Reporting a vulnerability

Open a private security advisory on the repository, or email the maintainer listed in
`package.json`. Please include a description, affected version (`catwaf version`), and a
reproduction. Do not open a public issue for an unpatched vulnerability.

## Secrets

**Where secrets live.** Deployment secrets live in `.env`. SQLite also contains password
hashes, session state, encrypted TOTP seeds, recovery-code hashes and integration settings.
Some integration tokens are stored as plaintext settings. Protect the database, its WAL
sidecars, generated Caddyfiles and backups as credentials. Redacted API reads do not mean
the stored data is encrypted.

| Secret | Purpose | Created by |
|---|---|---|
| `JWT_SECRET` | Signs dashboard session tokens | Generated at setup — 32 random bytes |
| Admin password hash | Dashboard login | bcrypt, cost 12, in the database |
| `CF_API_TOKEN` | Cloudflare API access (optional) | You supply it |

**Permissions.** `.env` is written mode `600` and owned by the service account. The
installer writes it under `umask 077`, so it is never briefly world-readable between
creation and `chmod`. CatWAF warns at startup if `.env` is group- or world-readable.

**Logs.** The API request logger omits request bodies and credential headers. Generated
Coraza configuration now uses `SecAuditLogParts AHZ`, excluding full request/response
headers and bodies. Transaction URIs and rule messages can still contain sensitive
values or matched fragments; restrict log access and retention. Earlier logs may contain
headers and bodies. Re-render existing configuration to adopt the new default; existing
log files are not automatically scrubbed.

**Admin passwords.** Setup reads the password from the `CATWAF_ADMIN_PASSWORD`
environment variable rather than a flag, because a flag would be visible in your shell
history and in `ps` output for the lifetime of the process. There are no default
accounts — until you create one, there is nothing to log into. Minimum length is 8
characters and new passwords must fit within bcrypt's 72-byte UTF-8 limit. Changing a
password invalidates every existing session for that account.

**First account.** Prefer the local CLI. Web bootstrap requires `CATWAF_SETUP_TOKEN`
containing at least 32 bytes and a matching `X-CatWAF-Setup-Token` header on every setup
request. Without it, setup returns 404. Creating the first account closes the bootstrap
surface under the configuration lock. Remove the token after setup.

## Network exposure

Binding the dashboard to every interface (`HOST=0.0.0.0` in `.env`) is how you reach it from another machine without a domain — that serves plain HTTP on port 8000 to anyone who can route to it, so keep it off the public internet or put TLS in front.

**Default bindings.** The API binds `127.0.0.1:8000`. It is meant to sit behind Caddy,
which terminates TLS and proxies to it. Do not bind it to `0.0.0.0` unless something else
is restricting access to it.

**Caddy's admin API** controls the reverse proxy. Compose uses a Unix socket at
`/run/catwaf-admin/admin.sock`, mode 0660, shared only with the backend. It has no TCP
listener. The dashboard's HTTP port 8081 is published on loopback only. Native installs
may use a local admin endpoint or set `CADDY_ADMIN_SOCKET`; never expose it to an origin
container or untrusted network.

**No Docker socket.** CatWAF does not mount or use `/var/run/docker.sock`. Socket access
is effectively root on the host — the wrong trade for a security product. Caddy is
reloaded either through the local `caddy` binary or through Caddy's admin API.

## API security

Requests to `/api/*` must satisfy all of the following:

1. **A rotating path segment.** The real API lives under `/g/<segment>/api/...`, where the
   segment is an HMAC of the current 15-minute window. Requests to `/api/...` directly
   receive a decoy 404. This is obscurity, not a control — it raises the cost of
   untargeted scanning and nothing more. The controls below are what actually enforce
   access.
2. **A bearer token.** A signed JWT (HS256), re-validated against the live user store on
   every request, so a deleted account, a demoted admin, or a session predating a password
   reset loses access immediately rather than at token expiry. Tokens are accepted in the
   `Authorization` header only — never in a query string.
3. **A request signature.** HMAC over method, path, timestamp, nonce and body hash, with a
   2-minute clock-skew window. Nonces are stored atomically in SQLite, so replay rejection
   survives restarts and works across workers sharing that database.
4. **A durable session.** Missing, revoked, expired, idle, mismatched or unreadable session
   state rejects access. A successful login creates the session before returning its JWT.
5. **A role.** Administrative mutations require `admin`. Logout acts on the caller's
   own session; viewer chat requests cannot apply CatAI actions.

Public health/auth-status, login, token-gated setup, metrics and Caddy's keyed gateway
endpoints have their own controls. See [the route inventory](docs/security-api-inventory.csv).

Rate limits apply to both gated and ungated paths. Login attempts are limited per
IP-and-username **and** per account, so a client that controls its `X-Forwarded-For`
header (direct exposure without a reverse proxy) still faces a cumulative budget per
targeted username.

A note on trust boundaries: the enforcement and upload-scan hops derive the visitor's
address from `X-Real-IP` / `X-CatWAF-Client-IP` only with a valid derived gateway key.
The generated Caddyfile overwrites these headers before anything reaches the backend. If you
put your own proxy in front of CatWAF's API port, it must do the same — do not forward
client-supplied versions of those headers untouched.

How many forwarded hops CatWAF trusts is inferred unless you set `TRUST_PROXY_HOPS`
explicitly: 1 when DOMAIN or CATWAF_HTTPS indicates a proxied deployment, 0 otherwise.
On a direct deployment (dashboard on `localhost:8000`, a bare LAN port) forwarded
headers are ignored entirely — a client cannot forge its way past rate limiting or IP
checks by inventing them. If you front the API with your own proxy without setting
DOMAIN, set `TRUST_PROXY_HOPS=1`.

## Kernel-level drops (opt-in)

The nftables mirror runs only when BOTH the setting is enabled and
`CATWAF_KERNEL_BANS=1` is set in `.env`, and refuses to run in containers or
without root. CatWAF creates and fills exactly one table (`inet catwaf_edge`)
and deletes/recreates it atomically per refresh — it never touches any other
firewall rule. The forwarding rule that makes the kernel consult the set is
applied by you, as root, from `catwaf kernel-bans print-rules` output.

## Update check

`catwaf update`, the dashboard diagnostics and a daily background job perform
one HTTPS GET to `api.github.com/repos/agugusgeyehe-dot/catwaf/releases/latest`.
No telemetry, no identifiers beyond your IP as seen by GitHub, response cached
for 24h. Read-only: nothing is downloaded or installed. If the repository has
no releases yet the check reports that instead of an error.

## Backup encryption

With `backups.encrypt` enabled, new manifests and database copies use AES-256-GCM,
PBKDF2-HMAC-SHA256 (310,000 iterations), a random salt and nonce, and an authenticated
`CWBACK02` header. Wrong keys or modified ciphertext fail authentication. The passphrase
comes from `CATWAF_BACKUP_PASSPHRASE`, outside the database. Keep it separately recoverable.

Legacy OpenSSL CBC backups remain readable for migration and have no authenticity
guarantee; only restore legacy files from a trusted source, then create a new encrypted
backup. A redacted manifest does not redact its optional full database sibling. Database
copies use a consistent SQLite snapshot and mode 0600. Stop all CatWAF processes before
database restore; the WAL-age warning is not proof that every database handle is closed.

## Concurrent configuration writers

The API server, the `catwaf` CLI and scheduled jobs can all change WAF configuration.
Every mutation path serializes through one lock file in the data directory
(`data/config.lock`), re-reads committed state before applying its change, and writes
the Caddyfile atomically. A crashed holder's lock is broken automatically; you should
never need to touch the file by hand.

## GeoIP data

CatWAF uses [`geoip-lite`](https://www.npmjs.com/package/geoip-lite), which bundles a
converted **MaxMind GeoLite2** database.

- **Licensing.** GeoLite2 data is distributed by MaxMind under the
  [Creative Commons Attribution-ShareAlike 4.0](https://creativecommons.org/licenses/by-sa/4.0/)
  license and MaxMind's
  [GeoLite2 End User License Agreement](https://www.maxmind.com/en/geolite2/eula).
  If you redistribute CatWAF or a product containing this data, those terms apply to you.
  This product includes GeoLite2 data created by MaxMind, available from
  [maxmind.com](https://www.maxmind.com).
- **Disk footprint.** Roughly 150 MB. On a Lite install it is the single largest component.
- **Accuracy.** City-level geolocation is approximate and should be treated as a hint, not
  as evidence. Do not make blocking decisions on it that you would not be comfortable
  defending.
- **Updates.** The bundled database ages. Refreshing it requires a MaxMind license key —
  see the `geoip-lite` documentation.
- **Private addresses are never geolocated.** RFC 1918 space, loopback, link-local, CGNAT,
  benchmarking, multicast and IPv6 ULA/link-local addresses are excluded, including when
  written as IPv4-mapped IPv6 (`::ffff:10.0.0.1`). An address that cannot be resolved is
  stored as `NULL` and does not appear on the Attack Map. CatWAF does not fabricate
  coordinates to fill in a map.

## Installer trust model

The installer is a shell script that runs as root. Understand what that means before
running it.

**Recommended — download, read, then run:**

```bash
curl -fsSLo setup.sh https://raw.githubusercontent.com/agugusgeyehe-dot/catwaf/main/setup.sh
less setup.sh
sudo bash setup.sh --lite
```

**The one-line form** (`curl … | sudo bash`) is supported but is not the recommendation.
Piping into a root shell means trusting, sight unseen: GitHub, the TLS chain, DNS
resolution at that moment, and every future change to that file. HTTPS authenticates the
transport — it says nothing about whether the content is what you expected. There is no
step at which you can inspect what is about to run as root.

What the installer itself does:

- runs with `set -euo pipefail`, quotes every variable, and never uses `eval`
- fetches the NodeSource and Ollama scripts **to a file** and executes them explicitly,
  rather than piping them into a shell, so a failed download cannot become a partial
  execution
- pins `--proto '=https' --tlsv1.2` on downloads
- writes secrets under `umask 077`
- creates a dedicated non-login `catwaf` system account and never runs the service as root
- refuses to overwrite a non-empty directory that is not a CatWAF checkout
- validates every argument — `--yes` suppresses prompts, never validation

It does not verify a signature or checksum on the Node and Ollama installers it fetches;
it inherits the trust model of those upstream projects.

## systemd hardening

The generated unit runs as the `catwaf` account with `NoNewPrivileges=true`,
`ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`, `RestrictSUIDSGID`,
`RestrictNamespaces`, `LockPersonality`, and write access limited to the data directory.

Interactive `catwaf setup` installs the same hardened unit when run as root — including
the dedicated service account and its `.env` ownership — so re-running setup can never
downgrade a hardened install to a root-running, unsandboxed one.

CatWAF Lite installs no API service at all. If you convert a Full install to Lite, the
existing unit is disabled and removed rather than left to fail on every boot.

## Docker

- No Docker socket is mounted.
- Caddy's admin API is a permissioned Unix socket with no TCP listener.
- Containers run with `no-new-privileges:true`.
- The test app is intentionally vulnerable. Its direct origin port is published only
  on `127.0.0.1:8082`; direct access bypasses Coraza. Never expose that port publicly.
- `catwaf docker` validates subcommands against an allowlist and builds its argument
  vector from constants. It runs `docker compose`, which requires access to the Docker
  daemon; anyone who can run it can already control containers on that host.

## Updates

Re-run `setup.sh`, or `git pull && npm install && catwaf setup --<edition>`. Both are
idempotent and preserve your configuration, database, rules and accounts. Check
`CHANGELOG.md` before updating — security fixes are listed under a **Security** heading in
each release.

## Dependency posture

The 2026-10-17 update refreshes both npm lockfiles, React Router and Tailwind.
CatWAF application code remains Node.js. Local Go source, module manifests,
runtime overlays and listener patches were removed at the maintainer's request.
The original upstream Caddy/Coraza dependency integration remains, with pinned
versions and no CatWAF modifications to either dependency. Container bases are
pinned by digest, with distribution security updates applied during the build.
Backend and demo runtime images omit npm/yarn; rebuild them for updates.

The current scans report zero npm/OS advisories and an OpenPGP module finding.
The current upstream binary retains symbols; its binary scan reports zero
reachable or imported-package vulnerabilities and one required-module advisory.
The image gate still blocks every reported advisory, including this unfixed
finding. See [the assessment](docs/go-advisory-assessment.md) and the raw recheck
evidence. Neither package-level evidence nor zero npm findings is an all-clear.

All fixed API operations are now documented and schema-validated; method drift and
inspection failures fail CI. Shipped containers and discovery fixtures run without
root, have health checks, and pass the saved configuration and live isolation checks.

The Node.js installer checks existing/downloaded Caddy binaries against the
compiler/module security baseline and validates a candidate before replacing
an installed executable. The upstream download uses
HTTPS, size/deadline limits, optional CATWAF_CADDY_SHA256 and local TOFU pinning.
TOFU is not an upstream signature. An existing hash pin can require an explicit
CATWAF_CADDY_ALLOW_NEW_BUILD=1 after the operator verifies an intended upgrade.

The Linux security workflow runs backend/WAF/browser tests, npm scans,
container isolation and image scans. See [the measured audit](docs/security-audit-2026-10-16.md)
and [restore procedure](docs/security-recovery.md) for evidence and limitations.
