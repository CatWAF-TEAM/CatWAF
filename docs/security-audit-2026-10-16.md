# CatWAF security audit and hardening — updated 2026-10-17

**Current evidence:** use [the subsequent Node.js security recheck](security-recheck-2026-10-17.md).
The older tables below are historical snapshots. The current release is blocked
by reload connection resets and the unsuppressed module advisory; load tests
must not be described as passing.

The update fixes configuration rollback and offline database restore, completes OpenAPI coverage, hardens containers and discovery fixtures, and completes Linux, live Caddy, browser, package, image and configuration checks. The patched source and measured evidence are supplied together. This is a security review with explicit coverage limits, not a guarantee of vulnerability-free software.

**Subsequent reliability pass:** the 30-suite results below describe the earlier
security snapshot. Additional tests found connection resets during Caddy reloads;
the current [reliability baseline](reliability-baseline.md) keeps that release gate
blocked. Do not interpret the earlier green security snapshot as an all-green
result for the expanded reliability suite.

**Source correction:** all added Go source, module manifests, runtime patches
and local build machinery have since been removed at the maintainer's request.
CatWAF application code stays in Node.js. Historical dependency-build results
below are retained as evidence, not as validation of the current upstream build.
The previous dependency advisory exception has been withdrawn.

## Source and scope

- Repository: https://github.com/CatWAF-TEAM/CatWAF
- Base: `de0b84a3730c5e53a21ffd4cbc044f407fffb0b7`, upstream branch `release-1.0.1`, package version `1.0.2`.
- Local working branch: `security/full-audit-2026-10-16`. Nothing was pushed or deployed.
- The original checkout contained 335 tracked files. The review focused on all 20 route modules and the authentication, signing, session, database, configuration, rendering, networking, integration, backup, installation and deployment boundaries they use. Frontend dependencies and security-sensitive client flows were inspected; the dashboard was built and its browser smoke/authentication suites were executed.
- Automated authorization coverage: **176 route declarations**, of which **163 require a signed live session**. Every protected declaration was probed without authentication and with a JWT lacking a request signature. GET declarations were also probed with HEAD. All **82 explicitly admin-gated declarations**, plus the inline diagnostics-export gate, were probed as a viewer.
- The complete declared surface is in [CSV](security-api-inventory.csv) and [JSON](security-api-inventory.json), including source locations and boundary classifications. `/healthz`, Express-generated HEAD/OPTIONS behavior and static/SPA fallbacks are described separately in the inventory.
- Tests used isolated fixture databases and local servers. No production credentials, remote targets or deployed customer systems were tested.

The route matrix verifies rejection boundaries. It does **not** mean every valid payload, parameter combination, integration, browser state or WAF bypass has been exercised. The OpenAPI contract now covers **191 operations across 161 paths, with zero coverage warnings**. This includes OpenAPI-standard methods for the two all-method internal gateway routes. The strict test validates the full OpenAPI schema, method/path parity, local references, parameter declarations, signing requirements, and 56 representative live response schemas. This review does not claim a line-by-line proof of every tracked file.

## Implemented findings

Severity here is a contextual triage judgment, not a CVSS score. High findings require the preconditions in their descriptions; they are not all anonymous internet attacks.

| ID | Priority | Previous behavior / impact | Implemented change and evidence |
|---|---|---|---|
| CW-01 | High | A newly exposed installation allowed an unauthenticated caller to take the first admin account and reach bootstrap discovery. | All `/api/setup/*` requests require an operator-provided token of at least 32 bytes, compared in constant time. Account creation rechecks bootstrap state under the configuration lock. Default is closed. Bootstrap regression passes. |
| CW-02 | High | Session state could be reconstructed or treated permissively after removal, idle/binding rejection or tracking eviction, undermining revocation. | Durable session records are authoritative; missing, damaged, expired or revoked records reject access. Rejection deletes the record and retry cannot resurrect it. Absolute JWT expiry, account binding and a 500-record cap are enforced. Logout, fresh-process loading, idle, binding, eviction and expiry regressions pass. |
| CW-03 | High | Authentication state corruption could look like an empty/unconfigured store. A password reset racing an asynchronous bcrypt comparison could allow issuance against stale account data. | Strict reads reject malformed JSON and stored JSON `null`; account initialization is recorded; live authentication forces a fresh user read. Login rechecks identity and password hash after comparison. Reserved usernames and bcrypt's 72-byte limit are enforced for new passwords. Corruption and reset-race tests pass. |
| CW-04 | High | Concurrent workers could consume the same MFA recovery code; damaged MFA state could look unenrolled. Re-enrollment could replace an enabled factor. | MFA read/modify/write operations and recovery-code consumption use the cross-process lock; malformed state fails closed; enabled enrollment cannot be overwritten. A real two-child-process test accepts a recovery code exactly once. |
| CW-05 | Medium | Request-signature nonce tracking was process-local, allowing replay to a different worker or after restart within the validity window. | Verified nonces are atomically inserted into SQLite under a `(session_id, nonce)` primary key, with bounded time retention. A signed request accepted in one process is rejected in another. |
| CW-06 | High | Final enforcement verdicts cached only by IP could reuse an allow decision made for an exempt path on a different request. | Removed the final verdict cache; request-dependent classification runs per request. The individual intelligence caches remain. An exempt-path-then-protected-path regression passes. |
| CW-07 | Medium | Public challenge handling accepted caller-supplied forwarding identity headers without authenticating the gateway that supplied them. | Forwarded client identity is used only with a valid derived enforce/upload/challenge key; otherwise the configured Express client IP is used. Generated challenge proxy rules supply the key. Spoofed-header regressions pass. |
| CW-08 | High | Expanded IPv4-mapped IPv6 could bypass private-address checks. Redirects could carry integration credentials or request bodies to another origin. | Normalize numeric IPv6, reject private/reserved embedded addresses and additional translation ranges, pin DNS lookup results, bound the pin cache, reject URL credentials and HTTPS downgrade redirects, and refuse cross-origin sensitive requests. IPv6 and redirect-exfiltration tests pass. |
| CW-09 | High | The upload gate used plaintext HTTP even for an allowlisted HTTPS origin and mishandled some framing/stream cases. | Resolve the scheme from the configured upstream, use certificate-verifying HTTPS, support bracketed IPv6, strip hop-by-hop and Connection-nominated headers, remove internal request headers, and handle aborted streams. Unsupported h2c fails closed. A local wire-level test observes a TLS ClientHello rather than plaintext. Upload-scan tests pass. |
| CW-10 | High | `rediss://` could send Redis credentials/commands over a plain TCP connection. Parser and increment/expiry handling also had robustness gaps. | Use TLS and wait for `secureConnect`; bound reply size, nesting and duration; decode bulk strings by bytes; use an atomic Redis script for increment plus initial expiry. TLS-on-the-wire, UTF-8 and oversized-response tests pass. A real Redis 8 TLS fixture also passed authenticated commands, wrong-password rejection, database selection, 40 concurrent atomic increments, expiry, UTF-8 and deletion. |
| CW-11 | High | Compose exposed Caddy's unauthenticated configuration API over a network shared with the protected origin. | Replace TCP admin access with a mode-0660 Unix socket mounted only in Caddy and backend. Publish the dashboard on host loopback. Add socket support to backend reload/status calls and CI isolation probes. The built stack passes live permissioned-socket, origin isolation, healthy traffic and SQLi-block checks on an isolated Docker daemon. |
| CW-12 | High | Redacted backups/templates could retain write-only settings, Caddy secrets or credentials embedded in URLs. SQLite checkpoint-plus-copy could race writers. | Redact legacy exports and stored template reads; filter write-only template imports; sanitize credential URLs; use `VACUUM INTO` for a consistent database snapshot and matching manifest/database filenames. Secret-redaction and snapshot integrity tests pass. A full database backup remains secret-bearing. |
| CW-13 | Medium | New encrypted backups used unauthenticated AES-CBC, which does not detect modification. Restore settings were not fully schema-validated. | New `CWBACK02` format uses AES-256-GCM, random salt/IV, authenticated header and PBKDF2-SHA256 with 310,000 iterations. Files start with private permissions. Validate restored settings and SQLite integrity; use unique staging paths. Round-trip, wrong-key, tampering and invalid-settings tests pass. Legacy CBC remains read-only compatibility. |
| CW-14 | Medium | Preview temporarily persisted candidate settings and generated assets, exposing supposed preview changes to other readers/live files. | Run previews inside a locked SQLite savepoint that is always rolled back; suppress asset writes and reload caches. A separate database reader sees only committed settings; asset bytes are unchanged. Full configuration activation now has separate immutable generations and crash recovery, described in CW-19. |
| CW-15 | Medium | Dead-lock recovery could return ownership without completing the lock record or closing its descriptor. Age alone could evict a live writer. Several sensitive files were created with broad permissions or nonexclusive temporary names. | Serialize lock acquisition and stale recovery with a SQLite OS lock; preserve the diagnostic legacy token and do not evict live PIDs on age alone. Use exclusive temporary creation, complete writes, atomic replacement and explicit private/shared-group modes for databases, generated configuration, keys and backups. Lock and concurrency regressions pass. Linux contention, dead-holder and POSIX permission tests pass. |
| CW-16 | Medium | Express 4 route promises could reject without returning a response. Cloudflare requests lacked bounded duration; generated keys used predictable paths. | Wrap mounted route handlers so synchronous/async failures reach the error boundary. Add Cloudflare timeouts and redirect refusal; create unique private key files before OpenSSL runs. Bound CatAI chat input; restrict application-discovery previews to admins. Async error and authorization regressions pass. |
| CW-17 | Medium | Default Coraza audit sections included full request/response headers and bodies, creating unnecessary credential and personal-data retention. | Generate `SecAuditLogParts AHZ`, restrict log creation/rotation permissions, and document residual URI/rule-message sensitivity. Real Coraza traffic verifies attack classification remains available, raw user-agent headers are omitted, and injected Authorization/Cookie sentinels are absent from the raw audit log and database. |
| CW-18 | Dependency / deployment | Lockfiles contained known advisories; unpinned WAF builds could drift; production CORS and API caching defaults were broader than necessary. | Refresh npm locks; upgrade React Router and Tailwind; pin Caddy/Coraza and Caddy image digests; use `npm ci` in Docker, the installer and frontend postinstall; bound and optionally hash-verify downloads; production same-origin CORS and API `no-store`; add restrictive dashboard headers and a Linux security workflow. Both npm audits report zero known advisories; dashboard build passes. |

| CW-19 | High | Configuration mutations could persist before validation; generated assets could overwrite the live generation; failures or process crashes could leave SQLite, Caddyfile and the running configuration inconsistent. | SQLite IMMEDIATE transaction, immutable asset generations, candidate validation, durable recovery journal and transactional commit marker. Mutation/validation/reload/commit failures restore state and file; unresolved rollback is reported honestly and retried at startup. Legacy WAF/network, CatAI, discovery, edge-ban, audit-log and Cloudflare publication paths use the transaction. Real process-crash and separate-reader regressions pass. |
| CW-20 | High | Database restore used WAL age as a liveness guess and replaced the database file beneath possible open connections; the CLI could report success after a failed restore or partially apply the manifest before confirmation. | Require exclusive process-lifetime database leases, stopped Caddy, staged integrity/schema checks and SQLite backup API copying without inode/WAL replacement. Retain a private recovery copy, revoke restored sessions, apply the matching manifest and block startup while restore is incomplete. Active-reader refusal, corruption, schema, CLI exit status and real offline CLI/container restore tests pass. |
| CW-21 | Dependency / deployment | A Caddy version pin alone still produced vulnerable Go standard-library and x/net code. Container scans additionally found vulnerable distribution packages and bundled npm tooling. | Commit the complete Caddy build module graph, use Go 1.26.9 and x/net 0.61.0, validate installer candidates before replacement, pin container base digests, update Alpine packages, and remove runtime package managers. Final npm and OS scans are clean; govulncheck reports zero reachable/imported-package vulnerabilities. One unimported OpenPGP module advisory remains visible. |

| CW-22 | Medium | OpenAPI omitted 102 legacy operations; path-only comparison missed missing methods, and inspection failures exited successfully. Old flow-style YAML descriptions also parsed into invalid schema fields. | Document all fixed API operations, bootstrap/gateway trust boundaries, signing, request fields and response schemas. Full OpenAPI validation and fail-closed method-level drift checks pass; regressions reject missing methods, weaker security, external references and inspection failure. |
| CW-23 | Deployment | Caddy ran as root; runtime and fixture images lacked health checks. Old nginx and MariaDB fixture images carried large dependency advisory sets. | Separate non-root backend/proxy UIDs, actual health checks, restricted demo filesystem/capabilities, patched and pinned Alpine fixture builds, and a non-root socket-authenticated MariaDB fixture. Live tests and all eight Dockerfile configuration scans pass; five final fixture images have no package findings. |

Principal implementation files: [authentication](../backend/middleware/auth.js), [sessions](../backend/services/session.js), [signing](../backend/middleware/signing.js), [MFA](../backend/services/totp.js), [gateway](../backend/routes/gateway.js), [network guard](../backend/services/netGuard.js), [Redis](../backend/services/sharedState.js), [backups](../backend/services/backups.js), [preview](../backend/services/preview.js), [configuration lock](../backend/services/configLock.js), [Compose](../docker-compose.yml). Reproductions are maintained in [the security regression suite](../test/security-audit.test.js).

## Validation actually performed

Machine-readable results: [security-validation.json](security-validation.json). Raw Linux logs, before/after dependency scans, container scans and prior Windows evidence are in the accompanying security-validation-2026-10-17 directory.

Native environment: Kali Linux on WSL2, Node 24.19.0, npm 11.19.0, Go 1.26.9 and Chromium 156. Container runtime: Node 24.22.0 on Alpine. Docker used a separate socket, data root, bridge, containerd namespace, project and loopback ports; the user's running stack was not modified.

**30 suite files passed, zero failed and zero fully skipped.** Their harnesses report 1,831 passes (custom assertions and Node test counts, including parent tests; these are not a uniform coverage metric). The complete configured npm test chain also exited 0. Browser smoke and auth-flow were run separately with the installed Chromium fixture.

| Suite | Final result |
|---|---|
| apps-api | 37 pass, 0 fail |
| attack | 142 pass, 0 fail |
| audit-log | 37 pass, 0 fail |
| audit-rotation | 61 pass, 0 fail |
| auth-flow | 27 pass, 0 fail |
| catai | 66 pass, 0 fail |
| concurrency | 16 pass, 0 fail |
| discovery | 291 pass, 0 fail |
| edge-e2e | 13 pass, 0 fail |
| edition | 166 pass, 0 fail |
| extensions | 35 pass, 0 fail |
| features | 32 pass, 0 fail |
| frontend-smoke | 44 pass, 0 fail |
| openapi-drift | 73 pass, 0 fail; zero warnings |
| image-policy | 6 pass, 0 fail |
| platform | 110 pass, 0 fail |
| protect-e2e | 33 pass, 0 fail |
| protection-units | 167 pass, 0 fail |
| qr | 39 pass, 0 fail |
| render | 12 pass, 0 fail |
| restore-e2e | 1 pass, 0 fail |
| security-audit | 25 pass, 0 fail |
| security-recovery | 16 pass, 0 fail |
| security | 52 pass, 0 fail |
| sfl-e2e | 39 pass, 0 fail |
| subdomain | 39 pass, 0 fail |
| trust-proxy | 4 pass, 0 fail |
| upload-scan | 44 pass, 0 fail |
| waf-e2e | 37 pass, 0 fail |
| waftools | 167 pass, 0 fail |

| Additional check | Final result |
|---|---|
| Backend / frontend npm audit | 0 known advisories in each lockfile |
| Frontend production build | Pass |
| Native and container Caddy govulncheck | 0 reachable vulnerabilities; 0 affected imported packages; 1 module-only advisory |
| Runtime image Trivy 0.76.0 scans | 0 OS-package advisories in backend, Caddy and demo; 0 packaged Node dependency advisories. Backend/Caddy retain only GO-2026-5932 at module level |
| Built container isolation | Health, allowed request, socket mode 0660, origin/admin isolation, non-root backend UID 1000 and Caddy UID 1001, actual DB read denied to Caddy, generated assets readable by Caddy, no backend Docker socket, SQLi blocked: pass |
| Offline restore inside backend container | Real CLI + SQLite + Caddy validation: pass |
| Authenticated Redis 8 over TLS | AUTH, wrong-password refusal, SELECT, concurrent atomic increment/TTL, UTF-8, expiry and deletion: pass |
| JavaScript syntax / YAML / whitespace | 208 JavaScript files syntax-clean; five YAML documents parse; Git whitespace checks pass |
| Trivy configuration scan | 8 Dockerfiles, 216 checks passed, 0 findings |
| Discovery fixtures | Both stacks pass live HTTP/PHP, non-root identity, health and database authentication checks; 5 rebuilt images have 0 package findings |
| Go package-policy guard | No affected OpenPGP imports on Linux amd64/arm64; a real injected OpenPGP import correctly fails the guard |

The initial Windows failures and skips are preserved as historical evidence, not presented as final results. Two Linux test assumptions were corrected: the API concurrency test now holds an explicit barrier rather than relying on request timing, and the WAF audit test verifies the new header-privacy contract against real traffic. An error-message regression in discovery was fixed and rerun separately and through npm test.

## Remaining limitations and operational requirements

1. **GO-2026-5932 remains at module level.** It describes the unmaintained x/crypto/openpgp package. The locked Caddy binary does not import that package; govulncheck reports no affected imported packages or reachable symbols. The raw evidence is unfiltered. The latest x/crypto version is already selected, and no fixed version exists for this advisory. CI explicitly assesses only this exact module/version in the Caddy binary, checks that affected imports remain absent on both Linux architectures, and rejects every other finding including unfixed advisories. See [the assessment](go-advisory-assessment.md).
2. **API inventory is not exhaustive behavioral proof.** The 176-declaration authorization matrix checks rejection boundaries. OpenAPI has complete method coverage and 56 live response samples, with zero warnings. Successful payload combinations, all frontend visual states, browser engines other than Chromium and every possible WAF evasion were not exhaustively tested.
3. **Recovery has an explicit operating model.** Stop old-version processes and unrelated SQLite tools before migration; they do not participate in the new lease protocol. SQLite and Caddy are not one indivisible commit, and in-flight requests can straddle activation. Recovery resumes on CatWAF startup. No power-loss, NFS or multi-host lock correctness claim is made. Generated assets are retained for old configurations; monitor storage and manage retention as described in [security-recovery.md](security-recovery.md).
4. **Deployment integrations still require their own staging validation.** Real Cloudflare accounts, external email/notification and AI providers, production AV engines and DNS/certificate topologies were not exercised with production credentials. Redis TLS was exercised locally. Custom Caddy transport behavior and h2c remain outside the upload-forwarding compatibility coverage; h2c is deliberately refused rather than downgraded.
5. **Administrative and availability boundaries remain deliberate.** Administrators can edit raw Caddy configuration, discover local services and configure integrations; this is not a tenant sandbox. Some abuse counters remain process-local and configurable fail-open behaviors remain operator choices. These tests do not establish distributed load/availability guarantees.
6. **Historical and retained secrets are not scrubbed by upgrading.** Integration credentials and full DB backups remain sensitive. URIs and rule messages can contain secrets even with AHZ audit parts. Old AES-CBC backups are unauthenticated compatibility inputs. Download TOFU is not a signed upstream release, and package/image vulnerability data is a point-in-time result.

## Upgrade and rollback notes

1. Take a consistent, access-restricted backup of the database, `.env`, Caddyfile and generated assets. Keep the encryption passphrase separately. Preserve the actual repository license notices: this checkout uses PolyForm Internal Use 1.0.0.
2. Install from the updated lockfiles with `npm ci` and `npm --prefix frontend ci`; build the dashboard. Use Node 22.16+ (22 LTS) or Node 24+. Use the existing upstream dependency integration or the Node.js `ensure-caddy` downloader. Verify the binary actually selected by PATH/systemd; installing a file does not restart a running service. Runtime Docker images omit npm/yarn and are updated by rebuilding.
3. Web bootstrap now returns 404 unless explicitly enabled with `CATWAF_SETUP_TOKEN` and the `X-CatWAF-Setup-Token` header. Prefer `catwaf user add` for the first account. Remove the bootstrap token afterwards. Passwords newly set through CatWAF must be 8+ characters and no more than 72 UTF-8 bytes. Existing passwords previously truncated by bcrypt should be reset.
4. A session without a valid durable record is now rejected. Some existing sessions will require login again. Do not copy active session tables between unrelated deployments. Keep the instance root secret stable for normal upgrades; rotating it also affects encrypted MFA material and gateway keys, not just JWTs.
5. **Existing Docker volumes require migration.** Rebuilding an image does not replace the Caddyfile or ownership stored in a named volume. While the stack is stopped and backed up, edit the existing Caddy global block to use `admin unix//run/catwaf-admin/admin.sock|0660`, preserving the site's actual routes and certificates. Apply the updated Compose mounts and `CADDY_ADMIN_SOCKET`. Caddy now runs as UID `1001`, distinct from backend UID `1000`. Preserve certificate storage and migrate Caddy-owned `/data` and `/config` contents to `1001:1000`; ensure shared configuration/log/socket directories have group `1000`, setgid directory permissions and restricted file modes. Do not change database ownership or make it group-readable. Do not use `docker compose down -v` as an upgrade procedure: it destroys named data volumes.
6. For native installs, give only the backend and Caddy service identities access to the shared configuration/asset group. Database files are owner-only (0600); generated configuration and private TLS assets that Caddy must read use restricted group access (0640); shared audit logs and the admin socket use 0660. A group-readable key is safe only when that group is limited to the trusted service identities. Existing ownership may need migration.
7. Re-render and reload the protected configuration to adopt challenge gateway headers and AHZ audit defaults. Confirm normal traffic, an attack fixture, challenge completion, scanned uploads and admin actions. AHZ intentionally stops recording complete headers/bodies: user-agent/header-derived analytics lose input, and some nonblocking response status fields may be absent. Rule-message and URI logging still require retention controls.
8. Redis URLs may no longer embed credentials; place the password in the write-only password setting. An installation depending on cross-origin credential redirects must use the final intended endpoint explicitly. Validate integrations in staging.
9. Run `npm run test:all` in the supported Linux environment with Caddy/Coraza and a configured Playwright browser. For the repository's running Compose stack, run `node scripts/check-container-isolation.js`. Confirm the backend can use the Unix socket and the origin cannot connect to Caddy TCP port 2019. These checks passed on the isolated validation stack; repeat them against the intended staging deployment before rollout.
10. A rollback should restore the matching source, lockfiles, configuration and data snapshot while services are stopped. Old source cannot read newly encrypted GCM backups. Do not roll back only the Caddyfile while leaving incompatible secrets or generated assets in place.

Follow [security-recovery.md](security-recovery.md) for the validated database restore command, stopped-stack Docker procedure, incomplete-restore recovery and generated-asset retention.

## Upstream references

- [Caddy v2.11.7 release](https://github.com/caddyserver/caddy/releases/tag/v2.11.7) and [coraza-caddy v2.6.2 release](https://github.com/corazawaf/coraza-caddy/releases/tag/v2.6.2): versions selected for the build update.
- [coraza-caddy v2.6.2 module manifest](https://github.com/corazawaf/coraza-caddy/blob/v2.6.2/go.mod): upstream Go and dependency requirements; this patch explicitly selects Caddy 2.11.7.
- [Caddy admin API guidance](https://caddyserver.com/docs/api) and [network address conventions](https://caddyserver.com/docs/conventions): permissioned Unix sockets and socket mode syntax.
- [Coraza audit-log directives](https://www.coraza.io/docs/seclang/directives/#secauditlogparts) and [Coraza transaction implementation](https://github.com/corazawaf/coraza/blob/v3.8.1/internal/corazawaf/transaction.go): audit section behavior and metadata availability.
- [Tailwind upgrade guide](https://tailwindcss.com/docs/upgrade-guide): v4 migration and modern-browser requirements.
- [braces advisory](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm) and [proxy-addr advisory](https://github.com/advisories/GHSA-jqcg-44mw-7w3h): examples motivating transitive dependency updates. The saved npm audit reports are the measured dependency evidence.

- [Go HTTP/2 advisory GO-2026-6617](https://pkg.go.dev/vuln/GO-2026-6617): the patched Go/x/net baseline; the full initial scan lists the other affected standard-library advisories.
- [OpenPGP advisory GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932): remaining module-only finding.
- [Node SQLite backup API](https://nodejs.org/api/sqlite.html) and [SQLite online backup design](https://sqlite.org/backup.html): transaction-aware database copying.
- [Trivy v0.76.0](https://github.com/aquasecurity/trivy/releases/tag/v0.76.0): image scanner version; downloaded archive checked against its published SHA-256.
