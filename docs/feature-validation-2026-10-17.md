# Free feature validation — 2026-10-17

This extends the [1.0.2 security recheck](security-recheck-2026-10-17.md) with
bot challenges, manual-ban activation, CrowdSec and orchestration changes.
**The release gates still fail.** Publishing these changes does not establish
BunkerWeb equivalence or mean they have been deployed to production.

The application, metadata bridge and controllers are Node.js. No Go source,
module graph or custom Go runtime patch was added. Live proxy checks used the
existing upstream Caddy/Coraza binary with SHA-256
`7e2adaa80b0bf1ebd1356c69b8caefeb8e213babd826afbedb96f997ac2f250f`.

## Results

| Check | Observed result |
|---|---|
| Complete backend suite matrix | 33/35 files pass; reliability and audit-lifetime files fail |
| Final feature/controller regression run | 12/12 tests pass, no skips |
| Focused security, recovery, feature and protocol checks | 56/56 tests pass |
| OpenAPI | 76 checks pass; 193 operations / 163 paths; zero warnings |
| Native proxy orchestration | Host/path routing, WAF, bans, cookie challenge, update/removal and TLS rotation/rollback pass |
| Real Docker lifecycle | 5/5 checks pass: labelled routing, metadata outage retention, recreation, deletion and bridge isolation |
| Real CrowdSec v1.8.1 Local API | 6/6 checks pass: authentication, Range ban, revocation, CAPTCHA, expiry and invalid credentials |
| Dashboard build / browser smoke / authentication | Build succeeds; 45 / 27 browser checks pass |
| JavaScript syntax | 230 files pass |
| npm dependency audits | Zero backend/frontend findings |
| Metadata image vulnerability scan | Zero findings |
| Configuration scan | Two Kubernetes findings remain visible; see below |
| Secret scan | Zero findings in the source snapshot |

The suite matrix ran each file independently so a failing gate could not hide
later results. Its outer shell wrapper reported an error after writing all 35
individual outcomes; it is not represented as a successful aggregate command.
The final focused run separately exited successfully. Tests and scanner rules
were not weakened or suppressed to obtain these results.

## Security behavior verified

- CAPTCHA images contain rendered pixels rather than the answer as SVG text.
- Cookie challenges require a cookie round trip; pass cookies bind to client and
  challenge policy. Provider checks reject mismatched hosts, stale responses and
  concurrent nonce replay. mCaptcha uses its native JSON verification contract.
- CrowdSec decisions expire independently of local bans. Cached revocation has
  a bounded delay. CAPTCHA decisions cannot be satisfied by a cookie-only mode.
  Failure handling follows the operator's explicit fail-open/fail-closed choice.
- The first manual runtime ban enables its enforcement gate transactionally.
  Failed validation rolls back both; unexpected gateway exceptions return 503.
- Reconciliation validates complete inventories, preserves source ownership,
  retains the last working routes on failure, and avoids unchanged reloads.
- Kubernetes transport validates CA certificates, rereads rotated credentials,
  bounds paginated reads and rejects invalid TLS Secrets. Live proxy checks
  verify certificate rotation and rollback after a rejected generation.
- The Docker bridge exposes one filtered metadata read over a Unix socket. Its
  tested container runs without root, network access or Linux capabilities,
  with a read-only root filesystem. Only the bridge receives the engine socket.

## Findings and limits

Trivy still reports **KSV-0036** for the explicitly projected API token and
**KSV-0113** for access to TLS Secrets. The service account and Pod disable
automatic token mounting. Only the backend receives the projected token; Secret
RBAC permits `get` on the named `app-tls` Secret, with no list/watch/write access.
These are controller capabilities with consequences if the backend is
compromised. They remain unsuppressed findings, and the configuration scan exits
nonzero. Adjust the explicit Secret allowlist for the deployment.

The existing strict tests still reproduce connection resets during reload and
lost audit records for requests spanning rotations. GO-2026-5932 remains an
unsuppressed upstream module advisory; the backend/Caddy images were not rebuilt
or rescanned in this feature pass. Earlier load, upgrade, filesystem and static
analysis results belong to the preceding source snapshot, not a new run here.

No real Kubernetes cluster, ingress conformance suite, live CAPTCHA provider
account, public ACME issuance or multi-node deployment was exercised. Kubernetes
is currently a namespace-scoped, single-replica polling controller with the
documented unsupported cases. Manual Coraza rules and IP/CIDR lists already
existed and remain shared protection for managed hosts.

See [feature coverage](bunkerweb-feature-coverage.md),
[controller setup](orchestration.md), and
[raw scanner reports and per-file outcomes](feature-validation-2026-10-17/).
The optional real integration checks are `npm run test:docker-autoconf` and
`npm run test:crowdsec`; neither touches the production stack.
