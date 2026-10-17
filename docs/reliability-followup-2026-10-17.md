# Audit and Kubernetes reliability follow-up — 2026-10-17

**The fixes are implemented, but the release gates are not all passing.** Audit
loss across rotations and the Kubernetes findings are fixed. Reload connection
resets and the unsuppressed GO-2026-5932 module advisory remain reproducible.
The application, controllers and new proxy supervisor are Node.js. No Go source,
private runtime patch, scanner exception or relaxed load limit was added.

## Fixes

Audit ingestion now follows every retained generation with a persistent,
inode-bound cursor. A successful reload no longer authorizes deleting the old
log. Pruning requires evidence that Caddy closed its writable descriptor, followed
by a complete successful drain. Unavailable writer evidence, partial records,
permission errors and database failures preserve the archive. Deterministic
record IDs prevent duplicates on replay. Restrictive umasks no longer remove
the shared group's write permission from new audit files.

The Caddy image runs a small Node.js supervisor that observes its child's
descriptors through a private Unix socket. Backend and proxy remain separate
users, with separate process namespaces and no added capabilities. Native Linux
installations can inspect the matching Caddy process through `/proc`. Unknown
writer state retains archives, so age/count retention limits can be exceeded;
monitor disk use and repair the observer instead of deleting live archives.

The Kubernetes manifest no longer grants Secret API permissions. TLS Secrets
are explicitly mounted read-only in the backend; both certificate and key are
read from one kubelet generation. The projected API token is backend-only,
mode 0440, with a requested 600-second lifetime and automatic mounting disabled.
The token uses a dedicated mount path. Both KSV0036 and KSV0113 are absent in the
unmodified Trivy scan. No rule or manifest suppression was added.
KSV0036 uses the conventional service-account mount path as a heuristic; the
controller still needs its explicitly projected token. The security changes are
the restricted mode and shorter requested lifetime, alongside backend-only
mounting and disabled automount. A clean scan does not mean the Pod is token-free.

Real-cluster testing also found that the upstream-built Caddy executable carried
a file capability that prevented execution with `cap_drop: ALL` and
`no-new-privileges`. Both image builds now remove that file capability. Kubernetes
continues to use unprivileged listener ports, read-only roots, distinct non-root
users and dropped capabilities. The executable's bytes and SHA-256 are unchanged.

CatAI's broken knowledge link was corrected, and its orchestration guidance and
deployment documentation now describe the mounted-Secret and audit behavior.

## Measured checks

The [evidence directory](reliability-followup-2026-10-17/) contains unfiltered
scanner results, test summaries, failure output and source SHA-256 values.
The complete matrix runs every test file independently so one failure cannot
hide later results; it preserves their exit codes and assertions.

| Check | Result |
|---|---|
| Backend, security, live WAF and orchestration matrix | 35/36 files pass; reload reliability fails |
| Slow request spanning three audit rotations | Pass; exactly one record, eventual pruning after writer retirement |
| Audit writer/cursor/failure regressions | Pass |
| OpenAPI contracts and warning checks | 76 passed, 0 failed, 0 warnings |
| Real Kubernetes cluster | 10/10 checks passed on the final runtime code |
| Browser navigation and authentication | 45 + 27 checks passed |
| Non-root audit rotation / CatAI | 61 / 66 checks passed, including permission cases |
| Real filesystem exhaustion and crash recovery | 9/9 passed on a private 32 MiB tmpfs |
| Upgrade, rollback, reopen and re-upgrade | 1.0.1 and earlier 1.0.2 exports, Lite and Full: all four cases passed |
| Disposable Docker recovery and TLS persistence | 8/8 passed; separate isolation check passed |
| Docker metadata lifecycle / native CrowdSec API | 5 / 6 checks passed |
| Apache/PHP, Nginx/PHP and database fixtures | Passed; all five fixture images have zero vulnerability findings |
| Root and frontend npm audit, including development dependencies | Zero findings |
| Trivy configuration and secret scans | Zero findings |
| Backend and Caddy image vulnerability gates | Fail: GO-2026-5932 only |
| Demo and metadata image vulnerability scans | Zero findings |
| JavaScript syntax / clean Linux frontend build | 230 files clean / build passed |
| Extra Semgrep review | One warning retained; manual assessment below |
| Strict 900-second mixed-protocol load | Fail: 94 request errors across 138,352 requests and 421 reloads; no observed bypasses or duplicate writes |

The cluster was a real, single-node kind v0.33.0 cluster running Kubernetes
v1.37.0 with containerd 2.3.4, CNI, DNS and dynamically provisioned persistent
storage on WSL2. Its separate kubeconfig and unique cluster name isolated it from
other infrastructure. No production containers or host service ports were
changed. Fixture resources and the disposable cluster were deleted afterward.
This establishes those checks on this environment, not multi-node HA,
LoadBalancer-provider behavior, Kubernetes conformance or BunkerWeb equivalence.

The ten Kubernetes checks cover startup and writer observation, actual RBAC
denials, Service routing/TLS/WAF blocking, controller permission loss, late audit
completion across containers, valid and invalid kubelet TLS rotations, origin
rollout and automatic path reconciliation, Pod recreation with SQLite/certificate
persistence, and Ingress deletion. A separate CI job repeats these checks using
checksum-verified tools and a digest-pinned Kubernetes node image.

## Remaining failures

The reload reliability regression still reports six failed request pairs under
concurrent valid/invalid reloads. The minimal upstream reproducer, using only
Caddy's static responder with no Coraza, CatWAF API, database or origin, reports
16 failures across 20 reloads. The upstream binary was rebuilt and has SHA-256
`7e2adaa80b0bf1ebd1356c69b8caefeb8e213babd826afbedb96f997ac2f250f`.
The related [Go shutdown issue](https://github.com/golang/go/issues/75591)
remains open. No verified Node/configuration-only fix was found in this pass.
HTTP/1 requests are not retried, and the load gate still requires zero errors.
The final load ran for 900.68 seconds at concurrency 24, with 46 audit rotations,
34,594 observed writes and a measured p99 of 622 ms. Peak proxy RSS was 171.84 MiB,
fixture disk use 552.86 MiB and open descriptors 113. Four HTTP/2
`REFUSED_STREAM` responses were separately counted under the existing test
policy; HTTP/1 retries were not introduced. Raw errors and the failed assertion
are in [load.json](reliability-followup-2026-10-17/load.json).

The [GO-2026-5932 record](https://pkg.go.dev/vuln/GO-2026-5932) covers the
unmaintained OpenPGP package family, with no fixed version. Current binary
`govulncheck` reports zero reachable vulnerabilities, zero affected imported
packages and one affected required module. Trivy's module-level finding remains
in both images containing Caddy. That distinction explains exposure; it does
not remove the finding or pass the strict image gate. See the
[advisory assessment](go-advisory-assessment.md).

The additional Semgrep scan ran 107 applicable rules over 334 files, with no
parse errors. Its raw exit is 1 because it flags the report download response in
`backend/routes/ops.js:85`. Manual tracing shows the request dates are normalized,
HTML table fields are escaped by `reports.escapeHtml`, and downloads use an
attachment header. The existing `HTML report exports escape attacker-controlled
log fields` regression passes with a script-tag payload. This is assessed as an
interprocedural false positive; the raw warning is preserved without a rule
exclusion or a claim that the scanner returned zero findings. Semgrep's default
ignore patterns skipped 40 files; this is not a claim of exhaustive SAST coverage.

An initial Linux build attempt against Windows-installed frontend dependencies
failed on the missing Linux Rollup binary. A fresh locked Linux dependency
installation and build passed. The first two cluster attempts exposed the file
capability and audit umask bugs described above; both were fixed before the final
successful run. Earlier failed runs are not counted as successful validation.
After cluster testing, the proxy image also gained Node.js's bundled license
notice. All 43 executable, supervisor, dashboard and configuration files were
hash-compared with the cluster-tested image and are identical; the image was
rescanned and container isolation rerun. Both image IDs and the comparison are
recorded in `proxy-image-equivalence.json`.
