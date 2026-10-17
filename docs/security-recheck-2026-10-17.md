# Node.js security and reliability recheck — 2026-10-17

**Release remains blocked.** CatWAF is still a Node.js application with its original upstream Caddy/Coraza integration. No Go source, local Go module graph or custom runtime patches are included. This report records the 1.0.2 security-update validation snapshot; publishing the patchset does not mean the release gates passed or that the patchset was deployed.

## Patches in this pass

- Lock acquisition closes descriptors and removes its own incomplete lock on ENOSPC.
- Configuration recovery recognizes SQLite automatic rollback after SQLITE_FULL.
- Settings and revision writes commit together; malformed policy/revision reads fail closed.
- Audit rotation persists its journal atomically and retains live/pending log paths and recovery evidence when ingestion or rollback fails.
- AES-GCM decryption requires a full 16-byte tag; shortened TOTP tags are rejected.
- Upstream proxy builds retain symbols for accurate binary scanning without custom Go code.

## Results

| Check | Result |
|---|---|
| Complete suite matrix | 32/34 suite files pass; reload and audit-lifetime regressions fail |
| OpenAPI | 73 checks pass; 191 operations / 161 paths; zero warnings |
| Real filesystem/crash faults | 9/9 pass in private 32 MiB tmpfs, running without root |
| Data/config upgrade and rollback | v1.0.1 and base 1.0.2, Lite and Full: 4/4 pass |
| Disposable container lifecycle | 8/8 pass, including identical certificate after recreation |
| Browser smoke / authentication | 44 / 27 checks pass |
| npm dependency audits | Zero backend/frontend findings |
| Configuration / secret scanning | 216 configuration checks pass; zero misconfiguration or secret findings |
| Static analysis | 308 targets, zero parsing errors, 4 reviewed false positives retained in raw output |
| Current proxy binary scan | Zero reachable/imported-package vulnerabilities; one required-module record |
| Images | Backend/Caddy blocked by GO-2026-5932; demo and five discovery images have zero findings |
| Redis / discovery | Authenticated TLS Redis and both PHP/web/database fixtures pass |

## Load and failure evidence

The final load ran for 900.5 seconds with 24 clients over HTTP/1, HTTPS and HTTP/2. It completed 142227 successful requests, 434 reloads and 48 audit rotations, with **89 errors**. It observed 0 WAF bypasses and 0 duplicate writes. The strict zero-error gate fails. p99 was 622 ms; peak proxy RSS 159.6 MiB, fixture disk 566.0 MiB and descriptors 122.

HTTP/1 requests have no retries. Explicit HTTP/2 REFUSED_STREAM retries remain separately counted (8) and checked against duplicate POST execution. Lost requests are not reclassified as successes. Two earlier 15-minute runs are retained as earlier source snapshots. A separate run interrupted after roughly 715 seconds by a WSL restart is marked incomplete; it is not counted as a finished test.

The strict reload fixture recorded 1280 successful sampled requests and 13 failed pairs. The new audit-lifetime test first verifies a normal 500 response is logged, then shows that a slow 500 response crossing several rotations loses its audit record. Earlier rotation tests did not cover that writer lifetime. Both regressions remain enabled and failing.

## Remaining blockers

The upstream HTTP server can close a newly accepted HTTP/1 request while shutdown starts; see [Go issue 75591](https://github.com/golang/go/issues/75591). No Node-only connection-management fix has been implemented. A reload acknowledgement also does not establish that older requests have finished writing audit records; safe audit-file retirement remains unresolved.

[GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) has no fixed version. The current binary scan narrows exposure to required-module metadata, but does not eliminate the record. Every reported advisory still blocks image policy. See [the advisory assessment](go-advisory-assessment.md).

- Reload connection resets remain unresolved on the existing upstream dependency; no Node-only connection-management fix has been implemented.
- A slow request spanning multiple rotations can lose its audit record after an old file is pruned. The positive logging control passes and the new strict regression fails.
- GO-2026-5932 has no fixed version. Binary scanning finds no affected imported packages, but the unfiltered image gate still blocks its module record.
- 15-minute local Linux/amd64 load is not a completed 24-hour soak or a production-capacity benchmark.
- Physical power loss, block-device EIO, kernel-OOM, network filesystems and the full supported-platform installer matrix were not tested.
- API rejection tests and representative response schemas do not exhaust valid payload combinations or WAF evasions.
- Third-party provider accounts, real ACME issuance, and complete ClamAV/Ollama deployment matrices were not exercised.
- No equivalence to BunkerWeb reliability or guarantee of zero bugs/vulnerabilities is established.

Runtime source SHA-256: `a8ecbeab23731f32276cdcc75331d617f6ce839d95f25fd7ff58434e5d0da206`. Proxy binary SHA-256: `7e2adaa80b0bf1ebd1356c69b8caefeb8e213babd826afbedb96f997ac2f250f`.

The [machine-readable record](security-recheck-2026-10-17.json) and accompanying `node-security-recheck-2026-10-17` directory contain per-suite outcomes, unfiltered scanner reports and load logs. Earlier audit documents are historical snapshots.
