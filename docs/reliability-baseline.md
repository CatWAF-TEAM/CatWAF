# Reliability baseline — 2026-10-17

The release remains blocked: 32 of 34 suite files pass, while reload connection resets and audit-record loss during overlapping requests/rotations remain reproducible. The final 15-minute mixed-protocol load fails the strict zero-error gate. GO-2026-5932 remains unsuppressed and blocks both images containing Caddy.

See [current results](security-recheck-2026-10-17.md) and [the validation record](security-recheck-2026-10-17.json). No equivalence to BunkerWeb reliability or absence of all vulnerabilities is established.

## Reproduce

Use Node 24 and the upstream Caddy/Coraza binary built by the repository Dockerfile on disposable Linux storage.

```bash
npm ci --ignore-scripts
npm --prefix frontend ci --ignore-scripts
npm test
npm run test:reliability
npm run test:reliability:load
sudo env PATH="$PATH" CATWAF_TEST_USER="$(id -un)" bash scripts/check-filesystem-reliability.sh
# Build disposable stack images first.
CATWAF_TEST_IMAGE_PREFIX=catwaf-security-check node scripts/check-container-reliability.js
```

The filesystem wrapper mounts a newly created private tmpfs, never an existing data directory. HTTP/1 retries, advisory exceptions and relaxed error budgets are not used. The container script creates and removes only its own unique test project.
