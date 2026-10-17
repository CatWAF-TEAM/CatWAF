# Reliability baseline — 2026-10-17

The release remains blocked by reload connection resets and GO-2026-5932 in
both images containing Caddy. The audit-lifetime regression is fixed and has
passed with native Caddy and separate containers on a real Kubernetes cluster.
The latest complete suite has 35 of 36 files passing; the strict reload gate
remains enabled and failing.

See [current results](reliability-followup-2026-10-17.md) and the
[earlier validation record](security-recheck-2026-10-17.json). No equivalence to
BunkerWeb reliability or absence of all vulnerabilities is established.

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
