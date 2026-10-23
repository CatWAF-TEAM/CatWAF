# Contributing to CatWAF

Thanks for taking a look. CatWAF Free is open source under the [MIT License](LICENSE). Bug reports, feature requests, security disclosures, and pull requests are welcome. By submitting a contribution, you agree that your contribution is licensed under the same MIT terms.

## Getting set up

```bash
git clone https://github.com/agugusgeyehe-dot/catwaf
cd catwaf
npm run install:all
npm run dev
```

This starts the backend, the frontend dev server, and — if Caddy with the Coraza module is installed (`npm install` fetches it automatically) — Caddy itself, fronting `:8081` (dashboard) and `:8000` (API) with a dev-only Coraza block so requests are actually WAF-inspected, the same as production. The backend and Vite move to internal ports (`:8001`/`:5173` by default) in that case; hit `:8081`/`:8000` as usual either way. If Caddy isn't available, `npm run dev` says so and falls back to the backend and Vite talking to each other directly with no WAF in the loop — see [docs/installation.md](docs/installation.md).

Run `catwaf setup --full` first if you haven't — there are no default accounts, so without it there's nothing to log into.

**Editions when developing.** `npm run install:all` and `npm run dev` are the Full path, which is what you want for frontend work. If you are working on the WAF, CLI or backend only, `CATWAF_EDITION=lite npm install` skips the frontend toolchain entirely. The edition lives in `.env`; `catwaf edition` prints it. When touching anything edition-dependent, check both — `test/edition.test.js` exercises the boundary but cannot catch a UI assumption baked into a backend service.

## Project structure

```
backend/
  server.js       # thin bootstrap — creates the app, mounts routers, listens
  routes/         # one file per feature area (waf.js, network.js, catai.js, ...)
  services/       # shared logic the routes call into (state, db, audit, caddy, ...)
  services/catai/ # the local assistant — self-contained, deletable as a unit
  knowledge/      # CatAI's knowledge base (markdown + YAML frontmatter)
  middleware/     # auth (JWT + request signing + admin/viewer gate), path gate
frontend/
  src/pages/      # one file per major page/section
  src/components/ # shared UI (Sidebar, Header, WelcomeTour, catai/)
  src/utils/api.js # the signed-request client — all backend calls go through it
bin/catwaf.js     # the CLI entry point
src/tui/          # the CLI's commands, terminal UI and doctor checks
scripts/          # dev/start wrappers, Caddy fetch, settings-doc generator
test/             # 26 suites — 24 in the `npm test` chain + browser/auth (see below)
docker/           # Dockerfiles + Caddyfile for the compose stack
logo/             # brand assets (see logo/README.md)
docs/             # setup + feature guides
openapi.yaml      # the HTTP API specification
setup.sh          # the installer
```

`data/` is not in the repository — it is created on first run and holds the SQLite
database, Caddyfile backups and rotated audit logs. All of it is gitignored, because
it is real WAF state.

See [docs/architecture.md](docs/architecture.md) for what each service does.

## Running the tests

```bash
npm test              # the 24 core suites (includes real-Caddy E2E when Caddy is present)
npm run test:unit     # the 14 that need no Caddy binary
npm run test:frontend # adds the Playwright smoke test (needs a browser)
npm run test:all      # everything
```

**Stop CatWAF before running the suite on a machine where it is installed.**
Every suite redirects `CADDYFILE_PATH`, `DB_DIR`, `CORAZA_AUDIT_LOG` and
`CADDY_ADMIN_URL` into a temporary directory and a dead admin port, so the
tests cannot touch your Caddyfile, your database, your audit log or your
running Caddy. The cost of that isolation is that the suites which apply a
setting end to end cannot complete a reload while a Caddy they are walled off
from is running — `configTx` correctly rolls the change back, and those checks
fail. `catwaf stop` first, or run the suite somewhere else. Running as root is
fine; a few checks that need an unprivileged user skip themselves.

Individually — none need network. The five at the bottom drive a real Caddy +
Coraza and **skip rather than fail** when that binary is not installed:

```bash
node --experimental-sqlite test/security.test.js          #  52 checks — request signing, replay, tampering
node --experimental-sqlite test/attack.test.js          # 142 checks — hostile input across every route
node --experimental-sqlite test/concurrency.test.js     #  16 checks — cross-process locking, no lost updates (spawns children)
node --experimental-sqlite test/trust-proxy.test.js     #   4 checks — forwarded-header trust inference, four deployment shapes
node --experimental-sqlite test/features.test.js        #  32 checks — canary, edge bans, kernel rulesets, alert dispatch, backup restore
node --experimental-sqlite test/catai.test.js             #  66 checks — retrieval, extraction, action safety
node --experimental-sqlite test/platform.test.js          # 110 checks — packaging, platform assumptions, SSRF-guard invariants
node --experimental-sqlite test/waftools.test.js          # 167 checks — rules, modes, snapshots, simulate
node --experimental-sqlite test/edition.test.js           # 166 checks — editions, CLI, docker, GeoIP, setup.sh
node --experimental-sqlite test/subdomain.test.js         #  39 checks — rotating path segment, decoy responses
node --experimental-sqlite test/discovery.test.js         # 291 checks — runtime/webserver/container discovery
node --experimental-sqlite test/audit-log.test.js         #  37 checks — Coraza audit ingestion
node --experimental-sqlite test/audit-rotation.test.js    #  61 checks — audit-log rotation and retention
node --experimental-sqlite test/protection-units.test.js  # 167 checks — TOTP, feeds, bans, plugin validator
node --experimental-sqlite test/apps-api.test.js          #  37 checks — the apps/protect API
node test/qr.test.js                                      #  39 checks — the in-tree QR encoder
node --experimental-sqlite test/upload-scan.test.js       #  44 checks — ClamAV gate, bounded buffering
node --experimental-sqlite test/extensions.test.js        #  35 checks — Caddy module capability reporting
node --experimental-sqlite test/render.test.js            #  12 checks — six configs validated by real caddy
node --experimental-sqlite test/protect-e2e.test.js       #  33 checks — protect flow end to end
node --experimental-sqlite test/waf-e2e.test.js           #  36 checks — real Coraza blocking end to end
node --experimental-sqlite test/sfl-e2e.test.js           #  39 checks — real sensitive-file blocking, SFL1-4 cumulative
node --experimental-sqlite test/edge-e2e.test.js         #  13 checks — banned source aborted by real Caddy at the edge; un-ban propagates via reload
```

**~1,642 checks** in total for `npm test`. Two further suites need extra
prerequisites — a browser or a running backend — and are not in that number:
`test/frontend-smoke.test.js` (44 checks, walks every dashboard route in real
Chromium) and `test/auth-flow.test.js` (27 checks, full login → TOTP → LAN-CORS
flow in the browser).

Coverage is real but not complete: request signing, CatAI's deterministic half, the WAF
tooling, the edition model and the CLI surface are well covered; most individual route
handlers are exercised only indirectly.

Two conventions worth knowing before you add tests:

- **Never assert on fabricated data.** Several suites specifically check that CatWAF
  reports "no data" rather than inventing it — the Attack Map is the clearest case. If a
  feature would look better with placeholder values, that is the feature to change.
- **`test/edition.test.js` cross-checks the CLI against itself**: every command in
  `catwaf help` must dispatch, and every dispatched command must be documented. Adding a
  command without help text fails the suite.

## Reporting bugs

Open an issue with:
- What you expected vs. what happened
- Steps to reproduce
- Output of `GET /api/diagnostics/export` if it's a backend issue — it's a sanitized diagnostic dump built exactly for this (no database path, tokens, or secrets included)

## Reporting security issues

Please report security issues privately rather than as a public issue — email agugusgeyehe@gmail.com with what you found, how to reproduce it, and its impact.

## Feature requests

Open an issue describing the problem you're trying to solve, not just the feature you have in mind — the best additions come from a real wall someone hit, not a feature list.

## Code style

For reading the code: nothing is enforced by a linter — 2-space indent, no semicolons-as-religion (the codebase is inconsistent), and small named functions in `services/` over inlining logic in route handlers.
