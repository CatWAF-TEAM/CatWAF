# Installation

Use Node 22.16+ on the 22 LTS line, or Node 24+. Offline database restore uses
the built-in SQLite backup API. `node scripts/ensure-caddy.js` obtains the
existing upstream Caddy/Coraza dependency and validates it before installation.
CatWAF application code remains Node.js; there is no local Go application,
vendored engine, or patched Go runtime. Docker retains the original upstream
xcaddy integration with security version pins.
See [security-recovery.md](security-recovery.md) before restoring or upgrading.

## Choose an edition first

Everything below depends on this choice. It is written to `.env` as
`CATWAF_EDITION` and enforced at runtime — it is not a label.

### CatWAF Lite

**Installs:** Caddy + Coraza + the OWASP CRS · the full `catwaf` CLI · the SQLite
event and request log · a systemd service for the WAF.

**Does not install:** React · Vite · `frontend/node_modules` · the HTTP API
server · the web dashboard · CatAI/Ollama · Docker stack tooling.

`catwaf start` brings up the WAF. It does not start an HTTP server, because Lite
does not have one. You investigate and tune entirely from the CLI —
`catwaf audit`, `catwaf explain`, `catwaf rules`, `catwaf paranoia`,
`catwaf mode`, `catwaf config`. All of them work exactly as they do in Full.

Choose Lite when the machine is a server you administer over SSH, when you do not
want a web control panel exposed at all, or when disk and memory matter.

### CatWAF Full

**Adds:** the HTTP API server · the built React dashboard · the Attack Map,
Threats, Logs and Rules pages · CatAI where configured · `catwaf docker`.

CatAI is genuinely optional — Full works without Ollama installed, and setup says
so rather than reporting a failure.

Choose Full when you want the dashboard.

### Switching later

```bash
catwaf setup --full     # Lite  → Full: installs frontend deps, builds, enables the API
catwaf setup --lite     # Full  → Lite: removes the API service
```

Safe to re-run. Preserves WAF configuration, the database, event history, rules,
domain settings and admin accounts.

## The installer (recommended)

Download it, read it, then run it:

```bash
curl -fsSLo setup.sh https://raw.githubusercontent.com/CatWAF-TEAM/CatWAF/release-1.0.1/setup.sh
less setup.sh
sudo bash setup.sh --lite      # or --full, or omit for an interactive menu
```

| Option | Meaning |
|---|---|
| `--lite` / `--full` | Edition. Omit for an interactive menu. |
| `--dir <path>` | Install directory. Default `/opt/catwaf`. |
| `--domain <domain>` | Base domain. Omit to run locally. |
| `--admin-user <name>` | Admin account to create. |
| `--with-ai` / `--no-ai` | Install Ollama for CatAI, or skip it. Full only. |
| `--yes` | Never prompt. Suppresses prompts only — validation still runs. |

Set `CATWAF_ADMIN_PASSWORD` in the environment rather than passing a password
flag, so it does not land in your shell history or `ps` output:

```bash
CATWAF_ADMIN_PASSWORD='...' sudo -E bash setup.sh --lite --yes \
  --domain example.com --admin-user admin
```

**Supported distributions:** Debian, Ubuntu, Fedora, RHEL/Rocky/AlmaLinux,
Alpine. On anything else the installer stops with an explanation and points you
at the manual path below rather than guessing.

The installer creates a dedicated non-login `catwaf` system account, writes
`.env` mode `600` under `umask 077`, installs a hardened systemd unit, and is
idempotent — re-running updates in place, and it refuses to overwrite a non-empty
directory that is not a CatWAF checkout.

On the `curl … | sudo bash` one-liner and what you are trusting when you use it,
see [SECURITY.md](../SECURITY.md#installer-trust-model).

## Docker (fastest path)

```bash
git clone https://github.com/CatWAF-TEAM/CatWAF.git catwaf
cd catwaf
cp .env.example .env   # then set JWT_SECRET — see the file for how
docker compose up --build
```

| Service | URL |
|---|---|
| Control Panel (admin) | http://localhost:8081 |
| Protected website (through the WAF) | http://localhost — and https://localhost once you configure a domain |
| Backend API | http://localhost:8000 |
| Protected website's origin (bypasses the WAF) | http://127.0.0.1:8082 |

There are no accounts yet — create your login before opening the dashboard:

```bash
docker compose exec backend node bin/catwaf.js user add admin --role admin
```

This builds Caddy with the Coraza module for you (the manual `xcaddy` step below happens inside the image build instead), and ships a `test-app` service — the repository's deliberately vulnerable demo app, published on loopback only as the `:8082` origin — so the "prove it's working" curl commands further down have something to protect immediately. The WAF is active on `:80` from first boot at CatWAF's defaults, and `:8082` is the same app *without* the WAF in front of it, so you can see both sides. See [docker.md](docker.md) for the full architecture, how to point it at your real application instead of the demo, and a security tradeoff in the compose file that's worth reading before you deploy this anywhere but your own machine.

The rest of this doc is the manual (non-Docker) path — useful if you want Caddy and Node running directly on the host, or you're adapting the setup for something docker-compose doesn't cover yet.

## Requirements

- **Node 22+** — CatWAF's backend uses the built-in `node:sqlite` module, no separate database server needed.
- **Caddy with the Coraza module** — this is what actually inspects traffic. The dashboard and API run fine without it, but nothing gets blocked until it's in place.
- **Go** (only needed to build Caddy with the Coraza module — see below)
- **Ollama** *(optional)* — only for [CatAI](catai.md), the local assistant. Skipping it changes nothing else.

## 1. Build Caddy with Coraza

CatWAF isn't a ModSecurity wrapper — it uses [Coraza](https://github.com/corazawaf/coraza), a WAF engine written natively in Go, plugged into Caddy as a module. You build your own Caddy binary with that module included:

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
xcaddy build --with github.com/corazawaf/coraza-caddy/v2 --output /usr/bin/caddy

# Confirm the module is actually in there:
caddy list-modules | grep waf
# → http.handlers.waf
```

If you'd rather not build Go binaries locally, do this step in Docker — the module needs to end up in the `caddy` binary that ends up running, however you get there.

## 2. Clone and install

```bash
git clone https://github.com/CatWAF-TEAM/CatWAF.git catwaf
cd catwaf

# Lite
CATWAF_EDITION=lite npm install

# Full
CATWAF_EDITION=full npm install
npm run build
```

`npm install` fetches the backend's dependencies and Caddy with the Coraza
module. Its postinstall step reads `CATWAF_EDITION` and installs the frontend's
dependencies **only for Full** — a Lite install pulls no React and no Vite at
all. With the variable unset, the edition is inferred from whether a built
dashboard is already present.

For Full, `npm run build` is **not optional.** `frontend/dist/` is gitignored,
and both the backend's static handler and the generated Caddyfile serve from it —
skip it and the dashboard answers every request with a 404. Lite does not need
it and does not use it.

Set `CATWAF_SKIP_CADDY_DOWNLOAD=1` if you supply Caddy yourself (container
images, CI) and do not want the postinstall step fetching a binary.

### Making `catwaf` a real command

```bash
sudo npm link
```

This puts `catwaf` on your `PATH`, so `catwaf --setup` and `catwaf --status` work from anywhere. Without it, run the CLI as `node bin/catwaf.js --setup`.

(The one-line installer at the top of this page does this for you, via a small wrapper in `/usr/local/bin`.)

## 3. Run the setup wizard

```bash
catwaf setup --lite       # or --full, or omit for the interactive menu
```

This is not optional — **there are no default accounts.** Nothing ships with a password, so until the wizard runs there is nothing to log into.

The wizard checks your environment, asks for a domain (leave it blank to run locally), creates your admin account with a password you choose, generates a `JWT_SECRET`, writes a starter Caddyfile, records the edition in `.env`, and — in Full — builds the dashboard and optionally offers to set up [CatAI](catai.md).

`catwaf --setup` still works as a legacy alias, as do `--minimal` (Lite) and `--standard` (Full).

## 4. Run it

```bash
npm run dev     # development: backend :8000 + dashboard :8081
npm start       # production
```

`npm run dev` starts the backend API and the frontend dev server, and also starts Caddy fronting `:8081`/`:8000` with a dev-only Coraza WAF block if a Caddy build with the Coraza module is available (`npm install` fetches one automatically) — see `scripts/dev.js`. The backend and Vite quietly move to internal ports in that case; you still use `:8081`/`:8000` as shown below. If no working Caddy is found, it says so and falls back to the backend and Vite talking directly with no WAF in the loop.

If CatAI is enabled, both commands check Ollama, pull a missing model, and attempt to warm it before starting the dashboard. The first pull needs network access and can take substantially longer than a normal startup. If Ollama cannot start or the pull fails, the dashboard still starts and CatAI reports itself unavailable. See the [CatAI guide](catai.md) for the default local endpoint and the privacy effect of changing `OLLAMA_URL`.

| Service | URL |
|---|---|
| Control Panel (admin) | http://localhost:8081 |
| Backend API | http://localhost:8000 |

**Production** (`npm start`, or the installer) is simpler: one port serves
everything — **http://localhost:8000** for the dashboard *and* the API.

### Where is my dashboard?

| You installed… | Open | How |
|---|---|---|
| On this machine (default) | `http://localhost:8000` | Nothing to do |
| On a server/VPS, no domain | `http://<server-ip>:8000` | `HOST=0.0.0.0` in `.env`, restart, open firewall port 8000. Plain HTTP — fine for a home lab ([exposure notes](SECURITY.md#network-exposure)) |
| You own a domain | `https://catwaf.<your-domain>` | Set `DOMAIN` / re-run setup; DNS records per [README](../README.md#where-is-my-dashboard) |

`HOST` and `PORT` in `.env` control the bind address and port.

Your protected site is separate from both of these: Caddy serves it on `:80`
(and `:443` with a domain), proxying to wherever your application actually
listens — `:8082` by convention throughout these docs. See
[reverse-proxy.md](reverse-proxy.md).

Log in with the admin account you created in step 3.

## 5. First things to do

1. **Set a real `JWT_SECRET`**: copy `.env.example` to `.env` and set a random value (`openssl rand -hex 32`). The wizard usually does this; leaving it unset means every restart invalidates sessions.
2. **Optional environment gates** (all documented in `.env.example`): `CATWAF_KERNEL_BANS=1` for [kernel-level drops](protection.md#kernel-level-drops-opt-in), `CATWAF_BACKUP_PASSPHRASE` for [encrypted backups](SECURITY.md#backup-encryption).
2. **Set `CORS_ORIGIN`** to your real dashboard URL before exposing this to the internet.
3. **Point Caddy at your actual application** — see [reverse-proxy.md](reverse-proxy.md).
4. **Check the Security page** (`/security-score`) — it grades your actual current configuration, not a demo number, and tells you exactly what to fix.
5. **Run the Origin Exposure Scanner** (`/origin-scanner`) to confirm your real server isn't still reachable around the WAF.

## Environment variables

See `.env.example` in the project root for the full list with descriptions. None are required for local development — everything has a sane default.

The ones that matter most at install time:

| Variable | Meaning |
|---|---|
| `CATWAF_EDITION` | `lite` or `full`. Written by setup; read by `npm install`, the CLI and `catwaf status`. |
| `CATWAF_ADMIN_PASSWORD` | Admin password for non-interactive setup. Preferred over a flag. |
| `CATWAF_SKIP_CADDY_DOWNLOAD` | Set to `1` to stop postinstall fetching a Caddy binary. |
| `CADDYFILE_PATH` | The Caddyfile CatWAF writes into. Auto-detected when unset. |
| `JWT_SECRET` | Signs session tokens. Generated at setup if absent. |
| `CATWAF_DEBUG` | Set to `1` to print stack traces on CLI errors. |

`.env` holds every secret CatWAF has. It is written mode `600`; CatWAF warns at
startup if it is readable by other users. See [SECURITY.md](../SECURITY.md#secrets).

## Verifying it's actually blocking things

```bash
curl "http://localhost/?id=1+UNION+SELECT+1,2,3--"
curl "http://localhost/?q=<script>alert(1)</script>"
curl -A "sqlmap/1.0" http://localhost/
```

All three should come back blocked. If they don't, start with **Setup Diagnostics** (`/diagnostics`) — the most common cause is the Caddyfile not actually having the `coraza_waf` directive wired in, which it checks for directly.
