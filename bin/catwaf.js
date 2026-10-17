#!/usr/bin/env node

const fs = require('fs')
const path = require('path')

const PROJECT_ROOT = path.join(__dirname, '..')
const pkg = require(path.join(PROJECT_ROOT, 'package.json'))

const argv = process.argv.slice(2)

const C = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  green: '\x1b[32m', yellow: '\x1b[33m', red: '\x1b[31m', cyan: '\x1b[36m',
}
const useColor = process.stdout.isTTY && !process.env.NO_COLOR
const c = (s, ...codes) => useColor ? codes.join('') + s + C.reset : s

function parseArgs(args) {
  const flags = {}
  const positional = []
  for (let i = 0; i < args.length; i++) {
    const a = args[i]
    if (a === '--') { positional.push(...args.slice(i + 1)); break }
    if (a.startsWith('--')) {
      const eq = a.indexOf('=')
      if (eq !== -1) { flags[a.slice(2, eq)] = a.slice(eq + 1); continue }
      const key = a.slice(2)
      const next = args[i + 1]
      if (next && !next.startsWith('-')) { flags[key] = next; i++ }
      else flags[key] = true
      continue
    }
    if (a.startsWith('-') && a.length > 1) { flags[a.slice(1)] = true; continue }
    positional.push(a)
  }
  return { flags, positional }
}

const HELP = {
  main: `
${c('CatWAF', C.bold, C.cyan)} v${pkg.version} — Coraza WAF control panel

${c('Usage:', C.bold)} catwaf <command> [options]

${c('Getting started', C.bold)}
  setup              First-run wizard (interactive, or --lite / --full)
  doctor             Diagnose this environment; exits non-zero if unhealthy
  provision          Configure your web server to serve the dashboard
  auto               Discover running web apps and protect them automatically

${c('Operations', C.bold)}
  explain            Explain why a request was blocked
  audit              Traffic and attack summary
  simulate           Test what the WAF would do, without touching upstream
  replay             Re-test a historical attack against the current config
  rules              Inspect and toggle CRS rules
  paranoia           Show or set the paranoia level (1-4)
  mode               Show or set the operating mode
  health             Component health; exits non-zero when degraded
  security-test      Assess CatWAF's own security posture
  diff               What changed since the last snapshot

${c('Protection & configuration', C.bold)}
  settings [group]   Show or change any settings group (--preview, --reset)
  bans <sub>         Active bans (list, add, lift, clear)
  template <sub>     Configuration templates (list, save, apply, remove)
  jobs <sub>         Scheduled jobs (list, run)
  cache <sub>        Cached lookups (list, clear, refresh)
  backup <sub>       Backups (now, list, verify, restore)
  kernel-bans        Kernel-level drops status (print-rules emits the nft ruleset)
  report             Export activity over a date range
  2fa <sub>          Two-factor login (status, enroll, confirm, disable, codes)

${c('Service', C.bold)}
  start              Start CatWAF
  stop               Stop CatWAF
  restart            Restart CatWAF
  status             Version, edition, protection, Caddy and recent activity
  logs               Show CatWAF logs
  update             Check GitHub for a newer CatWAF release
  docker <sub>       Manage the Docker stack ${c('(Full only)', C.dim)}

${c('Administration', C.bold)}
  user <sub>         Manage accounts (list, add, remove, passwd, role)
  config             Show effective configuration
  config snapshot    Save a restorable configuration snapshot
  config snapshots   List snapshots
  config diff <id>   Compare a snapshot with the current configuration
  config restore <id> Restore a snapshot (validated, auto-rollback)
  uninstall          Remove CatWAF's service and generated files

${c('Other', C.bold)}
  version            Print the version
  edition            Print the installed edition (lite or full)
  help [command]     Show help for a command

Run ${c('catwaf help <command>', C.cyan)} for details on any command.
Legacy flag forms (${c('--setup', C.dim)}, ${c('--status', C.dim)}, ${c('--version', C.dim)}) still work.
`,

  setup: `
${c('catwaf setup', C.bold)} — first-run wizard

Checks the environment, configures a domain, creates your admin account,
writes a Caddyfile, and optionally sets up the CatAI assistant.

${c('Usage:', C.bold)} catwaf setup [--lite | --full | --custom] [options]

${c('Editions', C.bold)}
  --lite             Caddy + Coraza + CRS, the CLI and the event database.
                     No dashboard, no API server, no CatAI, no frontend
                     dependencies installed at all.
  --full             Everything in Lite plus the HTTP API, the built
                     dashboard, the Attack Map and CatAI (optional).
  --custom           Interactive component selection.
  (no flag)          Interactive menu.

Re-running with a different edition converts in place. ${c('catwaf setup --full', C.cyan)}
on a Lite install adds the dashboard and API and keeps your WAF
configuration, rules, event history and admin accounts.

${c('Non-interactive options', C.bold)}
  --domain <domain>  Base domain. Omit to run locally.
  --admin-user <u>   Admin username to create.
  --admin-pass <p>   Admin password (min 8 chars). Prefer CATWAF_ADMIN_PASSWORD.
  --yes              Never prompt; fail instead of asking.
  --no-ai            Skip CatAI even in Full.

${c('Legacy flags', C.bold)}
  --minimal          Accepted; identical to --lite.
  --standard         Accepted; identical to --full.

Non-interactive mode never asks questions. If something required is missing
it fails with a clear message instead of prompting. ${c('--yes', C.dim)} suppresses
prompts only — it never skips validation.
`,

  docker: `
${c('catwaf docker', C.bold)} — manage the Docker stack ${c('(CatWAF Full only)', C.yellow)}

Wraps ${c('docker compose', C.cyan)} against this repository's docker-compose.yml
(backend API, Caddy + Coraza, and the local test app).

${c('Usage:', C.bold)} catwaf docker <subcommand> [options]

${c('Subcommands', C.bold)}
  up                 Start the stack in the background (--build to rebuild)
  down               Stop the stack and remove its containers
  restart            Restart every service
  status             Show each service and its state
  ps                 Alias of status
  logs               Recent logs from every service (--follow to stream)
  build              Rebuild the stack images

${c('Options', C.bold)}
  --build            With ${c('up', C.cyan)}: rebuild images before starting.
  --follow, -f       With ${c('logs', C.cyan)}: stream instead of printing a snapshot.

${c('Exit codes', C.bold)}
  0  success
  1  the compose command itself failed
  2  unknown or missing subcommand
  3  Docker or the Compose plugin is not installed
  5  this is a Lite installation

Subcommands are matched against a fixed allowlist and the argument vector is
built from constants — no shell is used and nothing you type is interpolated
into a command.
`,

  doctor: `
${c('catwaf doctor', C.bold)} — diagnose this environment

Read-only. Makes no changes. Checks the OS, Node runtime, Caddy and the
Coraza module, Caddyfile syntax and writability, the audit log pipeline,
the database and its schema, authentication, ports, other web servers,
and control panels (cPanel/Plesk/DirectAdmin).

${c('Usage:', C.bold)} catwaf doctor [--verbose] [--json]

  --verbose          Include informational checks and full environment data
  --json             Machine-readable output for automation

${c('Exit codes', C.bold)}
  0                  Healthy — no failed checks
  1                  One or more checks failed
  2                  Doctor itself could not run
`,

  auto: `
${c('catwaf auto', C.bold)} — discover and protect web apps automatically

Detects Docker, enumerates running containers, and identifies which ones are
web applications (PHP/nginx/Apache, Node.js, Python, static) using multiple
signals — image name, running processes, filesystem probes, HTTP headers and
body fingerprints, and container labels/env — combined into a confidence
score rather than trusted individually.

For each web application found, CatWAF generates a protected reverse-proxy
route (Client → CatWAF → Coraza/OWASP CRS → app), validates it with
\`caddy validate\`, backs up the previous Caddyfile, and applies it atomically.
If validation fails, nothing is written and the previous configuration is
kept untouched.

${c('Usage:', C.bold)} catwaf auto [--dry-run] [--verbose] [--json]

  --dry-run          Discover and show what would happen; change nothing
  --verbose          Show routing caveats (network reachability, port reuse)
  --json             Machine-readable output

Upstreams prefer the container/compose-service name over its IP (IPs churn
across restarts); a published host port is used only as a fallback, and is
always flagged as bypassing the WAF directly. CatWAF never modifies or stops
a discovered container.

If Docker isn't available, this command fails gracefully and exits non-zero;
it does not fall back to guessing at non-Docker deployments.
`,

  provision: `
${c('catwaf provision', C.bold)} — serve the dashboard at catwaf.<your-domain>

Detects your web server (Caddy, nginx, Apache) or control panel (cPanel,
Plesk, DirectAdmin), then generates the right configuration to serve the
CatWAF dashboard on a dedicated subdomain.

${c('Usage:', C.bold)} catwaf provision [--print] [--apply] [options]

  --print            Show the generated configuration and exit (default)
  --apply            Write it, validate it, and reload the web server
  --domain <domain>  Base domain (default: auto-detected)
  --target <name>    Force caddy | nginx | apache | cpanel
  --port <n>         CatWAF API port (default: 8000 or \$PORT)
  --yes              Skip the confirmation prompt when using --apply

--apply always backs up the existing file first, validates the result, and
rolls back automatically if validation fails. Control panels are detection
only: CatWAF never edits panel-managed configuration.
`,

  user: `
${c('catwaf user', C.bold)} — manage accounts

${c('Usage:', C.bold)} catwaf user <subcommand> [options]

  list                       List accounts and roles
  add <username>             Create an account
    --role admin|viewer      Role (default: viewer)
    --password <p>           Password (min 8 chars)
                             Prefer CATWAF_USER_PASSWORD to keep it out of history
  remove <username>          Delete an account
  passwd <username>          Change an account's password
    --password <p>           New password
  role <username> <role>     Change an account's role

Passwords are stored as bcrypt hashes, never plaintext. The last admin
account cannot be removed or demoted.
`,

  status: `
${c('catwaf status', C.bold)} — health summary

Shows protection mode, Caddy/Coraza state, the security score, and recent
WAF activity. All values are read from the running system.

${c('Usage:', C.bold)} catwaf status
`,

  start: `
${c('catwaf start', C.bold)} — start CatWAF and protect your applications

This is the "put my website behind CatWAF" command. It starts the service,
then discovers running web applications, places the WAF in front of them,
and ${c('proves', C.bold)} the protection with real traffic before reporting success.

${c('Usage:', C.bold)} catwaf start [--no-auto] [--no-verify] [--verbose] [--json]

  --no-auto          Start the service only; do not discover or protect
  --no-verify        Apply routes without the live protection self-test
  --verbose          Show routing caveats
  --json             Machine-readable output

${c('What it does', C.bold)}
  1. Starts CatWAF (systemd when available, otherwise a background process)
  2. Discovers running web applications (see ${c('catwaf help auto', C.cyan)})
  3. Attaches CatWAF's proxy to the app's Docker network so it can reach it
  4. Generates routes that send traffic through Coraza + OWASP CRS first
  5. Validates the whole configuration, backs it up, applies it atomically
  6. Reloads the proxy
  7. Sends a benign request and a CRS test payload to its own endpoint and
     confirms the first is served and the second is blocked

A route is reported ${c('protected', C.green)} only if step 7 passes. If traffic does not
actually traverse the WAF, CatWAF says so and exits non-zero — a generated
configuration is never treated as evidence of protection.

Idempotent: re-running regenerates CatWAF's own managed region only, keeps
listen ports stable, leaves unrelated configuration untouched, and handles
containers that restarted, changed network, or disappeared.
`,

  stop: `
${c('catwaf stop', C.bold)} — stop CatWAF

Sends SIGTERM, waits for a clean exit, then escalates to SIGKILL only if
the process refuses to exit.

${c('Usage:', C.bold)} catwaf stop
`,

  restart: `
${c('catwaf restart', C.bold)} — restart CatWAF

${c('Usage:', C.bold)} catwaf restart
`,

  logs: `
${c('catwaf logs', C.bold)} — show CatWAF logs

Reads the journal under systemd, otherwise the log file in the data
directory.

${c('Usage:', C.bold)} catwaf logs [--lines <n>] [--follow]

  --lines <n>        Number of lines (default 50)
  --follow, -f       Stream new output
`,

  config: `
${c('catwaf config', C.bold)} — show effective configuration

Prints resolved paths, ports, WAF settings and feature flags. Secrets are
never printed — only whether they are set.

${c('Usage:', C.bold)} catwaf config [--json]
`,


  explain: `
${c('catwaf explain', C.bold)} — explain why a request was blocked

${c('Usage:', C.bold)} catwaf explain <event-id>
       catwaf explain --last [--json]

Shows the classification, matched CRS rules and their descriptions, paranoia
level, anomaly score, severity, which part of the request matched, and what
you can do about it.

Request bodies, cookies and Authorization headers are never stored by CatWAF,
so they cannot appear here. Sensitive-looking query parameters are redacted.

Find event IDs with \`catwaf audit\`.
`,

  simulate: `
${c('catwaf simulate', C.bold)} — test what the WAF would do

${c('Usage:', C.bold)} catwaf simulate --url <url>
       catwaf simulate --request <file> [--json]

Runs the request through a throwaway Caddy + Coraza instance using your
CURRENT WAF configuration, against a local sink. Your real upstream is never
contacted, so nothing destructive can happen.

  --url <url>        Simulate a request to this URL. CatWAF does NOT fetch it;
                     only the method, path, query and headers are evaluated.
  --request <file>   A raw HTTP request file:
                       POST /login HTTP/1.1
                       Host: example.com
                       Content-Type: application/json

                       {"user":"x"}

Sensitive headers (Authorization, Cookie, API keys) are stripped before the
request is simulated and are never logged.
`,

  replay: `
${c('catwaf replay', C.bold)} — re-test a historical attack

${c('Usage:', C.bold)} catwaf replay <event-id> [--json]

Rebuilds a stored attack from sanitized event fields and replays it against
CatWAF's local simulation sandbox — never against production, and never
against your real upstream.

Reports whether the attack is still blocked by your current configuration,
which rules changed, and flags a regression if something that used to be
blocked would now get through.
`,

  rules: `
${c('catwaf rules', C.bold)} — inspect and toggle OWASP CRS rules

${c('Usage:', C.bold)} catwaf rules list [--category <c>] [--disabled|--enabled]
       catwaf rules search <query>
       catwaf rules show <rule-id>
       catwaf rules enable <rule-id>
       catwaf rules disable <rule-id>

Disabling a rule writes a real \`SecRuleRemoveById\` directive into your
Caddyfile. Every change is backed up, validated, and rolled back
automatically if Caddy rejects the result.

Rule metadata comes from local CRS files when available; otherwise CatWAF
falls back to rules observed in real traffic and says so.
`,

  audit: `
${c('catwaf audit', C.bold)} — traffic and attack summary

${c('Usage:', C.bold)} catwaf audit [--last 24h] [--attack SQLi] [--severity critical] [--json]

  --last <window>    30m, 6h, 24h, 7d, 4w  (default 24h)
  --attack <type>    SQLi, XSS, RCE, LFI, Scanner Detection, ...
  --severity <sev>   critical, error, warning, notice
  --limit <n>        Recent attacks to list (default 10)
  --json             Stable machine-readable output

Shows totals, block rate, top attack types, top CRS rules, severity
distribution and anomaly-score statistics for the window.
`,

  mode: `
${c('catwaf mode', C.bold)} — operating mode

${c('Usage:', C.bold)} catwaf mode [normal|lockdown|learning|maintenance] [--yes]

  normal        Standard production protection.
  lockdown      Paranoia 4 and a tighter anomaly threshold, for an active
                incident. Blocks aggressively and will cause false positives.
  learning      DetectionOnly at high paranoia. Records everything, BLOCKS
                NOTHING — your site is exposed while it is active.
  maintenance   Protection unchanged; audit logging reduced.

With no argument, shows the current mode. Every change is validated and
rolled back automatically if Caddy rejects it.
`,

  paranoia: `
${c('catwaf paranoia', C.bold)} — CRS paranoia level

${c('Usage:', C.bold)} catwaf paranoia          Show levels and the active one
       catwaf paranoia <1-4> [--yes]

  1  Balanced     Clear attacks, very few false positives (default)
  2  Elevated     Adds usually-malicious patterns
  3  Aggressive   Adds heuristics; expect to tune
  4  Maximum      Blocks nearly anything unusual

This sets the real CRS \`tx.blocking_paranoia_level\` in your Caddyfile.
Raising to 3 or 4 prompts for confirmation. Changes are backed up,
validated, and rolled back if Caddy rejects them.
`,

  health: `
${c('catwaf health', C.bold)} — component health

${c('Usage:', C.bold)} catwaf health [--json]
       catwaf health --watch [--interval 5]

Checks CatWAF, Caddy, Coraza, CRS, the database and its schema, the
Caddyfile and its validity, WAF interception, audit-log and event
ingestion, the dashboard build and the Caddy admin API.

${c('Exit codes', C.bold)}
  0  healthy      1  degraded      2  unhealthy
`,

  'security-test': `
${c('catwaf security-test', C.bold)} — assess CatWAF's own security posture

${c('Usage:', C.bold)} catwaf security-test [--json]

Checks bind addresses, admin-API exposure, Docker socket and privileged
containers, secret strength and file permissions, CORS, security headers,
proxy trust, WAF interception and bypass risk, disabled rules, and rate
limiting.

${c('Exit codes', C.bold)}
  0  no high or critical findings
  1  at least one high finding
  2  at least one critical finding

Passing these checks does not mean the protected application is secure.
`,

  diff: `
${c('catwaf diff', C.bold)} — what changed since the last snapshot

${c('Usage:', C.bold)} catwaf diff [--config] [--rules] [--json]

Compares the current configuration with the most recent snapshot: WAF
settings, paranoia level, enabled/disabled rules and categories, and the
operating mode. Secrets are never printed.
`,

  'security-test': `
${c('catwaf security-test', C.bold, C.cyan)} — assess CatWAF's own security posture

Checks how CatWAF itself is deployed, not the traffic it filters: the API's
bind address, the scope of Caddy's admin API, whether the Docker socket is
mounted, container privileges, secret file permissions and the strength of
the configured JWT secret.

${c('Usage:', C.bold)}
  catwaf security-test              Run every check and print a summary
  catwaf security-test --json       Machine-readable output

Findings are graded CRITICAL / HIGH / MEDIUM / LOW. The command exits non-zero
when anything CRITICAL or HIGH is outstanding, so it works in CI.
`,

  version: `
${c('catwaf version', C.bold, C.cyan)} — print the installed version

${c('Usage:', C.bold)}
  catwaf version                    Print the version and exit
  catwaf --version                  Same thing

Prints the version on its own line with no decoration, so it is safe to
capture in a script.
`,

  edition: `
${c('catwaf edition', C.bold, C.cyan)} — print the installed edition

${c('Usage:', C.bold)}
  catwaf edition                    Prints "lite" or "full"

${c('lite', C.bold)}  Caddy + Coraza + CRS, the catwaf CLI and the event
      database. No HTTP API, no dashboard, no CatAI.
${c('full', C.bold)}  Everything above plus the API, the built dashboard,
      CatAI and the Docker tooling.

The edition comes from CATWAF_EDITION in .env, written by
\`catwaf setup --lite|--full\`. With it unset, CatWAF infers the edition from
whether a built dashboard is present. Run \`catwaf setup --full\` to upgrade a
Lite install in place — existing configuration and data are preserved.
`,

  uninstall: `
${c('catwaf uninstall', C.bold)} — remove CatWAF

Stops CatWAF, removes its systemd unit and the CLI shim, and removes the
WAF block from your Caddyfile. Asks before touching your data, and never
deletes backups or unrelated files.

${c('Usage:', C.bold)} catwaf uninstall [--yes] [--purge-data]

  --yes              Do not prompt for confirmation
  --purge-data       Also delete the database and logs (asks unless --yes)
`,

  settings: `
${c('catwaf settings', C.bold, C.cyan)} — show or change any settings group

Every switch the dashboard exposes is reachable here, from the same schema,
with the same validation. A change is written, rendered into the Caddyfile,
validated by Caddy and only then applied — if the result would not load, the
previous configuration is kept.

${c('Usage:', C.bold)}
  catwaf settings                          List every group
  catwaf settings <group>                  Show one group's current values
  catwaf settings <group> --verbose        …with the help text for each field
  catwaf settings <group> field=value ...  Change one or more fields
  catwaf settings <group> --preview f=v    Show the Caddyfile diff, apply nothing
  catwaf settings <group> --reset          Restore this group's defaults

${c('Values', C.bold)}
  Switches take true/false (also yes/no, on/off, 1/0).
  Lists take a comma- or space-separated string: ${c('methods=GET,POST,HEAD', C.dim)}
  Fields holding structured rows are refused here — use the dashboard or a
  template, so a half-expressed row cannot be written.

${c('Examples', C.bold)}
  catwaf settings access reject_unknown_host=true
  catwaf settings challenge --preview mode=suspicious
  catwaf settings backups destination=/var/backups/catwaf enabled=true
`,

  bans: `
${c('catwaf bans', C.bold, C.cyan)} — addresses CatWAF is currently refusing

Shows the unified ban store: behavioural banning, DNSBL hits, the challenge
gate, community lists and the threat feed all write here. Your manual IP
blocklist is separate and is never changed by these commands.

${c('Usage:', C.bold)}
  catwaf bans [list]                       Show active bans
  catwaf bans list --source bad_behavior   Only bans from one source
  catwaf bans list --include-expired       Include bans that have lapsed
  catwaf bans add <ip|cidr> [--minutes N]  Ban by hand (omit --minutes = forever)
  catwaf bans add <ip> --reason "..."      With a note
  catwaf bans lift <ip|cidr>               Unban
  catwaf bans clear [--yes]                Lift every automatic ban
`,

  template: `
${c('catwaf template', C.bold, C.cyan)} — save and apply whole configurations

A template is a set of settings captured together. Applying one rewrites
several groups at once, so ${c('apply', C.cyan)} always prints the diff and asks
before doing anything.

${c('Usage:', C.bold)}
  catwaf template [list]             Built-in and saved templates
  catwaf template show <id>          Print a template as JSON
  catwaf template save "<name>"      Capture the current configuration
  catwaf template apply <id>         Show the diff, then apply on confirmation
  catwaf template apply <id> --dry-run   Show the diff and stop
  catwaf template remove <id>        Delete a saved template
`,

  report: `
${c('catwaf report', C.bold, C.cyan)} — export activity over a date range

${c('Usage:', C.bold)}
  catwaf report --from 2026-01-01 --to 2026-02-01 [--format csv]
  catwaf report --format html --out /tmp/january.html
  catwaf report --format json

${c('Formats', C.bold)}
  csv          Summary totals, categories, top addresses (default)
  events-csv   One row per logged request in the range
  html         Printable report
  json         The whole report as structured data

Without --out the report is written to stdout, so it pipes.
`,

  jobs: `
${c('catwaf jobs', C.bold, C.cyan)} — everything CatWAF runs on a timer

One scheduler drives list refreshes, ban expiry, backups, certificate checks
and telemetry. A job whose feature is switched off is listed but never
scheduled, which makes this the answer to "is that actually running?".

${c('Usage:', C.bold)}
  catwaf jobs [list]                 Show every job, its interval and last run
  catwaf jobs run <name>             Run one now, regardless of its schedule
`,

  backup: `
${c('catwaf backup', C.bold, C.cyan)} — configuration and history snapshots

${c('Usage:', C.bold)}
  catwaf backup [list]               Show stored backups
  catwaf backup now                  Write one now
  catwaf backup now --dry-run        Show what would be written
  catwaf backup verify               Check the destination is writable

Set the destination first: ${c('catwaf settings backups destination=/var/backups/catwaf', C.dim)}
`,

  cache: `
${c('catwaf cache', C.bold, C.cyan)} — what CatWAF is holding on to

Every namespace here is rebuildable, so clearing one is safe. The cost is
that the next request needing that data pays for the lookup again.

${c('Usage:', C.bold)}
  catwaf cache [list]                Namespaces, entry counts and sizes
  catwaf cache clear <namespace>     Empty one ("all" empties every namespace)
  catwaf cache refresh <namespace>   Rebuild one now
`,

  '2fa': `
${c('catwaf 2fa', C.bold, C.cyan)} — two-factor login for an admin account

Enrollment is two steps on purpose: nothing is enforced until a working code
proves the authenticator app is set up, because enrolling without that check
is how people lock themselves out.

${c('Usage:', C.bold)}
  catwaf 2fa [status] [--user <u>]   Whether it is enabled, and codes remaining
  catwaf 2fa enroll --user <u>       Generate a secret and otpauth:// URI
  catwaf 2fa confirm <code> --user <u>   Prove it works; prints recovery codes
  catwaf 2fa disable --user <u>      Turn it off (asks unless --yes)
  catwaf 2fa codes --user <u>        New recovery codes; the old set stops working

--user may be omitted when there is exactly one admin account.
`,
}

function printHelp(topic) {
  const key = topic && HELP[topic] ? topic : 'main'
  console.log(HELP[key])
  if (topic && !HELP[topic]) console.log(c(`No help topic for "${topic}".`, C.yellow))
}

async function confirm(question, defaultYes = false) {
  if (!process.stdin.isTTY) return defaultYes
  const readline = require('readline')
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
  const answer = await new Promise(resolve => {
    rl.question(`${question} [${defaultYes ? 'Y/n' : 'y/N'}] `, a => { rl.close(); resolve(a.trim()) })
  })
  if (!answer) return defaultYes
  return /^y(es)?$/i.test(answer)
}

function ext() {
  require(path.join(PROJECT_ROOT, 'backend', 'services', 'env.js')).load()
  return require(path.join(PROJECT_ROOT, 'src', 'tui', 'commands.js'))
}

function kv2(k, v) {
  console.log('  ' + k.padEnd(20) + String(v))
}

async function cmdDoctor(flags) {
  const doctor = require(path.join(PROJECT_ROOT, 'src', 'tui', 'doctor.js'))
  return doctor.run({ json: !!flags.json, verbose: !!(flags.verbose || flags.v) })
}

async function cmdStatus() {
  const single = require(path.join(PROJECT_ROOT, 'src', 'tui', 'cliCommands.js'))
  await single.status()
  return 0
}

async function cmdSetup(flags) {
  const setup = require(path.join(PROJECT_ROOT, 'src', 'tui', 'setup.js'))
  const code = await setup.run(flags)
  return typeof code === 'number' ? code : 0
}

async function cmdStart(flags = {}) {
  const edition = editionSvc()
  const svc = require(path.join(PROJECT_ROOT, 'src', 'tui', 'service.js'))

  if (edition.isLite()) {
    const r = svc.startWaf()
    if (r.alreadyRunning) {
      console.log(`${c('•', C.yellow)} ${r.message}`)
      return 0
    }
    if (!r.ok) {
      console.error(`${c('✗', C.red)} Could not start the WAF: ${r.error}`)
      return r.code === 'NO_CADDY' ? EXIT.MISSING_DEPENDENCY : EXIT.FAILURE
    }
    console.log(`${c('✓', C.green)} CatWAF Lite started — WAF active via ${r.manager}${r.pid ? c(` (pid ${r.pid})`, C.dim) : ''}`)
    console.log(c('  No API server or dashboard in Lite. Use `catwaf audit` / `catwaf status`.', C.dim))
    return await autoProtectAfterStart(flags)
  }

  const r = svc.start()
  if (r.alreadyRunning) {
    console.log(`${c('•', C.yellow)} ${r.message}${r.pid ? c(` (pid ${r.pid})`, C.dim) : ''}`)
    console.log(c(`  Dashboard: ${svc.dashboardUrl()}`, C.dim))
    // Still re-run protection: containers may have been recreated, moved
    // network, or disappeared since CatWAF was started. This is idempotent.
    return await autoProtectAfterStart(flags)
  }
  if (!r.ok) {
    console.error(`${c('✗', C.red)} Could not start CatWAF: ${r.error}`)
    return EXIT.FAILURE
  }

  // Spawning is not starting. Wait for the API to actually answer before
  // telling anyone it is up — otherwise the next thing they see is the
  // dashboard failing to connect, with nothing to explain why.
  const ready = await svc.waitUntilReady(20000, { pid: r.pid })
  if (!ready.ok) {
    console.error(`${c('✗', C.red)} CatWAF was started but its API is not answering.`)
    console.error(c(`  ${ready.error}`, C.yellow))
    if (ready.log) {
      console.error(c('\n  Last lines of the CatWAF log:', C.dim))
      for (const line of ready.log.split('\n')) console.error(c(`    ${line}`, C.dim))
    }
    console.error(c(`\n  Full log: ${svc.logFile()}`, C.dim))
    console.error(c('  Common causes: the port is already in use, the database directory is not', C.dim))
    console.error(c('  writable, or JWT_SECRET is missing. `catwaf doctor` checks all three.', C.dim))
    return EXIT.FAILURE
  }

  console.log(`${c('✓', C.green)} CatWAF started via ${r.manager}${r.pid ? c(` (pid ${r.pid})`, C.dim) : ''}`)
  console.log(`  Dashboard: ${c(ready.url, C.cyan)}`)
  if (r.logFile) console.log(c(`  Logs: ${r.logFile}`, C.dim))
  return await autoProtectAfterStart(flags)
}

// `catwaf start` is the "put my website behind CatWAF" command: after the
// service is up it discovers running applications and actually places the
// WAF in front of them, then proves it with real traffic. Opt out with
// --no-auto. Never reports a site as protected on the strength of a
// generated config alone.
async function autoProtectAfterStart(flags) {
  if (flags['no-auto']) {
    console.log(c('  Auto-protection skipped (--no-auto). Run `catwaf auto` to protect discovered apps.', C.dim))
    return 0
  }
  try {
    return await ext().cmdStartProtect(flags)
  } catch (e) {
    console.error(c(`  Auto-protection could not run: ${e.message}`, C.yellow))
    console.error(c('  CatWAF itself is running. Run `catwaf auto` to retry protection.', C.dim))
    return 0
  }
}

async function cmdStop() {
  const svc = require(path.join(PROJECT_ROOT, 'src', 'tui', 'service.js'))
  const r = await svc.stop()
  if (r.alreadyStopped) { console.log(`${c('•', C.yellow)} ${r.message}`); return 0 }
  if (!r.ok) { console.error(`${c('✗', C.red)} Could not stop CatWAF: ${r.error}`); return 1 }
  console.log(`${c('✓', C.green)} CatWAF stopped.`)
  return 0
}

async function cmdRestart() {
  const svc = require(path.join(PROJECT_ROOT, 'src', 'tui', 'service.js'))
  const r = await svc.restart()
  if (!r.ok) { console.error(`${c('✗', C.red)} Restart failed during ${r.phase}: ${r.error}`); return 1 }

  // Same reason as `catwaf start`: a restart that spawns and immediately dies
  // must not be reported as a restart that worked.
  const ready = await svc.waitUntilReady(20000, { pid: r.pid })
  if (!ready.ok) {
    console.error(`${c('✗', C.red)} CatWAF restarted but its API is not answering.`)
    console.error(c(`  ${ready.error}`, C.yellow))
    if (ready.log) for (const line of ready.log.split('\n')) console.error(c(`    ${line}`, C.dim))
    return 1
  }
  console.log(`${c('✓', C.green)} CatWAF restarted via ${r.manager}${r.pid ? c(` (pid ${r.pid})`, C.dim) : ''}`)
  console.log(`  Dashboard: ${c(ready.url, C.cyan)}`)
  return 0
}

async function cmdLogs(flags) {
  const svc = require(path.join(PROJECT_ROOT, 'src', 'tui', 'service.js'))
  const lines = Number(flags.lines || flags.n || 50)
  const follow = !!(flags.follow || flags.f)
  const plan = svc.logs({ lines, follow })

  if (plan.mode === 'journalctl') {
    const { spawn } = require('child_process')
    const p = spawn(plan.command, plan.args, { stdio: 'inherit' })
    return await new Promise(resolve => p.on('exit', code => resolve(code ?? 0)))
  }

  if (!fs.existsSync(plan.file)) {
    console.log(c(`No log file yet at ${plan.file}`, C.yellow))
    console.log(c('CatWAF writes there when started with `catwaf start` outside systemd.', C.dim))
    return 0
  }
  const body = fs.readFileSync(plan.file, 'utf8').split('\n')
  console.log(body.slice(-lines).join('\n'))
  if (follow) {
    console.log(c(`\n(following ${plan.file} — ctrl+c to stop)`, C.dim))
    const { spawn } = require('child_process')
    const p = spawn('tail', ['-f', plan.file], { stdio: 'inherit' })
    return await new Promise(resolve => p.on('exit', code => resolve(code ?? 0)))
  }
  return 0
}

async function cmdConfig(flags) {
  require(path.join(PROJECT_ROOT, 'backend', 'services', 'env.js')).load()
  const caddySvc = require(path.join(PROJECT_ROOT, 'backend', 'services', 'caddy.js'))
  const dbSvc = require(path.join(PROJECT_ROOT, 'backend', 'services', 'db.js'))
  const state = require(path.join(PROJECT_ROOT, 'backend', 'services', 'state.js'))
  const svc = require(path.join(PROJECT_ROOT, 'src', 'tui', 'service.js'))

  const cfg = {
    version: pkg.version,
    project_root: PROJECT_ROOT,
    api: { host: process.env.HOST || '127.0.0.1', port: Number(process.env.PORT || 8000) },
    domain: process.env.DOMAIN || null,
    cors_origin: process.env.CORS_ORIGIN || null,
    caddyfile: { path: caddySvc.CADDYFILE_PATH, source: caddySvc.CADDYFILE_SOURCE, exists: fs.existsSync(caddySvc.CADDYFILE_PATH) },
    caddy_admin_url: caddySvc.CADDY_ADMIN_URL,
    audit_log: caddySvc.AUDIT_LOG_PATH,
    database: dbSvc.DB_PATH,
    dashboard_built: fs.existsSync(path.join(PROJECT_ROOT, 'frontend', 'dist', 'index.html')),
    service: svc.status(),
    waf: {
      engine: state.WAF.engine,
      paranoia_level: state.WAF.paranoia_level,
      inbound_anomaly_threshold: state.WAF.inbound_anomaly_threshold,
      audit_log_enabled: !!state.WAF.audit_log,
      retention_days: state.WAF.retention_days,
      blocked_countries: state.WAF.geo_blocking.length,
      blocked_ips: state.WAF.ip_blacklist.length,
      allowed_ips: state.WAF.ip_whitelist.length,
    },
    catai: { enabled: process.env.CATAI_ENABLED === 'true', model: process.env.CATAI_MODEL || 'qwen3:1.7b' },
    secrets_set: {
      JWT_SECRET: !!process.env.JWT_SECRET,
      CLOUDFLARE_API_TOKEN: !!process.env.CLOUDFLARE_API_TOKEN,
    },
  }

  if (flags.json) { console.log(JSON.stringify(cfg, null, 2)); return 0 }

  console.log('\n' + c('CatWAF configuration', C.bold, C.cyan) + '\n')
  const line = (k, v) => console.log('  ' + k.padEnd(26) + c(String(v), C.cyan))
  line('version', cfg.version)
  line('project root', cfg.project_root)
  line('api', `${cfg.api.host}:${cfg.api.port}`)
  line('domain', cfg.domain || '(local only)')
  line('caddyfile', `${cfg.caddyfile.path}${cfg.caddyfile.source === 'auto-detected' ? ' (auto-detected)' : ''}`)
  line('caddy admin api', cfg.caddy_admin_url)
  line('audit log', cfg.audit_log)
  line('database', cfg.database)
  line('dashboard built', cfg.dashboard_built ? 'yes' : 'no')
  line('service', `${cfg.service.manager} — ${cfg.service.running ? 'running' : 'stopped'}`)
  console.log('\n  ' + c('WAF', C.bold))
  line('  engine', cfg.waf.engine)
  line('  paranoia level', `${cfg.waf.paranoia_level} of 4`)
  line('  anomaly threshold', cfg.waf.inbound_anomaly_threshold)
  line('  audit logging', cfg.waf.audit_log_enabled ? 'on' : 'off')
  line('  retention (days)', cfg.waf.retention_days)
  line('  blocked countries', cfg.waf.blocked_countries)
  line('  blocked ips', cfg.waf.blocked_ips)
  console.log('\n  ' + c('Secrets', C.bold) + c('  (values never printed)', C.dim))
  line('  JWT_SECRET', cfg.secrets_set.JWT_SECRET ? 'set' : 'NOT SET')
  line('  CatAI', cfg.catai.enabled ? `enabled (${cfg.catai.model})` : 'disabled')
  console.log('')
  return 0
}

async function cmdUser(positional, flags) {
  require(path.join(PROJECT_ROOT, 'backend', 'services', 'env.js')).load()
  const auth = require(path.join(PROJECT_ROOT, 'backend', 'middleware', 'auth.js'))
  const sub = positional[0]

  if (!sub || sub === 'help') { printHelp('user'); return sub ? 0 : 1 }

  if (sub === 'list' || sub === 'ls') {
    const users = auth.listUsers()
    if (!users.length) {
      console.log(c('\nNo accounts exist yet. Create one with:', C.yellow))
      console.log(c('  catwaf user add <username> --role admin\n', C.cyan))
      return 0
    }
    console.log('\n' + c('USERNAME'.padEnd(24) + 'ROLE'.padEnd(10) + 'CREATED', C.bold))
    for (const u of users) {
      console.log(u.username.padEnd(24) + u.role.padEnd(10) + c(u.created_at || '-', C.dim))
    }
    console.log('')
    return 0
  }

  const username = positional[1]

  if (sub === 'add') {
    if (!username) { console.error(c('✗ Usage: catwaf user add <username> [--role admin|viewer]', C.red)); return 1 }
    const role = flags.role || (flags.admin ? 'admin' : 'viewer')
    const password = process.env.CATWAF_USER_PASSWORD || flags.password
    if (!password || password === true) {
      console.error(c('✗ A password is required.', C.red))
      console.error(c('  Set CATWAF_USER_PASSWORD, or pass --password <p>.', C.dim))
      return 1
    }
    try {
      const u = auth.addUser({ username, password: String(password), role })
      console.log(`${c('✓', C.green)} Created ${c(u.username, C.cyan)} with role ${c(u.role, C.cyan)}`)
      return 0
    } catch (e) { console.error(`${c('✗', C.red)} ${e.message}`); return 1 }
  }

  if (sub === 'remove' || sub === 'rm' || sub === 'del') {
    if (!username) { console.error(c('✗ Usage: catwaf user remove <username>', C.red)); return 1 }
    if (!flags.yes && !(await confirm(`Remove account "${username}"?`, false))) {
      console.log('Cancelled.'); return 0
    }
    try { auth.removeUser(username); console.log(`${c('✓', C.green)} Removed ${username}`); return 0 }
    catch (e) { console.error(`${c('✗', C.red)} ${e.message}`); return 1 }
  }

  if (sub === 'passwd') {
    if (!username) { console.error(c('✗ Usage: catwaf user passwd <username> --password <p>', C.red)); return 1 }
    const password = process.env.CATWAF_USER_PASSWORD || flags.password
    if (!password || password === true) {
      console.error(c('✗ A new password is required.', C.red))
      console.error(c('  Set CATWAF_USER_PASSWORD, or pass --password <p>.', C.dim))
      return 1
    }
    try { auth.setPassword(username, String(password)); console.log(`${c('✓', C.green)} Password updated for ${username}`); return 0 }
    catch (e) { console.error(`${c('✗', C.red)} ${e.message}`); return 1 }
  }

  if (sub === 'role') {
    const role = positional[2] || flags.role
    if (!username || !role || role === true) { console.error(c('✗ Usage: catwaf user role <username> <admin|viewer>', C.red)); return 1 }
    try { const r = auth.setRole(username, String(role)); console.log(`${c('✓', C.green)} ${r.username} is now ${c(r.role, C.cyan)}`); return 0 }
    catch (e) { console.error(`${c('✗', C.red)} ${e.message}`); return 1 }
  }

  console.error(c(`✗ Unknown subcommand "${sub}".`, C.red))
  printHelp('user')
  return 1
}

async function cmdProvision(flags) {
  require(path.join(PROJECT_ROOT, 'backend', 'services', 'env.js')).load()
  const envSvc = require(path.join(PROJECT_ROOT, 'backend', 'services', 'environment.js'))
  const prov = require(path.join(PROJECT_ROOT, 'backend', 'services', 'provision.js'))

  const env = await envSvc.detect()

  console.log('\n' + c('CatWAF provisioning', C.bold, C.cyan) + '\n')
  console.log('  Detected web server : ' + c(env.primaryWebServer, C.cyan))
  if (env.controlPanel) console.log('  Control panel       : ' + c(env.controlPanel, C.yellow))
  if (env.nginx.present) console.log('  nginx               : ' + c(`present${env.nginx.running ? ', running' : ''}`, C.dim))
  if (env.apache.present) console.log('  Apache              : ' + c(`present${env.apache.running ? ', running' : ''}`, C.dim))

  const discovered = env.cpanel.detected ? env.cpanel.sites.map(s => s.domain)
    : [...new Set([...(env.nginx.domains || []), ...(env.apache.domains || [])])]
  if (discovered.length) {
    console.log('\n  ' + c('Websites discovered', C.bold))
    for (const d of discovered.slice(0, 15)) console.log('    ' + d)
    if (discovered.length > 15) console.log(c(`    …and ${discovered.length - 15} more`, C.dim))
  }

  const plan = prov.plan({
    env,
    baseDomain: typeof flags.domain === 'string' ? flags.domain : null,
    target: typeof flags.target === 'string' ? flags.target : null,
    apiPort: flags.port ? Number(flags.port) : null,
  })

  if (!plan.ok) {
    console.log('\n' + c('✗ ' + plan.error, C.red))
    console.log(c('\n  Pass a domain explicitly:  catwaf provision --domain example.com\n', C.dim))
    return 1
  }

  console.log('\n  Dashboard hostname  : ' + c(plan.dashboardHost, C.green))
  console.log('  Target              : ' + c(plan.targetLabel, C.cyan))
  console.log('  CatWAF API port     : ' + plan.apiPort)
  console.log('  Dashboard files     : ' + plan.distPath + (plan.distExists ? '' : c('  (NOT BUILT — run `npm run build`)', C.yellow)))

  if (!plan.automatable) {
    console.log('\n' + c('  Automatic configuration: NOT AVAILABLE', C.yellow))
    if (plan.unsupportedReason) console.log('\n' + plan.unsupportedReason.split('\n').map(l => '  ' + l).join('\n'))
    else console.log(c('  No writable configuration directory was found for this target.', C.dim))
    console.log('\n' + c('  Reference configuration:', C.bold))
    console.log(c('  ' + '-'.repeat(60), C.dim))
    console.log(plan.config.split('\n').map(l => '  ' + l).join('\n'))
    console.log(c('  ' + '-'.repeat(60), C.dim))
    console.log('\n  ' + plan.dnsHint)
    console.log('  ' + plan.httpsNote + '\n')
    return 0
  }

  if (!flags.apply) {
    console.log('\n  Destination         : ' + c(plan.destination, C.cyan))
    console.log('\n' + c('  Generated configuration:', C.bold))
    console.log(c('  ' + '-'.repeat(60), C.dim))
    console.log(plan.config.split('\n').map(l => '  ' + l).join('\n'))
    console.log(c('  ' + '-'.repeat(60), C.dim))
    console.log('\n  ' + plan.dnsHint)
    console.log('  ' + plan.httpsNote)
    console.log('\n' + c('  Nothing has been changed. Re-run with --apply to install it.', C.dim) + '\n')
    return 0
  }

  console.log('\n  Destination         : ' + c(plan.destination, C.cyan))
  if (!flags.yes && !(await confirm(`\nWrite this configuration to ${plan.destination}?`, false))) {
    console.log('Cancelled - nothing was changed.')
    return 0
  }

  console.log('\nBacking up configuration...')
  const result = prov.apply(plan)

  if (!result.ok) {
    console.log(`${c('✗', C.red)} ${result.error}`)
    if (result.rolledBack) {
      console.log('\n' + c('CatWAF did not activate the new configuration.', C.yellow))
      console.log(c('Previous configuration has been preserved.', C.yellow))
    }
    if (result.backup) console.log(c(`Backup: ${result.backup}`, C.dim))
    return 1
  }

  if (result.backup) console.log(`${c('✓', C.green)} Backup created ${c(result.backup, C.dim)}`)
  console.log(`${c('✓', C.green)} Configuration generated`)
  console.log(`${c('✓', C.green)} Configuration valid`)

  if (plan.target === 'nginx') {
    const link = prov.enableNginxSite(result.destination)
    if (link.linked) console.log(`${c('✓', C.green)} Site enabled ${c(link.link, C.dim)}`)
    else if (link.error) console.log(`${c('!', C.yellow)} Could not enable site: ${link.error}`)
  }

  if (result.reloaded) console.log(`${c('✓', C.green)} ${plan.targetLabel} reloaded`)
  else console.log(`${c('!', C.yellow)} ${plan.targetLabel} not reloaded: ${result.reloadError || 'unknown'} - reload it manually`)

  console.log('\n  Dashboard will be at: ' + c('http://' + plan.dashboardHost, C.green))
  console.log('  ' + plan.dnsHint)
  console.log('  ' + plan.httpsNote + '\n')
  return 0
}

async function cmdUninstall(flags) {
  require(path.join(PROJECT_ROOT, 'backend', 'services', 'env.js')).load()
  const svc = require(path.join(PROJECT_ROOT, 'src', 'tui', 'service.js'))
  const { execFileSync } = require('child_process')

  console.log('\n' + c('CatWAF uninstall', C.bold, C.cyan) + '\n')
  console.log('This will stop CatWAF, remove its service unit and CLI shim, and')
  console.log('remove CatWAF\'s block from your Caddyfile.')
  console.log(c('It will NOT delete your database, logs, or backups unless you ask.\n', C.dim))

  if (!flags.yes && !(await confirm('Continue?', false))) { console.log('Cancelled.'); return 0 }

  const done = []
  const failed = []

  try {
    const st = await svc.stop()
    done.push(st.alreadyStopped ? 'CatWAF was already stopped' : 'Stopped CatWAF')
  } catch (e) { failed.push('stop: ' + e.message) }

  if (svc.hasSystemdUnit()) {
    try {
      try { execFileSync('systemctl', ['disable', '--now', 'catwaf'], { timeout: 15000, stdio: 'ignore' }) } catch {}
      fs.unlinkSync(svc.UNIT_PATH)
      try { execFileSync('systemctl', ['daemon-reload'], { timeout: 10000, stdio: 'ignore' }) } catch {}
      done.push(`Removed systemd unit ${svc.UNIT_PATH}`)
    } catch (e) { failed.push(`systemd unit (${svc.UNIT_PATH}): ${e.message}`) }
  }

  for (const shim of ['/usr/local/bin/catwaf']) {
    try {
      if (fs.existsSync(shim)) {
        const body = fs.readFileSync(shim, 'utf8')
        if (body.includes('catwaf.js')) { fs.unlinkSync(shim); done.push(`Removed CLI shim ${shim}`) }
        else failed.push(`${shim} does not look like CatWAF's shim - left alone`)
      }
    } catch (e) { failed.push(`${shim}: ${e.message}`) }
  }

  try {
    const caddySvc = require(path.join(PROJECT_ROOT, 'backend', 'services', 'caddy.js'))
    const p = caddySvc.CADDYFILE_PATH
    if (fs.existsSync(p)) {
      const body = fs.readFileSync(p, 'utf8')
      const START = '# @@CATWAF_WAF_START@@'
      const END = '# @@CATWAF_WAF_END@@'
      if (body.includes(START) && body.includes(END)) {
        const backup = `${p}.catwaf-uninstall-${new Date().toISOString().replace(/[:.]/g, '-')}`
        fs.copyFileSync(p, backup)
        const s = body.indexOf(START)
        const e = body.indexOf(END)
        const next = body.slice(0, s) + body.slice(e + END.length).replace(/^\n/, '')
        fs.writeFileSync(p, next, 'utf8')
        done.push(`Removed WAF block from ${p} (backup: ${backup})`)
      } else {
        done.push(`No CatWAF block found in ${p} - left alone`)
      }
    }
  } catch (e) { failed.push('Caddyfile cleanup: ' + e.message) }

  const dataPath = process.env.DB_DIR || path.join(PROJECT_ROOT, 'data')
  if (flags['purge-data']) {
    const sure = flags.yes || await confirm(`Permanently delete all CatWAF data in ${dataPath}?`, false)
    if (sure) {
      try { fs.rmSync(dataPath, { recursive: true, force: true }); done.push(`Deleted data directory ${dataPath}`) }
      catch (e) { failed.push('data directory: ' + e.message) }
    } else {
      done.push(`Kept data directory ${dataPath}`)
    }
  } else {
    done.push(`Kept data directory ${dataPath}`)
  }

  console.log('')
  for (const d of done) console.log(`${c('✓', C.green)} ${d}`)
  for (const f of failed) console.log(`${c('!', C.yellow)} ${f}`)

  console.log('')
  if (failed.length) {
    console.log(c('Uninstall finished with warnings - see above.', C.yellow))
    console.log(c(`The CatWAF source directory itself (${PROJECT_ROOT}) was not removed.`, C.dim) + '\n')
    return 1
  }
  console.log(c('CatWAF uninstalled.', C.green))
  console.log(c(`The source directory (${PROJECT_ROOT}) was not removed - delete it manually if you want it gone.`, C.dim) + '\n')
  return 0
}

const LEGACY = {
  '--setup': 'setup', '--status': 'status', '--doctor': 'doctor',
  '--version': 'version', '-v': 'version', '--help': 'help', '-h': 'help',
}

const EXIT = {
  OK: 0,
  FAILURE: 1,
  USAGE: 2,
  MISSING_DEPENDENCY: 3,
  PERMISSION: 4,
  WRONG_EDITION: 5,
}

function editionSvc() {
  require(path.join(PROJECT_ROOT, 'backend', 'services', 'env.js')).load()
  return require(path.join(PROJECT_ROOT, 'backend', 'services', 'edition.js'))
}

const FULL_ONLY_COMMANDS = { docker: 'docker' }

function refuseIfLite(command) {
  const capability = FULL_ONLY_COMMANDS[command]
  if (!capability) return null
  const blocked = editionSvc().checkCapability(capability)
  if (!blocked) return null
  console.error(c(blocked.message, C.yellow))
  return EXIT.WRONG_EDITION
}

async function cmdDocker(rest, flags) {
  const docker = require(path.join(PROJECT_ROOT, 'src', 'tui', 'docker.js'))
  return await docker.run(rest, flags)
}

async function main() {
  require(path.join(PROJECT_ROOT, 'backend', 'services', 'env.js')).load()

  const { flags, positional } = parseArgs(argv)
  let command = positional[0]

  if (argv[0] && LEGACY[argv[0]]) command = LEGACY[argv[0]]

  if (!command) { printHelp('main'); return 0 }

  const rest = positional.slice(1)

  if (flags.help && command !== 'help') { printHelp(command); return 0 }

  const refused = refuseIfLite(command)
  if (refused !== null) return refused

  // Recover an interrupted configuration activation before any CLI command
  // can mutate state. Read-only help/version do not need a database.
  if (!['help', 'version', 'edition', 'stop', 'logs'].includes(command)) {
    require(path.join(PROJECT_ROOT, 'backend', 'services', 'configTx.js')).recover()
  }
  if (['start', 'restart', 'setup', 'install', 'auto'].includes(command)) {
    require(path.join(PROJECT_ROOT, 'backend', 'services', 'configTx.js')).assertReady()
  }

  switch (command) {
    case 'help': printHelp(rest[0]); return 0
    case 'version': console.log(pkg.version); return 0
    case 'edition': console.log(editionSvc().current()); return 0
    case 'docker': return await cmdDocker(rest, flags)
    case 'doctor': return await cmdDoctor(flags)
    case 'status': return await cmdStatus()
    case 'setup':
    case 'install': return await cmdSetup(flags)
    case 'start': return await cmdStart(flags)
    case 'stop': return await cmdStop()
    case 'restart': return await cmdRestart()
    case 'logs': return await cmdLogs(flags)
    case 'config':
      if (rest.length) {
        require(path.join(PROJECT_ROOT, 'backend', 'services', 'env.js')).load()
        return await ext().cmdConfigSub(rest, flags, cmdConfig)
      }
      return await cmdConfig(flags)
    case 'user':
    case 'users': return await cmdUser(rest, flags)
    case 'explain': return await ext().cmdExplain(rest, flags)
    case 'simulate': return await ext().cmdSimulate(flags)
    case 'replay': return await ext().cmdReplay(rest, flags)
    case 'rules': return await ext().cmdRules(rest, flags)
    case 'audit': return await ext().cmdAudit(flags)
    case 'mode': return await ext().cmdMode(rest, flags)
    case 'paranoia': return await ext().cmdParanoia(rest, flags)
    case 'health': return await ext().cmdHealth(flags)
    case 'security-test': return await ext().cmdSecurityTest(flags)
    case 'diff': return await ext().cmdDiff(flags)
    case 'settings': return await ext().cmdSettings(rest, flags)
    case 'bans':
    case 'ban': return await ext().cmdBans(rest, flags)
    case 'template':
    case 'templates': return await ext().cmdTemplate(rest, flags)
    case 'report':
    case 'reports': return await ext().cmdReport(rest, flags)
    case 'jobs':
    case 'job': return await ext().cmdJobs(rest, flags)
    case 'backup':
    case 'backups': return await ext().cmdBackup(rest, flags)
    case 'update': {
      const uc = require(path.join(PROJECT_ROOT, 'backend', 'services', 'updateCheck'))
      const r = await uc.check({ force: !!flags.force || !!flags.check })
      console.log(c('CatWAF update check', C.bold))
      kv2('Running version', r.current)
      kv2('Latest release', r.latestVersion || (r.noReleases ? c('none published yet', C.dim) : c('unknown', C.yellow)))
      if (r.error) console.log('  ' + c('Check failed: ' + r.error, C.yellow))
      if (r.latestVersion && !r.upToDate) {
        for (const line of uc.upgradeInstructions(r)) console.log('  ' + c(line, C.cyan))
      } else if (!r.noReleases && !r.error) {
        console.log('  ' + c('✓ You are up to date.', C.green))
      }
      if (r.noReleases) {
        console.log('  ' + c('No GitHub releases exist yet for ' + uc.REPO + '.', C.dim))
        console.log('  ' + c('Publish one (tag v<version>) and this check starts working.', C.dim))
      }
      return 0
    }
    case 'kernel-bans': {
      const kb = require(path.join(PROJECT_ROOT, 'backend', 'services', 'kernelBans'))
      if (rest[0] === 'print-rules' || flags['print-rules']) {
        console.log(kb.printRules())
        return 0
      }
      const st = kb.status()
      console.log(c('Kernel-level drops (nftables)', C.bold))
      console.log('  Enabled (settings): ' + (st.enabled ? c('yes', C.green) : 'no'))
      console.log('  Enabled (.env gate): ' + (st.env_enabled ? c('yes', C.green) : 'no'))
      console.log('  Preflight: ' + (st.preflight.ok ? c('ok', C.green) : c(st.preflight.problems.join('; '), C.red)))
      if (!st.preflight.ok) {
        console.log('\n  ' + c('Firewall rule to add once (as root):', C.dim))
        console.log('  ' + c('$ catwaf kernel-bans print-rules | sudo nft -f -', C.cyan))
      }
      return 0
    }
    case 'cache':
    case 'caches': return await ext().cmdCache(rest, flags)
    case '2fa': return await ext().cmdTwoFactor(rest, flags)
    case 'provision': return await cmdProvision(flags)
    case 'auto': return await ext().cmdAuto(flags)
    case 'uninstall': return await cmdUninstall(flags)
    default:
      console.error(c(`Unknown command: ${command}`, C.red))
      printHelp('main')
      return EXIT.USAGE
  }
}

main()
  .then(code => process.exit(typeof code === 'number' ? code : 0))
  .catch(err => {
    console.error(c('\nCatWAF CLI error: ' + err.message, C.red))
    if (process.env.CATWAF_DEBUG) console.error(err.stack)
    process.exit(1)
  })
