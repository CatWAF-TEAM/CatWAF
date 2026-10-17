// configCommands.js — the CLI half of everything the dashboard gained: the
// settings schema, active bans, templates, reports, scheduled jobs, backups,
// caches and two-factor enrollment.
//
// These deliberately go through the same services the HTTP routes use rather
// than reimplementing anything, so `catwaf settings` and the Settings page
// cannot disagree about what a value means or whether it is valid. In
// particular every write goes through configTx, which validates the rendered
// Caddyfile and rolls back if it would not load — the CLI is not a way around
// that safety net.

const fs = require('fs')
const path = require('path')

const PROJECT_ROOT = path.join(__dirname, '..', '..')
const BACKEND = path.join(PROJECT_ROOT, 'backend')

const C = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  green: '\x1b[32m', yellow: '\x1b[33m', red: '\x1b[31m', cyan: '\x1b[36m', magenta: '\x1b[35m',
}
const useColor = process.stdout.isTTY && !process.env.NO_COLOR
const c = (s, ...codes) => (useColor ? codes.join('') + s + C.reset : s)

const req = (m) => require(path.join(BACKEND, 'services', m))

function out(obj, json) {
  if (json) { console.log(JSON.stringify(obj, null, 2)); return true }
  return false
}
function fail(msg) { console.error(`${c('✗', C.red)} ${msg}`); return 1 }
function ok(msg) { console.log(`${c('✓', C.green)} ${msg}`) }
function heading(t) { console.log('\n' + c(t, C.bold, C.cyan) + '\n') }
function kv(k, v, width = 26) {
  console.log('  ' + String(k).padEnd(width) + (v === null || v === undefined || v === '' ? c('-', C.dim) : String(v)))
}

async function confirm(question, flags) {
  if (flags.yes || flags.y) return true
  if (!process.stdin.isTTY) return false
  const readline = require('readline')
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
  const answer = await new Promise(r => rl.question(`${question} [y/N] `, a => { rl.close(); r(a.trim()) }))
  return /^y(es)?$/i.test(answer)
}

function ago(iso) {
  if (!iso) return c('never', C.dim)
  const delta = Math.round((Date.now() - new Date(iso).getTime()) / 1000)
  if (!Number.isFinite(delta)) return String(iso)
  const abs = Math.abs(delta)
  const unit = abs < 60 ? [abs, 's'] : abs < 3600 ? [Math.round(abs / 60), 'm'] : abs < 86400 ? [Math.round(abs / 3600), 'h'] : [Math.round(abs / 86400), 'd']
  return delta >= 0 ? `${unit[0]}${unit[1]} ago` : `in ${unit[0]}${unit[1]}`
}

// ─── settings ───────────────────────────────────────────────────────────

// Turns "field=value" into the type the schema expects. Getting this wrong
// silently — storing the string "false" for a boolean, say — is worse than
// refusing, so anything unparseable is an error rather than a guess.
function coerce(spec, raw, field) {
  if (!spec) return { ok: false, error: `Unknown field "${field}".` }
  switch (spec.type) {
    case 'bool': {
      if (/^(true|yes|on|1)$/i.test(raw)) return { ok: true, value: true }
      if (/^(false|no|off|0)$/i.test(raw)) return { ok: true, value: false }
      return { ok: false, error: `${field} is a switch — use true or false, not "${raw}".` }
    }
    case 'int': {
      if (!/^-?\d+$/.test(raw.trim())) return { ok: false, error: `${field} is a whole number, not "${raw}".` }
      return { ok: true, value: Number(raw.trim()) }
    }
    case 'list':
      return { ok: true, value: raw.split(/[\s,]+/).map(s => s.trim()).filter(Boolean) }
    case 'enum':
      return { ok: true, value: typeof spec.default === 'number' ? Number(raw) : raw }
    case 'records':
    case 'map':
      return {
        ok: false,
        error: `${field} holds structured rows, which the command line cannot express safely. Edit it in the dashboard, or set it with a template.`,
      }
    default:
      return { ok: true, value: raw }
  }
}

function printGroup(group, describe, values, flags) {
  const def = describe[group]
  heading(`${def.label}  ${c(`(${group})`, C.dim)}`)
  console.log('  ' + c(def.summary, C.dim) + '\n')
  for (const field of def.fields) {
    if (field.name.endsWith('_set')) continue
    const v = values[field.name]
    const shown = field.write_only
      ? (values[`${field.name}_set`] ? c('(set)', C.green) : c('(not set)', C.dim))
      : Array.isArray(v) ? (v.length ? v.join(', ') : c('(empty)', C.dim))
      : typeof v === 'object' && v !== null ? JSON.stringify(v)
      : typeof v === 'boolean' ? (v ? c('true', C.green) : c('false', C.dim))
      : v === '' || v === null ? c('(unset)', C.dim)
      : String(v)
    kv(field.name, shown, 30)
    if (flags.verbose && field.help) console.log('  ' + c('  ' + field.help, C.dim))
  }
  console.log('')
}

async function cmdSettings(positional, flags) {
  const settings = req('settings')
  const describe = settings.describe()
  const group = positional[0]

  if (!group) {
    if (out(Object.fromEntries(Object.entries(describe).map(([g, d]) => [g, d.summary])), flags.json)) return 0
    heading('Settings groups')
    for (const [g, d] of Object.entries(describe)) {
      console.log('  ' + c(g.padEnd(18), C.cyan) + d.summary)
    }
    console.log('\n  ' + c('catwaf settings <group>                    show a group', C.dim))
    console.log('  ' + c('catwaf settings <group> field=value ...    change it', C.dim))
    console.log('  ' + c('catwaf settings <group> --preview ...      show the Caddyfile diff first', C.dim))
    console.log('  ' + c('catwaf settings <group> --reset            back to defaults\n', C.dim))
    return 0
  }

  if (!settings.isGroup(group)) {
    return fail(`Unknown settings group "${group}". Run \`catwaf settings\` for the list.`)
  }

  // Only a bare --reset resets; `--reset field=value` is an assignment whose
  // token the flag parser absorbed, and is recovered below.
  if (flags.reset === true) {
    if (!(await confirm(`Reset every setting in "${group}" to its default?`, flags))) {
      console.log('Cancelled — nothing changed.')
      return 0
    }
    const configTx = req('configTx')
    const tx = configTx.apply({
      label: `settings.${group}.reset`,
      mutate: () => {
        const result = settings.reset(group)
        if (!result.ok) throw new Error(result.error)
        return { group }
      },
    })
    if (!tx.ok) return fail(tx.error)
    ok(`${group} reset to defaults${tx.reloaded ? ' and Caddy reloaded' : ''}`)
    return 0
  }

  // Assignments arrive as positionals ("field=value") or via --set. A bare
  // switch like --preview swallows the token after it during flag parsing,
  // so `--preview field=value` lands in flags.preview rather than in the
  // positionals — recover it instead of silently previewing a change the
  // operator did not ask for.
  const assignments = positional.slice(1)
  for (const key of ['set', 'preview', 'reset']) {
    if (typeof flags[key] === 'string' && flags[key].includes('=')) assignments.push(flags[key])
  }

  if (!assignments.length) {
    const values = settings.getRedacted(group)
    if (out({ group, schema: describe[group], values }, flags.json)) return 0
    printGroup(group, describe, values, flags)
    return 0
  }

  const specs = Object.fromEntries(describe[group].fields.map(f => [f.name, f]))
  const patch = {}
  for (const assignment of assignments) {
    const eq = assignment.indexOf('=')
    if (eq === -1) return fail(`"${assignment}" is not a field=value assignment.`)
    const field = assignment.slice(0, eq).trim()
    const raw = assignment.slice(eq + 1)
    const coerced = coerce(specs[field], raw, field)
    if (!coerced.ok) return fail(coerced.error)
    patch[field] = coerced.value
  }

  const check = settings.validate(group, patch)
  if (!check.ok) return fail(check.error)

  if (flags.preview) {
    const preview = req('preview')
    const result = preview.previewSettings(group, patch)
    if (!result.ok) return fail(result.error)
    if (out(result, flags.json)) return 0
    console.log(preview.toUnifiedText(result))
    for (const skipped of result.render_report?.newly_skipped || []) {
      console.log(c(`\n! ${skipped.feature} would not take effect: ${skipped.reason}`, C.yellow))
    }
    console.log(c('\nNothing was applied — drop --preview to make this change.', C.dim))
    return 0
  }

  const configTx = req('configTx')
  const tx = configTx.apply({
    label: `settings.${group}`,
    mutate: () => {
      const result = settings.set(group, patch)
      if (!result.ok) throw new Error(result.error)
      return { group, fields: Object.keys(patch) }
    },
  })
  if (!tx.ok) {
    return fail(`${tx.error}\n  ${tx.message || 'The change was not applied and the previous configuration was kept.'}`)
  }

  if (out({ ok: true, group, values: settings.getRedacted(group), reloaded: tx.reloaded }, flags.json)) return 0
  ok(`${group} updated: ${Object.keys(patch).join(', ')}`)
  if (tx.reloaded === false && tx.reloadError) {
    console.log(c(`  Caddy did not reload: ${tx.reloadError}`, C.yellow))
  }
  const report = req('caddy').lastRenderReport()
  for (const skipped of report?.skipped || []) {
    console.log(c(`  ! ${skipped.feature} is not in effect: ${skipped.reason}`, C.yellow))
  }
  return 0
}

// ─── bans ───────────────────────────────────────────────────────────────

async function cmdBans(positional, flags) {
  const bans = req('bans')
  const enforce = req('enforce')
  const action = positional[0] || 'list'

  if (action === 'list') {
    const list = bans.list({
      source: flags.source || null,
      limit: Number(flags.limit) || 200,
      includeExpired: !!flags['include-expired'],
    })
    const stats = bans.stats()
    if (out({ bans: list, stats }, flags.json)) return 0

    heading(`Active bans (${stats.total})`)
    if (!list.length) {
      console.log('  ' + c('Nothing is currently banned.', C.dim) + '\n')
      return 0
    }
    for (const ban of list) {
      const when = ban.permanent ? c('permanent', C.red) : c(`expires ${ago(ban.expires_at)}`, C.yellow)
      console.log('  ' + c(ban.target.padEnd(22), C.bold) + c(ban.source.padEnd(16), C.cyan) + when)
      console.log('    ' + c(ban.reason, C.dim))
    }
    console.log('\n  ' + c(`${stats.permanent} permanent, ${stats.temporary} temporary`, C.dim))
    console.log('  ' + c('Your manual IP blocklist is separate and is not shown here.\n', C.dim))
    return 0
  }

  if (action === 'add') {
    const target = positional[1]
    if (!target) return fail('Which address? `catwaf bans add 203.0.113.7 --minutes 60`')
    const seconds = flags.minutes === undefined ? null : Math.max(1, Math.round(Number(flags.minutes) * 60))
    if (seconds !== null && !Number.isFinite(seconds)) return fail('--minutes must be a number.')
    const result = bans.addManual({
      target,
      source: 'manual',
      seconds,
      reason: typeof flags.reason === 'string' ? flags.reason : 'Added from the command line',
      escalateRepeat: false,
    })
    if (!result.ok) return fail(result.error)
    enforce.invalidate(target)
    if (out(result, flags.json)) return 0
    ok(`${target} banned ${seconds === null ? 'permanently' : `for ${flags.minutes} minute(s)`}`)
    return 0
  }

  if (action === 'lift') {
    const target = positional[1]
    if (!target) return fail('Which address? `catwaf bans lift 203.0.113.7`')
    const result = bans.liftTarget(target, { source: flags.source || null })
    enforce.invalidate(target)
    if (out(result, flags.json)) return 0
    if (!result.removed) return fail(`${target} was not banned.`)
    ok(`${target} unbanned (${result.removed} entr${result.removed === 1 ? 'y' : 'ies'} removed)`)
    return 0
  }

  if (action === 'clear') {
    if (!(await confirm('Lift every automatic ban?', flags))) {
      console.log('Cancelled — nothing changed.')
      return 0
    }
    bans.clearAll()
    enforce.invalidate()
    ok('All automatic bans lifted. Your manual IP blocklist is unchanged.')
    return 0
  }

  return fail(`Unknown action "${action}". Use list, add, lift or clear.`)
}

// ─── templates ──────────────────────────────────────────────────────────

async function cmdTemplate(positional, flags) {
  const templates = req('templates')
  const action = positional[0] || 'list'

  if (action === 'list') {
    const list = templates.list()
    if (out({ templates: list }, flags.json)) return 0
    heading('Configuration templates')
    for (const t of list) {
      console.log('  ' + c(t.id.padEnd(22), C.cyan) + t.label + (t.built_in ? c('  (built-in)', C.dim) : ''))
      if (t.description) console.log('    ' + c(t.description, C.dim))
    }
    console.log('')
    return 0
  }

  if (action === 'show') {
    const t = templates.get(positional[1])
    if (!t) return fail(`No template named "${positional[1]}".`)
    console.log(JSON.stringify(t, null, 2))
    return 0
  }

  if (action === 'save') {
    const name = positional.slice(1).join(' ').trim()
    if (!name) return fail('Give the template a name: `catwaf template save "my setup"`')
    const result = templates.save(name, { includeWaf: flags['no-waf'] !== true, description: flags.description || '' })
    if (!result.ok) return fail(result.error)
    if (out(result, flags.json)) return 0
    ok(`Saved as "${result.template.id}"`)
    return 0
  }

  if (action === 'apply') {
    const id = positional[1]
    if (!id) return fail('Which template? `catwaf template apply hardened`')

    // Always show the diff first: applying a template rewrites several groups
    // at once, which is exactly the change worth reading before it happens.
    const dry = templates.apply(id, { dryRun: true })
    if (!dry.ok) return fail(dry.error || dry.detail)
    if (out(dry, flags.json) && flags['dry-run']) return 0

    if (!dry.changes.length) {
      console.log('Your configuration already matches this template — nothing to do.')
      return 0
    }
    heading(`"${id}" would change ${dry.changes.length} setting(s)`)
    for (const ch of dry.changes) {
      console.log('  ' + c(`${ch.group}.${ch.field}`, C.cyan))
      console.log('    ' + c(JSON.stringify(ch.from), C.red) + ' → ' + c(JSON.stringify(ch.to), C.green))
    }
    console.log('')
    if (flags['dry-run']) {
      console.log(c('Nothing was applied.\n', C.dim))
      return 0
    }
    if (!(await confirm('Apply this template?', flags))) {
      console.log('Cancelled — nothing changed.')
      return 0
    }

    const result = templates.apply(id, { dryRun: false })
    if (!result.ok) return fail(result.error || result.detail)
    ok(`Applied "${id}" — ${result.changes.length} setting(s) changed${result.reloaded ? ', Caddy reloaded' : ''}`)
    return 0
  }

  if (action === 'remove' || action === 'delete') {
    const result = templates.remove(positional[1])
    if (!result.ok) return fail(result.error)
    ok(`Removed "${positional[1]}"`)
    return 0
  }

  return fail(`Unknown action "${action}". Use list, show, save, apply or remove.`)
}

// ─── reports ────────────────────────────────────────────────────────────

async function cmdReport(positional, flags) {
  const reports = req('reports')
  const format = ['json', 'csv', 'html', 'events-csv'].includes(flags.format) ? flags.format : (flags.json ? 'json' : 'csv')
  const result = reports.generate({ from: flags.from, to: flags.to, format })
  if (!result.ok) return fail(result.error)

  if (format === 'json') {
    console.log(JSON.stringify(result.report, null, 2))
    return 0
  }

  if (flags.out) {
    const target = path.resolve(String(flags.out))
    fs.writeFileSync(target, result.body)
    ok(`Wrote ${target}`)
    return 0
  }
  process.stdout.write(result.body)
  return 0
}

// ─── jobs ───────────────────────────────────────────────────────────────

async function cmdJobs(positional, flags) {
  const jobs = req('jobs')
  // The registry is populated by the server at boot. The CLI runs in its own
  // process, so it has to register the same jobs before it can list or run
  // one — without this every job would simply be missing.
  req('jobRegistry').registerAll()
  const action = positional[0] || 'list'

  if (action === 'list') {
    const list = jobs.list()
    if (out({ jobs: list }, flags.json)) return 0
    heading('Scheduled jobs')
    for (const job of list) {
      const state = job.disabled ? c('disabled', C.dim)
        : !job.feature_enabled ? c('feature off', C.dim)
        : c('scheduled', C.green)
      console.log('  ' + c(job.name.padEnd(22), C.cyan) + state.padEnd(20) + c(`every ${job.interval_sec}s`, C.dim))
      console.log('    ' + c(job.description, C.dim))
      if (job.last_run) {
        const okMark = job.last_run.ok === false ? c('failed', C.red) : c('ok', C.green)
        console.log('    ' + c(`last run ${ago(job.last_run.at)} — ${okMark}`, C.dim) + (job.last_run.error ? c(` (${job.last_run.error})`, C.red) : ''))
      }
    }
    console.log('')
    return 0
  }

  if (action === 'run') {
    const name = positional[1]
    if (!name) return fail('Which job? `catwaf jobs run refresh-lists`')
    if (!jobs.has(name)) return fail(`No job named "${name}". Run \`catwaf jobs\` for the list.`)
    const result = await jobs.runJob(name, { manual: true })
    if (out(result, flags.json)) return result.ok ? 0 : 1
    if (!result.ok) return fail(`${name} failed: ${result.error}`)
    ok(`${name} finished`)
    return 0
  }

  return fail(`Unknown action "${action}". Use list or run.`)
}

// ─── backups ────────────────────────────────────────────────────────────

async function cmdBackup(positional, flags) {
  const backups = req('backups')
  const action = positional[0] || 'list'

  if (action === 'list') {
    const result = backups.list()
    if (out(result, flags.json)) return 0
    heading('Backups')
    if (!result.destination) {
      console.log('  ' + c('No destination set. `catwaf settings backups destination=/var/backups/catwaf`\n', C.dim))
      return 0
    }
    kv('Destination', result.destination)
    if (result.error) { console.log('  ' + c(result.error, C.red) + '\n'); return 1 }
    console.log('')
    for (const b of result.backups) {
      console.log('  ' + b.name.padEnd(40) + c(`${ago(b.created_at)}  ${(b.size_bytes / 1024).toFixed(0)} KB`, C.dim) + (b.has_database ? c('  +db', C.green) : ''))
    }
    if (!result.backups.length) console.log('  ' + c('No backups written yet.', C.dim))
    console.log('')
    return 0
  }

  if (action === 'restore') {
    const file = positional[1]
    if (!file) {
      console.error(c('Usage: catwaf backup restore <backup.json> [--db] [--allow-redacted] [--confirm-db-restore]', C.yellow))
      return 1
    }
    let result = backups.restoreFromFile(file, {
      restoreDatabase: !!flags.db,
      allowRedacted: !!flags['allow-redacted'],
    })
    if (!result.ok && result.database?.requires_stopped_services && flags['confirm-db-restore']) {
      const confirmed = backups.confirmDatabaseRestore(file)
      result = confirmed.ok
        ? { ...backups.restoreFromFile(file, { allowRedacted: !!flags['allow-redacted'] }), database: confirmed }
        : { ok: false, error: confirmed.error, restored_from: file, database: confirmed }
      if (result.ok) {
        result.database.requires_config_apply = false
        result.database.instruction = 'Database and matching configuration restored. Historical sessions were revoked. Services can now be restarted.'
      }
    }
    if (!out(result, flags.json)) {
      if (!result.ok) { console.error(c('✗ ' + (result.detail || result.error), C.red)); return 1 }
      heading('Restore complete')
      kv('From', result.restored_from)
      kv('WAF state', result.waf ? 'restored & validated' : 'unchanged')
      if (result.settings_groups?.length) kv('Settings groups', result.settings_groups.join(', '))
      kv('Caddyfile', result.caddyfile_replaced ? 'replaced from backup' : 'left untouched')
      if (result.database) console.log(c('\n  Database: ' + (result.database.error || result.database.instruction || ''), C.yellow))
    }
    return result.ok ? 0 : 1
  }

  if (action === 'now' || action === 'run') {
    const result = backups.run({ dryRun: !!flags['dry-run'], destination: flags.destination || null })
    if (out(result, flags.json)) return 0
    if (result.skipped === 'disabled') return fail('Backups are switched off. `catwaf settings backups enabled=true`')
    if (result.dryRun) { ok(`Would write ${result.would_write} (${result.bytes} bytes)`); return 0 }
    ok(`Backup written: ${result.file}${result.database ? ` (+ ${result.database})` : ''}`)
    if (result.pruned) console.log(c(`  Pruned ${result.pruned} old file(s).`, C.dim))
    return 0
  }

  if (action === 'verify') {
    const settings = req('settings')
    const result = backups.verifyDestination(flags.destination || settings.get('backups').destination)
    if (out(result, flags.json)) return result.ok ? 0 : 1
    if (!result.ok) return fail(result.error)
    ok(`${result.destination} is writable`)
    return 0
  }

  return fail(`Unknown action "${action}". Use now, list or verify.`)
}

// ─── caches ─────────────────────────────────────────────────────────────

async function cmdCache(positional, flags) {
  const caches = req('caches')
  const action = positional[0] || 'list'

  if (action === 'list') {
    const overview = caches.overview()
    if (out(overview, flags.json)) return 0
    heading(`Caches — ${overview.total_entries} entries, ${(overview.total_bytes / 1024).toFixed(0)} KB`)
    for (const ns of overview.namespaces) {
      console.log('  ' + c(ns.id.padEnd(20), C.cyan) + String(ns.entries ?? '-').padStart(8) + c(`  ${ns.label}`, C.dim))
      if (ns.error) console.log('    ' + c(ns.error, C.red))
    }
    console.log('')
    return 0
  }

  if (action === 'clear') {
    const id = positional[1]
    if (!id) return fail('Which namespace? `catwaf cache clear all`')
    const result = caches.clear(id)
    if (!result.ok) return fail(result.error)
    if (out(result, flags.json)) return 0
    ok(`Cleared ${id}`)
    return 0
  }

  if (action === 'refresh') {
    const id = positional[1]
    if (!id) return fail('Which namespace? `catwaf cache refresh community-lists`')
    const result = await caches.refresh(id)
    if (!result.ok) return fail(result.error)
    if (out(result, flags.json)) return 0
    ok(`Refreshed ${id}`)
    return 0
  }

  return fail(`Unknown action "${action}". Use list, clear or refresh.`)
}

// ─── two-factor ─────────────────────────────────────────────────────────

// --user may be omitted when the answer is unambiguous. When it is not, say
// which of the three situations applies rather than one message for all of
// them — "no such user" and "pick one of three" need different fixes.
function resolveUser(flags) {
  const auth = require(path.join(BACKEND, 'middleware', 'auth.js'))
  if (typeof flags.user === 'string') {
    const found = auth.USERS.find(u => u.username === flags.user)
    return found
      ? { ok: true, username: found.username }
      : { ok: false, error: `No account named "${flags.user}". Run \`catwaf user list\`.` }
  }
  const admins = auth.USERS.filter(u => u.role === 'admin')
  if (admins.length === 1) return { ok: true, username: admins[0].username }
  if (admins.length === 0) return { ok: false, error: 'No admin account exists yet. Run `catwaf setup` first.' }
  return {
    ok: false,
    error: `There are ${admins.length} admin accounts — say which one with --user (${admins.map(a => a.username).join(', ')}).`,
  }
}

async function cmdTwoFactor(positional, flags) {
  const totp = req('totp')
  const action = positional[0] || 'status'
  const resolved = resolveUser(flags)
  if (!resolved.ok) return fail(resolved.error)
  const username = resolved.username

  if (action === 'status') {
    const status = totp.status(username)
    if (out({ username, ...status }, flags.json)) return 0
    heading(`Two-factor authentication — ${username}`)
    kv('Enabled', status.enabled ? c('yes', C.green) : c('no', C.yellow))
    if (status.enrolled) {
      kv('Enrolled', status.enrolled_at)
      kv('Confirmed', status.confirmed_at)
      kv('Recovery codes left', status.recovery_codes_remaining)
    }
    console.log('')
    return 0
  }

  if (action === 'enroll') {
    if (totp.isEnabled(username)) return fail('Two-factor is already enabled for this account. Disable it before enrolling again.')
    const enrollment = totp.beginEnrollment(username, { account: username })
    if (out({ username, ...enrollment }, flags.json)) return 0
    heading(`Two-factor enrollment — ${username}`)
    kv('Secret', c(enrollment.secret, C.bold))
    kv('Digits / period', `${enrollment.digits} / ${enrollment.period}s`)
    console.log('\n  ' + c('Add this URI to your authenticator app:', C.dim))
    console.log('  ' + enrollment.uri)
    console.log('\n  ' + c('Nothing is enforced yet. Prove the app works first:', C.yellow))
    console.log('  ' + c(`catwaf 2fa confirm <code> --user ${username}\n`, C.cyan))
    return 0
  }

  if (action === 'confirm') {
    const code = positional[1] || flags.code
    if (!code) return fail('Enter the six-digit code: `catwaf 2fa confirm 123456`')
    const result = totp.confirmEnrollment(username, String(code))
    if (!result.ok) return fail(result.error)
    if (out(result, flags.json)) return 0
    ok(`Two-factor login is now required for ${username}`)
    console.log('\n  ' + c('Recovery codes — shown once, store them somewhere safe:', C.yellow))
    for (const rc of result.recovery_codes) console.log('    ' + c(rc, C.bold))
    console.log('')
    return 0
  }

  if (action === 'disable') {
    if (!(await confirm(`Disable two-factor authentication for ${username}?`, flags))) {
      console.log('Cancelled — nothing changed.')
      return 0
    }
    const result = totp.disable(username)
    if (!result.ok) return fail(result.error)
    ok(`Two-factor disabled for ${username}`)
    return 0
  }

  if (action === 'codes') {
    const result = totp.regenerateRecoveryCodes(username)
    if (!result.ok) return fail(result.error)
    if (out(result, flags.json)) return 0
    console.log(c('\n  New recovery codes — the previous set no longer works:\n', C.yellow))
    for (const rc of result.recovery_codes) console.log('    ' + c(rc, C.bold))
    console.log('')
    return 0
  }

  return fail(`Unknown action "${action}". Use status, enroll, confirm, disable or codes.`)
}

module.exports = {
  cmdSettings, cmdBans, cmdTemplate, cmdReport, cmdJobs, cmdBackup, cmdCache, cmdTwoFactor,
  coerce,
}
