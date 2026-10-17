// jobs.js — the single internal scheduler every time-based feature registers
// into (idea #44).
//
// This is infrastructure, not a feature: community blocklist refresh (#10),
// scheduled backups (#45), rDNS/DNSBL cache pruning, ban expiry, the
// autoconf scan (#66) and telemetry (#47) all register here rather than
// each growing its own timer. CatWAF is a single Node process, so a
// setInterval-based scheduler is the right shape — there is nothing to
// coordinate across.
//
// Two properties matter for correctness:
//   * Last-run timestamps persist, so a restart does not immediately re-run
//     everything that was due at some point in the past.
//   * A job that throws is recorded and rescheduled; one broken feed can
//     never take the scheduler (and therefore every other job) down.

const db = require('./db')
const settings = require('./settings')
const logger = require('./logger')

const log = logger.child('jobs')
const RUNS_KEY = 'job_runs'

const registry = new Map()
let running = false
let tickTimer = null

const TICK_MS = 15_000

function loadRuns() {
  const stored = db.getState(RUNS_KEY)
  return stored && typeof stored === 'object' ? stored : {}
}

function saveRun(name, record) {
  const runs = loadRuns()
  runs[name] = record
  db.setState(RUNS_KEY, runs)
}

function register(name, spec) {
  if (typeof name !== 'string' || !/^[a-z][a-z0-9._-]*$/.test(name)) {
    throw new Error(`Invalid job name "${name}" — use lowercase letters, digits and . _ -`)
  }
  if (typeof spec.fn !== 'function') throw new Error(`Job "${name}" needs a function to run`)
  registry.set(name, {
    name,
    label: spec.label || name,
    description: spec.description || '',
    // A function lets a job's interval follow its own setting (the
    // blocklist refresh window, the backup interval) without a restart.
    intervalSec: typeof spec.intervalSec === 'function' ? spec.intervalSec : Math.max(5, Number(spec.intervalSec) || 3600),
    // Some jobs change generated configuration (blocklist merges, autoconf);
    // those ask for a reload rather than performing one, so several jobs
    // firing in the same tick coalesce into a single Caddy reload.
    reloadAfter: !!spec.reloadAfter,
    runOnStart: !!spec.runOnStart,
    // A job whose feature is switched off stays registered but never fires,
    // so the jobs page can still show it and explain why it is idle.
    isEnabled: typeof spec.isEnabled === 'function' ? spec.isEnabled : () => true,
    fn: spec.fn,
    running: false,
  })
  return registry.get(name)
}

function intervalSecOf(job) {
  if (typeof job.intervalSec !== 'function') return job.intervalSec
  try { return Math.max(5, Number(job.intervalSec()) || 3600) } catch { return 3600 }
}

function intervalFor(job) {
  const cfg = settings.get('jobs')
  const jitter = Math.max(0, Math.min(50, cfg.jitter_percent)) / 100
  const seconds = intervalSecOf(job)
  // Jitter keeps several jobs registered with the same interval from all
  // firing in the same tick forever.
  const spread = seconds * jitter
  return (seconds + (Math.random() * 2 - 1) * spread) * 1000
}

function dueAt(job, runs) {
  const rec = runs[job.name]
  if (!rec || !rec.finished_at) return job.runOnStart ? 0 : Date.now() + intervalSecOf(job) * 1000
  return new Date(rec.finished_at).getTime() + intervalFor(job)
}

async function runJob(name, { manual = false } = {}) {
  const job = registry.get(name)
  if (!job) return { ok: false, error: `Unknown job "${name}"` }
  if (job.running) return { ok: false, error: `Job "${name}" is already running` }

  const cfg = settings.get('jobs')
  if (!manual && cfg.disabled_jobs.includes(name)) {
    return { ok: false, skipped: 'disabled' }
  }

  job.running = true
  const startedAt = new Date().toISOString()
  const t0 = Date.now()
  let record
  try {
    const result = await job.fn({ manual })
    record = {
      started_at: startedAt,
      finished_at: new Date().toISOString(),
      duration_ms: Date.now() - t0,
      ok: true,
      manual,
      result: summarizeResult(result),
    }
    if (job.reloadAfter && result && result.changed) requestReload(name)
    return { ok: true, ...record }
  } catch (e) {
    record = {
      started_at: startedAt,
      finished_at: new Date().toISOString(),
      duration_ms: Date.now() - t0,
      ok: false,
      manual,
      error: e.message,
    }
    log.error(`Job "${name}" failed`, { error: e.message })
    return { ok: false, error: e.message, ...record }
  } finally {
    job.running = false
    if (record) saveRun(name, record)
  }
}

// Results are stored in the database and shown in the UI, so only small,
// summarisable values are kept — never a whole downloaded blocklist.
function summarizeResult(result) {
  if (result == null || typeof result !== 'object') return null
  const out = {}
  for (const [k, v] of Object.entries(result)) {
    if (typeof v === 'number' || typeof v === 'boolean' || v === null) out[k] = v
    else if (typeof v === 'string') out[k] = v.slice(0, 200)
    else if (Array.isArray(v)) out[k] = v.length
  }
  return out
}

let reloadPending = new Set()
let reloadTimer = null

function requestReload(byJob) {
  reloadPending.add(byJob)
  if (reloadTimer) return
  reloadTimer = setTimeout(() => {
    const jobs = [...reloadPending]
    reloadPending = new Set()
    reloadTimer = null
    try {
      const caddySvc = require('./caddy')
      const r = caddySvc.applyToCaddy('jobs.reload', null)
      log.info('Reloaded after scheduled jobs', { jobs, reloaded: r.reloaded, error: r.error || null })
    } catch (e) {
      log.error('Reload after scheduled jobs failed', { jobs, error: e.message })
    }
  }, 2000)
  reloadTimer.unref?.()
}

async function tick() {
  if (!settings.get('jobs').enabled) return
  const runs = loadRuns()
  const now = Date.now()
  for (const job of registry.values()) {
    if (job.running) continue
    let enabled = true
    try { enabled = job.isEnabled() } catch { enabled = false }
    if (!enabled) continue
    if (now < dueAt(job, runs)) continue
    await runJob(job.name)
  }
}

function start() {
  if (running) return
  running = true
  tickTimer = setInterval(() => {
    tick().catch(e => log.error('Job tick failed', { error: e.message }))
  }, TICK_MS)
  tickTimer.unref()
  // A first pass shortly after boot, so runOnStart jobs do not wait a whole
  // tick and an overdue job catches up promptly.
  setTimeout(() => tick().catch(() => {}), 3000).unref()
}

function stop() {
  running = false
  if (tickTimer) clearInterval(tickTimer)
  tickTimer = null
}

function list() {
  const runs = loadRuns()
  const cfg = settings.get('jobs')
  return [...registry.values()].map(job => {
    let featureEnabled = true
    try { featureEnabled = job.isEnabled() } catch { featureEnabled = false }
    const rec = runs[job.name] || null
    return {
      name: job.name,
      label: job.label,
      description: job.description,
      interval_sec: intervalSecOf(job),
      reload_after: job.reloadAfter,
      running: job.running,
      feature_enabled: featureEnabled,
      disabled: cfg.disabled_jobs.includes(job.name),
      last_run: rec,
      next_run_at: featureEnabled && !cfg.disabled_jobs.includes(job.name)
        ? new Date(dueAt(job, runs)).toISOString()
        : null,
    }
  }).sort((a, b) => a.name.localeCompare(b.name))
}

function has(name) { return registry.has(name) }
function clear() { registry.clear() }

module.exports = { register, runJob, list, start, stop, tick, has, clear, requestReload, RUNS_KEY }
