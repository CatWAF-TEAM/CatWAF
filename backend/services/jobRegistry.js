// jobRegistry.js — every scheduled job CatWAF ships, registered in one place.
//
// jobs.js is the mechanism; this is the list. Keeping the registrations
// together (rather than each service registering itself on import) means the
// full schedule is readable at a glance, and importing a service for a
// one-off CLI command never has the side effect of scheduling work.

const jobs = require('./jobs')
const settings = require('./settings')
const logger = require('./logger')

const log = logger.child('jobs')

function registerAll() {
  // ── Ban expiry (#61) ──
  jobs.register('bans.expire', {
    label: 'Expire finished bans',
    description: 'Removes bans whose duration has elapsed so the active-bans view stays accurate.',
    intervalSec: 60,
    runOnStart: true,
    fn: () => require('./bans').purgeExpired(),
  })

  // ── Behavioural banning (#6) ──
  jobs.register('behavior.sweep', {
    label: 'Behavioural banning sweep',
    description: 'Counts bad responses per address over the rolling window and bans anything past the threshold.',
    intervalSec: 30,
    isEnabled: () => settings.get('bad_behavior').enabled,
    fn: () => require('./behavior').sweep(),
  })

  // ── Community blocklists (#10) ──
  jobs.register('lists.refresh', {
    label: 'Refresh community blocklists',
    description: 'Downloads each subscribed source, parses it and merges the entries, tagged with their source.',
    // Follows the configured refresh window, so changing it in the UI takes
    // effect without a restart.
    intervalSec: () => settings.get('community_lists').refresh_hours * 3600,
    reloadAfter: false,
    isEnabled: () => settings.get('community_lists').enabled,
    fn: () => require('./intel/lists').refreshAll(),
  })

  // ── Edge ban enforcement ──
  jobs.register('edge_bans.refresh', {
    label: 'Refresh edge ban rules',
    description: 'Renders the newest active bans into the Caddyfile so banned addresses are dropped by Caddy itself.',
    intervalSec: () => settings.get('edge_bans').refresh_seconds,
    runOnStart: true,
    reloadAfter: false,
    isEnabled: () => settings.get('edge_bans').enabled,
    fn: () => require('./edgeBans').refresh(),
  })

  // ── Kernel-level drops (opt-in) ──
  jobs.register('kernel_bans.refresh', {
    label: 'Sync kernel ban sets',
    description: 'Mirrors active bans into the catwaf_edge nftables set for drops at SYN.',
    intervalSec: 60,
    runOnStart: true,
    reloadAfter: false,
    isEnabled: () => settings.get('kernel_bans').enabled && process.env.CATWAF_KERNEL_BANS === '1',
    fn: () => require('./kernelBans').refresh(),
  })

  // ── SIEM event stream (#76) ──
  jobs.register('siem.export', {
    label: 'Export SIEM event batch',
    description: 'Appends recent requests to data/siem.jsonl and POSTs to the configured collector.',
    intervalSec: 60,
    reloadAfter: false,
    isEnabled: () => settings.get('siem').enabled,
    fn: () => require('./siemStream').poll(),
  })

  // Runtime counter flush (canary hits, alert deliveries…).
  jobs.register('counters.flush', {
    label: 'Flush runtime counters',
    description: 'Persists in-memory counters so a crash loses at most a minute of them.',
    intervalSec: 60,
    reloadAfter: false,
    fn: () => require('./counters').flush(),
  })

  // ── Update check (#77) ──
  jobs.register('update.check', {
    label: 'Check for CatWAF updates',
    description: 'Asks GitHub whether a newer release exists. Read-only — never auto-installs.',
    intervalSec: 24 * 3600,
    runOnStart: true,
    reloadAfter: false,
    fn: async () => {
      const r = await require('./updateCheck').check()
      return { latestVersion: r.latestVersion || null, upToDate: r.upToDate, error: r.error || null }
    },
  })

  // ── Alert delivery (#74) ──
  jobs.register('alerts.evaluate', {
    label: 'Evaluate alert triggers',
    description: 'Checks blocked-request volume against the spike threshold and announces engine changes.',
    intervalSec: 60,
    reloadAfter: false,
    isEnabled: () => settings.get('alert_dispatch').enabled,
    fn: async () => {
      const dispatch = require('./alertDispatch')
      const results = { spike: await dispatch.evaluateSpike(), engine: dispatch.checkEngineChange() }
      return results
    },
  })

  // ── Scheduled backups (#45) ──
  jobs.register('backups.run', {
    label: 'Scheduled backup',
    description: 'Copies configuration (and optionally the database) to the configured destination, pruning old ones.',
    intervalSec: 3600,
    isEnabled: () => settings.get('backups').enabled && !!settings.get('backups').destination,
    fn: () => {
      const cfg = settings.get('backups')
      const backups = require('./backups')
      const existing = backups.list()
      const newest = existing.backups?.[0]?.created_at
      if (newest && Date.now() - new Date(newest).getTime() < cfg.interval_hours * 3600_000) {
        return { skipped: 'not due yet', changed: false }
      }
      return backups.run()
    },
  })

  // ── Telemetry (#47) ──
  jobs.register('telemetry.send', {
    label: 'Send usage statistics',
    description: 'Only runs when telemetry is explicitly enabled and a collector endpoint is configured.',
    intervalSec: 6 * 3600,
    isEnabled: () => settings.get('telemetry').enabled && !!settings.get('telemetry').endpoint,
    fn: async () => {
      const cfg = settings.get('telemetry')
      const db = require('./db')
      const last = db.getState(require('./telemetry').LAST_SENT_KEY)
      if (last && Date.now() - new Date(last).getTime() < cfg.interval_hours * 3600_000) {
        return { skipped: 'not due yet', changed: false }
      }
      return require('./telemetry').send()
    },
  })

  // ── Shared threat network (#12) ──
  jobs.register('threat-network.submit', {
    label: 'Submit threat-network signals',
    description: 'Sends the anonymised attacker signals described in the data policy. Only runs when sharing is switched on.',
    intervalSec: 900,
    isEnabled: () => {
      const cfg = settings.get('threat_network')
      return cfg.enabled && cfg.share && !!cfg.endpoint
    },
    fn: async () => {
      const cfg = settings.get('threat_network')
      const db = require('./db')
      const network = require('./intel/network')
      const last = db.getState(`${network.CURSOR_KEY}:sent`)
      if (last && Date.now() - new Date(last).getTime() < cfg.submit_interval_min * 60_000) {
        return { skipped: 'not due yet', changed: false }
      }
      const result = await network.submit()
      db.setState(`${network.CURSOR_KEY}:sent`, new Date().toISOString())
      return result
    },
  })

  // ── Docker label autoconfiguration (#66) ──
  jobs.register('autoconf.scan', {
    label: 'Docker label scan',
    description: 'Re-reads container labels and applies the configuration they declare.',
    intervalSec: () => settings.get('autoconf').interval_sec,
    runOnStart: true,
    reloadAfter: false,
    isEnabled: () => settings.get('autoconf').enabled,
    fn: () => require('./autoconf').scan(),
  })

  jobs.register('kubernetes.reconcile', {
    label: 'Kubernetes ingress reconciliation',
    description: 'Reconciles selected Ingress resources, services and TLS secrets.',
    intervalSec: () => settings.get('kubernetes').interval_sec,
    runOnStart: true,
    reloadAfter: false,
    isEnabled: () => settings.get('kubernetes').enabled,
    fn: () => require('./kubernetes').scan(),
  })

  // ── Housekeeping ──
  jobs.register('caches.purge', {
    label: 'Purge expired cache entries',
    description: 'Drops timed-out entries from the rDNS, ASN, DNSBL and verdict caches.',
    intervalSec: 600,
    fn: () => require('./caches').purgeExpired(),
  })

  jobs.register('shared-state.sweep', {
    label: 'Sweep local counters',
    description: 'Removes expired rate-limit and attempt counters from the in-process store.',
    intervalSec: 300,
    fn: () => require('./sharedState').sweep(),
  })

  jobs.register('certs.check', {
    label: 'Certificate expiry check',
    description: 'Warns in the log when a certificate CatWAF can see is close to expiring.',
    intervalSec: 12 * 3600,
    runOnStart: true,
    fn: () => {
      const status = require('./certs').status()
      const expiring = []
      for (const cert of status.acme_storage?.certificates || []) {
        if (cert.days_remaining <= 21) expiring.push(cert)
      }
      if (status.custom?.ok && status.custom.days_remaining <= 21) {
        expiring.push({ file: 'uploaded certificate', hosts: status.custom.hosts, days_remaining: status.custom.days_remaining })
      }
      for (const cert of expiring) {
        log.warn('A certificate is close to expiry', { hosts: cert.hosts, days_remaining: cert.days_remaining })
      }
      return { checked: (status.acme_storage?.certificates || []).length, expiring: expiring.length, changed: false }
    },
  })

  return jobs.list().length
}

module.exports = { registerAll }
