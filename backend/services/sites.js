// Host registry shared by manually configured sites and managed routes.
// Both Free editions can raise their explicit site capacity.

const settings = require('./settings')
const edition = require('./edition')

function normalizeHost(value) {
  return String(value || '').trim().toLowerCase().replace(/\.$/, '')
}

function fromEnvironment() {
  const out = []
  const domain = normalizeHost(process.env.DOMAIN)
  if (domain) {
    out.push(domain)
    if (!domain.startsWith('www.')) out.push(`www.${domain}`)
  }
  for (const extra of String(process.env.CATWAF_EXTRA_HOSTS || '').split(',')) {
    const host = normalizeHost(extra)
    if (host) out.push(host)
  }
  return out
}

// Everything CatWAF is willing to serve, in precedence order: explicitly
// configured hosts first, then the site registry, then the environment.
function knownHosts() {
  const access = settings.get('access')
  const site = settings.get('sites')
  const hosts = [
    ...access.known_hosts,
    site.primary_host,
    ...site.aliases,
    ...fromEnvironment(),
    ...require('./managedRoutes').allRoutes().map(r => r.host),
  ].map(normalizeHost).filter(Boolean)
  return [...new Set(hosts)]
}

function primaryHost() {
  const site = settings.get('sites')
  if (site.primary_host) return normalizeHost(site.primary_host)
  return knownHosts()[0] || null
}

// Explicit operator-configured resource budget.
function capacity() {
  const configured = settings.get('sites').max_sites
  return { max: configured, edition: edition.current() }
}

function canAddSite(currentCount) {
  const { max } = capacity()
  if (currentCount < max) return { ok: true }
  return {
    ok: false,
    code: 'SITE_LIMIT',
    message: 'The configured site capacity has been reached. Increase Maximum protected sites before adding another site.',
  }
}

function describe() {
  const hosts = knownHosts()
  return {
    primary: primaryHost(),
    hosts,
    aliases: settings.get('sites').aliases,
    capacity: capacity(),
    source: settings.get('sites').primary_host
      ? 'configured'
      : (process.env.DOMAIN ? 'environment' : 'unset'),
  }
}

module.exports = { knownHosts, primaryHost, capacity, canAddSite, describe, normalizeHost }
