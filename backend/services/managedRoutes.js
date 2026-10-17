// Docker and Kubernetes own separate route sets. Policy and routes are published
// through the same SQLite/Caddy transaction as manual configuration changes.
const db = require('./db')
const settings = require('./settings')
const { q, indent, block, withoutAssetWrites } = require('./render/util')
const KEY = 'managed_routes'
const START = '# @@CATWAF_MANAGED_ROUTES_START@@'
const END = '# @@CATWAF_MANAGED_ROUTES_END@@'
const SOURCES = ['docker', 'kubernetes']

function hostname(value) {
  return typeof value === 'string' && value.length <= 253 && /^(\*\.)?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(value) &&
    value.replace(/^\*\./, '').split('.').every(x => x.length > 0 && x.length <= 63 && !x.startsWith('-') && !x.endsWith('-'))
}
function validate(route) {
  if (!route || typeof route !== 'object' || !hostname(route.host)) throw new Error('Managed route needs a valid hostname')
  if (typeof route.id !== 'string' || !/^[A-Za-z0-9_./:-]{1,256}$/.test(route.id)) throw new Error('Invalid managed route identity')
  if (!['Exact', 'Prefix'].includes(route.pathType) || typeof route.path !== 'string' || route.path.length > 512 || !/^\/[A-Za-z0-9/._~!$&()+,;=:@%-]*$/.test(route.path)) throw new Error('Invalid managed route path')
  if (typeof route.upstream !== 'string') throw new Error('Invalid managed upstream')
  const address = route.upstream.replace(/^(https?|h2c):\/\//, '')
  require('./proxy/generator').assertSafeUpstream(address)
  require('./proxy/generator').assertSafePort(address.split(':').pop())
  if (!['off', 'auto', 'secret'].includes(route.tls || 'off')) throw new Error('Invalid managed TLS mode')
  if (route.tls === 'secret' && !/^[a-f0-9]{64}$/.test(route.tlsRef || '')) throw new Error('Invalid TLS reference')
  const policy = route.policy || { patches: {}, waf: {} }
  if (typeof policy !== 'object' || Array.isArray(policy) || ['patches','waf'].some(k => policy[k] !== undefined && (!policy[k] || typeof policy[k] !== 'object' || Array.isArray(policy[k])))) throw new Error('Invalid managed policy')
  for (const [group, patch] of Object.entries(policy.patches || {})) {
    if (!['access', 'headers', 'proxy'].includes(group)) throw new Error('Unsupported managed policy group')
    const checked = settings.validate(group, patch)
    if (!checked.ok) throw new Error(checked.error)
  }
  const waf = policy.waf || {}
  if (Object.keys(waf).some(k => !['paranoia_level', 'executing_paranoia_level', 'engine'].includes(k)) ||
      (waf.engine && !['On', 'Off', 'DetectionOnly'].includes(waf.engine)) ||
      ['paranoia_level', 'executing_paranoia_level'].some(k => waf[k] !== undefined && (!Number.isInteger(waf[k]) || waf[k] < 1 || waf[k] > 4))) throw new Error('Invalid managed WAF policy')
  return { id: route.id, host: route.host, path: route.pathType === 'Prefix' ? route.path.replace(/\/+$/, '') || '/' : route.path, pathType: route.pathType, upstream: route.upstream, tls: route.tls || 'off', ...(route.tlsRef ? { tlsRef: route.tlsRef } : {}), policy }
}
function read() {
  const data = db.getStateStrict(KEY)
  if (data === null) return {}
  if (typeof data !== 'object' || Array.isArray(data)) throw new Error('Invalid managed route state')
  return data
}
function allRoutes(snapshot = read()) {
  return SOURCES.flatMap(source => (snapshot[source]?.routes || []).map(r => ({ ...r, source })))
}
function render(snapshot, waf) {
  const routes = allRoutes(snapshot).map(validate)
  if (routes.length && settings.get('origin').type !== 'reverse-proxy') throw new Error('Managed routing requires the reverse-proxy origin type')
  if (routes.length > 1000) throw new Error('Managed route limit exceeded')
  const hosts = new Map()
  for (const route of routes) {
    const list = hosts.get(route.host) || []
    if (list.some(r => r.path === route.path && r.pathType === route.pathType)) throw new Error('Duplicate managed route: ' + route.host + route.path)
    if (list[0] && JSON.stringify([route.policy, route.tls, route.tlsRef]) !== JSON.stringify([list[0].policy, list[0].tls, list[0].tlsRef])) throw new Error('Conflicting policies or TLS for host ' + route.host)
    list.push(route); hosts.set(route.host, list)
  }
  if (hosts.size > settings.get('sites').max_sites) throw new Error('Managed routes exceed Protected sites / Maximum protected sites')
  const lines = [START]
  const caddy = require('./caddy')
  for (const [host, list] of [...hosts].sort(([a], [b]) => a.localeCompare(b))) {
    const first = list[0]
    const pair = first.tls === 'secret' ? SOURCES.map(s => snapshot[s]?.certificates?.[first.tlsRef]).find(Boolean) : null
    if (first.tls === 'secret' && !pair) throw new Error('Missing managed TLS certificate')
    const scoped = { get: group => ({
      ...settings.get(group), ...(first.policy.patches?.[group] || {}),
      ...(group === 'tls' && pair ? { cert_source: 'custom', custom_cert_pem: pair.cert, custom_key_pem: pair.key } : {}),
    }) }
    const siteWaf = { ...waf, ...(first.policy.waf || {}) }
    const access = scoped.get('access')
    if (access.enforce_method_allowlist) siteWaf.allowed_methods = access.allowed_methods
    const upstreams = [...new Set(list.map(r => r.upstream))]
    if (scoped.get('upload_scan').enabled && upstreams.length !== 1) throw new Error('Upload scanning currently requires one upstream per managed host')
    const ext = require('./render/site').build({ settings: scoped, waf: siteWaf, upstreams, tlsCapable: first.tls !== 'off', backend: caddy.catwafBackendAddress(), managedRoutes: true, assetPrefix: first.tlsRef ? 'ingress-' + first.tlsRef + '-' : '' })
    const relevant = ext.skipped
    if (relevant.length) throw new Error('Managed site has unapplied settings: ' + relevant.map(s => s.feature + ': ' + s.reason).join('; '))
    lines.push((first.tls === 'off' ? 'http://' : 'https://') + host + ' {')
    const scope = caddy.corazaMatcherLines(access)
    const snippet = caddy.buildCorazaSnippet(siteWaf)
    lines.push(...indent(ext.lines), ...scope.lines, scope.matcher ? snippet.replace('  coraza_waf {', `  coraza_waf ${scope.matcher} {`) : snippet)
    const ordered = list.sort((a,b) => b.path.length - a.path.length || (a.pathType === 'Exact' ? -1 : 1))
    ordered.forEach((route, i) => {
      const prefix = route.path.replace(/\/+$/, '')
      const paths = route.pathType === 'Exact' ? [route.path] : prefix ? [prefix, prefix + '/*'] : ['/*']
      lines.push('    @managed_' + i + ' path ' + paths.map(q).join(' '))
      const proxy = { ...scoped.get('proxy'), protocol: route.upstream.startsWith('https://') ? 'https' : route.upstream.startsWith('h2c://') ? 'grpc' : 'http', upstream_tls_verify: route.upstream.startsWith('https://') }
      if (proxy.websockets === 'deny') {
        lines.push('    @managed_ws_' + i + ' {', '        path ' + paths.map(q).join(' '), '        header Upgrade websocket', '    }', '    respond @managed_ws_' + i + ' 403')
      }
      const target = proxy.protocol === 'grpc' && !route.upstream.includes('://') ? 'h2c://' + route.upstream : route.upstream
      const options = require('./render/site').proxyOptions(proxy)
      const upstream = options.length ? block('reverse_proxy ' + q(target), options) : ['reverse_proxy ' + q(target)]
      lines.push(...indent(block('handle @managed_' + i, upstream)))
    })
    lines.push('    handle {', '        respond 404', '    }', '}')
  }
  lines.push(END)
  return lines.join('\n')
}
function patch(content, waf) {
  const snapshot = read()
  const a = content.indexOf(START), b = content.indexOf(END)
  if ((a < 0) !== (b < 0) || (a >= 0 && b < a)) throw new Error('Invalid managed route markers')
  if (!allRoutes(snapshot).length && a < 0) return content
  let region = render(snapshot, waf)
  const outside = a >= 0 ? content.slice(0, a) + content.slice(b + END.length) : content
  const port = outside.match(/^\s*http_port\s+(\d+)\s*$/m)?.[1] || '80'
  const catchAll = require('./caddy').topLevelBlocks(outside).some(block => block.addresses.some(address =>
    address === ':' + port || address === 'http://' || address === 'http://:' + port || address === 'http://*'))
  if (!catchAll && !settings.get('access').reject_unknown_host) region = region.replace(END, 'http:// {\n    respond 404\n}\n' + END)
  return a >= 0 ? content.slice(0,a) + region + content.slice(b + END.length) : content + '\n' + region + '\n'
}
function reconcile(source, routes, { dryRun = false, removeOrphans = true, certificates = {} } = {}) {
  if (!SOURCES.includes(source) || !Array.isArray(routes) || routes.length > 1000) throw new Error('Invalid route source or count')
  return require('./configLock').withConfigLock(() => {
    const before = read()
    const desired = routes.map(validate).sort((a,b) => a.id.localeCompare(b.id))
    const ids = new Set(desired.map(r => r.id))
    if (ids.size !== desired.length) throw new Error('Duplicate route identity')
    if (!removeOrphans) desired.push(...(before[source]?.routes || []).filter(r => !ids.has(r.id)))
    desired.sort((a,b) => a.id.localeCompare(b.id))
    const next = { ...before, [source]: { routes: desired, certificates: { ...(before[source]?.certificates || {}), ...certificates } } }
    const used = new Set(desired.map(r => r.tlsRef).filter(Boolean))
    for (const key of Object.keys(next[source].certificates)) if (!used.has(key)) delete next[source].certificates[key]
    const state = require('./state')
    withoutAssetWrites(() => render(next, state.WAF))
    const changed = JSON.stringify(before[source]) !== JSON.stringify(next[source])
    const result = { ok: true, source, dryRun, changed, routes: desired, removed: (before[source]?.routes || []).filter(r => !desired.some(d => d.id === r.id)).length }
    if (dryRun || !changed) return result
    const tx = require('./configTx').apply({ label: source + '.reconcile', mutate: () => db.setState(KEY, next) })
    return { ...result, ...tx, changed: tx.ok && changed }
  })
}
module.exports = { KEY, START, END, hostname, validate, read, allRoutes, render, patch, reconcile }
