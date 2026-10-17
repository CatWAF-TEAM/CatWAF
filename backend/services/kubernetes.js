const fs = require('fs')
const http = require('http')
const https = require('https')
const crypto = require('crypto')
const net = require('net')
const path = require('path')
const settings = require('./settings')
const managed = require('./managedRoutes')
const ACCOUNT = '/var/run/secrets/kubernetes.io/serviceaccount'
const NAME = /^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$/
let inFlight = false
let last = null

function client() {
  const server = process.env.CATWAF_K8S_API || 'https://kubernetes.default.svc'
  const base = new URL(server)
  if ((base.protocol !== 'https:' && !(base.protocol === 'http:' && process.env.CATWAF_K8S_ALLOW_HTTP === '1')) || base.username || base.password || base.pathname !== '/' || base.search || base.hash) throw new Error('Invalid Kubernetes API origin')
  return { get: path => new Promise((resolve, reject) => {
    const token = fs.readFileSync(process.env.CATWAF_K8S_TOKEN_FILE || ACCOUNT + '/token', 'utf8').trim()
    const ca = base.protocol === 'https:' ? fs.readFileSync(process.env.CATWAF_K8S_CA_FILE || ACCOUNT + '/ca.crt') : undefined
    const url = new URL(path, base)
    if (url.origin !== base.origin) return reject(new Error('Kubernetes API origin cannot change'))
    const request = (base.protocol === 'https:' ? https : http).get(url, { ca, timeout: 5000, signal: AbortSignal.timeout(5000), headers: { Authorization: 'Bearer ' + token, Accept: 'application/json' } }, response => {
      let size = 0; const chunks = []
      response.on('data', data => { size += data.length; if (size > 8 * 1024 * 1024) response.destroy(new Error('Kubernetes response exceeds 8 MiB')); else chunks.push(data) })
      response.on('error', reject)
      response.on('end', () => {
        try {
          if (response.statusCode !== 200) throw new Error('Kubernetes API returned ' + response.statusCode)
          resolve(JSON.parse(Buffer.concat(chunks).toString()))
        } catch (e) { reject(e) }
      })
    })
    request.on('timeout', () => request.destroy(new Error('Kubernetes API timed out')))
    request.on('error', reject)
  }) }
}
async function list(api, path) {
  const items = []; let cursor = ''; const seen = new Set()
  do {
    const data = await api.get(path + '?limit=500' + (cursor ? '&continue=' + encodeURIComponent(cursor) : ''))
    if (!Array.isArray(data.items)) throw new Error('Kubernetes list is incomplete')
    items.push(...data.items)
    if (items.length > 1000) throw new Error('Kubernetes resource limit exceeded')
    cursor = data.metadata?.continue || ''
    if (typeof cursor !== 'string' || cursor.length > 8192 || seen.size >= 1000) throw new Error('Invalid or excessive Kubernetes pagination')
    if (cursor && seen.has(cursor)) throw new Error('Repeated Kubernetes continuation token')
    seen.add(cursor)
  } while (cursor)
  return items
}
function resolveService(backend, services, namespace) {
  const ref = backend?.service
  if (!ref || !NAME.test(ref.name || '') || ref.name.length > 63) throw new Error('Only same-namespace Service ingress backends are supported')
  const svc = services.find(s => s.metadata?.name === ref.name && s.metadata?.namespace === namespace)
  if (!svc || svc.spec?.type === 'ExternalName' || !net.isIP(svc.spec?.clusterIP || '')) throw new Error('Ingress backend requires an existing ClusterIP Service: ' + ref.name)
  const ports = svc.spec.ports || []
  const port = ports.find(p => (p.protocol || 'TCP') === 'TCP' && (ref.port?.number !== undefined ? p.port === ref.port.number : p.name === ref.port?.name))
  if (!port || !Number.isInteger(port.port) || port.port < 1 || port.port > 65535) throw new Error('Ingress Service port does not exist: ' + ref.name)
  return (net.isIP(svc.spec.clusterIP) === 6 ? '[' + svc.spec.clusterIP + ']' : svc.spec.clusterIP) + ':' + port.port
}
function tlsPair(secret, host) {
  if (secret?.type !== 'kubernetes.io/tls') throw new Error('Expected a kubernetes.io/tls Secret')
  const values = [secret.data?.['tls.crt'], secret.data?.['tls.key']]
  if (values.some(v => typeof v !== 'string' || v.length > 512 * 1024 || !/^[A-Za-z0-9+/=\r\n]+$/.test(v))) throw new Error('Invalid TLS Secret data')
  const [cert, key] = values.map(v => Buffer.from(v, 'base64').toString('utf8'))
  const x509 = new crypto.X509Certificate(cert)
  const matched = host.startsWith('*.') ? x509.checkHost(host, { wildcards: false }) === host : x509.checkHost(host)
  if (!x509.checkPrivateKey(crypto.createPrivateKey(key)) || !matched || Date.parse(x509.validTo) <= Date.now() || Date.parse(x509.validFrom) > Date.now()) throw new Error('TLS certificate does not match its host/key or is not currently valid')
  return { cert, key }
}
function mountedTlsSecret(root, name) {
  if (!NAME.test(name) || name.length > 253) throw new Error('Invalid mounted TLS Secret name')
  const dir = path.resolve(root, name)
  // Kubelet swaps ..data atomically. Read both files from one generation;
  // resolving each file separately can mix certificates during rotation.
  const generation = fs.realpathSync(path.join(dir, '..data'))
  const relative = path.relative(dir, generation)
  if (!relative || relative === '..' || relative.startsWith('..' + path.sep) || path.isAbsolute(relative)) throw new Error('TLS Secret generation escaped its mount')
  const read = file => {
    const target = path.join(generation, file)
    const stat = fs.lstatSync(target)
    if (!stat.isFile() || stat.size > 384 * 1024) throw new Error('Invalid mounted TLS Secret file')
    return fs.readFileSync(target).toString('base64')
  }
  return { type: 'kubernetes.io/tls', data: { 'tls.crt': read('tls.crt'), 'tls.key': read('tls.key') } }
}
async function plan(api, cfg) {
  const ns = encodeURIComponent(cfg.namespace)
  const cls = await api.get('/apis/networking.k8s.io/v1/ingressclasses/' + encodeURIComponent(cfg.ingress_class))
  if (cls.spec?.controller !== cfg.controller) throw new Error('IngressClass belongs to a different controller')
  const [ingresses, services] = await Promise.all([
    list(api, '/apis/networking.k8s.io/v1/namespaces/' + ns + '/ingresses'),
    list(api, '/api/v1/namespaces/' + ns + '/services'),
  ])
  const routes = [], certificates = {}, fetched = new Map()
  for (const ingress of ingresses) {
    const annotations = ingress.metadata?.annotations || {}
    if ((ingress.spec?.ingressClassName || annotations['kubernetes.io/ingress.class']) !== cfg.ingress_class) continue
    if (ingress.metadata?.namespace !== cfg.namespace || !NAME.test(ingress.metadata?.name || '')) throw new Error('Invalid Ingress metadata')
    if (ingress.spec.defaultBackend) throw new Error('Use an explicit host and / Prefix rule instead of defaultBackend')
    if (!Array.isArray(ingress.spec.rules) || !ingress.spec.rules.length) throw new Error('Ingress needs at least one host rule')
    for (const rule of ingress.spec.rules) {
      const host = String(rule.host || '').toLowerCase()
      if (!managed.hostname(host)) throw new Error('Ingress requires an explicit valid host')
      const tls = (ingress.spec.tls || []).find(t => (t.hosts || []).includes(host))
      let tlsRef
      if (tls) {
        if (!NAME.test(tls.secretName || '') || tls.secretName.length > 253) throw new Error('Ingress TLS requires a same-namespace Secret')
        if (!fetched.has(tls.secretName)) fetched.set(tls.secretName, process.env.CATWAF_K8S_TLS_DIR
          ? mountedTlsSecret(process.env.CATWAF_K8S_TLS_DIR, tls.secretName)
          : await api.get('/api/v1/namespaces/' + ns + '/secrets/' + encodeURIComponent(tls.secretName)))
        const pair = tlsPair(fetched.get(tls.secretName), host)
        tlsRef = crypto.createHash('sha256').update(pair.cert).update(pair.key).digest('hex')
        certificates[tlsRef] = pair
      }
      if (!Array.isArray(rule.http?.paths) || !rule.http.paths.length) throw new Error('Ingress needs HTTP paths')
      for (const path of rule.http.paths) {
        if (!['Prefix', 'Exact'].includes(path.pathType)) throw new Error('Ingress pathType must be Exact or Prefix')
        const protocol = annotations['catwaf.com/backend-protocol'] || 'http'
        if (!['http', 'https', 'grpc'].includes(protocol)) throw new Error('Invalid ingress backend protocol')
        const upstream = (protocol === 'https' ? 'https://' : protocol === 'grpc' ? 'h2c://' : '') + resolveService(path.backend, services, cfg.namespace)
        const id = cfg.namespace + '/' + ingress.metadata.name + '/' + crypto.createHash('sha256').update(host + path.path + path.pathType).digest('hex').slice(0, 20)
        routes.push(managed.validate({ id, host, path: path.path, pathType: path.pathType, upstream, tls: tls ? 'secret' : 'off', ...(tlsRef ? { tlsRef } : {}) }))
      }
    }
  }
  return { routes, certificates }
}
async function scan({ dryRun = null, api = null } = {}) {
  const cfg = settings.get('kubernetes')
  if (!cfg.enabled) return { ok: true, skipped: 'disabled', changed: false }
  if (inFlight) return { ok: false, error: 'Kubernetes reconciliation is already running', changed: false }
  inFlight = true
  try {
    const desired = await plan(api || client(), cfg)
    if (JSON.stringify(cfg) !== JSON.stringify(settings.get('kubernetes'))) throw new Error('Kubernetes settings changed during discovery; retry with the current settings')
    const result = managed.reconcile('kubernetes', desired.routes, { certificates: desired.certificates, dryRun: dryRun === null ? cfg.dry_run : dryRun })
    last = { at: new Date().toISOString(), ok: result.ok, routes: desired.routes.length, error: result.error || null }
    return result
  } catch (e) {
    last = { at: new Date().toISOString(), ok: false, error: e.message }
    return { ...last, changed: false }
  } finally { inFlight = false }
}
function describe() { return { ...settings.get('kubernetes'), running: inFlight, last, routes: managed.read().kubernetes?.routes || [] } }
module.exports = { client, list, resolveService, tlsPair, mountedTlsSecret, plan, scan, describe }
