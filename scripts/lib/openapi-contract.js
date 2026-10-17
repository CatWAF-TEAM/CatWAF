const METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace']
const normalizePath = value => value.replace(/:([A-Za-z0-9_]+)(?:\(([^)]*)\))?/g, '{$1}')
// A new regex fails closed. Metrics is a documented alias; the other two
// patterns serve frontend files rather than additional fixed API paths.
const NON_API_REGEX = new Map([
  [/^\/assets\//.toString(), 'frontend assets'],
  [/^(?!\/api|\/g\/|\/healthz).*/.toString(), 'frontend SPA'],
  [/^\/[A-Za-z0-9._~/-]{1,120}$/.toString(), 'configured alias of GET /metrics'],
])
function collectRoutes(stack) {
  if (!Array.isArray(stack)) throw new Error('Express route stack is not enumerable')
  const operations = new Set(), allPaths = new Set(), nonApi = []
  function visit(layers) {
    for (const layer of layers) {
      if (layer.route) {
        const route = layer.route
        if (route.path instanceof RegExp) {
          const classification = NON_API_REGEX.get(route.path.toString())
          if (!classification || Object.keys(route.methods).some(m => m !== 'get')) throw new Error(`Unclassified RegExp route: ${route.path}`)
          nonApi.push(classification)
          continue
        }
        for (const raw of Array.isArray(route.path) ? route.path : [route.path]) {
          if (typeof raw !== 'string') throw new Error('Unsupported route path type')
          if (raw === '/' && Object.keys(route.methods).every(m => m === 'get')) { nonApi.push('frontend-not-built status'); continue }
          const url = normalizePath(raw)
          const all = route.methods._all
          if (all) allPaths.add(url)
          const methods = all ? METHODS : Object.keys(route.methods).filter(m => route.methods[m])
          for (const method of methods) {
            if (!METHODS.includes(method)) throw new Error(`Unsupported HTTP method ${method}`)
            operations.add(`${method.toUpperCase()} ${url}`)
          }
        }
      } else if (layer.name === 'router') {
        // All current routers mount at /. Reject changed prefixes instead of
        // treating /v2/foo as /foo and reporting false coverage.
        if (!layer.regexp?.fast_slash) throw new Error('Router mount prefix needs explicit handling')
        if (!Array.isArray(layer.handle?.stack)) throw new Error('Router stack is not enumerable')
        visit(layer.handle.stack)
      }
    }
  }
  visit(stack)
  return { operations, allPaths, nonApi }
}
function inspectContract(spec, mounted) {
  const issues = [], documented = new Set(), ids = new Set()
  function checkReferences(value) {
    if (!value || typeof value !== 'object') return
    if (typeof value.$ref === 'string' && !value.$ref.startsWith('#/')) issues.push(`External reference is not allowed: ${value.$ref}`)
    for (const child of Object.values(value)) checkReferences(child)
  }
  checkReferences(spec)
  for (const [url, item] of Object.entries(spec.paths || {})) {
    for (const method of METHODS) {
      const op = item[method]
      if (!op) continue
      const pair = `${method.toUpperCase()} ${url}`
      documented.add(pair)
      if (!mounted.operations.has(pair)) issues.push(`Unmounted ${pair}`)
      if (!op.operationId) issues.push(`Missing operationId: ${pair}`)
      else if (ids.has(op.operationId)) issues.push(`Duplicate operationId: ${op.operationId}`)
      else ids.add(op.operationId)
      if (!op.summary || !Object.keys(op.responses || {}).length) issues.push(`Incomplete operation: ${pair}`)
      const params = [...(item.parameters || []), ...(op.parameters || [])]
      for (const [, name] of url.matchAll(/\{([^}]+)\}/g)) {
        if (!params.some(p => p.in === 'path' && p.name === name && p.required === true && p.schema)) issues.push(`Missing path parameter ${name}: ${pair}`)
      }
      if (mounted.allPaths.has(url) && op['x-catwaf-express-all'] !== true) issues.push(`Missing all-method annotation: ${pair}`)
      // Derive trust boundaries independently of the spec's access label.
      let required
      if (url.startsWith('/api/setup/')) required = ['setupToken']
      else if (url === '/api/handshake') required = ['bearerAuth']
      else if (url === '/api/enforce') required = method === 'options' ? [] : ['enforceKey']
      else if (url === '/api/upload-gate') required = method === 'options' ? [] : ['uploadKey']
      else if (url === '/metrics') required = ['metricsToken']
      else if (['/healthz','/api/auth/login','/api/auth/status'].includes(url) || url.startsWith('/catwaf-challenge')) required = []
      else {
        required = ['bearerAuth','requestSignature','requestTimestamp','requestNonce']
        if (!op.servers?.some(s => s.url === '/g/{segment}' && s.variables?.segment)) issues.push(`Missing rotating server: ${pair}`)
      }
      const security = op.security
      if (!Array.isArray(security) || (required.length === 0 ? security.length !== 0 : security.length !== 1)) issues.push(`Alternative security or incorrect security count: ${pair}`)
      if (required.length && !required.every(scheme => Object.hasOwn(security?.[0] || {}, scheme))) issues.push(`${required.includes('requestSignature') ? 'Missing signing scheme' : 'Incorrect security'}: ${pair}`)
    }
  }
  for (const pair of mounted.operations) if (!documented.has(pair)) issues.push(`Undocumented ${pair}`)
  return issues.sort()
}
module.exports = { METHODS, collectRoutes, inspectContract, normalizePath }
