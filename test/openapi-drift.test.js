// Compare METHOD + path; no legacy warning baseline or fail-open skips.
const os = require('os')
const fs = require('fs')
const path = require('path')
const assert = require('node:assert/strict')
const { collectRoutes, inspectContract } = require('../scripts/lib/openapi-contract')
const DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-openapi-drift-'))
process.env.DB_DIR = DIR
process.env.CADDYFILE_PATH = path.join(DIR, 'Caddyfile')
fs.writeFileSync(process.env.CADDYFILE_PATH, 'site:80 {\n    respond "test"\n}\n')
process.env.CORAZA_AUDIT_LOG = path.join(DIR, 'logs', 'audit.json')
process.env.CADDY_ADMIN_URL = 'http://127.0.0.1:19917'
process.env.JWT_SECRET = 'o'.repeat(64)
delete process.env.PORT
let pass = 0
function check(name, fn) { fn(); pass++; console.log('  ok   ' + name) }
;(async () => {
  const yaml = require('js-yaml')
  const parser = require('@apidevtools/swagger-parser')
  const { app } = require('../backend/server')
  const spec = yaml.load(fs.readFileSync(path.join(__dirname, '..', 'openapi.yaml'), 'utf8'))
  // External references cannot fetch URLs or read arbitrary files in CI.
  const resolved = await parser.validate(structuredClone(spec), { resolve: { external: false } })
  console.log('  ok   OpenAPI 3 schema and local references are valid'); pass++
  const mounted = collectRoutes(app._router?.stack)
  check('route inspection finds the complete API surface', () => assert.ok(mounted.operations.size > 170))
  check('every mounted method and documented operation match', () => assert.deepEqual(inspectContract(spec, mounted), []))
  console.log(`  ·    ${mounted.operations.size} operations, ${Object.keys(spec.paths).length} paths; ${mounted.nonApi.length} explicitly classified non-API/alias routes`)
  const problems = (mutate, predicate) => {
    const changed = structuredClone(spec)
    mutate(changed)
    assert.ok(inspectContract(changed, mounted).some(predicate))
  }
  check('missing POST cannot hide behind a documented GET', () => problems(s => delete s.paths['/api/waf/engine'].post, e => e.includes('Undocumented POST /api/waf/engine')))
  check('unmounted method on an existing path fails', () => problems(s => { s.paths['/api/waf/engine'].delete = structuredClone(s.paths['/api/waf/engine'].post) }, e => e.includes('Unmounted DELETE /api/waf/engine')))
  check('missing bootstrap documentation fails', () => problems(s => delete s.paths['/api/setup/account'], e => e.includes('Undocumented POST /api/setup/account')))
  check('gateway all-method coverage cannot silently shrink', () => problems(s => delete s.paths['/api/upload-gate'].put, e => e.includes('Undocumented PUT /api/upload-gate')))
  check('unknown regex routes require explicit classification', () => assert.throws(() => collectRoutes([{ route: { path: /^\/new-api\//, methods: { get: true } } }]), /Unclassified RegExp/))
  check('uninspectable Express stack fails closed', () => assert.throws(() => collectRoutes(undefined), /not enumerable/))
  check('nested router prefixes cannot be silently ignored', () => assert.throws(() => collectRoutes([{ name: 'router', regexp: { fast_slash: false }, handle: { stack: [] } }]), /mount prefix/))
  check('duplicate operation IDs fail', () => problems(s => { s.paths['/api/waf/engine'].get.operationId = s.paths['/api/auth/login'].post.operationId }, e => e.includes('Duplicate operationId')))
  check('undeclared path parameter fails', () => problems(s => { s.paths['/api/rules/{id}/{action}'].parameters = [] }, e => e.includes('Missing path parameter')))
  check('bearer-only documentation for a signed operation fails', () => problems(s => { s.paths['/api/waf/engine'].post.security = [{ bearerAuth: [] }] }, e => e.includes('Missing signing scheme')))
  check('authentication alternatives cannot weaken AND requirements', () => problems(s => { s.paths['/api/waf/engine'].post.security.push({}) }, e => e.includes('Alternative security')))
  check('protected operations require their rotating server prefix', () => problems(s => delete s.paths['/api/waf/engine'].post.servers, e => e.includes('Missing rotating server')))
  check('bootstrap security cannot be silently removed', () => problems(s => { s.paths['/api/setup/account'].post.security = [] }, e => e.includes('Incorrect security')))
  check('external references cannot evade local contract validation', () => problems(s => { s.paths['/api/auth/login'].post.responses[200] = { $ref:'https://example.invalid/response.json' } }, e => e.includes('External reference')))
  // Real HTTP responses on a disposable database, including a non-empty
  // snapshot and rule catalogue. Never call outbound integrations or apply
  // deployment changes just to exercise documentation.
  const crypto = require('crypto')
  const Ajv = require('ajv')
  const ajv = new Ajv({ strict: false, validateFormats: false, allErrors: true })
  const auth = require('../backend/middleware/auth')
  auth.addUser({ username: 'contract-admin', password: 'contract-only-password', role: 'admin', bootstrap: true })
  const server = await new Promise(resolve => { const listener = app.listen(0, '127.0.0.1', () => resolve(listener)) })
  const origin = `http://127.0.0.1:${server.address().port}`
  async function validateResponse(method, template, url, options = {}) {
    const response = await fetch(origin + url, { method, ...options })
    const contract = resolved.paths[template][method.toLowerCase()].responses[response.status]
    assert.ok(contract, `Undocumented response ${response.status}: ${method} ${template}`)
    const media = response.headers.get('content-type')?.split(';')[0]
    const schema = contract.content?.[media]?.schema
    assert.ok(schema, `Undocumented content type ${media}: ${template}`)
    const payload = media === 'application/json' ? await response.json() : await response.text()
    const validate = ajv.compile(schema)
    assert.ok(validate(payload), `${method} ${template}: ${JSON.stringify(validate.errors)}`)
    return payload
  }
  try {
    const login = await validateResponse('POST','/api/auth/login','/api/auth/login', { headers: { 'Content-Type':'application/json' }, body: JSON.stringify({username:'contract-admin',password:'contract-only-password'}) })
    pass++; console.log('  ok   real login response includes signing and rotating-path contract')
    const snapshot = require('../backend/services/snapshots').create({ label: 'contract fixture' })
    require('../backend/services/db').getDb().prepare(`INSERT INTO request_log
      (id, ts, ip, method, uri, status, action, attack_type, rule_ids, score, severity)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run('contract-event', new Date().toISOString(), '192.0.2.10', 'GET', '/?id=test', 403, 'block', 'SQLi', '["942100"]', 5, 'critical')
    const paths = [
      '/api/auth/me','/api/auth/2fa','/api/sessions','/api/users','/api/stats',
      '/api/traffic/chart','/api/traffic/attacks','/api/traffic/live','/api/traffic/top-ips','/api/attack-map',
      '/api/logs','/api/audit/summary','/api/rules','/api/rules/stats','/api/rules/{id}',
      '/api/mode','/api/performance-mode','/api/waf/engine','/api/waf/paranoia','/api/waf/anomaly','/api/waf/settings','/api/waf/paranoia-levels',
      '/api/settings','/api/settings/schema','/api/settings/{group}',
      '/api/config/snapshots','/api/config/snapshots/{id}','/api/config/snapshots/{id}/diff',
      '/api/wellknown/robots.txt','/api/wellknown/security.txt',
      '/api/sensitive/state','/api/sensitive/levels','/api/sensitive/blocked','/api/sensitive/scan',
      '/api/alerts','/api/caddy/reload-queue/status','/api/bans','/api/bans/stats',
      '/api/challenge/status','/api/intel/lists','/api/intel/network','/api/intel/probe/tradeoffs',
      '/api/jobs','/api/backups','/api/telemetry','/api/templates','/api/templates/{id}','/api/templates/{id}/export',
      '/api/plugins','/api/caches','/api/autoconf','/api/kubernetes','/api/sites','/api/cluster','/api/database','/api/catai/status',
    ]
    for (const template of paths) {
      const url = template.replace('{group}','headers').replace('{id}',template.startsWith('/api/config/snapshots')?snapshot.id:template.startsWith('/api/templates')?'hardened-public-site':'942100')
      const ts = String(Date.now()), nonce = crypto.randomBytes(16).toString('hex')
      const signature = crypto.createHmac('sha256',login.sessionKey).update(['GET',url,ts,nonce,crypto.createHash('sha256').update('').digest('hex')].join('\n')).digest('hex')
      await validateResponse('GET',template,login.api.basePath+url,{headers:{Authorization:`Bearer ${login.token}`,'X-CatWAF-Ts':ts,'X-CatWAF-Nonce':nonce,'X-CatWAF-Sig':signature}})
      pass++; console.log('  ok   response schema GET ' + template)
    }
    for (const url of ['/api/autoconf/scan','/api/kubernetes/scan']) {
      const body=JSON.stringify({dry_run:true}), ts=String(Date.now()), nonce=crypto.randomBytes(16).toString('hex')
      const sig=crypto.createHmac('sha256',login.sessionKey).update(['POST',url,ts,nonce,crypto.createHash('sha256').update(body).digest('hex')].join('\n')).digest('hex')
      const payload=await validateResponse('POST',url,login.api.basePath+url,{body,headers:{'Content-Type':'application/json',Authorization:`Bearer ${login.token}`,'X-CatWAF-Ts':ts,'X-CatWAF-Nonce':nonce,'X-CatWAF-Sig':sig}})
      assert.equal(payload.skipped,'disabled');pass++;console.log('  ok   response schema POST '+url)
    }
  } finally { await new Promise(resolve => server.close(resolve)) }
  console.log(`\n${pass} passed, 0 failed, 0 warnings\n`)
})().then(() => process.exit(0)).catch(error => {
  console.error(error.stack || error)
  console.log(`\n${pass} passed, 1 failed\n`)
  process.exit(1)
})
