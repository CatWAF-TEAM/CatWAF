#!/usr/bin/env node
// Creates and destroys ONLY a uniquely named disposable Compose project.
// No host ports, existing containers, existing volumes or production config.
const assert = require('node:assert/strict'), fs = require('node:fs'), os = require('node:os')
const path = require('node:path'), crypto = require('node:crypto')
const { execFileSync } = require('node:child_process')
const root = path.resolve(__dirname, '..')
const prefix = process.env.CATWAF_TEST_IMAGE_PREFIX
assert(prefix && /^[a-z0-9][a-z0-9._/-]*$/.test(prefix), 'Set CATWAF_TEST_IMAGE_PREFIX to the already-built stack image prefix')
const project = 'catwaf-reliability-' + crypto.randomBytes(6).toString('hex')
const dir = fs.mkdtempSync(path.join(os.tmpdir(), project + '-'))
const override = path.join(dir, 'compose.json'), envFile = path.join(dir, 'fixture.env')
fs.writeFileSync(envFile, `JWT_SECRET=${crypto.randomBytes(32).toString('hex')}\nCATWAF_EDITION=full\n`, { mode: 0o600 })
// YAML tags are required to remove inherited published ports, names and env.
const yaml = require('js-yaml')
const fixture = { services: {} }
for (const service of ['backend', 'caddy', 'test-app']) {
  fixture.services[service] = { image: `${prefix}-${service}`, container_name: null, ports: [] }
}
fixture.services.backend.env_file = [envFile]
const fixtureYaml = yaml.dump(fixture).replace(/container_name: null/g, 'container_name: !reset null')
  .replace(/ports: \[\]/g, 'ports: !reset []').replace(/env_file:/g, 'env_file: !override')
fs.writeFileSync(override, fixtureYaml)
const composeArgs = ['compose', '--project-name', project, '--project-directory', root, '-f', path.join(root, 'docker-compose.yml'), '-f', override]
const docker = args => execFileSync('docker', args, { encoding: 'utf8', timeout: 120000, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true })
const compose = args => docker([...composeArgs, ...args])
const inBackend = script => compose(['exec', '-T', 'backend', 'node', '-e', script]).trim()
const probe = () => JSON.parse(inBackend(`
  (async () => {
    const results=[];
    for (const suffix of ['/', '/?id=1%20UNION%20SELECT%201,2,3--']) {
      const r=await fetch('http://caddy'+suffix,{signal:AbortSignal.timeout(5000)});
      results.push(r.status); await r.arrayBuffer();
    }
    console.log(JSON.stringify(results));
  })().catch(e=>{console.error(e.message);process.exit(1)});
`))
const tlsIdentity = () => inBackend(`
  const https=require('https');
  const r=https.get({host:'caddy',port:8443,servername:'localhost',headers:{Host:'localhost:8443'},rejectUnauthorized:false,timeout:5000},res=>{
    const fp=res.socket.getPeerCertificate().fingerprint256;
    let body='';res.on('data',b=>body+=b);res.on('end',()=>{if(res.statusCode!==200||body!=='tls-persistence'){console.error('TLS probe status',res.statusCode);process.exit(1)}console.log(fp)});
  });r.on('timeout',()=>r.destroy(new Error('timeout')));r.on('error',e=>{console.error(e.message);process.exit(1)});
`)
let created = false
async function main() {
  try {
    compose(['config', '--quiet'])
    for (const service of ['backend', 'caddy', 'test-app']) docker(['image', 'inspect', `${prefix}-${service}`])
    created = true
    compose(['up', '-d', '--no-build', '--wait', '--wait-timeout', '90'])
    assert.deepEqual(probe(), [200, 403])
    const firstId = compose(['ps', '-q', 'caddy']).trim()
    const mounts = JSON.parse(docker(['inspect', firstId]))[0].Mounts
    for (const dest of ['/data', '/config']) {
      const mount = mounts.find(m => m.Destination === dest)
      assert(mount && mount.Type === 'volume' && mount.Name.startsWith(project + '_'), `${dest} must have a project-owned named volume`)
    }
    const tlsConfig = '\nhttps://localhost:8443 {\n tls internal\n respond "tls-persistence"\n}\n'
    inBackend(`require('fs').appendFileSync('/etc/caddy/Caddyfile',${JSON.stringify(tlsConfig)})`)
    compose(['exec', '-T', 'caddy', 'caddy', 'reload', '--config', '/etc/caddy/Caddyfile', '--address', 'unix//run/catwaf-admin/admin.sock'])
    const identity = tlsIdentity()
    assert.match(identity, /^(?:[A-F0-9]{2}:){31}[A-F0-9]{2}$/)
    const status = JSON.parse(inBackend(`require('./backend/services/healthcheck').run().then(r=>console.log(JSON.stringify(r)))`))
    assert.equal(status.checks.find(c => c.name === 'Caddy admin API').status, 'healthy')
    assert.equal(status.checks.find(c => c.name === 'Configuration recovery').status, 'healthy')

    compose(['stop', 'backend'])
    const stoppedBackendProbe = compose(['exec', '-T', 'test-app', 'node', '-e', `
      (async()=>{for(const [suffix,status] of [['/',200],['/?id=1%20UNION%20SELECT%201,2,3--',403]]){
        const r=await fetch('http://caddy'+suffix,{signal:AbortSignal.timeout(5000)});
        if(r.status!==status)throw new Error('unexpected '+r.status);await r.arrayBuffer();
      }console.log('protected without API')})().catch(e=>{console.error(e.message);process.exit(1)})`]).trim()
    assert.equal(stoppedBackendProbe, 'protected without API')

    compose(['down']) // deliberately retains volumes: this is the regression
    compose(['up', '-d', '--no-build', '--wait', '--wait-timeout', '90'])
    assert.notEqual(compose(['ps', '-q', 'caddy']).trim(), firstId)
    assert.equal(tlsIdentity(), identity, 'certificate identity must survive complete container recreation')
    assert.deepEqual(probe(), [200, 403])
    console.log(JSON.stringify({ project, checks: ['named TLS and runtime volumes', 'real Unix admin health', 'no pending recovery', 'allowed traffic and SQLi blocking', 'API outage independence', 'container recreation', 'identical TLS certificate after recreation', 'blocking after recreation'], passed: 8 }))
  } finally {
    if (created) {
      if (process.env.CATWAF_RELIABILITY_LOG_DIR) {
        fs.mkdirSync(process.env.CATWAF_RELIABILITY_LOG_DIR, { recursive: true })
        try { fs.writeFileSync(path.join(process.env.CATWAF_RELIABILITY_LOG_DIR, project + '.log'), compose(['logs', '--no-color'])) } catch {}
      }
      compose(['down', '--volumes', '--remove-orphans'])
    }
    fs.rmSync(dir, { recursive: true, force: true })
  }
}
main().catch(error => { console.error(error.stderr?.toString() || error.stack); process.exitCode = 1 })
