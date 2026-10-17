#!/usr/bin/env node
// Requires this repository's Compose stack to be running. Does not modify
// configuration or create accounts; sends a harmless SQLi-shaped test query.
const assert = require('node:assert/strict')
const { execFileSync } = require('node:child_process')

function inContainer(service, script) {
  return execFileSync('docker', ['compose', 'exec', '-T', service, 'node', '-e', script], {
    encoding: 'utf8', timeout: 15000, windowsHide: true,
  }).trim()
}

async function main() {
  const backendUrl = process.env.CATWAF_CHECK_BACKEND_URL || 'http://127.0.0.1:8000'
  const wafUrl = process.env.CATWAF_CHECK_WAF_URL || 'http://127.0.0.1'
  let ready = false
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      const backend = await fetch(backendUrl + '/healthz', { signal: AbortSignal.timeout(2000) })
      const origin = await fetch(wafUrl + '/', { signal: AbortSignal.timeout(2000) })
      if (backend.ok && origin.ok) { ready = true; break }
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 1000))
  }
  assert.equal(ready, true, 'Backend and WAF must become healthy')
  assert.equal(inContainer('backend', `
    const fs = require('fs'), http = require('http'), assert = require('assert/strict');
    assert.equal(process.getuid(), 1000);
    assert.equal(fs.statSync('/app/data/catwaf.db').mode & 0o777, 0o600);
    assert.equal(fs.existsSync('/var/run/docker.sock'), false);
    const socket = process.env.CADDY_ADMIN_SOCKET;
    assert(socket); assert.equal(fs.statSync(socket).mode & 0o777, 0o660);
    const req = http.get({ socketPath: socket, path: '/config/', timeout: 5000 }, res => {
      res.resume(); res.on('end', () => { assert.equal(res.statusCode, 200); console.log('socket-ok'); });
    });
    req.on('timeout', () => req.destroy(new Error('Admin socket timed out')));
    req.on('error', err => { console.error(err.message); process.exit(1); });
  `), 'socket-ok')
  assert.equal(inContainer('test-app', `
    const fs = require('fs'), net = require('net'), assert = require('assert/strict');
    assert.equal(fs.existsSync('/run/catwaf-admin/admin.sock'), false);
    const socket = net.createConnection({ host: 'caddy', port: 2019 });
    socket.setTimeout(5000);
    socket.on('connect', () => { console.error('Origin can reach Caddy admin TCP'); process.exit(1); });
    socket.on('timeout', () => { console.error('TCP isolation check timed out'); process.exit(1); });
    socket.on('error', err => { assert.equal(err.code, 'ECONNREFUSED'); console.log('isolated'); });
  `), 'isolated')
  const proxyUid = execFileSync('docker', ['compose', 'exec', '-T', 'caddy', 'id', '-u'], { encoding: 'utf8', timeout: 10000 }).trim()
  assert.equal(proxyUid, '1001', 'Proxy must use a non-root UID distinct from the backend')
  // Exercise an actual open/read instead of relying on a mode predicate.
  execFileSync('docker', ['compose', 'exec', '-T', 'caddy', 'sh', '-c', 'if head -c 1 /app/data/catwaf.db >/dev/null 2>&1; then exit 1; fi'], {
    encoding: 'utf8', timeout: 10000, windowsHide: true,
  })
  // The separate proxy UID must still read backend-generated 0640 assets.
  // Use an unreferenced generation; never alter the live configuration.
  const asset = inContainer('backend', `
    const util = require('./backend/services/render/util');
    console.log(util.withAssetGeneration(() => util.writeAsset('isolation.txt', 'catwaf-shared-asset')));
  `)
  assert.match(asset, /^\/app\/data\/caddy\/generations\/[a-f0-9-]+\/isolation\.txt$/)
  try {
    assert.equal(execFileSync('docker', ['compose', 'exec', '-T', 'caddy', 'cat', asset], { encoding: 'utf8', timeout: 10000 }), 'catwaf-shared-asset')
  } finally {
    inContainer('backend', `require('fs').rmSync(require('path').dirname(${JSON.stringify(asset)}), { recursive: true });`)
  }
  const attack = await fetch(wafUrl + '/?id=1%20UNION%20SELECT%201,2,3--', { signal: AbortSignal.timeout(10000) })
  assert.equal(attack.status, 403, 'The public WAF listener must block the test query')
  console.log('Container checks passed: health, allowed request, admin socket, origin isolation, distinct non-root backend/proxy UIDs, private DB unreadable by Caddy, no Docker socket and SQLi block.')
}

main().catch(error => { console.error(error.message); process.exitCode = 1 })
