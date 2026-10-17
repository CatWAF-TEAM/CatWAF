// Optional read-only metadata bridge. No caller-controlled Docker path, method,
// headers or request body reaches the engine; environment and mounts are omitted.
const http = require('http')
const fs = require('fs')
const path = require('path')
const socket = process.env.CATWAF_METADATA_LISTEN || '/run/catwaf-discovery/metadata.sock'
const prefix = process.env.CATWAF_LABEL_PREFIX || 'catwaf'
fs.mkdirSync(path.dirname(socket), { recursive: true, mode: 0o755 })
if (fs.existsSync(socket)) fs.unlinkSync(socket)
let busy = false
const server = http.createServer((req, res) => {
  if (req.method !== 'GET' || req.url !== '/containers') { res.writeHead(404); return res.end() }
  if (busy) { res.writeHead(503); return res.end() }
  busy = true
  let settled = false
  const done = (status, data) => {
    if (settled) return
    settled = true; busy = false
    if (res.destroyed) return
    res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' })
    res.end(JSON.stringify(data))
  }
  const upstream = http.get({ socketPath: process.env.CATWAF_METADATA_DOCKER_SOCKET || '/var/run/docker.sock', path: '/v1.45/containers/json?all=false', timeout: 5000, signal: AbortSignal.timeout(5000) }, response => {
    let size = 0; const chunks = []
    response.on('data', b => { size += b.length; if (size > 8 * 1024 * 1024) response.destroy(new Error('Inventory too large')); else chunks.push(b) })
    response.on('error', () => done(502, { error: 'Docker metadata failed' }))
    response.on('end', () => {
      try {
        if (response.statusCode !== 200) throw new Error('Docker API unavailable')
        const data = JSON.parse(Buffer.concat(chunks).toString())
        if (!Array.isArray(data) || data.length > 1000) throw new Error('Invalid Docker inventory')
        done(200, data.map(c => ({ id: c.Id, name: String(c.Names?.[0] || c.Id).replace(/^\//, ''), running: c.State === 'running',
          labels: Object.fromEntries(Object.entries(c.Labels || {}).filter(([key]) => key.startsWith(prefix + '.'))),
          networks: Object.fromEntries(Object.entries(c.NetworkSettings?.Networks || {}).map(([key, n]) => [key, { IPAddress: n.IPAddress, GlobalIPv6Address: n.GlobalIPv6Address }])),
        })))
      } catch { done(502, { error: 'Docker metadata unavailable' }) }
    })
  })
  upstream.on('timeout', () => upstream.destroy(new Error('Docker timeout')))
  upstream.on('error', () => done(502, { error: 'Docker metadata unavailable' }))
})
server.requestTimeout = 10000
server.headersTimeout = 5000
server.listen(socket, () => fs.chmodSync(socket, 0o666))
process.on('SIGTERM', () => server.close(() => process.exit(0)))
