#!/usr/bin/env node
// Same-UID observer for Caddy's descriptors; no capabilities or PID sharing.
const fs = require('fs'), http = require('http'), { spawn } = require('child_process')
const { processWriters } = require('../backend/services/auditWriters')
const socket = process.env.CATWAF_AUDIT_WRITER_SOCKET || '/run/catwaf-admin/audit-writers.sock'
let child, stopping = false
const server = http.createServer((req, res) => {
  if (req.method !== 'GET' || req.url !== '/writers') { res.writeHead(404).end(); return }
  try {
    if (!child?.pid || child.exitCode !== null || child.signalCode !== null) throw new Error('Proxy is not running')
    res.setHeader('Content-Type', 'application/json'); res.setHeader('Cache-Control', 'no-store')
    res.end(JSON.stringify({ ok: true, writers: processWriters(child.pid) }))
  } catch { res.writeHead(503).end('{"ok":false}') }
})
server.requestTimeout = 3000; server.headersTimeout = 3000; server.maxConnections = 16
try {
  const stat = fs.lstatSync(socket)
  if (!stat.isSocket() || stat.uid !== process.getuid()) throw new Error('Unexpected writer observer socket')
  fs.unlinkSync(socket)
} catch (e) { if (e.code !== 'ENOENT') throw e }
server.listen(socket, () => {
  fs.chmodSync(socket, 0o660)
  const args = process.argv.slice(2)
  child = spawn('caddy', args.length ? args : ['run','--config','/etc/caddy/Caddyfile','--adapter','caddyfile'], { stdio: 'inherit' })
  child.on('error', e => { console.error(e.message); finish(1) })
  child.on('exit', (code, signal) => finish(code ?? (stopping ? 0 : 1)))
})
function finish(code) {
  server.close(); server.closeAllConnections()
  try { fs.unlinkSync(socket) } catch {}
  process.exitCode = code
}
for (const signal of ['SIGINT','SIGTERM']) process.on(signal, () => { stopping = true; if (child) child.kill(signal); else finish(0) })
server.on('error', e => { console.error(e.message); if (child) child.kill('SIGTERM'); process.exitCode = 1 })
