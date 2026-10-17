#!/usr/bin/env node
// Minimal upstream reproduction: Caddy's static responder, no Coraza, no
// CatWAF API/database/origin. A nonzero exit preserves the strict zero-reset
// requirement. Operates only on an ephemeral loopback port and private socket.
const fs = require('node:fs'), os = require('node:os'), path = require('node:path')
const http = require('node:http'), { spawn, execFile } = require('node:child_process')
const { once } = require('node:events'), { promisify } = require('node:util')
const exec = promisify(execFile), sleep = ms => new Promise(r => setTimeout(r, ms))
const get = url => new Promise((resolve, reject) => {
  const req = http.get(url, { agent: false, signal: AbortSignal.timeout(3000) }, res => {
    res.resume(); res.on('error', reject); res.on('end', () => resolve(res.statusCode))
  })
  req.on('error', reject)
})
async function main() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-reload-repro-'))
  let proc, running = true
  const workers = [], errors = []
  let passed = 0
  try {
    const reserve = http.createServer()
    reserve.listen(0, '127.0.0.1'); await once(reserve, 'listening')
    const port = reserve.address().port
    await new Promise(resolve => reserve.close(resolve))
    const file = path.join(dir, 'Caddyfile'), socket = path.join(dir, 'admin.sock')
    const config = `{\n admin unix/${socket}|0600\n auto_https off\n}\n:${port} {\n bind 127.0.0.1\n respond ok\n}\n`
    fs.writeFileSync(file, config)
    const fd = fs.openSync(path.join(dir, 'caddy.log'), 'w')
    proc = spawn('caddy', ['run', '--config', file], { stdio: ['ignore', fd, fd], env: { ...process.env, XDG_DATA_HOME: path.join(dir, 'data'), XDG_CONFIG_HOME: path.join(dir, 'config') } })
    fs.closeSync(fd)
    const started = once(proc, 'spawn'); await started
    const url = 'http://127.0.0.1:' + port
    let ready = false
    for (let i = 0; i < 50; i++) {
      try { ready = (await get(url)) === 200 } catch {}
      if (ready) break
      await sleep(100)
    }
    if (!ready) throw new Error('Fixture did not become ready')
    for (let i = 0; i < 4; i++) workers.push((async () => {
      while (running) {
        try { if (await get(url) !== 200) throw new Error('unexpected HTTP status'); passed++ }
        catch (error) { errors.push(error.message) }
        await sleep(5)
      }
    })())
    for (let revision = 1; revision <= 20; revision++) {
      fs.writeFileSync(file, config.replace('respond ok', `header X-Revision ${revision}\n respond ok`))
      await exec('caddy', ['reload', '--config', file, '--address', `unix/${socket}`], { timeout: 15000 })
    }
  } finally {
    running = false; await Promise.all(workers)
    if (proc && proc.pid && proc.exitCode === null && proc.signalCode === null) {
      const stopped = once(proc, 'exit'); proc.kill('SIGTERM'); await stopped
    }
    fs.rmSync(dir, { recursive: true, force: true })
  }
  console.log(JSON.stringify({ coraza: false, catwafApi: false, reloads: 20, concurrency: 4, passed, failed: errors.length, errors }))
  if (errors.length) process.exitCode = 1
}
main().catch(error => { console.error(error.message); process.exitCode = 1 })
