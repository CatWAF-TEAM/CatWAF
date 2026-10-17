// Evidence that an archive has no remaining OS writer. Unknown means retain.
const fs = require('fs'), path = require('path'), { execFileSync } = require('child_process')
function identity(stat) { return String(stat.dev) + ':' + String(stat.ino) }
function processWriters(pid) {
  const writers = new Set()
  const dir = '/proc/' + pid + '/fd'
  const entries = fs.readdirSync(dir)
  if (entries.length > 65536) throw new Error('Proxy descriptor inventory exceeds limit')
  for (const fd of entries) {
    try {
      const info = fs.readFileSync('/proc/' + pid + '/fdinfo/' + fd, 'utf8')
      const flags = info.match(/^flags:\s+([0-7]+)$/m)
      if (!flags) throw new Error('Invalid proxy descriptor flags')
      if (!(parseInt(flags[1], 8) & 3)) continue
      const stat = fs.statSync(path.join(dir, fd), { bigint: true })
      if (stat.isFile()) writers.add(identity(stat))
    } catch (e) { if (e.code !== 'ENOENT') throw e }
  }
  return [...writers]
}
const CLIENT = `
const http=require('http');
const r=http.get({socketPath:process.env.CW_WRITER_SOCKET,path:'/writers',signal:AbortSignal.timeout(2000)},s=>{
 let b='';s.on('data',d=>{b+=d;if(b.length>2097152)s.destroy(new Error('oversize'))});
 s.on('end',()=>{if(s.statusCode!==200)process.exit(1);process.stdout.write(b)});s.on('error',()=>process.exit(1));
});r.on('error',()=>process.exit(1));
`
function snapshot() {
  try {
    const socket = process.env.CATWAF_AUDIT_WRITER_SOCKET || (process.env.CADDY_ADMIN_SOCKET && path.join(path.dirname(process.env.CADDY_ADMIN_SOCKET), 'audit-writers.sock'))
    if (socket && (process.env.CATWAF_AUDIT_WRITER_SOCKET || fs.existsSync(socket))) {
      const value = JSON.parse(execFileSync(process.execPath, ['-e', CLIENT], { env: { ...process.env, CW_WRITER_SOCKET: socket }, timeout: 3000, maxBuffer: 2 * 1024 * 1024, stdio: ['ignore','pipe','pipe'] }))
      if (value.ok !== true || !Array.isArray(value.writers) || value.writers.some(x => typeof x !== 'string' || !/^\d+:\d+$/.test(x))) throw new Error('Invalid proxy writer inventory')
      return { ok: true, writers: new Set(value.writers) }
    }
    if (process.platform !== 'linux' || fs.existsSync('/.dockerenv') || process.env.KUBERNETES_SERVICE_HOST) throw new Error('Proxy writer observer is required in an isolated process namespace')
    const writers = new Set()
    const expectedConfig = process.env.CADDYFILE_PATH || require('./caddy').CADDYFILE_PATH
    for (const pid of fs.readdirSync('/proc').filter(x => /^\d+$/.test(x))) {
      try {
        if (fs.readFileSync('/proc/' + pid + '/comm', 'utf8').trim() !== 'caddy') continue
        const argv = fs.readFileSync('/proc/' + pid + '/cmdline', 'utf8').split('\0').filter(Boolean)
        if (argv[1] !== 'run') continue // CLI validators/reload clients do not serve requests.
        const at = argv.indexOf('--config')
        const config = at >= 0 ? argv[at + 1] : argv.find(x => x.startsWith('--config='))?.slice(9)
        if (!config || !expectedConfig) throw new Error('Unidentified proxy configuration; use the writer observer')
        const actual = path.isAbsolute(config) ? path.resolve(config) : path.resolve(fs.readlinkSync('/proc/' + pid + '/cwd'), config)
        if (actual !== path.resolve(expectedConfig)) continue
        for (const id of processWriters(pid)) writers.add(id)
      } catch (e) { if (e.code !== 'ENOENT' && e.code !== 'ESRCH') throw e }
    }
    return { ok: true, writers }
  } catch (e) { return { ok: false, error: 'Cannot prove audit writers have retired: ' + e.message, writers: new Set() } }
}
module.exports = { identity, processWriters, snapshot }
