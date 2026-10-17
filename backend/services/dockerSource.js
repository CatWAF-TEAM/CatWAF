const http = require('http')
const { execFile } = require('child_process')
const { promisify } = require('util')
const exec = promisify(execFile)

function metadata(socketPath) {
  return new Promise((resolve, reject) => {
    const req = http.get({ socketPath, path: '/containers', timeout: 10000, signal: AbortSignal.timeout(10000) }, res => {
      const chunks = []; let bytes = 0
      res.on('data', b => { bytes += b.length; if (bytes > 8 * 1024 * 1024) res.destroy(new Error('Container inventory too large')); else chunks.push(b) })
      res.on('error', reject)
      res.on('end', () => {
        try {
          if (res.statusCode !== 200) throw new Error('Docker metadata unavailable: ' + res.statusCode)
          const data = JSON.parse(Buffer.concat(chunks).toString())
          if (!Array.isArray(data) || data.length > 1000) throw new Error('Invalid container inventory')
          resolve(data)
        } catch (e) { reject(e) }
      })
    })
    req.on('timeout', () => req.destroy(new Error('Docker metadata timed out')))
    req.on('error', reject)
  })
}
async function list() {
  if (process.env.CATWAF_DOCKER_METADATA_SOCKET) return metadata(process.env.CATWAF_DOCKER_METADATA_SOCKET)
  const { stdout } = await exec('docker', ['ps', '-q', '--no-trunc'], { timeout: 10000, maxBuffer: 1024 * 1024 })
  const ids = stdout.trim().split(/\s+/).filter(Boolean)
  if (ids.length > 1000 || ids.some(id => !/^[a-f0-9]{64}$/.test(id))) throw new Error('Invalid or oversized Docker inventory')
  if (!ids.length) return []
  const containers = []
  for (let i = 0; i < ids.length; i += 50) {
    const result = await exec('docker', ['inspect', ...ids.slice(i, i + 50)], { timeout: 10000, maxBuffer: 8 * 1024 * 1024 })
    const batch = JSON.parse(result.stdout)
    if (!Array.isArray(batch) || batch.length !== ids.slice(i,i+50).length) throw new Error('Incomplete Docker inventory')
    for (const c of batch) containers.push({ id: c.Id, name: String(c.Name || '').replace(/^\//, ''), running: !!c.State?.Running, labels: c.Config?.Labels || {}, networks: c.NetworkSettings?.Networks || {} })
  }
  return containers
}
module.exports = { list, metadata }
