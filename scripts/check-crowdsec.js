#!/usr/bin/env node
// Isolated Local API compatibility check; no host ports or online registration.
const fs = require('fs'), os = require('os'), path = require('path'), crypto = require('crypto')
const assert = require('assert/strict'), { promisify } = require('util'), { execFile } = require('child_process')
const exec = promisify(execFile)
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-crowdsec-'))
Object.assign(process.env, { DB_DIR: dir, JWT_SECRET: crypto.randomBytes(32).toString('hex') })
const name = 'cw-crowdsec-fixture-' + process.pid, network = name + '-net'
const image = process.env.CATWAF_CROWDSEC_IMAGE || 'crowdsecurity/crowdsec:v1.8.1'
const key = crypto.randomBytes(32).toString('hex'), ip = '198.51.100.54'
const docker = (...args) => exec('docker', args, { timeout: 60000, maxBuffer: 1024 * 1024 })
const pause = ms => new Promise(resolve => setTimeout(resolve, ms))
let createdNetwork = false, createdContainer = false
async function main() {
  assert.equal(process.platform, 'linux')
  await docker('network', 'create', '--internal', network); createdNetwork = true
  await docker('run', '-d', '--name', name, '--network', network,
    '--security-opt', 'no-new-privileges:true', '--memory', '256m', '--pids-limit', '128',
    '-e', 'DISABLE_AGENT=true', '-e', 'DISABLE_ONLINE_API=true',
    '-e', 'CROWDSEC_BYPASS_DB_VOLUME_CHECK=true', '-e', 'BOUNCER_KEY_catwaf=' + key, image)
  createdContainer = true
  const address = JSON.parse((await docker('inspect', name)).stdout)[0].NetworkSettings.Networks[network].IPAddress
  const settings = require('../backend/services/settings'), feed = require('../backend/services/intel/threatFeed')
  const cache = require('../backend/services/intel/cache')
  assert.equal(settings.set('threat_feed', { enabled: true, url: 'http://' + address + ':8080', api_key: key, fail_open: false, cache_seconds: 5 }).ok, true)
  let ready = false
  for (let i = 0; i < 60; i++) {
    if ((await feed.testConnection()).ok) { ready = true; break }
    await pause(500)
  }
  assert.equal(ready, true, 'CrowdSec Local API did not become ready')
  assert.equal(await feed.evaluate(ip), null)
  console.log('PASS authenticated native Local API with no decision')
  const decide = (...args) => docker('exec', name, 'cscli', 'decisions', ...args)
  await decide('add', '--range', '198.51.100.0/24', '--duration', '10m', '--type', 'ban')
  cache.clear(feed.NS)
  assert.equal((await feed.evaluate(ip)).decision, 'block')
  console.log('PASS native Range ban includes the queried client')
  await decide('delete', '--range', '198.51.100.0/24')
  await pause(5100)
  assert.equal(await feed.evaluate(ip), null)
  console.log('PASS revocation becomes effective when the bounded cache expires')
  await decide('add', '--ip', ip, '--duration', '10m', '--type', 'captcha')
  cache.clear(feed.NS)
  assert.equal((await feed.evaluate(ip)).decision, 'block')
  assert.equal(settings.set('challenge', { mode: 'captcha' }).ok, true)
  assert.equal((await feed.evaluate(ip)).decision, 'challenge')
  console.log('PASS native CAPTCHA decision requires an available CAPTCHA mode')
  await decide('delete', '--ip', ip)
  await decide('add', '--ip', ip, '--duration', '2s', '--type', 'ban')
  cache.clear(feed.NS)
  assert.equal((await feed.evaluate(ip)).decision, 'block')
  await pause(2200)
  assert.equal(await feed.evaluate(ip), null)
  console.log('PASS decision expiry takes precedence over the cache window')
  assert.equal(settings.set('threat_feed', { api_key: 'invalid-fixture-key' }).ok, true)
  assert.equal((await feed.evaluate(ip)).decision, 'block')
  assert.equal(settings.set('threat_feed', { fail_open: true }).ok, true)
  assert.equal((await feed.evaluate(ip)).decision, 'unavailable')
  console.log('PASS invalid credentials obey both configured failure policies')
}
main().catch(e => { console.error(e.message); process.exitCode = 1 }).finally(async () => {
  if (createdContainer) await docker('rm', '-fv', name).catch(e => { console.error('Fixture container cleanup failed'); process.exitCode = 1 })
  if (createdNetwork) await docker('network', 'rm', network).catch(e => { console.error('Fixture network cleanup failed'); process.exitCode = 1 })
})
