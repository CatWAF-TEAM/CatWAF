const crypto = require('crypto')
const secrets = require('./secrets')
const { normalizeClientIp } = require('./sanitize')

function hasGatewayKey(req) {
  return [['x-catwaf-enforce-key', 'enforce-key'], ['x-catwaf-upload-key', 'upload-gate-key'], ['x-catwaf-challenge-key', 'challenge-key']].some(([header, label]) => {
    const supplied = Buffer.from(String(req.headers?.[header] || ''))
    const expected = Buffer.from(secrets.derive(label))
    return supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected)
  })
}
function clientIp(req) {
  if (hasGatewayKey(req)) {
    const forwarded = req.headers?.['x-catwaf-client-ip'] || req.headers?.['x-real-ip']
    if (forwarded) return normalizeClientIp(String(forwarded).split(',')[0].trim())
  }
  return normalizeClientIp(req.ip || '')
}
module.exports = { clientIp, hasGatewayKey }
