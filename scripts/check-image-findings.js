#!/usr/bin/env node
// Inspect the unfiltered Trivy report. Every advisory blocks, including
// unfixed findings. No exception based on a now-removed local source graph.
const fs = require('fs')
function inspect(report) {
  if (!report || report.SchemaVersion !== 2 || !Array.isArray(report.Results) || !report.Results.length || !report.Metadata?.ImageID) throw new Error('Not a complete Trivy image report')
  const blocking = [], assessed = []
  for (const result of report.Results) for (const finding of result.Vulnerabilities || []) {
    blocking.push({ target: result.Target, id: finding.VulnerabilityID, package: finding.PkgName, version: finding.InstalledVersion })
  }
  return { blocking, assessed }
}
if (require.main === module) {
  try {
    if (process.argv.length !== 3) throw new Error('Usage: node scripts/check-image-findings.js <unfiltered-trivy.json>')
    const result = inspect(JSON.parse(fs.readFileSync(process.argv[2], 'utf8')))
    console.log(JSON.stringify(result, null, 2))
    process.exitCode = result.blocking.length ? 1 : 0
  } catch (error) { console.error(error.message); process.exitCode = 1 }
}
module.exports = { inspect }
