#!/usr/bin/env node
// Used by the synchronous offline restore command. SQLite's backup API
// updates the destination transactionally, retaining its inode and WAL.
const { DatabaseSync, backup } = require('node:sqlite')
async function main() {
  if (typeof backup !== 'function') throw new Error('Database restore requires Node.js 22.16+ or 24+.')
  const [source, target] = process.argv.slice(2)
  if (!source || !target || source === target) throw new Error('Distinct source and target database paths are required')
  const db = new DatabaseSync(source, { readOnly: true })
  try { await backup(db, target) } finally { db.close() }
}
main().catch(error => { console.error(error.message); process.exitCode = 1 })
