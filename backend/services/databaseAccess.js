// A separate rollback-journal SQLite database holds process-lifetime SHARED
// locks. Offline restore requires EXCLUSIVE access. The OS releases locks
// on crashes, and an idle process still holds its lock: no PID/WAL-age guess.
const fs = require('fs')
const { DatabaseSync } = require('node:sqlite')

function open(dbPath) {
  if (dbPath === ':memory:') return { exclusive: fn => fn(), close() {} }
  const file = dbPath + '.access.sqlite'
  fs.closeSync(fs.openSync(file, 'a', 0o600))
  fs.chmodSync(file, 0o600)
  const lock = new DatabaseSync(file)
  lock.exec('PRAGMA busy_timeout=5000')
  lock.exec('CREATE TABLE IF NOT EXISTS access_lock (id INTEGER PRIMARY KEY)')
  function shared() {
    lock.exec('BEGIN')
    lock.prepare('SELECT count(*) FROM access_lock').get()
  }
  shared()
  return {
    exclusive(fn) {
      lock.exec('ROLLBACK; PRAGMA busy_timeout=0')
      let held = false
      try {
        try { lock.exec('BEGIN EXCLUSIVE'); held = true }
        catch { throw new Error('Another CatWAF process has this database open. Stop all API, CLI and scheduler processes before restoring.') }
        return fn()
      } finally {
        if (held) lock.exec('ROLLBACK')
        lock.exec('PRAGMA busy_timeout=5000')
        shared()
      }
    },
    close() { lock.close() },
  }
}
module.exports = { open }
