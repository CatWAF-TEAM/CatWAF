
const path = require('path')
const fs = require('fs')
const { DatabaseSync } = require('node:sqlite')

const DB_DIR = process.env.DB_DIR || path.join(__dirname, '..', '..', 'data')
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true, mode: 0o750 })

let DB_PATH = process.env.DB_PATH || path.join(DB_DIR, 'catwaf.db')

function openDb(dbPath) {
  // Create before SQLite opens WAL sidecars so secrets are never created
  // world-readable under a permissive process umask.
  if (dbPath !== ':memory:') {
    const fd = fs.openSync(dbPath, 'a', 0o600)
    fs.closeSync(fd)
    fs.chmodSync(dbPath, 0o600)
  }
  const instance = new DatabaseSync(dbPath)

  // busy_timeout MUST come first: journal_mode=WAL below needs a brief
  // write lock, and on a fresh start several processes race to open the
  // same database — without the timeout their PRAGMA fails outright with
  // SQLITE_BUSY instead of waiting its turn.
  function execWithRetry(statements) {
    for (let attempt = 0; ; attempt++) {
      try { instance.exec(statements); return }
      catch (e) {
        if ((e.code === 'ERR_SQLITE_ERROR' && e.errcode === 5) && attempt < 20) {
          const until = Date.now() + 50
          while (Date.now() < until) { /* brief spin: boot-time only */ }
          continue
        }
        throw e
      }
    }
  }
  instance.exec('PRAGMA busy_timeout = 5000;')
  execWithRetry(`
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA temp_store = MEMORY;
  `)

  instance.exec(`
    CREATE TABLE IF NOT EXISTS waf_state (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS request_nonces (
      session_id TEXT NOT NULL,
      nonce TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      PRIMARY KEY (session_id, nonce)
    );
    CREATE INDEX IF NOT EXISTS request_nonces_expiry ON request_nonces(expires_at);
    CREATE TABLE IF NOT EXISTS audit_log (
      id    TEXT PRIMARY KEY,
      ts    TEXT,
      user  TEXT,
      role  TEXT,
      ip    TEXT,
      action TEXT,
      target TEXT,
      meta  TEXT
    );
    CREATE TABLE IF NOT EXISTS snapshots (
      id    TEXT PRIMARY KEY,
      ts    TEXT,
      username TEXT,
      label TEXT,
      state TEXT
    );
    CREATE TABLE IF NOT EXISTS false_positives (
      id   TEXT PRIMARY KEY,
      data TEXT
    );
    CREATE TABLE IF NOT EXISTS request_log (
      id          TEXT PRIMARY KEY,
      ts          TEXT NOT NULL,
      ip          TEXT,
      method      TEXT,
      uri         TEXT,
      status      INTEGER,
      action      TEXT,
      attack_type TEXT,
      rule_ids    TEXT,
      score       INTEGER,
      user_agent  TEXT,
      severity    TEXT,
      reason      TEXT,
      matched_var TEXT
    );
    -- One row per currently-active ban, whatever produced it (idea #61).
    -- Every ban-producing feature writes here so there is a single answer to
    -- "why is this address blocked right now, and can I lift it?".
    CREATE TABLE IF NOT EXISTS active_bans (
      id         TEXT PRIMARY KEY,
      target     TEXT NOT NULL,
      source     TEXT NOT NULL,
      reason     TEXT,
      rule_id    TEXT,
      created_at TEXT NOT NULL,
      expires_at TEXT,
      hits       INTEGER DEFAULT 1,
      meta       TEXT
    );
    -- Entries pulled from subscribed community lists (idea #10). Kept in
    -- their own table, tagged with the source they came from, so a user can
    -- unsubscribe from a feed without losing their own manual entries — and
    -- so a 50k-entry feed does not have to be JSON-parsed on every read.
    CREATE TABLE IF NOT EXISTS list_entries (
      source_id TEXT NOT NULL,
      kind      TEXT NOT NULL,
      list      TEXT NOT NULL,
      value     TEXT NOT NULL,
      added_at  TEXT,
      PRIMARY KEY (source_id, value)
    );
    CREATE INDEX IF NOT EXISTS idx_list_entries_lookup ON list_entries(kind, list, value);
    CREATE INDEX IF NOT EXISTS idx_active_bans_target ON active_bans(target);
    CREATE INDEX IF NOT EXISTS idx_active_bans_expires ON active_bans(expires_at);
    -- How many times an address has been banned before, so repeat offenders
    -- can be escalated without keeping every expired ban row forever.
    CREATE TABLE IF NOT EXISTS ban_history (
      target     TEXT PRIMARY KEY,
      count      INTEGER NOT NULL DEFAULT 0,
      last_ban   TEXT,
      last_source TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_request_log_ts ON request_log(ts DESC);
    -- Almost every analytics query is "blocked requests in a time window":
    -- the stats tiles, the attack-type breakdown, the severity split and the
    -- attack map all share that shape. On a ts-only index each of them scans
    -- the whole window and discards the passes.
    CREATE INDEX IF NOT EXISTS idx_request_log_action_ts ON request_log(action, ts DESC);
    -- Top-attacker aggregation groups by ip within blocked rows.
    CREATE INDEX IF NOT EXISTS idx_request_log_action_ip ON request_log(action, ip);
    -- Every audit read and the retention sweep order by ts.
    CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts DESC);
    CREATE INDEX IF NOT EXISTS idx_snapshots_ts ON snapshots(ts DESC);
  `)

  migrateColumns(instance, 'request_log', {
    severity: 'TEXT',
    reason: 'TEXT',
    matched_var: 'TEXT',
    country_code: 'TEXT',
    city: 'TEXT',
    lat: 'REAL',
    lon: 'REAL',
  })

  return instance
}

const SAFE_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/
const SAFE_COLUMN_TYPE = /^(TEXT|INTEGER|REAL|BLOB|NUMERIC)$/

function migrateColumns(instance, table, columns) {
  if (!SAFE_IDENTIFIER.test(table)) throw new Error(`Unsafe table identifier: ${table}`)
  const existing = instance.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name)
  for (const [name, type] of Object.entries(columns)) {
    if (!SAFE_IDENTIFIER.test(name)) throw new Error(`Unsafe column identifier: ${name}`)
    if (!SAFE_COLUMN_TYPE.test(type)) throw new Error(`Unsafe column type: ${type}`)
    if (!existing.includes(name)) {
      instance.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${type}`)
    }
  }
}

let access = require('./databaseAccess').open(DB_PATH)
let db = openDb(DB_PATH)

function getState(key) {
  const row = db.prepare('SELECT value FROM waf_state WHERE key = ?').get(key)
  if (!row) return null
  try { return JSON.parse(row.value) } catch { return null }
}
// Authentication state must distinguish absent data from damaged JSON.
function getStateStrict(key) {
  const row = db.prepare('SELECT value FROM waf_state WHERE key = ?').get(key)
  if (!row) return null
  const value = JSON.parse(row.value)
  if (value === null) throw new Error(`Invalid null state: ${key}`)
  return value
}
function setState(key, value) {
  db.prepare('INSERT OR REPLACE INTO waf_state (key, value) VALUES (?, ?)').run(key, JSON.stringify(value))
}

function switchDb(newPath) {
  db.close()
  access.close()
  access = require('./databaseAccess').open(newPath)
  db = openDb(newPath)
  DB_PATH = newPath
  return db
}

function withOfflineAccess(fn) {
  return access.exclusive(() => {
    db.close()
    try { return fn(DB_PATH) }
    finally { db = openDb(DB_PATH) }
  })
}

module.exports = {
  getDb: () => db,
  getState, getStateStrict, setState, switchDb, withOfflineAccess,
  get DB_PATH() { return DB_PATH },
  DB_DIR,
}
