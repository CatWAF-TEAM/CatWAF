const test = require('node:test'), assert = require('node:assert/strict')
const fs = require('fs'), path = require('path'), os = require('os')
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-writer-proof-'))
const base = path.join(dir, 'audit.json'), archive = path.join(dir, 'audit-20260101T000000Z.json')
Object.assign(process.env, { DB_DIR: dir, CADDYFILE_PATH: path.join(dir,'Caddyfile'), CORAZA_AUDIT_LOG: base, JWT_SECRET: 'writer-fixture-'.repeat(8) })
fs.writeFileSync(base,'');fs.writeFileSync(process.env.CADDYFILE_PATH,'# SecAuditLog '+base+'\n')
const writers = require('../backend/services/auditWriters'), audit = require('../backend/services/auditLog')
const logs = require('../backend/services/requestLog'), db = require('../backend/services/db')
test.after(() => { db.getDb().close(); fs.rmSync(dir, {recursive:true,force:true}) })
const entry = id => JSON.stringify({ transaction: { id, client_ip:'198.51.100.2', request:{method:'GET',uri:'/writer-'+id},response:{status:500} } })+'\n'
function seed(text) { fs.writeFileSync(archive,text);fs.utimesSync(archive,new Date(0),new Date(0)) }

test('writer inventory identifies a live writable descriptor and observes its close', () => {
  assert.equal(process.platform,'linux','writer lifetime checks require real Linux descriptors')
  const fd = fs.openSync(archive,'a'), id = writers.identity(fs.fstatSync(fd,{bigint:true}))
  assert(writers.processWriters(process.pid).includes(id));fs.closeSync(fd)
  assert(!writers.processWriters(process.pid).includes(id))
})
test('retention defers on missing proof, live writers, incomplete records and database failure', () => {
  const original = writers.snapshot, drain = logs.drainFile
  try {
    seed(entry('first'))
    writers.snapshot = () => ({ok:false,error:'observer unavailable'})
    assert.equal(audit.prune({}).deleted.length,0);assert(fs.existsSync(archive))
    writers.snapshot = () => ({ok:true,writers:new Set([writers.identity(fs.statSync(archive,{bigint:true}))])})
    assert.equal(audit.prune({}).deleted.length,0);assert(fs.existsSync(archive))
    writers.snapshot = () => ({ok:true,writers:new Set()})
    seed(entry('partial').trimEnd())
    assert.equal(audit.prune({}).deleted.length,0);assert(fs.existsSync(archive))
    seed(entry('complete'))
    logs.drainFile = () => {throw new Error('database unavailable')}
    assert.equal(audit.prune({}).failed.length,1);assert(fs.existsSync(archive))
    logs.drainFile = drain
    assert.equal(audit.prune({}).deleted.length,1);assert(!fs.existsSync(archive))
  } finally { writers.snapshot=original;logs.drainFile=drain }
})
test('late archive appends and active-file appends have independent restart-safe cursors', () => {
  seed(entry('old'));fs.writeFileSync(base,entry('new'))
  assert.equal(logs.ingestNewEntries().ingested,2)
  fs.appendFileSync(archive,entry('late'));fs.appendFileSync(base,entry('current'))
  assert.equal(logs.ingestNewEntries().ingested,2)
  assert.equal(logs.ingestNewEntries().ingested,0)
  logs._resetOffsetForTests();logs.ingestNewEntries()
  for (const id of ['old','new','late','current']) assert.equal(db.getDb().prepare('SELECT COUNT(*) AS n FROM request_log WHERE uri=?').get('/writer-'+id).n,1)
})

test('an inaccessible archive is a drain failure, never a missing-file success', () => {
  const original = fs.statSync
  fs.statSync = function(file, ...args) {
    if (file === archive) throw Object.assign(new Error('permission denied'), {code:'EACCES'})
    return original.call(this, file, ...args)
  }
  try { assert.throws(() => logs.drainFile(archive), {code:'EACCES'}) }
  finally { fs.statSync = original }
})
