// Native Caddy/Coraza is required. All services, files and listeners are disposable.
const test = require('node:test'), assert = require('node:assert/strict')
const fs = require('fs'), os = require('os'), path = require('path'), http = require('http')
const { once } = require('events'), { spawn, execFile } = require('child_process'), { promisify } = require('util')
const exec = promisify(execFile)
async function listen(s) { s.listen(0,'127.0.0.1'); await once(s,'listening'); return s.address().port }
function request(port, host, uri, { method='GET', headers={}, body }={}) {
  return new Promise((resolve,reject) => {
    const req=http.request({hostname:'127.0.0.1',port,path:uri,method,agent:false,headers:{host,'user-agent':'parity-browser',...headers},signal:AbortSignal.timeout(8000)},res=>{
      let data=''; res.on('data',b=>{data+=b}); res.on('error',reject); res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,body:data}))
    }); req.on('error',reject); req.end(body)
  })
}
test('managed host/path routing, reload, WAF, bans and challenge flows through the native proxy', {timeout:90000}, async t=>{
  assert.match((await exec('caddy',['list-modules'])).stdout,/http\.handlers\.waf/)
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cw-orchestrator-'))
  let proc; const servers=[]
  t.after(async()=>{
    if(proc && proc.exitCode===null && proc.signalCode===null) { const ended=once(proc,'exit'); proc.kill('SIGTERM'); await ended }
    for(const server of servers) { server.closeAllConnections(); await new Promise(r=>server.close(r)) }
    console.log('Orchestration fixture evidence: '+dir)
  })
  const a=http.createServer((req,res)=>{res.setHeader('Content-Type','text/plain');res.end('origin-a')})
  const b=http.createServer((req,res)=>{res.setHeader('Content-Type','text/plain');res.end('origin-b')})
  servers.push(a,b); const aPort=await listen(a),bPort=await listen(b)
  const reserve=http.createServer(); const port=await listen(reserve); await new Promise(r=>reserve.close(r))
  const tlsPort=await listen(reserve); await new Promise(r=>reserve.close(r))
  const api=http.createServer(); servers.push(api); const apiPort=await listen(api)
  Object.assign(process.env,{DB_DIR:dir,DB_PATH:path.join(dir,'fixture.db'),CADDYFILE_PATH:path.join(dir,'Caddyfile'),CORAZA_AUDIT_LOG:path.join(dir,'audit.json'),CADDY_ADMIN_SOCKET:path.join(dir,'admin.sock'),JWT_SECRET:'orchestration-fixture-'.repeat(4),CATWAF_INTERNAL_HOST:'127.0.0.1',PORT:String(apiPort),XDG_DATA_HOME:path.join(dir,'data'),XDG_CONFIG_HOME:path.join(dir,'config')})
  fs.writeFileSync(process.env.CORAZA_AUDIT_LOG,'')
  fs.writeFileSync(process.env.CADDYFILE_PATH,`{\n admin unix/${process.env.CADDY_ADMIN_SOCKET}\n http_port ${port}\n https_port ${tlsPort}\n auto_https off\n order coraza_waf first\n}\nhttp://fixture.invalid {\n respond "fixture"\n}\n`)
  const settings=require('../backend/services/settings'), managed=require('../backend/services/managedRoutes'), caddy=require('../backend/services/caddy'), tx=require('../backend/services/configTx'), state=require('../backend/services/state')
  const express=require('express'), app=express(); app.use(express.json()); app.use(require('../backend/routes/gateway')); api.on('request',app)
  assert.equal(settings.set('sites',{max_sites:10}).ok,true)
  const base={id:'docker/app',host:'app.example.test',path:'/foo',pathType:'Prefix',upstream:'127.0.0.1:'+aPort}
  const preview=managed.reconcile('docker',[base,{...base,id:'docker/exact',pathType:'Exact',upstream:'127.0.0.1:'+bPort}])
  assert.equal(preview.ok,true,JSON.stringify(preview))
  const kube={id:'default/web',host:'ingress.example.test',path:'/bar',pathType:'Prefix',upstream:'127.0.0.1:'+bPort}
  assert.equal(managed.reconcile('kubernetes',[kube]).ok,true)
  const fd=fs.openSync(path.join(dir,'caddy.log'),'w')
  proc=spawn('caddy',['run','--config',process.env.CADDYFILE_PATH],{stdio:['ignore',fd,fd]});fs.closeSync(fd)
  for(let i=0;i<80;i++){try{if((await request(port,base.host,'/foo')).status===200)break}catch{}await new Promise(r=>setTimeout(r,100))}
  assert.equal((await request(port,base.host,'/foo')).body,'origin-b','Exact wins over Prefix at the same path')
  assert.equal((await request(port,base.host,'/foo/child')).body,'origin-a')
  assert.equal((await request(port,base.host,'/foobar')).status,404,'Prefix is path-segment bounded')
  assert.equal((await request(port,kube.host,'/bar')).body,'origin-b')
  assert.equal((await request(port,kube.host,'/bar?id=1%20UNION%20SELECT%201,2,3--')).status,403,'CRS remains enabled on ingress routes')
  const updated=managed.reconcile('docker',[{...base,upstream:'127.0.0.1:'+bPort}])
  assert.equal(updated.ok,true,JSON.stringify(updated));assert.equal(updated.reloaded,true)
  assert.equal((await request(port,base.host,'/foo/child')).body,'origin-b')
  const removed=managed.reconcile('docker',[])
  assert.equal(removed.ok,true,JSON.stringify(removed))
  assert.notEqual((await request(port,base.host,'/foo')).status,200)
  assert.equal((await request(port,kube.host,'/bar')).body,'origin-b','Docker deletion preserves Kubernetes ownership')
  const crypto=require('crypto'), https=require('https')
  const tlsHost='tls.example.test'
  async function cert(name) {
    const key=path.join(dir,name+'.key'),file=path.join(dir,name+'.crt')
    await exec('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',key,'-out',file,'-subj','/CN='+tlsHost,'-addext','subjectAltName=DNS:'+tlsHost])
    const pair={cert:fs.readFileSync(file,'utf8'),key:fs.readFileSync(key,'utf8')}
    return {pair,ref:crypto.createHash('sha256').update(pair.cert).update(pair.key).digest('hex')}
  }
  function tlsRequest(pair) {
    return new Promise((resolve,reject)=>{
      const req=https.get({hostname:'127.0.0.1',port:tlsPort,servername:tlsHost,ca:pair.cert,agent:false,headers:{host:tlsHost,'user-agent':'parity-browser'},signal:AbortSignal.timeout(8000)},res=>{
        let body='';const fingerprint=res.socket.getPeerCertificate().fingerprint256
        res.on('data',b=>{body+=b});res.on('error',reject);res.on('end',()=>resolve({status:res.statusCode,body,fingerprint}))
      });req.on('error',reject)
    })
  }
  const first=await cert('first'), second=await cert('second')
  const tlsRoute={...kube,id:'default/tls',host:tlsHost,path:'/',tls:'secret',tlsRef:first.ref}
  let changed=managed.reconcile('kubernetes',[kube,tlsRoute],{certificates:{[first.ref]:first.pair}})
  assert.equal(changed.ok,true,JSON.stringify(changed))
  assert.equal((await tlsRequest(first.pair)).body,'origin-b')
  // Failed rotations must leave both served certificate and persisted refs intact.
  const validate=tx.validateCaddyfile
  try {
    tx.validateCaddyfile=()=>({ok:false,error:'injected TLS rotation validation failure'})
    const failed=managed.reconcile('kubernetes',[kube,{...tlsRoute,tlsRef:second.ref}],{certificates:{[second.ref]:second.pair}})
    assert.equal(failed.ok,false);assert.equal(failed.rolledBack,true)
    assert.equal(managed.read().kubernetes.routes.find(r=>r.id===tlsRoute.id).tlsRef,first.ref)
    assert.equal((await tlsRequest(first.pair)).status,200)
  } finally {tx.validateCaddyfile=validate}
  changed=managed.reconcile('kubernetes',[kube,{...tlsRoute,tlsRef:second.ref}],{certificates:{[second.ref]:second.pair}})
  assert.equal(changed.ok,true,JSON.stringify(changed))
  assert.equal((await tlsRequest(second.pair)).fingerprint,new crypto.X509Certificate(second.pair.cert).fingerprint256)
  // A manual ban must work even with all optional runtime features off.
  const bans=require('../backend/services/bans')
  assert.equal(require('../backend/services/enforce').isActive(),false)
  const firstBan=bans.addManual({target:'127.0.0.1',seconds:60,reason:'first manual ban'})
  assert.equal(firstBan.ok,true,JSON.stringify(firstBan));assert.equal(firstBan.reloaded,true)
  assert.equal((await request(port,kube.host,'/bar')).status,403)
  bans.lift(firstBan.ban.id)
  assert.equal((await request(port,kube.host,'/bar')).body,'origin-b')
  const enforce=require('../backend/services/enforce'), evaluate=enforce.evaluate
  try {
    enforce.evaluate=async()=>{throw new Error('injected private failure')}
    const failed=await request(port,kube.host,'/bar')
    assert.equal(failed.status,503);assert.doesNotMatch(failed.body,/injected private/)
  } finally {enforce.evaluate=evaluate}
  const enabled=tx.apply({label:'fixture.challenge',mutate:()=>settings.set('challenge',{mode:'cookie',trigger:'all',exempt_paths:[]})})
  assert.equal(enabled.ok,true,JSON.stringify(enabled))
  assert.equal((await request(port,kube.host,'/bar')).status,302)
  const page=await request(port,kube.host,'/catwaf-challenge?return_to=%2Fbar')
  assert.equal(page.status,503)
  const id=page.body.match(/name="challenge_id" value="([a-f0-9]+)"/)[1]
  const pending=page.headers['set-cookie'][0].split(';')[0]
  const solved=await request(port,kube.host,'/catwaf-challenge/verify',{method:'POST',headers:{cookie:pending,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({challenge_id:id,return_to:'/bar'}).toString()})
  assert.equal(solved.status,303,solved.body)
  const cookie=solved.headers['set-cookie'][0].split(';')[0]
  assert.equal((await request(port,kube.host,'/bar',{headers:{cookie}})).body,'origin-b')
  const ban=require('../backend/services/bans').ban({target:'127.0.0.1',source:'manual',seconds:60,reason:'fixture ban'})
  assert.ok(ban)
  assert.equal((await request(port,kube.host,'/bar',{headers:{cookie}})).status,403,'manual ban wins over solved challenge')
  assert.equal(state.WAF.engine,'On')
})
