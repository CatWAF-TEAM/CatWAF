#!/usr/bin/env node
// Disposable integration test. Requires local Linux Docker, Caddy/Coraza and
// permission to share a temporary bind directory with the non-root bridge.
const fs=require('fs'), os=require('os'), path=require('path'), http=require('http')
const {spawn,execFile}=require('child_process'), {promisify}=require('util'), {once}=require('events'), assert=require('assert/strict')
const exec=promisify(execFile)
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cw-docker-autoconf-'))
const name='cw-free-fixture-'+process.pid, network=name+'-net', bridge=name+'-metadata', app=name+'-app'
const prefix='cw_fixture_'+process.pid, image=process.env.CATWAF_METADATA_IMAGE || 'catwaf-metadata:test'
const dockerSocket=process.env.CATWAF_TEST_DOCKER_SOCKET || '/var/run/docker.sock'
const metadata=path.join(dir,'metadata');fs.mkdirSync(metadata);fs.chmodSync(metadata,0o777)
Object.assign(process.env,{DB_DIR:dir,CADDYFILE_PATH:path.join(dir,'Caddyfile'),CADDY_ADMIN_SOCKET:path.join(dir,'admin.sock'),CORAZA_AUDIT_LOG:path.join(dir,'audit.json'),JWT_SECRET:'docker-test-'.repeat(8),CATWAF_DOCKER_METADATA_SOCKET:path.join(metadata,'metadata.sock')})
const docker=(...args)=>exec('docker',['--host','unix://'+dockerSocket,...args],{timeout:60000,maxBuffer:8*1024*1024})
let proc, createdNetwork=false, createdBridge=false, createdApp=false
async function request(port,uri='/') {
  return new Promise((resolve,reject)=>{
    const req=http.get({hostname:'127.0.0.1',port,path:uri,headers:{host:'docker.example.test','user-agent':'fixture-browser'},agent:false,signal:AbortSignal.timeout(5000)},res=>{
      let body='';res.on('data',b=>{body+=b});res.on('end',()=>resolve({status:res.statusCode,body}));res.on('error',reject)
    });req.on('error',reject)
  })
}
async function runApp(version) {
  await docker('run','-d','--name',app,'--network',network,'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true',
    '--label',prefix+'.enable=true','--label',prefix+'.host=docker.example.test','--label',prefix+'.port=3000','--label',prefix+'.network='+network,
    image,'node','-e',`require('http').createServer((q,s)=>{s.setHeader('content-type','text/plain');s.end('origin-${version}')}).listen(3000,'0.0.0.0')`)
  createdApp=true
}
async function main() {
  assert.equal(process.platform,'linux')
  assert.match((await exec('caddy',['list-modules'])).stdout,/http\.handlers\.waf/)
  const reserve=http.createServer();reserve.listen(0,'127.0.0.1');await once(reserve,'listening');const port=reserve.address().port;await new Promise(r=>reserve.close(r))
  fs.writeFileSync(process.env.CORAZA_AUDIT_LOG,'')
  fs.writeFileSync(process.env.CADDYFILE_PATH,`{\n admin unix/${process.env.CADDY_ADMIN_SOCKET}\n http_port ${port}\n auto_https off\n order coraza_waf first\n}\nhttp://fixture.invalid {\n respond 404\n}\n`)
  await docker('network','create','--internal',network);createdNetwork=true
  await docker('run','-d','--name',bridge,'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true',
    '--group-add',String(fs.statSync(dockerSocket).gid),'-e','CATWAF_LABEL_PREFIX='+prefix,
    '--mount','type=bind,source='+dockerSocket+',target=/var/run/docker.sock,readonly',
    '--mount','type=bind,source='+metadata+',target=/run/catwaf-discovery',image)
  createdBridge=true
  await runApp('one')
  const settings=require('../backend/services/settings'), auto=require('../backend/services/autoconf'), managed=require('../backend/services/managedRoutes')
  assert.equal(settings.set('autoconf',{enabled:true,label_prefix:prefix,network,remove_orphans:true}).ok,true)
  let result
  for(let i=0;i<40;i++) {result=await auto.scan({dryRun:false});if(result.ok)break;await new Promise(r=>setTimeout(r,100))}
  assert.equal(result.ok,true,JSON.stringify(result));assert.equal(result.routes.length,1)
  const firstId=result.routes[0].id
  const log=fs.openSync(path.join(dir,'caddy.log'),'w');proc=spawn('caddy',['run','--config',process.env.CADDYFILE_PATH],{stdio:['ignore',log,log]});fs.closeSync(log)
  for(let i=0;i<60;i++){try{if((await request(port)).body==='origin-one')break}catch{}await new Promise(r=>setTimeout(r,100))}
  assert.equal((await request(port)).body,'origin-one')
  assert.equal((await request(port,'/?id=1%20UNION%20SELECT%201,2,3--')).status,403)
  console.log('PASS real Docker labels produce a live WAF-protected route')
  await docker('stop','-t','1',bridge)
  assert.equal((await auto.scan({dryRun:false})).ok,false)
  assert.equal(managed.allRoutes()[0].id,firstId)
  assert.equal((await request(port)).body,'origin-one')
  await docker('start',bridge)
  console.log('PASS metadata outage preserves routes and origin availability')
  await docker('rm','-f',app);createdApp=false
  await runApp('two')
  result=await auto.scan({dryRun:false})
  assert.equal(result.ok,true,JSON.stringify(result));assert.equal(result.reloaded,true);assert.equal(result.routes.length,1);assert.notEqual(result.routes[0].id,firstId)
  assert.equal((await request(port)).body,'origin-two')
  console.log('PASS container recreation replaces its upstream without stale duplicate routes')
  await docker('rm','-f',app);createdApp=false
  result=await auto.scan({dryRun:false})
  assert.equal(result.ok,true,JSON.stringify(result));assert.equal(result.routes.length,0);assert.equal((await request(port)).status,404)
  console.log('PASS deletion removes the managed route')
  const cfg=JSON.parse((await docker('inspect',bridge)).stdout)[0]
  assert.equal(cfg.Config.User,'65532:65532');assert.equal(cfg.HostConfig.NetworkMode,'none');assert.equal(cfg.HostConfig.ReadonlyRootfs,true)
  assert.ok(cfg.HostConfig.CapDrop.includes('ALL'));assert.ok(cfg.HostConfig.SecurityOpt.includes('no-new-privileges:true'))
  console.log('PASS bridge runs non-root with no TCP network, read-only root and no capabilities')
}
main().catch(e=>{console.error(e.stack||e);process.exitCode=1}).finally(async()=>{
  if(proc&&proc.exitCode===null&&proc.signalCode===null){const ended=once(proc,'exit');proc.kill();await ended}
  if(createdApp)await docker('rm','-f',app).catch(e=>{console.error('fixture app cleanup failed:',e.message);process.exitCode=1})
  if(createdBridge)await docker('rm','-f',bridge).catch(e=>{console.error('fixture bridge cleanup failed:',e.message);process.exitCode=1})
  if(createdNetwork)await docker('network','rm',network).catch(e=>{console.error('fixture network cleanup failed:',e.message);process.exitCode=1})
  console.log('Fixture evidence: '+dir)
})
