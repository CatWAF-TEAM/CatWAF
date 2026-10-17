const test = require('node:test'), assert = require('node:assert/strict')
const fs = require('fs'), path = require('path'), os = require('os'), https = require('https'), http = require('http')
const { once } = require('events'), { execFileSync, spawn } = require('child_process')
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-controller-client-'))
Object.assign(process.env, { DB_DIR: dir, JWT_SECRET: 'client-fixture-'.repeat(6) })
const k8s = require('../backend/services/kubernetes')
function certificate(name, san) {
  const key = path.join(dir, name + '.key'), cert = path.join(dir, name + '.crt')
  execFileSync('openssl', ['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',key,'-out',cert,'-subj','/CN='+name,'-addext','subjectAltName='+san], {stdio:'ignore'})
  return { key: fs.readFileSync(key), cert: fs.readFileSync(cert), caPath: cert }
}
test('Kubernetes transport verifies CA, rotates credentials, bounds lists and refuses bad TLS Secrets', async t => {
  const pair = certificate('api', 'IP:127.0.0.1'), appPair = certificate('web', 'DNS:web.example.test')
  const token = path.join(dir,'token'); fs.writeFileSync(token, 'one')
  let status = 200, page = 0; const authorization = []
  const server = https.createServer(pair, (req,res) => {
    authorization.push(req.headers.authorization)
    if (status !== 200) { res.writeHead(status); return res.end('{}') }
    res.setHeader('content-type','application/json')
    if (req.url.startsWith('/pages')) return res.end(JSON.stringify({items:[{page:page++}],metadata:{continue:page<2?'next':''}}))
    if (req.url.startsWith('/repeat')) return res.end(JSON.stringify({items:[],metadata:{continue:'same'}}))
    if (req.url.startsWith('/large')) return res.end(JSON.stringify({items:Array(1001).fill({}),metadata:{}}))
    res.end(JSON.stringify({items:[],metadata:{}}))
  })
  server.listen(0,'127.0.0.1'); await once(server,'listening')
  t.after(async()=>{server.closeAllConnections();await new Promise(r=>server.close(r))})
  Object.assign(process.env,{CATWAF_K8S_API:'https://127.0.0.1:'+server.address().port,CATWAF_K8S_TOKEN_FILE:token,CATWAF_K8S_CA_FILE:pair.caPath})
  const api = k8s.client()
  assert.deepEqual(await k8s.list(api,'/pages'),[{page:0},{page:1}])
  fs.writeFileSync(token,'two'); await api.get('/empty')
  assert.equal(authorization.at(-1),'Bearer two')
  assert.equal(authorization[0],'Bearer one')
  await assert.rejects(()=>k8s.list(api,'/repeat'),/Repeated/)
  await assert.rejects(()=>k8s.list(api,'/large'),/limit exceeded/)
  await assert.rejects(()=>api.get('https://other.example/path'),/origin/)
  status = 403; await assert.rejects(()=>api.get('/empty'),/403/)
  status = 302; await assert.rejects(()=>api.get('/empty'),/302/)
  status = 200; process.env.CATWAF_K8S_CA_FILE = appPair.caPath
  await assert.rejects(()=>api.get('/empty'),/self-signed|certificate/i)
  const secret={type:'kubernetes.io/tls',data:{'tls.crt':appPair.cert.toString('base64'),'tls.key':appPair.key.toString('base64')}}
  assert.equal(k8s.tlsPair(secret,'web.example.test').cert,appPair.cert.toString())
  assert.throws(()=>k8s.tlsPair(secret,'other.example.test'),/does not match/)
  assert.throws(()=>k8s.tlsPair(secret,'*.example.test'),/does not match/)
  const wild=certificate('wild','DNS:*.example.test')
  const wildSecret={type:'kubernetes.io/tls',data:{'tls.crt':wild.cert.toString('base64'),'tls.key':wild.key.toString('base64')}}
  assert.equal(k8s.tlsPair(wildSecret,'*.example.test').cert,wild.cert.toString())
  assert.throws(()=>k8s.tlsPair({...secret,data:{...secret.data,'tls.key':pair.key.toString('base64')}},'web.example.test'),/does not match/)
  assert.throws(()=>k8s.tlsPair({...secret,type:'Opaque'},'web.example.test'),/kubernetes.io\/tls/)
})

function socketRequest(socketPath, method, url) {
  return new Promise((resolve,reject)=>{
    const req=http.request({socketPath,method,path:url,signal:AbortSignal.timeout(7000)},res=>{
      let data='';res.on('data',b=>{data+=b});res.on('end',()=>resolve({status:res.statusCode,body:data?JSON.parse(data):null}));res.on('error',reject)
    });req.on('error',reject);req.end()
  })
}
test('Docker metadata bridge permits one fixed read and strips unrelated inventory fields', async t=>{
  const engine=path.join(dir,'engine.sock'), socket=path.join(dir,'metadata.sock')
  let calls=0, status=200
  const docker=http.createServer((req,res)=>{
    calls++; assert.equal(req.method,'GET'); assert.equal(req.url,'/v1.45/containers/json?all=false')
    res.writeHead(status,{'content-type':'application/json'})
    res.end(JSON.stringify([{Id:'a'.repeat(64),Names:['/fixture'],State:'running',Env:['SECRET=do-not-export'],Mounts:[{Source:'/private'}],Labels:{'catwaf.enable':'true','unrelated.secret':'do-not-export'},NetworkSettings:{Networks:{edge:{IPAddress:'172.19.0.5',Gateway:'172.19.0.1'}}}}]))
  });docker.listen(engine);await once(docker,'listening')
  const proc=spawn(process.execPath,[path.join(__dirname,'../scripts/docker-metadata.js')],{env:{...process.env,CATWAF_METADATA_LISTEN:socket,CATWAF_METADATA_DOCKER_SOCKET:engine},stdio:'pipe'})
  t.after(async()=>{
    if(proc.exitCode===null&&proc.signalCode===null){const ended=once(proc,'exit');proc.kill();await ended}
    docker.closeAllConnections();await new Promise(r=>docker.close(r))
  })
  for(let i=0;i<100&&!fs.existsSync(socket);i++)await new Promise(r=>setTimeout(r,20))
  const result=await socketRequest(socket,'GET','/containers')
  assert.equal(result.status,200)
  assert.deepEqual(result.body,[{id:'a'.repeat(64),name:'fixture',running:true,labels:{'catwaf.enable':'true'},networks:{edge:{IPAddress:'172.19.0.5'}}}])
  assert.equal((await socketRequest(socket,'POST','/containers')).status,404)
  assert.equal((await socketRequest(socket,'GET','/containers?all=true')).status,404)
  assert.equal((await socketRequest(socket,'GET','/v1.45/containers/fixture/json')).status,404)
  assert.equal(calls,1,'rejected paths must never reach the engine')
  status=500;assert.equal((await socketRequest(socket,'GET','/containers')).status,502)
  status=200;assert.equal((await socketRequest(socket,'GET','/containers')).status,200,'bridge recovers after an upstream error')
})
