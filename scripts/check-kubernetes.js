#!/usr/bin/env node
// Requires an EMPTY disposable kind-catwaf-* cluster and locally loaded images.
// Never changes the default kubeconfig. No host ports or production resources.
const fs=require('fs'),path=require('path'),os=require('os'),crypto=require('crypto'),http=require('http'),https=require('https')
const assert=require('assert/strict'),yaml=require('js-yaml'),{execFile,spawn}=require('child_process'),{promisify}=require('util')
const exec=promisify(execFile),root=path.resolve(__dirname,'..'),dir=fs.mkdtempSync(path.join(os.tmpdir(),'cw-k8s-'))
const kube=process.env.CATWAF_K8S_TEST_KUBECONFIG,bin=process.env.KUBECTL||'kubectl'
assert(kube,'Set CATWAF_K8S_TEST_KUBECONFIG to a disposable kind cluster')
const backendImage=process.env.CATWAF_K8S_BACKEND_IMAGE||'catwaf-backend:k8s-test'
const caddyImage=process.env.CATWAF_K8S_CADDY_IMAGE||'catwaf-caddy:k8s-test'
const k=(...args)=>exec(bin,['--kubeconfig',kube,...args],{timeout:240000,maxBuffer:4*1024*1024})
const pause=ms=>new Promise(r=>setTimeout(r,ms)),results=[]
let forward,owned=false,port,tlsPort,serial=0
async function apply(objects){const f=path.join(dir,'apply-'+(++serial)+'.json');fs.writeFileSync(f,JSON.stringify({apiVersion:'v1',kind:'List',items:objects}),{mode:0o600});await k('apply','-f',f)}
async function node(code){const r=await k('-n','catwaf','exec','deploy/catwaf','-c','backend','--','node','--experimental-sqlite','-e',code);const line=r.stdout.split('\n').find(x=>x.startsWith('RESULT '));assert(line,r.stdout);return JSON.parse(line.slice(7))}
const scan=()=>node("require('./backend/services/kubernetes').scan({dryRun:false}).then(r=>console.log('RESULT '+JSON.stringify(r)))")
function request(uri='/',ca){return new Promise((resolve,reject)=>{const r=(ca?https:http).get({hostname:'127.0.0.1',port:ca?tlsPort:port,path:uri,headers:{Host:'web.example.test'},servername:'web.example.test',ca,agent:false,signal:AbortSignal.timeout(30000)},s=>{let body='';const fingerprint=s.socket.getPeerCertificate?.().fingerprint256;s.on('data',d=>body+=d);s.on('error',reject);s.on('end',()=>resolve({status:s.statusCode,body,fingerprint}))});r.on('error',reject)})}
async function until(check,seconds=90){let last;for(let i=0;i<seconds;i++){try{if(await check())return}catch(e){last=e.message}await pause(1000)}throw new Error('Readiness/consistency deadline exceeded'+(last?': '+last:''))}
async function check(name,fn){await fn();results.push({name,ok:true});console.log('PASS '+name)}
async function certificate(name,host='web.example.test'){
  const key=path.join(dir,name+'.key'),cert=path.join(dir,name+'.crt')
  await exec('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',key,'-out',cert,'-subj','/CN='+host,'-addext','subjectAltName=DNS:'+host])
  const pem=fs.readFileSync(cert),privateKey=fs.readFileSync(key)
  return {pem,fingerprint:new crypto.X509Certificate(pem).fingerprint256,secret:{apiVersion:'v1',kind:'Secret',metadata:{name:'app-tls',namespace:'catwaf'},type:'kubernetes.io/tls',data:{'tls.crt':pem.toString('base64'),'tls.key':privateKey.toString('base64')}}}
}
async function startForward(){
  port=0;tlsPort=0
  forward=spawn(bin,['--kubeconfig',kube,'-n','catwaf','port-forward','svc/catwaf',':80',':443','--address','127.0.0.1'],{stdio:['ignore','pipe','pipe']})
  let output='';forward.stdout.on('data',d=>{output+=d;port=Number(output.match(/127\.0\.0\.1:(\d+) -> 8080/)?.[1]);tlsPort=Number(output.match(/127\.0\.0\.1:(\d+) -> 8443/)?.[1])})
  forward.stderr.on('data',d=>{output+=d})
  await until(()=>port&&tlsPort,30)
}
const security={runAsNonRoot:true,runAsUser:10110,runAsGroup:10110,readOnlyRootFilesystem:true,allowPrivilegeEscalation:false,capabilities:{drop:['ALL']}}
function app(version){return {apiVersion:'apps/v1',kind:'Deployment',metadata:{name:'origin',namespace:'catwaf'},spec:{replicas:1,selector:{matchLabels:{app:'origin'}},template:{metadata:{labels:{app:'origin'}},spec:{automountServiceAccountToken:false,securityContext:{seccompProfile:{type:'RuntimeDefault'}},containers:[{name:'origin',image:backendImage,imagePullPolicy:'Never',command:['node','-e',`require('http').createServer((q,s)=>{s.setHeader('Content-Type','text/plain');if(q.url==='/slow-audit'){s.statusCode=500;s.write('start');setTimeout(()=>s.end('finish'),15000)}else s.end('${version}')}).listen(3000,'0.0.0.0')`],securityContext:security,resources:{requests:{cpu:'10m',memory:'32Mi'},limits:{cpu:'1',memory:'128Mi'}}}]}}}}}
const ingress={apiVersion:'networking.k8s.io/v1',kind:'Ingress',metadata:{name:'web',namespace:'catwaf'},spec:{ingressClassName:'catwaf',tls:[{hosts:['web.example.test'],secretName:'app-tls'}],rules:[{host:'web.example.test',http:{paths:[{path:'/',pathType:'Prefix',backend:{service:{name:'origin',port:{name:'http'}}}}]}}]}}
async function main(){
  assert((await k('config','current-context')).stdout.trim().startsWith('kind-catwaf-'),'Refusing a non-disposable cluster context')
  for(const [kind,name] of [['namespace','catwaf'],['ingressclass','catwaf'],['clusterrole','catwaf-ingress-class'],['clusterrolebinding','catwaf-ingress-class']]) assert.equal((await k('get',kind,name,'--ignore-not-found','-o','name')).stdout.trim(),'','Fixture resource already exists: '+kind+'/'+name)
  const manifests=yaml.loadAll(fs.readFileSync(path.join(root,'deploy/kubernetes/catwaf.yaml'),'utf8')).filter(Boolean)
  const deployment=manifests.find(x=>x.kind==='Deployment')
  for(const c of [...deployment.spec.template.spec.initContainers,...deployment.spec.template.spec.containers]){c.image=c.name==='caddy'?caddyImage:backendImage;c.imagePullPolicy='Never'}
  const first=await certificate('first'),second=await certificate('second'),bad=await certificate('invalid','wrong.example.test')
  await apply([manifests.find(x=>x.kind==='Namespace')]);owned=true
  await apply([{apiVersion:'v1',kind:'Secret',metadata:{name:'catwaf-secrets',namespace:'catwaf'},stringData:{JWT_SECRET:crypto.randomBytes(32).toString('hex')}},first.secret])
  await apply(manifests)
  await apply([app('origin-one'),{apiVersion:'v1',kind:'Service',metadata:{name:'origin',namespace:'catwaf'},spec:{selector:{app:'origin'},ports:[{name:'http',port:8080,targetPort:3000}]}}])
  await k('-n','catwaf','rollout','status','deploy/catwaf','--timeout=180s');await k('-n','catwaf','rollout','status','deploy/origin','--timeout=180s')
  await check('non-root deployment and private writer observer are healthy',async()=>{
    const status=await node("const w=require('./backend/services/auditWriters').snapshot();console.log('RESULT '+JSON.stringify({uid:process.getuid(),writersOk:w.ok,error:w.error}))")
    assert.equal(status.uid,10100);assert.equal(status.writersOk,true,status.error)
  })
  await check('actual controller credentials cannot read Secrets or other namespaces',async()=>{
    const result=await node("const k=require('./backend/services/kubernetes').client();Promise.all(['/api/v1/namespaces/catwaf/secrets/app-tls','/api/v1/namespaces/default/services'].map(p=>k.get(p).then(()=>false,e=>/403/.test(e.message)))).then(r=>console.log('RESULT '+JSON.stringify(r)))")
    assert.deepEqual(result,[true,true])
  })
  await apply([ingress]);await node("const s=require('./backend/services/settings');for(const [g,p] of [['sites',{max_sites:5}],['kubernetes',{enabled:true,namespace:'catwaf',interval_sec:5}]]){const r=s.set(g,p);if(!r.ok)throw Error(r.error)}console.log('RESULT true')")
  const initial=await scan();assert.equal(initial.ok,true,JSON.stringify(initial))
  await startForward()
  await check('real Service routing, mounted TLS and Coraza blocking',async()=>{
    await until(async()=> (await request('/',first.pem)).body==='origin-one')
    assert.equal((await request('/',first.pem)).fingerprint,first.fingerprint)
    assert.equal((await request('/?id=1%20UNION%20SELECT%201,2,3--',first.pem)).status,403)
  })
  await check('controller permission outage preserves the active route',async()=>{
    await k('-n','catwaf','delete','rolebinding','catwaf-ingress')
    assert.equal((await scan()).ok,false)
    assert.equal((await request('/',first.pem)).body,'origin-one')
    await apply([manifests.find(x=>x.kind==='RoleBinding')]);assert.equal((await scan()).ok,true)
  })
  await check('late audit completion survives rotations across separate containers',async()=>{
    const pending=request('/slow-audit',first.pem);pending.catch(()=>{})
    await pause(1000)
    for(let n=0;n<3;n++){const r=await node("console.log('RESULT '+JSON.stringify(require('./backend/services/auditLog').maintain({force:true,env:{CATWAF_AUDIT_MAX_FILES:'1'}})))");assert.equal(r.ok,true,JSON.stringify(r));await pause(1100)}
    assert.equal((await pending).status,500)
    await until(async()=>await node("require('./backend/services/requestLog').ingestNewEntries();console.log('RESULT '+require('./backend/services/db').getDb().prepare(\"SELECT COUNT(*) AS n FROM request_log WHERE uri='/slow-audit'\").get().n)")===1)
  })
  await check('kubelet TLS rotation replaces the served certificate',async()=>{
    await apply([second.secret])
    await until(async()=> (await request('/',[first.pem,second.pem])).fingerprint===second.fingerprint,180)
  })
  await check('invalid mounted TLS update retains the last working certificate',async()=>{
    await apply([bad.secret])
    await until(async()=>await node("const fs=require('fs'),crypto=require('crypto');console.log('RESULT '+JSON.stringify(new crypto.X509Certificate(fs.readFileSync('/run/catwaf-tls/app-tls/tls.crt')).fingerprint256))")===bad.fingerprint,180)
    assert.equal((await scan()).ok,false)
    assert.equal((await request('/',second.pem)).fingerprint,second.fingerprint)
    await apply([second.secret])
    await until(async()=> (await scan()).ok,180)
  })
  await check('application rollout and ingress path updates reconcile automatically',async()=>{
    await apply([app('origin-two')]);await k('-n','catwaf','rollout','status','deploy/origin','--timeout=120s')
    await until(async()=> (await request('/',second.pem)).body==='origin-two')
    ingress.spec.rules[0].http.paths[0].path='/v2';await apply([ingress])
    await until(async()=> (await request('/',second.pem)).status===404)
    assert.equal((await request('/v2/test',second.pem)).body,'origin-two')
    assert.equal((await request('/v20',second.pem)).status,404)
  })
  await check('Pod recreation preserves configuration, certificates and SQLite',async()=>{
    forward.kill('SIGTERM');await k('-n','catwaf','rollout','restart','deploy/catwaf');await k('-n','catwaf','rollout','status','deploy/catwaf','--timeout=180s');await startForward()
    await until(async()=> (await request('/v2',second.pem)).body==='origin-two')
    assert.equal((await request('/v2',second.pem)).fingerprint,second.fingerprint)
    assert.equal(await node("console.log('RESULT '+require('./backend/services/db').getDb().prepare(\"SELECT COUNT(*) AS n FROM request_log WHERE uri='/slow-audit'\").get().n)"),1)
  })
  await check('deleting the Ingress removes the managed HTTP route',async()=>{
    await k('-n','catwaf','delete','ingress','web');await until(async()=> (await scan()).routes?.length===0)
    assert.equal((await request('/v2')).status,404)
  })
}
main().catch(async e=>{
  results.push({ok:false,error:e.message});console.error(e.message);process.exitCode=1
  if(owned)for(const c of ['backend','caddy','initialize-state']){try{fs.writeFileSync(path.join(dir,c+'.log'),(await k('-n','catwaf','logs','deploy/catwaf','-c',c,'--tail=200')).stdout)}catch{}}
}).finally(async()=>{
  if(forward)forward.kill('SIGTERM')
  fs.writeFileSync(path.join(dir,'results.json'),JSON.stringify(results,null,2));console.log('Kubernetes evidence: '+dir)
  if(owned&&process.env.CATWAF_K8S_TEST_KEEP!=='1'){
    await k('delete','namespace','catwaf','--wait=true','--timeout=120s').catch(()=>{process.exitCode=1})
    await k('delete','clusterrole,clusterrolebinding','catwaf-ingress-class').catch(()=>{process.exitCode=1})
    await k('delete','ingressclass','catwaf').catch(()=>{process.exitCode=1})
  }
})
