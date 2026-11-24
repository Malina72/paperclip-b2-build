// Bounded library checks only. Never imports the Paperclip application or an executor.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import net from 'node:net';
import { createRequire } from 'node:module';
import { gzipSync, deflateSync, brotliCompressSync, zstdCompressSync } from 'node:zlib';
const started = performance.now();
const require = createRequire('/app/server/package.json');
const checks = [];
assert.equal(process.platform,'linux');assert.equal(process.arch,'x64');assert.equal(process.version,'v24.22.3');
assert.equal(process.getuid(), 10001); checks.push('nonroot');
const status = fs.readFileSync('/proc/self/status','utf8');
assert.match(status,/CapEff:\s+0+\s/); assert.match(status,/NoNewPrivs:\s+1/); assert.match(status,/Seccomp:\s+2/); checks.push('kernel-guards');
const cgroups={memory:fs.readFileSync('/sys/fs/cgroup/memory.max','utf8').trim(),swap:fs.readFileSync('/sys/fs/cgroup/memory.swap.max','utf8').trim(),cpu:fs.readFileSync('/sys/fs/cgroup/cpu.max','utf8').trim(),pids:fs.readFileSync('/sys/fs/cgroup/pids.max','utf8').trim()};
assert.equal(cgroups.memory,'536870912');assert.equal(cgroups.swap,'0');assert.equal(cgroups.pids,'64');const [quota,period]=cgroups.cpu.split(/\s+/).map(Number);assert.equal(quota/period,1);checks.push('kernel-cgroup-hard-limits');
const apparmor=fs.readFileSync('/proc/self/attr/current','utf8').trim();assert.match(apparmor,/docker-default.*enforce/);checks.push('apparmor-enforced');
assert.throws(()=>fs.writeFileSync('/paperclip/.b2-component-canary','synthetic'),{code:'EROFS'}); checks.push('readonly-root');
assert.equal(fs.existsSync(process.env.B2_HOST_CANARY_PATH),false); checks.push('host-canary-not-mounted');
for (const name of ['GITHUB_TOKEN','GH_TOKEN','OPENAI_API_KEY','ANTHROPIC_API_KEY','SSH_AUTH_SOCK','AWS_ACCESS_KEY_ID']) assert.equal(process.env[name],undefined,name);
checks.push('no-injected-account-credentials');
assert.ok(Object.values(os.networkInterfaces()).flat().every(x=>x.internal));
const blocked = await new Promise(resolve=>{const s=net.connect({host:'1.1.1.1',port:443});s.setTimeout(750);s.once('connect',()=>{s.destroy();resolve('CONNECTED')});s.once('error',e=>{s.destroy();resolve(e.code)});s.once('timeout',()=>{s.destroy();resolve('TIMEOUT')})});
assert.ok(['ENETUNREACH','EHOSTUNREACH'].includes(blocked),blocked); checks.push('external-network-unreachable');
const sharp = require('sharp');
assert.equal(sharp.versions.sharp,'0.35.5'); assert.equal(sharp.versions.vips,'8.18.7'); assert.equal(sharp.versions.rsvg,'2.63.2');
const image=await sharp({create:{width:2,height:3,channels:4,background:{r:1,g:2,b:3,alpha:1}}}).png().toBuffer();
const meta=await sharp(image).metadata(); assert.equal(meta.width,2);assert.equal(meta.height,3);checks.push('sharp-native-png');
await assert.rejects(sharp(Buffer.from('bounded-invalid-image')).metadata());checks.push('sharp-invalid-input');
const express=require('express');const app=express();app.set('trust proxy',false);app.use((_req,res,next)=>{res.setHeader('Connection','close');next()});app.use(express.json({limit:'2kb'}));app.post('/fixture',(req,res)=>res.json(req.body));app.get('/route/:id',(req,res)=>res.json({id:req.params.id,ip:req.ip}));app.use((err,_req,res,_next)=>res.status(err.status||500).json({error:'component-error'}));
assert.throws(()=>app.get('/unsupported/:id(.*)',()=>{}));checks.push('path-regexp-rejects-unsupported-syntax');
const server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s))});
try {
 const base='http://127.0.0.1:'+server.address().port;
 for (const [encoding,compress] of [['gzip',gzipSync],['deflate',deflateSync],['br',brotliCompressSync],['zstd',zstdCompressSync]]) {
  const response=await fetch(base+'/fixture',{method:'POST',headers:{'content-type':'application/json','content-encoding':encoding,connection:'close'},body:compress(Buffer.from(JSON.stringify({value:'synthetic-unicode-✓'})))});
  assert.equal(response.status,200);assert.deepEqual(await response.json(),{value:'synthetic-unicode-✓'});checks.push('http-'+encoding);
 }
 const malformed=await fetch(base+'/fixture',{method:'POST',headers:{'content-type':'application/json','content-encoding':'gzip',connection:'close'},body:Buffer.from([31,139,8,0,0,0,0,0,0,3,255,255])});assert.equal(malformed.status,400);checks.push('malformed-gzip-handled');
 const tooLarge=await fetch(base+'/fixture',{method:'POST',headers:{'content-type':'application/json',connection:'close'},body:JSON.stringify({value:'x'.repeat(4096)})});assert.equal(tooLarge.status,413);checks.push('http-body-limit');
 const badPath=await fetch(base+'/route/%E0%A4%A',{headers:{connection:'close'}});assert.equal(badPath.status,400);checks.push('malformed-route-handled');
 const spoof=await fetch(base+'/route/fixture',{headers:{'x-forwarded-for':'8.8.8.8',connection:'close'}});assert.equal((await spoof.json()).ip,'127.0.0.1');checks.push('untrusted-forwarded-header-ignored');
 const health=await fetch(base+'/route/alive',{headers:{connection:'close'}});assert.equal(health.status,200);checks.push('http-process-survives-errors');
} finally { server.closeAllConnections();await new Promise(resolve=>server.close(resolve)); }
// These pure compiled authorization helpers import only errors.js, not the server.
const authz=await import('file:///app/server/dist/routes/workspace-command-authz.js');
for (const paths of [authz.collectAgentAdapterWorkspaceCommandPaths({workspaceStrategy:{provisionCommand:'synthetic-not-executed'}}),authz.collectExecutionWorkspaceCommandPaths({config:{cleanupCommand:'synthetic-not-executed'}})]) {
 assert.ok(paths.length>0);assert.throws(()=>authz.assertNoAgentHostWorkspaceCommandMutation({actor:{type:'agent'}},paths),e=>e.status===403);assert.doesNotThrow(()=>authz.assertNoAgentHostWorkspaceCommandMutation({actor:{type:'board'}},paths));
}
checks.push('agent-host-command-mutation-denied');
console.log(JSON.stringify({pass:true,checks,sharp_versions:sharp.versions,node:process.version,uid:process.getuid(),cgroups,apparmor,max_rss_kib:process.resourceUsage().maxRSS,seconds:(performance.now()-started)/1000,application_started:false,codex_started:false}));
