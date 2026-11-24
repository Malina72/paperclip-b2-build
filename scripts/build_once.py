"""At most one full build. Export locally and inspect before optional registry copy."""
import os,sys,pathlib,subprocess,json,hashlib,urllib.request,tarfile,shutil,time,signal,threading,atexit
R=pathlib.Path(os.environ['RUNNER_TEMP'])/'paperclip-b2';pins=json.loads(pathlib.Path('pins.json').read_text());report={'full_build_attempts':0,'published':False,'application_started':False};source=R/'source';source.mkdir();archive=R/'upstream.tar.gz'
def fetch(url,path,sha):
 with urllib.request.urlopen(url,timeout=45) as f,path.open('wb') as out:shutil.copyfileobj(f,out)
 assert hashlib.file_digest(path.open('rb'),'sha256').hexdigest()==sha
fetch(pins['archive_url'],archive,pins['archive_sha256'])
with tarfile.open(archive,'r:gz') as tf:
 prefix=tf.getmembers()[0].name.rstrip('/')+'/'
 for m in tf:
  if m.name.rstrip('/')==prefix.rstrip('/'):continue
  assert m.name.startswith(prefix);m.name=m.name[len(prefix):]
  if m.name:tf.extract(m,source,filter='data')
archive.unlink();subprocess.run(['patch','-p1','--batch','--fuzz=0','-i',str(pathlib.Path('patches/B3.patch').resolve())],cwd=source,check=True)
for name,expected in pins['source_hashes'].items():assert hashlib.file_digest((source/name).open('rb'),'sha256').hexdigest()==expected
assert hashlib.file_digest(pathlib.Path('patches/B3.patch').open('rb'),'sha256').hexdigest()==pins['patch_sha256']
d=source/'.pilot-build';d.mkdir();shutil.copy2('docker/Dockerfile',d/'Dockerfile');shutil.copy2('docker/Dockerfile.dockerignore',d/'Dockerfile.dockerignore');assert hashlib.file_digest((d/'Dockerfile').open('rb'),'sha256').hexdigest()==pins['dockerfile_sha256'];assert hashlib.file_digest((d/'Dockerfile.dockerignore').open('rb'),'sha256').hexdigest()==pins['dockerignore_sha256']
assert hashlib.sha256(pathlib.Path('scripts/b3_tls_fixture.rs').read_bytes()).hexdigest()==pins['rust_fixture_sha256']
for name in ['b3_tls_fixture.rs','rust_qualify.py','b3-rust-versions.json']:shutil.copy2(pathlib.Path('scripts')/name,d/name)
# Source identity records immutable upstream plus exact recipe/patch input revisions.
report['recipe_commit']=os.environ['GITHUB_SHA'];report['upstream_commit']=pins['upstream_commit'];report['patch_sha256']=pins['patch_sha256'];oci=R/'image-oci';e=R/'image-evidence';e.mkdir();(R/'build-result.json').write_text(json.dumps(report,indent=2))
args=['docker','buildx','build','--builder',os.environ.get('PILOT_BUILDER','default'),'--platform','linux/amd64','--target','production','--tag','ghcr.io/'+os.environ['GITHUB_REPOSITORY'].split('/')[0].lower()+'/paperclip-pilot-b3:'+os.environ['GITHUB_SHA'][:12],'--file','.pilot-build/Dockerfile','--build-arg','PAPERCLIP_BUILD_COMMIT='+os.environ['GITHUB_SHA'],'--build-arg','PAPERCLIP_BUILD_VERSION='+pins['version'],'--label','org.opencontainers.image.source=https://github.com/'+os.environ['GITHUB_REPOSITORY'],'--label','org.opencontainers.image.revision='+os.environ['GITHUB_SHA'],'--label','io.paperclip.upstream.revision='+pins['upstream_commit'],'--label','io.paperclip.patch.sha256='+pins['patch_sha256'],'--provenance=mode=max','--sbom=generator='+pins['sbom_generator'],'--metadata-file',str(e/'build-metadata.json'),'--output',f'type=oci,dest={oci},tar=false,compression=gzip','.']
samples=[];stop_monitor=threading.Event()
def resource_sample():
 while not stop_monitor.is_set():
  mem={x.split(':',1)[0]:int(x.split()[1])*1024 for x in pathlib.Path('/proc/meminfo').read_text().splitlines() if len(x.split())>=3}
  samples.append({'time':time.time(),'free_disk_bytes':shutil.disk_usage(R).free,'available_ram_bytes':mem['MemAvailable'],'load1':os.getloadavg()[0]})
  (R/'resource-samples.json').write_text(json.dumps(samples));stop_monitor.wait(5)
threading.Thread(target=resource_sample,daemon=True).start();atexit.register(stop_monitor.set)

# Test only the OS/tooling stage before compiling application sources. No app runs.
baseargs=['docker','buildx','build','--builder',os.environ.get('PILOT_BUILDER','default'),'--platform','linux/amd64','--target','base','--file','.pilot-build/Dockerfile','--load','--tag','paperclip-b2-base-check:local','.']
report['base_build_exit']=subprocess.run(baseargs,cwd=source,timeout=1200).returncode
(R/'build-result.json').write_text(json.dumps(report,indent=2))
if report['base_build_exit']:sys.exit(report['base_build_exit'])
# Non-root tests use private writable APT state and the unchanged archive keyring.
check=r"""set -eu
node -e 'const tls=require("node:tls"),c=require("node:crypto");console.log(JSON.stringify({source:"tls.rootCertificates",node:process.version,count:tls.rootCertificates.length,sha256:c.createHash("sha256").update(tls.rootCertificates.join("\n")+"\n").digest("hex")}))'
curl --fail --silent --show-error --max-time 30 https://snapshot.ubuntu.com/ubuntu/20261124T000000Z/dists/noble/InRelease >/dev/null
mkdir -p /tmp/apt-check/lists/partial /tmp/apt-check/cache/archives/partial
apt-get -o Dir::State::lists=/tmp/apt-check/lists -o Dir::Cache=/tmp/apt-check/cache -o APT::Sandbox::User=node update --error-on=any --snapshot 20261124T000000Z
python3 - <<'TLS'
import ssl,urllib.request
try:urllib.request.urlopen('https://snapshot.ubuntu.com/ubuntu/20261124T000000Z/dists/noble/InRelease',context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),timeout=30)
except urllib.error.URLError as e:
 assert isinstance(e.reason,ssl.SSLCertVerificationError),type(e.reason)
 print('NEGATIVE_EMPTY_TRUST_PASS')
else:raise AssertionError('untrusted HTTPS accepted')
TLS
find /tmp/apt-check/lists -name '*InRelease' -print -quit | grep .
for f in /tmp/apt-check/lists/*InRelease; do gpgv --keyring /usr/share/keyrings/ubuntu-archive-keyring.gpg "$f"; done
printf 'not a signed release' >/tmp/apt-check/invalid-release
if gpgv --keyring /usr/share/keyrings/ubuntu-archive-keyring.gpg /tmp/apt-check/invalid-release; then exit 1; fi
printf 'BASE_TLS_APT_CHECK_PASS\n'
"""
q=subprocess.run(['docker','run','--rm','--user','10001:10001','--read-only','--cap-drop=ALL','--security-opt','no-new-privileges:true','--memory','512m','--cpus','1','--pids-limit','64','--tmpfs','/tmp:rw,nosuid,nodev,size=256m','--entrypoint','/bin/sh','paperclip-b2-base-check:local','-c',check],timeout=600)
report['base_check_exit']=q.returncode
(R/'build-result.json').write_text(json.dumps(report,indent=2))
if q.returncode:sys.exit(q.returncode)

# Build/check native libraries first; only small reports are exported, never synthetic keys.
rust_out=R/'rust-qualification';rust_args=['docker','buildx','build','--builder',os.environ.get('PILOT_BUILDER','default'),'--platform','linux/amd64','--target','rust-qualification','--file','.pilot-build/Dockerfile','--output','type=local,dest='+str(rust_out),'.']
report['rust_qualification_exit']=subprocess.run(rust_args,cwd=source,timeout=3600).returncode;(R/'build-result.json').write_text(json.dumps(report,indent=2))
if report['rust_qualification_exit']:sys.exit(report['rust_qualification_exit'])
rust_proof=json.loads((rust_out/'results.json').read_text());assert rust_proof['pass'] and rust_proof['lock_sha256']==pins['source_hashes']['packages/paperclip-runner/runner/Cargo.lock'] and rust_proof['versions']==json.loads(pathlib.Path('scripts/b3-rust-versions.json').read_text()) and not rust_proof['application_started'] and not rust_proof['codex_started']

report['full_build_attempts']=1;start=time.monotonic();p=subprocess.Popen(args,cwd=source,start_new_session=True)
try:report['build_exit']=p.wait(timeout=7200)
except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGTERM);p.wait(timeout=30);report['build_exit']=124
report['build_seconds']=round(time.monotonic()-start,2);(R/'build-result.json').write_text(json.dumps(report,indent=2))
if report['build_exit']:print(json.dumps(report,indent=2));sys.exit(report['build_exit'])
report['oci_bytes']=sum(x.stat().st_size for x in oci.rglob('*') if x.is_file());report['oci_index_sha256']=hashlib.sha256((oci/'index.json').read_bytes()).hexdigest();(R/'build-result.json').write_text(json.dumps(report,indent=2))
inspection=subprocess.run([sys.executable,'scripts/inspect_oci.py',str(oci),str(e)]);report['inspection_exit']=inspection.returncode;(R/'build-result.json').write_text(json.dumps(report,indent=2))
if inspection.returncode:print('No publication: local image inspection did not pass');sys.exit(inspection.returncode)
assert hashlib.sha256(pathlib.Path('scripts/component-check.mjs').read_bytes()).hexdigest()==pins['component_check_sha256']
# Import the already-built OCI as data, then run only a bounded library fixture.
# This is not a second build and never invokes the application entrypoint.
with (e/'image-load.log').open('w') as log:
 loader=subprocess.Popen(['docker','image','load','--quiet'],stdin=subprocess.PIPE,stdout=log,stderr=subprocess.STDOUT)
 with tarfile.open(fileobj=loader.stdin,mode='w|') as tf:
  for file in sorted(oci.rglob('*')):
   if file.is_file():tf.add(file,arcname=str(file.relative_to(oci)),recursive=False)
 loader.stdin.close();assert loader.wait(timeout=180)==0,'OCI import failed'
proof=json.loads((e/'image-verification.json').read_text());manifest=json.loads((oci/'blobs/sha256'/proof['runtime_manifest_digest'].split(':')[1]).read_text());config_id=manifest['config']['digest'];tag='ghcr.io/'+os.environ['GITHUB_REPOSITORY'].split('/')[0].lower()+'/paperclip-pilot-b3:'+os.environ['GITHUB_SHA'][:12]
# Docker29 containerd image IDs are target/index digests, not config digests.
loaded=json.loads(subprocess.check_output(['docker','image','inspect',tag],text=True))[0];image_id=loaded['Id'];allowed_targets={x['digest'] for x in json.loads((oci/'index.json').read_text())['manifests']}|{proof['runtime_manifest_digest'],'sha256:'+proof['root_index_sha256']}
assert image_id in allowed_targets and loaded['Architecture']=='amd64' and loaded['Os']=='linux','Imported image identity/platform differs'

canary=R/'host-only-synthetic-canary';canary.write_text('synthetic host-only isolation marker');cid=None
try:
 create=['docker','create','--platform','linux/amd64','--pull=never','--name','b2-component-only','--user','10001:10001','--read-only','--cap-drop=ALL','--security-opt','no-new-privileges:true','--memory','512m','--memory-swap','512m','--cpus','1','--pids-limit','64','--network','none','--tmpfs','/tmp:rw,nosuid,nodev,size=32m','--env','B2_HOST_CANARY_PATH='+str(canary),'--entrypoint','node',image_id,'--input-type=module','-e',pathlib.Path('scripts/component-check.mjs').read_text()]
 cid=subprocess.check_output(create,text=True).strip();state=json.loads(subprocess.check_output(['docker','inspect',cid],text=True))[0];hc=state['HostConfig']
 if state.get('ImageManifestDescriptor'):assert state['ImageManifestDescriptor']['digest']==proof['runtime_manifest_digest']
 assert hc['Memory']==512*1024*1024 and hc['MemorySwap']==512*1024*1024 and (hc.get('NanoCpus') or hc.get('NanoCPUs'))==1000000000 and hc['PidsLimit']==64
 host_mounts=[m for m in state['Mounts'] if m.get('Type')!='tmpfs' or m.get('Source')]
 assert hc['ReadonlyRootfs'] and not hc['Privileged'] and hc['NetworkMode']=='none' and 'ALL' in hc['CapDrop'] and 'no-new-privileges:true' in hc['SecurityOpt'] and not host_mounts
 run=subprocess.run(['docker','start','-a',cid],capture_output=True,text=True,timeout=60)
 (e/'component-stdout.log').write_text(run.stdout);(e/'component-stderr.log').write_text(run.stderr);finished=json.loads(subprocess.check_output(['docker','inspect',cid],text=True))[0]['State']
 assert run.returncode==0 and finished['ExitCode']==0 and not finished['Running'] and not finished['OOMKilled'],'Bounded component check failed'
 component=json.loads(run.stdout.strip().splitlines()[-1]);assert component['pass'] and component['application_started'] is False and component['codex_started'] is False
 component['runtime_manifest_digest']=proof['runtime_manifest_digest'];component['runtime_config_digest']=config_id;component['docker_image_id']=image_id;component['hard_limits_verified']={'memory_bytes':hc['Memory'],'memory_swap_bytes':hc['MemorySwap'],'nano_cpus':hc.get('NanoCpus') or hc.get('NanoCPUs'),'pids':hc['PidsLimit'],'network':hc['NetworkMode'],'readonly':hc['ReadonlyRootfs'],'no_host_mounts':not host_mounts};component['component_process_exited']=True
 (e/'component-results.json').write_text(json.dumps(component,indent=2));proof['rust_tls_qualification_pass']=rust_proof['pass'];proof['rust_tls_tests']=rust_proof['tls_tests'];proof['rust_patch_versions']=rust_proof['versions'];proof['component_checks_pass']=True;proof['security_review_pass']=proof['static_review_pass'] and component['pass'];(e/'image-verification.json').write_text(json.dumps(proof,indent=2));print('COMPONENT_CHECKS',json.dumps(component))
finally:
 if cid:subprocess.run(['docker','rm','-f',cid],check=True,stdout=subprocess.DEVNULL)
 canary.unlink(missing_ok=True)

# This approval gate is consumed only after local composition/secrets/SBOM/provenance checks.
with open(os.environ['GITHUB_OUTPUT'],'a') as f:f.write('publish_eligible='+str(json.loads((e/'image-verification.json').read_text()).get('security_review_pass') is True).lower()+'\n')
print(json.dumps(report,indent=2))
