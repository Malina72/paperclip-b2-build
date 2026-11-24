"""At most one full build. Export locally and inspect before optional registry copy."""
import os,sys,pathlib,subprocess,json,hashlib,urllib.request,tarfile,shutil,time,signal
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
archive.unlink();subprocess.run(['patch','-p1','--batch','--fuzz=0','-i',str(pathlib.Path('patches/B2.patch').resolve())],cwd=source,check=True)
for name,expected in pins['source_hashes'].items():assert hashlib.file_digest((source/name).open('rb'),'sha256').hexdigest()==expected
assert hashlib.file_digest(pathlib.Path('patches/B2.patch').open('rb'),'sha256').hexdigest()==pins['patch_sha256']
d=source/'.pilot-build';d.mkdir();shutil.copy2('docker/Dockerfile',d/'Dockerfile');shutil.copy2('docker/Dockerfile.dockerignore',d/'Dockerfile.dockerignore');assert hashlib.file_digest((d/'Dockerfile').open('rb'),'sha256').hexdigest()==pins['dockerfile_sha256'];assert hashlib.file_digest((d/'Dockerfile.dockerignore').open('rb'),'sha256').hexdigest()==pins['dockerignore_sha256']
# Source identity records immutable upstream plus exact recipe/patch input revisions.
report['recipe_commit']=os.environ['GITHUB_SHA'];report['upstream_commit']=pins['upstream_commit'];report['patch_sha256']=pins['patch_sha256'];oci=R/'image-oci';e=R/'image-evidence';e.mkdir();(R/'build-result.json').write_text(json.dumps(report,indent=2))
args=['docker','buildx','build','--builder','default','--platform','linux/amd64','--target','production','--file','.pilot-build/Dockerfile','--build-arg','PAPERCLIP_BUILD_COMMIT='+os.environ['GITHUB_SHA'],'--build-arg','PAPERCLIP_BUILD_VERSION='+pins['version'],'--label','org.opencontainers.image.revision='+os.environ['GITHUB_SHA'],'--label','io.paperclip.upstream.revision='+pins['upstream_commit'],'--label','io.paperclip.patch.sha256='+pins['patch_sha256'],'--provenance=mode=max','--sbom=generator='+pins['sbom_generator'],'--metadata-file',str(e/'build-metadata.json'),'--output',f'type=oci,dest={oci},tar=false,compression=gzip','.']
report['full_build_attempts']=1;start=time.monotonic();p=subprocess.Popen(args,cwd=source,start_new_session=True)
try:report['build_exit']=p.wait(timeout=7200)
except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGTERM);p.wait(timeout=30);report['build_exit']=124
report['build_seconds']=round(time.monotonic()-start,2);(R/'build-result.json').write_text(json.dumps(report,indent=2))
if report['build_exit']:print(json.dumps(report,indent=2));sys.exit(report['build_exit'])
inspection=subprocess.run([sys.executable,'scripts/inspect_oci.py',str(oci),str(e)]);report['inspection_exit']=inspection.returncode;(R/'build-result.json').write_text(json.dumps(report,indent=2))
if inspection.returncode:print('No publication: local image inspection did not pass');sys.exit(inspection.returncode)
# This approval gate is consumed only after local composition/secrets/SBOM/provenance checks.
with open(os.environ['GITHUB_OUTPUT'],'a') as f:f.write('publish_eligible=true\n')
print(json.dumps(report,indent=2))
