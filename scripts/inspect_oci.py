"""Read a local OCI layout as data. Never extract executable files or start an image."""
import sys,pathlib,json,hashlib,tarfile,posixpath,re,gzip,struct,urllib.request,subprocess,os,shutil
root=pathlib.Path(sys.argv[1]);output=pathlib.Path(sys.argv[2]);output.mkdir(exist_ok=True);pins=json.loads(pathlib.Path('pins.json').read_text());seen=set();manifests=[];predicates=[]
def blob(desc):
 alg,h=desc['digest'].split(':',1);assert alg=='sha256';p=root/'blobs'/alg/h;assert p.is_file();assert p.stat().st_size==desc['size'];assert hashlib.file_digest(p.open('rb'),'sha256').hexdigest()==h;return p

def visit(desc):
 if desc['digest'] in seen:return
 seen.add(desc['digest']);p=blob(desc);x=json.loads(p.read_text())
 if 'manifests' in x:
  for d in x['manifests']:visit(d)
 elif 'layers' in x:
  if x.get('artifactType') or desc.get('annotations',{}).get('vnd.docker.reference.type')=='attestation-manifest' or all('in-toto' in d.get('mediaType','') for d in x['layers']):
   for layer in x['layers']:
    a=json.loads(blob(layer).read_text());predicates.append(a)
  else:manifests.append((desc,x))
index=json.loads((root/'index.json').read_text())
for d in index['manifests']:visit(d)
assert len(manifests)==1,'Expected one runnable platform';desc,manifest=manifests[0];cfg=json.loads(blob(manifest['config']).read_text());assert cfg['architecture']=='amd64' and cfg['os']=='linux';config=cfg['config'];assert config.get('User')=='10001:10001';assert config.get('Cmd')==['node','server/dist-runtime/index.mjs'];assert config.get('Entrypoint')==['/usr/bin/tini','-s','--','docker-entrypoint.sh']
assert any('spdx' in x.get('predicateType','') for x in predicates),'SBOM missing';assert any('slsa' in x.get('predicateType','') for x in predicates),'provenance missing'
assert any('spdx' in a.get('predicateType','') and a.get('predicate',{}).get('packages') for a in predicates),'SBOM package inventory empty'
# Preserve evidence even when a binding check fails; publication stays blocked.
(output/'attestations.json').write_text(json.dumps(predicates,indent=2))
attestation_binding_pass=all(any(s.get('digest',{}).get('sha256')==desc['digest'].split(':')[1] for s in a.get('subject',[])) for a in predicates)
print('ATTESTATION_BINDINGS',json.dumps({'runtime':desc['digest'],'subjects':[{'predicateType':a.get('predicateType'),'subject':a.get('subject')} for a in predicates],'pass':attestation_binding_pass}))
packages={};links={};texts={};names=set();headers={};flags=[];uncompressed=0
patterns=[('private_key',re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[A-Za-z0-9+/=\r\n]{80,}')),('github_token',re.compile(rb'gh[pousr]_[A-Za-z0-9]{30,}')),('openai_project_key',re.compile(rb'sk-proj-[A-Za-z0-9_-]{48,}'))]
for layer in manifest['layers']:
 p=blob(layer)
 with tarfile.open(p,mode='r|*') as tf:
  for member in tf:
   name=posixpath.normpath(member.name.lstrip('./'));assert not name.startswith('../')
   if '/.wh.' in name or name.startswith('.wh.'):
    parent=posixpath.dirname(name);bn=posixpath.basename(name);target=parent if bn=='.wh..wh..opq' else posixpath.join(parent,bn[4:])
    for collection in [packages,links,texts,headers]:
     for key in list(collection):
      if key==target or key.startswith(target+'/'):del collection[key]
    names={k for k in names if not(k==target or k.startswith(target+'/'))};continue
   names.add(name)
   if member.issym() or member.islnk():links[name]={'target':member.linkname,'hard':member.islnk()};continue
   if not member.isfile():continue
   uncompressed+=member.size;f=tf.extractfile(member);store=(name.endswith('/package.json') and member.size<4*1024*1024) or name=='var/lib/dpkg/status' or name=='app/packages/paperclip-runner/runner/Cargo.lock' or (name.endswith('/versions.json') and 'sharp-libvips' in name) or name.endswith('/build-info.json');data=bytearray() if store else None;tail=b'';flagtypes=set();match_hashes={};file_hash=hashlib.sha256();first=b''
   while True:
    chunk=f.read(65536)
    if not chunk:break
    file_hash.update(chunk)
    if not first:first=chunk[:64]
    if data is not None:data.extend(chunk)
    for kind,pattern in patterns:
     for m in pattern.finditer(tail+chunk):
      value=m.group()
      if kind!='private_key' and len(set(value.split(b'_',1)[-1]))<4:continue
      flagtypes.add(kind);match_hashes.setdefault(kind,set()).add(hashlib.sha256(value).hexdigest())
    tail=(tail+chunk)[-8192:]
   for kind in flagtypes:flags.append({'path':name,'kind':kind,'file_sha256':file_hash.hexdigest(),'match_sha256':sorted(match_hashes[kind]),'action':'BLOCK_PUBLICATION_PENDING_REVIEW','note':'May be a public synthetic fixture; no automatic blanket exception'})
   if first.startswith(b'\x7fELF'):headers[name]={'elf_type':int.from_bytes(first[16:18],'little'),'machine':int.from_bytes(first[18:20],'little')}
   if data is not None:
    if name.endswith('/package.json'):
     try:packages[name]=json.loads(data)
     except ValueError:pass
    else:texts[name]=bytes(data).decode('utf8',errors='replace')
# virtual filesystem resolution, including pnpm directory symlinks; no real filesystem access.
def resolve(p):
 for _ in range(60):
  parts=p.strip('/').split('/');changed=False
  for i in range(1,len(parts)+1):
   prefix='/'.join(parts[:i])
   if prefix not in links:continue
   link=links[prefix];t=link['target'];head=t.lstrip('/') if t.startswith('/') or link['hard'] else posixpath.join(posixpath.dirname(prefix),t);p=posixpath.normpath(posixpath.join(head,*parts[i:]));changed=True;break
  if not changed:return p
 raise ValueError('symlink cycle')
def pkg(base,name):
 p=resolve(base+'/node_modules/'+name+'/package.json');assert p in packages,(name,'manifest missing');return p,packages[p]
express_path,ex=pkg('app/server','express');exdir=posixpath.dirname(express_path)
def dep(start,name):
 d=start
 while d:
  p=resolve(d+'/node_modules/'+name+'/package.json')
  if p in packages:return p,packages[p]
  d=posixpath.dirname(d)
 raise ValueError('missing dependency '+name)
bp,bpm=dep(exdir,'body-parser');pa,pam=dep(exdir,'proxy-addr');router,rm=dep(exdir,'router');ptr,ptrm=dep(posixpath.dirname(router),'path-to-regexp');sharp,sm=pkg('app/server','sharp');actual={'express':ex['version'],'body-parser':bpm['version'],'proxy-addr':pam['version'],'router':rm['version'],'path-to-regexp':ptrm['version'],'sharp':sm['version']};assert actual=={'express':'5.2.1','body-parser':'2.4.0','proxy-addr':'2.0.8','router':'2.2.0','path-to-regexp':'8.4.2','sharp':'0.35.5'}
assert not any(n.startswith('opt/paperclip-runner/provider-pack') for n in names),'Unexpected provider pack';assert not any(n.startswith('usr/local/lib/node_modules/') for n in names),'Unexpected global npm installations';assert headers.get('usr/local/bin/node',{}).get('machine')==62,'Node not amd64'
status=texts.get('var/lib/dpkg/status','');assert '\nPackage: openssh-client\n' in '\n'+status;sshblock=next(x for x in status.split('\n\n') if x.startswith('Package: openssh-client\n'));assert '\nVersion: '+pins['openssh_client']+'\n' in '\n'+sshblock+'\n','Wrong Ubuntu security package'
native=[json.loads(v) for k,v in texts.items() if k.endswith('/versions.json') and 'sharp-libvips-linux-x64' in k];assert any(x.get('rsvg')=='2.63.2' for x in native),'Native librsvg inventory missing or unexpected'
for n in names:
 if n.endswith('/.env') or n.endswith('/auth.json') or '/.ssh/' in n:flags.append({'path':n,'kind':'sensitive_filename','action':'BLOCK_PUBLICATION_PENDING_REVIEW'})
versions={}
for p in packages.values():
 if isinstance(p,dict) and isinstance(p.get('name'),str) and isinstance(p.get('version'),str):versions.setdefault(p['name'],set()).add(p['version'])
req=urllib.request.Request('https://registry.npmjs.org/-/npm/v1/security/advisories/bulk',data=json.dumps({k:sorted(v) for k,v in versions.items()}).encode(),headers={'Content-Type':'application/json'})
with urllib.request.urlopen(req,timeout=30) as f:advisories=json.load(f)
(output/'physical-package-manifests.json').write_text(json.dumps({'packages':packages,'links':links},indent=2));(output/'npm-advisories.json').write_text(json.dumps(advisories,indent=2));(output/'os-dpkg-status.txt').write_text(status);(output/'native-inventory.json').write_text(json.dumps(native,indent=2));(output/'package-inventory.json').write_text(json.dumps({k:sorted(v) for k,v in versions.items()},indent=2));(output/'attestations.json').write_text(json.dumps(predicates,indent=2))
# Official pinned scanner: data-only analysis of this local OCI layout, no app execution.
scanner=pins['trivy'];toolroot=output.parent/'scanner-tools';toolroot.mkdir(exist_ok=True);archive=toolroot/'trivy.tar.gz'
with urllib.request.urlopen(scanner['url'],timeout=60) as src,archive.open('wb') as dst:shutil.copyfileobj(src,dst)
assert hashlib.file_digest(archive.open('rb'),'sha256').hexdigest()==scanner['sha256']
with tarfile.open(archive,'r:gz') as tf:
 member=tf.getmember('trivy');assert member.isfile() and member.size<200*1024*1024
 with tf.extractfile(member) as src,(toolroot/'trivy').open('wb') as dst:shutil.copyfileobj(src,dst)
tool=toolroot/'trivy';tool.chmod(0o700);archive.unlink();env=os.environ.copy();env['TRIVY_DISABLE_TELEMETRY']='true'
# The exporter wraps a platform index in the layout root. Trivy matches @digest
# only at that outer level. A data-only view selects exactly the verified runtime.
scanroot=output.parent/'runtime-scan-oci';scanroot.mkdir(exist_ok=True);(scanroot/'blobs').symlink_to(root/'blobs',target_is_directory=True);(scanroot/'oci-layout').write_text(json.dumps({'imageLayoutVersion':'1.0.0'}));(scanroot/'index.json').write_text(json.dumps({'schemaVersion':2,'manifests':[desc]}))
scan=subprocess.run([str(tool),'image','--input',str(scanroot),'--cache-dir',str(toolroot/'cache'),'--scanners','vuln','--severity','HIGH,CRITICAL','--format','json','--output',str(output/'trivy-high-critical.json'),'--timeout','15m','--parallel','2','--skip-java-db-update','--no-progress'],env=env,timeout=960)
scanproof={'version':scanner['version'],'binary_archive_sha256':scanner['sha256'],'exit':scan.returncode}
metadata=toolroot/'cache/db/metadata.json'
if metadata.exists():scanproof['database_metadata']=json.loads(metadata.read_text())
db=toolroot/'cache/db/trivy.db'
if db.exists():scanproof['database_sha256']=hashlib.file_digest(db.open('rb'),'sha256').hexdigest()
(output/'trivy-scan-proof.json').write_text(json.dumps(scanproof,indent=2))
# Review is bound to exact inputs/findings; new findings or changed fixtures fail closed.
assert hashlib.sha256(pathlib.Path('security-review.json').read_bytes()).hexdigest()==pins['security_review_sha256'];review=json.loads(pathlib.Path('security-review.json').read_text())
assert review['upstream_commit']==pins['upstream_commit'] and review['patch_sha256']==pins['patch_sha256'] and review['source_hashes']==pins['source_hashes'] and review['dockerfile_sha256']==pins['dockerfile_sha256']
reviewed=[];unknown=[]
for flag in flags:
 match=next((x for x in review['reviewed_public_fixture_exceptions'] if all(x.get(k)==flag.get(k) for k in ['path','kind','file_sha256','match_sha256'])),None)
 if match:reviewed.append(flag|{'review_reason':match['reason'],'origin':match['origin']})
 else:unknown.append(flag)
flags=unknown
normalized_npm={k:sorted(v,key=lambda x:(x.get('url',''),x.get('vulnerable_versions',''))) for k,v in advisories.items()}
npm_review_matches=hashlib.sha256(json.dumps(normalized_npm,sort_keys=True,separators=(',',':')).encode()).hexdigest()==review['reviewed_npm_response_sha256']
trivy_keys=[]
scan_report=output/'trivy-high-critical.json'
if scan.returncode==0 and scan_report.exists():
 scan_data=json.loads(scan_report.read_text());assert scan_data.get('Metadata',{}).get('OS',{}).get('Family')=='ubuntu','OS coverage missing'
 for row in scan_data.get('Results',[]):
  for v in row.get('Vulnerabilities') or []:
   trivy_keys.append([row['Type'],row['Target'] if row['Type']!='ubuntu' else 'ubuntu24.04-runtime',v['VulnerabilityID'],v['PkgName'],v['InstalledVersion'],v['Severity']])
trivy_review_matches=bool(scan.returncode==0 and scan_report.exists() and sorted(trivy_keys)==review['reviewed_trivy_finding_keys'])
from audit_rust import audit_lock
cargo=texts.get('app/packages/paperclip-runner/runner/Cargo.lock');assert cargo,'Runtime Cargo lock absent'
assert hashlib.sha256(cargo.encode()).hexdigest()==pins['source_hashes']['packages/paperclip-runner/runner/Cargo.lock']
rust=audit_lock(cargo);(output/'rust-audit.json').write_text(json.dumps(rust,indent=2));rust_review_matches=sorted([[x['name'],x['version'],x['id']] for x in rust['findings']])==review['reviewed_rust_finding_keys']
static_review_pass=bool(review.get('admission_allowed') is True and rust_review_matches and npm_review_matches and trivy_review_matches and attestation_binding_pass and not flags and scan.returncode==0)
(output/'security-review-result.json').write_text(json.dumps({'scope':review['scope'],'rust_review_matches':rust_review_matches,'rust_findings':review['rust_review'],'admission_allowed':review.get('admission_allowed') is True,'blocking_findings':review.get('blocking_findings',[]),'npm_review_matches':npm_review_matches,'trivy_review_matches':trivy_review_matches,'npm_reviewed_findings':len(review['npm_findings']),'trivy_reviewed_records':len(review['trivy_findings']),'reviewed_public_fixture_matches':reviewed,'unknown_secret_matches':unknown,'static_review_pass':static_review_pass,'runtime_conditions':review['required_runtime_conditions'],'coverage_limits':review['coverage_limits'],'application_started':False},indent=2))
result={'composition_pass':True,'static_review_pass':static_review_pass,'reviewed_public_fixture_matches':len(reviewed),'attestation_binding_pass':attestation_binding_pass,'scanner_exit':scan.returncode,'security_review_pass':False,'secrets_scan_pass':not flags,'secret_flags':flags,'local_oci_bytes':sum(p.stat().st_size for p in root.rglob('*') if p.is_file()),'runtime_layers_compressed_bytes':sum(x['size'] for x in manifest['layers']),'sum_layer_payload_bytes_not_deduplicated':uncompressed,'runtime_manifest_digest':desc['digest'],'root_index_sha256':hashlib.sha256((root/'index.json').read_bytes()).hexdigest(),'actual_runtime_versions':actual,'openssh':pins['openssh_client'],'platform':'linux/amd64','sbom_present':True,'provenance_present':True,'identity_signature_verified':False,'application_started':False,'remaining_risks':['Conditional inactive-tool/provider findings retained in security-review.json; runtime guards need separate qualification','Sharp embedded C/C++ coverage is supplier-inventory plus selected advisories, not exhaustive binary CVE detection','No Linux dynamic application/native smoke test; no application launched']}
(output/'image-verification.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2));sys.exit(0 if static_review_pass else 3)
