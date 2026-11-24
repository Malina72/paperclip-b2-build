"""Synthetic inspector gates only, no image/application execution or external requests."""
import types,pathlib,tempfile,json,tarfile,io,hashlib,runpy,sys,urllib.request,os,contextlib,subprocess
r=pathlib.Path(__file__).resolve().parents[1];public=r;results=[]
def case(name,secret=False,missing_sbom=False,bad_hash=False,bad_subject=False,scanner_error=False,review_fixture=False,mutate_exception=False,unknown_finding=False,manual_hold=False,unknown_rust=False):
 with tempfile.TemporaryDirectory(prefix='b2-oci-test-') as tmp:
  root=pathlib.Path(tmp);(root/'blobs/sha256').mkdir(parents=True);out=root/'evidence'
  def blob(obj,media):
   data=obj if isinstance(obj,bytes) else json.dumps(obj).encode();h=hashlib.sha256(data).hexdigest();(root/'blobs/sha256'/h).write_bytes(data);return {'mediaType':media,'digest':'sha256:'+h,'size':len(data)}
  files={};vers={'express':'5.2.1','body-parser':'2.4.0','proxy-addr':'2.0.8','router':'2.2.0','path-to-regexp':'8.4.2','sharp':'0.35.5'}
  for n,v in vers.items():files['app/server/node_modules/'+n+'/package.json']=json.dumps({'name':n,'version':v}).encode()
  files['app/packages/paperclip-runner/runner/Cargo.lock']=b'version = 4\n'
  files['var/lib/dpkg/status']=b'Package: openssh-client\nVersion: 1:9.6p1-3ubuntu13.20\n'
  files['app/server/node_modules/@img/sharp-libvips-linux-x64/versions.json']=b'{"rsvg":"2.63.2"}'
  elf=bytearray(64);elf[:4]=b'\x7fELF';elf[16:18]=(2).to_bytes(2,'little');elf[18:20]=(62).to_bytes(2,'little');files['usr/local/bin/node']=bytes(elf)
  if secret:files['app/unsafe.txt']=b'-----BEGIN PRIVATE KEY-----\n'+b'A'*128+b'\n-----END PRIVATE KEY-----'
  data=io.BytesIO()
  with tarfile.open(fileobj=data,mode='w:gz') as tar:
   for n,b in files.items():m=tarfile.TarInfo(n);m.size=len(b);tar.addfile(m,io.BytesIO(b))
  layer=blob(data.getvalue(),'application/vnd.oci.image.layer.v1.tar+gzip');cfg=blob({'architecture':'amd64','os':'linux','config':{'User':'10001:10001','Cmd':['node','server/dist-runtime/index.mjs'],'Entrypoint':['/usr/bin/tini','-s','--','docker-entrypoint.sh']}},'application/vnd.oci.image.config.v1+json');image=blob({'schemaVersion':2,'config':cfg,'layers':[layer]},'application/vnd.oci.image.manifest.v1+json');att=[]
  for typ in ['https://slsa.dev/provenance/v1']+([] if missing_sbom else ['https://spdx.dev/Document']):att.append(blob({'predicateType':typ,'subject':[{'digest':{'sha256':('0'*64 if bad_subject else image['digest'].split(':')[1])}}],'predicate':{'packages':[{'name':'synthetic'}]}},'application/vnd.in-toto+json'))
  a=blob({'schemaVersion':2,'artifactType':'application/vnd.docker.attestation.manifest.v1+json','config':cfg,'layers':att},'application/vnd.oci.image.manifest.v1+json');(root/'index.json').write_text(json.dumps({'schemaVersion':2,'manifests':[image,a]}))
  if bad_hash:(root/'blobs/sha256'/cfg['digest'].split(':')[1]).write_bytes(b'corrupt')
  recipe=root/'recipe';recipe.mkdir();synthetic_pins=json.loads((public/'pins.json').read_text());synthetic_pins['source_hashes']['packages/paperclip-runner/runner/Cargo.lock']=hashlib.sha256(files['app/packages/paperclip-runner/runner/Cargo.lock']).hexdigest();policy={k:synthetic_pins[k] for k in ['upstream_commit','patch_sha256','source_hashes','dockerfile_sha256']};policy.update({'scope':'Synthetic inspector test only','admission_allowed':not manual_hold,'reviewed_public_fixture_exceptions':[],'reviewed_npm_response_sha256':hashlib.sha256(b'{}').hexdigest(),'reviewed_trivy_finding_keys':[],'npm_findings':[],'trivy_findings':[],'rust_review':[],'reviewed_rust_finding_keys':[],'required_runtime_conditions':[],'coverage_limits':[]});
  if review_fixture:
   raw=files['app/unsafe.txt'];matched=raw.split(b'-----END',1)[0];policy['reviewed_public_fixture_exceptions']=[{'path':'app/unsafe.txt','kind':'private_key','file_sha256':('0'*64 if mutate_exception else hashlib.sha256(raw).hexdigest()),'match_sha256':[hashlib.sha256(matched).hexdigest()],'reason':'Known synthetic fixture in unit test only','origin':'synthetic'}]
  review_bytes=json.dumps(policy).encode();(recipe/'security-review.json').write_bytes(review_bytes);synthetic_pins['security_review_sha256']=hashlib.sha256(review_bytes).hexdigest();(recipe/'pins.json').write_text(json.dumps(synthetic_pins));oldrust=sys.modules.get('audit_rust');mockrust=types.ModuleType('audit_rust');mockrust.audit_lock=lambda text:{'findings':([{'name':'unreviewed','version':'1.0.0','id':'NEW-RUST-ADVISORY'}] if unknown_rust else [])};sys.modules['audit_rust']=mockrust
  oldargv=sys.argv;oldurl=urllib.request.urlopen;oldrun=subprocess.run;oldhash=hashlib.file_digest;cwd=os.getcwd();sys.argv=['inspect_oci.py',str(root),str(out)];scanbuf=io.BytesIO()
  with tarfile.open(fileobj=scanbuf,mode='w:gz') as tf:
   m=tarfile.TarInfo('trivy');m.size=4;tf.addfile(m,io.BytesIO(b'mock'))
  scanbytes=scanbuf.getvalue()
  urllib.request.urlopen=lambda url,*a,**k:io.BytesIO(scanbytes if 'trivy_' in str(url) else b'{}')
  class MockHash:
   def hexdigest(self):return json.loads((public/'pins.json').read_text())['trivy']['sha256']
  hashlib.file_digest=lambda f,alg:MockHash() if str(getattr(f,'name','')).endswith('trivy.tar.gz') else oldhash(f,alg)
  def mock_scan(args,**kwargs):
   outpath=pathlib.Path(args[args.index('--output')+1]);outpath.write_text(json.dumps({'Metadata':{'OS':{'Family':'ubuntu'}},'Results':([{'Type':'node-pkg','Target':'synthetic','Vulnerabilities':[{'VulnerabilityID':'UNREVIEWED','PkgName':'synthetic','InstalledVersion':'1.0.0','Severity':'HIGH'}]}] if unknown_finding else [])}));return subprocess.CompletedProcess(args,1 if scanner_error else 0)
  subprocess.run=mock_scan
  os.chdir(recipe)
  status='PASS'
  try:
   with contextlib.redirect_stdout(io.StringIO()):runpy.run_path(str(public/'scripts/inspect_oci.py'),run_name='__main__')
  except SystemExit as ex:status='PASS' if ex.code==0 else 'BLOCKED'
  except AssertionError:status='BLOCKED'
  finally:
   sys.argv=oldargv;urllib.request.urlopen=oldurl;subprocess.run=oldrun;hashlib.file_digest=oldhash;os.chdir(cwd)
   if oldrust is None:sys.modules.pop('audit_rust',None)
   else:sys.modules['audit_rust']=oldrust
  expected='BLOCKED' if unknown_rust or manual_hold or (secret and not review_fixture) or mutate_exception or unknown_finding or missing_sbom or bad_hash or bad_subject or scanner_error else 'PASS';assert status==expected,(name,status);results.append({'test':name,'result':status,'passed':True})
case('valid-synthetic-layout');case('secret-blocks-publication',secret=True);case('missing-sbom-blocks',missing_sbom=True);case('digest-tamper-blocks',bad_hash=True)
case('wrong-attestation-subject-blocks',bad_subject=True);case('scanner-failure-blocks',scanner_error=True)
case('known-public-fixture-exact-fingerprint',secret=True,review_fixture=True);case('modified-fixture-fingerprint-blocks',secret=True,review_fixture=True,mutate_exception=True);case('unreviewed-vulnerability-blocks',unknown_finding=True);case('explicit-security-hold-blocks',manual_hold=True);case('new-rust-advisory-blocks',unknown_rust=True)
evidence=pathlib.Path(os.environ.get('RUNNER_TEMP',tempfile.gettempdir()))/'paperclip-b2';evidence.mkdir(exist_ok=True)
(evidence/'inspector-unit-tests.json').write_text(json.dumps({'scope':'Synthetic data, mocked advisory endpoint, no app or Docker execution','tests':results},indent=2));print('Inspector synthetic gates PASS',len(results))
