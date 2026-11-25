"""Qualify a B3-only native artifact; never launches a provider or agent."""
import pathlib,subprocess,sys,json,hashlib,os,re,tomllib,platform,time
from audit_rust import audit_lock
repo=pathlib.Path.cwd();source=repo/'source';runner=source/'packages/paperclip-runner/runner';out=repo/'native-evidence';out.mkdir(exist_ok=True)
def run(a,cwd=runner):return subprocess.run(a,cwd=cwd,text=True,capture_output=True,check=True,timeout=180).stdout
lock=(runner/'Cargo.lock').read_text();pins=json.loads((repo/'pins.json').read_text());versions=json.loads((repo/'scripts/b3-rust-versions.json').read_text())
# The source archive and patch were already checked by the workflow.
assert platform.system()=='Darwin' and platform.machine()=='arm64'
tree=run(['cargo','tree','--locked','--edges','normal,build','--target','aarch64-apple-darwin','-p','paperclip-runner-core']);(out/'production-tree.txt').write_text(tree.replace(str(repo),'<recipe>'))
for n,v in versions.items():assert re.search(r'\b'+re.escape(n)+' v'+re.escape(v)+r'(?:\s|$)',tree),(n,v)
assert not re.search(r'\bquinn(?:-proto|-udp)? v',tree)
deps=runner/'target/release/deps';a=['rustc','--edition=2021','--test',str(repo/'scripts/b3_tls_fixture.rs'),'-L','dependency='+str(deps)]
for name in ['rustls','webpki_roots']:
 libs=list(deps.glob('lib'+name+'-*.rlib'));assert len(libs)==1,(name,len(libs));a+=['--extern',name+'='+str(libs[0])]
run(a+['-o',str(out/'tls-tests')]);certs=out/'certs';certs.mkdir()
openssl='/opt/homebrew/opt/openssl@3/bin/openssl';assert pathlib.Path(openssl).is_file()
for args in [['req','-x509','-newkey','rsa:2048','-nodes','-keyout','root.key','-out','root.pem','-subj','/CN=B3 Synthetic Test Root','-days','2'],['req','-newkey','rsa:2048','-nodes','-keyout','leaf.key','-out','leaf.csr','-subj','/CN=fixture.invalid']]:run([openssl]+args,certs)
(certs/'extensions.cnf').write_text('subjectAltName=DNS:fixture.invalid\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
run([openssl,'x509','-req','-in','leaf.csr','-CA','root.pem','-CAkey','root.key','-CAcreateserial','-out','leaf.pem','-days','2','-extfile','extensions.cnf'],certs)
for n in ['root','leaf']:run([openssl,'x509','-in',n+'.pem','-outform','DER','-out',n+'.der'],certs)
run([openssl,'pkcs8','-topk8','-nocrypt','-in','leaf.key','-outform','DER','-out','leaf.key.der'],certs)
p=subprocess.run([str(out/'tls-tests'),'--test-threads=1'],env=os.environ|{'B3_CERT_DIR':str(certs)},text=True,capture_output=True,timeout=60);assert p.returncode==0 and '6 passed; 0 failed' in p.stdout;(out/'tls-tests.txt').write_text(p.stdout)
# OSV compares the same complete lock against the previously reviewed records.
audit=audit_lock(lock);policy=json.loads((repo/'security-review.json').read_text())
expected={tuple(x) for x in policy['reviewed_rust_finding_keys']}
actual={(x['name'],x['version'],x['id']) for x in audit['findings']};assert actual==expected,'New or changed Rust finding requires review'
(out/'rust-audit.json').write_text(json.dumps(audit,indent=2))
binary=runner/'target/release/paperclip-runnerd';data=binary.read_bytes();sha=hashlib.sha256(data).hexdigest()
assert not re.search(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\s+[A-Za-z0-9+/=\r\n]{80,}',data),'Unknown private-key marker in artifact'
assert not re.search(rb'gh[pousr]_[A-Za-z0-9]{30,}|sk-proj-[A-Za-z0-9_-]{48,}',data),'Unknown secret-like marker'
metadata=json.loads(run([str(binary),'--build-metadata']));(out/'build-metadata.json').write_text(json.dumps(metadata,indent=2))
native=run(['/usr/bin/otool','-L',str(binary)]);(out/'native-libraries.txt').write_text(native.replace(str(runner),'<source>/runner'))
assert '/opt/homebrew/' not in native and '/Users/' not in native,'Unexpected non-system dylib'
packages=tomllib.loads(lock)['package'];spdx=[]
registry=pathlib.Path(os.environ.get('CARGO_HOME',str(pathlib.Path.home()/'.cargo')))/'registry/src'
for i,x in enumerate(packages):
 item={'name':x['name'],'SPDXID':'SPDXRef-Package-'+str(i),'versionInfo':x['version'],'downloadLocation':('https://crates.io/crates/'+x['name']+'/'+x['version'] if x.get('source','').startswith('registry+') else 'NOASSERTION'),'filesAnalyzed':False,'licenseConcluded':'NOASSERTION','licenseDeclared':'NOASSERTION','copyrightText':'NOASSERTION'}
 manifests=list(registry.glob('*/'+x['name']+'-'+x['version']+'/Cargo.toml'))
 if manifests:
  package=tomllib.loads(manifests[0].read_text()).get('package',{});license=package.get('license')
  if isinstance(license,str):item['licenseDeclared']=license
 item['externalRefs']=[{'referenceCategory':'PACKAGE-MANAGER','referenceType':'purl','referenceLocator':'pkg:cargo/'+x['name']+'@'+x['version']}]
 if 'checksum'in x:item['checksums']=[{'algorithm':'SHA256','checksumValue':x['checksum']}]
 spdx.append(item)
sbom={'spdxVersion':'SPDX-2.3','dataLicense':'CC0-1.0','SPDXID':'SPDXRef-DOCUMENT','name':'B3 darwin-arm64 runner source-lock inventory','documentNamespace':'https://github.com/'+os.environ['GITHUB_REPOSITORY']+'/runs/'+os.environ['GITHUB_RUN_ID']+'/sbom','creationInfo':{'created':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'creators':['Tool: B3-native-qualification']},'packages':spdx,'documentComment':'Lock overapproximation; production-tree.txt identifies active Darwin target dependencies. System frameworks in native-libraries.txt; no full Apple OS vulnerability certification.'}
(out/'sbom.spdx.json').write_text(json.dumps(sbom,indent=2))
provenance={'_type':'https://in-toto.io/Statement/v1','subject':[{'name':'paperclip-runnerd-darwin-arm64','digest':{'sha256':sha}}],'predicateType':'https://slsa.dev/provenance/v1','predicate':{'buildDefinition':{'buildType':'https://github.com/'+os.environ['GITHUB_REPOSITORY']+'/native-b3/v1','externalParameters':{'recipe':os.environ['GITHUB_SHA'],'source_commit':'c0f132898d2a2677312d8c72096187b27a3d9a38','cargo_lock_sha256':hashlib.sha256(lock.encode()).hexdigest()},'internalParameters':{},'resolvedDependencies':[]},'runDetails':{'builder':{'id':'https://github.com/'+os.environ['GITHUB_REPOSITORY']+'/actions/runs/'+os.environ['GITHUB_RUN_ID']},'metadata':{'invocationId':os.environ['GITHUB_RUN_ID']}}}}
(out/'provenance.json').write_text(json.dumps(provenance,indent=2));(out/'SHA256SUMS').write_text(sha+'  paperclip-runnerd-darwin-arm64\n')
proof={'artifact':'paperclip-runnerd-darwin-arm64','sha256':sha,'bytes':len(data),'platform':'darwin-arm64','tls_tests':6,'versions':versions,'lock_sha256':hashlib.sha256(lock.encode()).hexdigest(),'rust_advisory_records':len(actual),'new_rust_findings':False,'private_key_markers':False,'system_dylibs_only':True,'application_started':False,'provider_started':False,'model_calls':0,'identity_signature_verified':False,'pass':True};(out/'verification.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof,indent=2))
# Explicit publication set: no generated private test keys or test executable.
import shutil
pub=repo/'native-publication';pub.mkdir();shutil.copy2(binary,pub/'paperclip-runnerd-darwin-arm64')
for n in ['verification.json','SHA256SUMS','sbom.spdx.json','provenance.json','build-metadata.json','native-libraries.txt','production-tree.txt','tls-tests.txt']:shutil.copy2(out/n,pub/n)
