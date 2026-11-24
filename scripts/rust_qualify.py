"""Run exactly the build-only TLS test executable, with network disabled by Dockerfile."""
import pathlib,json,subprocess,os,re,hashlib
root=pathlib.Path('/app/packages/paperclip-runner/runner');tree=pathlib.Path('/tmp/b3-rust-tree.txt').read_text();expected=json.loads(pathlib.Path('/tmp/b3-rust-versions.json').read_text())
for name,version in expected.items():assert re.search(r'\b'+re.escape(name)+r' v'+re.escape(version)+r'(?:\s|$)',tree),(name,version)
assert not re.search(r'\bquinn(?:-proto|-udp)? v',tree),'Previously excluded QUIC is in active production tree'
import sys
if len(sys.argv)>1 and sys.argv[1]=='compile':
 deps=root/'target/release/deps';args=['rustc','--edition=2021','--test','/tmp/b3_tls_fixture.rs','-L','dependency='+str(deps)]
 for name in ['rustls','webpki_roots']:
  libs=list(deps.glob('lib'+name+'-*.rlib'));assert len(libs)==1,(name,[x.name for x in libs]);args+=['--extern',name+'='+str(libs[0])]
 subprocess.run(args+['-o','/tmp/b3-tls-test'],check=True,timeout=120);sys.exit(0)
p=subprocess.run(['/tmp/b3-tls-test','--nocapture','--test-threads=1'],capture_output=True,text=True,env=os.environ|{'B3_CERT_DIR':'/tmp/b3-certs'},timeout=60);print(p.stdout);print(p.stderr);assert p.returncode==0 and '6 passed; 0 failed' in p.stdout
pathlib.Path('/tmp/b3-rust-results.json').write_text(json.dumps({'pass':True,'lock_sha256':hashlib.sha256((root/'Cargo.lock').read_bytes()).hexdigest(),'tls_tests':6,'tests':['trusted-chain','untrusted-chain','wrong-hostname','corrupted-signature','expired-chain','emsign-root-removed'],'versions':expected,'uses_production_rlibs':True,'quic_in_active_tree':False,'network':'none','application_started':False,'codex_started':False},indent=2))
