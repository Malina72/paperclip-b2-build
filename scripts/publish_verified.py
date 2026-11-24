import pathlib,os,json,urllib.request,hashlib,subprocess
R=pathlib.Path(os.environ['RUNNER_TEMP'])/'paperclip-b2';pins=json.loads(pathlib.Path('pins.json').read_text());proof=json.loads((R/'image-evidence/image-verification.json').read_text());assert all(proof[k] for k in ['composition_pass','secrets_scan_pass','sbom_present','provenance_present','security_review_pass','static_review_pass','component_checks_pass','attestation_binding_pass','rust_tls_qualification_pass']);tool=R/'regctl'
with urllib.request.urlopen(pins['regctl']['url'],timeout=30) as f:tool.write_bytes(f.read())
assert hashlib.file_digest(tool.open('rb'),'sha256').hexdigest()==pins['regctl']['sha256'];tool.chmod(0o700)
env=os.environ.copy();env['REGCTL_CONFIG']=str(R/'registry-config.json');token=env.pop('GHCR_TOKEN');assert token
subprocess.run([str(tool),'registry','login','ghcr.io','--user',os.environ['GITHUB_ACTOR'],'--pass-stdin'],input=token,text=True,env=env,check=True,stdout=subprocess.DEVNULL);del token
# Address the complete verified root OCI index, preserving SBOM/provenance descriptors.
oci=R/'image-oci';raw=(oci/'index.json').read_bytes();h=hashlib.sha256(raw).hexdigest();(oci/'blobs/sha256'/h).write_bytes(raw);repo=os.environ['GITHUB_REPOSITORY'].split('/')[0].lower();tag=os.environ['GITHUB_SHA'][:12];dest=f'ghcr.io/{repo}/paperclip-pilot-b3:{tag}'
subprocess.run([str(tool),'image','copy','ocidir://'+str(oci)+'@sha256:'+h,dest],env=env,check=True)
p=subprocess.run([str(tool),'image','digest',dest],env=env,check=True,capture_output=True,text=True);assert p.stdout.strip()=='sha256:'+h,'Registry index differs';proof.update({'published_image':dest,'published_digest':p.stdout.strip()});(R/'image-evidence/image-verification.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof,indent=2));(R/'registry-config.json').unlink(missing_ok=True)
