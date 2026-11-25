"""Prepare an explicitly UNQUALIFIED diagnostic artifact; never run the binary."""
import pathlib,hashlib,json,re,shutil,os
from mac_binary_audit import macho_libraries

def prepare(binary,out,recipe,run_id):
 data=binary.read_bytes();macho_libraries(data)
 assert not re.search(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\s+[A-Za-z0-9+/=\r\n]{80,}|gh[pousr]_[A-Za-z0-9]{30,}|sk-proj-[A-Za-z0-9_-]{48,}',data),'Secret marker; do not preserve'
 out.mkdir();shutil.copy2(binary,out/'UNQUALIFIED-paperclip-runnerd-darwin-arm64')
 proof={'qualification':'NOT_COMPLETED_DO_NOT_EXECUTE','sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'recipe_commit':recipe,'github_run_id':run_id,'source_commit':'c0f132898d2a2677312d8c72096187b27a3d9a38','signed_provenance':False}
 (out/'UNQUALIFIED-inventory.json').write_text(json.dumps(proof,indent=2));return proof
if __name__=='__main__':
 print(json.dumps(prepare(pathlib.Path('source/packages/paperclip-runner/runner/target/release/paperclip-runnerd'),pathlib.Path('native-quarantine'),os.environ['GITHUB_SHA'],os.environ['GITHUB_RUN_ID']),indent=2))
