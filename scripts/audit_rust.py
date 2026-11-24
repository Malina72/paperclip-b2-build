"""Read Cargo.lock and public OSV/RustSec metadata only; no dependency execution."""
import json,hashlib,tomllib,urllib.request,concurrent.futures,pathlib,sys

def audit_lock(text):
 packages=[p for p in tomllib.loads(text)['package'] if p.get('source','').startswith('registry+')]
 queries=[{'package':{'ecosystem':'crates.io','name':p['name']},'version':p['version']} for p in packages]
 req=urllib.request.Request('https://api.osv.dev/v1/querybatch',data=json.dumps({'queries':queries}).encode(),headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(req,timeout=90) as f:result=json.load(f)
 assert len(result['results'])==len(packages)
 ids=sorted({v['id'] for x in result['results'] for v in x.get('vulns',[])})
 def detail(id):
  with urllib.request.urlopen('https://api.osv.dev/v1/vulns/'+id,timeout=45) as f:return id,json.load(f)
 with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:details=dict(pool.map(detail,ids))
 findings=[]
 for p,x in zip(packages,result['results']):
  for v in x.get('vulns',[]):
   d=details[v['id']];findings.append({'name':p['name'],'version':p['version'],'id':v['id'],'summary':d.get('summary'),'aliases':d.get('aliases',[]),'severity':d.get('severity'),'affected':d.get('affected'),'references':d.get('references')})
 return {'lock_sha256':hashlib.sha256(text.encode()).hexdigest(),'registry_packages':len(packages),'findings':findings,'raw_details':details,'scope':'Source lock overapproximation; compile-feature evidence needed. Missing CVSS is unknown, not zero.'}

if __name__=='__main__':
 p=pathlib.Path(sys.argv[1]);out=pathlib.Path(sys.argv[2]);data=audit_lock(p.read_text());out.write_text(json.dumps(data,indent=2));print('Rust audit',data['registry_packages'],'packages;',len(data['findings']),'records')
