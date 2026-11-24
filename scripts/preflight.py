"""Bounded inspection of the disposable hosted runner, no application execution."""
import os,json,subprocess,pathlib,shutil,platform,time,re
GIB=2**30;R=pathlib.Path(os.environ['RUNNER_TEMP'])/'paperclip-b2';R.mkdir(exist_ok=True)
pins=json.loads(pathlib.Path('pins.json').read_text());report={'runner':'ubuntu-24.04','architecture':platform.machine(),'cpu_count':os.cpu_count(),'advertised_disk_gb':14,'not_a_guarantee_of_35_gib':True,'extra_spending_usd':0}
def cmd(args,timeout=20):
 p=subprocess.run(args,capture_output=True,text=True,timeout=timeout);return p.returncode,p.stdout,p.stderr
def parse_builder_inspect(text):
 driver=re.search(r'^Driver:\s*(\S+)',text,re.M)
 versions=re.findall(r'^BuildKit version:\s*(\S+)',text,re.M)
 return (driver.group(1) if driver else None,versions)

def disk():
 path='/var/lib/docker' if pathlib.Path('/var/lib/docker').exists() else '/';u=shutil.disk_usage(path);return {'total_bytes':u.total,'free_bytes':u.free}
mem=dict((line.split(':',1)[0],int(line.split()[1])*1024) for line in pathlib.Path('/proc/meminfo').read_text().splitlines() if len(line.split())>=3)
report['ram_bytes']=mem['MemTotal'];report['available_ram_bytes']=mem['MemAvailable'];report['disk_before']=disk();code,out,err=cmd(['docker','version','--format','{{json .Server}}']);server=json.loads(out) if code==0 else {};report['docker']={k:server.get(k) for k in ['Version','ApiVersion','Os','Arch','KernelVersion']};code,out,err=cmd(['docker','buildx','version']);report['buildx']=out.strip();code,out,err=cmd(['docker','buildx','inspect',os.environ.get('PILOT_BUILDER','default')]);report['builder_probe_exit']=code;report['driver'],report['buildkit_versions']=parse_builder_inspect(out) if code==0 else (None,[]);code,out,err=cmd(['docker','info','--format','{{json .DriverStatus}}']);report['containerd_image_store']=code==0 and 'io.containerd.snapshotter' in out
# Conservative peak envelope, not a measured result or a minimum final-image size.
budget={'source_context':0.4,'os_node_layers_and_packages':2,'rust_toolchain_and_crate_cache':5,'js_store_and_dependency_snapshots':8,'rust_target_cache':10,'build_output_snapshots':6,'oci_export_and_streaming_inspection':5,'sbom_generator':1,'reserve':5,'native_tls_qualification':3};report['disk_budget_gib']=budget;report['estimated_peak_gib']=sum(budget.values());report['required_free_gib']=48;report['cleanup']=[]
# Only preinstalled SDKs on this fresh hosted VM; no Docker prune, security or daemon changes.
if report['disk_before']['free_bytes']<48*GIB and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted':
 for name in ['/usr/local/lib/android','/usr/share/dotnet','/opt/ghc']:
  if pathlib.Path(name).is_dir():
   code,_,_=cmd(['sudo','rm','-rf','--',name],timeout=90);report['cleanup'].append({'sdk_path':name,'exit':code})
report['disk_after']=disk();reasons=[]
if os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted' or os.environ.get('REPOSITORY_VISIBILITY')!='public':reasons.append('not_standard_public_hosted_context')
if platform.machine()!='x86_64':reasons.append('not_amd64')
if report['ram_bytes']<15_000_000_000:reasons.append('insufficient_ram')
if report['disk_after']['free_bytes']<48*GIB:reasons.append('insufficient_disk_for_conservative_envelope')
if report['driver']!='docker':reasons.append('default_docker_driver_required_no_privileged_custom_builder')
if not report['containerd_image_store']:reasons.append('existing_containerd_store_missing_no_daemon_reconfiguration')
# Tiny static OCI build tests exporter+attestations; it has no executable image code.
if not reasons:
 probe=R/'probe';probe.mkdir();(probe/'Dockerfile').write_text('FROM scratch\nCOPY probe.txt /probe.txt\n');(probe/'probe.txt').write_text('synthetic OCI attestation preflight\n')
 args=['docker','buildx','build','--builder',os.environ.get('PILOT_BUILDER','default'),'--platform','linux/amd64','--tag','paperclip-b2-attestation-probe:local','--provenance=mode=max','--sbom=generator='+pins['sbom_generator'],'--output',f'type=oci,dest={R}/probe-oci,tar=false',str(probe)]
 code,out,err=cmd(args,timeout=180);report['attestation_probe_exit']=code
 if code!=0:reasons.append('bounded_oci_attestation_probe_failed');report['probe_error_class']='Exporter/SBOM/provenance capability failure; no security fallback'
 else:
  predicates=[];subjects=[]
  for p in (R/'probe-oci/blobs/sha256').glob('*'):
   if p.stat().st_size>10*1024*1024:continue
   try:x=json.loads(p.read_text())
   except (ValueError,UnicodeDecodeError):continue
   if isinstance(x,dict) and x.get('predicateType'):predicates.append(x['predicateType']);subjects.append({'predicateType':x['predicateType'],'subject':x.get('subject')})
  report['attestation_predicates']=predicates;report['attestation_subjects']=subjects
  if not all(x['subject'] and all(y.get('digest',{}).get('sha256') for y in x['subject']) for x in subjects):reasons.append('empty_attestation_subject_before_full_build')
  if not any('spdx' in x for x in predicates) or not any('slsa' in x for x in predicates):reasons.append('attestations_not_present_in_export')
report['eligible']=not reasons;report['stop_reasons']=reasons;(R/'preflight.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2))
with open(os.environ['GITHUB_OUTPUT'],'a') as f:f.write('eligible='+str(report['eligible']).lower()+'\n')
with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as f:f.write('## B2 preflight\n```json\n'+json.dumps(report,indent=2)+'\n```\n')
