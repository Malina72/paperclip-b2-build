"""Read-only checks around a job-local Docker daemon. Never changes system settings."""
import os,json,pathlib,hashlib,subprocess,sys
R=pathlib.Path(os.environ['RUNNER_TEMP'])/'paperclip-b2';R.mkdir(exist_ok=True)
def docker(args,system=False):
 env=os.environ.copy();env.pop('DOCKER_HOST',None);env.pop('DOCKER_CONTEXT',None)
 prefix=['docker']+(['--host','unix:///var/run/docker.sock'] if system else [])
 return subprocess.run(prefix+args,env=env,capture_output=True,text=True,check=True,timeout=20).stdout

def snap():
 info=json.loads(docker(['info','--format','{{json .}}'],True));files={}
 for name in ['/etc/docker/daemon.json','/run/docker.pid','/proc/sys/kernel/apparmor_restrict_unprivileged_userns','/proc/sys/kernel/unprivileged_userns_clone','/proc/sys/kernel/seccomp/actions_avail']:
  p=pathlib.Path(name);files[name]=hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None
 return {'files':files,'system_id_hash':hashlib.sha256(info['ID'].encode()).hexdigest(),'system_root':info['DockerRootDir'],'system_security':info.get('SecurityOptions',[])}
if sys.argv[1]=='before':
 (R/'system-daemon-before.json').write_text(json.dumps(snap(),indent=2));print('Original daemon/security baseline recorded; no mutation')
else:
 before=json.loads((R/'system-daemon-before.json').read_text());after=snap();assert before==after,'System daemon/config/security changed'
 info=json.loads(docker(['info','--format','{{json .}}']));context=json.loads(docker(['context','inspect','paperclip-b2']))[0];endpoint=context['Endpoints']['docker']['Host'];scope=pathlib.Path(os.environ['RUNNER_TEMP'])/'paperclip-docker'
 assert endpoint.startswith('unix://'+str(scope)+'/'),'Socket not isolated'
 assert pathlib.Path(info['DockerRootDir']).is_relative_to(scope),'Data root not isolated'
 assert hashlib.sha256(info['ID'].encode()).hexdigest()!=before['system_id_hash'],'Same daemon as system'
 security=info.get('SecurityOptions',[]);assert any('seccomp' in x for x in security),'Seccomp missing';assert any('apparmor' in x for x in security),'AppArmor missing'
 ids=docker(['ps','-aq']).split()
 if ids:
  containers=json.loads(docker(['inspect']+ids));assert all(not c['HostConfig']['Privileged'] for c in containers),'Privileged container found';assert all(not any('unconfined' in s for s in (c['HostConfig'].get('SecurityOpt') or [])) for c in containers),'Unconfined container found'
 proof={'system_daemon_unchanged':True,'system_security_unchanged':True,'isolated_unix_socket':True,'isolated_data_root':True,'separate_daemon_id':True,'seccomp_enabled':True,'apparmor_enabled':True,'no_privileged_or_unconfined_containers_found':True,'stage':sys.argv[1]};(R/('isolation-'+sys.argv[1]+'.json')).write_text(json.dumps(proof,indent=2));print(json.dumps(proof,indent=2))
