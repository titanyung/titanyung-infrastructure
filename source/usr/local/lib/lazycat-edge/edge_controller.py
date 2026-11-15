"""DMIT-side authoritative account/rule publisher; edge needs no resident agent.

Registry, snapshots and payloads are root-private.  Empty/missing registry is a
no-op; importing this module never changes a service, firewall, user or file.
"""
from __future__ import annotations
import argparse,copy,hashlib,io,ipaddress,json,os,re,shlex,stat,subprocess,tarfile,tempfile,time,urllib.request
from pathlib import Path
from contextlib import contextmanager
from edge_bundle import build_bundle,canonical_json
REGISTRY=Path('/etc/submerge-edge/edges.json')
STATE=Path('/var/lib/submerge-edge')
class ControllerError(RuntimeError):pass
def need(value,code):
 if not value:raise ControllerError(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def private_json(path,*,missing=None):
 path=Path(path)
 if not path.exists():return missing
 need(not path.is_symlink(),'symlink_control_file')
 info=path.stat();need(stat.S_ISREG(info.st_mode) and info.st_size<=1024*1024,'control_file_size')
 if os.name!='nt':need(info.st_uid==0 and not info.st_mode&0o077,'private_control_file_required')
 return json.loads(path.read_bytes())
def atomic(path,value):
 path=Path(path);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 fd,name=tempfile.mkstemp(dir=str(path.parent),prefix='.edge-controller-')
 try:
  with os.fdopen(fd,'wb') as stream:
   stream.write(canonical_json(value));stream.flush();os.fsync(stream.fileno())
   if os.name!='nt':os.fchmod(stream.fileno(),0o600)
  os.replace(name,path)
 finally:
  if os.path.exists(name):os.unlink(name)

EXPECTED_ASNS={'lazycat-starhub':{'4657'},'uzuma-singtel':{'45143'},'uzuma-starhub':{'4657'}}
def origin_network(address,cache):
 address=str(ipaddress.ip_address(address));now=int(time.time());old=cache.get(address,{})
 if 0<=now-int(old.get('checked_at',0))<3600:return old
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
 with opener.open('https://stat.ripe.net/data/network-info/data.json?resource='+address,timeout=8) as response:raw=response.read(65537)
 need(len(raw)<=65536,'network_origin_response_limit');value=json.loads(raw)
 need(value.get('status')=='ok','network_origin_unverified');data=value['data']
 need(ipaddress.ip_address(address) in ipaddress.ip_network(data['prefix']),'network_origin_prefix_mismatch')
 result={'asns':[str(x) for x in data['asns']],'prefix':data['prefix'],'checked_at':now}
 need(bool(result['asns']),'network_origin_missing');cache[address]=result;return result
def qualify_ai_paths(proof,cache,*,lookup=origin_network):
 """Trust verified AI TLS observations plus current access-network origin.

 A dynamic residential IP need not match yesterday's IP, but its ASN and both
 sensitive-site observations must match. An ordinary data-centre trace is not
 evidence for either AI path.
 """
 value=copy.deepcopy(proof)
 if value.get('status')!='completed':return value
 for row in value.get('paths',[]):
  label=row.get('label')
  if label not in EXPECTED_ASNS:row['healthy']=False;continue
  checks=[item for item in row.get('checks',[]) if item.get('site') in ('chatgpt.com','claude.ai')]
  valid=len(checks)==2 and {item.get('site') for item in checks}=={'chatgpt.com','claude.ai'}
  origins=[]
  for item in checks:
   try:
    address=ipaddress.ip_address(item.get('ip'))
    need(item.get('status')=='observed' and item.get('returncode')==0 and item.get('http_status')==200
     and item.get('loc')=='SG' and address.version==4 and address.is_global,'ai_trace_unverified')
    origin=lookup(str(address),cache);asns=set(origin['asns'])
    need(bool(asns) and asns<=EXPECTED_ASNS[label],'unexpected_ai_access_network')
    origins.append(dict(origin,site=item['site'],ip=str(address)))
   except Exception:valid=False
  row.update(healthy=valid,status='verified_access_network' if valid else 'ai_access_network_unverified',network_origins=origins)
 return value
def registry(path=REGISTRY):
 value=private_json(path,missing={'schema':1,'edges':[]})
 need(isinstance(value,dict) and value.get('schema')==1 and isinstance(value.get('edges'),list),'registry_schema')
 ids=set();rows=[]
 for row in value['edges']:
  need(isinstance(row,dict) and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}',str(row.get('edge_id',''))),'registry_edge_id')
  need(row['edge_id'] not in ids,'registry_duplicate_edge');ids.add(row['edge_id'])
  if row.get('enabled') is True:rows.append(row)
 return rows
def write_delta(bundle,path,previous=None):
 old={row['path']:(row['sha256'],row['size'],row['mode']) for row in (previous or {}).get('files',[])}
 changed=[]
 with tarfile.open(str(path),mode='w',format=tarfile.USTAR_FORMAT) as archive:
  def add(name,raw,mode):
   entry=tarfile.TarInfo(name);entry.size=len(raw);entry.mode=mode;entry.uid=entry.gid=entry.mtime=0
   archive.addfile(entry,io.BytesIO(raw))
  add('manifest.json',bundle.manifest_bytes,0o600)
  for row in bundle.manifest['files']:
   if old.get(row['path'])==(row['sha256'],row['size'],row['mode']):continue
   add(row['path'],bundle.files[row['path']],row['mode']);changed.append(row['path'])
 Path(path).chmod(0o600)
 return {'changed_files':changed,'wire_bytes':Path(path).stat().st_size,'delta':previous is not None}
class SSHTransport:
 def __init__(self,edge):
  import ipaddress
  address=ipaddress.ip_address(edge['public_ipv4'])
  need(address.version==4 and address.is_global,'literal_edge_public_ip_required')
  need(type(edge.get('ssh_port')) is int and 0<edge['ssh_port']<65536,'invalid_edge_ssh_port')
  for field in ('identity_file','known_hosts'):
   path=Path(edge[field]);need(path.is_absolute() and path.is_file() and not path.is_symlink(),'pinned_ssh_file_required')
  self.edge=edge
  self.args=['ssh','-i',edge['identity_file'],'-o','UserKnownHostsFile='+edge['known_hosts'],
   '-o','IdentitiesOnly=yes','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
   '-o','ControlMaster=auto','-o','ControlPersist=60',
   '-o','ControlPath=/run/submerge-edge-'+edge['edge_id']+'.sock',
   '-o','ConnectTimeout=8','-p',str(edge['ssh_port']),'root@'+str(address)]
 def command(self,argv,*,stdin=None,timeout=60):
  try:r=subprocess.run(self.args+[shlex.join(argv)],stdin=stdin,capture_output=True,timeout=timeout)
  except (OSError,subprocess.TimeoutExpired):raise ControllerError('edge_ssh_unavailable') from None
  if r.returncode:raise ControllerError('edge_operation_not_acknowledged')
  need(len(r.stdout)<=256*1024,'edge_response_limit')
  try:return json.loads(r.stdout)
  except ValueError:raise ControllerError('edge_reply_invalid') from None
 def apply(self,path,manifest_sha,*,delta):
  argv=['python3','/usr/local/lib/lazycat-edge/edge_apply.py','--manifest-sha256',manifest_sha]
  if delta:argv.append('--delta')
  with Path(path).open('rb') as stream:return self.command(argv,stdin=stream,timeout=90)
 def status(self):return self.command(['python3','/usr/local/lib/lazycat-edge/edge_status.py','status'],timeout=20)
 def pool_probe(self,port):return self.command(['python3','/usr/local/lib/lazycat-edge/edge_pool_probe.py','--port',str(port)],timeout=20)
 def probe(self):return self.command(['python3','/usr/local/lib/lazycat-edge/edge_probe.py','--root',self.edge['install_root'],'--expected-exits','/etc/lazycat-edge/expected-exits.json'],timeout=25)
 def set_health(self,generation,mode):
  return self.command(['python3','/usr/local/lib/lazycat-edge/edge_status.py','set-health','--generation',str(generation),'--mode',mode],timeout=20)
 def logs(self,cursor):
  argv=['python3','/usr/local/lib/lazycat-edge/edge_logs.py','read','--limit','200']
  if cursor:argv+=['--cursor',cursor]
  return self.command(argv,timeout=15)
class LocalTransport(SSHTransport):
 def __init__(self,edge):
  need(edge.get('edge_id')=='dmit-ai-20261108' and edge.get('execution')=='local_authority','local_authority_scope_invalid')
  self.edge=edge;self.args=[]
 def command(self,argv,*,stdin=None,timeout=60):
  try:r=subprocess.run(argv,stdin=stdin,capture_output=True,timeout=timeout)
  except (OSError,subprocess.TimeoutExpired):raise ControllerError('local_ai_unavailable') from None
  need(r.returncode==0,'local_ai_operation_not_acknowledged')
  need(len(r.stdout)<=256*1024,'edge_response_limit')
  try:return json.loads(r.stdout)
  except ValueError:raise ControllerError('edge_reply_invalid') from None
def transport_for(edge):
 return LocalTransport(edge) if edge.get('execution')=='local_authority' else SSHTransport(edge)
class Authority:
 def __init__(self,runtime='/run/dmit-direct-staging/config.json',plan='/etc/submerge-topology/network-plan.json',binary='/root/lazycat-test-config/sing-box'):
  self.runtime,self.plan,self.binary=map(Path,(runtime,plan,binary))
 def fingerprint(self,edge):
  # Rechecking the small authoritative runtime is cheaper than loading binary
  # bytes or forwarding a full snapshot on every polling cycle.
  return sha(self.runtime.read_bytes()+b'\0'+self.plan.read_bytes()+b'\0'+canonical_json(edge))
 def build(self,edge,generation,*,bootstrap_health_proof=None):
  import sys
  sys.path[:0]=['/opt/submerge-topology','/opt/submerge-client-policy','/opt/submerge-user-access','/opt/submerge']
  import network_runtime
  runtime=json.loads(self.runtime.read_bytes());plan=json.loads(self.plan.read_bytes())
  network_runtime.validate_loaded_server_policy(runtime,plan)
  initial_mode='ai-z0s0l0pn' if edge.get('scope')=='ai' and edge.get('ai_pool_version',1)in (3,4) else 'ai-z0s0l0'
  if edge.get('scope')=='ai':
   version=edge.get('ai_pool_version',1)
   need(type(version) is int and version in (1,2,3,4),'unreviewed_ai_pool_version')
   if version==4:
    from edge_ai_policy_v4 import project_ai_runtime,MODES
    from ai_health_v4 import bootstrap_mode
    need(edge.get('bootstrap_health_mode') in MODES,'v4_bootstrap_mode_required')
    initial_mode=bootstrap_mode(bootstrap_health_proof,'dmit' if edge.get('execution')=='local_authority' else 'lazycat',now=time.time())
    need(initial_mode==edge['bootstrap_health_mode'],'bootstrap_mode_proof_disagreement')
    extra={'manual_tls':edge['manual_tls'],'routing_revision':plan['server_policy']['routing_revision'],
     'execution_front':'dmit' if edge.get('execution')=='local_authority' else 'lazycat'}
    if not any(row.get('tag')=='uzuma-starhub' for row in runtime['outbounds']):extra['extra_transport']=edge['extra_transports']['uzuma-starhub']
   elif version==3:
    from edge_ai_policy_v3 import project_ai_runtime
    extra={'manual_tls':edge['manual_tls']}
    if not any(row.get('tag')=='uzuma-starhub' for row in runtime['outbounds']):extra['extra_transport']=edge['extra_transports']['uzuma-starhub']
   elif version==2:
    from edge_ai_policy_v2 import project_ai_runtime
    extra={}
    if not any(row.get('tag')=='uzuma-starhub' for row in runtime['outbounds']):extra['extra_transport']=edge['extra_transports']['uzuma-starhub']
   else:
    from edge_ai_policy import project_ai_runtime
    extra={}
   roles={key:plan['server_policy']['rule_sets'][key] for key in ('ai','google','youtube')}
   raw_assets={row['path']:Path(row['path']).read_bytes() for row in roles.values()}
   runtime,_=project_ai_runtime(runtime,asset_roles=roles,asset_bytes=raw_assets,
    google_fallback_endpoint=edge['google_fallback_endpoint'],health_mode=initial_mode,**extra)
  assets={row['path']:Path(row['path']).read_bytes() for row in runtime['route']['rule_set'] if row.get('type')=='local'}
  def dictionaries(value):
   if isinstance(value,dict):
    yield value
    for child in value.values():yield from dictionaries(child)
   elif isinstance(value,list):
    for child in value:yield from dictionaries(child)
  tls={row[key]:Path(row[key]).read_bytes() for row in dictionaries(runtime) for key in
   ('certificate_path','key_path','client_certificate_path','client_key_path') if key in row}
  # New execution endpoints receive independent management secrets.  Their
  # transport-account cohort remains exactly the authoritative DMIT cohort.
  if edge.get('management_secrets'):
   runtime['experimental']['clash_api']['secret']=edge['management_secrets']['clash']
   for service in runtime.get('services',[]):
    if service.get('type')=='ssm-api' or 'secret' in service:service['secret']=edge['management_secrets']['native']
  if edge.get('management_ports'):
   runtime['experimental']['clash_api']['external_controller']='127.0.0.1:'+str(edge['management_ports']['clash'])
   for service in runtime.get('services',[]):service.update(listen='127.0.0.1',listen_port=edge['management_ports']['native'])
  if edge.get('log_level'):
   need(edge['log_level'] in ('info','debug'),'unreviewed_log_level')
   runtime['log']={'disabled':False,'level':edge['log_level'],'timestamp':True}
  endpoint_mapping=edge['endpoint_mapping'];local_services=edge.get('local_outbound_services')
  if edge.get('ai_pool_version')==4:
   # V4 no longer routes any Google traffic through the old Taiwan/HKT bridge.
   # Do not declare its unused listener as a bootstrap dependency either.
   endpoint_mapping={k:v for k,v in endpoint_mapping.items() if k!='dmit-google-fallback'}
   local_services={k:v for k,v in (local_services or {}).items() if k!='dmit-google-fallback'}
  return build_bundle(runtime,edge_id=edge['edge_id'],identity_generation=generation,
   install_root=edge['install_root'],binary=self.binary.read_bytes(),assets=assets,tls_files=tls,
   endpoint_mapping=endpoint_mapping,source_ipv4=edge['local_bind_ipv4'],source_ipv6=edge.get('local_bind_ipv6'),
   health_mode=initial_mode,inbound_listen=edge.get('inbound_listen','127.0.0.1'),
   outbound_overrides=edge.get('outbound_overrides'),local_outbound_services=local_services,
   expected_inbound_count=(4 if edge.get('ai_pool_version',1) in (3,4) else 2) if edge.get('scope')=='ai' else 14,
   authority_host=edge.get('execution')=='local_authority',inbound_port_mapping=edge.get('inbound_port_mapping'),
   routing_revision=plan['server_policy'].get('routing_revision') if edge.get('ai_pool_version',1)==4 else None,
   execution_front=('dmit' if edge.get('execution')=='local_authority' else 'lazycat') if edge.get('ai_pool_version',1)==4 else None)
class Publisher:
 def __init__(self,*,authority=None,state_dir=STATE,transport_factory=transport_for):
  self.authority=authority or Authority();self.state_dir=Path(state_dir);self.transport_factory=transport_factory
 @contextmanager
 def lock(self,edge_id):
  try:import fcntl
  except ImportError:fcntl=None
  self.state_dir.mkdir(mode=0o700,parents=True,exist_ok=True)
  with (self.state_dir/(edge_id+'.lock')).open('a+b') as stream:
   if os.name!='nt':os.fchmod(stream.fileno(),0o600)
   if fcntl is not None:fcntl.flock(stream,fcntl.LOCK_EX)
   yield
 def synchronize(self,edge,*,subject=None,enabled=None,source_generation=None,verify_interval=0):
  edge_id=edge['edge_id'];need(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}',edge_id),'unsafe_edge_id')
  with self.lock(edge_id):
   path=self.state_dir/(edge_id+'.json');state=private_json(path,missing={'highest_generation':0})
   transport=self.transport_factory(edge);fingerprint=self.authority.fingerprint(edge)
   try:
    if state.get('confirmed_input_sha256')==fingerprint:
     if subject is None and verify_interval and time.time()-state.get('verified_at',0)<verify_interval:
      return {'status':'confirmed','edge_id':edge_id,'generation':state['last_ack']['generation'],'idempotent':True}
     current=transport.status();ack=state['last_ack']
     need(current.get('generation')==ack['generation'] and current.get('cohort_sha256')==ack['cohort_sha256'] and current.get('verified') is True,'edge_loaded_state_unverified')
     users=current.get('active_usernames',[])
     if subject is not None:need((subject in users)==enabled,'subject_state_not_applied')
     mirror_path=self.state_dir/(edge_id+'-mirror.json')
     mirror=private_json(mirror_path,missing=None)
     if mirror is not None:
      mirror.update(loaded_status=current,checked_at=int(time.time()));atomic(mirror_path,mirror)
     state['verified_at']=int(time.time());atomic(path,state)
     return {'status':'confirmed','edge_id':edge_id,'generation':ack['generation'],'idempotent':True}
    bootstrap=None;execution_edge=edge
    if edge.get('ai_pool_version',1)==4:
     from edge_ai_policy_v4 import MODES
     need(edge.get('bootstrap_health_mode') in MODES,'v4_registry_bootstrap_mode_required')
     from ai_health_v4 import qualify,bootstrap_mode
     cache_path=self.state_dir/'origin-cache.json';cache=private_json(cache_path,missing={})
     bootstrap=qualify(transport.probe(),cache,lookup=origin_network,now=time.time())
     bootstrap['front']='dmit' if edge.get('execution')=='local_authority' else 'lazycat'
     mode=bootstrap_mode(bootstrap,bootstrap['front'],now=time.time())
     if mode=='ai-z0s0l0pn':
      revision=json.loads(self.authority.plan.read_bytes())['server_policy']['routing_revision']
      airport=transport.pool_probe(revision['pools']['SG']['server_port'])
      # A closed global airport gate is correct while the other front still
      # has an owned path. Account revocations must still be applied here;
      # this front fails application health and the client tries the other.
      bootstrap['airport_pool']=airport
     execution_edge=dict(edge,bootstrap_health_mode=mode)
     atomic(cache_path,dict(sorted(cache.items(),key=lambda row:row[1].get('checked_at',0),reverse=True)[:256]))
    generation=state.get('pending_generation') if state.get('pending_input_sha256')==fingerprint else None
    if bootstrap is not None and state.get('pending_bootstrap_mode')!=execution_edge['bootstrap_health_mode']:generation=None
    if generation is None:generation=state['highest_generation']+1
    bundle=self.authority.build(execution_edge,generation,bootstrap_health_proof=bootstrap) if bootstrap is not None else self.authority.build(edge,generation)
    users=bundle.manifest['accounts']['usernames']
    if subject is not None:need((subject in users)==enabled,'authoritative_subject_not_ready')
    need(self.authority.fingerprint(edge)==fingerprint,'authority_changed_during_export')
    state.update(highest_generation=generation,pending_generation=generation,pending_input_sha256=fingerprint,pending_manifest_sha256=bundle.manifest_sha256)
    if bootstrap is not None:
     state.update(pending_bootstrap_mode=execution_edge['bootstrap_health_mode'],last_bootstrap_health_proof=bootstrap)
    atomic(path,state)
    with tempfile.TemporaryDirectory(prefix='.outgoing-',dir=str(self.state_dir)) as name:
     payload=Path(name)/'bundle.tar';wire=write_delta(bundle,payload,state.get('confirmed_manifest'))
     ack=transport.apply(payload,bundle.manifest_sha256,delta=wire['delta'])
    need(ack.get('status')=='applied' and ack.get('edge_id')==edge_id and ack.get('generation')==generation and ack.get('manifest_sha256')==bundle.manifest_sha256 and ack.get('cohort_sha256')==bundle.manifest['accounts']['cohort_sha256'],'ack_identity_mismatch')
    expected='running_verified' if users else 'service_stopped_no_accounts'
    need(ack.get('enforcement')==expected and ack.get('health',{}).get('healthy') is True,'edge_enforcement_not_confirmed')
    loaded=transport.status()
    need(loaded.get('verified') is True and loaded.get('generation')==generation
     and loaded.get('cohort_sha256')==bundle.manifest['accounts']['cohort_sha256']
     and sorted(loaded.get('active_usernames',[]))==sorted(users),'edge_loaded_state_unverified')
    need(self.authority.fingerprint(edge)==fingerprint,'authority_superseded_before_confirmation')
    atomic(self.state_dir/(edge_id+'-mirror.json'),{'schema':1,'manifest':bundle.manifest,
     'manifest_sha256':bundle.manifest_sha256,'config':json.loads(bundle.files['config/runtime.json']),
     'ack':ack,'loaded_status':loaded,'checked_at':int(time.time())})
    state.update(confirmed_input_sha256=fingerprint,confirmed_manifest=bundle.manifest,last_ack=ack,
     confirmed_at=int(time.time()),verified_at=int(time.time()),pending_generation=None,pending_input_sha256=None,last_error=None,last_wire=wire,
     subject_generation=source_generation)
    # A health observation belongs to one acknowledged native generation.
    # Retain one prior diagnostic separately; never let a new manifest reuse
    # the old last_health as permission for a regional airport gate.
    if state.get('last_health') is not None:state['previous_generation_health']=state['last_health']
    state.pop('last_health',None);state.pop('last_health_attempt',None)
    state.pop('starhub_selection',None)
    atomic(path,state)
    return {'status':'confirmed','edge_id':edge_id,'generation':generation,'active_users':len(users),'wire_bytes':wire['wire_bytes'],'idempotent':False}
   except Exception as error:
    detail=str(error);code=detail if re.fullmatch(r'[a-z0-9_]{1,96}',detail) else type(error).__name__.lower()
    state.update(last_error=code,last_attempt_at=int(time.time()));atomic(path,state)
    raise ControllerError(code) from None
 def health(self,edge):
  with self.lock(edge['edge_id']):
   path=self.state_dir/(edge['edge_id']+'.json');state=private_json(path,missing={})
   need(state.get('last_ack') is not None,'edge_not_confirmed')
   if state['last_ack'].get('active_user_count',0)==0:return {'status':'deny_all','mode':None}
   transport=self.transport_factory(edge)
   try:proof=transport.probe()
   except Exception:
    if edge.get('ai_pool_version',1)==4:
     state['last_health_attempt']={'status':'unknown','checked_at':time.time(),'previous_mode_preserved':True}
     atomic(path,state)
    raise
   if edge.get('scope')=='ai':
    cache_path=self.state_dir/'origin-cache.json';cache=private_json(cache_path,missing={})
    if edge.get('ai_pool_version',1)==4:
     from ai_health_v4 import qualify
     proof=qualify(proof,cache,lookup=origin_network,now=time.time())
     if proof.get('qualification_state')=='unknown':
      state['last_health_attempt']={'status':'unknown','checked_at':time.time(),'previous_mode_preserved':True}
      atomic(path,state);raise ControllerError('ai_qualification_unknown')
    else:proof=qualify_ai_paths(proof,cache)
    atomic(cache_path,dict(sorted(cache.items(),key=lambda row:row[1].get('checked_at',0),reverse=True)[:256]))
   routes=proof.get('paths',proof.get('routes',proof.get('results',{})))
   if isinstance(routes,list):routes={row.get('label',row.get('tag')):row for row in routes}
   def healthy(tag):return routes.get(tag,{}).get('healthy') is True
   decision=None
   if edge.get('scope')=='ai' and edge.get('ai_pool_version',1) in (2,3,4):
    if edge.get('ai_pool_version',1)==4:
     from starhub_selection_v4 import choose
    elif edge.get('ai_pool_version',1)==3:
     from starhub_selection_v3 import choose
    else:
     from starhub_selection import choose
    decision=choose(proof,previous_state=state.get('starhub_selection'),now=time.time())
    mode=decision['mode']
   else:
    mode='ai-z'+str(int(healthy('zoro-sg')) if edge.get('scope')!='ai' else 0)+'s'+str(int(healthy('uzuma-singtel')))+'l'+str(int(healthy('lazycat-starhub')))
   airport=None
   if decision is not None and edge.get('ai_pool_version',1)==4:
    if not any(decision['health'].values()):
     from routing_contract import validate
     revision=validate(state['confirmed_manifest']['routing_revision'])
     try:airport=transport.pool_probe(revision['pools']['SG']['server_port'])
     except Exception:
      state['last_health_attempt']={'status':'unknown','checked_at':time.time(),'previous_mode_preserved':True}
      atomic(path,state);raise
    else:airport={'healthy':None,'status':'standby_not_required'}
   manifest=state.get('confirmed_manifest',{})
   config_rows=[row for row in manifest.get('files',[]) if row.get('path')==manifest.get('config_path')]
   if edge.get('ai_pool_version')==4:
    need(len(config_rows)==1 and manifest.get('accounts',{}).get('cohort_sha256')
     and state['last_ack'].get('manifest_sha256'),'v4_health_generation_binding_required')
    need(proof.get('generation')==state['last_ack']['generation'] and proof.get('edge_id')==edge['edge_id'],
     'v4_probe_generation_mismatch')
   ack=transport.set_health(state['last_ack']['generation'],mode)
   need(ack.get('mode')==mode and ack.get('verified') is True,'health_mode_not_confirmed')
   detail={'mode':mode,'checked_at':int(time.time()),'proof':proof,
    'generation':state['last_ack']['generation'],
    'manifest_sha256':state['last_ack'].get('manifest_sha256'),
    'cohort_sha256':manifest.get('accounts',{}).get('cohort_sha256'),
    'runtime_sha256':config_rows[0].get('sha256') if len(config_rows)==1 else None}
   if decision is not None:
    if edge.get('ai_pool_version',1)==4:
     detail['airport_pool']=airport
     detail['service_available']=any(decision['health'].values()) or detail['airport_pool'].get('healthy') is True
    state['starhub_selection']=decision['state'];detail['starhub_pool']=decision
   state.update(last_health=detail);atomic(path,state)
   return {'status':'confirmed','mode':mode}
 def logs(self,edge):
  with self.lock(edge['edge_id']):
   import sys
   if '/opt/security-mail-alerts' not in sys.path:sys.path.insert(0,'/opt/security-mail-alerts')
   from confirmed_watcher import JournalStore
   from edge_logs import ingest_batch
   store=JournalStore(self.state_dir/'confirmed-events.db')
   state=store.state(edge['edge_id']) or {}
   batch=self.transport_factory(edge).logs(state.get('cursor'))
   return ingest_batch(store,edge['edge_id'],batch)
def synchronize_subject(username,*,enabled,generation=None,registry_path=REGISTRY,publisher=None):
 need(isinstance(username,str) and username and type(enabled) is bool,'invalid_subject')
 publisher=publisher or Publisher();results=[]
 for edge in registry(registry_path):results.append(publisher.synchronize(edge,subject=username,enabled=enabled,source_generation=generation))
 return {'complete':all(row['status']=='confirmed' for row in results),'edges':results}
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--registry',default=str(REGISTRY));parser.add_argument('--state-dir',default=str(STATE));parser.add_argument('--once',action='store_true')
 args=parser.parse_args();os.umask(0o077);publisher=Publisher(state_dir=args.state_dir);last_health={}
 while True:
  for edge in registry(args.registry):
   try:
    result=publisher.synchronize(edge,verify_interval=30)
    if not result.get('idempotent') or time.monotonic()-last_health.get(edge['edge_id'],0)>15:
     publisher.health(edge);last_health[edge['edge_id']]=time.monotonic()
    publisher.logs(edge)
   except Exception as error:
    code=str(error) if isinstance(error,ControllerError) else type(error).__name__.lower()
    print(json.dumps({'event':'edge_sync_pending','edge_id':edge['edge_id'],'code':code}),flush=True)
  if args.once:break
  time.sleep(3)
if __name__=='__main__':main()
