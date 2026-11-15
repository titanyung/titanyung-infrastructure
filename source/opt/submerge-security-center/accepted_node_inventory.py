"""Current committed transaction audit; legacy owner labels are informational.

No installation or network action runs on import. Every root authority/export,
committed attempt, full owned kernel snapshot, persistent source and native
owner is checked; unknown or drift cannot become a protected result.
"""
import base64,collections,copy,hashlib,ipaddress,json,os,re,shlex,stat,subprocess,time
from pathlib import Path,PurePosixPath

REVISION='routing-revision-20261109-v1'
HOSTS={'hk':'ByteVirt-HK ISP','tw':'ByteVirt-TW','sg':'Lazycat-SG','hkt':'Lazycat-HKT',
       'singtel':'Uzuma-SG-Singtel1','uzuma-starhub':'Uzuma-SG-StarHub','uzuma-hkt':'Uzuma-HKT'}
SIX=frozenset(HOSTS)-{'uzuma-hkt'}

def need(value,code):
 if not value:raise ValueError(code)
def canonical(value):return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def digest(value):return hashlib.sha256(canonical(value)).hexdigest()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def private_raw(path):
 p=Path(path);s=p.stat();need(not p.is_symlink() and stat.S_ISREG(s.st_mode) and s.st_size<=8*1024*1024,'accepted_private_file')
 if hasattr(os,'geteuid') and os.geteuid()==0:need(s.st_uid==0 and not s.st_mode&0o077,'accepted_root_private')
 return p.read_bytes()
def private(path):return json.loads(private_raw(path))
def approved_path(path):
 p=PurePosixPath(path);need(p.is_absolute() and '..' not in p.parts and str(p).startswith(('/root/','/var/lib/','/etc/','/usr/'))
     and not any(c in str(p) for c in ('\n','\r')),'accepted_fixed_source_path');return path
def hash_value(value):need(isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value),'accepted_sha256');return value

def validate_hkt_acceptance(value,record):
 need(value.get('schema')==1 and value.get('plan_sha256')==record['plan_sha256'],'accepted_hkt_exact_plan_receipt')
 for field in ('fresh_reverse_ssh','persistent_reverse_alive','host_firewall_verified','native_loopback_only_verified',
   'native_source_acl_verified','openrc_dependencies_verified','no_system_loader_changes','no_package_changes','public_original_tcp_guard_verified'):
  need(value.get(field) is True,'accepted_hkt_receipt_incomplete')
 need(type(value.get('public_original_tcp_drop_counter_delta')) is int and value['public_original_tcp_drop_counter_delta']>0,'accepted_hkt_actual_drop_counter')
 need(all(value.get(field)=='blocked' for field in ('negative_public_ssh','negative_public_ss','negative_public_web')),'accepted_hkt_public_application_negatives')
 negative=value.get('authenticated_public_ss_negative',{})
 need(negative.get('executed') is True and negative.get('completed') is True and negative.get('status')=='blocked'
      and type(negative.get('returncode')) is int and negative['returncode']>0 and negative.get('valid_ss2022_credentials_used') is True
      and negative.get('native_client_checked') is True,'accepted_hkt_authenticated_public_negative')
 trace=value.get('dmit_proxy',{})
 need(trace.get('tls_verified') is True and trace.get('http_status')==200 and trace.get('loc')=='HK'
      and trace.get('observed_hkt_source_ip')=='127.0.0.1','accepted_hkt_actual_reverse_positive')
 independent=value.get('independent_negative',{});rows=independent.get('ports',[])
 need(independent.get('source_verified_independent_uzuma') is True and independent.get('source_loc')=='SG'
   and independent.get('source_http_status')==200 and independent.get('source_tls_verified') is True and len(rows)==3
   and {r.get('public_port') for r in rows}=={21018,21019,21020}
   and all(r.get('status')=='application_blocked' and r.get('application_response') is False and r.get('response_bytes')==0 for r in rows),
   'accepted_hkt_independent_negatives_incomplete')
 address=ipaddress.ip_address(independent.get('source_ip','0.0.0.0'));need(address.version==4 and address in ipaddress.ip_network('202.156.0.0/16'),'accepted_hkt_independent_source')
 return True

def normalize_rule(rule):
 value=copy.deepcopy(rule)
 for key in ('handle','index','position'):value.pop(key,None)
 for row in value.get('expr',[]):
  if 'counter' in row:row['counter']=None
 def norm(row):
  if isinstance(row,dict):return {k:sorted((norm(c) for c in v),key=canonical) if k=='set' and isinstance(v,list) else norm(v) for k,v in row.items()}
  if isinstance(row,list):return [norm(x) for x in row]
  return row
 return norm(value)

def selected_kernel(document,tables):
 result=[]
 for entry in document.get('nftables',[]):
  kind=next(iter(entry));row=entry[kind]
  if kind=='metainfo' or not isinstance(row,dict) or row.get('family')!='inet':continue
  table=row.get('name') if kind=='table' else row.get('table')
  if table not in tables:continue
  value=normalize_rule(row) if kind=='rule' else copy.deepcopy(row)
  value.pop('handle',None);result.append({kind:value})
 need({x['table']['name'] for x in result if 'table' in x}==set(tables),'accepted_owned_tables_missing')
 return result

def verify_export_rules(document,source):
 refs=source['kernel_rule_refs'];need(refs and all(isinstance(r,dict) for r in refs),'accepted_complete_rule_refs')
 tables={r['table'] for r in refs};selected=selected_kernel(document,tables)
 expected=collections.Counter((r['table'],r['chain'],r['normalized_sha256']) for r in refs)
 actual=collections.Counter((r['rule']['table'],r['rule']['chain'],digest(r['rule'])) for r in selected if 'rule' in r)
 need(actual==expected,'accepted_owned_rule_set_drift');return selected

def source_guards(rules):
 def contains(value):
  if isinstance(value,dict):return 'source_ip_cidr' in value or any(contains(v) for v in value.values())
  return isinstance(value,list) and any(contains(v) for v in value)
 need(isinstance(rules,list),'accepted_native_route_rules')
 return [copy.deepcopy(rule) for rule in rules if contains(rule)]

def sockets(document):
 rows=document.get('inbounds',[]);need(isinstance(rows,list),'accepted_native_inbound_shape')
 return sorted(({k:row.get(k) for k in ('tag','type','listen','listen_port')} for row in rows),key=canonical)

def check_authority_record(key,row,authority,*,read=private,read_raw=private_raw):
 record=authority['peers'][key];need(record.get('host')==HOSTS[key],'accepted_peer_host_binding')
 need(row.get('host')==record['host'] and row.get('ssh_argv')==record['ssh_argv'],'accepted_fixed_management_binding')
 args=record['ssh_argv'];need(isinstance(args,list) and args and args[0]=='ssh' and all(isinstance(x,str) and x for x in args),'accepted_ssh_argv')
 need(all(flag in args for flag in ('IdentitiesOnly=yes','BatchMode=yes','StrictHostKeyChecking=yes')),'accepted_pinned_management')
 need(record.get('kind') in ('six-committed-transaction','hkt3-v2-committed-reverse'),'accepted_record_kind')
 need(record['kernel_sha256']==digest(record['kernel_baseline']) and record.get('kernel_tables'),'accepted_kernel_baseline_binding')
 if key in SIX:
  export=authority['six_export'];raw=read_raw(export['path']);need(sha(raw)==export['sha256'],'accepted_export_changed')
  source=json.loads(raw)['leaves'][key]
  need(record['accepted_record_sha256']==digest(source) and record['job']==source['job'] and record['operation_id']==source['operation_id']
       and record['committed_at']==source['committed_at'],'accepted_committed_attempt_binding')
  state=read(approved_path(record['job']+'/journal.json'))
  need(state.get('phase')=='committed' and state.get('peer')==key and state.get('operation_id')==record['operation_id']
       and state.get('committed_at')==record['committed_at'],'accepted_attempt_no_longer_committed')
  receipt=read_raw(record['job']+'/acceptance-proof.json')
  need(sha(receipt)==source['acceptance_sha256'],'accepted_transaction_receipt_changed')
  need(record['persistent_sources']==source['persistent_sources'] and record['owner_bindings']==source['owner_bindings']
       and record['natives']==source['natives'],'accepted_source_metadata_changed')
  for native in record['natives']:
   matches=[n for n in state['natives'] if n['binding']['path']==native['path']]
   need(len(matches)==1 and record['native_source_guards'][native['path']]==source_guards(matches[0]['after_rules']),
        'accepted_native_source_scope_not_bound_to_committed_attempt')
 else:
  need(record.get('plan_id')=='uzuma-hkt3-20261109-v2' and record.get('access_mode')=='reverse_only','accepted_actual_hkt_v2_required')
  receipt=read_raw(record['local_acceptance_path']);need(sha(receipt)==record['acceptance_sha256'],'accepted_hkt_receipt_changed')
  plan=read(record['local_plan_path']);need(plan.get('plan_id')==record['plan_id'] and digest(plan)==record['plan_sha256'],'accepted_hkt_plan_changed')
  validate_hkt_acceptance(json.loads(receipt),record)
  expected=json.loads(base64.b64decode(plan['files'][record['proxy_config_path']]['base64']))
  need(record['native_source_guards'][record['proxy_config_path']]==source_guards(expected['route']['rules']),
       'accepted_hkt_source_guards_not_bound_to_plan')
 return record

def current(manifest,spec,*,now=None,read=private,read_raw=private_raw):
 need(spec.get('schema')==2 and spec.get('revision')==REVISION,'accepted_inventory_schema')
 need(spec.get('policy')=='routing-revision-20261109-committed-leaf-protection','accepted_inventory_policy')
 raw=read_raw(approved_path(spec['authority_path']));need(sha(raw)==hash_value(spec['authority_sha256']),'accepted_authority_hash')
 authority=json.loads(raw);need(authority.get('schema')==1 and authority.get('kind')=='committed-node-authority-v2'
     and authority.get('revision')==REVISION,'accepted_authority_kind')
 need(set(authority.get('peers',{}))==set(HOSTS),'accepted_seven_committed_peers_required')
 export_raw=read_raw(approved_path(authority['six_export']['path']));need(sha(export_raw)==hash_value(authority['six_export']['sha256']),'accepted_six_export_hash')
 export=json.loads(export_raw);need(export.get('schema')==1 and export.get('kind')=='fresh_six_committed_leaf_inventory'
      and set(export.get('leaves',{}))==set(SIX),'accepted_exact_six_export')
 fronts=export['fronts'];wanted4=[fronts['dmit_ipv4']+'/32',fronts['lazycat_ipv4']+'/32'];wanted6=[fronts['dmit_ipv6']+'/128']
 need(spec.get('allowed_ipv4')==wanted4 and spec.get('allowed_ipv6')==wanted6 and fronts.get('lazycat_global_ipv6')==[],'accepted_actual_front_sources')
 for text in wanted4+wanted6:
  net=ipaddress.ip_network(text,strict=True);need(net.network_address.is_global and net.prefixlen==net.max_prefixlen,'accepted_exact_global_fronts')
 rows=manifest['revision_inventory']['servers'];epoch=manifest['inventory_epoch'];now=int(time.time() if now is None else now)
 expected={host for host,r in rows.items() if r['monitoring_state']=='active' and host not in ('DMIT','Lazycat-SG-Front')
           and (r['retire_at'] is None or epoch<r['retire_at'])}
 need(isinstance(spec.get('peers'),dict),'accepted_exact_active_leaf_set')
 provided={r['host'] for r in spec['peers'].values()}
 need(expected<=provided and all(host in expected or host in rows and rows[host]['retire_at'] is not None
      and rows[host]['retire_at']<=epoch for host in provided),'accepted_exact_active_leaf_set')
 result=copy.deepcopy(spec);result['peers']={}
 for key,row in spec['peers'].items():
  need(key in HOSTS and row['host']==HOSTS[key],'accepted_canonical_peer_key')
  if rows[row['host']]['retire_at'] is not None and now>=rows[row['host']]['retire_at']:continue
  full=dict(row,ssh_argv=authority['peers'][key]['ssh_argv'])
  record=check_authority_record(key,full,authority,read=read,read_raw=read_raw)
  full.update(verification_kind='accepted_committed_v2',access_mode=record.get('access_mode','public_sources'),_accepted_record=record,
              _accepted_authority_path=spec['authority_path'],_accepted_authority_sha256=spec['authority_sha256'])
  result['peers'][key]=full
 return result

def _service(call,manager,unit,*,persistent=False):
 need(re.fullmatch('[A-Za-z0-9_.@-]{1,100}',unit),'accepted_fixed_unit')
 if manager=='systemd':
  output=call('systemctl is-active '+shlex.quote(unit)).decode().strip();need(output=='active','accepted_service_not_active')
  if persistent:need(call('systemctl is-enabled '+shlex.quote(unit)).decode().strip()=='enabled','accepted_boot_not_enabled')
 elif manager=='openrc':
  need(call('rc-service '+shlex.quote(unit)+' status'),'accepted_openrc_not_active')
  if persistent:call('test -L /etc/runlevels/default/'+shlex.quote(unit))
 else:raise ValueError('accepted_service_manager')

def _files(call,record):
 persistent={r['path']:r['sha256'] for r in record['persistent_sources']}
 def remote_sha(path):return call('sha256sum '+shlex.quote(approved_path(path))).decode().split()[0]
 for path,expected in persistent.items():need(remote_sha(path)==expected,'accepted_persistent_file_drift')
 for row in record['owner_bindings']:
  path=approved_path(row['path'])
  expected=persistent.get(path,row.get('sha256'))
  need(remote_sha(path)==expected if expected else sha(call('cat '+shlex.quote(path)).decode().strip().encode())==row.get('text_sha256'),'accepted_owner_binding_drift')

def _natives(call,record):
 for native in record['natives']:
  path=approved_path(native['path']);document=json.loads(call('cat '+shlex.quote(path)))
  need(source_guards(document.get('route',{}).get('rules',[]))==record['native_source_guards'][path],
       'accepted_native_source_guard_drift')
  need(sockets(document)==sorted(native['inbound_sockets'],key=canonical),'accepted_native_public_socket_drift')
  manager,unit=native['manager'],native['unit'];_service(call,manager,unit)
  if manager=='systemd':
   info=call('systemctl show '+shlex.quote(unit)+' -p ExecStart -p ActiveState').decode()
   match=re.search(r'(?m)^ExecStart=\{ path=([^ ;]+) ; argv\[\]=([^;]+)',info)
   need(match and match.group(1)==native['binary'] and (path in match.group(2) or '-C '+str(PurePosixPath(path).parent) in match.group(2)),
        'accepted_loaded_native_owner_drift')
  else:
   text=call('cat /etc/init.d/'+shlex.quote(unit)).decode()
   need('command="'+native['binary']+'"' in text and path in text,'accepted_openrc_native_owner_drift')

def _boot(call,record):
 need(record.get('boot_bindings'),'accepted_boot_bindings_required')
 for row in record['boot_bindings']:_service(call,row['manager'],row['unit'],persistent=True)

def check_peer(key,row,spec,*,call=None,read=private,read_raw=private_raw,local_reverse_probe=None):
 reverse=row.get('access_mode')=='reverse_only'
 status={'key':key,'name':row['name'],'host':row['host'],'status':'unknown','scope':'代理、SSH、Web及其他入站服务',
  'allowed_ipv4':'无公网入站；仅经 DMIT 中转' if reverse else ', '.join(spec['allowed_ipv4']),
  'allowed_ipv6':'无公网入站' if reverse else ', '.join(spec['allowed_ipv6']),'ipv4':False,'ipv6':False,'persistent':False,
  'access_mode':row.get('access_mode','public_sources'),'policy':spec['policy'],'authority_kind':'committed_transactions'}
 def remote(script):
  result=subprocess.run(row['ssh_argv']+[script],stdin=subprocess.DEVNULL,capture_output=True,timeout=18)
  need(result.returncode==0 and len(result.stdout)<=2*1024*1024,'accepted_live_remote_read_failed');return result.stdout
 call=call or remote
 try:
  raw=read_raw(row['_accepted_authority_path']);need(sha(raw)==row['_accepted_authority_sha256'],'accepted_authority_changed_during_audit')
  record=check_authority_record(key,row,json.loads(raw),read=read,read_raw=read_raw)
  live=json.loads(call('nft -j list ruleset'));baseline=selected_kernel(live,record['kernel_tables'])
  need(digest(baseline)==record['kernel_sha256'] and baseline==record['kernel_baseline'],'accepted_full_owned_kernel_drift')
  _files(call,record);_natives(call,record);_boot(call,record)
  if reverse:
   need(call('cat '+shlex.quote(record['status_path'])).decode().strip()=='committed','accepted_hkt_not_committed')
   need(call('cat '+shlex.quote(record['plan_hash_path'])).decode().strip()==record['plan_sha256'],'accepted_hkt_plan_owner_drift')
   need(sha(call('cat '+shlex.quote(record['guest_acceptance_path'])))==record['acceptance_sha256'],'accepted_hkt_guest_receipt_drift')
   config=json.loads(call('cat '+shlex.quote(record['proxy_config_path'])))
   need(config.get('inbounds') and all(ipaddress.ip_address(p.get('listen','0.0.0.0')).is_loopback for p in config['inbounds'])
      and any(p.get('listen_port')==21019 and p.get('type')=='shadowsocks' for p in config['inbounds']),'accepted_hkt_native_not_loopback_only')
   need(local_reverse_probe is not None and local_reverse_probe(19421),'accepted_hkt_actual_reverse_listener_missing')
  status.update(status='protected',ipv4=True,ipv6=True,persistent=True,configuration_matches=True,
    verified_at=int(time.time()),committed_operation=record.get('operation_id',record.get('plan_sha256')),
    actual_acceptance_scopes=record.get('actual_acceptance_scopes',{}),
    note='仅经 DMIT 中转；公网入站已拒绝' if reverse else '已核对当前入站规则、持久化配置和服务；仅允许已授权前置来源')
 except Exception as error:status.update(status='attention',verified_at=int(time.time()),error=type(error).__name__,note='当前状态与已提交验收不一致或核查未完成')
 return status
