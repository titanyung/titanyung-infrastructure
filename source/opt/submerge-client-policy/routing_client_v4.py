"""Pure eight-group client projection. No provider fetch, socket, or mode mutation."""
from __future__ import annotations
import copy,hashlib,ipaddress,json,os,re,stat,time
from pathlib import Path
from urllib.parse import urlsplit
from routing_contract import UZUMA_HKT_RETIRE_AT, validate as validate_contract

REVISION='routing-revision-20261109-v1'
MARKER='x-submerge-routing-revision'
CLIENT_GATE_PATH=Path('/etc/submerge-topology/routing-client-20261109.json')
BOUND_VALIDATION_MAX_AGE=45
VISIBLE_GROUPS=('全部节点','自动','chatgpt、claude、google（不含youtube）',
 'Mytvsuper专线','viu tv & HK其他','VPS访问','非中国大陆的其他','paoluz')
GROUP_IDS=dict(zip(('all','auto','ai','mytv','hk','vps','other','airport'),VISIBLE_GROUPS))
ROUTE_LABELS={
 'dmit':'DMIT','lazycat_sg':'Lazycat SG',
 'lc_singtel':'Lazycat SG → uzuma SG-Singtel1','dmit_singtel':'DMIT → uzuma SG-Singtel1',
 'lc_lazycat_starhub':'Lazycat SG → Lazycat starhub','dmit_lazycat_starhub':'DMIT → Lazycat starhub',
 'lc_uzuma_starhub':'Lazycat SG → uzuma starhub','dmit_uzuma_starhub':'DMIT → uzuma starhub',
 'dmit_uzuma_hkt':'DMIT → uzuma HKT','dmit_bytevirt_hk':'DMIT → Bytevirt HK ISP',
 'dmit_bytevirt_tw':'DMIT → Bytevirt HINET NAT','dmit_lazycat_hkt':'DMIT → Lazycat HKT'}
ROUTE_LABELS={key:'📡 '+value for key,value in ROUTE_LABELS.items()}
ROUTE_PAIRS={
 'dmit':('dmit','direct'),'lazycat_sg':('lazycat','direct'),
 'lc_singtel':('lazycat','uzuma-singtel'),'dmit_singtel':('dmit','uzuma-singtel'),
 'lc_lazycat_starhub':('lazycat','lazycat-starhub'),'dmit_lazycat_starhub':('dmit','lazycat-starhub'),
 'lc_uzuma_starhub':('lazycat','uzuma-starhub'),'dmit_uzuma_starhub':('dmit','uzuma-starhub'),
 'dmit_uzuma_hkt':('dmit','uzuma-hkt'),'dmit_bytevirt_hk':('dmit','bytevirt-hk'),
 'dmit_bytevirt_tw':('dmit','bytevirt-taiwan'),'dmit_lazycat_hkt':('dmit','lazycat-hkt')}
AI_ROUTES=('lc_singtel','dmit_singtel','lc_lazycat_starhub','dmit_lazycat_starhub','lc_uzuma_starhub','dmit_uzuma_starhub')
PROVIDER_GROUPS={key:'VPS · '+label for key,label in (('dmit','DMIT'),('bytevirt','Bytevirt'),('lazycat','Lazycat'),('uzuma','uzuma'))}
REGION_FAST={r:'__paoluz_'+r+'_最快' for r in ('SG','HK','ALL')}
AI_DEFAULT='🧭 默认'
AUTO_RAW='__服务器业务自动'
BUSINESS_LABELS={'all':'全部节点','mytv':'Mytvsuper','hk':'viu tv & HK其他','other':'非中国大陆的其他',
 'vps_dmit':'VPS · DMIT','vps_bytevirt':'VPS · Bytevirt','vps_lazycat':'VPS · Lazycat','vps_uzuma':'VPS · uzuma'}
BUSINESS_AUTO={key:label+' · 自动' for key,label in BUSINESS_LABELS.items()}
BUSINESS_AIRPORT={key:label+' · 机场最快' for key,label in BUSINESS_LABELS.items()}
BUSINESS_HEALTH={'all':'https://example.com/','mytv':'https://www.mytvsuper.com/robots.txt',
 'hk':'https://www.viu.com/robots.txt','other':'https://example.com/',
 'vps_dmit':'https://www.dmit.io/robots.txt','vps_bytevirt':'https://bytevirt.com/robots.txt',
 'vps_lazycat':'https://dash.lazycat.wiki/robots.txt','vps_uzuma':'https://uzuma.ru/robots.txt'}
NOTICE=('点什么都','没用，服','务器分流')
TEST_NOTICE=('测试订阅','按所选的','链路转发')
HEALTH_URL='https://chatgpt.com/robots.txt'
AIRPORT_PREFIX='paoluz · '
BUILTINS={'DIRECT','REJECT','REJECT-DROP','PASS'}
DNS_TARGETS={'DNS-Overseas':'other','DNS-GoogleAI':'ai','DNS-PlanHK':'hk','DNS-PlanTVB':'mytv'}
ENDPOINT_KEYS={'server','port','sni','fingerprint','skip-cert-verify','client-fingerprint','alpn'}
DMIT_BOUND=('dmit','dmit_bytevirt_hk','dmit_bytevirt_tw','dmit_lazycat_hkt','dmit_uzuma_hkt')

class ProfileError(ValueError):pass
def need(ok,code):
 if not ok:raise ProfileError(code)
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def digest(value):return hashlib.sha256(canonical(value)).hexdigest()
def unique(items):return list(dict.fromkeys(items))
def domain(value):
 need(isinstance(value,str) and value==value.lower() and '.' in value and len(value)<=253 and not value.endswith('.'),'normalized_domain_required')
 need(all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) for x in value.split('.')),'normalized_domain_required')
 try:ipaddress.ip_address(value)
 except ValueError:return value
 raise ProfileError('domain_must_not_be_ip')
def pin(value):
 need(isinstance(value,str) and re.fullmatch('[a-f0-9]{64}',value.replace(':','').lower()),'verified_certificate_pin_required')
 return value.replace(':','').lower()
def available(contract,as_of):
 need(type(as_of) is int and as_of>0,'explicit_as_of_required')
 for key in ('taiwan_retire_at','lazycat_hkt_retire_at'):need(type(contract.get(key)) is int and contract[key]>0,'explicit_retirement_epoch_required')
 return [key for key in ROUTE_LABELS if not (key=='dmit_bytevirt_tw' and as_of>=contract['taiwan_retire_at'])
  and not (key=='dmit_lazycat_hkt' and as_of>=contract['lazycat_hkt_retire_at'])
  and not (key=='dmit_uzuma_hkt' and as_of>=UZUMA_HKT_RETIRE_AT)]

def _settings(value):
 need(isinstance(value,dict),'frontend_settings_required')
 result=copy.deepcopy(value);domain(result.get('server_name'));pin(result.get('certificate_fingerprint'))
 try:address=ipaddress.ip_address(result['public_ip'])
 except (ValueError,KeyError):raise ProfileError('literal_lc_public_ipv4_required') from None
 need(address.version==4 and address.is_global,'literal_lc_public_ipv4_required')
 for field in ('public_ports','dmit_public_ports'):
  need(set(result.get(field,{}))=={'starhub','singtel'},'two_auto_front_ports_required')
  need(all(type(p) is int and 1<=p<=65535 for p in result[field].values()),'valid_front_port_required')
 manual=result.get('manual_settings');need(isinstance(manual,dict),'manual_front_settings_required')
 pin(manual.get('certificate_fingerprint'))
 for field in ('server_names','dmit_public_ports','lazycat_public_ports'):
  need(set(manual.get(field,{}))=={'lazycat_starhub','uzuma_starhub'},'both_manual_fronts_required')
  for v in manual[field].values():domain(v) if field=='server_names' else need(type(v) is int and 1<=v<=65535,'valid_front_port_required')
 for front in ('public_ports','dmit_public_ports'):
  extra=manual['lazycat_public_ports' if front=='public_ports' else 'dmit_public_ports']
  values=list(result[front].values())+list(extra.values())
  need(len(values)==len(set(values)),'front_ports_must_be_independent')
 return result

def _sites(sites,contract):
 need(isinstance(sites,dict) and set(sites)==set(ROUTE_LABELS),'twelve_explicit_sites_required')
 pairs={};seen=[]
 for key,row in sites.items():
  need(isinstance(row,dict) and set(row)=={'url','domains'},'test_site_fields')
  parsed=urlsplit(row['url']);need(parsed.scheme=='https' and parsed.hostname and not parsed.username and not parsed.password and not parsed.fragment,'https_test_site_required')
  need(isinstance(row['domains'],list) and row['domains'] and len(set(row['domains']))==len(row['domains']),'test_site_domains_required')
  for host in row['domains']:
   domain(host);need(not any(host==old or host.endswith('.'+old) or old.endswith('.'+host) for old in seen),'overlapping_test_sites');seen.append(host)
  need(any(parsed.hostname==host or parsed.hostname.endswith('.'+host) for host in row['domains']),'test_site_url_not_in_domains')
  pairs[ROUTE_PAIRS[key]]=row['domains']
 rows=contract.get('ip_tests');need(isinstance(rows,list),'server_test_site_contract_required')
 actual={(r['front'],r['outbound']):r['domains'] for r in rows}
 need(len(actual)==len(rows) and actual==pairs,'server_client_test_site_contract_mismatch')
 return copy.deepcopy(sites)

def _airport(cache):
 need(isinstance(cache,dict) and isinstance(cache.get('proxies'),list) and isinstance(cache.get('proxy-groups'),list),'complete_airport_cache_required')
 raw_nodes=cache['proxies'];raw_groups=cache['proxy-groups'];names=[r.get('name') for r in raw_nodes+raw_groups]
 need(all(isinstance(n,str) and n and n not in BUILTINS for n in names) and len(names)==len(set(names)),'airport_identity_inventory')
 nodes={r['name']:r for r in raw_nodes};groups={r['name']:r for r in raw_groups}
 roots=cache.get('provider_auto_roots')
 need(isinstance(roots,list) and roots and all(name in groups for name in roots),'airport_original_auto_unavailable')
 regions=cache.get('region_members');need(isinstance(regions,dict) and set(regions)=={'SG','HK','ALL'},'airport_regions_required')
 need(regions['ALL']==list(nodes),'airport_all_members_order')
 for members in regions.values():need(isinstance(members,list) and len(members)==len(set(members)) and all(n in nodes for n in members),'airport_region_members_invalid')
 mapping={name:AIRPORT_PREFIX+name for name in names}
 graph={};output_nodes=[];output_groups=[]
 for row in raw_nodes:
  item=copy.deepcopy(row);item['name']=mapping[row['name']];refs=[]
  if 'dialer-proxy' in item:
   ref=item['dialer-proxy'];need(ref in mapping or ref in BUILTINS,'airport_dialer_missing');refs.append(ref);item['dialer-proxy']=mapping.get(ref,ref)
  graph[row['name']]=refs;output_nodes.append(item)
 for row in raw_groups:
  item=copy.deepcopy(row);name=row['name'];need(item.get('type') in ('select','url-test','fallback','load-balance','relay'),'airport_group_type')
  materialized=any(k in item for k in ('use','include-all','include-all-proxies','include-all-providers','filter','exclude-filter'))
  members=cache.get('resolved_group_members',{}).get(name) if materialized else row.get('proxies')
  need(isinstance(members,list) and members and all(n in mapping or n in BUILTINS for n in members),'airport_group_materialization_required')
  graph[name]=members
  for key in ('use','include-all','include-all-proxies','include-all-providers','filter','exclude-filter'):item.pop(key,None)
  item.update(name=mapping[name],proxies=[mapping.get(n,n) for n in members],hidden=True)
  if 'default-selected' in item:
   need(item['default-selected'] in members,'airport_default_reference');item['default-selected']=mapping.get(item['default-selected'],item['default-selected'])
  output_groups.append(item)
 def visit(name,active,done):
  if name in BUILTINS or name in done:return
  need(name not in active,'airport_group_cycle');active.add(name)
  for child in graph[name]:visit(child,active,done)
  active.remove(name);done.add(name)
 done=set()
 for name in names:visit(name,set(),done)
 return output_nodes,output_groups,{r:[mapping[n] for n in values] for r,values in regions.items()},[mapping[n] for n in roots]

def _template(profile):
 # Source legacy output was already validated before the gate. Only canonical
 # DMIT transports provide the user's password; stale provider nodes do not.
 candidates=[r for r in profile.get('proxies',[]) if r.get('type')=='anytls' and r.get('server')=='179.255.136.79']
 need(candidates,'canonical_dmit_template_missing')
 passwords={r.get('password') for r in candidates};need(len(passwords)==1 and all(isinstance(p,str) and len(p)>=24 for p in passwords),'canonical_cohort_disagreement')
 first=candidates[0]
 fields=('type','server','port','password','tls','sni','fingerprint','skip-cert-verify','client-fingerprint','alpn')
 result={k:copy.deepcopy(first[k]) for k in fields if k in first}
 result.update(type='anytls',udp=False,**{'dialer-proxy':'DIRECT'})
 need(result.get('skip-cert-verify') is not True,'verified_dmit_tls_required')
 return result

def _endpoint(template,spec):
 need(isinstance(spec,dict) and 'port' in spec and set(spec)<=ENDPOINT_KEYS,'explicit_public_front_binding_required')
 result=copy.deepcopy(template);result.update(copy.deepcopy(spec))
 need(type(result.get('port')) is int and 1<=result['port']<=65535,'valid_public_binding_port')
 try:address=ipaddress.ip_address(result.get('server'))
 except ValueError:raise ProfileError('literal_public_front_required') from None
 need(address.is_global and result.get('skip-cert-verify') is not True,'verified_public_front_required')
 domain(result.get('sni'));result['fingerprint']=pin(result.get('fingerprint'));return result

def _route_nodes(template,settings,bindings,kind,active,test,sites):
 need(isinstance(bindings,dict) and set(bindings)=={'ordinary','test'},'explicit_front_bindings_required')
 role='test' if test else 'ordinary';ports=bindings.get(role,{}).get(kind)
 need(isinstance(ports,dict) and all(key in ports for key in DMIT_BOUND if key in active),'dmit_public_binding_missing')
 tls={'sni':settings['server_name'],'fingerprint':pin(settings['certificate_fingerprint']),'skip-cert-verify':False}
 manual=settings['manual_settings'];nodes={}
 for key in active:
  front,outbound=ROUTE_PAIRS[key]
  if key in DMIT_BOUND:spec=ports[key]
  elif key=='lazycat_sg':spec=dict(tls,server=settings['public_ip'],port=settings['public_ports']['starhub'])
  elif outbound=='uzuma-singtel':spec=dict(tls,server=settings['public_ip'] if front=='lazycat' else template['server'],
   port=settings['public_ports' if front=='lazycat' else 'dmit_public_ports']['singtel'])
  else:
   provider='lazycat_starhub' if outbound=='lazycat-starhub' else 'uzuma_starhub'
   spec={'server':settings['public_ip'] if front=='lazycat' else template['server'],
    'port':manual['lazycat_public_ports' if front=='lazycat' else 'dmit_public_ports'][provider],
    'sni':manual['server_names'][provider],'fingerprint':pin(manual['certificate_fingerprint']),'skip-cert-verify':False}
  node=_endpoint(template,spec)
  if front=='dmit':need(node['server']==template['server'],'dmit_binding_must_use_canonical_front')
  node.update(name=ROUTE_LABELS[key],desc='IP检测：'+sites[key]['url']);nodes[key]=node
 return nodes

def _select(name,members,default=None,hidden=True):
 need(members and (default is None or default in members),'nonempty_group_default')
 result={'name':name,'type':'select','proxies':unique(members),'default-selected':default or members[0]}
 if hidden:result['hidden']=True
 return result
def _fallback(name,members):
 return {'name':name,'type':'fallback','proxies':members,'url':HEALTH_URL,'expected-status':200,
  'interval':60,'timeout':5000,'lazy':False,'hidden':True}
def _business_owners(active):
 preferred_tw='dmit_bytevirt_tw' if 'dmit_bytevirt_tw' in active else 'dmit_bytevirt_hk'
 return {'all':[AUTO_RAW],
  'mytv':[ROUTE_LABELS['dmit_bytevirt_hk']],
  'hk':[ROUTE_LABELS['dmit_bytevirt_hk']],
  'other':[ROUTE_LABELS[key] for key in ('dmit_bytevirt_hk','dmit_uzuma_hkt','dmit_bytevirt_tw') if key in active],
  'vps_dmit':[ROUTE_LABELS['dmit']],
  'vps_bytevirt':[ROUTE_LABELS[key] for key in unique([preferred_tw,'dmit_bytevirt_hk','dmit_bytevirt_tw']) if key in active],
  'vps_lazycat':[ROUTE_LABELS[key] for key in ('lazycat_sg','lc_lazycat_starhub','dmit_lazycat_starhub','dmit_lazycat_hkt') if key in active],
  'vps_uzuma':[ROUTE_LABELS[key] for key in ('lc_singtel','dmit_singtel','lc_uzuma_starhub','dmit_uzuma_starhub')]}

def _business_helpers(active,regions):
 groups=[]
 for key,owners in _business_owners(active).items():
  region='HK' if key in ('mytv','hk') else 'ALL'
  groups.append({'name':BUSINESS_AIRPORT[key],'type':'url-test','proxies':regions[region] or ['REJECT'],
   'url':BUSINESS_HEALTH[key],'expected-status':'200-499','interval':120,'timeout':5000,'lazy':True,
   'tolerance':0,'max-failed-times':1,'hidden':True})
  groups.append({'name':BUSINESS_AUTO[key],'type':'fallback','proxies':owners+[BUSINESS_AIRPORT[key]],
   'url':BUSINESS_HEALTH[key],'expected-status':'200-499','interval':60,'timeout':5000,'lazy':False,
   'max-failed-times':1,'hidden':True})
 return groups

def _direct_or_reject(rule):return isinstance(rule,str) and rule.endswith((',DIRECT',',DIRECT,no-resolve',',REJECT',',REJECT-DROP')) and not rule.startswith('MATCH,')
def _protected(document):
 return {k:v for k,v in document.items() if k not in ('proxies','proxy-groups','rules','proxy-providers') and not k.startswith('x-submerge-')}
def _protection_hash(document):return digest({'fields':_protected(document),'guards':[r for r in document['rules'] if _direct_or_reject(r)]})
def _render_hash(document):return digest({k:document.get(k) for k in ('proxies','proxy-groups','rules','x-submerge-ip-tests')})

def project_profile(profile,*,settings,routing_contract,airport_cache,sites,as_of=None,front_bindings,test_mode=None):
 need(isinstance(profile,dict),'profile_object_required')
 need('x-submerge-lazycat-ai' not in profile,'legacy_edge_projected_input')
 try:contract=validate_contract(routing_contract)
 except ValueError:raise ProfileError('routing_contract_invalid') from None
 as_of=contract.get('as_of') if as_of is None else as_of
 active=available(contract,as_of);settings=_settings(settings);sites=_sites(sites,contract)
 kind=profile.get('x-submerge-client-kind');need(kind in ('mobile','desktop','router'),'client_kind_required')
 test=profile.get('x-submerge-manual-test') if test_mode is None else test_mode;need(type(test) is bool,'canonical_test_flag_required')
 airport_nodes,airport_groups,regions,provider_roots=_airport(airport_cache)
 template=_template(profile);route_nodes=_route_nodes(template,settings,front_bindings,kind,active,test,sites)
 output=copy.deepcopy(profile)
 for key in list(output):
  if key.startswith('x-submerge-') and key not in ('x-submerge-client-kind','x-submerge-server-policy'):output.pop(key)
 output.pop('proxy-providers',None)
 direct_nodes=[copy.deepcopy(row) for row in profile.get('proxies',[]) if row.get('type') in ('direct','reject')]
 output['proxies']=[*route_nodes.values(),*direct_nodes,*airport_nodes]
 auto=copy.deepcopy(route_nodes['dmit']);auto.update(name=AUTO_RAW);auto.pop('desc',None);output['proxies'].append(auto)
 groups=_business_helpers(active,regions)
 for region,members in regions.items():
  groups.append({'name':REGION_FAST[region],'type':'url-test','proxies':members or ['REJECT'],
   'url':HEALTH_URL,'expected-status':200,'interval':60,'timeout':5000,'lazy':False,'hidden':True})
 ai_cards={}
 for key in AI_ROUTES:
  counterpart=('dmit_'+key[3:]) if key.startswith('lc_') else ('lc_'+key[5:])
  name='🔷 '+ROUTE_LABELS[key][2:];ai_cards[key]=name
  groups.append(_fallback(name,[ROUTE_LABELS[key],ROUTE_LABELS[counterpart],REGION_FAST['SG']]))
 preferred='singtel' if kind=='mobile' else 'lazycat_starhub'
 groups.append(_fallback(AI_DEFAULT,[ROUTE_LABELS['lc_'+preferred],ROUTE_LABELS['dmit_'+preferred],REGION_FAST['SG']]))
 provider_routes={
  'dmit':['dmit'],
  'bytevirt':['dmit_bytevirt_hk','dmit_bytevirt_tw'],
  'lazycat':['lazycat_sg','lc_lazycat_starhub','dmit_lazycat_starhub','dmit_lazycat_hkt'],
  'uzuma':['lc_singtel','dmit_singtel','lc_uzuma_starhub','dmit_uzuma_starhub']}
 provider_defaults={'dmit':'dmit','bytevirt':'dmit_bytevirt_tw' if 'dmit_bytevirt_tw' in active else 'dmit_bytevirt_hk',
  'lazycat':'lazycat_sg','uzuma':'lc_singtel'}
 for provider,keys in provider_routes.items():
  members=[BUSINESS_AUTO['vps_'+provider],*[ROUTE_LABELS[key] for key in keys if key in active],BUSINESS_AIRPORT['vps_'+provider],*provider_roots,*regions['ALL']]
  groups.append(_select(PROVIDER_GROUPS[provider],members,BUSINESS_AUTO['vps_'+provider]))
 visible={}
 all_members=[GROUP_IDS[k] for k in ('auto','ai','mytv','hk','vps','other','airport')]
 if test:all_members=[*[ROUTE_LABELS[key] for key in active],*all_members]
 visible['all']=_select(GROUP_IDS['all'],all_members,ROUTE_LABELS['dmit'] if test else GROUP_IDS['auto'],False)
 visible['auto']=_select(GROUP_IDS['auto'],[BUSINESS_AUTO['all']],BUSINESS_AUTO['all'],False)
 visible['ai']=_select(GROUP_IDS['ai'],[AI_DEFAULT,*[ai_cards[key] for key in AI_ROUTES],REGION_FAST['SG'],*regions['SG']],AI_DEFAULT,False)
 visible['mytv']=_select(GROUP_IDS['mytv'],[BUSINESS_AUTO['mytv'],ROUTE_LABELS['dmit_bytevirt_hk'],BUSINESS_AIRPORT['mytv'],*regions['HK']],BUSINESS_AUTO['mytv'],False)
 visible['hk']=_select(GROUP_IDS['hk'],[BUSINESS_AUTO['hk'],ROUTE_LABELS['dmit_bytevirt_hk'],BUSINESS_AIRPORT['hk'],*regions['HK']],BUSINESS_AUTO['hk'],False)
 visible['vps']=_select(GROUP_IDS['vps'],[*PROVIDER_GROUPS.values(),REGION_FAST['ALL'],*provider_roots],PROVIDER_GROUPS['dmit'],False)
 visible['other']=_select(GROUP_IDS['other'],[BUSINESS_AUTO['other'],*[ROUTE_LABELS[k] for k in ('dmit_bytevirt_hk','dmit_uzuma_hkt','dmit_bytevirt_tw') if k in active],BUSINESS_AIRPORT['other'],*provider_roots,*regions['ALL']],BUSINESS_AUTO['other'],False)
 visible['airport']=_select(GROUP_IDS['airport'],[*provider_roots,REGION_FAST['ALL'],*regions['ALL']],provider_roots[0],False)
 dns_groups=[]
 for row in profile.get('proxy-groups',[]):
  if row.get('name','').startswith('DNS-'):
   need(row['name'] in DNS_TARGETS,'unmapped_preserved_dns_group')
   dns_groups.append(_select(row['name'],[GROUP_IDS[DNS_TARGETS[row['name']]]]))
 hidden_direct=[]
 direct_names={row['name'] for row in direct_nodes}
 for row in profile.get('proxy-groups',[]):
  if row.get('hidden') and row.get('proxies') and set(row['proxies'])<=direct_names|BUILTINS and (set(row['proxies'])&direct_names or '中国大陆' in row['name']):
   item=copy.deepcopy(row);item['hidden']=True;hidden_direct.append(item)
 global_group=_select('GLOBAL',[GROUP_IDS['all' if test else 'auto']])
 output['proxy-groups']=[global_group,*[visible[key] for key in GROUP_IDS],*groups,*airport_groups,*dns_groups,*hidden_direct]
 retained=unique([rule for rule in profile.get('rules',[]) if _direct_or_reject(rule) and rule!='NETWORK,UDP,REJECT'])
 broad=[r for r in retained if r in ('GEOSITE,cn,DIRECT','GEOIP,CN,DIRECT')];specific=[r for r in retained if r not in broad]
 frontend_rule='IP-CIDR,'+settings['public_ip']+'/32,DIRECT,no-resolve'
 if frontend_rule not in specific:specific.insert(0,frontend_rule)
 business=[];tests=[]
 if not test:
  tests=['DOMAIN-SUFFIX,'+host+','+ROUTE_LABELS[key] for key in active for host in sites[key]['domains']]
  for key,scope in (('mytv','mytvsuper_domains'),('hk','hk_domains')):
   business.extend('DOMAIN-SUFFIX,'+host+','+GROUP_IDS[key] for host in contract[scope])
  for provider,hosts in contract['vps_domains'].items():
   need(provider in PROVIDER_GROUPS,'provider_domain_inventory');business.extend('DOMAIN-SUFFIX,'+host+','+PROVIDER_GROUPS[provider] for host in hosts)
  # Retain only the existing AI/Youtube business exceptions, remapping their
  # semantic target. Never retain a previous node or retired business group.
  for rule in profile.get('rules',[]):
   if not isinstance(rule,str) or ',' not in rule:continue
   target=rule.rsplit(',',1)[-1]
   if target in ('🤖 chatgpt、claude、google（不含youtube）','chatgpt、claude、google（不含youtube）'):
    business.append(rule.rsplit(',',1)[0]+','+GROUP_IDS['ai'])
   elif rule.startswith(('DOMAIN-SUFFIX,youtube.','DOMAIN-SUFFIX,youtu.be,','GEOSITE,youtube,')):
    business.append(rule.rsplit(',',1)[0]+','+GROUP_IDS['other'])
 output['rules']=unique(tests+specific+business+broad+['MATCH,'+GROUP_IDS['all'],'NETWORK,UDP,REJECT'])
 output['x-submerge-server-policy']='dmit-domain-routing-20261109-v2'
 output['x-submerge-client-policy']=REVISION;output['x-submerge-manual-test']=test
 output['x-submerge-ip-tests']={ROUTE_LABELS[key]:sites[key]['url'] for key in active}
 output[MARKER]={'schema':1,'revision':REVISION,'as_of':as_of,'kind':kind,'test':test,
  'routes':{key:ROUTE_LABELS[key] for key in active},'ai_cards':ai_cards,'ai_default':AI_DEFAULT,'provider_groups':dict(PROVIDER_GROUPS),
  'airport_sha256':digest(airport_cache),'airport_binding':copy.deepcopy(airport_cache.get('_request_binding')),
  'sites_sha256':digest(sites),'contract_sha256':digest(contract),
  'bindings_sha256':digest(front_bindings),'empty_airport_regions':[key for key,values in regions.items() if not values],
  'protected_sha256':_protection_hash(output),'render_sha256':_render_hash(output)}
 validate_profile(output,settings=settings,routing_contract=contract,airport_cache=airport_cache,sites=sites,as_of=as_of,front_bindings=front_bindings)
 return output

def validate_profile(document,*,settings=None,routing_contract=None,airport_cache=None,sites=None,as_of=None,front_bindings=None):
 need(isinstance(document,dict),'profile_object_required');meta=document.get(MARKER)
 keys={'schema','revision','as_of','kind','test','routes','ai_cards','ai_default','provider_groups','airport_sha256','airport_binding','sites_sha256','contract_sha256','bindings_sha256','empty_airport_regions','protected_sha256','render_sha256'}
 need(isinstance(meta,dict) and set(meta)==keys and meta['schema']==1 and meta['revision']==REVISION,'revision_metadata_invalid')
 need(meta['kind'] in ('mobile','desktop','router') and type(meta['test']) is bool,'revision_platform_invalid')
 need(document.get('x-submerge-client-kind')==meta['kind'] and document.get('x-submerge-manual-test') is meta['test']
  and document.get('x-submerge-client-policy')==REVISION,'top_level_revision_flags_mismatch')
 need(document.get('x-submerge-server-policy')=='dmit-domain-routing-20261109-v2','revised_main_policy_id_required')
 need(meta['protected_sha256']==_protection_hash(document),'preserved_protection_changed')
 need(meta['render_sha256']==_render_hash(document),'rendered_graph_changed')
 nodes=document.get('proxies',[]);rows=document.get('proxy-groups',[])
 need(all(isinstance(r,dict) and isinstance(r.get('name'),str) for r in nodes+rows),'profile_inventory')
 indexed={n['name']:n for n in nodes};groups={g['name']:g for g in rows}
 need(len(indexed)==len(nodes) and len(groups)==len(rows) and not set(indexed)&set(groups),'profile_identity_collision')
 need([r['name'] for r in rows if not r.get('hidden')]==list(VISIBLE_GROUPS),'eight_visible_groups_required')
 need('x-submerge-lazycat-ai' not in document and not document.get('proxy-providers'),'legacy_or_upstream_metadata_not_allowed')
 need(all(k in ROUTE_LABELS and v==ROUTE_LABELS[k] for k,v in meta['routes'].items()),'route_id_inventory')
 removed=set(NOTICE)|set(TEST_NOTICE)|{'中转节点'}
 need(not removed&(set(indexed)|set(groups)),'removed_ui_item_present')
 for name in VISIBLE_GROUPS:
  group=groups[name];need(group['type']=='select','visible_group_type')
  need(not group.get('desc') and not removed&set(group['proxies']),'removed_ui_item_present')
  need(group.get('default-selected') in group['proxies'],'real_group_default')
 all_members=[GROUP_IDS[k] for k in ('auto','ai','mytv','hk','vps','other','airport')]
 if meta['test']:all_members=[*meta['routes'].values(),*all_members]
 need(groups[GROUP_IDS['all']]['proxies']==all_members and groups[GROUP_IDS['all']]['default-selected']==(ROUTE_LABELS['dmit'] if meta['test'] else GROUP_IDS['auto']),'all_group_route_selection_contract')
 global_target=GROUP_IDS['all' if meta['test'] else 'auto']
 need(groups.get('GLOBAL',{}).get('proxies')==[global_target] and groups['GLOBAL'].get('default-selected')==global_target,'global_selection_contract')
 for key,owners in _business_owners(meta['routes']).items():
  automatic=groups.get(BUSINESS_AUTO[key],{})
  fastest=groups.get(BUSINESS_AIRPORT[key],{})
  need(automatic.get('type')=='fallback' and automatic.get('proxies')==owners+[BUSINESS_AIRPORT[key]]
   and automatic.get('url')==BUSINESS_HEALTH[key] and automatic.get('expected-status')=='200-499','business_auto_fallback_contract')
  need(fastest.get('type')=='url-test' and fastest.get('url')==BUSINESS_HEALTH[key]
   and fastest.get('expected-status')=='200-499' and fastest.get('hidden') is True,'business_airport_health_contract')
 for key in ('all','mytv','hk','other'):
  target=GROUP_IDS['auto' if key=='all' else key]
  need(groups[target]['default-selected']==BUSINESS_AUTO[key] and BUSINESS_AUTO[key] in groups[target]['proxies'],
       'visible_business_auto_default')
 for provider,name in PROVIDER_GROUPS.items():
  need(groups[name]['default-selected']==BUSINESS_AUTO['vps_'+provider],'provider_business_auto_default')
 graph={n:[] for n in indexed}
 for name,node in indexed.items():
  if node.get('dialer-proxy'):graph[name]=[node['dialer-proxy']]
 for name,group in groups.items():graph[name]=group.get('proxies',[])
 def visit(name,active,done):
  if name in BUILTINS or name in done:return
  need(name in graph,'dangling_group_reference');need(name not in active,'profile_group_cycle');active.add(name)
  for child in graph[name]:visit(child,active,done)
  active.remove(name);done.add(name)
 done=set()
 for name in graph:visit(name,set(),done)
 for rule in document.get('rules',[]):
  target=rule.split(',')[-2] if rule.endswith(',no-resolve') else rule.split(',')[-1]
  need(target in graph or target in BUILTINS,'dangling_rule_target')
 need(document['rules'][-2:]==['MATCH,'+GROUP_IDS['all'],'NETWORK,UDP,REJECT'],'terminal_rule_guard')
 need('GEOSITE,cn,DIRECT' in document['rules'] and 'GEOIP,CN,DIRECT' in document['rules'],'domestic_direct_required')
 credentials={indexed[name].get('password') for name in meta['routes'].values()}
 need(len(credentials)==1 and all(isinstance(p,str) and len(p)>=24 for p in credentials),'canonical_route_credentials')
 for name in meta['routes'].values():need(indexed[name].get('type')=='anytls' and indexed[name].get('udp') is False and indexed[name].get('dialer-proxy')=='DIRECT' and indexed[name].get('skip-cert-verify') is not True,'authenticated_route_transport')
 need(set(meta['ai_cards'])==set(AI_ROUTES) and meta['ai_default']==AI_DEFAULT and meta['provider_groups']==PROVIDER_GROUPS,'semantic_helper_inventory')
 preferred='singtel' if meta['kind']=='mobile' else 'lazycat_starhub'
 need(groups[AI_DEFAULT]['proxies']==[ROUTE_LABELS['lc_'+preferred],ROUTE_LABELS['dmit_'+preferred],REGION_FAST['SG']],'device_ai_default')
 for key,name in meta['ai_cards'].items():
  other='dmit_'+key[3:] if key.startswith('lc_') else 'lc_'+key[5:]
  need(groups[name]['type']=='fallback' and groups[name]['proxies']==[ROUTE_LABELS[key],ROUTE_LABELS[other],REGION_FAST['SG']],'real_ai_front_preference')
 if routing_contract is not None:
  contract=routing_contract;expected_as_of=contract.get('as_of') if as_of is None else as_of
  need(meta['as_of']==expected_as_of and meta['contract_sha256']==digest(contract),'contract_hash_or_epoch_changed')
  need(list(meta['routes'])==available(contract,expected_as_of),'retirement_route_boundary')
  if sites is not None:need(meta['sites_sha256']==digest(_sites(sites,contract)),'site_contract_changed')
  if settings is not None and sites is not None and front_bindings is not None:
   expected=_route_nodes(_template(document),_settings(settings),front_bindings,meta['kind'],list(meta['routes']),meta['test'],sites)
   need(meta['bindings_sha256']==digest(front_bindings),'front_bindings_changed')
   for key,row in expected.items():need(indexed[ROUTE_LABELS[key]]==row,'route_endpoint_or_label_changed')
 if airport_cache is not None:
  need(meta['airport_binding']==airport_cache.get('_request_binding'),'airport_request_binding_changed')
  need(meta['airport_sha256']==digest(airport_cache),'airport_cache_changed')
  expected_nodes,expected_groups,regions,roots=_airport(airport_cache)
  for row in expected_nodes:need(indexed.get(row['name'])==row,'airport_node_changed')
  for row in expected_groups:need(groups.get(row['name'])==row,'airport_original_group_changed')
  for region,members in regions.items():need(groups[REGION_FAST[region]]['proxies']==(members or ['REJECT']),'airport_region_changed')
  for key in BUSINESS_AUTO:
   region='HK' if key in ('mytv','hk') else 'ALL'
   need(groups[BUSINESS_AIRPORT[key]]['proxies']==(regions[region] or ['REJECT']),'business_airport_region_changed')
  owned=set(meta['routes'].values())|{AUTO_RAW}|{r['name'] for r in nodes if r.get('type') in ('direct','reject')}
  need(set(indexed)==owned|{r['name'] for r in expected_nodes},'unreviewed_node_inventory')
  need(groups[GROUP_IDS['airport']]['default-selected']==roots[0],'provider_auto_default_changed')
 return True

def _read_private(path,limit):
 path=Path(path);need(not path.is_symlink(),'client_gate_symlink')
 fd=os.open(str(path),os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 with os.fdopen(fd,'rb') as stream:
  info=os.fstat(stream.fileno());need(stat.S_ISREG(info.st_mode) and info.st_size<=limit and info.st_mode&0o077==0 and getattr(info,'st_uid',0)==0,'client_gate_private_file')
  raw=stream.read(limit+1)
 need(len(raw)<=limit,'client_gate_file_bound');return json.loads(raw)

def _airport_context(value,*,expected_binding=None):
 # Production points at one atomic full provider graph plus current node-bound
 # qualifications. A captured JSON path remains an offline/legacy input API.
 if isinstance(value,str):
  need(expected_binding is None,'dynamic_airport_binding_for_static_cache')
  return _read_private(value,16*1024*1024)
 need(isinstance(value,dict) and set(value)=={'snapshot_path','qualification_path'}
  and all(isinstance(path,str) and Path(path).is_absolute() for path in value.values()),
  'dynamic_airport_descriptor_invalid')
 from full_graph_cache import read_bound_client_snapshot
 graph,binding=read_bound_client_snapshot(value['snapshot_path'],qualification_path=value['qualification_path'],
   expected_binding=expected_binding)
 graph['_request_binding']=binding
 return graph

def _gate_context(gate_path,*,airport_binding=None):
 path=Path(gate_path)
 if not os.path.lexists(str(path)):return None
 gate=_read_private(path,1024*1024)
 need(gate.get('schema')==1 and gate.get('revision')==REVISION and type(gate.get('enabled')) is bool,'client_gate_schema')
 if not gate['enabled']:return None
 required={'schema','revision','enabled','settings_path','contract_path','airport_cache_path','sites_path','front_bindings_path'}
 need(set(gate)==required,'client_gate_fields')
 settings=_read_private(gate['settings_path'],65536);contract=_read_private(gate['contract_path'],1024*1024)
 airport=_airport_context(gate['airport_cache_path'],expected_binding=airport_binding);sites=_read_private(gate['sites_path'],262144)
 bindings=_read_private(gate['front_bindings_path'],262144)
 return {'settings':settings,'routing_contract':contract,'airport_cache':airport,'sites':sites,'front_bindings':bindings}

def try_project(profile,*,gate_path=CLIENT_GATE_PATH,as_of=None):
 context=_gate_context(gate_path)
 if context is None:return None
 return project_profile(profile,as_of=int(time.time()) if as_of is None else as_of,**context)

def validate_projected(document,*,gate_path=CLIENT_GATE_PATH):
 meta=document.get(MARKER,{}) if isinstance(document,dict) else {}
 binding=meta.get('airport_binding')
 if binding is not None:
  need(isinstance(binding,dict) and type(binding.get('materialized_at')) is int
   and 0<=int(time.time())-binding['materialized_at']<=BOUND_VALIDATION_MAX_AGE,'airport_request_binding_epoch_stale')
 context=_gate_context(gate_path,airport_binding=binding)
 if context is None:return validate_profile(document)
 validate_profile(document,as_of=document.get(MARKER,{}).get('as_of'),**context)
 need(list(document[MARKER]['routes'])==available(context['routing_contract'],int(time.time())),'expired_profile_snapshot')
 return True
