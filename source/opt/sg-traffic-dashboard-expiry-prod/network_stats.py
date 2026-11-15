"""Drop-in, dual-version statistics facade for the reviewed routing revision.

Legacy reads keep their exact implementation. New-plan query helpers execute
in a separate immutable namespace with the manifest's verified identities;
this never mutates legacy module globals or another request's inventory.
"""
import collections.abc,copy,hashlib,ipaddress,json,os,sqlite3,stat,time,types,urllib.parse
from contextlib import closing
from datetime import datetime
from pathlib import Path
import network_stats_legacy as legacy
import revision_inventory as catalog
import routing_contract as contract_module

REVISION=catalog.REVISION
PLAN_VERSION='network-plan-20261109'
SERVER_POLICY_ID='dmit-domain-routing-20261109-v2'
MANIFEST='/var/lib/sg-traffic-dashboard/topology-20261105.json'
PHYSICAL={
 'bytevirt-hk':('ByteVirt-HK ISP','bytevirt_hk_isp','dmit-hk'),
 'bytevirt-taiwan':('ByteVirt-TW','bytevirt_taiwan','dmit-taiwan'),
 'lazycat-starhub':('Lazycat-SG','lazycat','dmit-starhub'),
 'lazycat-hkt':('Lazycat-HKT','lazycat_hkt','dmit-hkt'),
 'uzuma-singtel':('Uzuma-SG-Singtel1','uzuma_singtel','dmit-singtel'),
 'uzuma-starhub':('Uzuma-SG-StarHub','uzuma_starhub','dmit-ai-uzuma-starhub'),
 'uzuma-hkt':('Uzuma-HKT','uzuma_hkt','dmit-uzuma-hkt')}
POOL_CLASSES={r:('paoluz_'+r.lower(),'paoluz '+r) for r in ('SG','HK','ALL')}
SITE_CHAINS={'dmit':('dmit','direct'),'lazycat_sg':('lazycat','direct'),
 'lc_singtel':('lazycat','uzuma-singtel'),'dmit_singtel':('dmit','uzuma-singtel'),
 'lc_lazycat_starhub':('lazycat','lazycat-starhub'),'dmit_lazycat_starhub':('dmit','lazycat-starhub'),
 'lc_uzuma_starhub':('lazycat','uzuma-starhub'),'dmit_uzuma_starhub':('dmit','uzuma-starhub'),
 'dmit_uzuma_hkt':('dmit','uzuma-hkt'),'dmit_bytevirt_hk':('dmit','bytevirt-hk'),
 'dmit_bytevirt_tw':('dmit','bytevirt-taiwan'),'dmit_lazycat_hkt':('dmit','lazycat-hkt')}
RULE_GROUPS=('全部节点','自动','中转节点','chatgpt、claude、google（不含youtube）','Mytvsuper专线','viu tv & HK其他','VPS访问','非中国大陆的其他','paoluz')

def need(value,code):
    if not value:raise ValueError(code)

def is_revision(manifest):return isinstance(manifest,dict) and manifest.get('network_plan')==PLAN_VERSION
def is_network_manifest(manifest):return is_revision(manifest) or legacy.is_network_manifest(manifest)
def active_host_names(manifest,now=None):
    if is_revision(manifest):return tuple(catalog.active_hosts(manifest['revision_inventory'],now=_clock(now)))
    legacy.validate_manifest(manifest);return legacy.ACTIVE_HOSTS
def relay_peer_names(manifest,now=None):
    return dict(_scope(manifest,now)['RELAY_PEERS']) if is_revision(manifest) else dict(legacy.RELAY_PEERS)

def _contract(manifest):return contract_module.validate(manifest['routing_contract'])
def _clock(now=None):return int(time.time() if now is None else now)

def _physical(manifest,now):
    active=set(catalog.active_hosts(manifest['revision_inventory'],now=now))
    return {tag:row for tag,row in PHYSICAL.items() if row[0] in active}

def _fronts(manifest,now):
    result=dict(manifest['server_policy_managed_fronts'])
    for tag,row in PHYSICAL.items():
        if row[0] not in catalog.active_hosts(manifest['revision_inventory'],now=now):
            for name in (row[2],'mobile-'+row[2]):result.pop(name,None)
    # A retired obsolete Zoro identity can never be admitted as a new front.
    need(not any('zoro' in name for name in result),'retired_zoro_front')
    return result

def validate_revision(manifest):
    need(is_revision(manifest) and manifest.get('schema')==1 and manifest.get('routing_revision')==REVISION,'statistics_revision_schema')
    inv=catalog.validate(manifest['revision_inventory']);contract=_contract(manifest)
    for key in ('inventory_epoch','routing_revision_activated_at','network_activated_at','cutoff','server_policy_activated_at'):
        legacy._epoch(manifest.get(key),key)
    need(manifest['inventory_epoch']>=manifest['network_activated_at'],'statistics_epoch_order')
    need(inv['activated_at']==manifest['routing_revision_activated_at'],'statistics_activation_binding')
    need(inv['servers']['ByteVirt-TW']['retire_at']==contract['taiwan_retire_at'] and
         inv['servers']['Lazycat-HKT']['retire_at']==contract['lazycat_hkt_retire_at'] and
         inv['servers']['Uzuma-HKT']['retire_at']==contract_module.UZUMA_HKT_RETIRE_AT,'statistics_contract_retirement_mismatch')
    need(manifest.get('server_policy')==SERVER_POLICY_ID,'statistics_server_policy_id')
    declared=catalog.active_hosts(inv,now=manifest['inventory_epoch'])
    need(manifest.get('active_hosts')==declared,'statistics_declared_active_inventory')
    fronts=manifest.get('server_policy_managed_fronts')
    need(isinstance(fronts,dict) and fronts and all(isinstance(k,str) and type(v) is int and 0<v<65536 for k,v in fronts.items()),'statistics_explicit_front_inventory')
    need(len(fronts)==len(set(fronts)) and len(set(fronts.values()))==len(fronts),'statistics_front_collision')
    need(not any('zoro' in name for name in fronts),'statistics_zoro_retired')
    for key in ('retired_host_cards','retired_user_usage','sample_commands','active_since','archive_epochs','peer_snapshots'):
        need(isinstance(manifest.get(key),dict),'statistics_manifest_object_'+key)
    need(not set(declared)&set(manifest['retired_host_cards']),'statistics_active_archive_overlap')
    need('ZORO-SG' in manifest['retired_host_cards'],'statistics_real_zoro_archive_required')
    zoro=manifest['retired_host_cards']['ZORO-SG'];stamp=zoro.get('last_measured_at') or zoro.get('sampled_at')
    need(type(stamp) is int and 0<stamp<inv['servers']['ZORO-SG']['retire_at'] and all(type(zoro.get(k)) is int and zoro[k]>=0 for k in ('in','out')),'statistics_real_zoro_pre_cutoff_required')
    for host,argv in manifest['sample_commands'].items():
        need(host in declared,'statistics_inactive_sampler')
        legacy._sample_command(argv)
    for host,epoch in manifest['active_since'].items():
        need(host in inv['servers'] and type(epoch) is int and 0<epoch<=manifest['inventory_epoch'],'statistics_active_epoch')
    changed=manifest.get('counter_source_changed_at',{})
    need(isinstance(changed,dict) and all(host in inv['servers'] and type(epoch) is int and 0<epoch<=manifest['inventory_epoch']
         for host,epoch in changed.items()),'statistics_counter_source_change_epoch')
    reverse=manifest.get('reverse_transports',{})
    need(isinstance(reverse,dict) and set(reverse)<= {'uzuma-hkt'},'statistics_reverse_transport_inventory')
    for tag,row in reverse.items():
        need(isinstance(row,dict) and set(row)=={'type','server','server_port','access_mode','evidence_path'} and row.get('access_mode')=='reverse_only' and row.get('type')=='shadowsocks' and
             row.get('server')=='127.0.0.1' and type(row.get('server_port')) is int and 1024<=row['server_port']<=65535 and
             isinstance(row.get('evidence_path'),str) and row['evidence_path'].startswith(('/root/','/var/lib/')),
             'statistics_explicit_private_reverse_binding')
    _verified_routes(manifest['verified_routes'],manifest,manifest['inventory_epoch'])
    legacy._validate_hk_daily_baseline(manifest['server_policy_hk_daily_baseline'],manifest['server_policy_activated_at'])
    pools=manifest.get('pool_routes')
    need(isinstance(pools,dict) and set(pools)==set(POOL_CLASSES),'statistics_pool_inventory')
    for region,item in pools.items():
        need(isinstance(item,dict) and item.get('outbound_tag')==contract_module.POOL_TAGS[region] and
             item.get('type')=='socks' and {k:item.get(k) for k in ('server','server_port')}==contract['pools'][region],
             'statistics_pool_endpoint_binding')
    need(isinstance(manifest.get('ip_test_sites'),dict) and set(manifest['ip_test_sites'])==set(SITE_CHAINS),'statistics_twelve_site_inventory')
    for route,row in manifest['ip_test_sites'].items():
        need(isinstance(row,dict) and isinstance(row.get('url'),str) and isinstance(row.get('domains'),list),'statistics_test_site_shape')
        url=urllib.parse.urlsplit(row['url'])
        need(url.scheme=='https' and url.hostname and not url.username and not url.password and
             any(url.hostname==d or url.hostname.endswith('.'+d) for d in row['domains']),'statistics_test_site_https_domain')
        front,outbound=SITE_CHAINS[route]
        need(any(r['front']==front and r['outbound']==outbound and r['domains']==row['domains'] for r in contract['ip_tests']),'statistics_test_site_contract_mismatch')
    need(tuple(manifest.get('rule_groups',[]))==RULE_GROUPS,'statistics_rule_group_inventory')
    return manifest

def validate_manifest(manifest):return validate_revision(manifest) if is_revision(manifest) else legacy.validate_manifest(manifest)

def _verified_routes(routes,manifest,now):
    physical=_physical(manifest,now);rows=[];seen=set()
    need(isinstance(routes,list),'statistics_verified_routes_required')
    for raw in routes:
        need(isinstance(raw,dict),'statistics_verified_route_shape')
        tag=raw.get('outbound_tag')
        # Past revision declarations remain historical; current attribution
        # ignores an explicitly retired physical hop instead of reopening it.
        if tag in PHYSICAL and tag not in physical:continue
        need(tag in physical and tag not in seen,'statistics_verified_outbound_inventory')
        host,route,_=physical[tag]
        need(raw.get('host')==host and raw.get('route_class')==route,'statistics_actual_host_class_binding')
        need(raw.get('type') in ('shadowsocks','anytls') and type(raw.get('server_port')) is int and 0<raw['server_port']<65536,'statistics_transport_type_port')
        try:
            address=ipaddress.ip_address(raw.get('server',''))
            if not address.is_global:
                reverse=manifest.get('reverse_transports',{}).get(tag,{})
                need(tag=='uzuma-hkt' and address==ipaddress.ip_address('127.0.0.1') and reverse.get('access_mode')=='reverse_only' and
                     all(raw.get(k)==reverse.get(k) for k in ('type','server','server_port')),'statistics_transport_global_or_exact_reverse_required')
        except ValueError:raise ValueError('statistics_literal_verified_transport_required') from None
        for k in ('inbound_tag','outbound_tag'):need(isinstance(raw.get(k),str) and raw[k] and not any(c.isspace() for c in raw[k]),'statistics_verified_identity')
        rows.append({k:raw.get(k) for k in ('host','inbound_tag','outbound_tag','route_class','type','server','server_port')});seen.add(tag)
    need(seen==set(physical),'statistics_actual_routes_incomplete')
    return rows

def server_policy_enabled(manifest):
    if is_revision(manifest):return manifest.get('server_policy')==SERVER_POLICY_ID
    return legacy.server_policy_enabled(manifest)

def read_optional_manifest(path=None):
    target=Path(path or os.environ.get('TOPOLOGY_ARCHIVE_MANIFEST',MANIFEST))
    if not target.is_file():return None
    info=target.stat()
    need(not target.is_symlink() and stat.S_ISREG(info.st_mode) and info.st_size<=4*1024*1024,'statistics_private_manifest_shape')
    if hasattr(os,'geteuid') and os.geteuid()==0:need(info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o600,'statistics_manifest_root_private')
    value=json.loads(target.read_text(encoding='utf8'))
    return validate_manifest(value) if is_network_manifest(value) else None

def _inventory_rows(manifest):
    result={}
    for host,row in manifest['revision_inventory']['servers'].items():
        item=copy.deepcopy(row);item.update(network=item['description'],period='month' if item['billing']=='monthly' else 'year',country='US' if host=='DMIT' else 'TW' if 'TW' in host else 'HK' if 'HK' in host else 'SG')
        item['day']=item.get('due_day',1)
        if item.get('due_month_day'):
            item['month'],item['day']=map(int,item['due_month_day'].split('-'))
        if item['monitoring_state']=='pending':item['period']='unknown'
        result[host]=item
    return result

def _scope(manifest,now=None):
    """Independent query context; legacy and other request globals stay intact."""
    validate_revision(manifest);now=_clock(now)
    namespace=dict(vars(legacy))
    for name,value in list(namespace.items()):
        if isinstance(value,types.FunctionType) and value.__module__==legacy.__name__:
            clone=types.FunctionType(value.__code__,namespace,value.__name__,value.__defaults__,value.__closure__)
            clone.__kwdefaults__=value.__kwdefaults__;namespace[name]=clone
    active=tuple(catalog.active_hosts(manifest['revision_inventory'],now=now));physical=_physical(manifest,now)
    namespace.update(PLAN_VERSION=PLAN_VERSION,SERVER_POLICY_ID=SERVER_POLICY_ID,ACTIVE_HOSTS=active,
       SERVER_POLICY_FRONTS=_fronts(manifest,now),POLICY_OUTBOUNDS=physical,
       POLICY_EXCLUSIVE_FRONTS=frozenset(_fronts(manifest,now)),
       RELAY_PEERS={**{r[1]:r[0] for r in physical.values()},**{route:peer for route,peer in POOL_CLASSES.values()}},INVENTORY=_inventory_rows(manifest),
       FORWARDED_OBSERVATION_PEERS=tuple(r[0] for r in physical.values() if r[0]!='ByteVirt-HK ISP'))
    namespace['is_network_manifest']=is_revision
    namespace['server_policy_enabled']=server_policy_enabled
    namespace['validate_manifest']=validate_revision
    namespace['normalize_verified_routes']=lambda rows:_verified_routes(rows,manifest,now)
    namespace['attach_inventory']=lambda payload,m,now=None:_attach_inventory(payload,m,_clock(now))
    namespace['attach_relay_observations']=_attach_relay_observations
    return namespace

class _ActiveHosts(collections.abc.Sequence):
    def value(self):
        manifest=read_optional_manifest()
        return tuple(catalog.active_hosts(manifest['revision_inventory'],now=_clock())) if is_revision(manifest) else legacy.ACTIVE_HOSTS
    def __getitem__(self,index):return self.value()[index]
    def __len__(self):return len(self.value())
    def __iter__(self):return iter(self.value())
    def __eq__(self,other):return self.value()==other
    def __repr__(self):return repr(self.value())
ACTIVE_HOSTS=_ActiveHosts()

class _DynamicMap(collections.abc.Mapping):
    def __init__(self,name):self.name=name
    def value(self):
        manifest=read_optional_manifest()
        return _scope(manifest)[self.name] if is_revision(manifest) else getattr(legacy,self.name)
    def __getitem__(self,key):return self.value()[key]
    def __iter__(self):return iter(self.value())
    def __len__(self):return len(self.value())
RELAY_PEERS=_DynamicMap('RELAY_PEERS')
INVENTORY=_DynamicMap('INVENTORY')
SERVER_POLICY_FRONTS=_DynamicMap('SERVER_POLICY_FRONTS')
POLICY_OUTBOUNDS=_DynamicMap('POLICY_OUTBOUNDS')

def _attach_inventory(payload,manifest,now):
    result=copy.deepcopy(payload);rows=_inventory_rows(manifest)
    sites=copy.deepcopy(manifest['ip_test_sites'])
    if now>=contract_module.UZUMA_HKT_RETIRE_AT:sites.pop('dmit_uzuma_hkt',None)
    for host in catalog.active_hosts(manifest['revision_inventory'],now=now):
        card=result.setdefault('servers',{}).get(host)
        if card is None:continue
        card.update(inventory=copy.deepcopy(rows[host]),display_name=rows[host]['display_name'])
        card['monitoring_epoch_started_at']=manifest.get('active_since',{}).get(host)
        if not card.get('sampled_at'):
            card.update({'in':None,'out':None,'today_in':None,'today_out':None,'sampling_state':'not_sampled','proxy_app':None,'direct':None})
    result.setdefault('topology',{}).update(network_plan=PLAN_VERSION,routing_revision=REVISION,
       active_hosts=catalog.active_hosts(manifest['revision_inventory'],now=now),
       archived_hosts=list(manifest['retired_host_cards']),inventory=copy.deepcopy(rows),
       pending_hosts=[h for h,r in rows.items() if r['monitoring_state']=='pending'],
       ip_test_sites=sites,rule_groups=copy.deepcopy(manifest['rule_groups']),
       historical_monitoring_epochs=copy.deepcopy(manifest['archive_epochs']))
    return result

def attach_inventory(live,manifest,now=None):
    return _attach_inventory(live,manifest,_clock(now)) if is_revision(manifest) else legacy.attach_inventory(live,manifest,now)

def apply_daily_archive(policy,manifest):
    if is_revision(manifest):return catalog.merge_retirement_policy(policy,manifest,manifest['revision_inventory'])
    return legacy.apply_daily_archive(policy,manifest)

def runtime_route_classes(config,manifest):
    if not is_revision(manifest):return legacy.runtime_route_classes(config,manifest)
    scope=_scope(manifest);result=scope['runtime_route_classes'](config,manifest)
    actual={x['tag']:x for x in config['outbounds']}
    need(not any('zoro' in name for name in actual),'statistics_retired_zoro_runtime')
    for region,spec in manifest['pool_routes'].items():
        row=actual.get(spec['outbound_tag'])
        need(row is not None and all(row.get(k)==spec[k] for k in ('type','server','server_port')),'statistics_actual_pool_differs')
        result[spec['outbound_tag']]=POOL_CLASSES[region][0]
    return result

def actual_closed_route(manifest,host,inbound,outbound,created_at_ms):
    if not is_revision(manifest):return legacy.actual_closed_route(manifest,host,inbound,outbound,created_at_ms)
    if host!='DMIT':return None
    need(type(created_at_ms) is int and created_at_ms>0,'statistics_event_start_required')
    if created_at_ms<manifest['inventory_epoch']*1000:
        previous=manifest.get('revision_previous_statistics')
        need(isinstance(previous,dict),'statistics_prior_authority_required')
        return actual_closed_route(previous,host,inbound,outbound,created_at_ms)
    event_time=created_at_ms//1000
    need(inbound in _fronts(manifest,event_time),'statistics_actual_front_unmanaged')
    if outbound=='direct':return 'direct','DMIT'
    for region,spec in manifest['pool_routes'].items():
        if outbound==spec['outbound_tag']:return POOL_CLASSES[region]
    physical=_physical(manifest,event_time);need(outbound in physical,'statistics_actual_outbound_unverified')
    row=physical[outbound];return row[1],row[0]

def configure_source_adapters(manifest,*,subscriber=None,finalization=None,retention=None,role_policy=None):
    if not is_revision(manifest):return legacy.configure_source_adapters(manifest,subscriber=subscriber,finalization=finalization,retention=retention,role_policy=role_policy)
    scope=_scope(manifest);scope['configure_source_adapters'](manifest,subscriber=subscriber,finalization=finalization,retention=retention,role_policy=role_policy)
    for region,spec in manifest['pool_routes'].items():
        route,peer=POOL_CLASSES[region];tag=spec['outbound_tag']
        if subscriber is not None:subscriber.PROVIDERS[tag]=peer
        if retention is not None:retention.PROVIDERS[tag]=(route,peer)
        if role_policy is not None:role_policy.ROUTE_PEERS[route]=peer
    if role_policy is not None:
        role_policy.FIRST_HOPS=role_policy.FIRST_HOPS|frozenset({'Lazycat-SG-Front'})
        role_policy.ACTIVE_EXITS=frozenset(catalog.active_hosts(manifest['revision_inventory'],now=_clock()))-frozenset({'DMIT','Lazycat-SG-Front'})
    return manifest

def collector_sample(base_sample,item,manifest):
    if not is_revision(manifest):return legacy.collector_sample(base_sample,item,manifest)
    if item[0] not in catalog.active_hosts(manifest['revision_inventory'],now=_clock()):return item[0],None,'ExplicitRetirementNoSample'
    server,value,error=_scope(manifest)['collector_sample'](base_sample,item,manifest)
    if item[0]=='DMIT' and server=='DMIT' and not error and value is not None:
        # These four cached optional provider totals belong to approved retired
        # paths. They are not current observations. Keep every fresh NIC/rich
        # field and all stored history; never turn an unknown provider into an
        # allowed counter, or invent a zero for a retired one.
        retired={'nexip_sg','ip2up','proxyhive','zoro_sg'}
        if retired.intersection(value.get('static_egress',{})):
            value=copy.deepcopy(value)
            value['static_egress']={key:amount for key,amount in value['static_egress'].items() if key not in retired}
    return server,value,error

def store_epoch_sample(base_store,db,host,item,error,manifest):
    if not is_revision(manifest):return legacy.store_epoch_sample(base_store,db,host,item,error,manifest)
    if host not in catalog.active_hosts(manifest['revision_inventory'],now=_clock()):return None
    if item is not None:need(catalog.sample_allowed(manifest['revision_inventory'],host,item['ts'],now=_clock()),'statistics_retired_measurement_rejected')
    source_epoch=manifest.get('counter_source_changed_at',{}).get(host)
    baseline=False
    if source_epoch and not error and item is not None:
        need(item['ts']>=source_epoch,'statistics_counter_sample_predates_change')
        previous=db.execute('SELECT ts FROM samples WHERE server=? ORDER BY ts DESC LIMIT 1',(host,)).fetchone()
        baseline=previous is None or previous[0]<source_epoch
    result=_scope(manifest)['store_epoch_sample'](base_store,db,host,item,error,manifest)
    if baseline:
        # Preserve actual timestamp, real boot ID and cumulative NIC values.
        # Only the first new-strategy row establishes its delta baseline.
        db.execute('UPDATE samples SET delta_rx=0,delta_tx=0 WHERE server=? AND ts=?',(host,item['ts']))
    return result

def _attach_relay_observations(live,db_path,manifest,now=None,traffic_start=0):
    if not Path(db_path).is_file():return live
    now=_clock(now);physical=_physical(manifest,now)
    with closing(sqlite3.connect(Path(db_path).resolve().as_uri()+'?mode=ro',uri=True,timeout=2)) as db:
        for peer,_,_ in physical.values():
            if peer not in live.get('servers',{}):continue
            card=live['servers'][peer];start=max(int(traffic_start),now-30*86400,int(manifest.get('active_since',{}).get(peer,0)))
            if peer=='ByteVirt-HK ISP':start=max(start,manifest['server_policy_activated_at'])
            deadline=time.monotonic()+1;db.set_progress_handler(lambda:time.monotonic()>deadline,10000)
            try:
                row=db.execute('SELECT COUNT(*),COUNT(DISTINCT user),SUM(upload),SUM(download),MIN(started),MAX(started),MAX(changed) FROM unified_records INDEXED BY idx_unified_hk_usage WHERE relay=? AND started>=? AND started<=? AND traffic_known=1 AND route_type=\'中转\' AND ((origin=\'dmit\' AND ingress=\'DMIT\') OR (origin=\'lazycat\' AND ingress=\'Lazycat-SG-Front\')) AND upload>=0 AND download>=0 AND changed<=?',(peer,start,now,now)).fetchone()
            except sqlite3.Error as error:
                card.update(application_observation=None,application_observation_state='temporarily_unavailable',application_refresh_error_type=type(error).__name__);continue
            finally:db.set_progress_handler(None,0)
            if not row[0]:card.update(application_observation=None,application_observation_state='no_confirmed_sessions_in_window');continue
            observation={'observed_on':'DMIT','first_hop':'confirmed record ingress','relay':peer,'route_type':'中转','source':'unified_records','meter_basis':'confirmed_proxy_forwarding_application','estimated':True,'independent_egress_meter':False,'upload':int(row[2]),'download':int(row[3]),'bytes':int(row[2])+int(row[3]),'sessions':int(row[0]),'users':int(row[1]),'first_session_started':int(row[4]),'latest_session_started':int(row[5]),'last_observed_at':int(row[6]),'window_start':start,'window_end':now}
            card.update(application_observation=observation,application_observation_state='confirmed_forwarding_observation')
    return live

def attach_relay_observations(live,db_path,manifest,now=None,traffic_start=0):
    return _attach_relay_observations(live,db_path,manifest,now,traffic_start) if is_revision(manifest) else legacy.attach_relay_observations(live,db_path,manifest,now,traffic_start)

def active_whole_payload(db_path,traffic_start,now,manifest,empty_card):
    return _scope(manifest,now)['active_whole_payload'](db_path,traffic_start,now,manifest,empty_card) if is_revision(manifest) else legacy.active_whole_payload(db_path,traffic_start,now,manifest,empty_card)

def user_usage_query(manifest,traffic_start,now):
    """One complete aggregation with fixed leading-origin index predicates.

    Each relay keeps its own real activation/window boundary. CROSS JOIN fixes
    the tiny reviewed window table before the origin/relay/started index lookup;
    the two fixed origins avoid SQLite's observed ANY(origin) skip scan.
    """
    now=_clock(now);peers=[row[0] for row in _physical(manifest,now).values()];windows=[]
    for peer in peers:
        start=max(int(traffic_start),now-30*86400,int(manifest.get('active_since',{}).get(peer,0)))
        if peer=='ByteVirt-HK ISP':start=max(start,manifest['server_policy_activated_at'])
        windows.append((peer,start))
    need(bool(windows),'statistics_user_usage_windows_required')
    values=','.join('(?,?)' for _ in windows)
    branch="SELECT r.relay,r.user,r.upload+r.download bytes FROM windows w CROSS JOIN unified_records r INDEXED BY idx_unified_hk_usage WHERE r.origin=? AND r.ingress=? AND r.relay=w.peer AND r.started>=w.first_ts AND r.started<=? AND r.changed<=? AND r.traffic_known=1 AND r.route_type='中转' AND r.upload>=0 AND r.download>=0"
    query='WITH windows(peer,first_ts) AS (VALUES '+values+') SELECT relay,user,SUM(bytes) FROM ('+branch+' UNION ALL '+branch+') GROUP BY relay,user'
    args=[part for window in windows for part in window]+['dmit','DMIT',now,now,'lazycat','Lazycat-SG-Front',now,now]
    return query,args,peers

def extend_active_user_usage(rows,db_path,traffic_start,now,manifest):
    if not is_revision(manifest):return legacy.extend_active_user_usage(rows,db_path,traffic_start,now,manifest)
    now=_clock(now);query,args,peers=user_usage_query(manifest,traffic_start,now);active=set(catalog.active_hosts(manifest['revision_inventory'],now=now))
    result=[copy.deepcopy(r) for r in rows if r.get('server') in active and (r.get('server') not in peers or r.get('server')=='ByteVirt-HK ISP')]
    if not Path(db_path).is_file():return result
    with closing(sqlite3.connect(Path(db_path).resolve().as_uri()+'?mode=ro',uri=True,timeout=2)) as db:
        deadline=time.monotonic()+180;db.set_progress_handler(lambda:time.monotonic()>deadline,10000)
        # Materialize only the bounded grouped result. On any query failure no
        # partial user totals escape; the caller retains last-confirmed data.
        totals=list(db.execute(query,args))
    for peer,user,amount in totals:
        if not amount or amount<0:continue
        prior=next((r for r in result if r['server']==peer and r['user']==user),None)
        if prior:prior['total']+=int(amount);prior.update(estimated=True,basis='real prior meter plus confirmed forwarding application bytes')
        else:result.append({'server':peer,'user':user,'total':int(amount),'estimated':True,'basis':'confirmed forwarding application bytes'})
    return result

def adjust_hk_daily_rows(rows,manifest,from_day,to_day,*,user='',host=''):
    return _scope(manifest)['adjust_hk_daily_rows'](rows,manifest,from_day,to_day,user=user,host=host) if is_revision(manifest) else legacy.adjust_hk_daily_rows(rows,manifest,from_day,to_day,user=user,host=host)

def next_billing_at(host,now=None):
    manifest=read_optional_manifest()
    return _scope(manifest)['next_billing_at'](host,now) if is_revision(manifest) else legacy.next_billing_at(host,now)

def inventory(now=None):
    manifest=read_optional_manifest()
    return _scope(manifest)['inventory'](now) if is_revision(manifest) else legacy.inventory(now)

def verified_routes_from_observed_runtime(config,manifest=None):
    manifest=manifest or read_optional_manifest()
    if not is_revision(manifest):return legacy.verified_routes_from_observed_runtime(config)
    return _scope(manifest)['verified_routes_from_observed_runtime'](config)

def normalize_verified_routes(routes,manifest=None):
    manifest=manifest or read_optional_manifest()
    return _verified_routes(routes,manifest,_clock()) if is_revision(manifest) else legacy.normalize_verified_routes(routes)

def routes_from_runtime_marker(marker):
    if not isinstance(marker,dict) or marker.get('plan')!=PLAN_VERSION:return legacy.routes_from_runtime_marker(marker)
    manifest=read_optional_manifest();need(is_revision(manifest),'statistics_revision_marker_requires_manifest')
    policy=marker.get('server_policy',{})
    need(policy.get('id')==SERVER_POLICY_ID and policy.get('routing_revision')==manifest['routing_contract'],'statistics_runtime_marker_contract')
    hops=dict(marker.get('transports',{}));hops['bytevirt-hk']=policy.get('hk_transport',{})
    result=[]
    for tag,(host,route,front) in _physical(manifest,_clock()).items():
        source='bytevirt-tw' if tag=='bytevirt-taiwan' else tag;hop=hops.get(source,{})
        result.append(dict(host=host,route_class=route,inbound_tag=front,outbound_tag=tag,
                           **{k:hop.get(k) for k in ('type','server','server_port')}))
    result=_verified_routes(result,manifest,_clock())
    need(result==_verified_routes(manifest['verified_routes'],manifest,_clock()),'statistics_marker_route_drift')
    return result

def enable_server_policy_manifest(previous,observed_runtime,activated_at,*,hk_daily_baseline=None):
    if not is_revision(previous):return legacy.enable_server_policy_manifest(previous,observed_runtime,activated_at,hk_daily_baseline=hk_daily_baseline)
    validate_revision(previous)
    need(verified_routes_from_observed_runtime(observed_runtime,previous)==_verified_routes(previous['verified_routes'],previous,_clock()),'statistics_active_route_drift')
    return copy.deepcopy(previous)

def capture_hk_daily_baseline(previous,daily_db_path,cutoff):
    if not is_revision(previous):return legacy.capture_hk_daily_baseline(previous,daily_db_path,cutoff)
    validate_revision(previous);return copy.deepcopy(previous['server_policy_hk_daily_baseline'])

def prepare_revision_manifest(previous,payload,requirements,contract,observed_runtime,*,approved_fronts,
                              sample_commands,activated_at,ip_test_sites,rule_groups,
                              whole_db_path=None,traffic_start=0,reverse_transports=None,counter_source_changed_hosts=()):
    """One explicit release transition; caller validates native policy first.

    Old HK daily-authority baseline and date stay untouched. New routing
    activation is independent; no accumulated daily row is reset or renamed.
    """
    validate_manifest(previous);contract=contract_module.validate(contract)
    first_activation=previous['routing_revision_activated_at'] if is_revision(previous) else activated_at
    inv=catalog.build_inventory(requirements,contract,activated_at=first_activation)
    payload=copy.deepcopy(payload)
    retiring=set(previous['active_hosts'])-set(catalog.active_hosts(inv,now=activated_at))
    for host in retiring-set(previous.get('retired_host_cards',{})):
        cards=payload.setdefault('whole',{}).setdefault('servers',{})
        end=inv['servers'].get(host,{}).get('retire_at') or activated_at
        candidate=cards.get(host,{})
        stamp=candidate.get('last_measured_at') or candidate.get('sampled_at')
        if (any(type(candidate.get(k)) is not int or candidate[k]<0 for k in ('in','out'))
                or type(stamp) is not int or not 0<stamp<end):
            need(whole_db_path is not None,'statistics_pre_cutoff_payload_or_real_database_required')
            card,users=capture_retirement_from_database(whole_db_path,host,end,
                epoch=previous.get('active_since',{}).get(host,0),traffic_start=traffic_start)
            cards[host]=card
            payload.setdefault('server_user_usage',[]).extend(users)
    manifest=catalog.migrate_manifest(previous,payload,inv,now=activated_at,sample_commands=sample_commands)
    need(isinstance(counter_source_changed_hosts,(list,tuple,set,frozenset)) and
         set(counter_source_changed_hosts)<=set(manifest['active_hosts']),'statistics_explicit_changed_counter_hosts')
    manifest['counter_source_changed_at']=copy.deepcopy(previous.get('counter_source_changed_at',{}))
    for host in counter_source_changed_hosts:
        if host not in manifest['counter_source_changed_at'] or previous.get('sample_commands',{}).get(host)!=sample_commands[host]:
            manifest['counter_source_changed_at'][host]=activated_at
    manifest.update(network_plan=PLAN_VERSION,server_policy=SERVER_POLICY_ID,routing_contract=copy.deepcopy(contract),
        routing_revision_activated_at=first_activation,server_policy_managed_fronts=dict(approved_fronts),
        revision_previous_statistics=copy.deepcopy(previous),
        ip_test_sites=copy.deepcopy(ip_test_sites),rule_groups=copy.deepcopy(rule_groups),
        pool_routes={region:dict(outbound_tag=contract_module.POOL_TAGS[region],type='socks',**contract['pools'][region]) for region in POOL_CLASSES})
    reverse=reverse_transports if reverse_transports is not None else previous.get('reverse_transports',{})
    manifest['reverse_transports']={tag:{k:copy.deepcopy(row[k]) for k in ('type','server','server_port','access_mode','evidence_path') if k in row} for tag,row in reverse.items()}
    inbounds={row['tag']:row for row in observed_runtime['inbounds']}
    need(set(inbounds)==set(approved_fronts) and all(inbounds[t].get('type')=='anytls' and inbounds[t].get('listen_port')==port for t,port in approved_fronts.items()),'statistics_release_native_fronts_differ')
    outbounds={row['tag']:row for row in observed_runtime['outbounds']}
    routes=[]
    for tag,(host,route,front) in _physical(manifest,activated_at).items():
        row=outbounds.get(tag,{})
        routes.append(dict(host=host,route_class=route,inbound_tag=front,outbound_tag=tag,
                           **{k:row.get(k) for k in ('type','server','server_port')}))
    manifest['verified_routes']=_verified_routes(routes,manifest,activated_at)
    manifest['release_runtime_sha256']=hashlib.sha256(json.dumps(observed_runtime,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    # Every live physical host must be independently sampleable. The caller
    # passes the merged explicit DMIT/HK base argv too; no missing-host zeros.
    need(set(manifest['sample_commands'])==set(manifest['active_hosts']),'statistics_all_active_samplers_required')
    return validate_revision(manifest)

def capture_retirement_from_database(db_path,host,end,*,epoch=0,traffic_start=0):
    """Reboot/cutoff catch-up from actual pre-cutoff rows, never current clock.

    Does not require the retired host to remain in the live dashboard payload.
    Current/post-cutoff rows are excluded, and no timestamps are synthesized.
    """
    need(type(end) is int and end>0 and isinstance(host,str),'statistics_retirement_boundary')
    start=max(int(traffic_start),int(epoch),end-30*86400);today=max(start,end-1-((end-1+8*3600)%86400))
    with closing(sqlite3.connect(Path(db_path).resolve().as_uri()+'?mode=ro',uri=True,timeout=2)) as db:
        deadline=time.monotonic()+45;db.set_progress_handler(lambda:time.monotonic()>deadline,10000)
        row=db.execute('SELECT COUNT(*),SUM(delta_rx),SUM(delta_tx),SUM(CASE WHEN ts>=? THEN delta_rx ELSE 0 END),SUM(CASE WHEN ts>=? THEN delta_tx ELSE 0 END),MAX(ts) FROM samples WHERE server=? AND ts>=? AND ts<?',(today,today,host,start,end)).fetchone()
        need(row[0] and type(row[5]) is int and row[5]<end,'statistics_real_pre_cutoff_nic_rows_required')
        card={'in':int(row[1] or 0),'out':int(row[2] or 0),'today_in':int(row[3] or 0),'today_out':int(row[4] or 0),
              'sampled_at':int(row[5]),'last_measured_at':int(row[5]),'sampling_basis':'actual_pre_cutoff_database_rows',
              'proxy_app':None,'direct':None,'static_outbound':{},'mapping_wire':None}
        users=[{'server':host,'user':user,'total':int(amount),'estimated':True,
                'basis':'confirmed application records observed before retirement'}
               for user,amount in db.execute('SELECT user,SUM(upload+download) FROM unified_records INDEXED BY idx_unified_hk_usage WHERE relay=? AND started>=? AND started<? AND changed<? AND traffic_known=1 AND route_type=\'中转\' AND ((origin=\'dmit\' AND ingress=\'DMIT\') OR (origin=\'lazycat\' AND ingress=\'Lazycat-SG-Front\')) AND upload>=0 AND download>=0 GROUP BY user',(host,start,end,end)) if amount and amount>0]
    return card,users

def __getattr__(name):return getattr(legacy,name)
