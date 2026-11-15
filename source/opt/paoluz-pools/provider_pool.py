"""Offline provider graph projection and fail-closed pool decisions.

No subscription fetch, sockets, clocks or production mutations occur here.
Names nominate region probes; only fresh real exit observations admit nodes.
"""
import copy,hashlib,ipaddress,json,math,re

REVISION='routing-revision-20261109-v1'
AUTO_TYPES={'url-test','fallback','load-balance'}
BUILTINS={'DIRECT','REJECT','REJECT-DROP','PASS','COMPATIBLE'}
REGIONS=('SG','HK','ALL')
GATES={r:'PAOLUZ_'+r+'_GATE' for r in REGIONS}
FAST={r:'PAOLUZ_'+r+'_FAST' for r in REGIONS}
SG_ROUTES=('lc_singtel','dmit_singtel','lc_lazycat_starhub','dmit_lazycat_starhub','lc_uzuma_starhub','dmit_uzuma_starhub')
ROUTE_TO_PATH={'lc_singtel':('lazycat','S'),'dmit_singtel':('dmit','S'),
 'lc_lazycat_starhub':('lazycat','L'),'dmit_lazycat_starhub':('dmit','L'),
 'lc_uzuma_starhub':('lazycat','U'),'dmit_uzuma_starhub':('dmit','U')}
QUALIFICATION_SOURCES={'cloudflare','ipinfo'}

def need(condition,message):
    if not condition:raise ValueError(message)

def digest(value):
    return hashlib.sha256(json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def _rows(value,field):
    rows=value.get(field,[])
    need(isinstance(rows,list) and len(rows)<=1024,'provider_'+field+'_shape')
    names=[]
    for row in rows:
        need(isinstance(row,dict) and isinstance(row.get('name'),str) and 0<len(row['name'])<=256,'provider_name')
        names.append(row['name'])
    need(len(set(names))==len(names),'provider_duplicate_'+field)
    return copy.deepcopy(rows)

def _filter(names,group):
    for key,exclude in (('filter',False),('exclude-filter',True)):
        expression=group.get(key)
        if expression:
            need(isinstance(expression,str) and len(expression)<=256,'provider_filter_limit')
            pattern=re.compile(expression)
            names=[name for name in names if bool(pattern.search(name))!=exclude]
    return names

def materialize(raw,*,provider_snapshots=None,qualifications=None,now,max_qualification_age=600):
    """Retain actual upstream automatic group types/options, never invent one.

    provider_snapshots are caller-read offline documents keyed by upstream
    provider name. HTTP/file URLs are never followed. Unknown groups fail.
    """
    need(isinstance(raw,dict),'provider_document_required')
    need(type(now) is int and now>0,'explicit_now_required')
    proxies=_rows(raw,'proxies');groups=_rows(raw,'proxy-groups')
    snapshots=provider_snapshots or {};provider_names={}
    need(isinstance(snapshots,dict),'provider_snapshots_shape')
    for name,snapshot in snapshots.items():
        need(isinstance(name,str) and isinstance(snapshot,dict),'provider_snapshot_shape')
        rows=_rows(snapshot,'proxies');provider_names[name]=[x['name'] for x in rows];proxies.extend(rows)
    pnames=[x['name'] for x in proxies];gnames=[x['name'] for x in groups]
    need(len(set(pnames+gnames))==len(pnames+gnames),'provider_name_collision')
    need(not set(pnames+gnames)&BUILTINS,'provider_reserved_name')
    need(proxies,'provider_nodes_unavailable')
    need(groups,'airport_original_auto_unavailable')
    resolved={}
    for group in groups:
        members=group.get('proxies',[])
        need(isinstance(members,list) and all(isinstance(x,str) for x in members),'provider_group_members')
        members=list(members)
        uses=group.get('use',[])
        need(isinstance(uses,list) and all(isinstance(x,str) for x in uses),'provider_group_uses')
        for name in uses:
            need(name in provider_names,'offline_provider_snapshot_missing')
            members.extend(provider_names[name])
        if group.get('include-all') or group.get('include-all-proxies'):members.extend(pnames)
        if group.get('include-all-providers'):
            for names in provider_names.values():members.extend(names)
        members=list(dict.fromkeys(_filter(members,group)))
        need(members,'provider_empty_original_group')
        need(all(x in set(pnames+gnames)|BUILTINS for x in members),'provider_unresolved_reference')
        resolved[group['name']]=members
    graph={x['name']:resolved[x['name']] for x in groups}
    for proxy in proxies:
        if proxy.get('dialer-proxy'):
            ref=proxy['dialer-proxy'];need(ref in set(pnames+gnames)|BUILTINS,'provider_dialer_reference')
            graph[proxy['name']]=[ref]
    def visit(name,path):
        need(name not in path,'provider_group_cycle')
        for item in graph.get(name,[]):
            if item in graph:visit(item,path|{name})
    for name in graph:visit(name,set())
    automatic=[g['name'] for g in groups if g.get('type') in AUTO_TYPES]
    need(automatic,'airport_original_auto_unavailable')
    qualifications=qualifications or {}
    need(isinstance(qualifications,dict),'provider_qualifications_shape')
    region_members={'SG':[],'HK':[],'ALL':pnames[:]}
    verified={}
    for proxy in proxies:
        name=proxy['name'];proof=qualifications.get(name)
        if _qualified(proxy,proof,now,max_qualification_age):
            country=proof['checks'][0]['country']
            if country in ('SG','HK'):region_members[country].append(name)
            verified[name]=copy.deepcopy(proof)
    return {'schema':1,'revision':REVISION,'source_sha256':digest(raw),'materialized_at':now,
       'proxies':proxies,'proxy-groups':groups,'resolved_group_members':resolved,
       'region_members':region_members,'provider_auto_roots':automatic,
       'node_sha256':{p['name']:digest(p) for p in proxies},'qualifications':verified,
       'qualification_ttl':max_qualification_age,
       'region_probe_candidates':{'SG':[n for n in pnames if re.search(r'新加坡|狮城|獅城|singapore|(?:^|[^a-z])sg(?:[^a-z]|$)',n,re.I)],
                                  'HK':[n for n in pnames if re.search(r'香港|hong\s*kong|(?:^|[^a-z])hk(?:[^a-z]|$)',n,re.I)]}}

def _qualified(proxy,proof,now,max_age):
    if not isinstance(proof,dict) or proof.get('node_sha256')!=digest(proxy) or proof.get('status')!='completed':return False
    stamp=proof.get('checked_at');checks=proof.get('checks')
    if type(stamp) is not int or not 0<=now-stamp<=max_age:return False
    if not isinstance(checks,list) or len(checks)!=2:return False
    if {x.get('source') for x in checks if isinstance(x,dict)}!=QUALIFICATION_SOURCES:return False
    countries=[]
    for row in checks:
        if row.get('success') is not True or type(row.get('checked_at')) is not int or not 0<=now-row['checked_at']<=max_age:return False
        try:address=ipaddress.ip_address(row.get('ip',''))
        except (TypeError,ValueError):return False
        if not address.is_global or not re.fullmatch('[A-Z]{2}',str(row.get('country',''))):return False
        countries.append(row['country'])
    return len(set(countries))==1

def normalize_sg_observations(fronts,*,now,max_age=90):
    """Consume the actual V4 status+ACK format, not unhealthy booleans alone."""
    result={name:{'status':'unknown','completed':False} for name in SG_ROUTES}
    cohorts={row.get('cohort_sha256') for row in fronts.values() if isinstance(row,dict) and row.get('verified') is True}
    if len(cohorts)>1:return result
    for route,(front,label) in ROUTE_TO_PATH.items():
        row=fronts.get(front,{})
        fields=('generation','cohort_sha256','manifest_sha256','runtime_sha256')
        if row.get('verified') is not True or any(not row.get(k) for k in fields):continue
        stamp=row.get('checked_at');proof=row.get('proof',{})
        def fresh(value):return type(value) in (int,float) and math.isfinite(value) and -1<=now-value<=max_age
        if not fresh(stamp):continue
        ptime=proof.get('checked_at')
        if proof.get('status')!='completed' or proof.get('qualification_state')!='qualified' or not fresh(ptime):continue
        paths=proof.get('paths',[])
        aliases={'L':'lazycat-starhub','S':'uzuma-singtel','U':'uzuma-starhub'}
        matches=[p for p in paths if p.get('label') in (label,aliases[label])]
        if len(matches)!=1:continue
        path=matches[0];state=path.get('health_state')
        if state not in ('healthy','unhealthy') or path.get('healthy') is not (state=='healthy'):continue
        result[route]={'status':'healthy' if state=='healthy' else 'failed','completed':True,
                       'observed_at':int(min(stamp,ptime)),'source_generation':row['generation']}
    return result

def _all_failed(names,observations,now,max_age):
    if not names:return False
    for name in names:
        row=observations.get(name,{})
        stamp=row.get('observed_at')
        if row.get('completed') is not True or row.get('status')!='failed' or type(stamp) is not int or not 0<=now-stamp<=max_age:return False
        if not row.get('source_generation'):return False
    return True

def gate_decisions(cache,*,fronts,owned_observations,business_paths,now,max_age=90):
    """ALL gate permission complements, never replaces, category selectors.

    business_paths exactly defines mytvsuper, viu, other, vps active owned
    routes. Root's main control must still prove each category all-failed.
    """
    need(set(business_paths)=={'mytvsuper','viu','other','vps'},'business_paths_inventory')
    def groups(value):
        need(isinstance(value,list) and value,'business_paths_shape')
        rows=[value] if all(isinstance(x,str) for x in value) else value
        need(all(isinstance(r,list) and r and all(isinstance(x,str) for x in r) and len(r)==len(set(r)) for r in rows),'business_paths_shape')
        return rows
    branches={key:groups(value) for key,value in business_paths.items()}
    observations=dict(owned_observations);observations.update(normalize_sg_observations(fronts,now=now,max_age=max_age))
    members={'SG':[],'HK':[],'ALL':[]}
    for p in cache['proxies']:
        if _qualified(p,cache.get('qualifications',{}).get(p['name']),now,cache.get('qualification_ttl',600)):
            members['ALL'].append(p['name'])
            country=cache['qualifications'][p['name']]['checks'][0]['country']
            if country in ('SG','HK'):members[country].append(p['name'])
    permits={'SG':_all_failed(SG_ROUTES,observations,now,max_age),
             'HK':any(_all_failed(group,observations,now,max_age) for b in ('mytvsuper','viu') for group in branches[b]),
             'ALL':any(_all_failed(group,observations,now,max_age) for b in ('other','vps') for group in branches[b])}
    configured=pool_members(cache)
    return {region:{'selected':FAST[region] if permits[region] and members[region] and members[region]==configured[region] else 'REJECT',
                    'owned_all_failed':permits[region],'qualified_members':members[region],
                    'regeneration_required':members[region]!=configured[region],
                    'checked_at':now} for region in REGIONS}

def pool_members(cache):
    members={'SG':[],'HK':[],'ALL':[]}
    for proxy in cache['proxies']:
        proof=cache.get('qualifications',{}).get(proxy['name'])
        if _qualified(proxy,proof,cache['materialized_at'],cache.get('qualification_ttl',600)):
            members['ALL'].append(proxy['name'])
            country=proof['checks'][0]['country']
            if country in ('SG','HK'):members[country].append(proxy['name'])
    return members

def render_mihomo(cache,*,pools,api_port,api_secret,probe_port=18334,probe_ports=None):
    """Three local SOCKS pools plus an isolated local qualification selector."""
    need(set(pools)==set(REGIONS),'three_region_pools_required')
    probe_ports=list(probe_ports) if probe_ports is not None else [probe_port]
    need(1<=len(probe_ports)<=4,'bounded_qualification_probes')
    ports=[pools[r]['server_port'] for r in REGIONS]+[api_port]+probe_ports
    need(len(ports)==len(set(ports)) and all(type(p) is int and 1024<=p<=65535 for p in ports),'pool_ports')
    need(all(pools[r]['server']=='127.0.0.1' for r in REGIONS),'loopback_only_pools')
    need(isinstance(api_secret,str) and len(api_secret)>=32,'strong_private_api_secret')
    original=cache['proxies']+cache['proxy-groups'];names={r['name']:'UPSTREAM::'+r['name'] for r in original}
    def mapped(name):return names.get(name,name)
    proxies=copy.deepcopy(cache['proxies'])
    for p in proxies:
        if p.get('dialer-proxy'):p['dialer-proxy']=mapped(p['dialer-proxy'])
        p['name']=mapped(p['name'])
    groups=[]
    for g in copy.deepcopy(cache['proxy-groups']):
        name=g['name'];g['name']=mapped(name);g['proxies']=[mapped(n) for n in cache['resolved_group_members'][name]]
        for k in ('use','include-all','include-all-proxies','include-all-providers','filter','exclude-filter'):g.pop(k,None)
        if 'default-selected' in g:g['default-selected']=mapped(g['default-selected'])
        groups.append(g)
    qualified_members=pool_members(cache)
    for region in REGIONS:
        # Explicit REJECT is the initial and reboot selection. Persistence off.
        members=[mapped(n) for n in qualified_members[region]]
        groups.extend([{'name':FAST[region],'type':'url-test','proxies':members or ['REJECT'],
                        'url':'https://chatgpt.com/robots.txt' if region=='SG' else 'https://www.gstatic.com/generate_204',
                        'expected-status':200 if region=='SG' else 204,'interval':60,'tolerance':20,'lazy':False},
                       {'name':GATES[region],'type':'select','proxies':['REJECT',FAST[region]]}])
    listeners=[{'name':'paoluz-'+r.lower(),'type':'socks','listen':'127.0.0.1','port':pools[r]['server_port'],'udp':False,'proxy':GATES[r]} for r in REGIONS]
    for index,port in enumerate(probe_ports):
        tag='PAOLUZ_QUALIFICATION_PROBE'+('_'+str(index) if len(probe_ports)>1 else '')
        groups.append({'name':tag,'type':'select','proxies':['REJECT']+[mapped(p['name']) for p in cache['proxies']]})
        listeners.append({'name':'qualification-only-'+str(index),'type':'socks','listen':'127.0.0.1','port':port,'udp':False,'proxy':tag})
    return {'allow-lan':False,'bind-address':'127.0.0.1','mode':'rule','log-level':'warning','ipv6':False,
       'external-controller':'127.0.0.1:'+str(api_port),'secret':api_secret,
       'profile':{'store-selected':False,'store-fake-ip':False},'geodata-loader':'memconservative','geo-auto-update':False,
       'listeners':listeners,'proxies':proxies,'proxy-groups':groups,'rules':['MATCH,REJECT']}
