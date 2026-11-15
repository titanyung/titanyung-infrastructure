"""Gate the new routing revision while preserving the installed legacy branch."""
import copy,json,os,stat
from pathlib import Path,PurePosixPath
import network_runtime_legacy as legacy
from network_runtime_legacy import *
import server_route_policy as policy
import routing_contract as c

NEW_PLAN_ID='network-plan-20261109'
TRANSPORT_MAP={'bytevirt-tw':'bytevirt-taiwan','lazycat-starhub':'lazycat-starhub','lazycat-hkt':'lazycat-hkt',
    'uzuma-singtel':'uzuma-singtel','uzuma-starhub':'uzuma-starhub','uzuma-hkt':'uzuma-hkt'}

def revised(plan):return isinstance(plan,dict) and plan.get('server_policy',{}).get('id')==policy.NEW_POLICY_ID

def validate_network_plan(document):
    if not revised(document):return legacy.validate_network_plan(document)
    c.need(set(document)=={'schema','plan','transports','server_policy'} and document['schema']==1
        and document['plan']==NEW_PLAN_ID,'revised_network_schema')
    p=document['server_policy'];required={'schema','id','hk_transport','rule_sets','routing_revision'}
    c.need(required<=set(p) and set(p)<=required|{'service_ip_routes','remote_domains','front_port_mapping','local_transport_bridges'},'revised_policy_fields')
    contract=c.validate(p['routing_revision'])
    expected={key for key,tag in TRANSPORT_MAP.items() if c.available(contract,tag)}
    c.need(isinstance(document['transports'],dict) and set(document['transports'])==expected,'revised_transport_inventory')
    # Reuse the exact installed protocol/credential validator without enabling
    # its old server policy or retaining any Zoro transport.
    bridges=p.get('local_transport_bridges')
    if bridges is not None:
        from transport_bridges import validate_bridges
        validate_bridges(bridges)
    for tag,hop in [*document['transports'].items(),('bytevirt-hk',p['hk_transport'])]:
        checked=copy.deepcopy(hop)
        from transport_bridges import transport_exception
        if transport_exception(tag,hop,bridges):
            # Only the exact instance/key-bound bridge above bypasses the
            # old public-host predicate; the private protocol/secret fields
            # still receive its unchanged validation.
            checked['server']='112.119.186.108'
        multiplex=checked.get('multiplex')
        # The actually deployed UZ StarHub SS2022 transport has padding.
        # This opt-in revision accepts that exact extra boolean without
        # weakening the installed legacy plan's validation contract.
        if isinstance(multiplex,dict) and 'padding' in multiplex:
            c.need(set(multiplex)=={'enabled','padding'} and type(multiplex['enabled']) is bool
                and type(multiplex['padding']) is bool and checked.get('type')=='shadowsocks'
                and str(checked.get('method','')).startswith('2022-'),'revised_ss2022_padding_fields')
            del multiplex['padding']
        legacy.validate_network_plan({'schema':1,'plan':legacy.PLAN_ID,
            'transports':{key:copy.deepcopy(checked) for key in legacy.TRANSPORT_KEYS}})
    c.need(p['schema']==1 and p['hk_transport'].get('type')=='shadowsocks'
        and p['hk_transport'].get('server')==legacy.BYTEVIRT_HK_SERVER and p['hk_transport'].get('server_port')==2448,
        'revised_hk_transport_identity')
    roles=p['rule_sets'];c.need(isinstance(roles,dict) and set(roles)==set(policy.ASSET_KEYS),'revised_asset_inventory')
    import re
    for role in roles.values():
        c.need(isinstance(role,dict) and set(role)=={'path','format','sha256','source'}
            and isinstance(role.get('path'),str) and PurePosixPath(role['path']).is_absolute()
            and '..' not in PurePosixPath(role['path']).parts and role.get('format') in ('source','binary')
            and isinstance(role.get('sha256'),str) and re.fullmatch('[a-f0-9]{64}',role['sha256'])
            and isinstance(role.get('source'),str) and 0<len(role['source'])<=2048
            and '\n' not in role['source'] and not re.search(r'(?:token|password|secret)=',role['source'],re.I),'revised_asset_fields')
    c.need(p.get('remote_domains',contract['remote_domains'])==contract['remote_domains'],'remote_scope_disagreement')
    ports=p.get('front_port_mapping',{})
    hkt_ports={'dmit-uzuma-hkt','mobile-dmit-uzuma-hkt'} if c.available(contract,'uzuma-hkt') else set()
    c.need(isinstance(ports,dict) and hkt_ports<=set(ports)
        and set(ports)<=policy.expected_inbound_tags(contract)
        and all(type(port) is int and 1024<=port<=65535 for port in ports.values()),'revised_front_port_mapping')
    return copy.deepcopy(document)

def front_routes(plan):
    if not revised(plan):return legacy.front_routes(plan)
    plan=validate_network_plan(plan);contract=plan['server_policy']['routing_revision']
    wanted=policy.expected_inbound_tags(contract)
    rows=[copy.deepcopy(row) for row in legacy.SERVER_POLICY_FRONTS if row['tag'] in wanted]
    if c.available(contract,'uzuma-hkt'):
        for tag,kind in (('dmit-uzuma-hkt','desktop'),('mobile-dmit-uzuma-hkt','mobile')):
            rows.append({'key':'uzuma-hkt','probe':kind.title()+'-Uzuma-HKT','country':'HK','expected_ip':None,
                'tag':tag,'port':plan['server_policy']['front_port_mapping'][tag],'listen':'0.0.0.0','outbound':'uzuma-hkt','client_kind':kind})
    mapping=plan['server_policy'].get('front_port_mapping',{})
    for row in rows:row['port']=mapping.get(row['tag'],row['port'])
    c.need(len({row['port'] for row in rows})==len(rows),'revised_front_port_collision')
    return tuple(rows)

def managed_routes(plan):return tuple(row for row in front_routes(plan) if row['tag'])
def expected_fronts(plan):return {row['tag']:row['port'] for row in managed_routes(plan)}
def session_fronts(plan):return frozenset(expected_fronts(plan))
def server_policy_enabled(plan):return legacy.server_policy_enabled(plan)

def revision_client_fronts(plan,client_kind='desktop'):
    if not revised(plan):return legacy.client_fronts(plan,client_kind)
    c.need(client_kind in ('mobile','desktop','router'),'network_client_kind_invalid')
    family='mobile' if client_kind=='mobile' else 'desktop'
    keys=dict(legacy._CLIENT_KEYS,**{'uzuma-hkt':'uzuma_hkt'})
    return {keys[row['key']]:{'server':legacy.DMIT_SERVER,'port':row['port'],'tag':row['tag']}
        for row in front_routes(plan) if row['client_kind']==family}

def client_fronts(plan,client_kind='desktop',*,include_revision=False):
    """Legacy base renderer needs six templates before the new final projector.

    These templates are not endpoint reachability proof. The revision projector
    must remove retired templates; actual native inventory is front_routes().
    """
    if not revised(plan):return legacy.client_fronts(plan,client_kind)
    if include_revision:return revision_client_fronts(plan,client_kind)
    validate_network_plan(plan);c.need(client_kind in ('mobile','desktop','router'),'network_client_kind_invalid')
    family='mobile' if client_kind=='mobile' else 'desktop'
    mapping=plan['server_policy'].get('front_port_mapping',{})
    return {legacy._CLIENT_KEYS[row['key']]:{'server':DMIT_SERVER,'port':mapping.get(row['tag'],row['port']),'tag':row['tag']}
        for row in legacy.SERVER_POLICY_FRONTS if row['client_kind']==family}

def load_network_plan(path=NETWORK_PLAN_PATH):
    path=Path(path)
    try:fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    except FileNotFoundError:return None
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        c.need(stat.S_ISREG(info.st_mode) and not info.st_mode&0o077 and getattr(info,'st_uid',0)==0,'network_plan_private_permissions_invalid')
        raw=stream.read(1024*1024+1)
    c.need(len(raw)<=1024*1024,'network_plan_document_too_large')
    return validate_network_plan(json.loads(raw,object_pairs_hook=legacy._pairs))

def build_network_config(source,plan,*,users=None,ports=None,listen=None,clash_port=None,api_port=None,rule_set_loader=None,health=None):
    if not revised(plan):return legacy.build_network_config(source,plan,users=users,ports=ports,listen=listen,
        clash_port=clash_port,api_port=api_port,rule_set_loader=rule_set_loader)
    plan=validate_network_plan(plan);p=plan['server_policy'];fronts=front_routes(plan)
    origin=[row for row in source.get('inbounds',[]) if row.get('tag')=='dmit-direct-stage' and row.get('type')=='anytls']
    c.need(len(origin)==1 and origin[0].get('tls',{}).get('enabled') is True,'authoritative_template_required')
    template=origin[0];cohort=copy.deepcopy(template['users'] if users is None else users)
    c.need(isinstance(cohort,list) and len(cohort)<=1000 and all(isinstance(row,dict) and set(row)=={'name','password'}
        and isinstance(row['name'],str) and row['name'] and isinstance(row['password'],str) and len(row['password'])>=24
        for row in cohort) and len({row['name'] for row in cohort})==len(cohort),'authoritative_user_inventory')
    ports,listen=ports or {},listen or {};tags={row['tag'] for row in fronts}
    c.need(set(ports)<=tags and set(listen)<=tags,'unreviewed_listener_override')
    output=copy.deepcopy(source);output['inbounds']=[]
    for row in fronts:
        inlet=copy.deepcopy(template);address=listen.get(row['tag'],row['listen'])
        c.need(address in ('127.0.0.1','0.0.0.0','::1','::'),'invalid_listener_address')
        inlet.update(tag=row['tag'],listen=address,listen_port=ports.get(row['tag'],row['port']),users=copy.deepcopy(cohort))
        c.need(type(inlet['listen_port']) is int and 0<inlet['listen_port']<65536,'invalid_listener_port')
        output['inbounds'].append(inlet)
    c.need(len({row['listen_port'] for row in output['inbounds']})==len(fronts),'listener_port_collision')
    original={row['tag']:row for row in source['outbounds']}
    c.need(original.get('direct',{}).get('type')=='direct','source_direct_required')
    output['outbounds']=[copy.deepcopy(original['direct'])]
    for key,hop in sorted(plan['transports'].items()):
        outbound=copy.deepcopy(hop);outbound['tag']=TRANSPORT_MAP[key];outbound.setdefault('connect_timeout','8s')
        output['outbounds'].append(outbound)
    hk=copy.deepcopy(p['hk_transport']);hk.update(tag='bytevirt-hk');hk.setdefault('connect_timeout','8s')
    output['outbounds'] += [hk,copy.deepcopy(original['violation-bt-quarantine'])]
    clash=output.get('experimental',{}).get('clash_api',{})
    c.need(len(clash.get('secret',''))>=24,'authenticated_private_api_required')
    if clash_port is not None:
        c.need(type(clash_port) is int and 0<clash_port<65536,'invalid_private_clash_port')
        clash['external_controller']='127.0.0.1:'+str(clash_port)
    services=[row for row in output.get('services',[]) if row.get('type')=='api']
    c.need(len(services)==1 and services[0].get('listen')=='127.0.0.1','single_private_api_required')
    if api_port is not None:
        c.need(type(api_port) is int and 0<api_port<65536,'invalid_private_native_port')
        services[0]['listen_port']=api_port
    loader=policy.load_rule_sets if rule_set_loader is None else rule_set_loader
    return policy.build_server_route_policy(output,rule_sets=loader(p['rule_sets']),routing_revision=p['routing_revision'],
        service_ip_routes=p.get('service_ip_routes',[]),health=health)

def validate_loaded_fronts(document,plan):
    if not revised(plan):return legacy.validate_loaded_fronts(document,plan)
    expected=expected_fronts(plan);incoming=document.get('inbounds',[])
    c.need(len(incoming)==len(expected) and {row.get('tag'):row.get('listen_port') for row in incoming}==expected,'loaded_front_inventory')
    import edge_ai_policy as ai
    ai._cohort(incoming)
    tls=[row.get('tls') for row in incoming]
    c.need(tls and all(value==tls[0] and value.get('enabled') is True for value in tls),'loaded_tls_cohort')
    return expected,{row['tag']:row for row in incoming}

def validate_loaded_server_policy(document,plan,*,rule_set_loader=None):
    if not revised(plan):return legacy.validate_loaded_server_policy(document,plan,rule_set_loader=rule_set_loader)
    plan=validate_network_plan(plan);result=validate_loaded_fronts(document,plan)
    p=plan['server_policy'];loader=policy.load_rule_sets if rule_set_loader is None else rule_set_loader
    policy.validate_server_runtime(document,routing_revision=p['routing_revision'],rule_sets=loader(p['rule_sets']),service_ip_routes=p.get('service_ip_routes',[]))
    expected={TRANSPORT_MAP[k]:dict(copy.deepcopy(v),tag=TRANSPORT_MAP[k]) for k,v in plan['transports'].items()}
    expected['bytevirt-hk']=dict(copy.deepcopy(p['hk_transport']),tag='bytevirt-hk')
    actual={r['tag']:r for r in document['outbounds']}
    for tag,wanted in expected.items():
        wanted.setdefault('connect_timeout','8s');c.need(actual.get(tag)==wanted,'loaded_private_transport_changed')
    return result

def candidate_probe_profile(identity,dmit_password,plan,*,node_factory,bytevirt_fingerprint,ports=None,dmit_server=DMIT_SERVER):
    if not revised(plan):return legacy.candidate_probe_profile(identity,dmit_password,plan,node_factory=node_factory,
        bytevirt_fingerprint=bytevirt_fingerprint,ports=ports,dmit_server=dmit_server)
    plan=validate_network_plan(plan);ports=ports or {};c.need(set(ports)<=set(expected_fronts(plan)),'probe_port_override_inventory')
    c.need(isinstance(dmit_password,str) and len(dmit_password)>=24,'probe_credential_required')
    nodes=[];sites={};contract=plan['server_policy']['routing_revision']
    by_target={row['outbound']:row['domains'] for row in contract['ip_tests'] if row['front']=='dmit'}
    for row in front_routes(plan):
        node=node_factory(row['probe'],'dmit',dmit_server,ports.get(row['tag'],row['port']),dmit_password)
        node['udp']=False;nodes.append(node)
        sites[row['probe']]=by_target.get(policy.FRONT_TARGETS[row['tag']],[])
    return {'mode':'rule','log-level':'silent','allow-lan':False,'bind-address':'127.0.0.1','ipv6':False,
        'dns':{'enable':False},'tun':{'enable':False},'profile':{'store-selected':False},'proxies':nodes,
        'proxy-groups':[{'name':'TOPOLOGY_QA_ROUTE','type':'select','proxies':[row['name'] for row in nodes]}],
        'rules':['MATCH,TOPOLOGY_QA_ROUTE'],'x-submerge-required-probe-domains':sites}

def probe_expectations(plan,*,subid=None):
    if not revised(plan):return legacy.probe_expectations(plan,subid=subid)
    country={'direct':'US','bytevirt-hk':'HK','bytevirt-taiwan':'TW','lazycat-starhub':'SG',
        'lazycat-hkt':'HK','uzuma-singtel':'SG','uzuma-starhub':'SG','uzuma-hkt':'HK'}
    return [(row['probe'],country[policy.FRONT_TARGETS[row['tag']]],DMIT_SERVER if policy.FRONT_TARGETS[row['tag']]=='direct' else None)
        for row in front_routes(plan)]

def validate_probe_trace(name,trace,plan,*,subid=None):
    if not revised(plan):return legacy.validate_probe_trace(name,trace,plan,subid=subid)
    import ipaddress
    wanted={name:(country,ip) for name,country,ip in probe_expectations(plan,subid=subid)}
    c.need(name in wanted,'probe_name_invalid');country,ip=wanted[name]
    address=ipaddress.ip_address(trace.get('ip'))
    c.need(address.version==4 and address.is_global and trace.get('country')==country and trace.get('tls_verified') is True
        and (ip is None or str(address)==ip),'probe_egress_mismatch')
    return {'route':name,'country':country,'ip':str(address),'tls_verified':True}

def independent_negative_pairs(subject_profile,control_profile,plan):
    if not revised(plan):return legacy.independent_negative_pairs(subject_profile,control_profile,plan)
    expected=[name for name,_,_ in probe_expectations(plan)];out=[];pairs=[]
    subject={r['name']:r for r in subject_profile['proxies']};control={r['name']:r for r in control_profile['proxies']}
    c.need(set(subject)==set(control)==set(expected),'negative_probe_inventory')
    for name in expected:
        names=[]
        for prefix,source in (('control',control),('subject',subject)):
            node=copy.deepcopy(source[name]);node['name']=prefix+'-'+name;node.pop('dialer-proxy',None)
            out.append(node);names.append(node['name'])
        pairs.append((name,*names))
    return out,pairs
