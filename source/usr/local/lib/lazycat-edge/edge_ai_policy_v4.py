"""Finite-scope SG executor. Four real entrances, exact canonical test users.

Pure projection only. Mutable scope is passed explicitly and bound by the
generation manifest; validators never consult a mutable global policy file.
"""
import copy,ipaddress
import edge_ai_policy as v1
import edge_ai_policy_v2 as v2
import edge_ai_policy_v3 as v3
import routing_contract as c

POLICY_ID='lazycat-edge-ai-preferred-20261109-v4'
INBOUND_TAGS,PEER_TAGS=v3.INBOUND_TAGS,v3.PEER_TAGS
ASSET_ROLES,ASSET_TAGS=v3.ASSET_ROLES,v3.ASSET_TAGS
FALLBACK_TAG=v3.FALLBACK_TAG
SG_FALLBACK=c.POOL_TAGS['SG']
MODES=tuple(mode for mode in v3.MODES if not(mode[4]=='1' and mode[8]=='1' and mode[10]=='u'))
EMPTY_MODE=v3.EMPTY_MODE
need,AIPolicyError=v1.need,v1.AIPolicyError

def selected_outbound(mode,inbound):
    need(mode in MODES and inbound in INBOUND_TAGS,'unknown_ai_health_mode')
    U='uzuma-starhub' if mode[4]=='1' else None
    S='uzuma-singtel' if mode[6]=='1' else None
    L='lazycat-starhub' if mode[8]=='1' else None
    if inbound==INBOUND_TAGS[1]:return S or L or U or SG_FALLBACK
    if inbound==INBOUND_TAGS[3]:return U or L or S or SG_FALLBACK
    return L or U or S or SG_FALLBACK

def _dns():
    result=v2._dns();tag='edge-ai-dns-paoluz-sg'
    result['servers'].append({'type':'https','tag':tag,'server':'8.8.8.8','server_port':443,'path':'/dns-query',
        'tls':{'enabled':True,'server_name':'dns.google'},'detour':SG_FALLBACK})
    final=result['rules'].pop()
    result['rules'] += [dict(final,action='evaluate'),
        {'match_response':True,'response_rcode':'NOERROR','action':'respond'},
        {'match_response':True,'response_rcode':'NXDOMAIN','action':'respond'},
        {'action':'route','server':tag,'timeout':'1500ms'}]
    result['final']=tag
    return result

def _scopes(contract):
    return list(dict.fromkeys(host for name in sorted(contract['vps_domains']) for host in contract['vps_domains'][name]))

def _rules(contract,front):
    rows=[];users=contract['test_users'];alltests=[h for row in contract['ip_tests'] for h in row['domains']]
    def add(match,action='reject',**extra):
        match=copy.deepcopy(match)
        if match.get('type')=='logical':
            logical={k:match.pop(k) for k in ('type','mode','rules','invert') if k in match}
            rows.append({'type':'logical','mode':'and','rules':[{'inbound':list(INBOUND_TAGS),**match},logical],
                'action':action,**extra})
        else:rows.append({'inbound':list(INBOUND_TAGS),**match,'action':action,**extra})
    add({'type':'logical','mode':'or','rules':[{'clash_mode':m} for m in MODES],'invert':True})
    add({'network':['udp']});add({'network':['tcp']},'sniff',sniffer=['tls','http','bittorrent'],timeout='1s')
    add({'protocol':['bittorrent']});add({'ip_is_private':True});add({'ip_cidr':list(v1.RESERVED)})
    for endpoint in contract['protected_endpoints']:
        ip=ipaddress.ip_address(endpoint['server'])
        add({'ip_cidr':[str(ip)+'/'+str(ip.max_prefixlen)],'port':[endpoint['server_port']]})
    hosts=list(dict.fromkeys((*v1.EXACT_AI_HOSTS,*_scopes(contract),*alltests)))
    for host in hosts:add({'domain':[host]},'route-options',override_address=host)
    # Test users may explicitly address legal public literals. Normal users
    # retain the original no-literal-IP business boundary.
    literal={'ip_cidr':['0.0.0.0/0','::/0']}
    if users:add({'type':'logical','mode':'and','rules':[literal,{'auth_user':users,'invert':True}]})
    else:add(literal)
    if alltests:
        for test in contract['ip_tests']:
            if test['front']!=front:
                if users:add({'type':'logical','mode':'and','rules':[{'domain_suffix':test['domains']},
                    {'auth_user':users,'invert':True}]})
                else:add({'domain_suffix':test['domains']})
    # Revision V4 treats Google and sensitive AI as the same SG business
    # category. No pre-DNS Taiwan/HKT bridge may bypass the global six-owned
    # qualification gate. V1/V2/V3 retain their original bridge behavior.
    add({},'resolve',strategy='ipv4_only',timeout='6500ms')
    add({'ip_is_private':True});add({'ip_cidr':list(v1.RESERVED)})
    for endpoint in contract['protected_endpoints']:
        ip=ipaddress.ip_address(endpoint['server'])
        add({'ip_cidr':[str(ip)+'/'+str(ip.max_prefixlen)],'port':[endpoint['server_port']]})
    if users:
        targets=('direct','uzuma-singtel','lazycat-starhub','uzuma-starhub') if front=='lazycat' else \
                ('lazycat-starhub','uzuma-singtel','lazycat-starhub','uzuma-starhub')
        for tag,target in zip(INBOUND_TAGS,targets):add({'inbound':[tag],'auth_user':users},'route',outbound=target)
    for test in contract['ip_tests']:
        if test['front']!=front:continue
        allowed=(('direct',)+PEER_TAGS) if front=='lazycat' else PEER_TAGS
        if test['outbound'] not in allowed or not c.available(contract,test['outbound']):add({'domain_suffix':test['domains']});continue
        add({'domain_suffix':test['domains']},'route',outbound=test['outbound'])
    scope=_scopes(contract)
    if scope:
        for mode in MODES:
            for tag in INBOUND_TAGS:
                target='direct' if front=='lazycat' and tag==INBOUND_TAGS[0] else selected_outbound(mode,tag)
                # LC has only an SG airport bridge, not the ALL VPS bridge.
                # Do not silently mislabel SG as ALL; caller can fall to DMIT.
                if target==SG_FALLBACK:add({'inbound':[tag],'clash_mode':mode,'domain_suffix':scope})
                else:add({'inbound':[tag],'clash_mode':mode,'domain_suffix':scope},'route',outbound=target)
    add({'domain_suffix':list(v1.YOUTUBE_SUFFIXES)});add({'rule_set':[ASSET_TAGS['youtube']]})
    add({'type':'logical','mode':'or','rules':[{'rule_set':[ASSET_TAGS['ai'],ASSET_TAGS['google']]},
        {'domain_suffix':list(v1.SENSITIVE_SUFFIXES+v1.AI_TEST_SUFFIXES)}],'invert':True})
    for mode in MODES:
        for tag in INBOUND_TAGS:add({'inbound':[tag],'clash_mode':mode},'route',outbound=selected_outbound(mode,tag))
    rows.append({'action':'reject'})
    return rows

def _route(definitions,contract,front):
    return {'rules':_rules(contract,front),'rule_set':definitions,'final':PEER_TAGS[1],
        'default_domain_resolver':{'server':_dns()['final'],'strategy':'ipv4_only'}}

def project_ai_runtime(runtime,*,asset_roles,asset_bytes,google_fallback_endpoint,routing_revision,
        execution_front,health_mode=EMPTY_MODE,extra_transport=None,manual_tls=None):
    contract=c.validate(routing_revision);need(execution_front in ('dmit','lazycat'),'execution_front_required')
    need(health_mode in MODES,'unknown_ai_health_mode')
    config,meta=v3.project_v3(runtime,asset_roles=asset_roles,asset_bytes=asset_bytes,
        google_fallback_endpoint=google_fallback_endpoint,health_mode=health_mode,
        extra_transport=extra_transport,manual_tls=manual_tls)
    config['outbounds']=[row for row in config['outbounds'] if row['tag']!=FALLBACK_TAG]
    meta.pop('google_fallback',None)
    config['outbounds'] += c.pool_outbounds(contract,('SG',))+[{'type':'direct','tag':'direct'}]
    definitions=v1._definitions(config)
    config['route'],config['dns']=_route(definitions,contract,execution_front),_dns()
    validate_ai_runtime(config,routing_revision=contract,execution_front=execution_front)
    meta.update(policy_id=POLICY_ID,dns_transport_count=4,dns_independent_egress_count=4,initial_clash_mode=health_mode,
        routing_revision=contract,execution_front=execution_front,
        health_mode_semantics={'z':'uzuma_starhub_healthy','s':'singtel_healthy','l':'lazycat_starhub_healthy',
            'p':'l_if_lazycat_healthy_else_u_if_uzuma_healthy_else_n'},
        non_ai_policy='reject_except_exact_vps_test_scopes_and_canonical_test_identity',
        airport_last_resort={'region':'SG','tag':SG_FALLBACK,'only_when_all_owned_sg_fail':True},
        vps_all_failed='reject_no_ALL_bridge_in_lite_executor',
        required_local_endpoints=[dict(contract['pools']['SG'],tag=SG_FALLBACK)],
        legacy_google_bridge='excluded_from_v4_projection',google_all_owned_failed='global_gated_paoluz_SG_else_reject')
    return config,meta

project_v4=project_ai_runtime

def validate_ai_runtime(document,*,routing_revision,execution_front):
    contract=c.validate(routing_revision);need(execution_front in ('dmit','lazycat'),'execution_front_required')
    need(isinstance(document,dict),'ai_runtime_required')
    incoming=document.get('inbounds')
    need(isinstance(incoming,list) and len(incoming)==4 and [r.get('tag') for r in incoming]==list(INBOUND_TAGS),'ai_inbound_inventory_changed')
    accounts=v1._cohort(incoming)
    tls=[v3._manual_tls({k:r.get('tls',{}).get(k) for k in ('certificate_path','key_path')}) for r in incoming[2:]]
    need(tls[0]==tls[1],'manual_tls_pair_disagreement')
    definitions=v1._definitions(document)
    need([r['tag'] for r in definitions]==[ASSET_TAGS[k] for k in ASSET_ROLES],'ai_asset_inventory_changed')
    need(document.get('route')==_route(definitions,contract,execution_front),'ai_route_policy_changed')
    need(document.get('dns')==_dns(),'ai_dns_policy_changed')
    need(document.get('experimental',{}).get('clash_api',{}).get('default_mode') in MODES,'unknown_ai_health_mode')
    outbound=document.get('outbounds');tags=list(PEER_TAGS)+[SG_FALLBACK,'direct']
    need(isinstance(outbound,list) and [r.get('tag') for r in outbound]==tags,'ai_outbound_inventory_changed')
    for peer in outbound[:3]:
        need(peer.get('type')=='shadowsocks' and not peer.get('detour'),'unreviewed_sg_transport')
        try:ip=ipaddress.ip_address(peer.get('server'))
        except (TypeError,ValueError):raise AIPolicyError('invalid_sg_endpoint') from None
        need(not ip.is_unspecified and not ip.is_multicast and type(peer.get('server_port')) is int and
             0<peer['server_port']<65536,'invalid_sg_endpoint')
    need(outbound[3]==c.pool_outbounds(contract,('SG',))[0],'unreviewed_airport_fallback')
    direct=outbound[4]
    need(direct.get('type')=='direct' and set(direct)<={'type','tag','inet4_bind_address','inet6_bind_address'},'unreviewed_direct_semantics')
    for key,version in (('inet4_bind_address',4),('inet6_bind_address',6)):
        if key in direct:
            try:ip=ipaddress.ip_address(direct[key])
            except (TypeError,ValueError):raise AIPolicyError('invalid_direct_bind') from None
            need(ip.version==version and not ip.is_unspecified and not ip.is_multicast,'invalid_direct_bind')
    return {'policy_id':POLICY_ID,'cohort_inbound_count':4,'accounts':accounts,
        'asset_tags':[r['tag'] for r in definitions],'ordinary_traffic':'finite_scope_only','dns_transport_count':4,
        'routing_revision':contract,'execution_front':execution_front}

validate_ai_runtime_v4=validate_ai_runtime
