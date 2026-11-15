"""Pure four-entrance AI policy: auto, Singtel, Lazycat and Uzuma preference.

The same authoritative logical users/credentials appear on all four entrances.
The independent TLS SNI mux chooses an inlet; native policy enforces the real
egress preference and its healthy fallback. No credential aliases are created.
"""
from __future__ import annotations
import copy
import ipaddress
from pathlib import PurePosixPath
import edge_ai_policy as v1
import edge_ai_policy_v2 as v2

POLICY_ID='lazycat-edge-ai-starhub-manual-20261108-v3'
INBOUND_TAGS=('dmit-starhub','dmit-singtel','dmit-starhub-lazycat','dmit-starhub-uzuma')
PEER_TAGS=v2.PEER_TAGS
FALLBACK_TAG=v2.FALLBACK_TAG
ASSET_ROLES,ASSET_TAGS=v1.ASSET_ROLES,v1.ASSET_TAGS
DNS_TAGS=v2.DNS_TAGS
MODE_SEMANTICS={'z':'uzuma_starhub_healthy','s':'singtel_healthy','l':'lazycat_starhub_healthy',
                'p':'selected_auto_starhub_u_l_or_none'}
MODES=tuple('ai-z'+str(u)+'s'+str(s)+'l'+str(l)+'p'+p
    for u in (0,1) for s in (0,1) for l in (0,1)
    for p in (('l','u') if u and l else ('l',) if l else ('u',) if u else ('n',)))
EMPTY_MODE='ai-z0s0l0pn'
need,AIPolicyError=v1.need,v1.AIPolicyError


def selected_outbound(mode,inbound):
    need(mode in MODES and inbound in INBOUND_TAGS,'unknown_ai_health_mode')
    uzuma='uzuma-starhub' if mode[4]=='1' else None
    singtel='uzuma-singtel' if mode[6]=='1' else None
    lazycat='lazycat-starhub' if mode[8]=='1' else None
    auto={'u':uzuma,'l':lazycat,'n':None}[mode[10]]
    if inbound==INBOUND_TAGS[2]:return lazycat or uzuma or singtel
    if inbound==INBOUND_TAGS[3]:return uzuma or lazycat or singtel
    if inbound==INBOUND_TAGS[1]:return singtel or auto
    return auto or singtel


def _dns():return v2._dns()


def _rules():
    rules=[]
    def add(match,action='reject',**options):
        match=copy.deepcopy(match)
        if match.get('type')=='logical':
            logical={key:match.pop(key) for key in ('type','mode','rules','invert') if key in match}
            scope={'inbound':list(INBOUND_TAGS),**match}
            row={'type':'logical','mode':'and','rules':[scope,logical],'action':action,**options}
        else:row={'inbound':list(INBOUND_TAGS),**match,'action':action,**options}
        rules.append(row)
    add({'type':'logical','mode':'or','rules':[{'clash_mode':mode} for mode in MODES],'invert':True})
    add({'network':['udp']})
    add({'network':['tcp']},'sniff',sniffer=['tls','http','bittorrent'],timeout='1s')
    add({'protocol':['bittorrent']})
    add({'ip_is_private':True})
    add({'ip_cidr':list(v1.RESERVED)})
    add({'domain_suffix':list(v1.YOUTUBE_SUFFIXES)})
    add({'rule_set':[ASSET_TAGS['youtube']]})
    for host in v1.EXACT_AI_HOSTS:add({'domain':[host]},'route-options',override_address=host)
    add({'ip_cidr':['0.0.0.0/0','::/0']})
    add({'type':'logical','mode':'or','rules':[
        {'rule_set':[ASSET_TAGS['ai'],ASSET_TAGS['google']]},
        {'domain_suffix':list(v1.SENSITIVE_SUFFIXES+v1.AI_TEST_SUFFIXES)}],'invert':True})
    add({**v1._sensitive(),'clash_mode':EMPTY_MODE})
    add({'rule_set':[ASSET_TAGS['google']],'clash_mode':EMPTY_MODE},'route',outbound=FALLBACK_TAG)
    add({},'resolve',strategy='ipv4_only',timeout='5s')
    add({'ip_is_private':True})
    add({'ip_cidr':list(v1.RESERVED)})
    for mode in MODES:
        for inbound in INBOUND_TAGS:
            target=selected_outbound(mode,inbound)
            if target:add({'inbound':[inbound],'clash_mode':mode},'route',outbound=target)
    rules.append({'action':'reject'})
    return rules


def _route(definitions):
    return {'rules':_rules(),'rule_set':definitions,'final':PEER_TAGS[1],
        'default_domain_resolver':{'server':DNS_TAGS[2],'strategy':'ipv4_only'}}


def _manual_tls(template):
    need(isinstance(template,dict) and set(template)=={'certificate_path','key_path'},'explicit_manual_tls_template_required')
    for value in template.values():
        path=PurePosixPath(value) if isinstance(value,str) else None
        need(path is not None and path.is_absolute() and str(path)==value and '..' not in path.parts
            and '\\' not in value and not any(ord(char)<32 for char in value),'invalid_manual_tls_path')
    need(template['certificate_path']!=template['key_path'],'manual_tls_path_collision')
    return copy.deepcopy(template)


def project_ai_runtime(runtime,*,asset_roles,asset_bytes,google_fallback_endpoint,
        health_mode=EMPTY_MODE,extra_transport=None,manual_tls=None):
    need(isinstance(runtime,dict) and health_mode in MODES,'unknown_ai_health_mode')
    accounts=v1._cohort(runtime.get('inbounds'))
    definitions,proof=v1._verified_definitions(runtime,asset_roles,asset_bytes)
    incoming={row['tag']:row for row in runtime['inbounds']}
    need(set(INBOUND_TAGS[:2])<=set(incoming),'required_preference_inbound_missing')
    tls=_manual_tls(manual_tls)
    rows=runtime.get('outbounds')
    need(isinstance(rows,list) and all(isinstance(row,dict) for row in rows)
        and len({row.get('tag') for row in rows})==len(rows),'source_outbound_inventory_invalid')
    outbound={row['tag']:copy.deepcopy(row) for row in rows}
    if extra_transport is not None:
        need(isinstance(extra_transport,dict) and extra_transport.get('tag')==PEER_TAGS[2]
            and PEER_TAGS[2] not in outbound,'new_starhub_transport_conflict')
        outbound[PEER_TAGS[2]]=copy.deepcopy(extra_transport)
    need(set(PEER_TAGS)<=set(outbound),'required_sg_transport_missing')
    need(all(outbound[tag].get('type')=='shadowsocks' and not outbound[tag].get('detour')
        for tag in PEER_TAGS),'unreviewed_sg_transport')
    endpoint=v1._endpoint(google_fallback_endpoint)
    config={key:copy.deepcopy(runtime[key]) for key in ('log','experimental','services') if key in runtime}
    config['inbounds']=[copy.deepcopy(incoming[tag]) for tag in INBOUND_TAGS[:2]]
    for index,tag in enumerate(INBOUND_TAGS[2:]):
        clone=copy.deepcopy(incoming[INBOUND_TAGS[0]])
        clone.update(tag=tag,listen='127.0.0.1',listen_port=39519+index*2)
        clone.setdefault('tls',{}).update(tls)
        config['inbounds'].append(clone)
    config['outbounds']=[copy.deepcopy(outbound[tag]) for tag in PEER_TAGS]
    config['outbounds'].append(dict(endpoint,type='socks',tag=FALLBACK_TAG,version='5',connect_timeout='5s'))
    need(isinstance(config.get('experimental',{}).get('clash_api'),dict),'private_clash_api_required')
    config['experimental']['clash_api']['default_mode']=health_mode
    config['route'],config['dns']=_route(definitions),_dns()
    validate_ai_runtime(config)
    metadata={'schema':1,'policy_id':POLICY_ID,'accounts':accounts,
        'source_inbound_count':len(runtime['inbounds']),'cohort_inbound_count':4,
        'asset_roles':proof,'allowed_inbounds':list(INBOUND_TAGS),'sg_outbounds':list(PEER_TAGS),
        'dns_transport_count':3,'dns_independent_egress_count':3,'initial_clash_mode':health_mode,
        'non_ai_policy':'reject','health_mode_semantics':dict(MODE_SEMANTICS),'manual_tls':tls,
        'manual_preferences':{INBOUND_TAGS[2]:PEER_TAGS[0],INBOUND_TAGS[3]:PEER_TAGS[2]},
        'ip_only_policy':'reject_unless_exact_hostname_rewritten',
        'google_fallback':dict(endpoint,tag=FALLBACK_TAG,receiver_must_enforce_google_only=True)}
    return config,metadata


project_v3=project_ai_runtime


def validate_ai_runtime(document):
    need(isinstance(document,dict),'ai_runtime_required')
    incoming=document.get('inbounds')
    need(isinstance(incoming,list) and len(incoming)==4 and [row.get('tag') for row in incoming]==list(INBOUND_TAGS),
        'ai_inbound_inventory_changed')
    accounts=v1._cohort(incoming)
    manual=[_manual_tls({key:row.get('tls',{}).get(key) for key in ('certificate_path','key_path')}) for row in incoming[2:]]
    need(manual[0]==manual[1],'manual_tls_pair_disagreement')
    definitions=v1._definitions(document)
    need(len(document['route']['rule_set'])==3 and [row['tag'] for row in document['route']['rule_set']]
        ==[ASSET_TAGS[role] for role in ASSET_ROLES],'ai_asset_inventory_changed')
    need(document['route']==_route(definitions),'ai_route_policy_changed')
    need(document.get('dns')==_dns(),'ai_dns_policy_changed')
    need(document.get('experimental',{}).get('clash_api',{}).get('default_mode') in MODES,'unknown_ai_health_mode')
    outbounds=document.get('outbounds')
    need(isinstance(outbounds,list) and [row.get('tag') for row in outbounds]==list(PEER_TAGS)+[FALLBACK_TAG],
        'ai_outbound_inventory_changed')
    for peer in outbounds[:3]:
        need(peer.get('type')=='shadowsocks' and not peer.get('detour'),'unreviewed_sg_transport')
        try:address=ipaddress.ip_address(peer.get('server'))
        except (ValueError,TypeError):raise AIPolicyError('invalid_sg_endpoint') from None
        need(not address.is_unspecified and not address.is_multicast and type(peer.get('server_port')) is int
            and 0<peer['server_port']<65536,'invalid_sg_endpoint')
    fallback=outbounds[3]
    v1._endpoint({key:fallback.get(key) for key in ('server','server_port')})
    need(fallback.get('type')=='socks' and fallback.get('version')=='5' and not fallback.get('detour')
        and set(fallback)<={'type','tag','server','server_port','version','connect_timeout'},'unreviewed_google_fallback')
    return {'policy_id':POLICY_ID,'cohort_inbound_count':4,'accounts':accounts,
        'asset_tags':[row['tag'] for row in definitions],'ordinary_traffic':'reject',
        'health_mode_semantics':dict(MODE_SEMANTICS),'dns_transport_count':3,'dns_independent_egress_count':3}


validate_ai_runtime_v3=validate_ai_runtime
