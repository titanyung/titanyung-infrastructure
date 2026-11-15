"""Pure actual-source plan projection; no guessed credentials or listeners."""
import copy, hashlib, json, sys
from pathlib import Path

MODULES=Path(__file__).resolve().parents[2]/'server-candidate'
if MODULES.is_dir():sys.path.insert(0,str(MODULES))
import network_runtime as runtime
import routing_contract as contract_module
import server_route_policy as policy
from transport_bridges import HKT3,validate_bridges

class InputError(ValueError):pass

def need(value,code):
    if not value:raise InputError(code)

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()

def sha(raw):return hashlib.sha256(raw).hexdigest()

def users(runtime_document):
    import edge_ai_policy
    info=edge_ai_policy._cohort(runtime_document['inbounds'])
    result=sorted(copy.deepcopy(runtime_document['inbounds'][0]['users']),key=lambda r:r['name'])
    need(info['cohort_sha256']==sha(canonical(result)),'canonical_cohort_hash_disagreement')
    return result

def peer_core(row):
    return {k:copy.deepcopy(v) for k,v in row.items()
            if k not in ('tag','inet4_bind_address','inet6_bind_address','bind_interface','connect_timeout')}

def actual_uzuma_starhub(side_runtime,registry):
    side=[r for r in side_runtime.get('outbounds',[]) if r.get('tag')=='uzuma-starhub']
    need(len(side)==1,'actual_v3_uzuma_starhub_source_required')
    sources=[]
    for edge in registry.get('edges',[]):
        if edge.get('edge_id') not in ('dmit-ai-20261108','lazycat-ai-20261108'):continue
        row=edge.get('extra_transports',{}).get('uzuma-starhub')
        need(isinstance(row,dict) and row.get('tag')=='uzuma-starhub','both_v3_registry_transports_required')
        need(peer_core(row)==peer_core(side[0]),'registry_and_actual_side_uzuma_transport_disagree')
        sources.append(row)
    need(len(sources)==2 and peer_core(sources[0])==peer_core(sources[1]),'actual_two_front_uzuma_transport_required')
    # Registry transport has the original endpoint and credentials, before the
    # executing host's reviewed source bind was projected into the V3 runtime.
    result=copy.deepcopy(sources[0]);result.pop('tag')
    return result

def build_plan(old_plan,main_runtime,side_runtime,registry,contract,hkt_transport,*,native_hkt_ports):
    contract=contract_module.validate(contract)
    need(not runtime.revised(old_plan),'explicit_legacy_source_plan_required')
    runtime.legacy.validate_network_plan(old_plan)
    need(isinstance(native_hkt_ports,dict) and set(native_hkt_ports)=={'dmit-uzuma-hkt','mobile-dmit-uzuma-hkt'},
         'explicit_native_hkt_mapping_required')
    need(native_hkt_ports=={'dmit-uzuma-hkt':29520,'mobile-dmit-uzuma-hkt':29620},'reviewed_native_hkt_ports_required')
    occupied={r['listen_port'] for r in main_runtime['inbounds']}
    need(not (set(native_hkt_ports.values())&occupied),'new_hkt_native_ports_collide_with_source')
    hop=copy.deepcopy(hkt_transport)
    if hop.get('tag')=='uzuma-hkt':hop.pop('tag')
    need(hop.get('server')=='127.0.0.1' and hop.get('server_port')==19421,
         'actual_hkt3_reverse_transport_required')
    transports=copy.deepcopy(old_plan['transports'])
    transports['uzuma-starhub']=actual_uzuma_starhub(side_runtime,registry)
    transports['uzuma-hkt']=hop
    transports={k:v for k,v in transports.items() if contract_module.available(contract,runtime.TRANSPORT_MAP[k])}
    original=old_plan['server_policy']
    service_routes=[copy.deepcopy(row) for row in original.get('service_ip_routes',[])
                    if contract_module.available(contract,policy.OUTBOUNDS.get(row['target'],row['target']))
                    and 'zoro' not in row['target'].lower()]
    p={'schema':1,'id':policy.NEW_POLICY_ID,'hk_transport':copy.deepcopy(original['hk_transport']),
       'rule_sets':copy.deepcopy(original['rule_sets']),'routing_revision':contract,
       'remote_domains':copy.deepcopy(contract['remote_domains']),'service_ip_routes':service_routes,
       'front_port_mapping':copy.deepcopy(native_hkt_ports),'local_transport_bridges':{'uzuma-hkt':copy.deepcopy(HKT3)}}
    result={'schema':1,'plan':runtime.NEW_PLAN_ID,'transports':transports,'server_policy':p}
    runtime.validate_network_plan(result)
    # No obsolete transport, DNS, selector or listener policy survives in the
    # new plan. Protected old management endpoints remain denial guards.
    need('zoro' not in json.dumps({k:v for k,v in p.items() if k!='routing_revision'}).lower(),
         'obsolete_zoro_policy_survived')
    return result

def build_native(source,plan,desired_users,*,rule_set_loader,health=None,ports=None,listen=None,clash_port=None,api_port=None):
    need(isinstance(desired_users,list),'explicit_desired_accounts_required')
    existing={r['tag']:r for r in source['inbounds']}
    # Preserve all existing source listener bindings, especially the private
    # direct staging inlet. Only the new HKT pair takes declared new bindings.
    bindings={tag:row['listen'] for tag,row in existing.items() if tag in runtime.expected_fronts(plan)}
    bindings.update(listen or {})
    output=runtime.build_network_config(source,plan,users=desired_users,listen=bindings,ports=ports,
        clash_port=clash_port,api_port=api_port,rule_set_loader=rule_set_loader,health=health)
    runtime.validate_loaded_server_policy(output,plan,rule_set_loader=rule_set_loader)
    if runtime.revised(plan):
        need(not any('zoro' in r['tag'].lower() for r in output['inbounds']+output['outbounds']),
             'obsolete_zoro_native_tag_survived')
    need(len(output['inbounds'])==len(runtime.expected_fronts(plan)),'new_native_inventory_mismatch')
    return output

def descriptor(plan,runtime_document,*,source_plan_raw,source_runtime_raw,desired_token):
    common=users(runtime_document)
    return {'schema':1,'revision':plan.get('server_policy',{}).get('id'),
        'generation':'policy-'+sha(canonical(plan)+canonical(runtime_document)+desired_token.encode())[:24],
        'source_plan_sha256':sha(source_plan_raw),'source_runtime_sha256':sha(source_runtime_raw),
        'desired_token_sha256':desired_token,'plan_sha256':sha(canonical(plan)),
        'runtime_sha256':sha(canonical(runtime_document)),'cohort_sha256':sha(canonical(common)),
        'user_count':len(common),'runtime_mode':'stopped_empty_cohort' if not common else 'enabled',
        'native_hkt_ports':[row['listen_port'] for row in runtime_document['inbounds']
                            if row['tag'] in ('dmit-uzuma-hkt','mobile-dmit-uzuma-hkt')],
        'new_public_ports_are_uninstalled_proposals':True,
        'bridge':copy.deepcopy(plan.get('server_policy',{}).get('local_transport_bridges',{})),
        'zoro_removed':not any('zoro' in row['tag'].lower() for row in runtime_document['inbounds']+runtime_document['outbounds']),
        'production_changed':False}
