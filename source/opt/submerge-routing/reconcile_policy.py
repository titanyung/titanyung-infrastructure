"""Deterministic retirement/catch-up input recompiler; does not publish itself."""
import copy
from policy_inputs import runtime,contract_module as c,policy,need

def availability(plan):
    need(runtime.revised(plan),'revision_required_for_retirement_reconcile')
    value=plan['server_policy']['routing_revision']
    return tuple((tag,c.available(value,tag)) for tag in c.PHYSICAL)

def reconcile_plan(plan,as_of):
    runtime.validate_network_plan(plan)
    need(runtime.revised(plan),'revision_required_for_retirement_reconcile')
    result=copy.deepcopy(plan);contract=result['server_policy']['routing_revision']
    need(type(as_of) is int and as_of>=contract['as_of'],'as_of_must_not_move_backwards')
    contract['as_of']=as_of;c.validate(contract)
    result['transports']={key:row for key,row in result['transports'].items()
                          if c.available(contract,runtime.TRANSPORT_MAP[key])}
    p=result['server_policy']
    p['front_port_mapping']={tag:port for tag,port in p['front_port_mapping'].items()
                             if tag in policy.expected_inbound_tags(contract)}
    if not c.available(contract,'uzuma-hkt'):
        p.pop('local_transport_bridges',None)
    p['service_ip_routes']=[row for row in p.get('service_ip_routes',[])
                            if c.available(contract,policy.OUTBOUNDS.get(row['target'],row['target']))]
    runtime.validate_network_plan(result)
    return result
