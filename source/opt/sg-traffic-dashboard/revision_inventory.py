"""Authoritative new inventory and explicit-retirement overlay, all pure.

Billing recurrence never cancels an explicit retirement. Historical cards,
rows and source epochs are retained exactly; unobserved counters stay unknown.
"""
import copy,json
from datetime import datetime,timedelta,timezone
from routing_contract import UZUMA_HKT_RETIRE_AT
TZ=timezone(timedelta(hours=8),'Asia/Singapore')
REVISION='routing-revision-20261109-v1'
HOST_IDS={
 'dmit':'DMIT','bytevirt-hk':'ByteVirt-HK ISP','bytevirt-tw':'ByteVirt-TW',
 'bytevirt-tw-annual-pending':'ByteVirt-TW-Annual-Pending',
 'lazycat-starhub':'Lazycat-SG','lazycat-hkt':'Lazycat-HKT',
 'uzuma-singtel':'Uzuma-SG-Singtel1','zoro-sptel':'ZORO-SG',
 'lazycat-sg':'Lazycat-SG-Front','uzuma-starhub':'Uzuma-SG-StarHub','uzuma-hkt':'Uzuma-HKT'}

def need(condition,code):
    if not condition:raise ValueError(code)

def build_inventory(requirements,contract,*,activated_at):
    need(type(activated_at) is int and activated_at>0,'explicit_inventory_activation_required')
    need(contract.get('id')==REVISION,'shared_routing_contract_required')
    rows=requirements['servers'];need({x['id'] for x in rows}==set(HOST_IDS),'exact_server_inventory_required')
    result={}
    for original in rows:
        row=copy.deepcopy(original);service=row['id'];host=HOST_IDS[service]
        row['host']=host;row['display_name']=row.pop('label');row['amount']=str(row.pop('price'))
        row['monitoring_state']='pending' if row.get('state')=='pending_not_connected' else 'active'
        row['activation_at']=activated_at
        row['retire_at']=None
        if service=='zoro-sptel':row['retire_at']=activated_at
        if service=='bytevirt-tw':row['retire_at']=contract['taiwan_retire_at']
        if service=='lazycat-hkt':row['retire_at']=contract['lazycat_hkt_retire_at']
        if service=='uzuma-hkt':row['retire_at']=UZUMA_HKT_RETIRE_AT
        if row['retire_at'] is not None:need(type(row['retire_at']) is int and row['retire_at']>0,'explicit_retirement_epoch_required')
        result[host]=row
    return {'schema':1,'revision':REVISION,'activated_at':activated_at,'servers':result,
            'historical_sources_preserved':True,'cutoff_semantics':'sample ts strictly before retire_at'}

def active_hosts(inventory,*,now):
    validate(inventory)
    # JSON object key order is not an inventory declaration. Private canonical
    # writers sort those keys; derive the reviewed presentation/validation order
    # from the fixed host catalog so write/read round trips retain the same list.
    rows=inventory['servers']
    return [host for host in HOST_IDS.values() if rows[host]['monitoring_state']=='active' and
            (rows[host]['retire_at'] is None or now<rows[host]['retire_at'])]

def validate(inventory):
    need(isinstance(inventory,dict) and inventory.get('schema')==1 and inventory.get('revision')==REVISION,'inventory_schema')
    need(set(inventory.get('servers',{}))==set(HOST_IDS.values()),'inventory_host_names')
    need(type(inventory.get('activated_at')) is int and inventory['activated_at']>0,'inventory_activation')
    for host,row in inventory['servers'].items():
        need(row['host']==host and row['id'] in HOST_IDS and HOST_IDS[row['id']]==host,'inventory_host_binding')
        need(row.get('monitoring_state') in ('active','pending'),'inventory_monitoring_state')
        need(row.get('retire_at') is None or type(row['retire_at']) is int and row['retire_at']>0,'inventory_retirement')
    need(inventory['servers']['ZORO-SG']['retire_at']==inventory['activated_at'],'zoro_explicit_retirement_required')
    return inventory

def merge_retirement_policy(policy,manifest,inventory):
    """Apply AFTER old ACTIVE_HOSTS overrides, or replace that old override.

    Existing earlier retirements remain earlier, except still-active services
    without any explicit new retirement retain their approved renewal state.
    Explicit new TW/HKT retirements cannot be removed by ACTIVE_HOSTS.
    """
    if policy is None:return None
    validate(inventory);result=copy.deepcopy(policy)
    for host,row in inventory['servers'].items():
        service=result.canonical(host)
        if row['monitoring_state']=='pending':continue
        if row['retire_at'] is not None:
            # The shared native/client contract is the approved exact cutoff.
            result.cutoffs[service]=row['retire_at']
        else:
            result.cutoffs.pop(service,None)
    for host in set(manifest.get('retired_host_cards',{}))|set(manifest.get('archived_peers',[])):
        # Never let a legacy archived overlay reopen or predate a current
        # explicitly approved monitoring epoch for an active inventory host.
        if host in inventory['servers']:continue
        cutoff=manifest.get('network_activated_at',manifest.get('cutoff'))
        need(type(cutoff) is int and cutoff>0,'legacy_archive_cutoff_required')
        service=result.canonical(host);result.cutoffs[service]=min(result.cutoffs.get(service,cutoff),cutoff)
    return result

def sample_allowed(inventory,host,observed_at,*,now):
    if host not in active_hosts(inventory,now=now):return False
    row=inventory['servers'][host]
    return type(observed_at) is int and (row['retire_at'] is None or observed_at<row['retire_at'])

def sampling_commands(previous_commands,new_commands,inventory,*,now):
    """Whitelist callers' audited argv; no shell construction or guessed keys."""
    merged=dict(previous_commands);merged.update(new_commands)
    active=active_hosts(inventory,now=now);result={};missing=[]
    for host in active:
        command=merged.get(host)
        if command is None:missing.append(host);continue
        need(isinstance(command,list) and command and all(isinstance(v,str) and v for v in command),'sample_argv_required')
        result[host]=copy.deepcopy(command)
    return {'commands':result,'missing':missing,'ready':not missing}

def migrate_manifest(previous,payload,inventory,*,now,sample_commands):
    """Fresh pre-cutoff measurement required to freeze a newly retired host."""
    validate(inventory);need(isinstance(previous,dict) and previous.get('schema')==1,'previous_manifest_required')
    active=active_hosts(inventory,now=now);result=copy.deepcopy(previous)
    old_active=set(previous.get('active_hosts',[]));retired=result.setdefault('retired_host_cards',{})
    users=result.setdefault('retired_user_usage',{});epochs=result.setdefault('archive_epochs',{})
    cards=((payload or {}).get('whole') or {}).get('servers',{})
    for host in sorted(old_active-set(active)):
        if host in retired:continue
        card=cards.get(host);need(isinstance(card,dict),'real_pre_retirement_card_required_'+host)
        frozen=copy.deepcopy(card);end=inventory['servers'].get(host,{}).get('retire_at') or now
        measured=frozen.get('last_measured_at') or frozen.get('sampled_at')
        need(type(measured) is int and 0<measured<end,'pre_cutoff_measurement_required_'+host)
        need(all(type(frozen.get(k)) is int and frozen[k]>=0 for k in ('in','out')),'real_nic_counters_required_'+host)
        frozen.update(archived=True,expired=True,expires_at=end,freeze_at=end-1,last_measured_at=measured,
                      archive_reason='explicit routing revision retirement')
        retired[host]=frozen
        users[host]=[copy.deepcopy(r) for r in (payload or {}).get('server_user_usage',[]) if r.get('server')==host]
    # Reactivation is a new real epoch; never rewrite a prior frozen object.
    for host in active:
        if host in retired:
            epochs.setdefault(host,[]).append({'card':retired.pop(host),'users':users.pop(host,[]),'closed_at':now})
        if host not in old_active:result.setdefault('active_since',{})[host]=now
    allowed=sampling_commands({},sample_commands,inventory,now=now)
    result.update(routing_revision=REVISION,revision_inventory=copy.deepcopy(inventory),active_hosts=active,
                  sample_commands=allowed['commands'],sampling_pending=allowed['missing'],inventory_epoch=now)
    result['archived_peers']=sorted((set(result.get('archived_peers',[]))|set(retired))-set(active))
    return result

def attach_inventory(payload,inventory,*,now):
    """Display pending collection as unknown; never manufacture zero samples."""
    validate(inventory);out=copy.deepcopy(payload);servers=out.setdefault('whole',{}).setdefault('servers',{})
    active=set(active_hosts(inventory,now=now))
    for host,row in inventory['servers'].items():
        if host not in active:continue
        card=servers.setdefault(host,{'in':None,'out':None,'sampled_at':None,'sampling_state':'not_sampled'})
        card['inventory']=copy.deepcopy(row);card['display_name']=row['display_name']
    out.setdefault('topology',{}).update(routing_revision=REVISION,active_hosts=list(active_hosts(inventory,now=now)),
        pending_hosts=[h for h,r in inventory['servers'].items() if r['monitoring_state']=='pending'],
        retired_hosts=[h for h,r in inventory['servers'].items() if r['retire_at'] is not None and now>=r['retire_at']])
    return out

def metadata_document(inventory,sites):
    validate(inventory)
    return {'schema':1,'revision':REVISION,'servers':copy.deepcopy(inventory['servers']),
            'ip_test_sites':copy.deepcopy(sites),'historical_sources_preserved':True}
