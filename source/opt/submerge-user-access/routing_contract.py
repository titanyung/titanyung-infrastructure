"""Shared pure revision contract. No clocks, sockets or files are read here."""
import copy,ipaddress,re

REVISION='routing-revision-20261109-v1'
# Reviewed service expiry: 2026-12-10 00:00:00 Asia/Singapore.
# This is code-owned so the installed strict contract schema stays unchanged.
UZUMA_HKT_RETIRE_AT=1796832000
PEERS=('lazycat-starhub','uzuma-singtel','uzuma-starhub')
PHYSICAL=('direct','bytevirt-hk','bytevirt-taiwan','lazycat-starhub','lazycat-hkt','uzuma-singtel','uzuma-starhub','uzuma-hkt')
POOL_TAGS={'SG':'paoluz-sg-fallback','HK':'paoluz-hk-fallback','ALL':'paoluz-all-fallback'}
PROVIDERS=('dmit','bytevirt','lazycat','uzuma')

class ContractError(ValueError):pass
def need(value,code):
    if not value:raise ContractError(code)

def domains(values):
    need(isinstance(values,list) and len(values)<=200 and len(set(values))==len(values),'invalid_domain_inventory')
    for host in values:
        need(isinstance(host,str) and 0<len(host)<=253 and '.' in host and not host.endswith('.')
            and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',part) for part in host.split('.')),
            'normalized_domain_required')
        try:ipaddress.ip_address(host)
        except ValueError:continue
        raise ContractError('domain_must_not_be_ip')
    return list(values)

def endpoint(value):
    need(isinstance(value,dict) and set(value)=={'server','server_port'},'explicit_pool_endpoint_required')
    try:ip=ipaddress.ip_address(value['server'])
    except (TypeError,ValueError):raise ContractError('literal_pool_address_required') from None
    need(ip.is_loopback and type(value['server_port']) is int and 1024<=value['server_port']<=65535,'pool_must_be_loopback')
    return copy.deepcopy(value)

def validate(value):
    keys={'schema','id','as_of','taiwan_retire_at','lazycat_hkt_retire_at','pools','ip_tests','vps_domains',
          'mytvsuper_domains','hk_domains','remote_domains','test_users','protected_endpoints'}
    need(isinstance(value,dict) and set(value)==keys and value['schema']==1 and value['id']==REVISION,'revision_schema')
    for key in ('as_of','taiwan_retire_at','lazycat_hkt_retire_at'):
        need(type(value[key]) is int and value[key]>0,'explicit_revision_epoch_required')
    need(isinstance(value['pools'],dict) and set(value['pools'])==set(POOL_TAGS),'three_region_pools_required')
    for item in value['pools'].values():endpoint(item)
    need(len({(r['server'],r['server_port']) for r in value['pools'].values()})==3,'pool_endpoint_collision')
    need(isinstance(value['vps_domains'],dict) and set(value['vps_domains'])==set(PROVIDERS),'provider_scope_inventory')
    for items in value['vps_domains'].values():domains(items)
    for key in ('mytvsuper_domains','hk_domains','remote_domains'):domains(value[key])
    protected=value['protected_endpoints']
    need(isinstance(protected,list) and len(protected)<=128,'protected_endpoint_inventory')
    for row in protected:
        need(isinstance(row,dict) and set(row)=={'server','server_port'},'protected_endpoint_fields')
        try:ip=ipaddress.ip_address(row['server'])
        except (TypeError,ValueError):raise ContractError('protected_literal_address_required') from None
        need(ip.is_global and type(row['server_port']) is int and 0<row['server_port']<65536,'protected_endpoint_invalid')
    users=value['test_users'];need(isinstance(users,list) and len(users)<=4 and len(set(users))==len(users),'test_identity_inventory')
    need(all(isinstance(u,str) and re.fullmatch(r'[A-Za-z0-9._+=~-]{1,128}',u) for u in users),'canonical_test_identity_required')
    need(not users or protected,'test_identity_requires_recursion_guards')
    tests=value['ip_tests'];need(isinstance(tests,list) and len(tests)<=12,'test_site_inventory')
    seen=[];chains=set()
    for row in tests:
        need(isinstance(row,dict) and set(row)=={'domains','front','outbound'} and row['front'] in ('dmit','lazycat')
             and row['outbound'] in PHYSICAL,'test_site_fields')
        hosts=domains(row['domains']);need(hosts,'test_site_domains_required')
        chain=(row['front'],row['outbound']);need(chain not in chains,'one_site_per_chain');chains.add(chain)
        for host in hosts:
            need(not any(host==old or host.endswith('.'+old) or old.endswith('.'+host) for old in seen),'overlapping_test_sites')
            seen.append(host)
    return copy.deepcopy(value)

def available(contract,tag):
    if tag=='bytevirt-taiwan':return contract['as_of']<contract['taiwan_retire_at']
    if tag=='lazycat-hkt':return contract['as_of']<contract['lazycat_hkt_retire_at']
    if tag=='uzuma-hkt':return contract['as_of']<UZUMA_HKT_RETIRE_AT
    return tag in PHYSICAL

def pool_outbounds(contract,regions=('SG','HK','ALL')):
    return [dict(endpoint(contract['pools'][region]),tag=POOL_TAGS[region],type='socks',version='5',connect_timeout='5s') for region in regions]

def selected(ordered,health):
    """Last item is the explicit fail-closed airport endpoint, never DIRECT."""
    healthy=next((tag for tag in ordered[:-1] if health.get(tag) is True),None)
    if healthy:return healthy
    # Unknown is not proof of failure. Cold start attempts an owned route;
    # only explicit failed observations for every owner admit the airport.
    return next((tag for tag in ordered[:-1] if tag not in health),ordered[-1])
