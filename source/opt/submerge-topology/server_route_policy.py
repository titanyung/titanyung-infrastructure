"""Versioned DMIT policy. Old immutable policy remains an exact delegate."""
import copy,ipaddress
import server_route_policy_legacy as old
from server_route_policy_legacy import *
import routing_contract as c
from domain_destination_override import build_exact_domain_overrides,EXACT_SERVICE_DOMAINS

NEW_POLICY_ID='dmit-domain-routing-20261109-v2'
_require=old._require
SELECTOR_PREFIX='business-'
X_SUFFIXES=('x.com','twitter.com','twimg.com','t.co')
# Complete hosts documented by X; only these get IP-destination correction.
X_EXACT_DOMAINS=('x.com','www.x.com','twitter.com','www.twitter.com',
                 'api.x.com','api.twitter.com','t.co','pbs.twimg.com',
                 'video.twimg.com','abs.twimg.com')
FRONT_TARGETS={tag:OUTBOUNDS[key[7:] if key.startswith('mobile_') else key]
    for key,tag in INBOUNDS.items()}
FRONT_TARGETS.update({'dmit-uzuma-hkt':'uzuma-hkt','mobile-dmit-uzuma-hkt':'uzuma-hkt'})
# These exact published HTTPS applications share the audited web SNI branch. They
# share DMIT:443 with its SNI mux, not the node/control SNI destinations.
OWNED_WEB_DOMAINS=('bill.titanyung.top', 'docs.titanyung.top', 'git.titanyung.top', 'markdown.titanyung.top', 'mdeditor.titanyung.top', 'nav.titanyung.top', 'story.titanyung.top', 'task.titanyung.top', 'ledger.titanyung.top', 'nas.titanyung.top', 'ezbook.titanyung.top', 'memos.titanyung.top', 'www.titanyung.top', 'prototype.titanyung.top', 'adminprototype.titanyung.top', 'activity.titanyung.top', 'apidocs.titanyung.top')
OWNED_WEB_ADDRESSES=(DMIT_IP,'2605:52c0:2:6f85:be24:11ff:fea8:a90c')

def owned_website_exception(contract,incoming):
    addresses=[address for address in OWNED_WEB_ADDRESSES if
        any(row['server']==address and row['server_port']==443 for row in contract['protected_endpoints'])]
    users=sorted(row['name'] for row in incoming[0]['users']) if incoming else []
    if not addresses or not users:return []
    # Domain and destination IP are OR fields inside one default native rule.
    # Separate logical-AND children are essential to require BOTH identities.
    return [{'type':'logical','mode':'and','rules':[
        {'inbound':[row['tag'] for row in incoming],'auth_user':users,'network':['tcp'],'protocol':['tls'],'port':[443]},
        {'domain':list(OWNED_WEB_DOMAINS)},
        {'ip_cidr':[address+'/'+str(ipaddress.ip_address(address).max_prefixlen) for address in addresses]}],
        'action':'route','outbound':'direct'}]

def expected_inbound_tags(contract):
    return {tag for tag,target in FRONT_TARGETS.items() if c.available(contract,target)}

def selection_orders(contract):
    v=c.validate(contract);P=c.POOL_TAGS
    tw=['bytevirt-taiwan'] if c.available(v,'bytevirt-taiwan') else []
    hkt=['uzuma-hkt'] if c.available(v,'uzuma-hkt') else []
    return {
        'ai-desktop':['lazycat-starhub','uzuma-starhub','uzuma-singtel',P['SG']],
        'ai-mobile':['uzuma-singtel','lazycat-starhub','uzuma-starhub',P['SG']],
        'ai-lazycat':['lazycat-starhub','uzuma-starhub','uzuma-singtel',P['SG']],
        'ai-singtel':['uzuma-singtel','lazycat-starhub','uzuma-starhub',P['SG']],
        'ai-uzuma':['uzuma-starhub','lazycat-starhub','uzuma-singtel',P['SG']],
        'mytvsuper':['bytevirt-hk',P['HK']],
        'hk-other':['bytevirt-hk',P['HK']],
        'other':['bytevirt-hk',*hkt,*tw,P['ALL']],
        'china':[*tw,*hkt,'bytevirt-hk',P['HK']],
        'vps-bytevirt':[*tw,'bytevirt-hk',P['ALL']],
        'vps-lazycat':['lazycat-starhub',*(['lazycat-hkt'] if c.available(v,'lazycat-hkt') else []),P['ALL']],
        'vps-uzuma':['uzuma-singtel','lazycat-starhub','uzuma-starhub',P['ALL']]}

def desired_selections(contract,health,*,category_health=None):
    c.need(isinstance(health,dict) and all(type(x) is bool for x in health.values()),'qualified_health_required')
    overrides={} if category_health is None else category_health
    orders=selection_orders(contract)
    c.need(isinstance(overrides,dict) and set(overrides)<=set(orders)
        and all(isinstance(row,dict) and set(row)<=set(c.PHYSICAL)
            and all(type(value) is bool for value in row.values()) for row in overrides.values()),'category_health_fields')
    # A category-specific observation table is independent. Missing ordinary
    # VPS evidence cannot inherit an AI-ASN failure on a split-egress vendor.
    return {SELECTOR_PREFIX+name:c.selected(order,overrides.get(name,health)) for name,order in orders.items()}

def selector_outbounds(contract,health=None):
    selected=desired_selections(contract,{} if health is None else health)
    return [{'type':'selector','tag':SELECTOR_PREFIX+name,'outbounds':order,
        'default':selected[SELECTOR_PREFIX+name],'interrupt_exist_connections':False}
        for name,order in selection_orders(contract).items()]

def _dns(contract):
    cn=('bytevirt-taiwan' if c.available(contract,'bytevirt-taiwan') else
        'uzuma-hkt' if c.available(contract,'uzuma-hkt') else 'bytevirt-hk')
    specs=[('policy-dns-primary','1.1.1.1','cloudflare-dns.com',cn),
        ('policy-dns-singtel','8.8.4.4','dns.google','uzuma-singtel'),
        ('policy-dns-hk','8.8.8.8','dns.google','bytevirt-hk'),
        ('policy-dns-airport','1.0.0.1','cloudflare-dns.com',c.POOL_TAGS['ALL'])]
    servers=[{'type':'https','tag':tag,'server':ip,'server_port':443,'path':'/dns-query',
        'tls':{'enabled':True,'server_name':sni},'detour':peer} for tag,ip,sni,peer in specs]
    rules=[]
    for index,row in enumerate(servers[:-1]):
        rules += [{'action':'evaluate','server':row['tag'],'timeout':'1200ms' if index==0 else '1500ms'},
            {'match_response':True,'response_rcode':'NOERROR','action':'respond'},
            {'match_response':True,'response_rcode':'NXDOMAIN','action':'respond'}]
    rules.append({'action':'route','server':servers[-1]['tag'],'timeout':'1500ms'})
    return {'servers':servers,'rules':rules,'final':servers[-1]['tag'],'strategy':'ipv4_only'}

def _rules(contract,incoming,physical,service_ip_routes):
    tags=[row['tag'] for row in incoming];rules=[];tests=contract['ip_tests'];users=contract['test_users']
    websites=owned_website_exception(contract,incoming)
    def add(match,target=None,action='route',**extra):
        row={'inbound':tags,**copy.deepcopy(match),'action':action,**extra}
        if target is not None:row['outbound']=target
        rules.append(row)
    add({'network':['tcp']},action='sniff',sniffer=['tls','http','bittorrent'],timeout='1s')
    add({'protocol':['bittorrent']},'violation-bt-quarantine')
    add({'protocol':['bittorrent']},action='reject');add({'network':['udp']},action='reject')
    exact=list(dict.fromkeys((*EXACT_SERVICE_DOMAINS,*X_EXACT_DOMAINS,*(OWNED_WEB_DOMAINS if websites else ()),*contract['mytvsuper_domains'],*contract['hk_domains'],
        *(h for row in tests for h in row['domains']),*(h for name in sorted(contract['vps_domains']) for h in contract['vps_domains'][name]))))
    rules.extend(build_exact_domain_overrides(inbounds=tags,domains=exact))
    # Resolution always precedes the private/management guards and test-user
    # forwarding. Domain aliases cannot tunnel into the management plane.
    add({},action='resolve',strategy='ipv4_only',timeout='6500ms')
    add({'ip_is_private':True},action='reject')
    add({'ip_cidr':['0.0.0.0/8','127.0.0.0/8','169.254.0.0/16','224.0.0.0/4','::/128','::1/128','fe80::/10','ff00::/8']},action='reject')
    rules.extend(websites)
    for endpoint in contract['protected_endpoints']:
        ip=ipaddress.ip_address(endpoint['server'])
        add({'ip_cidr':[str(ip)+'/'+str(ip.max_prefixlen)],'port':[endpoint['server_port']]},action='reject')
    if users:
        for tag in tags:
            target=FRONT_TARGETS[tag]
            if target in physical:add({'inbound':[tag],'auth_user':users},target)
            else:add({'inbound':[tag],'auth_user':users},action='reject')
    for test in tests:
        if test['front']=='dmit' and test['outbound'] in physical:
            add({'domain_suffix':test['domains']},test['outbound'])
        else:add({'domain_suffix':test['domains']},action='reject')
    add({'domain':list(CONTROL_DOMAINS)},'direct');add({'ip_cidr':[DMIT_IP+'/32']},'direct')
    c.need(isinstance(service_ip_routes,list) and len(service_ip_routes)<=100,'service_ip_binding_inventory')
    seen=set()
    for binding in service_ip_routes:
        c.need(isinstance(binding,dict) and set(binding)=={'ip_cidr','target'},'service_ip_binding_fields')
        network=ipaddress.ip_network(binding['ip_cidr'],strict=True)
        c.need(network.network_address.is_global and network.prefixlen==network.max_prefixlen and str(network) not in seen,'service_ip_binding_public_exact')
        seen.add(str(network));target=OUTBOUNDS.get(binding['target'],binding['target'])
        c.need(target in c.PHYSICAL and (str(network.network_address)!=DMIT_IP or target=='direct'),'service_ip_binding_target')
        if target in physical:add({'ip_cidr':[str(network)]},target)
        else:add({'ip_cidr':[str(network)]},action='reject')
    for provider,hosts in sorted(contract['vps_domains'].items()):
        if not hosts:continue
        if provider=='dmit':add({'domain_suffix':hosts},'direct');continue
        for tag in tags:
            if tag in ('dmit-direct-stage','mobile-dmit-direct'):
                target=SELECTOR_PREFIX+'vps-'+provider
            else:target=FRONT_TARGETS[tag]
            if target in physical or target.startswith(SELECTOR_PREFIX):add({'inbound':[tag],'domain_suffix':hosts},target)
            else:add({'inbound':[tag],'domain_suffix':hosts},action='reject')
    cn=SELECTOR_PREFIX+'china'
    add({'domain_suffix':list(WECHAT_SUFFIXES)+contract['remote_domains']},cn)
    add({'rule_set':['server-cn-domain','server-cn-ip']},cn)
    add({'domain_suffix':contract['mytvsuper_domains']},SELECTOR_PREFIX+'mytvsuper')
    add({'domain_suffix':contract['hk_domains']},SELECTOR_PREFIX+'hk-other')
    # Youtube is excluded before the Google/AI asset rules.
    add({'domain_suffix':list(YOUTUBE_SUFFIXES)},SELECTOR_PREFIX+'other')
    add({'rule_set':['server-youtube']},SELECTOR_PREFIX+'other')
    for tag in tags:
        key='ai-lazycat' if tag in ('dmit-starhub','mobile-dmit-starhub') else \
            'ai-singtel' if tag in ('dmit-singtel','mobile-dmit-singtel') else \
            'ai-mobile' if tag.startswith('mobile-') else 'ai-desktop'
        add({'inbound':[tag],'domain_suffix':list(X_SUFFIXES)},SELECTOR_PREFIX+key)
        add({'inbound':[tag],'rule_set':['server-ai','server-google']},SELECTOR_PREFIX+key)
        add({'inbound':[tag],'domain_suffix':list(GOOGLE_AI_SUFFIXES)},SELECTOR_PREFIX+key)
    add({'rule_set':['server-hk-ip']},SELECTOR_PREFIX+'hk-other')
    add({'network':['tcp']},SELECTOR_PREFIX+'other')
    rules.append({'action':'reject'})
    return rules

def _build_v2(config,*,rule_sets,routing_revision,health=None,service_ip_routes=None,**unused):
    contract=c.validate(routing_revision)
    _require(isinstance(rule_sets,VerifiedRuleSets),'verified_rule_sets_required')
    output=copy.deepcopy(config)
    wanted=expected_inbound_tags(contract)
    output['inbounds']=[r for r in output.get('inbounds',[]) if r.get('tag') in wanted]
    incoming=output['inbounds'];_require({r.get('tag') for r in incoming}==wanted and len(incoming)==len(wanted),'revised_decrypted_fronts_required')
    import edge_ai_policy as ai
    ai._cohort(incoming)
    physical=[r for r in output.get('outbounds',[]) if r.get('tag') in c.PHYSICAL and c.available(contract,r['tag'])]
    actual={r['tag']:r for r in physical}
    expected={tag for tag in c.PHYSICAL if c.available(contract,tag)}
    _require(set(actual)==expected,'revised_physical_inventory_required')
    _require(actual['direct'].get('type')=='direct','direct_outbound_invalid')
    for tag,row in actual.items():
        if tag!='direct':_require(row.get('type') in ('shadowsocks','anytls') and not row.get('detour'),'verified_transport_required')
    quarantine=[r for r in output.get('outbounds',[]) if r.get('tag')=='violation-bt-quarantine']
    _require(len(quarantine)==1 and quarantine[0].get('server')=='127.0.0.1' and quarantine[0].get('server_port')==18115,'bt_quarantine_changed')
    output['outbounds']=physical+quarantine+c.pool_outbounds(contract)+selector_outbounds(contract,health)
    output['route']={'rules':_rules(contract,incoming,set(actual),service_ip_routes or []),'rule_set':rule_sets.definitions,
        'final':SELECTOR_PREFIX+'other','default_domain_resolver':{'server':_dns(contract)['final'],'strategy':'ipv4_only'}}
    output['dns']=_dns(contract)
    return output

def build_server_route_policy(config,*,routing_revision=None,health=None,**kwargs):
    if routing_revision is None:return old.build_server_route_policy(config,**kwargs)
    return _build_v2(config,routing_revision=routing_revision,health=health,**kwargs)

def validate_server_runtime(document,*,routing_revision,rule_sets,service_ip_routes=None):
    # Selector defaults are immutable generation contents; only runtime API
    # selections may vary. Rebuild with precisely those declared defaults.
    health={}
    selectors={r['tag']:r for r in document.get('outbounds',[]) if r.get('type')=='selector'}
    for tag,row in selectors.items():
        _require(row.get('default') in row.get('outbounds',[]),'invalid_selector_default')
    expected=_build_v2(document,rule_sets=rule_sets,routing_revision=routing_revision,health=health,service_ip_routes=service_ip_routes)
    for row in expected['outbounds']:
        if row.get('type')=='selector' and row['tag'] in selectors:row['default']=selectors[row['tag']]['default']
    _require(document.get('route')==expected['route'] and document.get('dns')==expected['dns']
        and document.get('outbounds')==expected['outbounds'],'revised_policy_changed')
    return {'policy_id':NEW_POLICY_ID,'selectors':{k:r['default'] for k,r in selectors.items()},
        'accounts':__import__('edge_ai_policy')._cohort(document['inbounds'])}
