"""Versioned client contract; imports neither change networking nor fetch providers."""
from __future__ import annotations
import copy, hashlib, json, os, re, stat, sys
from pathlib import Path

EDGE_CLIENT_SETTINGS_PATH = Path('/etc/submerge-edge/client-settings.json')
ROUTING_CLIENT_GATE_PATH = Path('/etc/submerge-topology/routing-client-20261109.json')

def _edge_legacy_policy():
    module=sys.modules.get(__name__)
    if module is not None and module.__dict__ is globals():
        return module
    # Some existing tools exec a module without registering its alias. Keep
    # their own functions/closure rather than returning another same-name copy.
    from types import SimpleNamespace
    return SimpleNamespace(**{key:globals()[key] for key in (
        'validate_profile','AI_AUTO','NOTICE','ai_keys','ai_offset','ai_site',
        'ai_manual_names','displayed_routes')})

def _routing_client_projection(output):
    # The revision gate precedes the legacy edge/manual-test early return.
    # No gate means the previous renderer/validator remains unchanged.
    path=Path(ROUTING_CLIENT_GATE_PATH)
    if not os.path.lexists(str(path)):
        return None
    from routing_client_v4 import try_project
    return try_project(output,gate_path=path)


def _edge_client_projection(output):
    revised=_routing_client_projection(output)
    if revised is not None:
        return revised
    if output.get('x-submerge-manual-test') is True:
        return output
    path=Path(EDGE_CLIENT_SETTINGS_PATH)
    if not os.path.lexists(str(path)):
        return output
    if path.is_symlink():
        raise ValueError('edge_client_settings_symlink')
    fd=os.open(str(path),os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_size>16384 or info.st_mode&0o077
            or getattr(info,'st_uid',0)!=0):
            raise ValueError('edge_client_settings_permissions')
        settings=json.loads(stream.read(16385))
    from edge_profile import project_profile
    return project_profile(output,settings,legacy_policy=_edge_legacy_policy())

REVISION = 'dmit-client-minimal-20261106-v2'
POLICY_PATH = Path('/etc/submerge-topology/client-policy.json')
DEADLINE = 1794024000  # 2026-11-07 12:00:00 Asia/Singapore
NOTICE = ('点什么都', '没用，服', '务器分流')
TEST_NOTICE = ('测试订阅', '按所选的', '链路转发')
AI_AUTO = '🧭 默认'
ZORO_LABEL='🔷 🏡 🇸🇬 DMIT → zorocloud sptel'
ZORO_SITE='https://ipinfo.io/what-is-my-ip'
def ai_keys(kind):return ('uzuma_sg','zoro_sg','lazycat_sg') if kind=='mobile' else ('zoro_sg','uzuma_sg','lazycat_sg')
def ai_offset(key):return {'lazycat_sg':15,'uzuma_sg':17,'zoro_sg':19}[key]
def ai_site(key):return ZORO_SITE if key=='zoro_sg' else SITES[key][0]
AI_MANUAL = {'uzuma_sg':'🔷 📱 🇸🇬 优先：uzuma SG-Singtel1',
             'lazycat_sg':'🔷 🐈 🇸🇬 优先：Lazycat starhub','zoro_sg':ZORO_LABEL}
SENSITIVE_SUFFIXES = ('openai.com','chatgpt.com','oaistatic.com','oaiusercontent.com',
 'anthropic.com','claude.ai','claudeusercontent.com','gemini.google.com',
 'gemini.google','bard.google.com','aistudio.google.com','makersuite.google.com',
 'generativelanguage.googleapis.com','aisandbox-pa.googleapis.com','ippure.com',
 'x.com','twitter.com','twimg.com','t.co')
SITES = {
 'dmit': ('https://ip.sb/', 'ip.sb', 'direct'),
 'uzuma_sg': ('https://whoer.net/zh', 'whoer.net', 'singtel'),
 'lazycat_sg': ('https://ipinfo.io/what-is-my-ip', 'ipinfo.io', 'starhub'),
 'bytevirt_hk': ('https://www.maxmind.com/en/locate-my-ip-address', 'maxmind.com', 'hk'),
 'lazycat_hkt': ('https://www.ip2location.com/demo', 'ip2location.com', 'hkt'),
 'bytevirt_tw': ('https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test', 'ipqualityscore.com', 'taiwan'),
}
OLD_PORTS = {'dmit':31117, 'bytevirt_hk':29518, 'bytevirt_tw':29514,
             'lazycat_sg':29515, 'lazycat_hkt':29516, 'uzuma_sg':29517,'zoro_sg':29519}
NEW_PORTS = {key:29711 if key=='dmit' else port+200 for key,port in OLD_PORTS.items()}
def front_ports(kind, *, new=True, test_mode=False):
    ports = dict(NEW_PORTS if new else OLD_PORTS)
    if new and test_mode:
        ports = {key:port+600 for key,port in ports.items()}
    if kind == 'mobile':
        ports = {key:(29611 if not new and key=='dmit' else port+100) for key,port in ports.items()}
    return ports

def port_forward_specs():
    """Public revision sockets terminate at the current authenticated core.

    Ordinary display routes all signal device auto. Only AI priority cards
    signal the chosen SG entry. The independent test identity uses six entries.
    """
    result={}
    for kind in ('desktop','mobile'):
        old=front_ports(kind,new=False)
        for port in front_ports(kind).values():result[port]=old['dmit']
        for key,port in front_ports(kind,test_mode=True).items():result[port]=old[key]
        for key,offset in (('lazycat_sg',15),('uzuma_sg',17),('zoro_sg',19)):
            result[(30200 if kind=='mobile' else 30100)+offset]=old[key]
    return result

def load_policy(path=POLICY_PATH):
    path=Path(path)
    if not os.path.lexists(str(path)):
        return None
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_size>16384 or info.st_mode&0o077:
        raise ValueError('client_policy_permissions_invalid')
    if hasattr(info,'st_uid') and info.st_uid != 0:
        raise ValueError('client_policy_owner_invalid')
    value=json.loads(path.read_bytes())
    if (not isinstance(value,dict) or set(value)!={'revision','deadline','test_users'} or
        value['revision']!=REVISION or value['deadline']!=DEADLINE or
        not isinstance(value['test_users'],list) or len(value['test_users'])>4 or
        len(set(value['test_users']))!=len(value['test_users']) or
        any(not isinstance(x,str) or re.fullmatch(r'route-test-[a-f0-9]{32}',x) is None for x in value['test_users'])):
        raise ValueError('client_policy_document_invalid')
    return value

def direct_or_reject(rule):
    return (rule.endswith((',DIRECT',',DIRECT,no-resolve',',REJECT',',REJECT-DROP'))
            and not rule.startswith('MATCH,'))

def displayed_routes():
    from new_topology import PLAN_ROUTE_NAMES
    return {key:name+'\nIP检测：'+SITES[key][0] for key,name in PLAN_ROUTE_NAMES.items()}

def ai_manual_names():
    return {k:v+'\nIP检测：'+ai_site(k) for k,v in AI_MANUAL.items()}

def simplified_rules(profile, *, test_mode=False):
    from new_topology import ALL, UDP_FALLBACK_GUARD, PLAN_GOOGLE, PLAN_YOUTUBE_SUFFIXES
    labels=displayed_routes()
    retained=[r for r in profile['rules'] if direct_or_reject(r) and r!=UDP_FALLBACK_GUARD]
    # IPinfo is shared by the SG choices and follows the selected AI ingress.
    tests=['DOMAIN-SUFFIX,'+SITES[key][1]+','+(PLAN_GOOGLE if SITES[key][1]=='ipinfo.io' else labels[key]) for key in SITES]
    # AI dispatch is the one business exception: only this group can signal an
    # explicit choice. YouTube stays outside it even if Google's geosite contains it.
    youtube=['DOMAIN-SUFFIX,'+d+','+ALL for d in PLAN_YOUTUBE_SUFFIXES]+['GEOSITE,youtube,'+ALL]
    ai=['DOMAIN-SUFFIX,'+d+','+PLAN_GOOGLE for d in SENSITIVE_SUFFIXES]
    ai+=['GEOSITE,google,'+PLAN_GOOGLE,'GEOSITE,category-ai-!cn,'+PLAN_GOOGLE]
    if test_mode:
        youtube=[];ai=[]
    broad=[r for r in retained if r in ('GEOSITE,cn,DIRECT','GEOIP,CN,DIRECT')]
    specific=[r for r in retained if r not in broad]
    return list(dict.fromkeys(tests+specific+youtube+ai+broad+['MATCH,'+ALL,UDP_FALLBACK_GUARD]))

def simplify_profile(profile, *, test_mode=False):
    from new_topology import PLAN_ROUTE_NAMES, PLAN_VISIBLE_GROUPS, PLAN_PAOLUZ, AIRPORT_FAST
    if type(test_mode) is not bool or profile.get('x-submerge-server-policy')!='dmit-domain-routing-20261106':
        raise ValueError('decrypted_server_policy_required')
    output=copy.deepcopy(profile)
    labels=displayed_routes()
    rename={PLAN_ROUTE_NAMES[key]:labels[key] for key in labels}
    kind=output['x-submerge-client-kind']
    ports=front_ports(kind,test_mode=test_mode)
    for node in output['proxies']:
        if node['name'] in rename:
            key=next(k for k,v in PLAN_ROUTE_NAMES.items() if v==node['name'])
            node.update(name=labels[key],port=ports[key],desc='IP检测：'+ai_site(key))
    notice=TEST_NOTICE if test_mode else NOTICE
    # Valid authenticated aliases: selecting a notice never creates a dead endpoint.
    first=next(n for n in output['proxies'] if n['name']==labels['dmit'])
    for name in notice:
        node=copy.deepcopy(first);node.update(name=name,desc=''.join(notice));output['proxies'].append(node)
    if not test_mode:
        node=copy.deepcopy(first);node.update(name=AI_AUTO,desc=''.join(NOTICE))
        output['proxies'].append(node)
        for key,name in ai_manual_names().items():
            node=copy.deepcopy(first)
            node.update(name=name,port=(30200 if kind=='mobile' else 30100)+ai_offset(key),
                        desc='IP检测：'+ai_site(key))
            output['proxies'].append(node)
    if test_mode:
        node=copy.deepcopy(first);node.update(name=ai_manual_names()['zoro_sg'],port=ports['zoro_sg'],desc='IP检测：'+ZORO_SITE);output['proxies'].append(node)
    for group in output['proxy-groups']:
        members=[rename.get(name,name) for name in group.get('proxies',[])]
        if members:
            group['proxies']=members
        if group.get('default-selected') in rename:
            group['default-selected']=rename[group['default-selected']]
        if group['name'] in PLAN_VISIBLE_GROUPS:
            from new_topology import PLAN_GOOGLE
            if group['name']==PLAN_GOOGLE and not test_mode:
                members=[AI_AUTO,*[ai_manual_names()[key] for key in
                    ai_keys(kind)]]
                group['default-selected']=AI_AUTO
            elif group['name']==PLAN_GOOGLE:
                mapping={'zoro_sg':ai_manual_names()['zoro_sg'],'uzuma_sg':labels['uzuma_sg'],'lazycat_sg':labels['lazycat_sg']}
                members=[mapping[k] for k in ai_keys(kind)];group['default-selected']=members[0]
            group['default-selected']=group.get('default-selected',members[0])
            if group['name']==PLAN_PAOLUZ:
                group['proxies']=members
                group.pop('desc',None)
            else:
                group['proxies']=list(notice)+members
                group['desc']=''.join(notice)
    # Keep overseas DNS through the existing authenticated proxy and all CN,
    # WeChat, DNS interception/fake-IP exclusions. Remove business DNS selectors.
    dns=output['dns'];old=dns.get('nameserver-policy',{})
    dns['nameserver-policy']={k:v for k,v in old.items() if v and
        all(isinstance(x,str) and x.endswith('#DIRECT') for x in v)}
    # Preserve the two existing independent DoH lanes and add Google via Singtel.
    extra='https://8.8.8.8/dns-query#DNS-Overseas'
    if extra not in dns['nameserver']:dns['nameserver'].append(extra)
    output['rules']=simplified_rules(profile,test_mode=test_mode)
    output.update({'x-submerge-client-policy':REVISION,'x-submerge-manual-test':test_mode,
                   'x-submerge-update-deadline':'2026.11.07 12:00:00 Asia/Singapore',
                   'x-submerge-ip-tests':{**{labels[k]:SITES[k][0] for k in SITES},ai_manual_names()['zoro_sg']:ZORO_SITE}})
    validate_profile(output)
    return _edge_client_projection(output)

def validate_profile(document, provider_document=None):
    if isinstance(document,dict) and 'x-submerge-routing-revision' in document:
        from routing_client_v4 import validate_projected
        return validate_projected(document,gate_path=ROUTING_CLIENT_GATE_PATH)
    if isinstance(document,dict) and 'x-submerge-lazycat-ai' in document:
        from edge_profile import validate_profile as validate_edge_profile
        return validate_edge_profile(document,legacy_policy=_edge_legacy_policy(),
                                     provider_document=provider_document)
    from new_topology import (PLAN_VISIBLE_GROUPS, PLAN_ROUTE_KEYS, PLAN_ROUTE_NAMES, CHINA,
        ALL, AUTO, PLAN_GOOGLE, PLAN_TVB, PLAN_HK_OTHER,VPS,OTHER,PLAN_PAOLUZ,
        AIRPORT_FAST, GLOBAL, UDP_FALLBACK_GUARD, PLAN_WECHAT_SUFFIXES)
    def need(ok,label):
        if not ok:raise ValueError('minimal_'+label)
    need(isinstance(document,dict) and document.get('x-submerge-client-policy')==REVISION,'revision')
    kind=document.get('x-submerge-client-kind');need(kind in ('mobile','desktop','router'),'platform')
    test=document.get('x-submerge-manual-test');need(type(test) is bool,'test_flag')
    notice=TEST_NOTICE if test else NOTICE
    need(all(len(x)==4 for x in notice),'notice_length')
    rows=document.get('proxy-groups',[]);nodes=document.get('proxies',[])
    need(all(isinstance(r,dict) and isinstance(r.get('name'),str) for r in rows+nodes),'inventory')
    groups={r['name']:r for r in rows};indexed={n['name']:n for n in nodes}
    need(len(groups)==len(rows) and len(indexed)==len(nodes),'unique')
    need([r['name'] for r in rows if not r.get('hidden')]==list(PLAN_VISIBLE_GROUPS),'visible_order')
    labels=displayed_routes();ports=front_ports(kind,test_mode=test)
    passwords=set()
    for key,name in labels.items():
        node=indexed.get(name,{})
        need(node.get('type')=='anytls' and node.get('server')=='179.255.136.79' and node.get('port')==ports[key]
             and node.get('udp') is False and node.get('dialer-proxy','DIRECT')=='DIRECT','route_endpoint')
        password=node.get('password');need(isinstance(password,str) and len(password)>=24,'credential');passwords.add(password)
        need(node.get('desc')=='IP检测：'+SITES[key][0],'test_description')
    need(len(passwords)==1,'cohort')
    for name in notice:
        compare=copy.deepcopy(indexed.get(name,{}));compare.update(name=labels['dmit'],desc=indexed[labels['dmit']]['desc'])
        need(compare==indexed[labels['dmit']],'notice_endpoint')
    for name in PLAN_VISIBLE_GROUPS:
        group=groups[name];need(group.get('type')=='select','group_type')
        if name==PLAN_PAOLUZ:
            need(not set(notice).intersection(group.get('proxies',[])) and not group.get('desc'),'backup_notice_absent')
            members=group.get('proxies',[])
        else:
            need(group.get('proxies',[])[:3]==list(notice),'notice_order')
            members=group['proxies'][3:]
        need(group.get('default-selected') in members,'real_default')
    sg=[labels['uzuma_sg'],labels['lazycat_sg']]
    sg=[(ai_manual_names()['zoro_sg'] if k=='zoro_sg' else labels[k]) for k in ai_keys(kind)]
    if not test:
        sg=[AI_AUTO,*[ai_manual_names()[key] for key in
            ai_keys(kind)]]
        need(indexed.get(AI_AUTO,{}).get('port')==ports['dmit'],'ai_auto_port')
        expected=copy.deepcopy(indexed[labels['dmit']]);expected.update(name=AI_AUTO,desc=''.join(NOTICE))
        need(indexed.get(AI_AUTO)==expected,'ai_auto_identity')
        for key,name in ai_manual_names().items():
            need(indexed.get(name,{}).get('port')==(30200 if kind=='mobile' else 30100)+ai_offset(key),'ai_manual_port')
            expected=copy.deepcopy(indexed[labels['dmit']]);expected.update(name=name,
                port=(30200 if kind=='mobile' else 30100)+ai_offset(key),desc='IP检测：'+ai_site(key))
            need(indexed.get(name)==expected,'ai_manual_identity')
    if test:
        expected=copy.deepcopy(indexed[labels['dmit']]);expected.update(name=ai_manual_names()['zoro_sg'],port=ports['zoro_sg'],desc='IP检测：'+ZORO_SITE)
        need(indexed.get(ai_manual_names()['zoro_sg'])==expected,'test_zoro_identity')
    expect={ALL:[AUTO,PLAN_GOOGLE,PLAN_TVB,PLAN_HK_OTHER,VPS,OTHER,PLAN_PAOLUZ],AUTO:[OTHER],
            PLAN_GOOGLE:sg,PLAN_TVB:[labels['bytevirt_hk']],PLAN_HK_OTHER:[labels['lazycat_hkt']],
            VPS:[labels[k] for k in PLAN_ROUTE_KEYS],OTHER:[labels['bytevirt_tw']]}
    for name,members in expect.items():need(groups[name]['proxies'][3:]==members,'group_members')
    backup=groups[PLAN_PAOLUZ];need(backup['proxies'][0]==AIRPORT_FAST and backup['default-selected']==AIRPORT_FAST,'backup_default')
    provider=(document.get('proxy-providers')or{}).get('paoluz',{})
    need(provider.get('proxy')=='DIRECT' and provider.get('url','').startswith('https://node.titanyung.click:31877/sub/'),'provider')
    airport=backup['proxies'][1:]
    if provider_document is not None:need(airport==[n['name'] for n in provider_document['proxies']],'provider_members')
    need(all(n in indexed for n in airport),'materialized')
    rules=document.get('rules',[])
    need(rules[-2:]==['MATCH,'+ALL,UDP_FALLBACK_GUARD],'terminal')
    tests=['DOMAIN-SUFFIX,'+SITES[k][1]+','+(PLAN_GOOGLE if SITES[k][1]=='ipinfo.io' else labels[k]) for k in SITES]
    from new_topology import PLAN_YOUTUBE_SUFFIXES
    exception=['DOMAIN-SUFFIX,'+d+','+ALL for d in PLAN_YOUTUBE_SUFFIXES]+['GEOSITE,youtube,'+ALL]
    exception+=['DOMAIN-SUFFIX,'+d+','+PLAN_GOOGLE for d in SENSITIVE_SUFFIXES]
    exception+=['GEOSITE,google,'+PLAN_GOOGLE,'GEOSITE,category-ai-!cn,'+PLAN_GOOGLE]
    if test:exception=[]
    need(rules[:6]==tests and all(direct_or_reject(r) or r in exception for r in rules[6:-2]),'only_minimal_rules')
    need(all(r in rules for r in exception),'ai_dispatch')
    need('GEOSITE,cn,DIRECT' in rules and 'GEOIP,CN,DIRECT' in rules,'domestic')
    need(all('DOMAIN-SUFFIX,'+d+',DIRECT' in rules for d in PLAN_WECHAT_SUFFIXES),'wechat')
    need(document.get('ipv6') is False,'ipv6')
    need(document.get('x-submerge-server-policy')=='dmit-domain-routing-20261106','server_policy')
    dns=document.get('dns')or{}
    need(dns.get('nameserver') and all('#DNS-' in x for x in dns['nameserver']),'dns_proxy')
    need(all(v and all(x.endswith('#DIRECT') for x in v) for v in dns.get('nameserver-policy',{}).values()),'dns_minimal')
    for r in rows:
        for name in r.get('proxies',[]):need(name in indexed or name in groups or name in {'DIRECT','REJECT'},'reference')
    return True
