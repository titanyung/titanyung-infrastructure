"""Current server-routing names and safe metadata for the authenticated UI."""
import copy,json,os,stat,time
from pathlib import Path
from routing_contract import UZUMA_HKT_RETIRE_AT
REVISION='routing-revision-20261109-v1'
GROUPS=('全部节点','自动','中转节点','chatgpt、claude、google（不含youtube）','Mytvsuper专线','viu tv & HK其他','VPS访问','非中国大陆的其他','paoluz')
ROUTE_LABELS={'dmit':'DMIT','lazycat_sg':'Lazycat SG','lc_singtel':'Lazycat SG → uzuma SG-Singtel1',
 'dmit_singtel':'DMIT → uzuma SG-Singtel1','lc_lazycat_starhub':'Lazycat SG → Lazycat starhub','dmit_lazycat_starhub':'DMIT → Lazycat starhub',
 'lc_uzuma_starhub':'Lazycat SG → uzuma starhub','dmit_uzuma_starhub':'DMIT → uzuma starhub','dmit_uzuma_hkt':'DMIT → uzuma HKT',
 'dmit_bytevirt_hk':'DMIT → Bytevirt HK ISP','dmit_bytevirt_tw':'DMIT → Bytevirt HINET NAT','dmit_lazycat_hkt':'DMIT → Lazycat HKT'}
METADATA=Path('/var/lib/sg-traffic-dashboard/topology-20261105.json')

def contract(plan,legacy_aliases):
    if plan.get('plan')!='network-plan-20261109' or plan.get('server_policy',{}).get('routing_revision',{}).get('id')!=REVISION:
        raise ValueError('routing_catalog_revision_mismatch')
    aliases=dict(legacy_aliases)
    buckets={
      '全部节点':('🌐 全部节点',),'自动':('🧭 自动',),'中转节点':('📡 中转节点',),
      GROUPS[3]:('🤖 '+GROUPS[3],'谷歌全系（不含流媒体）与AI','🤖 谷歌全系（不含流媒体）与AI','google（不含youtube）、chatgpt','🤖 google（不含youtube）、chatgpt','google（不含youtube）、chatgpt、claude','🤖 google（不含youtube）、chatgpt、claude'),
      GROUPS[4]:('TVB&viu tv','🇭🇰 TVB&viu tv','TVB、viu tv','🇭🇰 TVB、viu tv','大陆-TVB','大陆-TVB→解锁TVB','🇭🇰 Mytvsuper专线'),
      GROUPS[5]:('HK其他','🇭🇰 HK其他','🇭🇰 viu tv & HK其他'),
      GROUPS[6]:('🖥️ VPS访问','🖥 VPS访问'),
      GROUPS[7]:('🌍 非中国大陆的其他','币安','🪙 币安','非CN&HK流媒体的流媒体','🎬 非CN&HK流媒体的流媒体','非中国大陆&HK流媒体的流媒体','🎬 非中国大陆&HK流媒体的流媒体'),
      GROUPS[8]:('断线备用','✈️ 断线备用','Paoluz','✈️ 机场paoluz','机场paoluz','🦊 PAOLUZ','🦊 机场paoluz','✈️ paoluz','Paoluz-All')}
    for current,previous in buckets.items():
        aliases[current]=current
        for old in previous:aliases[old]=current
    # Flatten legacy alias chains while preserving unknown retired values.
    for key in list(aliases):
        value=aliases[key];seen={key}
        while value in aliases and value not in seen:
            seen.add(value);next_value=aliases[value]
            if next_value==value:break
            value=next_value
        aliases[key]=value
    targets={'DIRECT':'🟢 直连',**{name:name for name in GROUPS}}
    return {'targets':targets,'legacy_labels':{old:targets[new] for old,new in aliases.items() if new in targets},
            'legacy_group_targets':aliases,'summary_targets':{'hk':GROUPS[5],'tvb':GROUPS[4],'all':GROUPS[0]},
            'plan':plan['plan'],'routing_revision':REVISION}

def server_metadata(path=METADATA):
    path=Path(path);info=path.stat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size>4*1024*1024:raise ValueError('routing_metadata_file')
    if hasattr(os,'geteuid') and os.geteuid()==0 and (info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o600):raise ValueError('routing_metadata_private_permissions')
    manifest=json.loads(path.read_text(encoding='utf8'))
    if manifest.get('routing_revision')!=REVISION:return {'enabled':False,'servers':[],'ip_tests':{},'groups':[]}
    inventory=manifest['revision_inventory'];now=int(time.time());servers=[]
    fields=('id','host','display_name','description','currency','amount','quota','speed','billing','due_day','due_month_day','monitoring_state','retire_at')
    for host,row in inventory['servers'].items():
        item={k:copy.deepcopy(row[k]) for k in fields if k in row}
        item['status']='pending' if row['monitoring_state']=='pending' else 'archived' if row['retire_at'] is not None and now>=row['retire_at'] else 'active'
        servers.append(item)
    sites=copy.deepcopy(manifest['ip_test_sites']);labels=dict(ROUTE_LABELS)
    for key,cutoff in (('dmit_bytevirt_tw',manifest['routing_contract']['taiwan_retire_at']),
                       ('dmit_lazycat_hkt',manifest['routing_contract']['lazycat_hkt_retire_at']),
                       ('dmit_uzuma_hkt',UZUMA_HKT_RETIRE_AT)):
        if now>=cutoff:sites.pop(key,None);labels.pop(key,None)
    return {'enabled':True,'revision':REVISION,'checked_at':now,'servers':servers,
            'ip_tests':sites,'route_labels':labels,'groups':list(GROUPS),
            'server_policy':{'domestic_before_taiwan_retirement':'bytevirt-taiwan',
                             'domestic_after_taiwan_retirement':'uzuma-hkt' if now<UZUMA_HKT_RETIRE_AT else 'bytevirt-hk',
                             'taiwan_retire_at':manifest['routing_contract']['taiwan_retire_at'],
                             'lazycat_hkt_retire_at':manifest['routing_contract']['lazycat_hkt_retire_at'],
                             'uzuma_hkt_retire_at':UZUMA_HKT_RETIRE_AT,
                             'leaf_source_restriction':'DMIT and Lazycat SG actual IPv4/IPv6 only'}}
