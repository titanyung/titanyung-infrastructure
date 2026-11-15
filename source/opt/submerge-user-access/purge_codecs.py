"""Credential-free, explicit blocked subscription renderings; no upstream reads."""
from __future__ import annotations
import base64
import json
import urllib.parse

from lifecycle import prepare_purge

MAIN_LABELS=('全部节点', '自动', 'chatgpt、claude、google（不含youtube）', 'Mytvsuper专线', 'viu tv & HK其他', 'VPS访问', '非中国大陆的其他', 'paoluz')
BLOCKED_NAME='⛔ 账号已停用'
# Deliberately unusable, clearly labelled placeholder; no real server credential.
BLOCKED_NODE={'name':BLOCKED_NAME,'type':'ss','server':'127.0.0.1','port':9,
              'cipher':'aes-128-gcm','password':'REPLACE_BLOCKED_NODE_PASSWORD','udp':False}
BLOCKED_URI='ss://REPLACE_BLOCKED_URI_USERINFO@127.0.0.1:9#'+urllib.parse.quote(BLOCKED_NAME,safe='')
CONTROL_HOSTS=('node.titanyung.click','dnode.titanyung.click')
BLOCKED_JSON={'outbounds':[{'type':'direct','tag':'direct'},
    {'type':'socks','tag':'blocked','server':'127.0.0.1','server_port':9,'version':'5'}],
    'route':{'rules':[{'domain':list(CONTROL_HOSTS),'outbound':'direct'},
        {'ip_cidr':['179.255.136.79/32'],'outbound':'direct'}],'final':'blocked'}}
CONTROL_RULES=['DOMAIN,'+host+',DIRECT' for host in CONTROL_HOSTS]+['IP-CIDR,179.255.136.79/32,DIRECT,no-resolve','MATCH,REJECT']
CONTROL_DNS=['https://223.5.5.5/dns-query#DIRECT','https://223.6.6.6/dns-query#DIRECT']


def infer_format(query,user_agent='',content_type=''):
    """Return canonical codec; a provider poll is never a main profile."""
    explicit=str((query.get('format') or query.get('target') or [''])[0]).lower()
    if any(len(query.get(key,[]))>1 for key in ('format','target')):raise ValueError('ambiguous_subscription_format')
    if query.get('format') and query.get('target') and query['format'][0].lower()!=query['target'][0].lower():raise ValueError('ambiguous_subscription_format')
    if explicit in {'provider','clash-provider'}:return 'provider'
    if explicit in {'clash','clashmeta','clash-meta','mihomo','yaml','openclash','shadowrocket'}:return 'clash'
    if explicit in {'singbox','sing-box','sing_box','json'}:return 'sing-box'
    if explicit in {'uri','raw','links'}:return 'uri'
    if explicit in {'base64','v2ray','v2rayn','auto','mixed',''}:
        if not explicit and 'shadowrocket' in user_agent.lower():return 'clash'
        if any(name in user_agent.lower() for name in ('clash','mihomo')):return 'clash'
        if 'sing-box' in user_agent.lower() or 'singbox' in user_agent.lower():return 'sing-box'
        if 'json' in content_type.lower():return 'sing-box'
        return 'base64'
    raise ValueError('unsupported_subscription_format')


def _clash():
    return {'mode':'rule','ipv6':False,'proxies':[dict(BLOCKED_NODE)],
        # Mihomo rejects an empty inline provider. Removing its definition and
        # every reference clears paoluz while preserving a loadable profile.
        'proxy-providers':{},
        'proxy-groups':[{'name':'GLOBAL','type':'select','proxies':['REJECT'],
                         'default-selected':'REJECT','hidden':True}]+
                       [{'name':name,'type':'select','proxies':[BLOCKED_NAME],
                         'default-selected':BLOCKED_NAME} for name in MAIN_LABELS],
        'rules':list(CONTROL_RULES),
        'dns':{'enable':True,'ipv6':False,'enhanced-mode':'redir-host','respect-rules':False,
            'default-nameserver':['https://223.5.5.5/dns-query'],
            'nameserver':list(CONTROL_DNS),'proxy-server-nameserver':list(CONTROL_DNS),
            'nameserver-policy':{host:list(CONTROL_DNS) for host in CONTROL_HOSTS}}}


def validate_purge(body,format_name,content_type):
    try:
        if format_name=='provider':return (body,content_type)==empty_provider()
        if format_name=='clash':
            value=json.loads(body)
            return value==_clash()
        if format_name=='sing-box':
            value=json.loads(body)
            return value==BLOCKED_JSON
        if format_name=='uri':return body==(BLOCKED_URI+'\n').encode()
        if format_name=='base64':return base64.b64decode(body,validate=True)==(BLOCKED_URI+'\n').encode()
    except (ValueError,TypeError,KeyError):return False
    return False


def render_purge(format_name):
    if format_name=='provider':body,mime=empty_provider()
    elif format_name=='clash':body=json.dumps(_clash(),ensure_ascii=False,separators=(',',':')).encode();mime='application/yaml; charset=utf-8'
    elif format_name=='sing-box':body=json.dumps(BLOCKED_JSON,separators=(',',':')).encode();mime='application/json'
    elif format_name=='uri':body=(BLOCKED_URI+'\n').encode();mime='text/plain; charset=utf-8'
    elif format_name=='base64':body=base64.b64encode((BLOCKED_URI+'\n').encode());mime='text/plain; charset=utf-8'
    else:raise ValueError('unsupported_subscription_format')
    return prepare_purge(body,format_name,mime,validate_purge)


def empty_provider():return b'{"proxies":[]}\n','application/yaml; charset=utf-8'
