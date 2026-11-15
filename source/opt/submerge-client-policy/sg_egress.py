"""Verify AI-specific exits using exact production transports in a private probe core.

Normal traffic may deliberately exit a data centre. Only the two AI hosts below
are checked against the subscriber's intended access networks. No client or
production proxy configuration is changed by this collector.
"""
import concurrent.futures,copy,ipaddress,json,os,subprocess,sys,tempfile,time,urllib.request
from pathlib import Path
ROOT=Path('/root/topology-20261105/dmit-routing-20261106')
TAGS=('uzuma-singtel','zoro-sg','lazycat-starhub')
EXPECTED={'uzuma-singtel':{'45143'},'lazycat-starhub':{'4657'},'zoro-sg':{'139883','23856'}}
HOSTS=('chatgpt.com','claude.ai')
STATE=Path('/run/dmit-client-policy/egress.json')
CACHE=Path('/var/cache/dmit-ai-egress/networks.json')
sys.path.append(str(ROOT))
import probe_native_policy as core
os.umask(0o077)

def write(path,value):
    path=Path(path);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix='.egress-',dir=str(path.parent))
    try:
        with os.fdopen(fd,'w') as stream:
            os.fchmod(stream.fileno(),0o600);json.dump(value,stream);stream.flush();os.fsync(stream.fileno())
        os.replace(name,path)
    finally:
        if os.path.exists(name):os.unlink(name)

def network(address,cache):
    now=int(time.time());old=cache.get(address,{})
    if now-int(old.get('checked_at',0))<3600:return old
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open('https://stat.ripe.net/data/network-info/data.json?resource='+str(ipaddress.ip_address(address)),timeout=8) as response:
        raw=response.read(65537)
    if len(raw)>65536:raise ValueError('network_response_size')
    value=json.loads(raw)
    if value.get('status')!='ok':raise ValueError('network_response_status')
    data=value['data'];prefix=ipaddress.ip_network(data['prefix'])
    if ipaddress.ip_address(address) not in prefix:raise ValueError('network_prefix_mismatch')
    result={'asns':[str(x) for x in data['asns']],'prefix':str(prefix),'checked_at':now}
    if not result['asns']:raise ValueError('network_origin_missing')
    cache[address]=result;return result

def valid_exit(tag,trace,origin):
    try:
        address=ipaddress.ip_address(trace['ip'])
        asns={str(x) for x in origin['asns']}
        return address.version==4 and address.is_global and trace.get('loc')=='SG' and bool(asns) and asns.issubset(EXPECTED[tag])
    except (ValueError,KeyError,TypeError):return False

def fetch(port,host):
    result=subprocess.run(['curl','-q','-4','--noproxy','','--socks5-hostname','127.0.0.1:'+str(port),
        '--silent','--show-error','--connect-timeout','4','--max-time','10','--fail',
        'https://'+host+'/cdn-cgi/trace'],capture_output=True,text=True,timeout=13)
    if result.returncode:raise ValueError('ai_trace_unavailable')
    if len(result.stdout)>8192:raise ValueError('ai_trace_size')
    trace=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
    if trace.get('h')!=host:raise ValueError('ai_trace_host_mismatch')
    return {key:trace[key] for key in ('ip','loc','h')}

def collect(runtime='/run/dmit-direct-staging/config.json',state=STATE):
    started=int(time.time());document=json.loads(Path(runtime).read_bytes())
    cache=json.loads(CACHE.read_bytes()) if CACHE.exists() else {}
    ports=dict(zip(TAGS,core.allocate_ports(len(TAGS))))
    transports=[copy.deepcopy(x) for x in document['outbounds'] if x.get('tag') in TAGS]
    if {x['tag'] for x in transports}!=set(TAGS):raise ValueError('sg_outbound_inventory')
    incoming=[];rules=[]
    for tag in TAGS:
        incoming.append({'type':'mixed','tag':'audit-'+tag,'listen':'127.0.0.1','listen_port':ports[tag]})
        rules.append({'inbound':['audit-'+tag],'action':'route','outbound':tag})
    probe={'log':{'level':'error'},'inbounds':incoming,'outbounds':transports,'route':{'rules':rules,'final':TAGS[0]}}
    observations={}
    with tempfile.TemporaryDirectory(prefix='dmit-ai-exit-',dir='/run') as folder:
        with core.Core(Path('/root/lazycat-test-config/sing-box'),probe,Path(folder),'ai-exit'):
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                pending={(tag,host):pool.submit(fetch,ports[tag],host) for tag in TAGS for host in HOSTS}
                for (tag,host),future in pending.items():
                    try:observations[tag,host]=future.result()
                    except Exception:observations[tag,host]={'error':'ai_trace_unavailable'}
    report={'schema':1,'checked_at':started,'expires_at':started+120,'routes':{},'targets':list(HOSTS)}
    for tag in TAGS:
        checks=[]
        for host in HOSTS:
            trace=observations[tag,host]
            try:
                origin=network(trace['ip'],cache);ok=valid_exit(tag,trace,origin)
                checks.append({'host':host,'ok':ok,'exit_ip':trace['ip'],'country':trace.get('loc'),
                    'asns':origin['asns'],'prefix':origin['prefix'],'reason':'verified_access_network' if ok else 'unexpected_ai_exit_network'})
            except Exception:checks.append({'host':host,'ok':False,'reason':'ai_exit_unverified'})
        report['routes'][tag]={'verified':all(x['ok'] for x in checks),'checks':checks}
    write(CACHE,cache);write(state,report)
    return report

if __name__=='__main__':
    value=collect();print(json.dumps({'checked_at':value['checked_at'],'routes':value['routes']}))
