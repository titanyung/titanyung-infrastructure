"""Fixed-inventory read-only host audit; never accepts a hostname from an HTTP request."""
import concurrent.futures,hashlib,json,os,subprocess,sys,tempfile,time
from pathlib import Path
ROOT=Path('/root/dmit-host-ingress-20261107')
sys.path[:0]=[str(ROOT),'/root/topology-20261105/dmit-routing-20261106']
from policy import TABLE,POLICY,DMIT4,DMIT6,render
from prepare_peers import ssh_inventory
os.umask(0o077)
NAMES={'hk':'Bytevirt HK ISP','tw':'Bytevirt HINET NAT','sg':'Lazycat starhub','hkt':'Lazycat HKT','singtel':'uzuma SG-Singtel1','zoro-sg':'zorocloud sptel'}

def normalized(document):
    result=[]
    for entry in document.get('nftables',[]):
        if 'metainfo' in entry:continue
        typ=next(iter(entry));value=dict(entry[typ]);value.pop('handle',None)
        if typ=='rule':value['expr']=[{'counter':{}} if 'counter' in x else x for x in value.get('expr',[])]
        result.append({typ:value})
    return result

def check(item):
    key,args=item;status={'key':key,'name':NAMES[key],'status':'unknown','scope':'代理、SSH、Web及其他入站服务',
        'allowed_ipv4':DMIT4+'/32','allowed_ipv6':DMIT6+'/128','ipv4':False,'ipv6':False,'persistent':False}
    try:
        def call(script):
            result=subprocess.run(args+[script],capture_output=True,timeout=18)
            if result.returncode:raise RuntimeError('peer_read_failed')
            return result.stdout
        owner=json.loads(call('cat /var/lib/dmit-host-ingress/committed.json'))
        live=json.loads(call('nft -j list table inet '+TABLE))
        reference=json.loads((ROOT/(key+'-kernel.json')).read_bytes())
        same=normalized(live)==normalized(reference)
        if key=='singtel':boot=bool(call('rc-service dmit-host-ingress status'))
        else:
            boot=call('systemctl is-enabled dmit-host-ingress.service && systemctl is-active dmit-host-ingress.service').decode().splitlines()==['enabled','active']
        sha=call('sha256sum /etc/dmit-host-ingress/create.nft').decode().split()[0]
        valid=owner.get('policy')==POLICY and sha==hashlib.sha256(render().encode()).hexdigest()
        status.update(status='protected' if same and boot and valid else 'attention',ipv4=same and valid,
            ipv6=same and valid,persistent=boot,configuration_matches=same and valid,
            verified_at=int(time.time()),last_forwarding_verification=owner.get('checked_at'),
            management_source=owner.get('management_source'),independent_test=owner.get('negative'),
            note='仅DMIT来源可访问；包含出站回包和必要网络控制报文' if same and boot and valid else '限制或开机加载与已验收版本不一致')
    except Exception as error:status.update(note='核查暂未完成，请查看管理连接或规则状态',error=type(error).__name__,verified_at=int(time.time()))
    return status

def main():
    from node_inventory import current,collect
    revision=current()
    if revision is not None:
        print(json.dumps(collect()));return
    commands=ssh_inventory(json.loads(Path('/var/lib/sg-traffic-dashboard/topology-20261105.json').read_bytes()),ROOT)
    commands['zoro-sg']=['ssh','-i','/root/.ssh/dmit-zoro-sg','-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile=/root/.ssh/known-hosts-zoro-sg','-o','ConnectTimeout=8','-p','23424','root@61.13.236.140']
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:rows=list(pool.map(check,commands.items()))
    result={'schema':1,'checked_at':int(time.time()),'policy':POLICY,'peers':rows,'read_only':True}
    dest=Path('/var/lib/submerge-security-center/nodes.json');dest.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd,temporary=tempfile.mkstemp(prefix='.nodes-',dir=str(dest.parent))
    try:
        with os.fdopen(fd,'w') as stream:
            os.fchmod(stream.fileno(),0o600);json.dump(result,stream,ensure_ascii=False);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,dest)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)
    print(json.dumps({'checked':len(rows),'protected':sum(r['status']=='protected' for r in rows)}))

if __name__=='__main__':main()
