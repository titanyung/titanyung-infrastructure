"""Read-only node defence audit from the root-owned release inventory.

No host/command/expected-rule data comes from an HTTP request. Each result
requires actual kernel equality, persistent-file hash, owner and boot guard.
"""
import concurrent.futures,copy,hashlib,ipaddress,json,os,re,shlex,stat,subprocess,tempfile,time
from pathlib import Path,PurePosixPath
REVISION='routing-revision-20261109-v1'
MANIFEST=Path('/var/lib/sg-traffic-dashboard/topology-20261105.json')

def need(value,code):
    if not value:raise ValueError(code)

def private_json(path,limit=4*1024*1024):
    p=Path(path);info=p.stat()
    need(not p.is_symlink() and stat.S_ISREG(info.st_mode) and info.st_size<=limit,'node_inventory_private_file')
    if hasattr(os,'geteuid') and os.geteuid()==0:need(info.st_uid==0 and not info.st_mode&0o077,'node_inventory_root_private')
    return json.loads(p.read_bytes())

def current(path=MANIFEST,now=None):
    if not Path(path).is_file():
        marker=Path('/etc/submerge-topology/network-plan.json')
        if marker.is_file() and private_json(marker).get('plan')=='network-plan-20261109':raise ValueError('node_inventory_new_plan_manifest_missing')
        return None
    manifest=private_json(path)
    if manifest.get('routing_revision')!=REVISION:return None
    spec=copy.deepcopy(manifest['node_protection_inventory'])
    if spec.get('schema')==2:
        import accepted_node_inventory
        return accepted_node_inventory.current(manifest,spec,now=now)
    need(spec.get('schema')==1 and spec.get('revision')==REVISION,'node_inventory_schema')
    need(isinstance(spec.get('policy'),str) and spec['policy'],'node_inventory_policy')
    for field,version in (('allowed_ipv4',4),('allowed_ipv6',6)):
        need(isinstance(spec.get(field),list),'node_inventory_sources')
        for cidr in spec[field]:
            net=ipaddress.ip_network(cidr,strict=True)
            need(net.version==version and net.prefixlen==(32 if version==4 else 128) and net.network_address.is_global,'node_inventory_specific_sources')
    need(spec['allowed_ipv4'],'node_inventory_ipv4_sources_required')
    need(len(spec['allowed_ipv4'])==2 and 1<=len(spec['allowed_ipv6'])<=2,'node_inventory_two_fronts_only')
    peers=spec.get('peers');need(isinstance(peers,dict),'node_inventory_peers')
    rows=manifest['revision_inventory']['servers'];epoch=manifest['inventory_epoch']
    declared={h for h,row in rows.items() if row['monitoring_state']=='active' and
              h not in ('DMIT','Lazycat-SG-Front') and (row['retire_at'] is None or epoch<row['retire_at'])}
    need({row.get('host') for row in peers.values()}==declared and len(peers)==len(declared),'node_inventory_exact_leaf_set')
    now=int(time.time() if now is None else now)
    for key,row in list(peers.items()):
        need(isinstance(key,str) and re.fullmatch('[A-Za-z0-9_-]{1,64}',key),'node_inventory_key')
        argv=row.get('ssh_argv');need(isinstance(argv,list) and argv and argv[0]=='ssh' and all(isinstance(v,str) and v for v in argv),'node_inventory_ssh_argv')
        options=' '.join(argv)
        need('StrictHostKeyChecking=yes' in options and 'BatchMode=yes' in options and 'IdentitiesOnly=yes' in options,'node_inventory_pinned_management_required')
        need(re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,63}',row.get('nft_table','')),'node_inventory_table')
        for path_key in ('expected_kernel_json_path','persistent_file_path','owner_path'):
            path=PurePosixPath(row[path_key]);need(path.is_absolute() and '..' not in path.parts and str(path).startswith(('/root/','/var/lib/','/etc/')) and not any(c in str(path) for c in ('\n','\r')),'node_inventory_approved_path')
        need(re.fullmatch('[0-9a-f]{64}',row.get('persistent_sha256','')),'node_inventory_persistent_hash')
        need(row.get('boot_kind') in ('systemd','openrc') and re.fullmatch('[A-Za-z0-9_.@-]{1,96}',row.get('boot_service','')),'node_inventory_boot_guard')
        mode=row.get('access_mode','public_sources')
        need(mode in ('public_sources','reverse_only'),'node_inventory_access_mode')
        if mode=='reverse_only':
            need(row['host']=='Uzuma-HKT','node_inventory_explicit_hkt_reverse_only')
            for field in ('proxy_config_path','reverse_only_evidence_path'):
                value=PurePosixPath(row[field]);need(value.is_absolute() and '..' not in value.parts and str(value).startswith(('/root/','/etc/','/var/lib/')),'node_inventory_reverse_path')
            for field in ('proxy_listen_port','reverse_local_port'):
                need(type(row.get(field)) is int and 1024<=row[field]<=65535,'node_inventory_reverse_port')
            binding=manifest.get('reverse_transports',{}).get('uzuma-hkt',{})
            need(binding.get('access_mode')=='reverse_only' and binding.get('server')=='127.0.0.1'
                 and binding.get('server_port')==row['reverse_local_port'],'node_inventory_statistics_reverse_binding')
            need(row.get('reverse_boot_kind') in ('systemd','openrc') and re.fullmatch('[A-Za-z0-9_.@-]{1,96}',row.get('reverse_boot_service','')),'node_inventory_reverse_boot')
        host=rows[row['host']]
        if host['retire_at'] is not None and now>=host['retire_at']:peers.pop(key)
    return spec

def expected_keys(path=MANIFEST,now=None):
    spec=current(path,now)
    return set(spec['peers']) if spec is not None else None

def normalized(document):
    result=[]
    for entry in document.get('nftables',[]):
        if 'metainfo' in entry:continue
        typ=next(iter(entry));value=dict(entry[typ]);value.pop('handle',None)
        if typ=='rule':value['expr']=[{'counter':{}} if 'counter' in x else x for x in value.get('expr',[])]
        result.append({typ:value})
    return result

def _reverse_listener(port):
    result=subprocess.run(['ss','-H','-lntp'],capture_output=True,text=True,timeout=5)
    need(result.returncode==0,'reverse_listener_unavailable')
    matches=[line.split()[3] for line in result.stdout.splitlines() if len(line.split())>=5 and line.split()[3].endswith(':'+str(port))]
    return matches==['127.0.0.1:'+str(port)]

def check_peer(key,row,spec,*,call=None,read_reference=private_json,local_reverse_probe=_reverse_listener):
    if row.get('verification_kind')=='accepted_committed_v2':
        import accepted_node_inventory
        return accepted_node_inventory.check_peer(key,row,spec,call=call,local_reverse_probe=local_reverse_probe)
    reverse_only=row.get('access_mode')=='reverse_only'
    status={'key':key,'name':row['name'],'host':row['host'],'status':'unknown','scope':'代理、SSH、Web及其他入站服务',
       'access_mode':row.get('access_mode','public_sources'),
       'allowed_ipv4':'无公网入站；仅经 DMIT 中转' if reverse_only else ', '.join(spec['allowed_ipv4']),
       'allowed_ipv6':'无公网入站' if reverse_only else ', '.join(spec['allowed_ipv6']),
       'ipv4':False,'ipv6':False,'persistent':False,'policy':spec['policy']}
    def remote(script):
        p=subprocess.run(row['ssh_argv']+[script],capture_output=True,timeout=18)
        need(p.returncode==0 and len(p.stdout)<=2*1024*1024,'node_read_failed');return p.stdout
    call=call or remote
    try:
        reference=read_reference(row['expected_kernel_json_path'])
        owner=json.loads(call('cat '+shlex.quote(row['owner_path'])))
        live=json.loads(call('nft -j list table inet '+row['nft_table']))
        same=normalized(live)==normalized(reference)
        sha=call('sha256sum '+shlex.quote(row['persistent_file_path'])).decode().split()[0]
        if row['boot_kind']=='systemd':
            boot=call('systemctl is-enabled '+row['boot_service']+' && systemctl is-active '+row['boot_service']).decode().splitlines()==['enabled','active']
        else:boot=bool(call('rc-service '+row['boot_service']+' status'))
        valid=owner.get('policy')==row.get('owner_policy',spec['policy']) and sha==row['persistent_sha256']
        reverse_valid=True
        if reverse_only:
            evidence=read_reference(row['reverse_only_evidence_path'])
            canonical=hashlib.sha256(json.dumps(normalized(live),sort_keys=True,separators=(',',':')).encode()).hexdigest()
            reverse_valid=(evidence.get('access_mode')=='reverse_only' and evidence.get('kernel_normalized_sha256')==canonical
                and all(evidence.get(field) is True for field in ('public_ipv4_tcp_rejected','public_ipv6_tcp_rejected','native_loopback_only_verified','reverse_transport_verified')))
            config=json.loads(call('cat '+shlex.quote(row['proxy_config_path'])))
            inlets=config.get('inbounds',[])
            reverse_valid=bool(reverse_valid and inlets and all(p.get('listen')=='127.0.0.1' for p in inlets)
                and any(p.get('type')=='shadowsocks' and p.get('listen_port')==row['proxy_listen_port'] for p in inlets)
                and local_reverse_probe(row['reverse_local_port']))
            if row['reverse_boot_kind']=='systemd':
                reverse_boot=call('systemctl is-enabled '+row['reverse_boot_service']+' && systemctl is-active '+row['reverse_boot_service']).decode().splitlines()==['enabled','active']
            else:reverse_boot=bool(call('rc-service '+row['reverse_boot_service']+' status'))
            reverse_valid=reverse_valid and reverse_boot
            status.update(reverse_service_active=reverse_boot,reverse_transport=reverse_valid,
                          public_tcp_blocked=bool(same and valid and reverse_valid))
        valid=valid and reverse_valid
        status.update(status='protected' if same and valid and boot else 'attention',ipv4=same and valid,ipv6=same and valid,
            persistent=boot,configuration_matches=same and valid,verified_at=int(time.time()),
            note=('仅经 DMIT 中转；公网 TCP 入站已拒绝，代理仅监听回环地址' if reverse_only else '仅 DMIT、Lazycat SG 来源可访问；保留出站回包和必要网络控制报文') if same and valid and boot else '当前入站规则或开机加载与已验收版本不一致')
    except Exception as error:status.update(error=type(error).__name__,verified_at=int(time.time()),note='核查暂未完成，请查看管理连接或规则状态')
    return status

def collect(path=MANIFEST,destination=Path('/var/lib/submerge-security-center/nodes.json')):
    spec=current(path);need(spec is not None,'node_revision_required')
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        rows=list(pool.map(lambda item:check_peer(item[0],item[1],spec),spec['peers'].items()))
    report={'schema':1,'routing_revision':REVISION,'checked_at':int(time.time()),'policy':spec['policy'],'peers':rows,'read_only':True}
    destination=Path(destination);destination.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
    fd,temporary=tempfile.mkstemp(prefix='.nodes-',dir=str(destination.parent))
    try:
        with os.fdopen(fd,'w') as stream:
            os.fchmod(stream.fileno(),0o600);json.dump(report,stream,ensure_ascii=False);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,destination)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)
    return {'checked':len(rows),'protected':sum(r['status']=='protected' for r in rows)}
