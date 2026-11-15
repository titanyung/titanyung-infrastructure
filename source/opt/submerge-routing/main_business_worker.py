"""Single writer for main business selectors, using current physical exits.

No ordinary/test user credentials are read for probes. An isolated bounded
loopback native core copies only the currently validated physical transports.
Account intent and the actual main PID/API are independently guarded. The
published proof is read-only input for the regional pool gate controller.
"""
import argparse,concurrent.futures,copy,ipaddress,json,math,os,re,socket,subprocess,tempfile,time,urllib.request
from pathlib import Path
from policy_inputs import canonical,sha,need,policy,contract_module as c
from desired_accounts import Authority,DatabaseGenerationChanged
from main_guard import ActualMainGuard,set_business_selections
import ai_health_v4

STATE=Path('/var/lib/paoluz-pools/business-health.json')
COUNTRY={'direct':'US','bytevirt-hk':'HK','bytevirt-taiwan':'TW','lazycat-starhub':'SG','lazycat-hkt':'HK',
         'uzuma-singtel':'SG','uzuma-starhub':'SG','uzuma-hkt':'HK'}
REGION_SITES=('www.cloudflare.com','one.one.one.one')
AI_SITES=('chatgpt.com','claude.ai')
SAFE_ERROR_CODES=frozenset(('isolated_business_probe_native_check_failed','isolated_business_probe_exited',
    'isolated_business_probe_not_ready','owned_probe_directory_symlink','physical_probe_inventory_mismatch',
    'main_or_desired_generation_changed_during_physical_probe','verified_business_generation_required',
    'business_generation_changed','business_selector_not_confirmed','desired_account_ack_mismatch',
    'native_not_active','native_pid_missing','current_config_not_proven_loaded','main_api_not_private',
    'authenticated_api_not_owned_by_main_pid','actual_business_api_inventory_mismatch',
    'main_generation_changed_during_ack','main_pid_generation_changed'))

def public_error_code(error):
    code=str(error)
    # Matching an identifier regex does not establish that an exception body
    # is safe: a password/token may have exactly that shape.
    return code if code in SAFE_ERROR_CODES else type(error).__name__

def atomic(path,value):
    path=Path(path);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    need(not path.is_symlink(),'health_state_symlink')
    fd,temp=tempfile.mkstemp(prefix='.business-health-',dir=str(path.parent))
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(canonical(value));stream.flush();os.fsync(stream.fileno())
        os.replace(temp,path)
    finally:
        if os.path.exists(temp):os.unlink(temp)

def available_ports(count):
    sockets=[]
    try:
        for _ in range(count):
            sock=socket.socket();sock.bind(('127.0.0.1',0));sockets.append(sock)
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:sock.close()

def probe_config(source,ports):
    physical={row['tag']:copy.deepcopy(row) for row in source['outbounds'] if row['tag'] in c.PHYSICAL}
    need(set(ports)==set(physical),'physical_probe_inventory_mismatch')
    inlets=[];rules=[]
    for tag,port in ports.items():
        inlet='owned-business-'+tag
        inlets.append({'type':'mixed','tag':inlet,'listen':'127.0.0.1','listen_port':port})
        rules.append({'inbound':[inlet],'domain':list(AI_SITES+REGION_SITES),'action':'route','outbound':tag})
    # Direct monitoring uses the host resolver; SS sends the destination name
    # to its real peer resolver, so one Taiwan DNS path cannot fake all failures.
    physical['direct']['domain_resolver']={'server':'probe-system','strategy':'ipv4_only'}
    return {'log':{'level':'warn'},'dns':{'servers':[{'type':'local','tag':'probe-system'}],'final':'probe-system','strategy':'ipv4_only'},
        'inbounds':inlets,'outbounds':list(physical.values()),
        'route':{'rules':rules+[{'action':'reject'}],'final':'direct',
                 'default_domain_resolver':{'server':'probe-system','strategy':'ipv4_only'}}}

class ProbeCore:
    def __init__(self,binary,config,folder):self.binary=str(binary);self.config=config;self.folder=folder;self.process=None;self.log=None
    def __enter__(self):
        path=self.folder/'probe.json';path.write_bytes(canonical(self.config));path.chmod(0o600)
        checked=subprocess.run([self.binary,'check','-c',str(path)],capture_output=True,timeout=8)
        need(checked.returncode==0,'isolated_business_probe_native_check_failed')
        self.log=(self.folder/'private-core.log').open('wb')
        try:
            self.process=subprocess.Popen([self.binary,'run','-c',str(path)],stdin=subprocess.DEVNULL,
                stdout=self.log,stderr=self.log,start_new_session=True)
            deadline=time.monotonic()+4
            while True:
                need(self.process.poll() is None,'isolated_business_probe_exited')
                try:
                    with socket.create_connection(('127.0.0.1',self.config['inbounds'][0]['listen_port']),timeout=.1):return self
                except OSError:
                    if time.monotonic()>deadline:raise RuntimeError('isolated_business_probe_not_ready')
                    time.sleep(.05)
        except Exception:self.close();raise
    def close(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=2)
        if self.log:self.log.close()
    def __exit__(self,*args):self.close()

def fetch(port,site,folder,deadline):
    remaining=min(4.0,deadline-time.monotonic());started=time.monotonic()
    result={'site':site,'returncode':None,'status':'not_executed','observed_at':int(time.time())}
    if remaining<=.1:return dict(result,status='budget_exhausted',completed=False)
    path=folder/(str(port)+'-'+site+'.body')
    env={k:v for k,v in os.environ.items() if not k.upper().endswith('_PROXY')}
    args=['curl','-q','-4','--noproxy','','--socks5-hostname','127.0.0.1:'+str(port),'--silent','--fail',
          '--connect-timeout',str(min(2.0,remaining)),'--max-time',str(remaining),'--max-filesize','65536',
          '--output',str(path),'--write-out','%{json}','https://'+site+'/cdn-cgi/trace']
    try:
        value=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,env=env,timeout=remaining+.4)
        result.update(returncode=value.returncode,completed=value.returncode>=0,status='request_failed')
        if value.returncode==0:
            metric=json.loads(value.stdout);result.update(http_status=metric.get('http_code'),tls_verified=metric.get('ssl_verify_result')==0)
            if result['http_status']==200 and result['tls_verified']:
                rows={line.split('=',1)[0]:line.split('=',1)[1] for line in path.read_text().splitlines() if '=' in line}
                result.update(ip=rows.get('ip'),loc=rows.get('loc'),status='observed')
    except subprocess.TimeoutExpired:result.update(status='request_timeout',completed=True)
    except OSError:result.update(status='not_executed',completed=False)
    except (ValueError,UnicodeError):result.update(status='invalid_trace',completed=True)
    result.update(time_seconds=round(time.monotonic()-started,4),observed_at=int(time.time()))
    return result

def generic_state(checks,country,*,exact_ip=None):
    if not isinstance(checks,list) or len(checks)!=2:return 'unknown'
    states=[]
    for row in checks:
        if not isinstance(row,dict) or not row.get('completed') or (row.get('returncode') is not None and row['returncode']<0):states.append('unknown');continue
        try:address=ipaddress.ip_address(row.get('ip'))
        except (ValueError,TypeError):address=None
        authenticated=row.get('status')=='observed' and row.get('returncode')==0 and row.get('http_status')==200 \
            and row.get('tls_verified') is True
        # An authenticated but contradictory origin is not an availability
        # failure of one test site. Keep geographic/direct-IP safety decisive.
        if authenticated and address is not None and (not address.is_global or row.get('loc')!=country \
                or (exact_ip is not None and str(address)!=exact_ip)):
            return 'failed'
        okay=authenticated and address is not None and address.is_global and row.get('loc')==country \
            and (exact_ip is None or str(address)==exact_ip)
        states.append('healthy' if okay else 'failed')
    # A probe executor that did not run stays unknown. Once both attempts
    # completed, one verified regional trace proves generic route viability;
    # a single destination's TLS outage must not discard a usable default.
    return 'unknown' if 'unknown' in states else 'healthy' if 'healthy' in states else 'failed'

def lookup_origin(address,cache):
    now=int(time.time());old=cache.get(address,{})
    if 0<=now-old.get('checked_at',0)<3600:return old
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open('https://stat.ripe.net/data/network-info/data.json?resource='+address,timeout=3) as response:raw=response.read(65537)
    need(len(raw)<=65536,'origin_response_limit');value=json.loads(raw);data=value['data']
    need(value.get('status')=='ok' and ipaddress.ip_address(address) in ipaddress.ip_network(data['prefix']),'origin_prefix_not_verified')
    result={'asns':[str(n) for n in data['asns']],'prefix':data['prefix'],'checked_at':now}
    need(result['asns'],'origin_asn_missing');cache[address]=result;return result

def category_selection_scope(contract,observations):
    flat={tag:row['status']=='healthy' for tag,row in observations.items() if row['status']!='unknown'}
    generic={tag:row['generic_status']=='healthy' for tag,row in observations.items()
             if row.get('generic_status') in ('healthy','failed')}
    categories={name:copy.deepcopy(generic) for name in ('vps-lazycat','vps-uzuma')}
    only=[]
    for name,order in policy.selection_orders(contract).items():
        health=categories.get(name,flat);owned=order[:-1]
        if any(health.get(tag) is True for tag in owned) or all(health.get(tag) is False for tag in owned):
            only.append('business-'+name)
    return flat,categories,only

def business_paths(contract,observations):
    result={}
    for name,order in policy.selection_orders(contract).items():
        values={}
        for tag in order[:-1]:
            row=observations.get(tag,{})
            status=row.get('generic_status') if name in ('vps-lazycat','vps-uzuma') else row.get('status')
            status=status if status in ('healthy','failed','unknown') else 'unknown'
            # VPS ordinary traces are different observations, not duplicate
            # assertions made from an AI failure on the same physical VPS.
            checks=row.get('checks',[])
            relevant=checks[2:4] if name in ('vps-lazycat','vps-uzuma') and tag in c.PEERS else checks[:2]
            complete=len(relevant)==2 and all(x.get('completed') is True for x in relevant)
            values[tag]={'status':status,'completed':complete,'observed_at':row.get('observed_at',0)}
        result[name]={'owned':order[:-1],'observations':values,
                      'all_owned_failed':bool(values) and all(x['completed'] and x['status']=='failed' for x in values.values())}
    return result

def cycle(guard,binary,*,lookup=lookup_origin,origin_cache=None,write_selectors=True,temporary_root='/run/submerge-business-probe'):
    with guard.authority.lock():before=guard();snap=guard.authority.snapshot()
    source=snap['runtime'];contract=snap['plan']['server_policy']['routing_revision']
    tags=[row['tag'] for row in source['outbounds'] if row['tag'] in c.PHYSICAL]
    ports=dict(zip(tags,available_ports(len(tags))));observations={};cache=origin_cache if origin_cache is not None else {}
    parent=Path(temporary_root);need(not parent.is_symlink(),'owned_probe_directory_symlink')
    parent.mkdir(mode=0o700,parents=True,exist_ok=True);parent.chmod(0o700)
    with tempfile.TemporaryDirectory(prefix='main-business-probe-',dir=str(parent)) as name:
        folder=Path(name);folder.chmod(0o700)
        with ProbeCore(binary,probe_config(source,ports),folder):
            deadline=time.monotonic()+13
            def probe(tag):
                sites=AI_SITES+REGION_SITES if tag in c.PEERS else REGION_SITES
                return [fetch(ports[tag],site,folder,deadline) for site in sites]
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(8,len(tags))) as pool:
                measured=dict(zip(tags,pool.map(probe,tags)))
        ai_raw={'status':'completed','paths':[{'label':tag,'checks':measured[tag][:2]} for tag in c.PEERS]}
        qualified=ai_health_v4.qualify(ai_raw,cache,lookup=lookup,now=int(time.time()))
        by_ai={row['label']:row for row in qualified.get('paths',[])}
        for tag,checks in measured.items():
            if tag in c.PEERS:
                row=by_ai.get(tag,{});status={'healthy':'healthy','unhealthy':'failed','unknown':'unknown'}.get(row.get('health_state'),'unknown')
                # Ordinary VPS reachability is separate from a vendor's
                # AI-only residential split, using two real regional traces.
                generic=generic_state(checks[2:4],'SG') if len(checks)==4 else 'unknown'
            else:
                status=generic_state(checks,COUNTRY[tag],exact_ip='179.255.136.79' if tag=='direct' else None);generic=status
            observations[tag]={'status':status,'generic_status':generic,'completed':all(x.get('completed') is True for x in checks[:2]),
                'observed_at':max(x.get('observed_at',0) for x in checks),'source_generation':before['generation'],
                'checks':checks,'network_origins':by_ai.get(tag,{}).get('network_origins',[])}
    with guard.authority.lock():
        after=guard();need(after==before,'main_or_desired_generation_changed_during_physical_probe')
        flat,categories,only=category_selection_scope(contract,observations)
        result=None
        if write_selectors:
            import business_control
            result=business_control.set_selections(contract,flat,business_control.private_request(source),guard=guard,
                        category_health=categories,only=only)
    unknown=sorted(set('business-'+x for x in policy.selection_orders(contract))-set(only))
    return {'schema':1,'verified':True,'checked_at':int(time.time()),'main_ack':after,'observations':observations,
            'active_physical_tags':tags,'business_paths':business_paths(contract,observations),
            'selectors':result,'unknown_selectors_preserved':unknown,'classification_observations_complete':not unknown,
            'probe_user_credentials_used':False,'client_tun_or_mode_changed':False,'main_restarted':False,
            'temporary_core_cleaned':True,'regional_gate_writer':False,'direct_tag_scope':'dmit_only_LC_direct_is_separate_front_evidence'}

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',action='store_true');parser.add_argument('--once',action='store_true')
    parser.add_argument('--binary',default='/root/lazycat-test-config/sing-box');parser.add_argument('--binary-sha256')
    parser.add_argument('--state',default=str(STATE));parser.add_argument('--interval',type=int,default=30)
    args=parser.parse_args(argv)
    if not args.run:
        print(json.dumps({'status':'dry_run','network_requests':0,'selectors_changed':False}));return 0
    need(args.binary_sha256 and 15<=args.interval<=300,'explicit_binary_hash_and_bounded_interval_required')
    guard=ActualMainGuard(Authority(),rule_set_loader=policy.load_rule_sets,expected_binary_sha256=args.binary_sha256)
    cache={}
    for path in ('/var/lib/submerge-edge/origin-cache.json','/var/lib/paoluz-pools/business-origin-cache.json'):
        try:cache.update(json.loads(Path(path).read_bytes()))
        except (OSError,ValueError):pass
    while True:
        began=time.monotonic()
        try:
            result=cycle(guard,args.binary,origin_cache=cache)
            atomic(args.state,result);atomic(Path(args.state).with_name('business-origin-cache.json'),cache)
        except Exception as error:
            result={'schema':1,'verified':False,'checked_at':int(time.time()),'observations':{},'main_ack':None,
                    'status':'unknown','error_code':public_error_code(error),
                    'previous_selectors_preserved':True,'credentials_printed':False}
            atomic(args.state,result)
            # Read-only bind mounts pin their old inode across an atomic host
            # DB replacement. Fail closed, then let systemd rebuild the unit's
            # mount namespace instead of polling an obsolete authority forever.
            if isinstance(error,DatabaseGenerationChanged):return 78
        if args.once:print(json.dumps(result));return 0 if result['verified'] else 1
        time.sleep(max(1,args.interval-(time.monotonic()-began)))

if __name__=='__main__':raise SystemExit(main())
