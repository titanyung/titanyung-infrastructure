"""DMIT observer of actual V4 native/account ACK and owned route health.

Only fixed trusted registry/source paths are used. Unknown status/SSH/old V3
evidence never becomes a failure. Optional business control writes ONLY the
new main server's business-* selectors, never a client's/global network mode.
"""
import argparse,concurrent.futures,contextlib,hashlib,json,os,re,subprocess,sys,time,urllib.error,urllib.parse,urllib.request
from pathlib import Path
import full_graph_cache as files
import provider_pool as pool

PHYSICAL_IDS={'direct':'dmit','bytevirt-hk':'dmit_bytevirt_hk','bytevirt-taiwan':'dmit_bytevirt_tw',
 'lazycat-starhub':'dmit_lazycat_starhub','lazycat-hkt':'dmit_lazycat_hkt','uzuma-singtel':'dmit_singtel',
 'uzuma-starhub':'dmit_uzuma_starhub','uzuma-hkt':'dmit_uzuma_hkt'}

def business_paths_from_orders(orders):
    """Use the main selector's exact owned members, in its own namespace.

    A physical VPS delay observation is different from a front's residential
    AI qualification. It cannot authorize the SG airport gate, and the AI
    qualification must not hide completed physical failures for VPS fallback.
    """
    def owned(name,region):
        order=orders[name]
        pool.need(isinstance(order,list) and len(order)>1 and order[-1]=='paoluz-'+region.lower()+'-fallback'
            and all(tag in PHYSICAL_IDS for tag in order[:-1]) and len(order)==len(set(order)),'business_owned_order_shape')
        return ['main_'+PHYSICAL_IDS[tag] for tag in order[:-1]]
    return {'mytvsuper':owned('mytvsuper','HK'),'viu':owned('hk-other','HK'),'other':owned('other','ALL'),
            'vps':[owned(name,'ALL') for name in ('vps-bytevirt','vps-lazycat','vps-uzuma')]}

def bound_business_inputs(orders,payload,*,now,generation):
    """Consume exact per-business observations chosen by the sole writer.

    VPS StarHub/Singtel generic reachability is distinct from AI residential
    qualification. Raw SG status cannot overwrite the category's own proof.
    """
    business_paths_from_orders(orders)  # Validate the authoritative member shape.
    categories={'mytvsuper':['mytvsuper'],'viu':['hk-other'],'other':['other'],
                'vps':['vps-bytevirt','vps-lazycat','vps-uzuma']}
    result={};observations={}
    for category,names in categories.items():
        branches=[]
        for name in names:
            owned=orders[name][:-1];proof=payload.get(name,{}) if isinstance(payload,dict) else {}
            same=proof.get('owned')==owned and isinstance(proof.get('observations'),dict)
            branch=[]
            for tag in owned:
                route='business_'+name+'__'+PHYSICAL_IDS[tag];branch.append(route)
                row=proof['observations'].get(tag,{}) if same else {};stamp=row.get('observed_at')
                valid=(bool(generation) and row.get('completed') is True and row.get('status') in ('healthy','failed')
                    and type(stamp) in (int,float) and -1<=now-stamp<=90)
                observations[route]=({'status':row['status'],'completed':True,'observed_at':int(stamp),'source_generation':generation}
                    if valid else {'status':'unknown','completed':False,'observed_at':now})
            branches.append(branch)
        result[category]=branches if category=='vps' else branches[0]
    return observations,result

def read_business_proof(path,main,*,now):
    """Only the main-business single writer supplies physical health states."""
    unknown={route:{'status':'unknown','completed':False,'observed_at':now} for route in PHYSICAL_IDS.values()}
    try:
        raw,_=files._read_private(path,2*1024*1024);value=json.loads(raw);ack=value.get('main_ack',{})
        pool.need(value.get('schema')==1 and value.get('verified') is True and type(value.get('checked_at')) in (int,float)
            and -1<=now-value['checked_at']<=90,'pool_business_source_unknown')
        pool.need(ack.get('verified') is True and ack.get('runtime_sha256')==main['runtime_sha256'] and ack.get('cohort_sha256')==main['cohort_sha256'],
                  'pool_business_source_stale_authority')
        if 'main_pid' in ack:pool.need(ack['main_pid']==main['pid'],'pool_business_source_process_changed')
        elif 'pid' in ack:pool.need(ack['pid']==main['pid'],'pool_business_source_process_changed')
        rows=value.get('observations',{});pool.need(isinstance(rows,dict),'pool_business_observation_shape')
        for tag,route in PHYSICAL_IDS.items():
            row=rows.get(tag,{})
            stamp=row.get('observed_at')
            if (row.get('completed') is True and row.get('status') in ('healthy','failed') and
                type(stamp) in (int,float) and -1<=now-stamp<=90):
                unknown[route]=dict(row,observed_at=int(stamp),source_generation=ack['generation'])
        return unknown,{'verified':True,'source_sha256':hashlib.sha256(raw).hexdigest(),'checked_at':value['checked_at'],
                        'generation':ack['generation'],'business_paths':value.get('business_paths',{})}
    except Exception:return unknown,{'verified':False,'status':'unknown'}

def native_delay_probe(config,tag,*,now=None):
    """v1.14.3 GET /proxies/name/delay: 504 or its exact 503 is a real test.

    Primary API source: SagerNet/sing-box/v1.14.3/experimental/clashapi/proxies.go
    All other API/unavailable/malformed responses are unknown, not failure.
    """
    now=int(time.time() if now is None else now);unknown={'status':'unknown','completed':False,'observed_at':now}
    api=config['experimental']['clash_api'];address=api.get('external_controller','')
    pool.need(address.startswith('127.0.0.1:') and isinstance(api.get('secret'),str),'main_private_api_required')
    pool.need(any(r.get('tag')==tag for r in config['outbounds']),'owned_physical_outbound_required')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}));base='http://'+address
    def request(path):
        req=urllib.request.Request(base+path,headers={'Authorization':'Bearer '+api['secret']})
        with opener.open(req,timeout=7) as response:raw=response.read(8193)
        pool.need(len(raw)<=8192,'owned_probe_response_limit');return json.loads(raw)
    delay_attempted=False
    try:
        meta=request('/proxies/'+urllib.parse.quote(tag,safe=''))
        if meta.get('name')!=tag:return unknown
        delay_attempted=True
        value=request('/proxies/'+urllib.parse.quote(tag,safe='')+'/delay?'+urllib.parse.urlencode({'url':'https://www.gstatic.com/generate_204','timeout':5000}))
        if type(value.get('delay')) is int and value['delay']>0:return {'status':'healthy','completed':True,'observed_at':now,'delay_ms':value['delay']}
    except urllib.error.HTTPError as error:
        try:body=json.loads(error.read(8193))
        except Exception:return unknown
        if delay_attempted and (error.code==504 or error.code==503 and body.get('message')=='An error occurred in the delay test'):
            return {'status':'failed','completed':True,'observed_at':now,'basis':'executed_native_delay_test'}
    except Exception:pass
    return unknown

def _main_identity(runtime,binary,plan,*,network):
    raw,_=files._read_private(runtime,16*1024*1024);config=json.loads(raw)
    network.validate_loaded_server_policy(config,plan)
    from edge_bundle import _cohort
    cohort=_cohort(config['inbounds']);matches=[]
    for path in Path('/proc').glob('[0-9]*'):
        try:
            args=path.joinpath('cmdline').read_bytes().split(b'\0')
            if str(runtime).encode() in args and path.joinpath('exe').resolve()==Path(binary).resolve():matches.append(int(path.name))
        except OSError:continue
    pool.need(len(matches)==1,'main_running_process_ambiguous')
    from edge_apply import verify_process
    verify_process(matches[0],binary,runtime)
    stat_fields=Path('/proc/'+str(matches[0])+'/stat').read_text().rsplit(')',1)[1].split()
    ticks=int(stat_fields[19]);uptime=float(Path('/proc/uptime').read_text().split()[0])
    started=time.time()-uptime+ticks/os.sysconf('SC_CLK_TCK')
    pool.need(Path(runtime).stat().st_mtime<=started+1,'main_config_newer_than_running_process')
    return config,{'verified':True,'generation':'native-'+hashlib.sha256(raw).hexdigest()[:24],
       'cohort_sha256':cohort['cohort_sha256'],'runtime_sha256':hashlib.sha256(raw).hexdigest(),
       'pid':matches[0],'process_start_ticks':ticks,'checked_at':int(time.time())}

@contextlib.contextmanager
def _read_edge_lock(path):
    import fcntl
    stream=Path(path).open('a+b');os.fchmod(stream.fileno(),0o600)
    try:
        deadline=time.monotonic()+10
        while True:
            try:fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB);break
            except BlockingIOError:
                remaining=deadline-time.monotonic()
                if remaining<=0:raise RuntimeError('edge_publication_busy') from None
                time.sleep(min(0.2,remaining))
        yield
    finally:stream.close()

def _front(edge,controller,authority,contract,main,*,state_dir,now):
    name='dmit' if edge.get('execution')=='local_authority' else 'lazycat'
    unknown={'verified':False,'checked_at':now,'proof':{'qualification_state':'unknown','checked_at':now}}
    if edge.get('ai_pool_version')!=4:return name,unknown
    try:
        with _read_edge_lock(state_dir/(edge['edge_id']+'.lock')):
            state=controller.private_json(state_dir/(edge['edge_id']+'.json'))
            manifest=state['confirmed_manifest'];ack=state['last_ack']
            pool.need(manifest.get('routing_revision')==contract and manifest.get('routing_execution_front')==name,'front_v4_manifest_contract')
            pool.need(state.get('pending_generation') is None and state.get('confirmed_input_sha256')==authority.fingerprint(edge),'front_current_authority_not_acknowledged')
            transport=controller.transport_for(edge);loaded=transport.status()
            pool.need(loaded.get('verified') is True and loaded.get('generation')==ack['generation']==manifest['generation'] and
                loaded.get('manifest_sha256')==ack['manifest_sha256'] and loaded.get('cohort_sha256')==main['cohort_sha256']==manifest['accounts']['cohort_sha256']
                and loaded.get('health_state_matches') is True,'front_actual_loaded_ack_mismatch')
            rows=[r for r in manifest['files'] if r['path']==manifest['config_path']];pool.need(len(rows)==1,'front_native_runtime_descriptor')
            out={'verified':True,'generation':loaded['generation'],'manifest_sha256':loaded['manifest_sha256'],
                 'cohort_sha256':loaded['cohort_sha256'],'runtime_sha256':rows[0]['sha256'],'checked_at':now,
                 'proof':{'qualification_state':'unknown','checked_at':now}}
            health=state.get('last_health',{});proof=health.get('proof',{});attempt=state.get('last_health_attempt',{})
            bound=(health.get('generation')==out['generation'] and health.get('manifest_sha256')==out['manifest_sha256'] and
                   health.get('cohort_sha256')==out['cohort_sha256'] and health.get('runtime_sha256')==out['runtime_sha256'] and
                   health.get('mode')==loaded.get('mode') and type(health.get('checked_at')) in (int,float) and 0<=now-health['checked_at']<=90)
            unknown_after=attempt.get('status')=='unknown' and attempt.get('checked_at',0)>health.get('checked_at',0)
            if bound and not unknown_after:out['proof']=proof
            out['actual_v4']=True
            if name=='lazycat':
                script='import json,sys;sys.path.insert(0,"/usr/local/lib/lazycat-edge");from pool_native_probe import run;print(json.dumps(run(sys.argv[1],sys.argv[2])))'
                # pool_native_probe is a tiny standard-library helper; root
                # installs only this file on LC, never the Mihomo pool worker.
                try:out['direct_probe']=transport.command(['python3','-c',script,str(Path(edge['install_root'])/'current'/manifest['config_path']),'direct'],timeout=12)
                except Exception:out['direct_probe']={'status':'unknown','completed':False,'observed_at':now}
            return name,out
    except Exception:return name,unknown

def observe(*,runtime,main_binary,plan_path,registry_path,state_dir,apply_business=False,
            business_proof_path=Path('/var/lib/paoluz-pools/business-health.json'),development_native_probe=False):
    now=int(time.time());result={'schema':1,'revision':pool.REVISION,'verified':False,'checked_at':now,
      'main_ack':{},'fronts':{},'owned_observations':{},'business_paths':{}}
    try:
        import network_runtime as network
        import edge_controller as controller
        import routing_contract as contract_module
        import server_route_policy as server_policy
        plan=network.load_network_plan(plan_path)
        pool.need(plan.get('plan')=='network-plan-20261109','pool_new_main_policy_not_active')
        contract=contract_module.validate(plan['server_policy']['routing_revision'])
        registry_raw=Path(registry_path).read_bytes();edges=controller.registry(registry_path)
        edges=[e for e in edges if e.get('scope')=='ai']
        pool.need(len(edges)==2 and all(e.get('ai_pool_version')==4 for e in edges),'pool_v4_fronts_not_active')
        config,main=_main_identity(runtime,main_binary,plan,network=network);result['main_ack']=main
        authority=controller.Authority(runtime=runtime,plan=plan_path,binary=main_binary)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as threads:
            fronts=dict(threads.map(lambda edge:_front(edge,controller,authority,contract,main,state_dir=Path(state_dir),now=now),edges))
        result['fronts']=fronts
        # Actual V4 manifests/ACKs, not registry intent alone, are required.
        pool.need(set(fronts)=={'dmit','lazycat'} and all(r.get('actual_v4') is True for r in fronts.values()),'pool_actual_v4_ack_unavailable')
        observations=pool.normalize_sg_observations(fronts,now=now)
        physical,business_source=read_business_proof(business_proof_path,main,now=now)
        # SG qualification comes only from the two exact V4 source fronts;
        # a generic physical delay must never override residential-AI proof.
        for route,row in physical.items():
            observations['main_'+route]=row
            if route not in pool.SG_ROUTES:observations[route]=row
        result['business_health_source']=business_source
        if development_native_probe:
            tags=[tag for tag in ('direct','bytevirt-hk','bytevirt-taiwan','lazycat-hkt','uzuma-hkt') if any(r['tag']==tag for r in config['outbounds'])]
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as threads:
                probes=dict(zip(tags,threads.map(lambda tag:native_delay_probe(config,tag,now=now),tags)))
            for tag,row in probes.items():observations[PHYSICAL_IDS[tag]]=dict(row,source_generation=main['generation'])
        direct=fronts['lazycat'].get('direct_probe',{'status':'unknown','completed':False,'observed_at':now})
        observations['lazycat_sg']=dict(direct,source_generation=fronts['lazycat']['generation'])
        business_observations,result['business_paths']=bound_business_inputs(server_policy.selection_orders(contract),
            business_source.get('business_paths',{}),now=now,generation=business_source.get('generation'))
        observations.update(business_observations)
        result['owned_observations']=observations
        def main_guard():
            _,again=_main_identity(runtime,main_binary,plan,network=network)
            pool.need(all(again.get(k)==main[k] for k in ('generation','cohort_sha256','runtime_sha256','pid','process_start_ticks')) and Path(registry_path).read_bytes()==registry_raw,'pool_main_authority_changed')
            return {k:main[k] for k in ('verified','generation','cohort_sha256','runtime_sha256')}
        main_guard()
        if apply_business:
            import business_control
            health={tag:observations[route]['status']=='healthy' for tag,route in PHYSICAL_IDS.items()
                    if route in observations and observations[route].get('completed') is True and observations[route].get('status') in ('healthy','failed')}
            result['business_control']=business_control.set_selections(contract,health,business_control.private_request(config),guard=main_guard)
        result.update(verified=True,checked_at=int(time.time()))
    except Exception as error:
        code=str(error)
        result.update(verified=False,error=code if re.fullmatch('[a-z0-9_]{1,100}',code) else type(error).__name__,checked_at=int(time.time()))
    return result

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--runtime',default='/run/dmit-direct-staging/config.json');parser.add_argument('--main-binary',default='/root/lazycat-test-config/sing-box')
    parser.add_argument('--plan',default='/etc/submerge-topology/network-plan.json');parser.add_argument('--registry',default='/etc/submerge-edge/edges.json')
    parser.add_argument('--state-dir',default='/var/lib/submerge-edge');parser.add_argument('--output',default='/var/lib/paoluz-pools/control-proof.json')
    parser.add_argument('--business-proof-path',default='/var/lib/paoluz-pools/business-health.json')
    parser.add_argument('--edge-module-dir',default='/opt/submerge-edge');parser.add_argument('--network-module-dir',default='/opt/submerge-topology')
    parser.add_argument('--once',action='store_true');parser.add_argument('--apply-business-selections',action='store_true')
    parser.add_argument('--development-native-probe',action='store_true');args=parser.parse_args()
    sys.path[:0]=[args.edge_module_dir,args.network_module_dir]
    while True:
        value=observe(runtime=Path(args.runtime),main_binary=Path(args.main_binary),plan_path=Path(args.plan),registry_path=Path(args.registry),state_dir=Path(args.state_dir),apply_business=args.apply_business_selections,
            business_proof_path=Path(args.business_proof_path),development_native_probe=args.development_native_probe)
        files.legacy._atomic(Path(args.output),json.dumps(value,sort_keys=True).encode())
        print(json.dumps({'current_authority':value['verified'],'checked_at':value['checked_at'],'fronts':{k:r.get('verified') for k,r in value['fronts'].items()},'error':value.get('error')}),flush=True)
        if args.once:break
        time.sleep(15)

if __name__=='__main__':main()
