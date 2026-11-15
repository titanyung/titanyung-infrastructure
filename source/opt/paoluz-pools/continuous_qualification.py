"""DMIT-only bounded qualification rotation and optional sole gate owner.

No upstream fetch or remote SSH. The root publisher owns the full graph; an
independent root observer owns current native/account authority proof. This
worker can never turn missing/stale evidence into 'all routes failed'.
"""
import argparse,copy,hashlib,json,os,queue,re,signal,subprocess,threading,time
from pathlib import Path
import yaml
import full_graph_cache as full
import provider_pool as policy
from pool_control import private_request,qualify,apply_gates

def read_control_proof(path,*,now,max_age=45):
    raw,_=full._read_private(path,2*1024*1024);value=json.loads(raw)
    policy.need(value.get('schema')==1 and value.get('revision')==policy.REVISION and value.get('verified') is True,'pool_current_authority_schema')
    stamp=value.get('checked_at')
    policy.need(type(stamp) is int and 0<=now-stamp<=max_age,'pool_current_authority_stale')
    main=value.get('main_ack',{});stamp=main.get('checked_at')
    policy.need(main.get('verified') is True and type(stamp) is int and 0<=now-stamp<=max_age and
        all(main.get(k) for k in ('generation','cohort_sha256','runtime_sha256')),'pool_current_main_ack_required')
    policy.need(isinstance(value.get('fronts'),dict) and isinstance(value.get('owned_observations'),dict) and isinstance(value.get('business_paths'),dict),'pool_current_authority_inputs')
    for front in value['fronts'].values():
        if isinstance(front,dict) and front.get('verified') is True:
            policy.need(front.get('cohort_sha256')==main['cohort_sha256'],'pool_current_cohort_mismatch')
    return value,hashlib.sha256(raw).hexdigest()

def _hash_file(path):
    digest=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):digest.update(chunk)
    return digest.hexdigest()

def probe_layout(config):
    rows=[r for r in config.get('listeners',[]) if str(r.get('proxy','')).startswith('PAOLUZ_QUALIFICATION_PROBE')]
    policy.need(1<=len(rows)<=4,'pool_dedicated_probe_inventory')
    allowed={'PAOLUZ_QUALIFICATION_PROBE',*(f'PAOLUZ_QUALIFICATION_PROBE_{i}' for i in range(4))}
    policy.need(all(r.get('listen')=='127.0.0.1' and r.get('udp') is False and r.get('proxy') in allowed for r in rows),'pool_dedicated_local_probes')
    policy.need(len({r['port'] for r in rows})==len(rows) and len({r['proxy'] for r in rows})==len(rows),'pool_probe_collision')
    return [(r['port'],r['proxy']) for r in rows]

class Worker:
    def __init__(self,*,binary,config_path,snapshot_path,qualification_path,materialized_path,
                 pool_unit,control_proof_path=None,period=300,native_check=True):
        policy.need(re.fullmatch('[A-Za-z0-9_.@-]{1,100}',pool_unit),'fixed_pool_service_required')
        policy.need(180<=period<=450,'bounded_qualification_period')
        self.binary=Path(binary);self.config_path=Path(config_path);self.snapshot_path=Path(snapshot_path)
        self.qualification_path=Path(qualification_path);self.materialized_path=Path(materialized_path)
        self.pool_unit=pool_unit;self.control_proof_path=Path(control_proof_path) if control_proof_path else None
        self.period=period;self.native_check=native_check;self.stop=threading.Event()
        raw,_=full._read_private(self.config_path);self.config=yaml.safe_load(raw);self.config_hash=hashlib.sha256(raw).hexdigest()
        self.probes=probe_layout(self.config);self.request=private_request(self.config)
        self.condition=threading.Condition();self.reloading=False;self.active=0
        self.results_lock=threading.Lock();self.results={};self.source=None;self.graph=None;self.source_stamp=None
        self.jobs=queue.Queue(maxsize=1024);self.queued=set();self.last_reload=0;self.threads=[]
        self.queue_lock=threading.Lock()
        try:
            value=json.loads(full._read_private(self.qualification_path,10*1024*1024)[0])
            self.results=value.get('qualifications',{}) if value.get('schema')==1 else value
        except (OSError,ValueError,AttributeError):pass

    def close_gates(self):
        for region in policy.REGIONS:
            try:self.request('PUT','/proxies/'+policy.GATES[region],{'name':'REJECT'})
            except Exception:pass

    def runtime_guard(self):
        raw,_=full._read_private(self.config_path)
        policy.need(hashlib.sha256(raw).hexdigest()==self.config_hash,'pool_runtime_config_changed')
        result=subprocess.run(['systemctl','show',self.pool_unit,'-p','MainPID,ActiveState'],capture_output=True,text=True,timeout=5)
        fields=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
        pid=int(fields.get('MainPID',0));policy.need(result.returncode==0 and fields.get('ActiveState')=='active' and pid>0,'pool_runtime_not_active')
        command=Path('/proc/'+str(pid)+'/cmdline').read_bytes().split(b'\0')
        policy.need(str(self.binary).encode() in command and str(self.config_path).encode() in command,'pool_runtime_process_not_owned')
        started=Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()[19]
        return {'verified':True,'config_sha256':self.config_hash,'process_identity':str(pid)+':'+started}

    def _cache(self,now):
        with self.results_lock:proofs=copy.deepcopy(self.results)
        for proxy in self.graph['proxies']:
            if proxy.get('dialer-proxy') not in (None,'DIRECT') and proofs.get(proxy['name'],{}).get('snapshot_id')!=self.source['snapshot_id']:
                proofs.pop(proxy['name'],None)
        cache=policy.materialize(self.source['source_document'],provider_snapshots=self.source['provider_snapshots'],qualifications=proofs,now=now)
        cache.update(snapshot_id=self.source['snapshot_id'],full_node_sha256=self.source['nodes_sha256'],original_graph_sha256=self.source['graph_sha256'])
        return cache

    def _compiled_members(self):
        groups={g['name']:g for g in self.config['proxy-groups']}
        return {r:[n[len('UPSTREAM::'):] for n in groups[policy.FAST[r]]['proxies'] if n.startswith('UPSTREAM::')] for r in policy.REGIONS}

    def _verify_loaded(self,config):
        groups={g['name']:g for g in config['proxy-groups']}
        for region in policy.REGIONS:
            actual=self.request('GET','/proxies/'+policy.FAST[region])
            policy.need(actual.get('all')==groups[policy.FAST[region]]['proxies'],'pool_reload_group_members_differ')
            policy.need(self.request('GET','/proxies/'+policy.GATES[region]).get('now')=='REJECT','pool_reload_gate_not_closed')
        for _,tag in probe_layout(config):
            self.request('PUT','/proxies/'+tag,{'name':'REJECT'})
            policy.need(self.request('GET','/proxies/'+tag).get('now')=='REJECT','pool_reload_probe_not_closed')

    def _reload(self,cache):
        with self.condition:
            self.reloading=True
            if not self.condition.wait_for(lambda:self.active==0,timeout=30):
                self.reloading=False;self.condition.notify_all();raise RuntimeError('pool_probe_drain_timeout')
        previous=self.config_path.read_bytes();old_config=self.config;self.close_gates()
        try:
            pools={r:{'server':'127.0.0.1','server_port':next(x['port'] for x in self.config['listeners'] if x.get('proxy')==policy.GATES[r])} for r in policy.REGIONS}
            config=policy.render_mihomo(cache,pools=pools,api_port=int(self.config['external-controller'].split(':')[1]),
                api_secret=self.config['secret'],probe_ports=[p for p,_ in self.probes])
            encoded=yaml.safe_dump(config,allow_unicode=True,sort_keys=False).encode()
            candidate=self.config_path.with_name(self.config_path.name+'.candidate-'+str(os.getpid()))
            full.legacy._atomic(candidate,encoded)
            try:
                if self.native_check:
                    checked=subprocess.run([str(self.binary),'-t','-d',str(self.config_path.parent),'-f',str(candidate)],capture_output=True,timeout=30)
                    policy.need(checked.returncode==0,'pool_native_configuration_rejected')
                full.legacy._atomic(self.config_path,encoded)
                self.request('PUT','/configs?force=true',{'path':str(self.config_path)})
                self._verify_loaded(config)
                self.config=config;self.config_hash=hashlib.sha256(encoded).hexdigest();self.last_reload=time.monotonic()
            except Exception:
                full.legacy._atomic(self.config_path,previous)
                try:
                    self.request('PUT','/configs?force=true',{'path':str(self.config_path)})
                    self._verify_loaded(old_config)
                finally:self.close_gates()
                raise
            finally:
                try:candidate.unlink()
                except FileNotFoundError:pass
        finally:
            with self.condition:self.reloading=False;self.condition.notify_all()

    def _load_source(self,now):
        raw,stamp=full._read_private(self.snapshot_path)
        if stamp==self.source_stamp:return False
        source=json.loads(raw);graph=full._verified_snapshot(source,now=now)
        changed=self.source is None or source['snapshot_id']!=self.source['snapshot_id']
        if changed:
            # Stop claims based on a preceding graph before switching input.
            self.close_gates()
            with self.condition:
                self.reloading=True
                if not self.condition.wait_for(lambda:self.active==0,timeout=30):
                    self.reloading=False;self.condition.notify_all();raise RuntimeError('pool_source_probe_drain_timeout')
            previous_source,previous_graph=self.source,self.graph
            with self.results_lock:previous_results=copy.deepcopy(self.results)
            try:
                self.source=source;self.graph=graph
                with self.results_lock:
                    expected={p['name']:policy.digest(p) for p in graph['proxies']}
                    self.results={name:q for name,q in self.results.items() if q.get('node_sha256')==expected.get(name)}
                self._reload(self._cache(now))
            except Exception:
                self.source,self.graph=previous_source,previous_graph
                with self.results_lock:self.results=previous_results
                raise
            finally:
                with self.condition:self.reloading=False;self.condition.notify_all()
        self.source_stamp=stamp
        return changed

    def _probe_loop(self,port,selector):
        while not self.stop.is_set():
            try:job=self.jobs.get(timeout=.5)
            except queue.Empty:continue
            sid,proxy=job;key=(sid,proxy['name'])
            try:
                with self.condition:
                    self.condition.wait_for(lambda:not self.reloading or self.stop.is_set())
                    if self.stop.is_set() or self.source is None or sid!=self.source['snapshot_id']:continue
                    self.active+=1
                try:
                    expected=self.runtime_guard()
                    stamp=self.source_stamp
                    def guard():
                        policy.need(self.source['snapshot_id']==sid and self.snapshot_path.stat().st_mtime_ns==stamp[0],'pool_qualification_source_changed')
                        actual=self.runtime_guard();policy.need(actual==expected,'pool_qualification_runtime_changed');return actual
                    result=qualify(proxy,request=self.request,socks_port=port,selector_tag=selector,guard=guard)
                    result['snapshot_id']=sid
                    with self.results_lock:self.results[proxy['name']]=result
                finally:
                    with self.condition:self.active-=1;self.condition.notify_all()
            except Exception:
                # Unknown preserves the preceding qualified proof only until
                # its original TTL. No fabricated fresh failure is produced.
                pass
            finally:
                with self.queue_lock:self.queued.discard(key)
                self.jobs.task_done()

    def _schedule(self,now):
        candidates=set(self.graph['region_probe_candidates']['SG']+self.graph['region_probe_candidates']['HK'])
        proxies=sorted(self.graph['proxies'],key=lambda p:p['name'] not in candidates)
        for proxy in proxies:
            key=(self.source['snapshot_id'],proxy['name']);q=self.results.get(proxy['name'],{})
            with self.queue_lock:
                if key not in self.queued and (q.get('node_sha256')!=policy.digest(proxy) or now-q.get('checked_at',0)>=self.period):
                    self.queued.add(key)
                    try:self.jobs.put_nowait((key[0],copy.deepcopy(proxy)))
                    except queue.Full:self.queued.discard(key);break

    def _publish(self,cache,now):
        with self.results_lock:proofs=copy.deepcopy(self.results)
        # The graph reader binds each subscription to the exact qualification
        # file bytes. Replacing the file every five seconds only to refresh the
        # envelope timestamp invalidates a fresh subscription during its own
        # verification. Per-node proof timestamps still enforce the 600-second
        # qualification TTL; materialized.json remains the five-second status
        # heartbeat below.
        try:previous=json.loads(full._read_private(self.qualification_path,10*1024*1024)[0])
        except FileNotFoundError:previous=None
        if previous is not None:
            policy.need(isinstance(previous,dict) and
                set(previous)=={'schema','snapshot_id','checked_at','qualifications'} and
                previous['schema']==1 and isinstance(previous['snapshot_id'],str) and
                type(previous['checked_at']) is int and
                isinstance(previous['qualifications'],dict),'pool_qualification_publication_source_invalid')
        if (previous is None or previous.get('snapshot_id')!=self.source['snapshot_id'] or
                previous['qualifications']!=proofs):
            full.legacy._atomic(self.qualification_path,json.dumps({'schema':1,
                'snapshot_id':self.source['snapshot_id'],'checked_at':now,
                'qualifications':proofs},ensure_ascii=False).encode())
        full.legacy._atomic(self.materialized_path,json.dumps(cache,ensure_ascii=False).encode())

    def _control(self,cache,now):
        if self.control_proof_path is None:return
        try:
            current,digest=read_control_proof(self.control_proof_path,now=now)
            decisions=policy.gate_decisions(cache,fronts=current['fronts'],owned_observations=current['owned_observations'],business_paths=current['business_paths'],now=now)
            compiled=self._compiled_members()
            for r in policy.REGIONS:
                if compiled[r]!=decisions[r]['qualified_members']:decisions[r]['selected']='REJECT'
            def guard():
                actual,observed=read_control_proof(self.control_proof_path,now=int(time.time()))
                policy.need(observed==digest,'pool_current_authority_changed')
                return dict(self.runtime_guard(),authority_sha256=observed)
            apply_gates(decisions,self.request,guard=guard)
        except Exception:self.close_gates()

    def run(self):
        self.close_gates()
        for port,selector in self.probes:
            thread=threading.Thread(target=self._probe_loop,args=(port,selector),daemon=True);thread.start();self.threads.append(thread)
        try:
            while not self.stop.is_set():
                now=int(time.time())
                try:
                    self._load_source(now);cache=self._cache(now);self._publish(cache,now)
                    if policy.pool_members(cache)!=self._compiled_members():
                        self.close_gates()
                        if time.monotonic()-self.last_reload>=30:self._reload(cache)
                    self._control(cache,now);self._schedule(now)
                except Exception:self.close_gates()
                self.stop.wait(5)
        finally:
            self.stop.set();self.close_gates()
            with self.condition:self.condition.notify_all()
            for thread in self.threads:thread.join(timeout=10)
            for _,tag in self.probes:
                try:self.request('PUT','/proxies/'+tag,{'name':'REJECT'})
                except Exception:pass

    def once(self):
        now=int(time.time());self.close_gates();self._load_source(now);cache=self._cache(now)
        self._publish(cache,now);self._control(cache,now)
        return self.status()

    def status(self):
        graph=full.read_client_snapshot(self.snapshot_path,self.qualification_path)
        gates={}
        for region in policy.REGIONS:
            try:gates[region]=self.request('GET','/proxies/'+policy.GATES[region]).get('now')
            except Exception:gates[region]='unknown'
        try:authority=read_control_proof(self.control_proof_path,now=int(time.time()))[0] if self.control_proof_path else None
        except Exception:authority=None
        return {'schema':1,'checked_at':int(time.time()),'snapshot_id':graph['snapshot_id'],'provider_nodes':len(graph['proxies']),
            'original_groups':len(graph['proxy-groups']),'original_auto_roots':len(graph['provider_auto_roots']),
            'current_qualified':{r:len(v) for r,v in policy.pool_members(graph).items()},
            'compiled_qualified':{r:len(v) for r,v in self._compiled_members().items()},'gates':gates,
            'current_authority':authority is not None,'qualification_workers':len(self.probes),
            'upstream_fetch_performed':False,'client_or_tun_mode_changed':False}

def main():
    parser=argparse.ArgumentParser()
    for name in ('binary','config-path','snapshot-path','qualification-path','materialized-path','pool-unit','expected-binary-sha256'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--control-proof-path');parser.add_argument('--period',type=int,default=300)
    mode=parser.add_mutually_exclusive_group();mode.add_argument('--once',action='store_true');mode.add_argument('--status',action='store_true');args=parser.parse_args()
    policy.need(hasattr(os,'geteuid') and os.geteuid()==0,'root_dmit_worker_required')
    policy.need(_hash_file(args.binary)==args.expected_binary_sha256,'reviewed_mihomo_binary_required')
    worker=Worker(binary=args.binary,config_path=args.config_path,snapshot_path=args.snapshot_path,qualification_path=args.qualification_path,
       materialized_path=args.materialized_path,pool_unit=args.pool_unit,control_proof_path=args.control_proof_path,period=args.period)
    for signum in (signal.SIGTERM,signal.SIGINT):signal.signal(signum,lambda *_:worker.stop.set())
    if args.status:print(json.dumps(worker.status()));return
    with full._process_lock(Path(args.materialized_path).with_suffix('.worker.lock')) as acquired:
        policy.need(acquired,'single_pool_worker_required')
        if args.once:print(json.dumps(worker.once()))
        else:worker.run()

if __name__=='__main__':main()
