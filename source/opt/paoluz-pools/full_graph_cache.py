"""Authorization-aware last-good full provider graph, one atomic generation.

The returned legacy provider remains {'proxies': ...}; the complete graph and
its source binding live in one private snapshot, never in separately mixed
node/group files. Importing/reading a snapshot never refreshes upstream.
"""
import copy,hashlib,ipaddress,json,os,stat,threading,time,urllib.parse
from contextlib import contextmanager
from pathlib import Path
import yaml
import paoluz_cache_legacy as legacy
import provider_pool as pool

_FULL_STATES={};_LOCK=threading.Lock();MAX_SNAPSHOT=legacy.MAX_BYTES*4

def _state(path):
    with _LOCK:
        return _FULL_STATES.setdefault(str(path.resolve()),{'lock':threading.Lock(),'document':None,'sha256':None,
          'last_attempt':None,'last_success':None,'snapshot':None,'disk_stamp':None})

def _read_private(path,limit=MAX_SNAPSHOT):
    path=Path(path);info=path.stat()
    pool.need(not path.is_symlink() and stat.S_ISREG(info.st_mode) and info.st_size<=limit,'full_graph_private_file')
    if hasattr(os,'geteuid') and os.geteuid()==0:
        pool.need(info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o600,'full_graph_root_private')
    return path.read_bytes(),(info.st_mtime_ns,info.st_size)

def _shape_nodes(nodes):
    pool.need(isinstance(nodes,list) and 0<len(nodes)<=legacy.MAX_NODES,'full_graph_usable_nodes_required')
    names={}
    for node in nodes:
        pool.need(isinstance(node,dict),'full_graph_node_object')
        name=node.get('name');kind=str(node.get('type','')).lower()
        pool.need(isinstance(name,str) and name.strip() and kind in legacy.SUPPORTED_TYPES,'full_graph_node_identity')
        if kind=='wireguard' and node.get('peers'):
            pool.need(isinstance(node['peers'],list),'full_graph_wireguard_peers')
        else:
            pool.need(isinstance(node.get('server'),str) and node['server'] and type(node.get('port')) is int and 0<node['port']<65536,'full_graph_node_endpoint')
            try:address=ipaddress.ip_address(node['server'])
            except ValueError:pass
            else:pool.need(address.is_global,'full_graph_private_literal_proxy_endpoint')
        pool.need(name not in names or names[name]==node,'full_graph_conflicting_node_names')
        names[name]=node
    return list(names.values())

def _graph_binding(graph):
    return {'nodes_sha256':pool.digest(graph['proxies']),
            'graph_sha256':pool.digest({k:graph[k] for k in ('proxy-groups','resolved_group_members','provider_auto_roots')})}

def make_snapshot(source,provider_snapshots,*,now,last_success=None,final_url=None,validator=None):
    graph=pool.materialize(source,provider_snapshots=provider_snapshots,now=int(now))
    _shape_nodes(graph['proxies'])
    if validator is not None:
        # The existing native parser receives the actual materialized graph,
        # without an HTTP provider or a synthetic replacement automatic group.
        carrier={'proxies':copy.deepcopy(graph['proxies']),'proxy-groups':[]}
        for group in copy.deepcopy(graph['proxy-groups']):
            name=group['name'];group['proxies']=graph['resolved_group_members'][name]
            for key in ('use','include-all','include-all-proxies','include-all-providers','filter','exclude-filter'):group.pop(key,None)
            carrier['proxy-groups'].append(group)
        pool.need(validator(carrier) is not False,'full_graph_native_validation_failed')
    binding={'source_sha256':pool.digest(source),'providers_sha256':pool.digest(provider_snapshots),**_graph_binding(graph)}
    snapshot={'schema':1,'revision':pool.REVISION,'snapshot_id':pool.digest(binding),**binding,
       'published_at':now,'last_success_at':last_success,'latest_resolved_upstream_url':final_url,
       'source_document':copy.deepcopy(source),'provider_snapshots':copy.deepcopy(provider_snapshots)}
    encoded=json.dumps(snapshot,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
    pool.need(len(encoded)<=MAX_SNAPSHOT,'full_graph_snapshot_size_limit')
    return snapshot,graph,encoded

def _verified_snapshot(snapshot,*,now):
    pool.need(isinstance(snapshot,dict) and snapshot.get('schema')==1 and snapshot.get('revision')==pool.REVISION,'full_graph_snapshot_schema')
    graph=pool.materialize(snapshot['source_document'],provider_snapshots=snapshot['provider_snapshots'],now=int(now))
    _shape_nodes(graph['proxies'])
    binding={'source_sha256':pool.digest(snapshot['source_document']),'providers_sha256':pool.digest(snapshot['provider_snapshots']),**_graph_binding(graph)}
    pool.need(all(snapshot.get(k)==v for k,v in binding.items()) and snapshot.get('snapshot_id')==pool.digest(binding),'full_graph_generation_binding')
    return graph

def read_client_snapshot(snapshot_path,qualification_path=None,now=None):
    """Trusted local descriptor reader. No fetcher, DNS or upstream access."""
    now=int(time.time() if now is None else now)
    raw,_=_read_private(snapshot_path);snapshot=json.loads(raw);baseline=_verified_snapshot(snapshot,now=now)
    qualifications={}
    if qualification_path is not None:
        try:
            qraw,_=_read_private(qualification_path,legacy.MAX_BYTES);value=json.loads(qraw)
            if isinstance(value,dict) and value.get('schema')==1:
                # A newly atomically published graph can precede its next
                # qualification round. Keep its complete current manual graph
                # usable; old qualification is unknown, never a failure/pass.
                qualifications=value.get('qualifications',{}) if value.get('snapshot_id')==snapshot['snapshot_id'] else {}
            elif isinstance(value,dict):qualifications=value
        except FileNotFoundError:pass
    pool.need(isinstance(qualifications,dict),'full_graph_qualification_map')
    for proxy in baseline['proxies']:
        if proxy.get('dialer-proxy') not in (None,'DIRECT') and qualifications.get(proxy['name'],{}).get('snapshot_id')!=snapshot['snapshot_id']:
            # Its effective path depends on the same-generation group graph,
            # not solely on the proxy's own server/password fields.
            qualifications.pop(proxy['name'],None)
    graph=pool.materialize(snapshot['source_document'],provider_snapshots=snapshot['provider_snapshots'],
                           qualifications=qualifications,now=now)
    graph.update(snapshot_id=snapshot['snapshot_id'],full_node_sha256=snapshot['nodes_sha256'],
                 original_graph_sha256=snapshot['graph_sha256'])
    return graph

@contextmanager
def _process_lock(path):
    path=Path(path);path.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
    fd=os.open(str(path),os.O_RDWR|os.O_CREAT,0o600);acquired=False
    try:
        if os.name=='nt':
            import msvcrt
            if os.fstat(fd).st_size==0:os.write(fd,b'0')
            os.lseek(fd,0,os.SEEK_SET)
            try:msvcrt.locking(fd,msvcrt.LK_NBLCK,1);acquired=True
            except OSError:pass
        else:
            import fcntl
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);acquired=True
            except BlockingIOError:pass
        yield acquired
    finally:
        if acquired:
            if os.name=='nt':
                os.lseek(fd,0,os.SEEK_SET);msvcrt.locking(fd,msvcrt.LK_UNLCK,1)
            else:fcntl.flock(fd,fcntl.LOCK_UN)
        os.close(fd)

class FullGraphPaoluzCache(legacy.PaoluzCache):
    def __init__(self,*args,snapshot_file=None,**kwargs):
        # New mode may not silently import the old 123-node seed when root's
        # accepted same-generation 118-node full graph has not been supplied.
        kwargs.setdefault('seed_file',None)
        super().__init__(*args,**kwargs)
        self.snapshot_file=Path(snapshot_file or str(self.cache_file)+'.full.snapshot.json')
        self.attempt_file=Path(str(self.snapshot_file)+'.attempt.json')
        self.lock_file=Path(str(self.snapshot_file)+'.refresh.lock')
        self._state=_state(self.snapshot_file)
        self._require_https=urllib.parse.urlsplit(self.upstream_url).scheme=='https'

    @property
    def snapshot_id(self):return (self._state.get('snapshot') or {}).get('snapshot_id')

    def _public_url(self,value):
        checked=super()._public_url(value);parsed=urllib.parse.urlsplit(checked)
        if getattr(self,'_require_https',False):pool.need(parsed.scheme=='https','full_graph_https_downgrade')
        pool.need(parsed.username is None and parsed.password is None,'full_graph_url_userinfo')
        return checked

    def _provider_snapshots(self,source,context,*,allow_fetch):
        providers=source.get('proxy-providers') or {};pool.need(isinstance(providers,dict),'full_graph_provider_definitions')
        snapshots={}
        def expand(document):
            nodes=list(document.get('proxies') or [])
            pool.need(isinstance(document.get('proxies',[]),list),'full_graph_provider_nodes')
            for name,definition in (document.get('proxy-providers') or {}).items():
                context['providers']+=1
                pool.need(context['providers']<=legacy.MAX_PROVIDERS and isinstance(definition,dict),'full_graph_provider_limit')
                if definition.get('type')=='inline':child={'proxies':definition.get('payload')}
                else:
                    pool.need(allow_fetch and definition.get('type')=='http','full_graph_authorized_provider_snapshot_required')
                    url=definition.get('url');pool.need(url not in context['visited'],'full_graph_provider_cycle')
                    context['visited'].add(url);child,_=self._fetch(url,context)
                pool.need(isinstance(child,dict),'full_graph_provider_document')
                child_nodes=expand(child);pool.need(len(nodes)+len(child_nodes)<=legacy.MAX_NODES,'full_graph_node_limit')
                nodes.extend(child_nodes)
            return _shape_nodes(nodes)
        for name,definition in providers.items():
            context['providers']+=1
            pool.need(context['providers']<=legacy.MAX_PROVIDERS and isinstance(definition,dict),'full_graph_provider_limit')
            if definition.get('type')=='inline':child={'proxies':definition.get('payload')}
            else:
                pool.need(allow_fetch and definition.get('type')=='http','full_graph_authorized_provider_snapshot_required')
                url=definition.get('url');pool.need(url not in context['visited'],'full_graph_provider_cycle')
                context['visited'].add(url);child,_=self._fetch(url,context)
            snapshots[name]={'proxies':expand(child)}
        return snapshots

    def _remember_snapshot(self,snapshot,graph):
        self._state['snapshot']=snapshot
        self._remember({'proxies':copy.deepcopy(graph['proxies'])},snapshot.get('last_success_at'))
        info=self.snapshot_file.stat();self._state['disk_stamp']=(info.st_mtime_ns,info.st_size)

    def _publish(self,source,providers,*,now,last_success=None,final_url=None):
        snapshot,graph,encoded=make_snapshot(source,providers,now=now,last_success=last_success,final_url=final_url,validator=self.validator)
        # This single file is authoritative. Mirrors never supply half a graph.
        legacy._atomic(self.snapshot_file,encoded)
        self._remember_snapshot(snapshot,graph)
        try:
            legacy._atomic(self.cache_file,self._serialize(self._state['document']))
            metadata={'schema':1,'last_success_at':last_success,'content_sha256':self.content_sha256,
                      'full_snapshot_id':snapshot['snapshot_id'],'latest_resolved_upstream_url':final_url}
            legacy._atomic(self.metadata_file,json.dumps(metadata,sort_keys=True).encode())
        except OSError:
            # Full snapshot/get() are still coherent; old mirrors are not read.
            pass

    def _load_existing(self):
        if self.snapshot_file.is_file():
            info=self.snapshot_file.stat();stamp=(info.st_mtime_ns,info.st_size)
            if self._state['document'] is not None and self._state['disk_stamp']==stamp:return
            raw,_=_read_private(self.snapshot_file);snapshot=json.loads(raw)
            graph=_verified_snapshot(snapshot,now=self.clock());self._remember_snapshot(snapshot,graph);return
        if self._state['document'] is not None:return
        if self.seed_file is not None and self.seed_file.is_file():
            raw,_=_read_private(self.seed_file,legacy.MAX_BYTES);source=yaml.safe_load(raw)
            pool.need(isinstance(source,dict),'full_graph_seed_document')
            providers=self._provider_snapshots(source,{'providers':0,'visited':set(),'bytes':len(raw),'deadline':time.monotonic()},allow_fetch=False)
            self._publish(source,providers,now=self.clock())

    def get(self,refresh=True,authorized=None):
        state=self._state;locked=state['lock'].acquire(blocking=False)
        if not locked:
            if state['document'] is not None:return copy.deepcopy(state['document'])
            locked=state['lock'].acquire(timeout=self.timeout+.5)
            if not locked:raise legacy.CacheUnavailable('Paoluz full graph unavailable')
        try:
            self.last_refresh_succeeded=False
            try:self._load_existing()
            except Exception as error:self.last_error=type(error).__name__
            now=self.clock();due=state['last_attempt'] is None or now-state['last_attempt']>=self.refresh_guard
            if refresh and authorized is not False and due:
                with _process_lock(self.lock_file) as acquired:
                    if acquired:
                        attempt=None
                        try:attempt=json.loads(_read_private(self.attempt_file,65536)[0]).get('attempt_at')
                        except (OSError,ValueError,KeyError):pass
                        if not isinstance(attempt,(int,float)) or now-attempt>=self.refresh_guard:
                            state['last_attempt']=now
                            legacy._atomic(self.attempt_file,json.dumps({'attempt_at':now}).encode())
                            try:
                                context={'providers':0,'visited':{self.upstream_url},'bytes':0,'deadline':time.monotonic()+self.timeout}
                                source,final_url=self._fetch(self.upstream_url,context)
                                providers=self._provider_snapshots(source,context,allow_fetch=True)
                                self._publish(source,providers,now=now,last_success=now,final_url=final_url)
                                self.last_error=None;self.last_refresh_succeeded=True
                            except Exception as error:self.last_error=type(error).__name__
                        else:
                            state['last_attempt']=attempt
                            try:self._load_existing()
                            except Exception:pass
            if state['document'] is None:raise legacy.CacheUnavailable('Paoluz full graph unavailable')
            return copy.deepcopy(state['document'])
        finally:state['lock'].release()
