"""Initial client publication owner. Default dry-run; no client/TUN mode writes.

Static prerequisites and compatibility readers may be installed while the
current plan is legacy and the delivery gate is disabled. Only a later explicit
activation, backed by actual main and both V4 enforcement ACKs, enables it.
"""
import argparse,contextlib,copy,hashlib,importlib.util,json,os,re,stat,subprocess,sys,tempfile,time,urllib.error,urllib.parse,urllib.request
from pathlib import Path,PurePosixPath
from prepared_restart import private,atomic

ROOT='/root/routing-revision-20261109'
STATE='/var/lib/submerge-topology/client-bootstrap.json'
GATE='/etc/submerge-topology/routing-client-20261109.json'
PLAN='/etc/submerge-topology/network-plan.json'
MAIN='/run/dmit-direct-staging/config.json'
REGISTRY='/etc/submerge-edge/edges.json'
SETTINGS='/etc/submerge-edge/client-settings.json'
MAP='/etc/nginx/conf.d/submerge-delivery-format-map.conf'
MODULE_DIRS={'/opt/submerge-routing','/opt/submerge-topology','/opt/submerge-edge',
             '/opt/submerge-user-access','/opt/submerge-client-policy','/usr/local/lib/lazycat-edge'}
SCRIPTS={'topology':'/opt/submerge-topology/topology_server.py','gateway':'/opt/submerge-user-access/delivery_gateway.py'}
EXPECTED_UNITS={'topology':'submerge.service','gateway':'submerge-user-access.service'}
STATIC_TARGETS={'/etc/submerge-topology/routing-contract-20261109.json',
    '/etc/submerge-topology/routing-client-bindings-20261109.json','/etc/submerge-topology/routing-sites-20261109.json',
    '/etc/systemd/system/submerge.service.d/zz-routing-client-20261109.conf'}
NATIVE_SHA='768d31fa7f68debc067bb4626539498a1e8751d36a7b99e1a54bee6a23815f93'
DISABLED={'schema':1,'revision':'routing-revision-20261109-v1','enabled':False}
OPERATION_PHASE='preflight'

def need(value,code):
    if not value:raise RuntimeError(code)
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(path):return json.loads(private(path))

def posix(path):
    need(isinstance(path,str) and '\\' not in path and '\n' not in path and PurePosixPath(path).is_absolute()
         and '..' not in PurePosixPath(path).parts,'client_bootstrap_absolute_posix_path_required')
    return Path(path)

def regular(path):
    p=posix(str(path));info=p.stat()
    need(not p.is_symlink() and stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_size<8*1024*1024,
         'client_bootstrap_regular_root_source_required')
    return p.read_bytes()

def hash_file(path):
    return sha(regular(path)) if Path(path).exists() else None

def write(path,raw,mode=0o600,uid=0,gid=0):
    path=posix(str(path));need(not path.is_symlink(),'client_bootstrap_target_symlink')
    need(all(not parent.is_symlink() for parent in path.parents),'client_bootstrap_parent_symlink')
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix='.client-bootstrap-',dir=str(path.parent))
    try:
        with os.fdopen(fd,'wb') as stream:
            os.fchmod(stream.fileno(),mode);os.fchown(stream.fileno(),uid,gid)
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
        os.replace(name,path)
    finally:
        if os.path.exists(name):os.unlink(name)

def command(argv,*,timeout=30):
    result=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=timeout)
    need(result.returncode==0,'client_bootstrap_external_command_failed')
    return result.stdout

def descriptor(path,expected_sha256):
    p=posix(path);need(str(p).startswith(ROOT+'/client-gate-inputs-'),'client_bootstrap_prepared_descriptor_path')
    raw=private(p);need(sha(raw)==expected_sha256,'client_bootstrap_reviewed_descriptor_hash_required')
    value=json.loads(raw)
    need(value.get('schema')==1 and value.get('kind')=='client-gate-env-prepared'
         and value.get('revision')==DISABLED['revision'],'client_bootstrap_prepared_schema')
    need(value['private_paths']['client_gate']==GATE and value['private_paths']['client_settings']==SETTINGS,
         'client_bootstrap_fixed_gate_and_readonly_settings')
    need(set(value['service_roles'])==set(SCRIPTS),'client_bootstrap_exact_subscription_roles')
    for role,row in value['service_roles'].items():
        need(row['unit']==EXPECTED_UNITS[role] and row['script']==SCRIPTS[role],'client_bootstrap_actual_subscription_owner_changed')
    allowed={value['private_paths'][key] for key in ('client_gate','client_contract','client_bindings','client_sites','topology_env_dropin')}
    need(allowed==STATIC_TARGETS|{GATE},'client_bootstrap_exact_static_production_paths')
    need(len(value['artifacts'])==5 and {row['target'] for row in value['artifacts']}==allowed,
         'client_bootstrap_exact_five_artifacts')
    need(sum(row['activation_order']==2 for row in value['artifacts'])==1
         and all(row['activation_order'] in (1,2) for row in value['artifacts']),
         'client_bootstrap_gate_must_be_sole_last_artifact')
    for row in value['artifacts']:
        target=posix(row['target']);source=posix(row['candidate_path'])
        need(source.parent==p.parent,'client_bootstrap_candidate_must_be_in_reviewed_bundle')
        need(sha(private(source))==row['after_sha256'],'client_bootstrap_candidate_hash')
        need((row['activation_order']==2)==(str(target)==GATE),'client_bootstrap_gate_activation_order')
    return value

def helper(tools_dir,expected_sha256):
    installed_reader_paths()
    root=posix(tools_dir)
    need(root.parent==Path(ROOT) and re.fullmatch('client-gate-tools-[a-f0-9]{12}',root.name)
         and not root.is_symlink(),'client_bootstrap_reviewed_tools_directory')
    source=root/'client_activation_inputs.py'
    need(sha(private(source))==expected_sha256,'client_bootstrap_helper_source_hash')
    spec=importlib.util.spec_from_file_location('client_bootstrap_reviewed_inputs',source)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

def fences(value):
    for path,expected in value['source_fences'].items():
        need(hash_file(path)==expected,'client_bootstrap_source_fence_changed')
    need(load(GATE).get('enabled') is False if Path(GATE).exists() else True,'client_bootstrap_gate_must_be_disabled')

def code_priority(path):
    name=Path(path).name
    if name.endswith('_legacy.py'):return 0,name,path
    if name in ('routing_contract.py','transport_bridges.py','domain_destination_override.py'):return 1,name,path
    order=('edge_ai_policy.py','edge_ai_policy_v2.py','edge_ai_policy_v3.py','edge_ai_policy_v4.py',
           'starhub_selection.py','starhub_selection_v3.py','starhub_selection_v4.py',
           'server_route_policy.py','network_runtime.py','edge_bundle.py','edge_apply.py','edge_status.py',
           'policy_inputs.py','desired_accounts.py','main_guard.py','main_policy_cas.py')
    return (2,order.index(name),path) if name in order else (3,name,path)

def preinstall_readers(stage,spec_sha256,backup):
    stage=posix(stage);need(stage.parent==Path(ROOT) and stage.name=='main-release-v5','client_bootstrap_exact_main_stage')
    raw=private(stage/'spec.json');need(sha(raw)==spec_sha256,'client_bootstrap_main_spec_hash')
    spec=json.loads(raw);need(spec.get('stage')==str(stage) and spec.get('kind')=='main-v4-stage','client_bootstrap_reviewed_main_spec')
    need(load(PLAN).get('plan')!='network-plan-20261109','client_bootstrap_compatibility_preinstall_requires_legacy_plan')
    rows=[]
    for path,row in spec['files'].items():
        if not path.endswith('.py'):continue
        p=posix(path);need(str(p.parent) in MODULE_DIRS,'client_bootstrap_unreviewed_python_target')
        source=stage/'files'/row['file'];need(source.parent==stage/'files','client_bootstrap_scoped_stage_source')
        data=private(source);need(sha(data)==row['sha256'],'client_bootstrap_policy_payload_hash')
        compile(data,path,'exec')
        observed=hash_file(path);need(observed in (row['expected'],row['sha256']),'client_bootstrap_policy_reader_source_cas')
        rows.append((path,row,data,observed))
    need(rows,'client_bootstrap_reviewed_python_sources_missing')
    journal=[]
    for index,(path,row,data,before) in enumerate(sorted(rows,key=lambda entry:code_priority(entry[0]))):
        current=hash_file(path);need(current in (before,row['sha256']),'client_bootstrap_reader_changed_during_preinstall')
        target=Path(path);info=target.stat() if target.exists() else None
        if current is not None:
            write(backup/('reader-'+str(index)+'.before'),regular(path))
        if current!=row['sha256']:
            write(path,data,row['mode'],info.st_uid if info else 0,info.st_gid if info else 0)
        need(hash_file(path)==row['sha256'],'client_bootstrap_reader_hash_after_install')
        journal.append({'target':path,'before_sha256':before,'after_sha256':row['sha256']})
    return {'verified':True,'stage':str(stage),'spec_sha256':spec_sha256,'python_files':len(journal),'files':journal,
        'units_config_native_plan_runtime_or_registry_changed':False}

def static_install(value,*,descriptor_path,descriptor_sha256,main_stage=None,main_spec_sha256=None):
    fences(value)
    protected=(PLAN,MAIN,REGISTRY,SETTINGS,MAP)
    before={path:hash_file(path) for path in protected}
    folder=Path(ROOT)/('client-bootstrap-static-'+str(time.time_ns()));folder.mkdir(mode=0o700)
    gate_before=hash_file(GATE)
    rows=[];reader_proof=None
    if main_stage is not None:
        need(main_spec_sha256 is not None,'client_bootstrap_explicit_main_spec_hash')
        reader_proof=preinstall_readers(main_stage,main_spec_sha256,folder)
    for index,row in enumerate(item for item in value['artifacts'] if item['activation_order']==1):
        path=Path(row['target']);current=hash_file(path)
        need(current in (row['before_sha256'],row['after_sha256']),'client_bootstrap_static_source_cas')
        source=private(row['candidate_path']);need(sha(source)==row['after_sha256'],'client_bootstrap_static_candidate_changed')
        info=path.stat() if path.exists() else None
        if current is not None:write(folder/(str(index)+'.before'),regular(path))
        rows.append({'target':row['target'],'before_sha256':current,'after_sha256':row['after_sha256'],
            'before':str(folder/(str(index)+'.before')),'mode':stat.S_IMODE(info.st_mode) if info else row['mode'],
            'uid':info.st_uid if info else 0,'gid':info.st_gid if info else 0,'changed':False})
    journal={'schema':1,'phase':'installing_static_gate_disabled','descriptor':descriptor_path,'descriptor_sha256':descriptor_sha256,
             'job':str(folder),'gate_before_sha256':gate_before,'rows':rows,'policy_readers':reader_proof}
    write(folder/'journal.json',canonical(journal))
    try:
        if gate_before is None:write(GATE,canonical(DISABLED))
        for row in rows:
            path=row['target'];need(hash_file(path)==row['before_sha256'],'client_bootstrap_static_changed_before_write')
            if row['before_sha256']==row['after_sha256']:continue
            candidate=next(item for item in value['artifacts'] if item['target']==path)
            row['changed']=True;write(folder/'journal.json',canonical(journal))
            write(path,private(candidate['candidate_path']),candidate['mode'],row['uid'],row['gid'])
        need(load(GATE).get('enabled') is False,'client_bootstrap_gate_was_not_kept_disabled')
        need(before=={path:hash_file(path) for path in protected},'client_bootstrap_protected_authority_changed')
        command(['nginx','-t'],timeout=20)
    except Exception:
        for row in reversed(rows):
            if row['changed'] and hash_file(row['target'])==row['after_sha256']:
                if row['before_sha256'] is None:Path(row['target']).unlink()
                else:write(row['target'],private(row['before']),row['mode'],row['uid'],row['gid'])
        journal.update(phase='static_failed_gate_disabled');write(folder/'journal.json',canonical(journal));raise
    journal.update(phase='static_ready_gate_disabled',checked_at=int(time.time()),
        current_gate_sha256=hash_file(GATE),services_restarted=False,nginx_reloaded=False)
    write(folder/'journal.json',canonical(journal));write(STATE,canonical(journal))
    return {'status':journal['phase'],'job':str(folder),'static_files':len(rows),
        'policy_python_files_preinstalled':reader_proof['python_files'] if reader_proof else 0,
        'gate_enabled':False,'services_restarted':False,'native_account_authority_changed':False}

def wait_subscription_owner(value,inputs,role,*,guard,timeout=20):
    """Type=simple may ACK before exec; require two stable, exact observations."""
    unit=value['service_roles'][role]['unit'];deadline=time.monotonic()+timeout
    expected_env=({'TOPOLOGY_FULL_GRAPH_SEED_FILE':value['private_paths']['full_graph_seed'],
        'TOPOLOGY_FULL_GRAPH_SNAPSHOT_FILE':value['private_paths']['full_graph_snapshot']} if role=='topology' else {})
    previous=None
    while time.monotonic()<deadline:
        guard()
        try:actual=inputs.discover_service(SCRIPTS[role])
        except (FileNotFoundError,ProcessLookupError):actual=None
        except (ValueError,RuntimeError) as error:
            if str(error) not in ('exact_single_actual_service_script_owner_required','actual_python_owner_must_be_active',
                                 'actual_script_unit_binding_required','actual_service_owner_unavailable'):raise
            actual=None
        if actual is not None:
            need(actual['unit']==unit and actual['main_pid']>0,'client_bootstrap_reloaded_owner_mismatch')
            for path,digest in value['service_roles'][role]['unit_file_hashes'].items():
                need(actual['unit_file_hashes'].get(path)==digest,'client_bootstrap_reloaded_base_unit_changed')
            if actual['selected_effective_environment']==expected_env:
                current=canonical(actual)
                if current==previous:return actual
                previous=current
            else:previous=None
        else:previous=None
        remaining=deadline-time.monotonic()
        if remaining>0:time.sleep(min(.15,remaining))
    raise RuntimeError('client_bootstrap_reloaded_owner_not_stable_before_deadline')


def reload_subscriptions(value,inputs):
    state=load(STATE);need(state['phase'] in ('static_ready_gate_disabled','activation_failed'),'client_bootstrap_static_phase_required')
    need(state['descriptor_sha256']==sha(private(state['descriptor'])),'client_bootstrap_static_descriptor_changed')
    fences(value)
    need(state.get('policy_readers',{}).get('verified') is True,'client_bootstrap_compatibility_readers_required_before_restart')
    for row in state['policy_readers']['files']:
        need(hash_file(row['target'])==row['after_sha256'],'client_bootstrap_preinstalled_reader_drift')
    for role,row in value['service_roles'].items():
        actual=inputs.discover_service(SCRIPTS[role]);need(actual['unit']==row['unit'],'client_bootstrap_subscription_owner_changed')
        for path,digest in row['unit_file_hashes'].items():need(actual['unit_file_hashes'].get(path)==digest,'client_bootstrap_base_unit_changed')
    protected={path:hash_file(path) for path in (PLAN,MAIN,REGISTRY,SETTINGS,MAP)}
    def guard():
        need(protected=={path:hash_file(path) for path in protected},'client_bootstrap_reload_changed_native_authority')
        need(load(GATE).get('enabled') is False,'client_bootstrap_reload_enabled_gate')
    def phase(label):
        global OPERATION_PHASE
        OPERATION_PHASE=label;state['subscription_reload_phase']=label
        write(STATE,canonical(state))
    phase('before_subscription_daemon_reload')
    command(['systemctl','daemon-reload'])
    proof={}
    for role in ('topology','gateway'):
        guard();unit=value['service_roles'][role]['unit'];phase('restarting_subscription_'+role)
        command(['systemctl','restart',unit],timeout=30);phase('waiting_subscription_'+role)
        actual=wait_subscription_owner(value,inputs,role,guard=guard)
        proof[role]={'unit':unit,'main_pid':actual['main_pid'],'selected_effective_environment':actual['selected_effective_environment']}
        phase('verified_subscription_'+role)
    expected_env={'TOPOLOGY_FULL_GRAPH_SEED_FILE':value['private_paths']['full_graph_seed'],
        'TOPOLOGY_FULL_GRAPH_SNAPSHOT_FILE':value['private_paths']['full_graph_snapshot']}
    need(proof['topology']['selected_effective_environment']==expected_env,'client_bootstrap_fullgraph_environment_not_loaded')
    need(protected=={path:hash_file(path) for path in protected},'client_bootstrap_reload_changed_native_authority')
    need(load(GATE).get('enabled') is False,'client_bootstrap_reload_enabled_gate')
    state.update(phase='static_ready_gate_disabled',subscription_readers_reloaded=True,
        subscription_owner_proof=proof,subscription_reloaded_at=int(time.time()))
    phase('all_subscription_readers_verified')
    write(STATE,canonical(state));write(Path(state['job'])/'subscription-reload.json',canonical(proof))
    return {'status':'subscription_readers_reloaded_gate_disabled','owners':proof,'main_lc_or_network_mode_changed':False}

def installed_reader_paths():
    for path in reversed(('/opt/submerge-routing','/opt/submerge-topology','/opt/submerge-edge','/opt/submerge-user-access','/opt/submerge-client-policy','/opt/submerge')):
        if path in sys.path:sys.path.remove(path)
        sys.path.insert(0,path)


def authority():
    installed_reader_paths()
    from desired_accounts import Authority
    from empty_main_guard import CurrentMainGuard
    import server_route_policy
    a=Authority();return a,CurrentMainGuard(a,rule_set_loader=server_route_policy.load_rule_sets,expected_binary_sha256=NATIVE_SHA)

def anchor(snapshot):return {key:snapshot[key] for key in ('source_plan_sha256','source_runtime_sha256','cohort_sha256','desired_token_sha256')}

def executor_status(snapshot):
    import edge_controller
    registry=load(REGISTRY);edges=[row for row in registry['edges'] if row.get('enabled') is True]
    need({row['edge_id'] for row in edges}=={'dmit-ai-20261108','lazycat-ai-20261108'}
         and all(row.get('ai_pool_version')==4 for row in edges),'client_bootstrap_two_live_v4_executors_required')
    policy=snapshot['plan']['server_policy']['routing_revision'];expected_users=sorted(row['name'] for row in snapshot['desired_users'])
    rows=[];publisher=edge_controller.Publisher()
    for edge in edges:
        status=edge_controller.transport_for(edge).status()
        state=load('/var/lib/submerge-edge/'+edge['edge_id']+'.json');manifest=state['confirmed_manifest'];ack=state['last_ack']
        need(state['confirmed_input_sha256']==publisher.authority.fingerprint(edge),'client_bootstrap_executor_current_input_mismatch')
        need(status.get('verified') is True and 0<=time.time()-status.get('verified_at',0)<=45,
             'client_bootstrap_actual_fresh_executor_status_required')
        need(status['generation']==ack['generation']==manifest['generation']
             and status['manifest_sha256']==ack['manifest_sha256']
             and status['cohort_sha256']==snapshot['cohort_sha256']==manifest['accounts']['cohort_sha256']
             and sorted(status['active_usernames'])==expected_users,
             'client_bootstrap_loaded_executor_cohort_or_generation_mismatch')
        need(manifest.get('routing_revision')==policy,'client_bootstrap_executor_different_routing_contract')
        wanted='running_verified' if expected_users else 'service_stopped_no_accounts'
        need(status['enforcement']==wanted,'client_bootstrap_executor_enforcement_mismatch')
        rows.append({'edge_id':edge['edge_id'],'generation':status['generation'],'cohort_sha256':status['cohort_sha256'],
                     'manifest_sha256':status['manifest_sha256'],'enforcement':wanted,'verified_at':status['verified_at']})
    return rows

def fetch_profile(username):
    url='https://node.titanyung.click:31877/sub/'+urllib.parse.quote(username,safe='')+'?format=clash&client=desktop&refresh=0'
    request=urllib.request.Request(url,headers={'User-Agent':'Mihomo/1.19.32','Accept':'application/yaml'})
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request,timeout=20) as response:code=response.status;body=response.read(2*1024*1024+1)
    except urllib.error.HTTPError as error:code=error.code;body=error.read(2*1024*1024+1)
    need(len(body)<=2*1024*1024,'client_bootstrap_public_profile_size_bound')
    return code,body

def safe_public_usernames(snapshot):
    from desired_accounts import Paths,database_rows
    rows=database_rows(Paths().control_db,'SELECT username,state FROM subjects ORDER BY client_id',require_host_view=True)
    states=dict(rows);need(len(states)==len(rows),'client_bootstrap_duplicate_lifecycle_username')
    return {row['name'] for row in snapshot['desired_users'] if states.get(row['name']) in (None,'active')}


def _public_checks_once(snapshot):
    import routing_client_v4 as client
    import yaml
    from purge_codecs import validate_purge
    contract=snapshot['plan']['server_policy']['routing_revision'];names=safe_public_usernames(snapshot)
    normal=sorted(names-set(contract['test_users']));ordinary='gsdn' if 'gsdn' in normal else normal[0] if normal else None
    test_enabled=any(name in names for name in contract['test_users']);proof={}
    for kind,username,enabled,manual in (('ordinary',ordinary,bool(ordinary),False),('test','dycetest' if test_enabled else None,test_enabled,True)):
        if username is None:
            proof[kind]={'status':'no_eligible_live_http_account','account_restored_for_test':False,'lifecycle_not_consumed':True};continue
        code,body=fetch_profile(username)
        if enabled:
            need(code==200,'client_bootstrap_cached_public_subscription_failed')
            document=yaml.safe_load(body);client.validate_projected(document,gate_path=GATE)
            meta=document[client.MARKER]
            need(meta['contract_sha256']==client.digest(contract) and meta['test'] is manual,
                 'client_bootstrap_public_test_or_contract_scope_mismatch')
        elif code==200:
            need(validate_purge(body,'clash','application/yaml; charset=utf-8'),'client_bootstrap_disabled_test_received_real_profile')
        else:need(code in (403,404,410),'client_bootstrap_disabled_test_not_denied')
        proof[kind]={'status':'public_profile_validated' if enabled else 'disabled_test_denied',
                     'http_status':code,'body_sha256':sha(body),'manual_test':manual,'refresh':0}
    if not ordinary or not test_enabled:
        context=client._gate_context(GATE)
        for kind,eligible,manual in (('ordinary',bool(ordinary),False),('test',test_enabled,True)):
            if eligible:continue
            source={'mode':'rule','proxies':[{'type':'anytls','server':'179.255.136.79','port':29711,
                'password':'REPLACE_OFFLINE_FIXTURE_PASSWORD','sni':context['settings']['server_name'],
                'fingerprint':context['settings']['certificate_fingerprint'],'skip-cert-verify':False}],
                'proxy-groups':[],'rules':['DOMAIN,owned.invalid,DIRECT','MATCH,全部节点'],
                'x-submerge-client-kind':'desktop','x-submerge-manual-test':manual}
            projected=client.project_profile(source,as_of=int(time.time()),**context)
            client.validate_profile(projected,as_of=projected[client.MARKER]['as_of'],**context)
            proof[kind]['owned_offline_projection_validated']=True
    return proof


def public_checks(snapshot):
    # A qualification heartbeat can atomically replace a bound source between
    # GET and verification. Only this explicit source-CAS race earns a new GET.
    for attempt in range(3):
        try:return _public_checks_once(snapshot)
        except ValueError as error:
            if str(error)!='full_graph_bound_source_changed' or attempt==2:raise
            time.sleep(.1)

def activate(value,inputs,descriptor_path):
    global OPERATION_PHASE
    OPERATION_PHASE='activation_metadata_preflight'
    state=load(STATE)
    need(state.get('subscription_readers_reloaded') is True and state['descriptor']==descriptor_path,
         'client_bootstrap_reloaded_subscription_prerequisite_required')
    metadata=inputs.check_ready(descriptor_path)
    need(metadata.get('status')=='read_only_client_gate_preflight_passed','client_bootstrap_metadata_not_ready')
    need(load(GATE).get('enabled') is False,'client_bootstrap_gate_already_enabled')
    a,guard=authority();before_gate=regular(GATE);enabled_row=next(row for row in value['artifacts'] if row['activation_order']==2)
    enabled=private(enabled_row['candidate_path']);need(sha(enabled)==enabled_row['after_sha256'],'client_bootstrap_enabled_gate_payload_changed')
    protected={path:hash_file(path) for path in (PLAN,MAIN,REGISTRY,SETTINGS,MAP)}
    activated=False
    try:
        OPERATION_PHASE='activation_current_main_executors'
        with a.lock():
            snap=a.snapshot();main=guard();expected=anchor(snap)
            need(main['cohort_sha256']==snap['cohort_sha256'],'client_bootstrap_main_actual_cohort_mismatch')
            from bootstrap_revision import assert_fresh_boundary
            assert_fresh_boundary(snap['plan'],int(time.time()))
            executors=executor_status(snap)
            need(anchor(a.snapshot())==expected,'client_bootstrap_authority_changed_before_gate_enable')
            contract=snap['plan']['server_policy']['routing_revision'];old=load(value['private_paths']['client_contract'])
            need({k:v for k,v in old.items() if k!='as_of'}=={k:v for k,v in contract.items() if k!='as_of'}
                 and old['as_of']<=contract['as_of'],'client_bootstrap_only_contract_epoch_may_change')
            write(value['private_paths']['client_contract'],canonical(contract))
            need(regular(GATE)==before_gate,'client_bootstrap_gate_changed_before_enable')
            write(GATE,enabled);activated=True
        # Delivery may acquire the common admission lock itself; never issue
        # HTTP while holding it. No refresh or client mode change is requested.
        OPERATION_PHASE='activation_nginx_validation_reload'
        command(['nginx','-t'],timeout=20);command(['systemctl','reload','nginx.service'],timeout=20)
        OPERATION_PHASE='activation_cached_public_checks';public=public_checks(snap)
        OPERATION_PHASE='activation_fresh_generation_recheck'
        with a.lock():
            need(anchor(a.snapshot())==expected and guard()==main,'client_bootstrap_main_or_desired_changed_after_public_check')
            final_executors=executor_status(a.snapshot())
            need({row['edge_id']:(row['generation'],row['manifest_sha256']) for row in final_executors}
                 =={row['edge_id']:(row['generation'],row['manifest_sha256']) for row in executors},
                 'client_bootstrap_executor_generation_changed_during_activation')
            need(regular(GATE)==enabled and protected=={path:hash_file(path) for path in protected},
                 'client_bootstrap_protected_sources_changed_during_activation')
        proof={'status':'client_gate_activated_actual_ack_verified','checked_at':int(time.time()),'main_ack':main,
            'executors':final_executors,'public_checks':public,'metadata':metadata,'gate_sha256':sha(enabled),
            'contract_sha256':sha(canonical(contract)),'descriptor_sha256':state['descriptor_sha256'],
            'accounts_native_or_credentials_changed':False,'client_mode_or_tun_changed':False,
            'provider_upstream_refreshed':False,'nginx_reloaded':True}
        state.update(phase='client_gate_enabled_verified',activation_proof=proof)
        write(STATE,canonical(state));write(Path(state['job'])/'activation-proof.json',canonical(proof))
        return proof
    except Exception as error:
        disabled=False
        if activated and hash_file(GATE)==sha(enabled):write(GATE,canonical(DISABLED));disabled=True
        elif load(GATE).get('enabled') is False:disabled=True
        code=str(error);safe=code if re.fullmatch('[a-z0-9_]{1,120}',code) else type(error).__name__
        failure={'status':'client_activation_failed_gate_disabled' if disabled else 'client_activation_failed_gate_changed_by_other_owner',
            'error_code':safe,'gate_disabled':disabled,'old_credentials_or_cohort_restored':False,'checked_at':int(time.time())}
        state.update(phase='activation_failed',activation_failure=failure);write(STATE,canonical(state))
        write(Path(state['job'])/'activation-failure.json',canonical(failure));raise

def main(argv=None):
    global OPERATION_PHASE
    p=argparse.ArgumentParser(description=__doc__);actions=p.add_mutually_exclusive_group()
    actions.add_argument('--static',action='store_true');actions.add_argument('--reload-subscriptions',action='store_true')
    actions.add_argument('--activate',action='store_true');actions.add_argument('--check-ready',action='store_true')
    p.add_argument('--descriptor',required=True);p.add_argument('--descriptor-sha256',required=True)
    p.add_argument('--tools-dir',required=True);p.add_argument('--helper-sha256',required=True)
    p.add_argument('--install-policy-readers',action='store_true');p.add_argument('--main-stage');p.add_argument('--main-spec-sha256')
    args=p.parse_args(argv)
    if not any((args.static,args.reload_subscriptions,args.activate,args.check_ready)):
        print(json.dumps({'status':'dry_run','changed':False}));return 0
    try:
        need(os.geteuid()==0,'client_bootstrap_root_required')
        value=descriptor(args.descriptor,args.descriptor_sha256)
        inputs=helper(args.tools_dir,args.helper_sha256)
        import fcntl
        lock=Path('/var/lib/submerge-topology/client-bootstrap.lock');lock.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        need(not lock.is_symlink(),'client_bootstrap_lock_symlink')
        with lock.open('a+b') as stream:
            os.fchmod(stream.fileno(),0o600);fcntl.flock(stream,fcntl.LOCK_EX)
            if args.static:
                result=static_install(value,descriptor_path=args.descriptor,descriptor_sha256=args.descriptor_sha256,
                    main_stage=args.main_stage if args.install_policy_readers else None,
                    main_spec_sha256=args.main_spec_sha256 if args.install_policy_readers else None)
            elif args.reload_subscriptions:result=reload_subscriptions(value,inputs)
            elif args.check_ready:
                OPERATION_PHASE='read_only_metadata_preflight'
                result=inputs.check_ready(args.descriptor);a,g=authority()
                OPERATION_PHASE='read_only_current_native_executors'
                with a.lock():result.update(main_ack=g(),executors=executor_status(a.snapshot()))
            else:result=activate(value,inputs,args.descriptor)
        print(json.dumps(result));return 0
    except Exception as error:
        text=str(error);safe=text if re.fullmatch('[a-z0-9_]{1,120}',text) else type(error).__name__
        answer={'status':'failed','code':safe,'phase':OPERATION_PHASE,'credentials_printed':False}
        if isinstance(error,ModuleNotFoundError):
            import traceback
            answer['missing_module']=error.name if isinstance(error.name,str) and re.fullmatch('[A-Za-z_][A-Za-z0-9_.]{0,127}',error.name) else None
            answer['frames']=[{'filename':row.filename,'line':row.lineno,'function':row.name} for row in traceback.extract_tb(error.__traceback__)]
        print(json.dumps(answer));return 1

if __name__=='__main__':raise SystemExit(main())
