"""Whole-layer retirement and reboot catch-up owner for the installed revision.

--preboot only prepares fresh authorized native bytes, before native startup.
--catch-up publishes/validates the clients, two executors and statistics, then
signs the strict full-layer receipt. Neither mode changes a client mode or TUN.
No upstream subscription refresh and no saved credential runtime rollback exist.
"""
import argparse,contextlib,copy,hashlib,json,os,re,subprocess,sys,tempfile,time,urllib.error,urllib.parse,urllib.request
from pathlib import Path
from prepared_restart import current_lease,prepared_restart,private,atomic
from routing_contract import UZUMA_HKT_RETIRE_AT

REVISION='routing-revision-20261109-v1'
SETTINGS='/etc/submerge-routing/reconcile-settings.json'
BOOT_SETTINGS='/etc/submerge-routing/bootstrap-settings.json'
PLAN='/etc/submerge-topology/network-plan.json'
MAIN='/run/dmit-direct-staging/config.json'
GATE='/etc/submerge-topology/routing-client-20261109.json'
REGISTRY='/etc/submerge-edge/edges.json'
MANIFEST='/var/lib/sg-traffic-dashboard/topology-20261105.json'
RECEIPT='/var/lib/submerge-topology/full-layer-catchup.json'
EVIDENCE='/var/lib/submerge-topology/full-layer-evidence.json'
LOCK='/var/lib/submerge-topology/reconcile.lock'
AUDIT='/var/lib/submerge-topology/reconcile-audit.jsonl'
BOOT='dmit-routing-bootstrap.service'
MAIN_UNIT='dmit-direct-staging.service'
CONTROLLER='dmit-ai-edge-control.service'
WORKER='dmit-main-business-health.service'
BINARY='/root/lazycat-test-config/sing-box'
BINARY_SHA='768d31fa7f68debc067bb4626539498a1e8751d36a7b99e1a54bee6a23815f93'
HKT_PUBLIC_SOCKETS=(29720,29820,30320,30420)
PREPARE='/root/routing-revision-20261109/stats-preparation/prepare_manifest.py'
ACTIVATE='/root/routing-revision-20261109/stats-preparation/activate_manifest.py'
ACTIVATE_TIMEOUT=300
RUN_SOFT_DEADLINE=810  # Leave 90 seconds below the oneshot unit's 900-second limit.
FINGERPRINT=('source_plan_sha256','source_runtime_sha256','cohort_sha256','desired_token_sha256')

def need(value,code):
    if not value:raise RuntimeError(code)
def require_activation_budget(run_started,*,now=None):
    now=time.monotonic() if now is None else now
    need(now+ACTIVATE_TIMEOUT<=run_started+RUN_SOFT_DEADLINE,
         'reconcile_statistics_activation_time_budget_exhausted')
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(path):return json.loads(private(path))
def digest_file(path):return sha(private(path))
def write_json(path,value):atomic(path,canonical(value))
def fingerprint(snapshot):return {key:snapshot[key] for key in FINGERPRINT}

def wait_current_main_ack(authority,guard,expected,*,timeout=15,clock=time.monotonic,sleep=time.sleep):
    """Wait for Type=simple exec/API startup without weakening the actual guard.

    The caller keeps its existing CAS lock and prepared restart lease. Only
    known startup transients are retried; desired/source drift is never retried.
    Two identical complete ACKs prove a stable process/API generation.
    """
    deadline=clock()+timeout;previous=None
    transient={'native_not_active','native_pid_missing','native_process_config_path_mismatch',
        'current_config_not_proven_loaded','authenticated_api_not_owned_by_main_pid',
        'actual_business_api_inventory_mismatch','main_process_state_unavailable',
        'main_pid_generation_changed','empty_main_not_actually_stopped','empty_main_owned_native_listener_survives'}
    while clock()<deadline:
        need(fingerprint(authority.snapshot())==expected,'reconcile_restart_authority_changed_during_ack')
        try:proof=guard()
        except (FileNotFoundError,ProcessLookupError,ConnectionRefusedError,ConnectionResetError,TimeoutError):proof=None
        except urllib.error.HTTPError:raise
        except urllib.error.URLError as error:
            if not isinstance(error.reason,(ConnectionRefusedError,ConnectionResetError,TimeoutError)):raise
            proof=None
        except (RuntimeError,ValueError) as error:
            if str(error) not in transient:raise
            proof=None
        if proof is not None:
            need(proof.get('verified') is True and all(proof.get(key)==expected[source] for key,source in (
                ('plan_sha256','source_plan_sha256'),('runtime_sha256','source_runtime_sha256'),
                ('cohort_sha256','cohort_sha256'),('desired_token_sha256','desired_token_sha256'))),
                'reconcile_restart_main_ack_wrong_generation')
            if proof==previous:return proof
        previous=proof;remaining=deadline-clock()
        if remaining>0:sleep(min(.15,remaining))
    raise RuntimeError('reconcile_restart_actual_main_ack_deadline')

def call(args,*,timeout=30):
    value=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,timeout=timeout)
    need(value.returncode==0,'reconcile_external_command_failed')
    return value.stdout

def systemctl(*args,timeout=30):return call(['systemctl',*args],timeout=timeout)
def unit_state(unit):
    raw=systemctl('show',unit,'--property=ActiveState,SubState,MainPID','--no-pager',timeout=5).decode()
    return dict(line.split('=',1) for line in raw.splitlines() if '=' in line)

def installed_modules():
    # Explicit deployment paths; no cwd-relative provider or historical modules.
    for path in reversed(('/opt/submerge-routing','/opt/submerge-topology','/opt/submerge-edge',
            '/opt/submerge-user-access','/opt/submerge-client-policy','/opt/submerge','/opt/sg-traffic-dashboard-expiry-prod')):
        if path not in sys.path:sys.path.insert(0,path)
    from bootstrap_revision import BootAuthority
    from main_policy_cas import Transaction
    from policy_inputs import runtime,policy,users
    from reconcile_policy import reconcile_plan,availability
    from empty_main_guard import CurrentMainGuard
    return BootAuthority,Transaction,runtime,policy,users,reconcile_plan,availability,CurrentMainGuard

def authority_from_boot():
    BootAuthority,*_=installed_modules()
    settings=load(BOOT_SETTINGS)
    need(set(settings)=={'schema','template_path','template_sha256','durable_receipt'} and settings['schema']==1,
         'reconcile_exact_boot_settings_required')
    return BootAuthority(template=settings['template_path'],template_sha256=settings['template_sha256']),settings

@contextlib.contextmanager
def release_lock(authority=None,*,preboot=False,timeout=40,path=LOCK):
    """Separate lock, with a kernel-verified CAS-owner escape for boot jobs."""
    import fcntl
    p=Path(path);need(not p.is_symlink(),'reconcile_lock_symlink');p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    deadline=time.monotonic()+timeout
    with p.open('a+b') as stream:
        os.fchmod(stream.fileno(),0o600)
        while True:
            if preboot:
                proof=current_lease(authority)
                if proof is not None:yield proof;return
            try:fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB);break
            except BlockingIOError:
                need(time.monotonic()<deadline,'reconcile_owner_busy_no_unsafe_lock_wait')
                time.sleep(.1)
        try:yield None
        finally:fcntl.flock(stream,fcntl.LOCK_UN)

@contextlib.contextmanager
def boot_admission(authority):
    """Cold boot cannot wait on an unleased owner which may wait for systemd."""
    import fcntl
    p=Path(authority.paths.admission_lock);need(not p.is_symlink(),'reconcile_admission_lock_symlink')
    with p.open('a+b') as stream:
        os.fchmod(stream.fileno(),0o600)
        try:fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise RuntimeError('admission_owner_requires_prepared_restart_lease') from None
        try:yield
        finally:fcntl.flock(stream,fcntl.LOCK_UN)

def native_check(config):
    need(sha(Path(BINARY).read_bytes())==BINARY_SHA,'reconcile_native_binary_changed')
    fd,name=tempfile.mkstemp(prefix='.reconcile-native-check-',dir='/root')
    try:
        with os.fdopen(fd,'wb') as stream:os.fchmod(stream.fileno(),0o600);stream.write(canonical(config))
        call([BINARY,'check','-c',name],timeout=12)
    finally:Path(name).unlink()

def preboot(*,clock=time.time):
    _,Transaction,runtime,policy,_,reconcile_plan,_,_=installed_modules()
    # Legacy no-op precedes new private settings/templates and every lock.
    if not runtime.revised(load(PLAN)):return {'status':'legacy_preboot_noop','changed':False}
    authority,settings=authority_from_boot()
    skip=current_lease(authority)
    if skip is not None:return skip
    with release_lock(authority,preboot=True) as skipped:
        if skipped is not None:return skipped
        # Priming BOOT outside the caller's CAS must not change a running
        # process's source behind its back. Running catch-up owns its restart.
        if unit_state(MAIN_UNIT).get('ActiveState')=='active':
            return {'status':'running_main_deferred_to_catchup','changed':False,'whole_layer_catchup_claimed':False}
        with boot_admission(authority):
            before=authority.snapshot();now=int(clock());target=reconcile_plan(before['plan'],now)
            tx=Transaction(authority,rule_set_loader=policy.load_rule_sets)
            prepared=tx._prepare(before,target);native_check(prepared['runtime'])
            tx._assert_current(prepared,authority.snapshot())
            from bootstrap_revision import durable_receipt
            atomic(MAIN,canonical(prepared['runtime']));atomic(PLAN,canonical(prepared['plan']))
            durable=durable_receipt(prepared);durable.update(boot_rendered_at=now,whole_layer_catchup_claimed=False)
            write_json(settings['durable_receipt'],durable)
            write_json('/var/lib/submerge-topology/reconcile-pending.json',{'schema':1,'status':'native_prepared_before_start',
                'checked_at':now,'as_of':target['server_policy']['routing_revision']['as_of'],
                **{key:prepared['manifest'][key] for key in ('plan_sha256','runtime_sha256','cohort_sha256','desired_token_sha256')},
                'user_count':prepared['manifest']['user_count'],'whole_layer_catchup_claimed':False})
            return {'status':'preboot_native_prepared','user_count':prepared['manifest']['user_count'],
                'plan_sha256':prepared['manifest']['plan_sha256'],'runtime_sha256':prepared['manifest']['runtime_sha256'],
                'cohort_sha256':prepared['manifest']['cohort_sha256'],'whole_layer_catchup_claimed':False,
                'main_restarted':False,'client_mode_or_tun_changed':False}

def settings_document(path=SETTINGS):
    value=load(path)
    need(isinstance(value,dict) and set(value)=={'schema','revision','statistics_prepare_descriptor','statistics_activation_descriptor'}
         and value['schema']==1 and value['revision']==REVISION,'reconcile_settings_schema')
    for key in ('statistics_prepare_descriptor','statistics_activation_descriptor'):
        p=Path(value[key]);need(p.is_absolute() and '..' not in p.parts and str(p).startswith('/root/routing-revision-20261109/'),
                              'reconcile_private_statistics_descriptor_required')
    return value

def receipt_for(snapshot):
    return {'schema':1,'status':'completed','as_of':snapshot['plan']['server_policy']['routing_revision']['as_of'],
        'plan_sha256':snapshot['source_plan_sha256'],'cohort_sha256':snapshot['cohort_sha256'],
        'desired_token_sha256':snapshot['desired_token_sha256'],'layers':{'clients':True,'statistics':True,'edges':True}}

def filter_node_inventory(document,contract):
    result=copy.deepcopy(document);peers=result['peers']
    cutoff={'ByteVirt-TW':contract['taiwan_retire_at'],'Lazycat-HKT':contract['lazycat_hkt_retire_at'],
            'Uzuma-HKT':UZUMA_HKT_RETIRE_AT}
    result['peers']={key:row for key,row in peers.items()
                     if row['host'] not in cutoff or contract['as_of']<cutoff[row['host']]}
    return result

def retire_hkt_public_aliases(contract):
    if contract['as_of']<UZUMA_HKT_RETIRE_AT:
        return {'retired':False}
    for port in HKT_PUBLIC_SOCKETS:
        base='dmit-routing-hkt-'+str(port)
        socket_unit=base+'.socket';service_unit=base+'.service'
        # Close socket activation before stopping the currently serving alias.
        systemctl('disable','--now',socket_unit)
        systemctl('stop',service_unit)
        socket_state=systemctl('show',socket_unit,'--property=UnitFileState,ActiveState','--no-pager',timeout=5).decode()
        socket_fields=dict(line.split('=',1) for line in socket_state.splitlines() if '=' in line)
        need(socket_fields.get('UnitFileState')=='disabled' and socket_fields.get('ActiveState')=='inactive',
             'retired_hkt_public_alias_still_available')
        service_state=systemctl('show',service_unit,'--property=ActiveState','--no-pager',timeout=5).decode()
        service_fields=dict(line.split('=',1) for line in service_state.splitlines() if '=' in line)
        need(service_fields.get('ActiveState')=='inactive','retired_hkt_public_alias_service_still_active')
    return {'retired':True,'ports':list(HKT_PUBLIC_SOCKETS)}

class LiveOwner:
    def __init__(self,settings,*,clock=time.time,run_started=None):
        self.settings,self.clock=settings,clock
        self.run_started=time.monotonic() if run_started is None else run_started
        self.authority,self.boot_settings=authority_from_boot()
        _,self.Transaction,self.runtime,self.policy,self.users,self.reconcile_plan,self.availability,guard=installed_modules()
        self.guard=guard(self.authority,rule_set_loader=self.policy.load_rule_sets,expected_binary_sha256=BINARY_SHA)
        self.job=Path('/root/routing-revision-20261109/reconcile-'+str(time.time_ns()))
        self.job.mkdir(mode=0o700,parents=True)
        self.unit_before={unit:unit_state(unit) for unit in (WORKER,CONTROLLER)}
        self.stopped_controls=False

    def snapshot(self):return self.authority.snapshot()

    def current(self):
        value=self.snapshot();target=self.reconcile_plan(value['plan'],int(self.clock()))
        return value,self.availability(value['plan'])==self.availability(target)

    def already_current(self,snapshot,boundary_current):
        if not boundary_current:return False
        try:
            if load(RECEIPT)!=receipt_for(snapshot):return False
            gate=load(GATE)
            if gate.get('enabled') is not True:return False
            contract=load(gate['contract_path']);manifest=load(MANIFEST)
            if contract!=snapshot['plan']['server_policy']['routing_revision'] or manifest.get('routing_contract')!=contract:return False
            self.guard()
            return True
        except (OSError,ValueError,RuntimeError):return False

    def main(self):
        before=self.snapshot();target=self.reconcile_plan(before['plan'],int(self.clock()))
        boundary=self.availability(before['plan'])!=self.availability(target)
        if not boundary:target=before['plan']
        state=unit_state(MAIN_UNIT)
        needed=boundary or self.users(before['runtime'])!=before['desired_users'] or before.get('bootstrap_runtime_source')=='verified_private_template'
        needed=needed or (bool(before['desired_users'])!=(state.get('ActiveState')=='active'))
        if not needed:
            with self.authority.lock():return wait_current_main_ack(self.authority,self.guard,fingerprint(before))
        tx=self.Transaction(self.authority,rule_set_loader=self.policy.load_rule_sets)
        prepared=tx.prepare(target);native_check(prepared['runtime'])
        for unit in (WORKER,CONTROLLER):systemctl('stop',unit)
        self.stopped_controls=True
        try:
            with tx.checked_install(prepared) as payload:
                atomic(MAIN,payload['runtime_bytes']);atomic(PLAN,payload['plan_bytes'])
                from bootstrap_revision import durable_receipt
                write_json(self.boot_settings['durable_receipt'],durable_receipt(prepared))
                from raw_guard_install import apply
                apply(target)
                with prepared_restart(self.authority):
                    systemctl('stop' if not prepared['manifest']['user_count'] else 'restart',MAIN_UNIT,timeout=35)
                    proof=wait_current_main_ack(self.authority,self.guard,{
                        'source_plan_sha256':prepared['manifest']['plan_sha256'],
                        'source_runtime_sha256':prepared['manifest']['runtime_sha256'],
                        'cohort_sha256':prepared['manifest']['cohort_sha256'],
                        'desired_token_sha256':prepared['manifest']['desired_token_sha256']})
                need(proof['cohort_sha256']==prepared['manifest']['cohort_sha256'],'reconcile_main_cohort_ack_mismatch')
                return proof
        except Exception:
            # Retirement is monotonic. Never restore a saved runtime or revive
            # a route after cutoff merely to turn a failed probe green.
            systemctl('stop',MAIN_UNIT)
            raise

    def edges(self,anchor):
        import edge_controller
        registry=load(REGISTRY);rows=[row for row in registry['edges'] if row.get('enabled') is True]
        need({row['edge_id'] for row in rows}=={'dmit-ai-20261108','lazycat-ai-20261108'}
             and all(row.get('ai_pool_version')==4 for row in rows),'reconcile_exact_v4_executors_required')
        publisher=edge_controller.Publisher();evidence=[]
        with self.authority.lock():
            need(fingerprint(self.snapshot())==anchor,'reconcile_account_or_policy_superseded_before_edges')
            for edge in sorted(rows,key=lambda row:row.get('execution')!='local_authority'):
                ack=publisher.synchronize(edge);need(ack.get('status')=='confirmed','reconcile_v4_loaded_ack_required')
                status=edge_controller.transport_for(edge).status()
                need(status.get('verified') is True and status.get('cohort_sha256')==anchor['cohort_sha256'],
                     'reconcile_v4_actual_cohort_mismatch')
                health=publisher.health(edge);need(health.get('status') in ('confirmed','deny_all'),'reconcile_v4_health_ack_required')
                evidence.append({'edge_id':edge['edge_id'],'generation':status['generation'],
                    'cohort_sha256':status['cohort_sha256'],'verified':True,'enforcement':status.get('enforcement'),
                    'health_status':health['status']})
            need(fingerprint(self.snapshot())==anchor,'reconcile_account_or_policy_superseded_during_edges')
        return {'verified':True,'executors':evidence}

    def clients(self,anchor):
        import routing_client_v4 as client
        gate=load(GATE);need(gate.get('enabled') is True,'reconcile_client_gate_not_enabled')
        contract_path=Path(gate['contract_path']);allowed=('/etc/submerge-topology/','/etc/submerge-routing/',
            '/var/lib/submerge-routing/','/root/routing-revision-20261109/')
        need(contract_path.is_absolute() and '..' not in contract_path.parts and str(contract_path).startswith(allowed),
             'reconcile_approved_client_contract_path_required')
        with self.authority.lock():
            snap=self.snapshot();need(fingerprint(snap)==anchor,'reconcile_superseded_before_clients')
            target=snap['plan']['server_policy']['routing_revision'];old=load(contract_path)
            need({k:v for k,v in old.items() if k!='as_of'}=={k:v for k,v in target.items() if k!='as_of'}
                 and old['as_of']<=target['as_of'],'reconcile_only_retirement_epoch_may_change_client_contract')
            write_json(contract_path,target)
            context=client._gate_context(GATE)
            need(context is not None and context['routing_contract']==target,'reconcile_client_context_not_published')
        # Share the initial publisher's fresh active-only selection and bound
        # graph validation. Never consume an armed user's first-purge update.
        from client_bootstrap import public_checks
        public=public_checks(snap)
        with self.authority.lock():need(fingerprint(self.snapshot())==anchor,'reconcile_superseded_during_clients')
        return {'verified':True,'kind':'lifecycle_safe_cached_public_or_owned_offline_validation','public_checks':public,
                'contract_sha256':sha(canonical(target)),'provider_refresh_performed':False}

    def statistics(self,anchor):
        prepare=copy.deepcopy(load(self.settings['statistics_prepare_descriptor']))
        activation=copy.deepcopy(load(self.settings['statistics_activation_descriptor']))
        current=self.snapshot();need(fingerprint(current)==anchor,'reconcile_superseded_before_statistics')
        contract=current['plan']['server_policy']['routing_revision']
        inventory=filter_node_inventory(load(prepare['node_protection_inventory']),contract)
        write_json(self.job/'node-inventory.json',inventory)
        prepare.update(network_module_dir='/opt/submerge-routing',network_plan=PLAN,runtime=MAIN,
            output=str(self.job/'statistics-envelope.json'),activated_at=int(self.clock()),
            node_protection_inventory=str(self.job/'node-inventory.json'))
        write_json(self.job/'prepare-statistics.json',prepare)
        old_sha=digest_file(MANIFEST)
        output=call(['/usr/bin/python3',PREPARE,'--input',str(self.job/'prepare-statistics.json')],timeout=240)
        prepared_result=json.loads(output);need(prepared_result.get('status')=='prepared_only_not_activated','reconcile_statistics_prepare_failed')
        activation.update(prepared_envelope=prepare['output'],expected_live_manifest_sha256=old_sha,
                          native_binary_sha256=BINARY_SHA,policy_module_dir='/opt/submerge-routing')
        write_json(self.job/'activate-statistics.json',activation)
        # This CLI owns the SAME admission lock itself. Never invoke it inside
        # authority.lock()/checked_install, including from a boot callback.
        require_activation_budget(self.run_started)
        proof=json.loads(call(['/usr/bin/python3',ACTIVATE,'--input',str(self.job/'activate-statistics.json'),'--activate'],timeout=ACTIVATE_TIMEOUT))
        need(proof.get('status')=='statistics_activated','reconcile_statistics_service_ack_required')
        ack=proof['native_ack']
        need(all(ack.get(k)==anchor.get(source) for k,source in (
            ('plan_sha256','source_plan_sha256'),('runtime_sha256','source_runtime_sha256'),
            ('cohort_sha256','cohort_sha256'),('desired_token_sha256','desired_token_sha256'))),
            'reconcile_statistics_current_native_generation_mismatch')
        return {'verified':True,'proof':proof,'manifest_sha256':digest_file(MANIFEST)}

    def finalize(self,anchor,evidence):
        with self.authority.lock():
            current=self.snapshot();need(fingerprint(current)==anchor,'reconcile_final_authority_superseded')
            from bootstrap_revision import assert_fresh_boundary
            assert_fresh_boundary(current['plan'],int(self.clock()))
            actual=self.guard()
            need(actual.get('verified') is True,'reconcile_final_main_ack_missing')
            contract=current['plan']['server_policy']['routing_revision']
            need(load(load(GATE)['contract_path'])==contract and load(MANIFEST)['routing_contract']==contract,
                 'reconcile_final_client_statistics_contract_drift')
            need(all(evidence[key].get('verified') is True for key in ('clients','statistics','edges')),
                 'reconcile_all_actual_layer_ack_required')
            evidence['hkt_public_aliases']=retire_hkt_public_aliases(contract)
            receipt=receipt_for(current)
            from bootstrap_revision import validate_catchup_receipt
            prepared=self.Transaction(self.authority,rule_set_loader=self.policy.load_rule_sets)._prepare(current,current['plan'])
            validate_catchup_receipt(receipt,prepared)
            evidence=dict(evidence,main_ack=actual,checked_at=int(self.clock()),authority=anchor)
            write_json(self.job/'evidence.json',evidence);write_json(EVIDENCE,evidence)
            write_json(RECEIPT,receipt)
            event={'event':'full_layer_catchup_completed','checked_at':int(self.clock()),'receipt_sha256':sha(canonical(receipt)),
                   'evidence_sha256':sha(canonical(evidence)),'authority':anchor,'job':str(self.job)}
            fd=os.open(AUDIT,os.O_WRONLY|os.O_APPEND|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
            with os.fdopen(fd,'ab') as stream:stream.write(canonical(event)+b'\n');stream.flush();os.fsync(stream.fileno())
            return {'status':'full_layer_catchup_completed','receipt_sha256':event['receipt_sha256'],
                'as_of':receipt['as_of'],'cohort_sha256':receipt['cohort_sha256'],'job':str(self.job),
                'client_mode_or_tun_changed':False,'upstream_refresh_performed':False}

    def resume_controls(self):
        if not self.stopped_controls:return
        outcomes={}
        if self.unit_before[CONTROLLER].get('ActiveState')=='active':
            try:systemctl('start',CONTROLLER);outcomes[CONTROLLER]='start_requested'
            except Exception:outcomes[CONTROLLER]='start_failed'
        try:
            snap=self.snapshot()
            if snap['desired_users'] and unit_state(MAIN_UNIT).get('ActiveState')=='active':
                systemctl('start',WORKER);outcomes[WORKER]='start_requested'
        except Exception:outcomes[WORKER]='not_started_authority_or_native_unknown'
        write_json(self.job/'control-resume.json',outcomes)

def catch_up(settings_path=SETTINGS):
    run_started=time.monotonic()
    _,_,runtime,*_=installed_modules()
    if not runtime.revised(load(PLAN)):return {'status':'legacy_catchup_noop','changed':False}
    # Prime boot OUTSIDE both admission and release flocks: BOOT itself can run
    # this program --preboot. RemainAfterExit avoids subsequent nested locking.
    systemctl('start',BOOT,timeout=45)
    settings=settings_document(settings_path)
    with release_lock():
        owner=LiveOwner(settings,run_started=run_started)
        before,boundary_current=owner.current()
        if owner.already_current(before,boundary_current):return {'status':'already_current','changed':False,'receipt_sha256':digest_file(RECEIPT)}
        evidence={}
        try:
            evidence['main_ack']=owner.main();anchor=fingerprint(owner.snapshot())
            evidence['edges']=owner.edges(anchor);evidence['clients']=owner.clients(anchor)
            evidence['statistics']=owner.statistics(anchor)
            return owner.finalize(anchor,evidence)
        except Exception as error:
            message=str(error);safe=message if re.fullmatch('[a-z0-9_]{1,120}',message) else type(error).__name__
            write_json(owner.job/'pending.json',{'status':'catchup_incomplete','checked_at':int(time.time()),
                'error_type':type(error).__name__,'error_code':safe,'completed_layers':[key for key,value in evidence.items() if value.get('verified') is True],
                'full_layer_receipt_written':False,'old_account_runtime_restored':False})
            raise
        finally:owner.resume_controls()

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    actions=parser.add_mutually_exclusive_group();actions.add_argument('--preboot',action='store_true');actions.add_argument('--catch-up',action='store_true')
    parser.add_argument('--settings',default=SETTINGS);args=parser.parse_args(argv)
    if not (args.preboot or args.catch_up):print(json.dumps({'status':'dry_run','changed':False}));return 0
    try:
        need(os.geteuid()==0,'reconcile_root_required')
        result=preboot() if args.preboot else catch_up(args.settings);print(json.dumps(result));return 0
    except Exception as error:
        code=str(error);safe=code if re.fullmatch('[a-z0-9_]{1,120}',code) else type(error).__name__
        print(json.dumps({'status':'failed','code':safe,'full_layer_success_claimed':False,'credentials_printed':False}));return 1

if __name__=='__main__':raise SystemExit(main())
