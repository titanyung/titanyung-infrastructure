"""Explicit, staged main+V4 release; never changes a client mode or TUN.

The initial commit covers main/native, both V4 executors, the raw-port guard,
public HKT aliases, and the continuous main health worker. Client/statistics
whole-layer publication and retirement catch-up remain the root owner's next
transaction; no such acknowledgement is fabricated here.
"""
import argparse,base64,contextlib,copy,hashlib,io,json,os,re,subprocess,tempfile,time
from pathlib import Path
from desired_accounts import Authority,read_file
from main_policy_cas import Transaction
from main_guard import ActualMainGuard
from policy_inputs import canonical,need,sha,policy,runtime
from bootstrap_revision import assert_fresh_boundary,durable_receipt,render_dropin
import edge_controller
from routing_contract import POOL_TAGS

ROOT=Path('/root/routing-revision-20261109')
NATIVE_SHA='768d31fa7f68debc067bb4626539498a1e8751d36a7b99e1a54bee6a23815f93'
NATIVE='/root/lazycat-test-config/sing-box'
PLAN='/etc/submerge-topology/network-plan.json'
MAIN='/run/dmit-direct-staging/config.json'
REGISTRY='/etc/submerge-edge/edges.json'
SETTINGS='/etc/submerge-edge/client-settings.json'
TEMPLATE='/etc/submerge-topology/dmit-template.json'
MODULE_DIRS={'/opt/submerge-routing','/opt/submerge-topology','/opt/submerge-edge',
             '/opt/submerge-user-access','/opt/submerge-client-policy','/usr/local/lib/lazycat-edge'}
EDGE_LIBRARY='/usr/local/lib/lazycat-edge'
OLD_WRITERS=('dmit-sg-health.service','dmit-ai-egress-audit.timer')
CONTROLLER='dmit-ai-edge-control.service'
WORKER='dmit-main-business-health.service'
BOOT='dmit-routing-bootstrap.service'
RAW='dmit-routing-raw-guard.service'
HKT_ALIASES={29720:31117,29820:29611,30320:29520,30420:29620}

def run(args,*,timeout=20,input=None):
    p=subprocess.run(args,input=input,capture_output=True,timeout=timeout)
    need(p.returncode==0,'release_external_command_failed')
    return p.stdout

def systemctl(*args,timeout=25):return run(['systemctl',*args],timeout=timeout)

def unit_status(name):
    p=subprocess.run(['systemctl','show',name,'--property=ActiveState,UnitFileState,MainPID','--no-pager'],capture_output=True,text=True,timeout=5)
    return dict(x.split('=',1) for x in p.stdout.splitlines() if '=' in x)

def file_hash(path):
    p=Path(path)
    need(not p.is_symlink(),'release_target_symlink')
    return sha(p.read_bytes()) if p.exists() else None

def write(path,raw,mode=0o600):
    p=Path(path)
    need(p.is_absolute() and '..' not in p.parts and not p.is_symlink(),'unsafe_release_target')
    for parent in p.parents:need(not parent.is_symlink(),'release_parent_symlink')
    p.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix='.routing-release-',dir=str(p.parent))
    try:
        with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno());os.fchmod(stream.fileno(),mode)
        os.replace(name,p)
    finally:
        if os.path.exists(name):os.unlink(name)

def native_check(config):
    fd,name=tempfile.mkstemp(prefix='.owned-main-check-',dir='/root')
    try:
        with os.fdopen(fd,'wb') as stream:stream.write(canonical(config));os.fchmod(stream.fileno(),0o600)
        run([NATIVE,'check','-c',name],timeout=10)
    finally:Path(name).unlink()

def alias_files():
    out={}
    for public,inside in HKT_ALIASES.items():
        name='dmit-routing-hkt-'+str(public)
        out['/etc/systemd/system/'+name+'.socket']=(
            '[Unit]\nDescription=Versioned HKT public alias '+str(public)+'\n'
            '[Socket]\nListenStream=0.0.0.0:'+str(public)+'\nListenStream=[::]:'+str(public)+'\n'
            'BindIPv6Only=ipv6-only\nNoDelay=true\n[Install]\nWantedBy=sockets.target\n').encode()
        out['/etc/systemd/system/'+name+'.service']=(
            '[Unit]\nDescription=Versioned HKT authenticated native alias\n'
            'Requires=dmit-direct-staging.service\nAfter=dmit-direct-staging.service\n'
            '[Service]\nExecStart=/lib/systemd/systemd-socket-proxyd 127.0.0.1:'+str(inside)+'\n'
            'NoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\n').encode()
    return out

def validate_spec(spec):
    need(isinstance(spec,dict) and spec.get('schema')==1 and spec.get('kind')=='main-v4-stage', 'main_release_spec_required')
    root=Path(spec['stage'])
    need(root.is_absolute() and root.parent==ROOT and re.fullmatch('main-release-[a-z0-9-]{1,40}',root.name),'owned_release_stage_required')
    need(not root.is_symlink(),'release_stage_symlink')
    for target,row in spec['files'].items():
        path=Path(target)
        need(str(path.parent) in MODULE_DIRS or str(path.parent)=='/etc/systemd/system'
             or target=='/etc/submerge-routing/bootstrap-settings.json'
             or target in ('/etc/systemd/system/dmit-direct-staging.service.d/99-routing-revision.conf','/etc/systemd/system/dmit-direct-staging.service.d/zzzz-routing-revision.conf'),
             'unreviewed_release_file_target')
        source=root/'files'/row['file']
        need(source.parent==root/'files' and not source.is_symlink() and sha(read_file(source))==row['sha256'],'release_source_hash_mismatch')
    return root

def prepare_stage(stage,target_plan,files,*,worker_sandbox_proof,hkt_acceptance_proof):
    """Private staging only. files maps explicit installed paths to public bytes."""
    stage=Path(stage);need(stage.parent==ROOT and not stage.exists() and not stage.is_symlink(),'new_owned_release_stage_required')
    runtime.validate_network_plan(target_plan);need(runtime.revised(target_plan),'new_main_plan_required')
    assert_fresh_boundary(target_plan,int(time.time()))
    need(sha(Path(NATIVE).read_bytes())==NATIVE_SHA,'actual_native_binary_changed')
    authority=Authority();tx=Transaction(authority,rule_set_loader=policy.load_rule_sets)
    prepared=tx.prepare(target_plan);native_check(prepared['runtime'])
    stage.mkdir(mode=0o700,parents=True);(stage/'files').mkdir(mode=0o700)
    spec={'schema':1,'kind':'main-v4-stage','stage':str(stage),'created_at':int(time.time()),
        'target_plan_sha256':sha(canonical(target_plan)),'source_plan_sha256':file_hash(PLAN),
        'source_runtime_sha256':file_hash(MAIN),'source_registry_sha256':file_hash(REGISTRY),
        'client_settings_sha256':file_hash(SETTINGS),'template_sha256':file_hash(TEMPLATE),
        'worker_sandbox_proof':str(worker_sandbox_proof),'hkt_acceptance_proof':str(hkt_acceptance_proof),
        'prepared_manifest':prepared['manifest'],'files':{},'retirement_timer_enabled':False,
        'client_statistics_catchup_claimed':False}
    material=dict(files)
    material.update(alias_files())
    material['/etc/submerge-routing/bootstrap-settings.json']=canonical({'schema':1,'template_path':TEMPLATE,
        'template_sha256':spec['template_sha256'],'durable_receipt':'/var/lib/submerge-topology/main-bootstrap.json'})
    # One-shot boot rendering is separate from the nonlocking main condition.
    # Start it (legacy no-op) before the first CAS-held native restart.
    drop=render_dropin(template_sha256=spec['template_sha256'],prepared=True)
    drop='[Unit]\nRequires='+BOOT+' '+RAW+'\nAfter='+BOOT+' '+RAW+'\n'+drop
    drop=drop.replace('[Service]\n','[Service]\nEnvironment=PYTHONPATH=/opt/submerge-routing:/opt/submerge-topology:/opt/submerge-user-access:/opt/submerge-edge:/opt/submerge-client-policy:/opt/submerge\n',1)
    material['/etc/systemd/system/dmit-direct-staging.service.d/zzzz-routing-revision.conf']=drop.encode()
    material['/etc/systemd/system/'+RAW]=(
        '[Unit]\nDescription=Exact IPv4 and IPv6 private raw proxy ingress guard\nBefore=dmit-direct-staging.service\n'
        '[Service]\nType=oneshot\nRemainAfterExit=yes\nUMask=0077\n'
        'Environment=PYTHONDONTWRITEBYTECODE=1\nEnvironment=PYTHONPATH=/opt/submerge-routing:/opt/submerge-topology:/opt/submerge-user-access:/opt/submerge\n'
        'ExecStart=/usr/bin/python3 /opt/submerge-routing/raw_guard_install.py --apply\n').encode()
    for index,(target,raw) in enumerate(sorted(material.items())):
        name=str(index)+'.bin';write(stage/'files'/name,raw)
        spec['files'][target]={'file':name,'sha256':sha(raw),'expected':file_hash(target),'mode':0o644 if target.endswith(('.py','.service','.socket','.conf')) else 0o600}
    write(stage/'target-plan.json',canonical(target_plan));write(stage/'previous-plan.json',read_file(PLAN))
    write(stage/'spec.json',canonical(spec))
    validate_spec(spec)
    return {'status':'staged_only','stage':str(stage),'spec_sha256':sha(canonical(spec)),
        'target_plan_sha256':spec['target_plan_sha256'],'cohort_sha256':prepared['manifest']['cohort_sha256'],
        'users':prepared['manifest']['user_count'],'files':len(spec['files']),'production_changed':False,
        'client_statistics_catchup_claimed':False}

REMOTE_MODULE_INSTALL=r'''import base64,hashlib,json,os,pathlib,tempfile
payload=json.load(__import__('sys').stdin);root=pathlib.Path('/usr/local/lib/lazycat-edge')
if root.is_symlink():raise RuntimeError('edge_library_symlink')
out={}
for name,item in payload.items():
 if not name.endswith('.py') or '/' in name:raise RuntimeError('unreviewed_edge_module')
 p=root/name
 if p.is_symlink():raise RuntimeError('edge_module_symlink')
 current=hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None
 if current!=item['expected']:raise RuntimeError('edge_module_source_changed')
 raw=base64.b64decode(item['base64'],validate=True)
 if hashlib.sha256(raw).hexdigest()!=item['sha256']:raise RuntimeError('edge_module_payload_hash')
 compile(raw,str(p),'exec')
out['before']={name:hashlib.sha256((root/name).read_bytes()).hexdigest() if (root/name).exists() else None for name in payload}
backup=pathlib.Path(payload[next(iter(payload))]['backup']);backup.mkdir(mode=0o700,parents=True,exist_ok=True)
for name,item in payload.items():
 p=root/name
 if p.exists():
  b=backup/name
  if not b.exists():b.write_bytes(p.read_bytes());b.chmod(0o600)
 raw=base64.b64decode(item['base64']);fd,temp=tempfile.mkstemp(dir=str(root),prefix='.revision-module-')
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno());os.fchmod(f.fileno(),0o644)
 os.replace(temp,p)
out.update(status='installed',files=len(payload))
print(json.dumps(out))
'''
REMOTE_MODULE_HASH=r'''import hashlib,json,pathlib,sys
root=pathlib.Path('/usr/local/lib/lazycat-edge');names=json.load(sys.stdin)
out={}
for name in names:
 if '/' in name or not name.endswith('.py'):raise RuntimeError('module_name')
 p=root/name
 if p.is_symlink():raise RuntimeError('module_symlink')
 out[name]=hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None
print(json.dumps(out))
'''

def install_local(spec,root):
    for target,row in spec['files'].items():need(file_hash(target) in (row['expected'],row['sha256']),'release_installed_source_changed')
    backup=root/'previous-files';backup.mkdir(mode=0o700)
    for index,(target,row) in enumerate(sorted(spec['files'].items())):
        if row['expected'] is not None:write(backup/(str(index)+'.bin'),Path(target).read_bytes())
        row['backup_index']=index
        row['previous_mode']=Path(target).stat().st_mode&0o777 if Path(target).exists() else None
        write(target,read_file(root/'files'/row['file']),row['mode'])

def restore_control_files(spec,root):
    """Restore only unchanged owned unit/config writes; keep compatible code."""
    restored=[]
    for target,row in spec['files'].items():
        if not (target.startswith('/etc/systemd/system/') or target=='/etc/submerge-routing/bootstrap-settings.json'):continue
        if 'backup_index' not in row:continue
        need(file_hash(target)==row['sha256'],'rollback_control_file_changed')
        if row['expected'] is None:Path(target).unlink()
        else:write(target,read_file(root/'previous-files'/(str(row['backup_index'])+'.bin')),row['previous_mode'])
        restored.append(target)
    systemctl('daemon-reload')
    return restored

def module_names(spec):return {Path(p).name:row for p,row in spec['files'].items() if str(Path(p).parent)==EDGE_LIBRARY and p.endswith('.py')}

def install_remote_modules(edge,spec,root):
    names=module_names(spec);transport=edge_controller.transport_for(edge)
    # subprocess stdin must own a real fileno. BytesIO.fileno raises
    # UnsupportedOperation before SSH even starts, which the transport safely
    # reports as unavailable. Keep native bundle transport untouched.
    with tempfile.TemporaryFile() as stream:
        stream.write(canonical(sorted(names)));stream.seek(0)
        current=transport.command(['python3','-c',REMOTE_MODULE_HASH],stdin=stream,timeout=12)
    data={name:{'expected':current[name],'sha256':row['sha256'],
         'base64':base64.b64encode(read_file(root/'files'/row['file'])).decode(),
         'backup':'/root/routing-revision-20261109/'+root.name+'-previous-edge-modules'} for name,row in names.items()}
    with tempfile.TemporaryFile() as stream:
        stream.write(canonical(data));stream.seek(0)
        return transport.command(['python3','-c',REMOTE_MODULE_INSTALL],stdin=stream,timeout=20)

def registry_v4(registry):
    value=copy.deepcopy(registry);active=[r for r in value['edges'] if r.get('enabled') is True]
    need({r['edge_id'] for r in active}=={'dmit-ai-20261108','lazycat-ai-20261108'},'exact_two_front_registry_required')
    for row in active:
        need(row.get('ai_pool_version') in (3,4),'existing_four_inlet_front_required')
        row['ai_pool_version']=4
        row['bootstrap_health_mode']='ai-z0s0l0pn' # validation token only; Publisher replaces from a fresh actual probe before any bundle
        for field in ('endpoint_mapping','local_outbound_services'):
            row.setdefault(field,{})[POOL_TAGS['SG']]={'server':'127.0.0.1','server_port':18331}
    return value

def empty_or_main_ack(authority):
    snapshot=authority.snapshot()
    if not snapshot['desired_users']:
        need(unit_status('dmit-direct-staging.service').get('ActiveState')!='active','empty_native_must_be_stopped')
        need(not snapshot['runtime']['inbounds'][0]['users'],'empty_runtime_has_credentials')
        return {'verified':True,'enforcement':'service_stopped_no_accounts','users':0,'cohort_sha256':snapshot['cohort_sha256']}
    return ActualMainGuard(authority,rule_set_loader=policy.load_rule_sets,expected_binary_sha256=NATIVE_SHA)()

def verify_prerequisites(spec):
    for name in ('release_reconcile.py','prepared_restart.py'):
        p=Path('/opt/submerge-routing')/name
        need(p.is_file() and not p.is_symlink(),'root_preboot_and_prepared_restart_owner_must_be_installed')
    sandbox=json.loads(read_file(spec['worker_sandbox_proof']))
    need(sandbox.get('status')=='passed' and sandbox.get('proof',{}).get('actual_admission_lock_opened_rw') is True,
         'actual_worker_systemd_sandbox_pass_required')
    need(sandbox.get('proof',{}).get('actual_caller_kernel_flock_owner_verified') is True,
         'actual_account_reload_kernel_flock_predicate_pass_required')
    hkt=json.loads(read_file(spec['hkt_acceptance_proof']))
    need(hkt.get('status')=='committed' and hkt.get('commit',{}).get('status')=='committed',
         'hkt_reverse_native_committed_proof_required')
    need(file_hash(SETTINGS)==spec['client_settings_sha256'],'client_settings_changed_since_stage')
    need(file_hash(TEMPLATE)==spec['template_sha256'],'private_boot_template_changed')
    need(file_hash(PLAN)==spec['source_plan_sha256'] and file_hash(MAIN)==spec['source_runtime_sha256']
         and file_hash(REGISTRY)==spec['source_registry_sha256'],'main_release_sources_changed_since_stage')
    for port in HKT_ALIASES:
        text=run(['ss','-H','-lnt','sport','=',':'+str(port)],timeout=5)
        need(not text.strip(),'new_public_alias_port_collision')
    for port in (29520,29620):
        text=run(['ss','-H','-lnt','sport','=',':'+str(port)],timeout=5)
        need(not text.strip(),'new_native_hkt_port_collision')

def install_prepared_main(transaction,prepared,*,preboot=False):
    """Reusable root catch-up API, CURRENT desired users and existing CAS.

    preboot only publishes fresh files/raw guard. It NEVER restarts the unit
    whose Before dependency is currently running, starts workers, or fabricates
    a native/full-layer ACK. Post-start callers prove the actual process with
    ActualMainGuard and finish clients/statistics/edge acknowledgements.
    """
    assert_fresh_boundary(prepared['plan'],int(time.time()))
    native_check(prepared['runtime'])
    with transaction.checked_install(prepared) as payload:
        write(PLAN,payload['plan_bytes']);write(MAIN,payload['runtime_bytes'])
        write('/var/lib/submerge-topology/main-bootstrap.json',canonical(durable_receipt(prepared)))
        from raw_guard_install import apply as raw_apply
        raw=raw_apply(prepared['plan'])
        if not preboot:
            from prepared_restart import prepared_restart
            with prepared_restart(transaction.authority):
                systemctl('restart',RAW)
                systemctl('restart','dmit-direct-staging.service',timeout=30)
            ack=empty_or_main_ack(transaction.authority)
        else:ack=None
    return {'status':'prepared_main_preboot' if preboot else 'main_current_desired_acknowledged',
            'manifest':prepared['manifest'],'main_ack':ack,'raw_guard':raw,
            'native_restarted':not preboot,'whole_layer_catchup_claimed':False}

def commit(stage,*,expected_spec_sha256):
    os.umask(0o077);root=Path(stage);raw=read_file(root/'spec.json')
    need(sha(raw)==expected_spec_sha256,'reviewed_main_release_spec_hash_required')
    spec=json.loads(raw);validate_spec(spec);verify_prerequisites(spec)
    target=json.loads(read_file(root/'target-plan.json'));need(sha(canonical(target))==spec['target_plan_sha256'],'target_plan_changed')
    previous=json.loads(read_file(root/'previous-plan.json'));registry=json.loads(read_file(REGISTRY))
    authority=Authority();tx=Transaction(authority,rule_set_loader=policy.load_rule_sets)
    prepared=tx.prepare(target);native_check(prepared['runtime'])
    journal={'status':'preparing','checked_at':int(time.time()),'client_statistics_catchup_claimed':False,'phases':[]}
    old_states={unit:unit_status(unit) for unit in (*OLD_WRITERS,CONTROLLER,WORKER,BOOT,RAW)}
    journal['previous_unit_states']=old_states;write(root/'journal.json',canonical(journal))
    mutated=False;main_changed=False;success=False
    try:
        systemctl('stop',CONTROLLER)
        mutated=True;install_local(spec,root)
        for edge in registry['edges']:
            if edge.get('enabled') is True and edge.get('execution')!='local_authority':
                journal['remote_modules']=install_remote_modules(edge,spec,root)
        systemctl('daemon-reload')
        # RemainAfterExit is primed as an old-plan no-op OUTSIDE admission CAS.
        # Subsequent main restarts cannot reacquire the caller's lock.
        systemctl('start',BOOT)
        need(unit_status(BOOT).get('ActiveState')=='active','bootstrap_oneshot_not_ready')
        with tx.checked_install(prepared) as payload:
            for unit in OLD_WRITERS:
                systemctl('stop',unit)
                if old_states[unit].get('UnitFileState') in ('enabled','enabled-runtime'):systemctl('disable',unit)
            systemctl('stop',WORKER)
            write(PLAN,payload['plan_bytes']);write(MAIN,payload['runtime_bytes']);main_changed=True
            write('/var/lib/submerge-topology/main-bootstrap.json',canonical(durable_receipt(prepared)))
            from raw_guard_install import apply as raw_apply
            journal['raw_guard']=raw_apply(target)
            from prepared_restart import prepared_restart
            with prepared_restart(authority):
                systemctl('restart',RAW)
                systemctl('restart','dmit-direct-staging.service',timeout=30)
            journal['main_ack']=empty_or_main_ack(authority)
            updated=registry_v4(registry)
            # Fresh per-front V3 probe/ASN qualification happens inside
            # Publisher.synchronize, immediately before each V4 build/apply.
            publisher=edge_controller.Publisher()
            rows=sorted((x for x in updated['edges'] if x.get('enabled') is True),key=lambda x:x.get('execution')!='local_authority')
            edge_controller.atomic(REGISTRY,updated)
            journal['edges']=[]
            for edge in rows:
                ack=publisher.synchronize(edge)
                need(ack.get('status')=='confirmed','v4_front_ack_required')
                health=publisher.health(edge)
                need(health.get('status') in ('confirmed','deny_all'),'v4_front_health_ack_required')
                journal['edges'].append({'ack':ack,'health':health})
                need(authority.snapshot()['desired_token_sha256']==prepared['manifest']['desired_token_sha256'],'desired_accounts_changed_inside_main_release')
            for port in HKT_ALIASES:
                systemctl('enable','--now','dmit-routing-hkt-'+str(port)+'.socket')
            if prepared['manifest']['user_count']:
                systemctl('enable',WORKER);systemctl('start',WORKER)
        # Worker deliberately waits on the same lock; only await its proof
        # AFTER releasing CAS, never deadlock systemd startup with that lock.
        if prepared['manifest']['user_count']:
            deadline=time.monotonic()+55
            while True:
                proof={}
                try:proof=json.loads(read_file('/var/lib/paoluz-pools/business-health.json'))
                except (FileNotFoundError,ValueError):pass
                if proof.get('verified') is True and proof.get('checked_at',0)>=journal['checked_at']:
                    actual=empty_or_main_ack(authority)
                    if proof.get('main_ack')==actual:journal['business_health_ack']=actual;break
                need(time.monotonic()<deadline,'fresh_continuous_business_worker_ack_required')
                need(unit_status(WORKER).get('ActiveState')=='active','main_business_worker_not_running')
                time.sleep(.5)
        systemctl('start',CONTROLLER)
        need(file_hash(SETTINGS)==spec['client_settings_sha256'],'client_settings_changed_during_main_stage')
        with authority.lock():journal['final_main_ack']=empty_or_main_ack(authority)
        journal.update(status='committed_main_v4_stage',checked_at=int(time.time()),latest_desired_accounts_verified=True,
            tun_changed=False,network_mode_changed=False,client_settings_unchanged=True,
            client_statistics_catchup_claimed=False,retirement_reconciler_still_requires_root_owner=True)
        write(root/'journal.json',canonical(journal));success=True
        return {k:v for k,v in journal.items() if k!='previous_unit_states'}
    except Exception as error:
        journal.update(status='failed',error_type=type(error).__name__,checked_at=int(time.time()))
        if main_changed:
            try:
                systemctl('stop',WORKER);systemctl('stop',CONTROLLER)
                for port in HKT_ALIASES:systemctl('disable','--now','dmit-routing-hkt-'+str(port)+'.socket')
                # Never restore saved runtime bytes: rebase old policy onto
                # the current desired cohort under its admission lock.
                rebased=tx.prepare_rebased_rollback(previous)
                native_check(rebased['runtime'])
                with tx.checked_install(rebased) as payload:
                    write(PLAN,payload['plan_bytes']);write(MAIN,payload['runtime_bytes'])
                    # Old renderer/source remains compatible, but the new
                    # strict condition only applies to revised plans.
                    journal['restored_control_files']=restore_control_files(spec,root)
                    systemctl('restart','dmit-direct-staging.service',timeout=30)
                    edge_controller.atomic(REGISTRY,registry)
                    publisher=edge_controller.Publisher()
                    journal['rollback_edges']=[publisher.synchronize(e) for e in registry['edges'] if e.get('enabled') is True]
                    journal['rollback_current_cohort_sha256']=rebased['manifest']['cohort_sha256']
                for unit in OLD_WRITERS:
                    if old_states[unit].get('UnitFileState') in ('enabled','enabled-runtime'):systemctl('enable',unit)
                    if old_states[unit].get('ActiveState')=='active':systemctl('start',unit)
                journal['rollback']='previous_policy_current_desired_accounts'
            except Exception as rollback_error:
                # Empty legacy cannot be recompiled as an active runtime.
                # Deny at main and preserve new empty-cohort data; do not
                # resurrect a saved credential snapshot for availability.
                systemctl('stop','dmit-direct-staging.service')
                journal['rollback']='stopped_fail_closed';journal['rollback_error_type']=type(rollback_error).__name__
        elif mutated:
            try:journal['restored_control_files']=restore_control_files(spec,root)
            except Exception as restore_error:journal['restore_error_type']=type(restore_error).__name__
        if old_states[CONTROLLER].get('ActiveState')=='active':
            try:systemctl('start',CONTROLLER)
            except Exception:pass
        write(root/'journal.json',canonical(journal))
        return journal

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--commit',action='store_true');p.add_argument('--stage');p.add_argument('--spec-sha256');a=p.parse_args(argv)
    if not a.commit:print(json.dumps({'status':'dry_run','changed':False,'whole_layer_catchup_claimed':False}));return 0
    try:
        value=commit(a.stage,expected_spec_sha256=a.spec_sha256);print(json.dumps(value));return 0 if value['status']=='committed_main_v4_stage' else 1
    except Exception as e:print(json.dumps({'status':'failed','error_type':type(e).__name__,'credentials_printed':False}));return 1
if __name__=='__main__':raise SystemExit(main())
