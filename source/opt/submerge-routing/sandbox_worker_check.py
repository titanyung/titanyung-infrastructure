"""Read-only authority/API + owned core smoke check for the REAL unit sandbox.

No selector writes, no real user credentials used by a probe, and no external
HTTP request. Intended for a transient systemd unit with the exact production
filesystem/capability restrictions before enabling the persistent worker.
"""
import hashlib,json,socket,subprocess,tempfile,sqlite3,re
from pathlib import Path
from desired_accounts import Authority,database_rows
from policy_inputs import sha,need
from main_guard import owns_tcp_port
from main_business_worker import ProbeCore,available_ports
from bootstrap_current import caller_holds_admission_lock
import business_control

PHASE='initial'

def step(label,call):
    global PHASE
    PHASE=label
    return call()

def error_detail(error):
    result={'status':'failed','error_type':type(error).__name__,'phase':PHASE,'selectors_changed':False}
    if isinstance(error,sqlite3.Error):
        result['sqlite_error_name']=getattr(error,'sqlite_errorname',None)
        result['sqlite_error_code']=getattr(error,'sqlite_errorcode',None)
        text=str(error)
        if text.startswith(('unable to open database','attempt to write a readonly database','database is locked',
                            'database is busy','no such table:','no such column:','disk I/O error','readonly database')) \
           and re.fullmatch(r'[A-Za-z0-9_ ./:()-]{1,180}',text):result['sqlite_message']=text
    return result

def run(binary='/root/lazycat-test-config/sing-box'):
    authority=Authority();before={p:sha(Path(p).read_bytes()) for p in
      ('/run/dmit-direct-staging/config.json','/etc/submerge-topology/network-plan.json','/etc/submerge-edge/client-settings.json')}
    with step('admission_lock_open_rw',authority.lock):
        need(step('verify_real_caller_kernel_flock',lambda:caller_holds_admission_lock(authority)),'actual_kernel_flock_owner_unproven')
        for label,path in (('sui',authority.paths.sui_db),('lifecycle',authority.paths.control_db)):
            step('readonly_'+label+'_sqlite_open',lambda path=path:database_rows(path,'PRAGMA journal_mode'))
        snapshot=step('fresh_authority_snapshot',authority.snapshot)
    result=step('read_main_pid',lambda:subprocess.run(['systemctl','show','dmit-direct-staging.service','--property=MainPID','--value'],capture_output=True,text=True,timeout=5))
    need(result.returncode==0 and result.stdout.strip().isdigit(),'actual_native_pid_unavailable')
    pid=int(result.stdout.strip());need(pid>0,'actual_native_not_running')
    api=snapshot['runtime']['experimental']['clash_api']['external_controller']
    need(api.startswith('127.0.0.1:') and owns_tcp_port(pid,int(api.rsplit(':',1)[1])),'actual_main_api_owner_failed')
    current=step('authenticated_read_main_api',lambda:business_control.private_request(snapshot['runtime'])('GET','/configs',None))
    need(isinstance(current.get('mode'),str),'actual_authenticated_api_read_failed')
    parent=Path('/run/submerge-business-probe');parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    port=available_ports(1)[0]
    config={'log':{'level':'warn'},'inbounds':[{'type':'mixed','tag':'owned-sandbox','listen':'127.0.0.1','listen_port':port}],
            'outbounds':[{'type':'direct','tag':'owned-direct'}],'route':{'rules':[{'action':'reject'}],'final':'owned-direct'}}
    with tempfile.TemporaryDirectory(prefix='owned-sandbox-check-',dir=str(parent)) as name:
        folder=Path(name);folder.chmod(0o700)
        with step('owned_native_core_start',lambda:ProbeCore(binary,config,folder)) as core:need(core.process.poll() is None,'owned_sandbox_core_failed')
    after={p:sha(Path(p).read_bytes()) for p in before};need(after==before,'production_guard_changed')
    fresh=subprocess.run(['systemctl','show','dmit-direct-staging.service','--property=MainPID','--value'],capture_output=True,text=True,timeout=5)
    need(fresh.returncode==0 and fresh.stdout.strip()==str(pid),'main_pid_changed')
    return {'status':'passed','actual_systemd_sandbox_required':True,'actual_admission_lock_opened_rw':True,
        'readonly_sui_and_lifecycle_snapshot':True,'actual_main_api_pid_owner_verified':True,
        'actual_caller_kernel_flock_owner_verified':True,
        'authenticated_get_configs_only':True,'isolated_native_started_and_cleaned':True,
        'owned_temp_removed':not folder.exists(),'external_requests':0,'selectors_changed':False,
        'main_and_client_source_hashes_unchanged':True,'cohort_count':len(snapshot['desired_users'])}

if __name__=='__main__':
    try:print(json.dumps(run()))
    except Exception as error:print(json.dumps(error_detail(error)))
