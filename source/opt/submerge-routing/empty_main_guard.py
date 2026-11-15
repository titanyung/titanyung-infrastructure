"""Actual main enforcement ACK for an intentionally empty subscriber cohort."""
import copy,hashlib,json,subprocess,time
from pathlib import Path

def need(value,code):
    if not value:raise RuntimeError(code)

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def sha(value):return hashlib.sha256(value).hexdigest()

def _listeners(ports,proc):
    for name in ('tcp','tcp6'):
        path=Path(proc)/'net'/name
        for row in path.read_text().splitlines()[1:]:
            cells=row.split()
            if len(cells)>3 and cells[3]=='0A' and int(cells[1].rsplit(':',1)[1],16) in ports:return True
    return False

class CurrentMainGuard:
    """Delegate nonempty cohorts to ActualMainGuard; prove empty from OS state."""
    def __init__(self,authority,*,rule_set_loader,expected_binary_sha256,runner=subprocess.run,proc=Path('/proc'),clock=time.time,
                 active_guard_factory=None,runtime_module=None,users_function=None):
        if active_guard_factory is None:
            from main_guard import ActualMainGuard
            active_guard_factory=ActualMainGuard
        if runtime_module is None:
            from policy_inputs import runtime
            runtime_module=runtime
        if users_function is None:
            from policy_inputs import users
            users_function=users
        self.authority,self.runtime,self.users=authority,runtime_module,users_function
        self.loader,self.runner,self.proc,self.clock=rule_set_loader,runner,Path(proc),clock
        self.active=active_guard_factory(authority,rule_set_loader=rule_set_loader,
            expected_binary_sha256=expected_binary_sha256,runner=runner,proc=proc)

    def __call__(self):
        before=self.authority.snapshot()
        if before['desired_users']:return self.active()
        need(before.get('bootstrap_runtime_source')!='verified_private_template','empty_main_actual_runtime_required')
        need(self.runtime.revised(before['plan']),'empty_main_new_revision_required')
        self.runtime.validate_loaded_server_policy(before['runtime'],before['plan'],rule_set_loader=self.loader)
        need(self.users(before['runtime'])==[],'empty_main_runtime_still_has_credentials')
        ports={row['listen_port'] for row in before['runtime'].get('inbounds',[]) if 'listen_port' in row}
        api=before['runtime'].get('experimental',{}).get('clash_api',{}).get('external_controller','')
        if api.startswith('127.0.0.1:'):ports.add(int(api.rsplit(':',1)[1]))
        def stopped():
            result=self.runner(['systemctl','show','dmit-direct-staging.service',
                '--property=MainPID,ActiveState,SubState','--no-pager'],capture_output=True,text=True,timeout=5)
            need(result.returncode==0,'empty_main_unit_state_unavailable')
            values=dict(row.split('=',1) for row in result.stdout.splitlines() if '=' in row)
            need(values.get('MainPID')=='0' and values.get('ActiveState')=='inactive'
                 and values.get('SubState') in ('dead','exited'),'empty_main_not_actually_stopped')
            need(not _listeners(ports,self.proc),'empty_main_owned_native_listener_survives')
            return values
        observed=stopped();after=self.authority.snapshot();observed_after=stopped()
        fields=('source_runtime_sha256','source_plan_sha256','desired_token_sha256','cohort_sha256')
        need(observed==observed_after and all(before[k]==after[k] for k in fields)
             and not after['desired_users'] and self.users(after['runtime'])==[],
             'empty_main_or_desired_changed_during_ack')
        boot=(self.proc/'sys/kernel/random/boot_id').read_text().strip()
        generation=sha(canonical({'enforcement':'service_stopped_no_accounts','boot_id':boot,
            **{k:after[k] for k in fields}}))
        return {'verified':True,'generation':generation,'cohort_sha256':after['cohort_sha256'],
            'runtime_sha256':after['source_runtime_sha256'],'plan_sha256':after['source_plan_sha256'],
            'desired_token_sha256':after['desired_token_sha256'],'main_pid':0,'boot_id':boot,'start_ticks':0,
            'enforcement':'service_stopped_no_accounts','native_listener_absence_verified':True,
            'desired_account_ack_verified':True,'users':0}
