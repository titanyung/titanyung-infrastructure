"""Actual process/API/current-intent proof for business selector writes.

Read-only collection. It authenticates the loopback API and verifies its socket
belongs to the current native MainPID, whose source config predates startup.
No stored mirror, static lambda, source-file hash alone, or old ACK is enough.
"""
import hashlib, json, os, re, subprocess, time
from pathlib import Path
from policy_inputs import sha,canonical,need,users,runtime
import business_control

UNIT='dmit-direct-staging.service'

def process_start(pid,*,proc=Path('/proc'),clock_ns=time.time_ns):
    stat_text=(proc/str(pid)/'stat').read_text();parts=stat_text.rsplit(') ',1)[1].split()
    ticks=int(parts[19]);hz=os.sysconf('SC_CLK_TCK')
    # /proc/uptime is rounded down to 10ms; this is a conservative lower bound
    # on process start wall time. Ambiguous very-recent files fail closed.
    before=clock_ns();uptime=float((proc/'uptime').read_text().split()[0])
    lower=before-int((uptime+0.01)*1_000_000_000)+int(ticks/hz*1_000_000_000)
    return {'pid':pid,'start_ticks':ticks,'boot_id':(proc/'sys/kernel/random/boot_id').read_text().strip(),
            'start_wall_lower_ns':lower}

def owns_tcp_port(pid,port,*,proc=Path('/proc')):
    inode=set()
    for line in (proc/'net/tcp').read_text().splitlines()[1:]:
        fields=line.split()
        if len(fields)>9 and fields[1]=='0100007F:'+format(port,'04X') and fields[3]=='0A':inode.add(fields[9])
    if len(inode)!=1:return False
    for fd in (proc/str(pid)/'fd').iterdir():
        try:target=os.readlink(str(fd))
        except OSError:continue
        if target=='socket:['+next(iter(inode))+']':return True
    return False

class ActualMainGuard:
    def __init__(self,authority,*,rule_set_loader,expected_binary_sha256,runner=subprocess.run,proc=Path('/proc')):
        need(re.fullmatch('[a-f0-9]{64}',expected_binary_sha256 or ''),'explicit_native_binary_hash_required')
        self.authority,self.loader=authority,rule_set_loader
        self.expected_binary_sha256=expected_binary_sha256;self.runner=runner;self.proc=Path(proc);self._exe_cache=None

    def __call__(self):
        snap=self.authority.snapshot();config=snap['runtime'];plan=snap['plan']
        need(runtime.revised(plan),'business_guard_requires_revised_main')
        runtime.validate_loaded_server_policy(config,plan,rule_set_loader=self.loader)
        need(sha(canonical(users(config)))==snap['cohort_sha256'],'desired_account_ack_mismatch')
        result=self.runner(['systemctl','show',UNIT,'--property=MainPID,ActiveState','--no-pager'],
                           capture_output=True,text=True,timeout=5)
        need(result.returncode==0,'main_process_state_unavailable')
        fields=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
        need(fields.get('ActiveState')=='active' and fields.get('MainPID','').isdigit(),'native_not_active')
        pid=int(fields['MainPID']);need(pid>0,'native_pid_missing')
        process=process_start(pid,proc=self.proc)
        command=(self.proc/str(pid)/'cmdline').read_bytes().split(b'\0')
        expected=str(self.authority.paths.runtime).encode()
        need(sum(value==b'-c' for value in command)==1
             and any(command[i]==b'-c' and i+1<len(command) and command[i+1]==expected for i in range(len(command))),
             'native_process_config_path_mismatch')
        info=Path(self.authority.paths.runtime).stat()
        need(info.st_mtime_ns<=process['start_wall_lower_ns'],'current_config_not_proven_loaded')
        cache_key=(pid,process['start_ticks'],process['boot_id'])
        if self._exe_cache!=cache_key:
            h=hashlib.sha256()
            with (self.proc/str(pid)/'exe').open('rb') as stream:
                for block in iter(lambda:stream.read(65536),b''):h.update(block)
            need(h.hexdigest()==self.expected_binary_sha256,'actual_loaded_native_binary_hash_mismatch')
            self._exe_cache=cache_key
        api=config['experimental']['clash_api'];address=api['external_controller']
        need(re.fullmatch(r'127\.0\.0\.1:[0-9]+',address),'main_api_not_private')
        need(owns_tcp_port(pid,int(address.rsplit(':',1)[1]),proc=self.proc),'authenticated_api_not_owned_by_main_pid')
        request=business_control.private_request(config)
        modes=request('GET','/configs',None)
        peers=request('GET','/proxies',None).get('proxies',{})
        expected_selectors={r['tag'] for r in config['outbounds'] if r.get('type')=='selector'}
        need(isinstance(modes,dict) and isinstance(modes.get('mode'),str)
             and expected_selectors<=set(peers),'actual_business_api_inventory_mismatch')
        after=self.authority.snapshot()
        need(all(after[k]==snap[k] for k in ('source_runtime_sha256','source_plan_sha256','desired_token_sha256','cohort_sha256')),
             'main_generation_changed_during_ack')
        process_after=process_start(pid,proc=self.proc)
        need(all(process_after[k]==process[k] for k in ('pid','start_ticks','boot_id')),'main_pid_generation_changed')
        generation=sha(canonical({k:process[k] for k in ('pid','start_ticks','boot_id')} )
                       +snap['source_plan_sha256'].encode()+snap['source_runtime_sha256'].encode())
        return {'verified':True,'generation':generation,'cohort_sha256':snap['cohort_sha256'],
                'runtime_sha256':snap['source_runtime_sha256'],'plan_sha256':snap['source_plan_sha256'],
                'desired_token_sha256':snap['desired_token_sha256'],'main_pid':pid,
                'boot_id':process['boot_id'],'start_ticks':process['start_ticks'],
                'actual_api_owned_by_main_pid':True,'desired_account_ack_verified':True}

def set_business_selections(guard,qualified_health,*,category_health=None,only=None):
    # Share the admission lock with revocation/restore/enrollment and the main
    # policy installer throughout every guarded selector mutation.
    with guard.authority.lock():
        snap=guard.authority.snapshot()
        return business_control.set_selections(snap['plan']['server_policy']['routing_revision'],qualified_health,
            business_control.private_request(snap['runtime']),guard=guard,category_health=category_health,only=only)
