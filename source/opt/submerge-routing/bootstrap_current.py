"""Boot-only fresh-cohort renderer for the installed revision.

Runs once BEFORE main startup, taking the common admission lock. Main's
ExecCondition is nonlocking, so an account coordinator can restart it while
holding that same lock. Crossing a retirement boundary requires the root
whole-layer catch-up owner first; this program never invents its receipt.
"""
import argparse,json,time,os
from pathlib import Path
from bootstrap_revision import BootAuthority,assert_fresh_boundary,durable_receipt
from main_policy_cas import Transaction
from policy_inputs import canonical,need,runtime,sha
from server_route_policy import load_rule_sets
from desired_accounts import read_file

SETTINGS='/etc/submerge-routing/bootstrap-settings.json'

def caller_holds_admission_lock(authority,*,proc_locks='/proc/locks'):
    """Prove this process owns the EXISTING coordinator FLOCK, never a proxy lock."""
    path=Path(authority.paths.admission_lock)
    info=path.stat();wanted=(os.major(info.st_dev),os.minor(info.st_dev),info.st_ino)
    for line in Path(proc_locks).read_text().splitlines():
        fields=line.split()
        if len(fields)<6 or fields[1]!='FLOCK' or fields[3]!='WRITE' or fields[4]!=str(os.getpid()):continue
        parts=fields[5].split(':')
        if len(parts)==3 and (int(parts[0],16),int(parts[1],16),int(parts[2]))==wanted:return True
    return False

def render_current(settings,*,authority=None,clock=time.time,write=None,caller_locked=False):
    from dmit_topology_render import write_revision_bytes
    write=write or write_revision_bytes
    need(isinstance(settings,dict) and set(settings)=={'schema','template_path','template_sha256','durable_receipt'}
         and settings['schema']==1,'exact_bootstrap_settings_required')
    now=int(clock())
    a=authority or BootAuthority(template=settings['template_path'],template_sha256=settings['template_sha256'])
    import contextlib
    if caller_locked:need(caller_holds_admission_lock(a),'current_process_admission_flock_required')
    with contextlib.nullcontext() if caller_locked else a.lock():
        before=a.snapshot()
        if not runtime.revised(before['plan']):return {'status':'legacy_bootstrap_noop','changed':False}
        assert_fresh_boundary(before['plan'],now)
        tx=Transaction(a,rule_set_loader=load_rule_sets)
        prepared=tx._prepare(before,before['plan'])
        tx._assert_current(prepared,a.snapshot())
        write(a.paths.runtime,canonical(prepared['runtime']))
        receipt=durable_receipt(prepared)
        receipt['boot_rendered_at']=now;receipt['whole_layer_catchup_claimed']=False
        write(settings['durable_receipt'],canonical(receipt))
        return {'status':'fresh_cohort_boot_rendered','user_count':prepared['manifest']['user_count'],
                'runtime_sha256':prepared['manifest']['runtime_sha256'],
                'cohort_sha256':prepared['manifest']['cohort_sha256'],'changed':True,
                'retirement_boundaries_current':True,'whole_layer_catchup_claimed':False}

def refresh_caller_locked(settings_path=SETTINGS):
    """Enrollment/revoke/restore callback, before its synchronous main restart."""
    return render_current(json.loads(read_file(settings_path)),caller_locked=True)

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',action='store_true');p.add_argument('--settings',default=SETTINGS)
    a=p.parse_args(argv)
    if not a.run:print(json.dumps({'status':'dry_run','changed':False}));return 0
    try:print(json.dumps(render_current(json.loads(read_file(a.settings)))));return 0
    except Exception as e:
        print(json.dumps({'status':'failed','error_type':type(e).__name__,'native_start_allowed':False}));return 1
if __name__=='__main__':raise SystemExit(main())
