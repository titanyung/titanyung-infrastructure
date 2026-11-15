"""Prepare exact-source account reload hooks, no installation or SSH."""
import hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
SOURCE=ROOT/'.private/live-source/dmit/opt'

def prepare():
    target=HERE/'account-hooks';target.mkdir(exist_ok=True)
    outputs={}
    for folder,name,anchor,replacement in (
      ('submerge-topology','topology_enrollment_runtime.py',
       "    def reload():\n        commands = [['systemctl', 'restart', unit], ['systemctl', 'is-active', '--quiet', unit]]\n",
       """    def reload():
        from contextlib import nullcontext
        restart_lease = nullcontext()
        if unit == 'dmit-direct-staging.service':
            from network_runtime import revised
            if revised(_network_plan()):
                # The enrollment/revoke/restore coordinator ALREADY owns the
                # shared admission FLOCK. Prove it and render fresh users in
                # this parent process; never reacquire it in a systemd child.
                import sys
                if '/opt/submerge-routing' not in sys.path:
                    sys.path.insert(0, '/opt/submerge-routing')
                from bootstrap_current import refresh_caller_locked
                refresh_caller_locked()
                from prepared_restart import prepared_restart
                from desired_accounts import Authority
                restart_lease = prepared_restart(Authority())
        commands = [['systemctl', 'restart', unit], ['systemctl', 'is-active', '--quiet', unit]]
"""),
      ('submerge-user-access','production_adapter.py',
       "        if explicitly_empty_cohort(local, sui):\n            before = _pid('dmit-direct-staging.service', runner)\n",
       """        if explicitly_empty_cohort(local, sui):
            from network_runtime import revised
            if revised(_network_plan()):
                # Preserve an exact empty current runtime for both V4
                # executors and durable denial before the last core stops.
                import sys
                if '/opt/submerge-routing' not in sys.path:
                    sys.path.insert(0, '/opt/submerge-routing')
                from bootstrap_current import refresh_caller_locked
                refresh_caller_locked()
            before = _pid('dmit-direct-staging.service', runner)
""")):
        raw=(SOURCE/folder/name).read_bytes();text=raw.decode().replace('\r\n','\n')
        if text.count(anchor)!=1:raise ValueError('account_boot_hook_source_anchor_changed')
        code=text.replace(anchor,replacement,1);compile(code,name,'exec')
        if name=='topology_enrollment_runtime.py':
            # The scope includes the synchronous systemd dependency startup.
            # A boot helper can validate this short-lived prepared lease
            # without attempting the parent's already-held admission lock.
            start=code.index('        for argv in commands:\n',code.index('def systemd_reload('))
            end=code.index('    return reload\n',start)
            body=code[start:end]
            code=code[:start]+'        with restart_lease:\n'+''.join('    '+line if line.strip() else line for line in body.splitlines(keepends=True))+code[end:]
            compile(code,name,'exec')
        out=target/name;out.write_bytes(code.encode())
        outputs['/opt/'+folder+'/'+name]={'file':name,'source_sha256':hashlib.sha256(raw).hexdigest(),
                                         'candidate_sha256':hashlib.sha256(out.read_bytes()).hexdigest()}
    (target/'manifest.json').write_text(json.dumps({'schema':1,'files':outputs,'production_changed':False},indent=2))
    return outputs
if __name__=='__main__':print(json.dumps(prepare()))
