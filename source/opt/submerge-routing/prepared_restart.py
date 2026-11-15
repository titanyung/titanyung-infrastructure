"""Kernel-bound permission for a CAS owner's synchronous main restart.

The boot helper must not reacquire an admission flock held by the caller which
is waiting for systemd. A short root-private lease is useful only while that
exact process actually holds that exact existing flock and the currently
published plan/runtime/desired cohort still match. A PID alone is never enough.
"""
import contextlib, hashlib, json, os, stat, tempfile, time
from pathlib import Path

LEASE='/var/lib/submerge-topology/prepared-main-restart.json'
FIELDS=('source_plan_sha256','source_runtime_sha256','cohort_sha256','desired_token_sha256')

def need(value,code):
    if not value:raise RuntimeError(code)

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def sha(value):return hashlib.sha256(value).hexdigest()

def private(path,*,require_root=True):
    fd=os.open(str(path),os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_size<=1024*1024,'prepared_restart_private_file')
        need(not require_root or (info.st_uid==0 and not info.st_mode&0o077),'prepared_restart_private_permissions')
        raw=stream.read(1024*1024+1)
    need(len(raw)<=1024*1024,'prepared_restart_file_bound')
    return raw

def atomic(path,raw):
    path=Path(path);need(not path.is_symlink(),'prepared_restart_symlink')
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix='.prepared-main-',dir=str(path.parent))
    try:
        with os.fdopen(fd,'wb') as stream:
            if hasattr(os,'fchmod'):os.fchmod(stream.fileno(),0o600)
            else:os.chmod(name,0o600)
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
        os.replace(name,path)
    finally:
        if os.path.exists(name):os.unlink(name)

def process_identity(pid,*,proc=Path('/proc')):
    raw=(Path(proc)/str(pid)/'stat').read_text()
    ticks=int(raw.rsplit(') ',1)[1].split()[19])
    return {'pid':pid,'start_ticks':ticks,'boot_id':(Path(proc)/'sys/kernel/random/boot_id').read_text().strip()}

def lock_identity(path):
    path=Path(path);need(not path.is_symlink(),'prepared_restart_lock_symlink')
    info=path.stat();need(stat.S_ISREG(info.st_mode),'prepared_restart_regular_lock')
    return {'path':str(path),'major':os.major(info.st_dev),'minor':os.minor(info.st_dev),'inode':info.st_ino}

def owns_flock(pid,identity,*,proc_locks=Path('/proc/locks')):
    for line in Path(proc_locks).read_text().splitlines():
        fields=line.split()
        if len(fields)<6 or fields[1]!='FLOCK' or fields[3]!='WRITE' or fields[4]!=str(pid):continue
        parts=fields[5].split(':')
        if len(parts)==3 and (int(parts[0],16),int(parts[1],16),int(parts[2]))==(
                identity['major'],identity['minor'],identity['inode']):return True
    return False

def snapshot_fingerprint(snapshot):
    need(snapshot.get('account_sources_verified') is True,'prepared_restart_fresh_account_sources_required')
    expected=sorted(snapshot['desired_users'],key=lambda row:row['name'])
    inlets=[row for row in snapshot['runtime'].get('inbounds',[]) if row.get('type')=='anytls']
    need(inlets and all(sorted(row.get('users',[]),key=lambda user:user['name'])==expected for row in inlets),
         'prepared_restart_published_cohort_differs_from_intent')
    return {key:snapshot[key] for key in FIELDS}

def current_lease(authority,*,path=LEASE,now=None,proc=Path('/proc'),proc_locks=Path('/proc/locks'),require_root=True):
    """Return a verified skip proof or None for no/dead/old-boot leases.

    An active lock owner's invalid/stale lease is an error, not permission to
    wait on its flock. The caller waiting for systemd can then fail and unwind.
    """
    try:raw=private(path,require_root=require_root)
    except FileNotFoundError:return None
    value=json.loads(raw)
    expected={'schema','kind','checked_at','expires_at','process','admission_lock','snapshot'}
    need(isinstance(value,dict) and set(value)==expected and value['schema']==1
         and value['kind']=='cas-main-restart','prepared_restart_lease_schema')
    current_boot=(Path(proc)/'sys/kernel/random/boot_id').read_text().strip()
    if value['process'].get('boot_id')!=current_boot:return None
    try:actual=process_identity(value['process']['pid'],proc=proc)
    except (FileNotFoundError,ProcessLookupError):return None
    if actual!=value['process']:return None
    actual_lock=lock_identity(authority.paths.admission_lock)
    if value['admission_lock']!=actual_lock or not owns_flock(actual['pid'],actual_lock,proc_locks=proc_locks):return None
    now=int(time.time()) if now is None else now
    need(type(value['checked_at']) is int and type(value['expires_at']) is int
         and 0<=now-value['checked_at']<=60 and now<=value['expires_at']<=value['checked_at']+60,
         'active_prepared_restart_lease_expired')
    need(value['snapshot']==snapshot_fingerprint(authority.snapshot()),'active_prepared_restart_snapshot_changed')
    return {'status':'prepared_owner_verified_no_relock','owner_pid':actual['pid'],
            'lease_sha256':sha(raw),**value['snapshot'],'whole_layer_catchup_claimed':False}

@contextlib.contextmanager
def prepared_restart(authority,*,path=LEASE,clock=time.time,proc=Path('/proc'),proc_locks=Path('/proc/locks'),require_root=True):
    """Use INSIDE the existing admission lock, around synchronous restart."""
    pid=os.getpid();identity=lock_identity(authority.paths.admission_lock)
    need(owns_flock(pid,identity,proc_locks=proc_locks),'current_process_admission_flock_required')
    previous=current_lease(authority,path=path,now=int(clock()),proc=proc,proc_locks=proc_locks,require_root=require_root)
    need(previous is None,'another_active_prepared_restart_lease')
    now=int(clock());value={'schema':1,'kind':'cas-main-restart','checked_at':now,'expires_at':now+60,
        'process':process_identity(pid,proc=proc),'admission_lock':identity,
        'snapshot':snapshot_fingerprint(authority.snapshot())}
    raw=canonical(value);atomic(path,raw)
    try:yield value
    finally:
        # A concurrent owner's file must never be removed by this context.
        try:
            if private(path,require_root=require_root)==raw:Path(path).unlink()
        except FileNotFoundError:pass
