"""Fresh canonical intent from existing admission files and read-only DBs.

Uses the existing admission lock. No credentials are added, user restored,
SQLite row written, or service restarted. An empty cohort is a real result.
"""
import base64, contextlib, copy, hashlib, json, os, sqlite3, stat, time
from dataclasses import dataclass
from pathlib import Path
from policy_inputs import canonical,sha,need

@dataclass(frozen=True)
class Paths:
    runtime: str='/run/dmit-direct-staging/config.json'
    plan: str='/etc/submerge-topology/network-plan.json'
    private: str='/etc/dmit-direct-staging/private.json'
    map0: str='/var/lib/submerge-staging/dmit-direct-users.json'
    map1: str='/var/lib/submerge-public/dmit-users.json'
    ready: str='/var/lib/submerge-public/ready-users.json'
    sui_db: str='/usr/local/s-ui/db/s-ui.db'
    control_db: str='/var/lib/submerge-user-access/control.db'
    admission_lock: str='/root/topology-enrollment-20261105/lock'

def read_file(path,*,require_root=True):
    fd=os.open(str(path),os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and (not require_root or
             (getattr(info,'st_uid',0)==0 and not info.st_mode&0o077)),'private_authority_permissions')
        raw=stream.read(16*1024*1024+1)
    need(len(raw)<=16*1024*1024,'authority_input_size')
    return raw

def typed(value):
    if isinstance(value,(bytes,bytearray,memoryview)):return {'blob':base64.b64encode(value).decode()}
    return {'value':value}

class DatabaseGenerationChanged(RuntimeError):pass

def database_rows(path,statement,*,require_host_view=False):
    path=Path(path);need(path.is_file() and not path.is_symlink(),'existing_readonly_database_required')
    if require_host_view and os.name!='nt':
        host=Path('/proc/1/root')/str(path).lstrip('/')
        here=path.stat();actual=host.stat()
        if (here.st_dev,here.st_ino)!=(actual.st_dev,actual.st_ino):
            raise DatabaseGenerationChanged('database_inode_generation_changed_restart_required')
    with contextlib.closing(sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True,timeout=5)) as db:
        db.execute('PRAGMA query_only=ON')
        return db.execute(statement).fetchall()

class Authority:
    def __init__(self,paths=None,*,identity_reader=None,require_root=True,clock=time.time):
        self.paths=paths or Paths();self.require_root=require_root;self.clock=clock
        if identity_reader is None:
            from new_enrollment import read_sui_identity
            identity_reader=lambda name,**kwargs:read_sui_identity(name,self.paths.sui_db,**kwargs)
        self.identity_reader=identity_reader

    @contextlib.contextmanager
    def lock(self):
        # The same lock file is used by production LocalCredentialAdapter and
        # EnrollmentCoordinator; a new unrelated migration lock is insufficient.
        import fcntl
        path=Path(self.paths.admission_lock)
        need(path.parent.is_dir() and not path.is_symlink(),'existing_admission_lock_required')
        with path.open('a+b') as stream:
            if self.require_root:os.fchmod(stream.fileno(),0o600)
            fcntl.flock(stream.fileno(),fcntl.LOCK_EX)
            try:yield
            finally:fcntl.flock(stream.fileno(),fcntl.LOCK_UN)

    def material(self):
        values={name:read_file(getattr(self.paths,name),require_root=self.require_root)
                for name in ('private','map0','map1','ready')}
        sui=database_rows(self.paths.sui_db,'SELECT id,enable,name,sub_secret,config,inbounds FROM clients ORDER BY id',require_host_view=self.require_root)
        subjects=database_rows(self.paths.control_db,'SELECT client_id,username,generation,state FROM subjects ORDER BY client_id',require_host_view=self.require_root)
        token=sha(canonical({'files':{k:sha(v) for k,v in values.items()},
            'sui':[[typed(v) for v in row] for row in sui],
            'subjects':[[typed(v) for v in row] for row in subjects]}))
        return values,subjects,token

    def snapshot(self):
        values,subjects,before=self.material()
        docs={key:json.loads(raw) for key,raw in values.items()}
        rows=docs['private'].get('users')
        need(isinstance(rows,list) and all(isinstance(row,dict) and set(row)=={'name','password'}
             and isinstance(row['name'],str) and row['name'] and isinstance(row['password'],str)
             and len(row['password'])>=24 for row in rows),'private_cohort_schema')
        need(len({r['name'] for r in rows})==len(rows) and len({r['password'] for r in rows})==len(rows),
             'private_credentials_not_unique')
        states={username:(str(client_id),generation,state) for client_id,username,generation,state in subjects}
        need(len(states)==len(subjects),'lifecycle_username_not_unique')
        selected=[]
        for row in rows:
            name=row['name'];trial=name=='test' and docs['private'].get('topology_trial_test_enabled') is True
            if name=='test' and not trial:continue
            intent=states.get(name)
            if intent and intent[2] not in ('active','armed','restore_pending','restoring'):continue
            try:identity=self.identity_reader(name,allow_trial=trial)
            except Exception as error:
                # Only the production reader's fixed enrollment rejection is a
                # per-user exclusion; unknown reader/storage failure aborts.
                if type(error).__name__=='EnrollmentError':continue
                raise RuntimeError('identity_reader_unavailable') from None
            need(identity.name==name and identity.sub_secret==name,'canonical_sui_binding_changed')
            bound=str(identity.client_id)+':'+hashlib.sha256(name.encode()).hexdigest()[:24]
            if intent and intent[0]!=bound:continue
            need(all(isinstance(docs[k],dict) and docs[k].get(name)==row['password'] for k in ('map0','map1')),
                 'canonical_map_credential_disagreement')
            selected.append(copy.deepcopy(row))
        _,_,after=self.material()
        need(after==before,'desired_accounts_changed_during_snapshot')
        runtime_raw=read_file(self.paths.runtime,require_root=self.require_root)
        plan_raw=read_file(self.paths.plan,require_root=self.require_root)
        selected.sort(key=lambda row:row['name'])
        return {'schema':1,'checked_at':int(self.clock()),'desired_token_sha256':before,
                'desired_users':selected,'cohort_sha256':sha(canonical(selected)),
                'source_runtime_sha256':sha(runtime_raw),'source_plan_sha256':sha(plan_raw),
                'source_runtime_raw':runtime_raw,'source_plan_raw':plan_raw,
                'runtime':json.loads(runtime_raw),'plan':json.loads(plan_raw),
                'runtime_mode':'stopped_empty_cohort' if not selected else 'enabled',
                'account_sources_verified':True}
