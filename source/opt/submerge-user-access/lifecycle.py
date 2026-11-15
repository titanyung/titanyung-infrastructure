"""Durable next-update purge and revocation lifecycle; no network operations.

Callers MUST resolve Subject from authenticated S-UI data, authorize admin
actions, validate purge codecs, and make revocation executors idempotent.
An issued HTTP response does not prove that a client erased cached credentials.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
import uuid


class Conflict(RuntimeError):pass
class BindingMismatch(Conflict):pass
class LostLease(Conflict):pass


def _label(value,name,maximum=128):
    if not isinstance(value,str) or not value or len(value)>maximum or value!=value.strip() or any(ord(c)<32 for c in value):
        raise ValueError('invalid_'+name)
    return value


def _identifier(value,name):
    _label(value,name)
    if re.fullmatch(r'[A-Za-z0-9_.:@+\-]{1,128}',value) is None:raise ValueError('invalid_'+name)
    return value


@dataclass(frozen=True)
class Subject:
    username: str
    client_id: str
    def __post_init__(self):
        _label(self.username,'canonical_username')
        if any(c in self.username for c in '/\\?#'):raise ValueError('invalid_canonical_username')
        _identifier(self.client_id,'client_id')


_VALIDATED=object()
MANUAL_DISABLED_STATES=frozenset({'armed','purge_issued','revoking','revoked'})
RESTORE_PENDING_STATES=frozenset({'restore_pending','restoring'})


@dataclass(frozen=True)
class PreparedPurge:
    body: bytes=field(repr=False)
    format_name: str
    content_type: str
    sha256: str
    _proof: object=field(repr=False,compare=False)
    def __post_init__(self):
        if self._proof is not _VALIDATED:raise ValueError('purge_payload_not_validated')


def prepare_purge(body,format_name,content_type,validator):
    """Validate before entering the claim transaction; never persist the body.

    validator(body, format_name, content_type) must explicitly return True.
    Codec validity and absence of airport references are integration concerns.
    """
    if not isinstance(body,bytes) or not 0<len(body)<=2*1024*1024:raise ValueError('invalid_purge_body')
    if not isinstance(format_name,str) or re.fullmatch(r'[a-z0-9_+\-]{1,32}',format_name) is None:raise ValueError('invalid_format')
    _label(content_type,'content_type')
    if not content_type.isascii() or not callable(validator) or validator(body,format_name,content_type) is not True:
        raise ValueError('purge_payload_not_validated')
    return PreparedPurge(body,format_name,content_type,hashlib.sha256(body).hexdigest(),_VALIDATED)


@dataclass(frozen=True)
class Decision:
    action: str
    state: str | None
    reason: str=''
    claim_id: str | None=None
    response: PreparedPurge | None=field(default=None,repr=False)
    generation: int | None=None


SCHEMA='''
CREATE TABLE IF NOT EXISTS control_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS subjects(
 client_id TEXT PRIMARY KEY,username TEXT NOT NULL UNIQUE,generation INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('active','armed','purge_issued','revoking','revoked','restore_pending','restoring')),
 armed_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,claim_id TEXT UNIQUE,claimed_at INTEGER,
 delivery_state TEXT CHECK(delivery_state IN ('pending','succeeded','failed')),delivery_at INTEGER,
 revoked_at INTEGER,last_error_code TEXT);
CREATE TABLE IF NOT EXISTS operations(
 operation_id TEXT PRIMARY KEY,client_id TEXT NOT NULL,username TEXT NOT NULL,
 actor TEXT NOT NULL,reason TEXT NOT NULL,created_at INTEGER NOT NULL,
 action TEXT NOT NULL CHECK(action IN ('arm','restore')));
CREATE TABLE IF NOT EXISTS revocation_jobs(
 job_id TEXT PRIMARY KEY,client_id TEXT NOT NULL,generation INTEGER NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('revoke','restore')),
 state TEXT NOT NULL CHECK(state IN ('pending','running','done','cancelled')),
 attempts INTEGER NOT NULL DEFAULT 0,not_before INTEGER NOT NULL,
 lease_owner TEXT,lease_token TEXT,lease_until INTEGER,last_error_code TEXT,
 created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,UNIQUE(client_id,generation),
 FOREIGN KEY(client_id) REFERENCES subjects(client_id));
CREATE INDEX IF NOT EXISTS due_revocation_jobs ON revocation_jobs(state,not_before,lease_until);
CREATE TABLE IF NOT EXISTS audit_log(
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT NOT NULL UNIQUE,
 at INTEGER NOT NULL,client_id TEXT NOT NULL,username TEXT NOT NULL,
 actor TEXT NOT NULL,action TEXT NOT NULL,details_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS audit_subject_sequence ON audit_log(client_id,sequence);
CREATE INDEX IF NOT EXISTS audit_manual_arm_subject ON audit_log(client_id,username,sequence DESC)
 WHERE action IN ('armed','arm_reaffirmed');
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
 BEGIN SELECT RAISE(ABORT,'audit_log_is_append_only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
 BEGIN SELECT RAISE(ABORT,'audit_log_is_append_only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_replace BEFORE INSERT ON audit_log
 WHEN EXISTS(SELECT 1 FROM audit_log WHERE sequence=NEW.sequence OR event_id=NEW.event_id)
 BEGIN SELECT RAISE(ABORT,'audit_log_is_append_only'); END;
'''


class LifecycleStore:
    def __init__(self,path,*,clock=None,delivery_grace=30):
        self.path=Path(path);self.clock=clock or (lambda:int(time.time()))
        if type(delivery_grace) is not int or not 1<=delivery_grace<=300:raise ValueError('invalid_delivery_grace')
        self.delivery_grace=delivery_grace
        if self.path.is_symlink():raise ValueError('database_symlink_forbidden')
        if not self.path.parent.exists():self.path.parent.mkdir(parents=True,mode=0o700)
        if not self.path.exists():
            try:
                descriptor=os.open(str(self.path),os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600);os.close(descriptor)
            except FileExistsError:pass
        if self.path.is_symlink():raise ValueError('database_symlink_forbidden')
        if not self.path.is_file():raise ValueError('database_not_regular')
        os.chmod(self.path,0o600)
        with self._db() as db:
            db.execute('PRAGMA journal_mode=WAL')
            exists=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='control_meta'").fetchone()
            row=db.execute("SELECT value FROM control_meta WHERE key='schema_version'").fetchone() if exists else None
            if row is not None and row[0]=='1':self._migrate_v1(db)
            elif row is not None and row[0]!='2':raise ValueError('unsupported_schema_version')
            db.executescript(SCHEMA)
            db.execute("INSERT OR IGNORE INTO control_meta VALUES('schema_version','2')")

    @staticmethod
    def _migrate_v1(db):
        """Expand state/job CHECK sets without touching the permanent audit."""
        if db.execute('PRAGMA foreign_key_check').fetchone() is not None:raise ValueError('legacy_foreign_key_error')
        db.execute('PRAGMA foreign_keys=OFF');db.execute('BEGIN IMMEDIATE')
        try:
            current=db.execute("SELECT value FROM control_meta WHERE key='schema_version'").fetchone()
            if current is not None and current[0]=='2':
                db.execute('COMMIT');return
            for old,new in (('subjects','subjects_v2'),('revocation_jobs','revocation_jobs_v2')):
                sql=re.search(r'CREATE TABLE IF NOT EXISTS '+old+r'\(.*?\);',SCHEMA,re.S).group(0)
                db.execute(sql.replace('IF NOT EXISTS '+old,'IF NOT EXISTS '+new,1))
            columns='client_id,username,generation,state,armed_at,updated_at,claim_id,claimed_at,delivery_state,delivery_at,revoked_at,last_error_code'
            db.execute('INSERT INTO subjects_v2('+columns+') SELECT '+columns+' FROM subjects')
            columns='job_id,client_id,generation,state,attempts,not_before,lease_owner,lease_token,lease_until,last_error_code,created_at,updated_at'
            db.execute("INSERT INTO revocation_jobs_v2("+columns+",kind) SELECT "+columns+",'revoke' FROM revocation_jobs")
            if 'action' not in {row[1] for row in db.execute('PRAGMA table_info(operations)')}:
                db.execute("ALTER TABLE operations ADD COLUMN action TEXT NOT NULL DEFAULT 'arm'")
            db.execute('DROP TABLE revocation_jobs');db.execute('DROP TABLE subjects')
            db.execute('ALTER TABLE subjects_v2 RENAME TO subjects')
            db.execute('ALTER TABLE revocation_jobs_v2 RENAME TO revocation_jobs')
            db.execute("UPDATE control_meta SET value='2' WHERE key='schema_version'")
            db.execute('COMMIT')
        except BaseException:
            db.execute('ROLLBACK');raise
        finally:db.execute('PRAGMA foreign_keys=ON')

    @contextmanager
    def _db(self,write=False):
        db=sqlite3.connect(str(self.path),timeout=5,isolation_level=None)
        db.row_factory=sqlite3.Row;db.execute('PRAGMA foreign_keys=ON');db.execute('PRAGMA busy_timeout=5000')
        try:
            if write:db.execute('BEGIN IMMEDIATE')
            yield db
            if write:db.execute('COMMIT')
        except BaseException:
            if write and db.in_transaction:db.execute('ROLLBACK')
            raise
        finally:db.close()

    def _now(self,now):
        value=self.clock() if now is None else now
        if type(value) is not int or value<0:raise ValueError('invalid_clock')
        return value

    @staticmethod
    def _subject(subject):
        if not isinstance(subject,Subject):raise TypeError('authoritative_subject_required')

    @staticmethod
    def _bound(db,subject):
        row=db.execute('SELECT * FROM subjects WHERE client_id=? OR username=?',(subject.client_id,subject.username)).fetchall()
        if not row:return None
        if len(row)!=1 or (row[0]['client_id'],row[0]['username'])!=(subject.client_id,subject.username):
            raise BindingMismatch('authoritative_identity_changed')
        return row[0]

    @staticmethod
    def _audit(db,subject,actor,action,now,details,*,event_id=None):
        db.execute('INSERT INTO audit_log(event_id,at,client_id,username,actor,action,details_json) VALUES(?,?,?,?,?,?,?)',
            (event_id or uuid.uuid4().hex,now,subject.client_id,subject.username,actor,action,json.dumps(details,ensure_ascii=False,sort_keys=True)))

    @staticmethod
    def _manual_disabled_context(db,row):
        """Only a confirmed manual arm for this generation enables repeats.

        A S-UI disabled flag or an unrelated automatic policy is not inferred
        from the state name. Permanent manual operation/audit bindings provide
        the reason and prevent an old ban from affecting a restored generation.
        """
        if row['state'] not in MANUAL_DISABLED_STATES:return None
        event=db.execute("SELECT details_json FROM audit_log WHERE client_id=? AND username=? AND action IN ('armed','arm_reaffirmed') ORDER BY sequence DESC LIMIT 1",
                         (row['client_id'],row['username'])).fetchone()
        if event is None:return None
        try:details=json.loads(event['details_json'])
        except (ValueError,TypeError):return None
        if not isinstance(details,dict) or details.get('generation')!=row['generation']:return None
        operation=db.execute("SELECT operation_id,reason FROM operations WHERE operation_id=? AND client_id=? AND username=? AND action='arm'",
                             (details.get('operation_id'),row['client_id'],row['username'])).fetchone()
        return dict(operation) if operation is not None else None

    @staticmethod
    def _restoring_context(db,row):
        """Only a confirmed restore for this generation may get a placeholder."""
        if row['state'] not in RESTORE_PENDING_STATES:return None
        event=db.execute("SELECT details_json FROM audit_log WHERE client_id=? AND username=? AND action='restore_requested' ORDER BY sequence DESC LIMIT 1",
                         (row['client_id'],row['username'])).fetchone()
        if event is None:return None
        try:details=json.loads(event['details_json'])
        except (ValueError,TypeError):return None
        if not isinstance(details,dict) or details.get('generation')!=row['generation']:return None
        operation=db.execute("SELECT operation_id,reason FROM operations WHERE operation_id=? AND client_id=? AND username=? AND action='restore'",
                             (details.get('operation_id'),row['client_id'],row['username'])).fetchone()
        return dict(operation) if operation is not None else None

    def arm(self,subject,*,actor,operation_id,reason,now=None):
        self._subject(subject);_label(actor,'authenticated_actor');_identifier(operation_id,'operation_id');_label(reason,'reason',512)
        now=self._now(now)
        with self._db(write=True) as db:
            previous=db.execute('SELECT * FROM operations WHERE operation_id=?',(operation_id,)).fetchone()
            if previous is not None:
                if (previous['client_id'],previous['username'],previous['actor'],previous['reason'],previous['action'])!=(subject.client_id,subject.username,actor,reason,'arm'):
                    raise Conflict('operation_id_reused_with_different_binding')
                return dict(self._bound(db,subject))
            row=self._bound(db,subject)
            if row is not None and row['state'] not in ('active','armed'):raise Conflict('purge_already_consumed')
            generation=1 if row is None else row['generation']+(row['state']=='active')
            db.execute('INSERT INTO operations(operation_id,client_id,username,actor,reason,created_at,action) VALUES(?,?,?,?,?,?,?)',(operation_id,subject.client_id,subject.username,actor,reason,now,'arm'))
            if row is None:
                db.execute("INSERT INTO subjects(client_id,username,generation,state,armed_at,updated_at) VALUES(?,?,1,'armed',?,?)",
                           (subject.client_id,subject.username,now,now))
            elif row['state']=='active':
                db.execute("UPDATE subjects SET state='armed',generation=?,armed_at=?,updated_at=?,claim_id=NULL,claimed_at=NULL,delivery_state=NULL,delivery_at=NULL,revoked_at=NULL,last_error_code=NULL WHERE client_id=?",
                           (generation,now,now,subject.client_id))
            self._audit(db,subject,actor,'arm_reaffirmed' if row is not None and row['state']=='armed' else 'armed',now,
                        {'operation_id':operation_id,'reason':reason,'generation':generation})
            return dict(self._bound(db,subject))

    def restore(self,subject,*,actor,operation_id,reason,now=None):
        self._subject(subject);_label(actor,'authenticated_actor');_identifier(operation_id,'operation_id');_label(reason,'reason',512)
        now=self._now(now)
        with self._db(write=True) as db:
            previous=db.execute('SELECT * FROM operations WHERE operation_id=?',(operation_id,)).fetchone()
            if previous is not None:
                if (previous['client_id'],previous['username'],previous['actor'],previous['reason'],previous['action'])!=(subject.client_id,subject.username,actor,reason,'restore'):
                    raise Conflict('operation_id_reused_with_different_binding')
                return dict(self._bound(db,subject))
            row=self._bound(db,subject)
            db.execute('INSERT INTO operations(operation_id,client_id,username,actor,reason,created_at,action) VALUES(?,?,?,?,?,?,?)',
                       (operation_id,subject.client_id,subject.username,actor,reason,now,'restore'))
            if row is None:
                generation=1
                db.execute("INSERT INTO subjects(client_id,username,generation,state,armed_at,updated_at) VALUES(?,?,1,'active',?,?)",(subject.client_id,subject.username,now,now))
                action='restore_noop';cancelled=[]
            elif row['state']=='active':
                generation=row['generation'];action='restore_noop';cancelled=[]
            elif row['state'] in ('restore_pending','restoring'):
                generation=row['generation'];action='restore_reaffirmed';cancelled=[]
            else:
                generation=row['generation']+1
                cancelled=[item['job_id'] for item in db.execute("SELECT job_id FROM revocation_jobs WHERE client_id=? AND state IN ('pending','running')",(subject.client_id,))]
                db.execute("UPDATE revocation_jobs SET state='cancelled',lease_owner=NULL,lease_token=NULL,lease_until=NULL,last_error_code='superseded_by_restore',updated_at=? WHERE client_id=? AND state IN ('pending','running')",(now,subject.client_id))
                immediate=row['state']=='armed'
                state='active' if immediate else 'restore_pending'
                db.execute('UPDATE subjects SET state=?,generation=?,updated_at=?,claim_id=NULL,claimed_at=NULL,delivery_state=NULL,delivery_at=NULL,revoked_at=NULL,last_error_code=NULL WHERE client_id=?',
                           (state,generation,now,subject.client_id))
                action='restored_before_purge' if immediate else 'restore_requested'
                if not immediate:
                    db.execute("INSERT INTO revocation_jobs(job_id,client_id,generation,kind,state,not_before,created_at,updated_at) VALUES(?,?,?,'restore','pending',?,?,?)",
                               (uuid.uuid4().hex,subject.client_id,generation,now,now,now))
            self._audit(db,subject,actor,action,now,{'operation_id':operation_id,'reason':reason,'generation':generation,'cancelled_job_ids':cancelled})
            return dict(self._bound(db,subject))

    def state(self,subject):
        self._subject(subject)
        with self._db() as db:
            row=self._bound(db,subject);return dict(row) if row is not None else None

    def gate(self,subject,*,method,kind,format_name,request_id,prepared=None,
             expected_generation=None,now=None):
        """Authoritative subscription gate, called after identity resolution.

        kind='profile' is the full main subscription; kind='provider' is an
        airport-provider poll. Only the first profile GET creates the runtime
        revocation job. Every later manual-ban update receives the same blocked
        payload, with independent permanent delivery receipts and no job delay.
        """
        self._subject(subject);_identifier(request_id,'request_id')
        if not isinstance(method,str) or not isinstance(kind,str):raise ValueError('invalid_request_kind')
        if expected_generation is not None and (type(expected_generation) is not int or expected_generation<=0):raise ValueError('invalid_expected_generation')
        now=self._now(now)
        with self._db(write=True) as db:
            try:row=self._bound(db,subject)
            except BindingMismatch:return Decision('block',None,'identity_binding_mismatch')
            if row is None:return Decision('allow',None)
            state=row['state']
            if expected_generation is not None and row['generation']!=expected_generation:
                return Decision('block',state,'disabled_generation_superseded')
            if state=='active':return Decision('allow',state)
            manual=self._manual_disabled_context(db,row)
            restoring=self._restoring_context(db,row)
            if state!='armed' and manual is None and restoring is None:return Decision('block',state,'subscription_and_proxy_disabled')
            if method=='HEAD':return Decision('head',state,'nonconsuming_head',generation=row['generation'])
            if method!='GET':return Decision('block',state,'unsupported_method')
            if kind=='provider' and prepared is None:
                return Decision('empty_provider',state,'nonconsuming_empty_provider',generation=row['generation'])
            if kind not in ('profile','provider'):return Decision('block',state,'unsupported_representation')
            if kind=='provider' and manual is None:
                return Decision('empty_provider',state,'nonconsuming_empty_provider',generation=row['generation'])
            if prepared is None:return Decision('prepare',state,'validated_purge_required',generation=row['generation'])
            if not isinstance(prepared,PreparedPurge) or prepared._proof is not _VALIDATED or prepared.format_name!=format_name or hashlib.sha256(prepared.body).hexdigest()!=prepared.sha256:
                raise ValueError('purge_payload_binding_invalid')
            if kind=='provider' and format_name!='provider':raise ValueError('provider_payload_binding_invalid')
            if kind=='profile' and format_name=='provider':raise ValueError('profile_payload_binding_invalid')
            if (manual is not None or restoring is not None) and (state!='armed' or kind=='provider'):
                receipt=uuid.uuid4().hex
                context=manual if manual is not None else restoring
                self._audit(db,subject,'subscription_gateway','disabled_subscription_issued',now,
                    {'delivery_id':receipt,'request_id':request_id,'kind':kind,'format':format_name,
                     'payload_sha256':prepared.sha256,'payload_bytes':len(prepared.body),
                     'generation':row['generation'],'reason':context['reason'],
                     'operation_id':context['operation_id'],'runtime_job_unchanged':True},event_id=receipt)
                return Decision('purge_repeat',state,'manual_subscription_disabled' if manual is not None else 'restoration_pending',claim_id=receipt,
                                response=prepared,generation=row['generation'])
            claim=uuid.uuid4().hex;job=uuid.uuid4().hex
            db.execute("UPDATE subjects SET state='purge_issued',claim_id=?,claimed_at=?,delivery_state='pending',updated_at=? WHERE client_id=? AND state='armed'",
                       (claim,now,now,subject.client_id))
            db.execute("INSERT INTO revocation_jobs(job_id,client_id,generation,kind,state,not_before,created_at,updated_at) VALUES(?,?,?,'revoke','pending',?,?,?)",
                       (job,subject.client_id,row['generation'],now+self.delivery_grace,now,now))
            self._audit(db,subject,'subscription_gateway','purge_claimed',now,
                {'claim_id':claim,'request_id':request_id,'format':format_name,'payload_sha256':prepared.sha256,
                 'payload_bytes':len(prepared.body),'generation':row['generation'],'delivery_deadline':now+self.delivery_grace,
                 **({'reason':manual['reason'],'operation_id':manual['operation_id'],'kind':kind}
                    if manual is not None else {})},event_id=claim if manual is not None else None)
            return Decision('purge','purge_issued',
                'manual_subscription_disabled' if manual is not None else '',
                claim_id=claim,response=prepared,generation=row['generation'])

    def disabled_delivery_result(self,subject,delivery_id,generation,*,succeeded,now=None):
        """Append one receipt; stale callbacks never modify a job or new state."""
        self._subject(subject);_identifier(delivery_id,'delivery_id')
        if type(generation) is not int or generation<=0:raise ValueError('invalid_delivery_generation')
        if type(succeeded) is not bool:raise ValueError('invalid_delivery_result')
        now=self._now(now);event_id=delivery_id+'-result'
        with self._db(write=True) as db:
            issued=db.execute("SELECT * FROM audit_log WHERE event_id=? AND client_id=? AND username=? AND action IN ('purge_claimed','disabled_subscription_issued')",
                              (delivery_id,subject.client_id,subject.username)).fetchone()
            if issued is None:raise Conflict('disabled_delivery_receipt_not_issued')
            details=json.loads(issued['details_json'])
            if details.get('generation')!=generation:raise Conflict('disabled_delivery_generation_mismatch')
            previous=db.execute('SELECT action FROM audit_log WHERE event_id=?',(event_id,)).fetchone()
            action='disabled_delivery_succeeded' if succeeded else 'disabled_delivery_failed'
            if previous is not None:
                if previous['action']!=action:raise Conflict('disabled_delivery_already_finalized')
                return
            try:row=self._bound(db,subject)
            except BindingMismatch:row=None
            superseded=(row is None or row['generation']!=generation or row['state'] not in MANUAL_DISABLED_STATES|RESTORE_PENDING_STATES)
            self._audit(db,subject,'subscription_gateway',action,now,
                {'delivery_id':delivery_id,'generation':generation,'reason':details.get('reason',''),
                 'operation_id':details.get('operation_id'),'kind':details.get('kind','profile'),
                 'format':details['format'],'payload_sha256':details['payload_sha256'],
                 'server_write_result_only':True,'client_acknowledged':False,
                 'superseded':superseded,'current_generation':row['generation'] if row is not None else None,
                 'runtime_job_unchanged':True},event_id=event_id)

    def proxy_allowed(self,subject):
        try:row=self.state(subject)
        except BindingMismatch:return False
        return row is None or row['state'] in ('active','armed')

    def requires_revocation(self,subject,generation):return self._runtime_intent(subject,generation,('purge_issued','revoking'))

    def requires_restore(self,subject,generation):return self._runtime_intent(subject,generation,('restore_pending','restoring'))

    def _runtime_intent(self,subject,generation,states):
        if type(generation) is not int or generation<=0:raise ValueError('invalid_generation')
        try:row=self.state(subject)
        except BindingMismatch:return False
        return row is not None and row['generation']==generation and row['state'] in states

    def delivery_result(self,subject,claim_id,*,succeeded,now=None):
        self._subject(subject);_identifier(claim_id,'claim_id')
        if type(succeeded) is not bool:raise ValueError('invalid_delivery_result')
        now=self._now(now);value='succeeded' if succeeded else 'failed'
        with self._db(write=True) as db:
            row=self._bound(db,subject)
            if row is None or row['claim_id']!=claim_id:raise Conflict('claim_binding_mismatch')
            if row['delivery_state']!='pending':
                if row['delivery_state']!=value:raise Conflict('delivery_already_finalized')
                return
            db.execute('UPDATE subjects SET delivery_state=?,delivery_at=?,updated_at=? WHERE client_id=?',(value,now,now,subject.client_id))
            db.execute("UPDATE revocation_jobs SET not_before=MIN(not_before,?),updated_at=? WHERE client_id=? AND generation=? AND state='pending'",
                       (now,now,subject.client_id,row['generation']))
            self._audit(db,subject,'subscription_gateway','delivery_'+value,now,
                        {'claim_id':claim_id,'server_write_result_only':True,'client_acknowledged':False})

    def claim_job(self,worker_id,*,lease_seconds=30,now=None):
        _identifier(worker_id,'worker_id')
        if type(lease_seconds) is not int or not 1<=lease_seconds<=900:raise ValueError('invalid_lease')
        now=self._now(now)
        with self._db(write=True) as db:
            row=db.execute("SELECT * FROM revocation_jobs WHERE (state='pending' AND not_before<=?) OR (state='running' AND lease_until<=?) ORDER BY not_before,created_at,job_id LIMIT 1",(now,now)).fetchone()
            if row is None:return None
            subject_row=db.execute('SELECT * FROM subjects WHERE client_id=?',(row['client_id'],)).fetchone()
            expected=('purge_issued','revoking') if row['kind']=='revoke' else ('restore_pending','restoring')
            if subject_row is None:
                raise Conflict('job_subject_state_mismatch')
            if subject_row['generation']!=row['generation'] or subject_row['state'] not in expected:
                db.execute("UPDATE revocation_jobs SET state='cancelled',lease_owner=NULL,lease_token=NULL,lease_until=NULL,last_error_code='superseded_intent',updated_at=? WHERE job_id=?",(now,row['job_id']))
                self._audit(db,Subject(subject_row['username'],subject_row['client_id']),worker_id,'obsolete_job_cancelled',now,{'job_id':row['job_id'],'kind':row['kind'],'generation':row['generation']})
                return None
            subject=Subject(subject_row['username'],subject_row['client_id']);token=uuid.uuid4().hex
            db.execute("UPDATE revocation_jobs SET state='running',attempts=attempts+1,lease_owner=?,lease_token=?,lease_until=?,updated_at=? WHERE job_id=?",
                (worker_id,token,now+lease_seconds,now,row['job_id']))
            db.execute('UPDATE subjects SET state=?,updated_at=? WHERE client_id=?',('revoking' if row['kind']=='revoke' else 'restoring',now,subject.client_id))
            self._audit(db,subject,worker_id,'revocation_started' if row['kind']=='revoke' else 'restoration_started',now,{'job_id':row['job_id'],'kind':row['kind'],'generation':row['generation'],'attempt':row['attempts']+1,'reclaimed':row['state']=='running'})
            result=dict(db.execute('SELECT * FROM revocation_jobs WHERE job_id=?',(row['job_id'],)).fetchone())
            result['username']=subject.username
            result['action']=result['kind']
            return result

    def finish_job(self,job_id,lease_token,*,succeeded,error_code=None,retry_after=None,now=None):
        _identifier(job_id,'job_id');_identifier(lease_token,'lease_token')
        if type(succeeded) is not bool:raise ValueError('invalid_job_result')
        if not succeeded:
            if not isinstance(error_code,str) or re.fullmatch(r'[a-z0-9_\-]{1,64}',error_code) is None:raise ValueError('invalid_error_code')
            if retry_after is not None and (type(retry_after) is not int or not 1<=retry_after<=86400):raise ValueError('invalid_retry_delay')
        now=self._now(now)
        with self._db(write=True) as db:
            row=db.execute('SELECT * FROM revocation_jobs WHERE job_id=?',(job_id,)).fetchone()
            if row is None or row['state']!='running' or row['lease_token']!=lease_token:raise LostLease('revocation_lease_lost')
            subject_row=db.execute('SELECT * FROM subjects WHERE client_id=?',(row['client_id'],)).fetchone()
            expected=('purge_issued','revoking') if row['kind']=='revoke' else ('restore_pending','restoring')
            if subject_row is None or subject_row['generation']!=row['generation'] or subject_row['state'] not in expected:
                raise LostLease('job_generation_superseded')
            subject=Subject(subject_row['username'],subject_row['client_id'])
            if succeeded:
                db.execute("UPDATE revocation_jobs SET state='done',lease_owner=NULL,lease_token=NULL,lease_until=NULL,last_error_code=NULL,updated_at=? WHERE job_id=?",(now,job_id))
                if row['kind']=='revoke':
                    db.execute("UPDATE subjects SET state='revoked',revoked_at=?,updated_at=?,last_error_code=NULL WHERE client_id=?",(now,now,subject.client_id))
                else:
                    db.execute("UPDATE subjects SET state='active',updated_at=?,last_error_code=NULL WHERE client_id=?",(now,subject.client_id))
                self._audit(db,subject,row['lease_owner'],'revoked' if row['kind']=='revoke' else 'restored',now,{'job_id':job_id,'kind':row['kind'],'generation':row['generation'],'attempt':row['attempts']})
            else:
                delay=retry_after if retry_after is not None else min(300,2**min(row['attempts'],9))
                db.execute("UPDATE revocation_jobs SET state='pending',not_before=?,lease_owner=NULL,lease_token=NULL,lease_until=NULL,last_error_code=?,updated_at=? WHERE job_id=?",(now+delay,error_code,now,job_id))
                db.execute('UPDATE subjects SET last_error_code=?,updated_at=? WHERE client_id=?',(error_code,now,subject.client_id))
                self._audit(db,subject,row['lease_owner'],'revocation_retry_scheduled' if row['kind']=='revoke' else 'restoration_retry_scheduled',now,{'job_id':job_id,'kind':row['kind'],'generation':row['generation'],'attempt':row['attempts'],'error_code':error_code,'not_before':now+delay})

    def overview(self,*,after_client_id='',limit=100):
        if type(limit) is not int or not 1<=limit<=500:raise ValueError('invalid_limit')
        if after_client_id:_identifier(after_client_id,'after_client_id')
        with self._db() as db:
            return [dict(row) for row in db.execute('SELECT * FROM subjects WHERE client_id>? ORDER BY client_id LIMIT ?',(after_client_id,limit))]

    def audit(self,*,client_id=None,after_sequence=0,limit=100):
        if type(after_sequence) is not int or after_sequence<0 or type(limit) is not int or not 1<=limit<=500:raise ValueError('invalid_cursor')
        if client_id is not None:_identifier(client_id,'client_id')
        where='sequence>?';args=[after_sequence]
        if client_id is not None:where+=' AND client_id=?';args.append(client_id)
        with self._db() as db:
            rows=[dict(row) for row in db.execute('SELECT * FROM audit_log WHERE '+where+' ORDER BY sequence LIMIT ?',args+[limit])]
        for row in rows:row['details']=json.loads(row.pop('details_json'))
        return rows
