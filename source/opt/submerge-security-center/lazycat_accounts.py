"""DMIT-owned Lazycat account status, durable requests and permanent audit.

The browser supplies only a bound account ID and an operation ID.  No desired
enabled flag, credential, payload, edge, path or generation is accepted.  A
worker re-reads the existing identity/lifecycle coordinator at execution time.
Importing this module performs no I/O and never creates a background thread.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
import uuid

DB_PATH = Path('/var/lib/submerge-security-center/lazycat-accounts.sqlite3')
EDGE_ID = 'lazycat-ai-20261108'
FRESH_SECONDS = 90
NAME = re.compile(r'[A-Za-z0-9_+.\-]{1,128}')
BINDING = re.compile(r'[1-9][0-9]*:[0-9a-f]{24}')
OPERATION = re.compile(r'[A-Za-z0-9_.\-]{16,80}')
HASH = re.compile(r'[0-9a-f]{64}')
ALLOWED_STATES = {'active', 'armed'}


class AccountError(RuntimeError):
    """Only stable codes, never subprocess output or credential values."""


def need(value, code):
    if not value:
        raise AccountError(code)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode()


def error_code(error):
    value = str(error)
    return value if isinstance(error, AccountError) and re.fullmatch(
        r'[a-z0-9_]{1,96}', value) else 'lazycat_operation_unavailable'


SCHEMA = '''
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS jobs(
 request_id TEXT PRIMARY KEY,operation_id TEXT NOT NULL,actor TEXT NOT NULL,
 client_id TEXT NOT NULL,username TEXT NOT NULL,created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL,state TEXT NOT NULL CHECK(state IN ('queued','running','confirmed','failed')),
 attempts INTEGER NOT NULL DEFAULT 0,lease_token TEXT,lease_until INTEGER,
 error_code TEXT,result_json TEXT,UNIQUE(actor,operation_id));
CREATE INDEX IF NOT EXISTS jobs_due ON jobs(state,created_at);
CREATE INDEX IF NOT EXISTS jobs_subject ON jobs(client_id,created_at DESC);
CREATE TABLE IF NOT EXISTS cache(key TEXT PRIMARY KEY,checked_at INTEGER NOT NULL,value_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log(
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT NOT NULL UNIQUE,
 at INTEGER NOT NULL,username TEXT NOT NULL,actor TEXT NOT NULL,
 action TEXT NOT NULL,details_json TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS lazycat_audit_no_update BEFORE UPDATE ON audit_log
 BEGIN SELECT RAISE(ABORT,'permanent_audit_is_append_only'); END;
CREATE TRIGGER IF NOT EXISTS lazycat_audit_no_delete BEFORE DELETE ON audit_log
 BEGIN SELECT RAISE(ABORT,'permanent_audit_is_append_only'); END;
CREATE TRIGGER IF NOT EXISTS lazycat_audit_no_replace BEFORE INSERT ON audit_log
 WHEN EXISTS(SELECT 1 FROM audit_log WHERE sequence=NEW.sequence OR event_id=NEW.event_id)
 BEGIN SELECT RAISE(ABORT,'permanent_audit_is_append_only'); END;
'''


class Store:
    """One private DB; no retention/prune method exists for requests or audit."""
    def __init__(self, path=DB_PATH, *, clock=None):
        self.path = Path(path)
        self.clock = clock or (lambda: int(time.time()))
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        need(not self.path.is_symlink(), 'account_database_symlink')
        if not self.path.exists():
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
                os.close(fd)
            except FileExistsError:
                pass
        info = self.path.lstat()
        need(stat.S_ISREG(info.st_mode) and not self.path.is_symlink(),
             'account_database_not_regular')
        if os.name != 'nt':
            need(info.st_uid == 0 and not info.st_mode & 0o077,
                 'account_database_not_private')
        with self.db() as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.executescript(SCHEMA)
            row = db.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
            need(row is None or row[0] == '1', 'account_database_schema')
            db.execute("INSERT OR IGNORE INTO meta VALUES('schema','1')")

    @contextmanager
    def db(self, write=False):
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA busy_timeout=5000')
        try:
            if write:
                db.execute('BEGIN IMMEDIATE')
            yield db
            if write:
                db.execute('COMMIT')
        except BaseException:
            if db.in_transaction:
                db.execute('ROLLBACK')
            raise
        finally:
            db.close()

    @staticmethod
    def _audit(db, now, actor, action, username='', details=None):
        db.execute('INSERT INTO audit_log(event_id,at,username,actor,action,details_json) '
                   'VALUES(?,?,?,?,?,?)', (uuid.uuid4().hex, now, username, actor,
                                          action, canonical(details or {}).decode()))

    def rejected(self, actor, code):
        with self.db(True) as db:
            self._audit(db, self.clock(), actor, 'Lazycat账号下发：请求未受理',
                        details={'phase': 'rejected', 'error': code})

    def enqueue(self, *, actor, client_id, username, operation_id):
        need(isinstance(actor, str) and 0 < len(actor) <= 120 and
             not any(ord(c) < 32 for c in actor), 'authenticated_actor_invalid')
        need(BINDING.fullmatch(client_id or '') and NAME.fullmatch(username or '')
             and OPERATION.fullmatch(operation_id or ''), 'account_request_invalid')
        now = self.clock()
        with self.db(True) as db:
            previous = db.execute('SELECT * FROM jobs WHERE actor=? AND operation_id=?',
                                  (actor, operation_id)).fetchone()
            if previous:
                need((previous['client_id'], previous['username']) == (client_id, username),
                     'operation_binding_conflict')
                request_id = previous['request_id']
            else:
                request_id = uuid.uuid4().hex
                db.execute('INSERT INTO jobs(request_id,operation_id,actor,client_id,username,'
                           'created_at,updated_at,state) VALUES(?,?,?,?,?,?,?,?)',
                           (request_id, operation_id, actor, client_id, username,
                            now, now, 'queued'))
            self._audit(db, now, actor, 'Lazycat账号下发：已请求', username,
                        {'phase': 'requested', 'request_id': request_id,
                         'client_id': client_id, 'duplicate_request': previous is not None})
            return {'request_id': request_id,
                    'state': previous['state'] if previous else 'queued'}

    def claim(self, *, lease_seconds=300):
        now = self.clock()
        with self.db(True) as db:
            row = db.execute("SELECT * FROM jobs WHERE state='queued' OR "
                             "(state='running' AND lease_until<=?) ORDER BY created_at,request_id LIMIT 1",
                             (now,)).fetchone()
            if row is None:
                return None
            row = dict(row)
            token = uuid.uuid4().hex
            db.execute("UPDATE jobs SET state='running',attempts=attempts+1,updated_at=?,"
                       'lease_token=?,lease_until=? WHERE request_id=?',
                       (now, token, now + lease_seconds, row['request_id']))
            self._audit(db, now, row['actor'], 'Lazycat账号下发：开始执行', row['username'],
                        {'phase': 'started', 'request_id': row['request_id'],
                         'attempt': row['attempts'] + 1, 'recovered_lease': row['state'] == 'running'})
            row.update(state='running', lease_token=token, attempts=row['attempts'] + 1)
            return row

    def finish(self, job, *, result=None, error=None):
        now = self.clock()
        safe_result = {key: result[key] for key in (
            'generation', 'source_generation', 'source_revision', 'enabled', 'idempotent', 'checked_at')
                       if result is not None and key in result}
        with self.db(True) as db:
            changed = db.execute("UPDATE jobs SET state=?,updated_at=?,lease_token=NULL,"
                'lease_until=NULL,error_code=?,result_json=? WHERE request_id=? '
                "AND state='running' AND lease_token=? AND lease_until>?",
                ('failed' if error else 'confirmed', now, error,
                 canonical(safe_result).decode(), job['request_id'], job['lease_token'], now))
            need(changed.rowcount == 1, 'account_job_lease_lost')
            self._audit(db, now, job['actor'], 'Lazycat账号下发：' + ('未完成' if error else '已核实'),
                        job['username'], {'phase': 'result', 'request_id': job['request_id'],
                                          'error': error, **safe_result})

    def require_lease(self, job):
        with self.db() as db:
            current = db.execute('SELECT state,lease_token,lease_until FROM jobs WHERE request_id=?',
                                 (job['request_id'],)).fetchone()
        need(current is not None and current['state'] == 'running'
             and current['lease_token'] == job['lease_token']
             and current['lease_until'] > self.clock(), 'account_job_lease_lost')

    def set_cache(self, value):
        with self.db(True) as db:
            db.execute('INSERT INTO cache VALUES(?,?,?) ON CONFLICT(key) DO UPDATE '
                       'SET checked_at=excluded.checked_at,value_json=excluded.value_json',
                       ('loaded', self.clock(), canonical(value).decode()))

    def cached(self):
        with self.db() as db:
            row = db.execute("SELECT checked_at,value_json FROM cache WHERE key='loaded'").fetchone()
        return {'checked_at': row[0], **json.loads(row[1])} if row else None

    def latest_jobs(self):
        with self.db() as db:
            rows = db.execute('SELECT j.* FROM jobs j WHERE request_id=(SELECT request_id '
                'FROM jobs WHERE client_id=j.client_id ORDER BY created_at DESC,rowid DESC LIMIT 1)').fetchall()
        return {row['client_id']: {key: row[key] for key in
                ('request_id', 'state', 'updated_at', 'error_code')} for row in rows}


class MasterAuthority:
    """Read existing identity/lifecycle and verified native cohort, never enroll."""
    def __init__(self, backend, native_reader):
        self.backend, self.native_reader = backend, native_reader

    def _identities(self):
        rows = []
        seen = set()
        for identity in self.backend.list_users():
            client_id, name = identity['target_id'], identity['username']
            need(BINDING.fullmatch(client_id or '') and NAME.fullmatch(name or '')
                 and name not in seen, 'master_identity_invalid')
            seen.add(name)
            subject = self.backend.subject(client_id)
            need(subject.username == name and subject.client_id == client_id,
                 'master_identity_binding_changed')
            lifecycle = self.backend.state(subject) or {'state': 'active', 'generation': 0}
            state = lifecycle.get('state')
            need(type(identity.get('enabled')) is bool and state in {
                'active', 'armed', 'purge_issued', 'revoking', 'revoked',
                'restore_pending', 'restoring', 'identity_conflict'}, 'master_state_unknown')
            generation = lifecycle.get('generation', 0)
            need(type(generation) is int and generation >= 0, 'master_generation_invalid')
            rows.append({'client_id': client_id, 'username': name,
                'sui_enabled': identity['enabled'], 'lifecycle': state,
                'source_generation': generation,
                'identity_revision': str(identity.get('revision', '')),
                'enabled': identity['enabled'] and state in ALLOWED_STATES})
        return sorted(rows, key=lambda row: row['client_id'])

    def snapshot(self):
        first = self._identities()
        native = self.native_reader()
        need(isinstance(native, dict) and isinstance(native.get('usernames'), list)
             and HASH.fullmatch(native.get('sha256', '')), 'master_native_unknown')
        names = native['usernames']
        need(all(isinstance(name, str) and NAME.fullmatch(name) for name in names)
             and len(names) == len(set(names)), 'master_native_cohort_invalid')
        need(first == self._identities(), 'master_changed_during_read')
        by_name = {row['username']: row for row in first}
        ready = all(name in by_name and by_name[name]['enabled'] for name in names)
        for row in first:
            row['native_loaded'] = row['username'] in names
        return {'rows': first, 'usernames': sorted(names), 'ready': ready,
            'token': hashlib.sha256(canonical({'identities': first, 'native': native})).hexdigest()}


def validate_loaded(value):
    need(isinstance(value, dict) and value.get('verified') is True
         and value.get('edge_id') == EDGE_ID, 'lazycat_loaded_unverified')
    need(type(value.get('generation')) is int and value['generation'] > 0
         and HASH.fullmatch(value.get('cohort_sha256', ''))
         and HASH.fullmatch(value.get('manifest_sha256', '')), 'lazycat_loaded_identity_invalid')
    names = value.get('active_usernames')
    need(isinstance(names, list) and all(isinstance(x, str) and NAME.fullmatch(x) for x in names)
         and len(names) == len(set(names)) and type(value.get('active_user_count')) is int
         and value['active_user_count'] == len(names),
         'lazycat_loaded_cohort_invalid')
    need(value.get('active') is bool(names) and value.get('enforcement') ==
         ('running_verified' if names else 'service_stopped_no_accounts'), 'lazycat_enforcement_unverified')
    return {key: value[key] for key in ('verified', 'edge_id', 'generation',
        'cohort_sha256', 'manifest_sha256', 'active_usernames', 'active_user_count', 'enforcement', 'active')}


class AccountService:
    def __init__(self, store, master, *, clock=None):
        self.store, self.master = store, master
        self.clock = clock or (lambda: int(time.time()))

    def request(self, body, actor):
        need(isinstance(body, dict) and set(body) == {'client_id', 'operation_id'}
             and isinstance(body['client_id'], str) and isinstance(body['operation_id'], str),
             'account_request_fields_invalid')
        snapshot = self.master.snapshot()
        rows = [row for row in snapshot['rows'] if row['client_id'] == body['client_id']]
        need(len(rows) == 1, 'master_identity_not_found')
        return self.store.enqueue(actor=actor, client_id=rows[0]['client_id'],
                                  username=rows[0]['username'], operation_id=body['operation_id'])

    def status(self):
        now, snapshot = self.clock(), self.master.snapshot()
        cache, jobs = self.store.cached(), self.store.latest_jobs()
        age = now - cache['checked_at'] if cache else None
        fresh = bool(cache and type(age) is int and 0 <= age <= FRESH_SECONDS
                     and cache.get('verified') is True and cache.get('authority_token') == snapshot['token'])
        loaded = cache.get('loaded', {}) if cache else {}
        if fresh:
            try:
                loaded = validate_loaded(loaded)
            except AccountError:
                fresh = False
        names = set(loaded.get('active_usernames', [])) if fresh else set()
        rows = []
        for row in snapshot['rows']:
            state = ('loaded' if row['username'] in names else 'missing') if fresh else 'unknown'
            reason = ('master_native_not_converged' if not snapshot['ready'] else
                      'master_native_missing' if row['enabled'] and not row['native_loaded'] else None)
            rows.append({'client_id': row['client_id'], 'username': row['username'],
                'dmit_state': 'enabled' if row['enabled'] else 'disabled',
                'dmit_native_loaded': row['native_loaded'], 'lifecycle': row['lifecycle'],
                'source_generation': row['source_generation'], 'lazycat_state': state,
                'fresh': fresh, 'matches': (row['enabled'] == (state == 'loaded')) if fresh else None,
                'can_sync': reason is None, 'sync_blocked_reason': reason,
                'generation': loaded.get('generation') if fresh else
                    (cache.get('last_known_generation') or loaded.get('generation')) if cache else None,
                'generation_verified': fresh,
                'last_checked_at': cache['checked_at'] if cache else None,
                'last_sync_at': cache.get('confirmed_at') if cache else None,
                'error': reason or (cache.get('error') if cache else 'lazycat_status_not_checked'),
                'last_request': jobs.get(row['client_id'])})
        return {'schema': 1, 'edge_id': EDGE_ID, 'checked_at': now, 'fresh_seconds': FRESH_SECONDS,
                'fresh': fresh, 'users': rows, 'permanent_audit': True}


def register(app, *, actor_guard, mutation_guard, backend, service=None):
    """Reuse caller's authenticated session, same-origin and CSRF boundary."""
    from flask import jsonify, request
    if app.extensions.get('lazycat_accounts'):
        return
    if service is None:
        from lazycat_accounts_worker import native_reader
        service = AccountService(Store(), MasterAuthority(backend, native_reader))
    app.extensions['lazycat_accounts'] = service

    @app.after_request
    def lazycat_accounts_no_cache(response):
        if request.path.startswith('/api/center/lazycat/'):
            response.headers['Cache-Control'] = 'no-store'
        return response

    @app.get('/api/center/lazycat/accounts')
    def lazycat_accounts_status():
        denied = actor_guard()
        if denied:
            return denied
        try:
            return jsonify(service.status())
        except Exception as error:
            return jsonify(error=error_code(error)), 503

    @app.post('/api/center/lazycat/accounts/sync')
    def lazycat_accounts_sync():
        denied = mutation_guard()
        if denied:
            return denied
        actor = request.authorization.username
        try:
            need(request.content_length is None or request.content_length <= 4096,
                 'account_request_too_large')
            result = service.request(request.get_json(silent=True), actor)
            return jsonify(**result), 202
        except Exception as error:
            code = error_code(error)
            try:
                service.store.rejected(actor, code)
            except Exception:
                return jsonify(error='permanent_audit_unavailable'), 503
            status = 404 if code == 'master_identity_not_found' else 409 if code in {
                'operation_binding_conflict', 'master_changed_during_read'} else 400 if code in {
                'account_request_fields_invalid', 'account_request_invalid', 'account_request_too_large'} else 503
            return jsonify(error=code), status
