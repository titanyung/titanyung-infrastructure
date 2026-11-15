"""Protected UI/API registration for confirmed, next-update user revocation.

Importing this module performs no access-control operation. The existing
Nginx admin identity and TOTP/view-key callbacks remain authoritative. Since
the current security application has no sessions or CSRF tokens, this plugin
adds a narrow server-side session used only by its own endpoints.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import time
from urllib.parse import urlsplit
import uuid

from flask import Response, jsonify, request

ASSETS = Path(__file__).with_name('ui')
COOKIE = '__Secure-submerge_user_access'
CSRF_HEADER = 'X-User-Access-CSRF'
ACTIONS = frozenset(('arm','restore'))
INVENTORY_REASONS = frozenset(('', 'disabled', 'unconfigured', 'trial', 'identity_conflict'))


class Problem(Exception):
    def __init__(self, code, status=400):
        self.code, self.status = code, status


def digest(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def normalized_origin(value):
    try:
        if not isinstance(value,str) or any(character.isspace() or ord(character)<32 for character in value) or ',' in value:
            return None
        parsed = urlsplit(value)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or
                parsed.password or parsed.path not in ('', '/') or parsed.query or parsed.fragment):
            return None
        return parsed.scheme, parsed.hostname.lower(), parsed.port or 443
    except (ValueError, TypeError):
        return None


def public_request_origin():
    """Trust only headers overwritten by the audited loopback Nginx hop."""
    host=request.headers.get('X-Forwarded-Host')
    proto=request.headers.get('X-Forwarded-Proto')
    if host is not None or proto is not None:
        if request.remote_addr not in ('127.0.0.1','::1') or proto!='https' or not host:
            return None
        # A forwarded host is one authority, never an URL, chain, or path.
        if any(character in host for character in '/?#@'):
            return None
        return normalized_origin('https://'+host)
    return normalized_origin(request.scheme+'://'+request.host)


class AdminStore:
    """Private operation sessions and short-lived, session-bound confirmations.

    Confirmation rows are retained. Permanent lifecycle audit is owned by the
    separate LifecycleStore; this class never deletes its records or state.
    """
    def __init__(self, path, *, clock=time.time, require_root=True):
        self.path, self.clock, self.require_root = Path(path), clock, require_root
        if require_root and (not hasattr(os, 'geteuid') or os.geteuid() != 0):
            raise RuntimeError('user_access_admin_root_required')
        self.path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if require_root:
            os.chmod(self.path.parent, 0o700)
        if not os.path.lexists(self.path):
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
        info = self.path.lstat()
        if (not stat.S_ISREG(info.st_mode) or self.path.is_symlink() or
                (require_root and (info.st_uid != 0 or info.st_mode & 0o077))):
            raise RuntimeError('user_access_admin_storage_permissions_invalid')
        with self.connection() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS admin_sessions(
              session_hash TEXT PRIMARY KEY, actor TEXT NOT NULL, csrf TEXT NOT NULL,
              created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
              recent_auth_at INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS confirmations(
              token_hash TEXT PRIMARY KEY, operation_id TEXT NOT NULL UNIQUE,
              action TEXT NOT NULL, actor TEXT NOT NULL, session_hash TEXT NOT NULL,
              client_id TEXT NOT NULL, username TEXT NOT NULL, revision TEXT NOT NULL,
              reason TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
              confirmed_at INTEGER);
            ''')

    def connection(self):
        return closing(sqlite3.connect(str(self.path), timeout=3, isolation_level=None))

    def session(self, raw, actor):
        if not isinstance(raw, str) or not re.fullmatch(r'[A-Za-z0-9_-]{40,80}', raw):
            return None
        with self.connection() as db:
            db.row_factory = sqlite3.Row
            row = db.execute('SELECT * FROM admin_sessions WHERE session_hash=? AND actor=?',
                             (digest(raw), actor)).fetchone()
        if row is None or row['expires_at'] <= int(self.clock()):
            return None
        return dict(row)

    def new_session(self, actor):
        raw, csrf, now = secrets.token_urlsafe(32), secrets.token_urlsafe(32), int(self.clock())
        row = dict(session_hash=digest(raw), actor=actor, csrf=csrf,
                   created_at=now, expires_at=now + 1800, recent_auth_at=0)
        with self.connection() as db:
            db.execute('INSERT INTO admin_sessions VALUES(?,?,?,?,?,?)',
                       tuple(row[key] for key in ('session_hash','actor','csrf','created_at','expires_at','recent_auth_at')))
        return raw, row

    def recent(self, session):
        now = int(self.clock())
        return session['recent_auth_at'] > 0 and 0 <= now - session['recent_auth_at'] <= 300

    def authenticate_recently(self, session):
        now = int(self.clock())
        with self.connection() as db:
            changed = db.execute('UPDATE admin_sessions SET recent_auth_at=? '
                'WHERE session_hash=? AND actor=? AND expires_at>?',
                (now, session['session_hash'], session['actor'], now)).rowcount
        if changed != 1:
            raise Problem('session_required', 401)

    def prepare(self, identity, session, reason, action):
        raw, now = secrets.token_urlsafe(32), int(self.clock())
        record = dict(token_hash=digest(raw), operation_id=str(uuid.uuid4()), action=action,
            actor=session['actor'], session_hash=session['session_hash'],
            client_id=identity['client_id'], username=identity['username'], revision=identity['revision'],
            reason=reason, created_at=now, expires_at=now + 120)
        with self.connection() as db:
            db.execute('INSERT INTO confirmations('+','.join(record)+') VALUES('+','.join('?' for _ in record)+')',
                       tuple(record.values()))
        return raw, record

    def confirm(self, raw, identity, session, action, callback):
        if not isinstance(raw, str) or not re.fullmatch(r'[A-Za-z0-9_-]{40,80}', raw):
            raise Problem('confirmation_invalid', 409)
        now = int(self.clock())
        with self.connection() as db:
            db.row_factory = sqlite3.Row
            db.execute('BEGIN IMMEDIATE')
            try:
                row = db.execute('SELECT * FROM confirmations WHERE token_hash=?', (digest(raw),)).fetchone()
                if row is None:
                    raise Problem('confirmation_invalid', 409)
                row = dict(row)
                if (row['action'] != action or row['actor'] != session['actor'] or
                        row['session_hash'] != session['session_hash'] or
                        any(row[field] != identity[field] for field in ('client_id','username','revision'))):
                    raise Problem('confirmation_binding_changed', 409)
                if row['confirmed_at'] is None and row['expires_at'] <= now:
                    raise Problem('confirmation_expired', 409)
                # arm() is idempotent by this server-issued UUID. If its DB
                # commit succeeds but this DB commit is interrupted, retrying
                # the same confirmation cannot create a second operation.
                result = callback(row)
                db.execute('UPDATE confirmations SET confirmed_at=COALESCE(confirmed_at,?) WHERE token_hash=?',
                           (now, row['token_hash']))
                db.commit()
                return result
            except Exception:
                db.rollback()
                raise


def register(app, admin_request, same_origin_request, verify_view_key, *,
             lifecycle, list_eligible, subject_factory, allowed_origins,
             admin_db='/var/lib/submerge-user-access/admin-ui.sqlite3',
             auth_mode=lambda: 'totp', clock=time.time, require_root=True,
             cookie_path='/security/'):
    """Register without arming a real user. Guards are existing security hooks.

    list_eligible()->[{client_id:str,username:str,revision:str}] is authoritative
    and read fresh before both prepare and confirm. No user-supplied actor or
    canonical username is accepted. subject_factory(username,client_id) binds
    lifecycle.Subject without coupling this plugin to a particular import path.
    """
    if app.extensions.get('user_access_admin'):
        return
    if not all(callable(value) for value in (admin_request,same_origin_request,verify_view_key,
                                            list_eligible,subject_factory,auth_mode)):
        raise RuntimeError('user_access_admin_callbacks_required')
    origins = {normalized_origin(value) for value in allowed_origins}
    if not origins or None in origins:
        raise RuntimeError('user_access_admin_origins_invalid')
    if cookie_path not in ('/','/security/'):
        raise RuntimeError('user_access_admin_cookie_path_invalid')
    store = AdminStore(admin_db, clock=clock, require_root=require_root)
    app.extensions['user_access_admin'] = store

    def actor():
        if not admin_request():
            raise Problem('admin_required', 403)
        auth = request.authorization
        if not auth or not isinstance(auth.username, str) or not auth.username:
            raise Problem('admin_required', 403)
        return auth.username

    def context(*, mutation=False, recent=False):
        identity = actor()
        session = store.session(request.cookies.get(COOKIE), identity)
        if session is None:
            raise Problem('session_required', 401)
        if mutation:
            origin=normalized_origin(request.headers.get('Origin'))
            if origin not in origins or origin!=public_request_origin() or not same_origin_request():
                raise Problem('same_origin_required', 403)
            supplied = request.headers.get(CSRF_HEADER, '')
            if not re.fullmatch(r'[A-Za-z0-9_-]{40,80}',supplied) or not hmac.compare_digest(supplied, session['csrf']):
                raise Problem('csrf_required', 403)
            if recent and not store.recent(session):
                raise Problem('recent_auth_required', 403)
        return session

    def json_body(allowed):
        if request.mimetype != 'application/json' or request.content_length is None or request.content_length > 8192:
            raise Problem('request_body_invalid')
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or set(body) - set(allowed):
            raise Problem('request_fields_invalid')
        return body

    def client_id(value):
        if not isinstance(value, str) or not re.fullmatch(r'[1-9][0-9]{0,18}(?::[0-9a-f]{24})?', value):
            raise Problem('target_invalid')
        return value

    def action_name(body):
        action=body.get('action','arm')
        if not isinstance(action,str) or action not in ACTIONS:
            raise Problem('action_invalid')
        return action

    def identities():
        rows = list_eligible()
        if not isinstance(rows, list) or len(rows) > 10000:
            raise RuntimeError('eligible_identities_invalid')
        ids, names = set(), set()
        for row in rows:
            if (not isinstance(row, dict) or client_id(row.get('client_id')) in ids or
                    not isinstance(row.get('username'), str) or not row['username'] or
                    row['username'] in names or not isinstance(row.get('revision'), str) or
                    not re.fullmatch(r'[0-9a-f]{64}', row['revision'])):
                raise RuntimeError('eligible_identity_binding_invalid')
            ids.add(row['client_id']); names.add(row['username'])
        return rows

    def resolve(value,action=None):
        value = client_id(value)
        matches = [row for row in identities() if row['client_id'] == value]
        if len(matches) != 1:
            raise Problem('target_not_eligible', 404)
        if action=='arm' and matches[0].get('eligible',True) is not True:
            raise Problem('target_not_eligible',404)
        return matches[0]

    def response_error(error):
        if isinstance(error, Problem):
            return jsonify(ok=False,error=error.code),error.status
        # Conflict names are checked without returning arbitrary worker text.
        if type(error).__name__ in {'Conflict','BindingMismatch','LostLease'}:
            return jsonify(ok=False,error='operation_conflict'),409
        return jsonify(ok=False,error='access_control_temporarily_unavailable'),503

    @app.route('/api/user-access/session',methods=['GET'])
    def user_access_session():
        try:
            identity = actor()
            session = store.session(request.cookies.get(COOKIE), identity)
            raw = None
            if session is None:
                raw,session = store.new_session(identity)
            result = jsonify(ok=True,csrf_token=session['csrf'],recent_auth=store.recent(session),
                             expires_at=session['expires_at'],auth_mode=auth_mode())
            if raw is not None:
                result.set_cookie(COOKIE,raw,max_age=1800,secure=True,httponly=True,samesite='Strict',path=cookie_path)
            return result
        except Exception as error:
            return response_error(error)

    @app.route('/api/user-access/reauth',methods=['POST'])
    def user_access_reauth():
        try:
            session = context(mutation=True)
            json_body(())
            if not verify_view_key():
                raise Problem('second_factor_required',403)
            store.authenticate_recently(session)
            return jsonify(ok=True,recent_auth=True)
        except Exception as error:
            return response_error(error)

    @app.route('/api/user-access/overview',methods=['GET'])
    def user_access_overview():
        try:
            context()
            users=[]
            for identity in identities():
                state=lifecycle.state(subject_factory(identity['username'],identity['client_id']))
                current=state['state'] if state else 'active'
                selectable=identity.get('eligible',True) is True and current=='active'
                eligible=identity.get('eligible',True) is True
                reason=identity.get('unavailable_reason','')
                if current=='active':
                    # S-UI's display flag and this system's verified runtime
                    # revocation are separate. A valid disabled S-UI account
                    # may still need its cached proxy credentials withdrawn.
                    if identity.get('enabled',True) is False:
                        current='disabled'
                    elif not eligible:
                        current=reason or 'unavailable'
                users.append({'client_id':identity['client_id'],'username':identity['username'],
                    'enabled':identity.get('enabled',True), 'unavailable_reason':reason,
                    'state':current,'selectable':selectable,
                    'restorable':state is not None and current in ('armed','purge_issued','revoking','revoked')})
            operations=lifecycle.overview(limit=100)
            return jsonify(ok=True,users=users,user_total=len(users),
                selectable_total=sum(user['selectable'] for user in users),
                operations=operations,audit_retention='permanent')
        except Exception as error:
            return response_error(error)

    @app.route('/api/user-access/prepare',methods=['POST'])
    def user_access_prepare():
        try:
            session=context(mutation=True,recent=True)
            body=json_body(('client_id','reason','action'))
            action=action_name(body)
            identity=resolve(body.get('client_id'),action)
            state=lifecycle.state(subject_factory(identity['username'],identity['client_id']))
            if action=='arm' and state is not None and state.get('state')!='active':
                raise Problem('operation_already_exists',409)
            if action=='restore' and (state is None or state.get('state') not in ('armed','purge_issued','revoking','revoked')):
                raise Problem('restore_not_available',409)
            reason=body.get('reason','')
            if not isinstance(reason,str) or len(reason)>500 or any(ord(char)<32 for char in reason):
                raise Problem('reason_invalid')
            reason=reason.strip() or ('管理员确认恢复' if action=='restore' else '管理员确认停用')
            raw,prepared=store.prepare(identity,session,reason,action)
            return jsonify(ok=True,confirmation_token=raw,expires_at=prepared['expires_at'],
                target={'client_id':identity['client_id'],'username':identity['username']},
                action=action,requires_confirmation=True)
        except Exception as error:
            return response_error(error)

    @app.route('/api/user-access/confirm',methods=['POST'])
    def user_access_confirm():
        try:
            session=context(mutation=True,recent=True)
            body=json_body(('client_id','confirmation_token','acknowledged','action'))
            if body.get('acknowledged') is not True:
                raise Problem('confirmation_acknowledgement_required')
            action=action_name(body)
            identity=resolve(body.get('client_id'),action)
            def dispatch(prepared):
                operation=getattr(lifecycle,prepared['action'])
                return operation(subject_factory(identity['username'],identity['client_id']),
                    actor=session['actor'],operation_id=prepared['operation_id'],reason=prepared['reason'])
            state=store.confirm(body.get('confirmation_token'),identity,session,action,dispatch)
            return jsonify(ok=True,operation=state)
        except Exception as error:
            return response_error(error)

    @app.route('/api/user-access/audit',methods=['GET'])
    def user_access_audit():
        try:
            context()
            raw=request.args.get('after_sequence','0')
            if not re.fullmatch(r'[0-9]{1,18}',raw):
                raise Problem('audit_cursor_invalid')
            target=request.args.get('client_id')
            if target is not None: target=client_id(target)
            rows=lifecycle.audit(client_id=target,after_sequence=int(raw),limit=100)
            return jsonify(ok=True,events=rows,audit_retention='permanent',
                next_after_sequence=rows[-1]['sequence'] if rows else int(raw),has_more=len(rows)==100)
        except Exception as error:
            return response_error(error)

    @app.route('/user-access-ui.js',methods=['GET'])
    def user_access_script():
        return Response((ASSETS/'user-access-ui.js').read_text(encoding='utf-8'),
                        content_type='application/javascript; charset=utf-8')

    @app.route('/user-access-ui.css',methods=['GET'])
    def user_access_styles():
        return Response((ASSETS/'user-access-ui.css').read_text(encoding='utf-8'),content_type='text/css; charset=utf-8')

    @app.after_request
    def user_access_headers_and_assets(response):
        if request.path.startswith('/api/user-access/') or request.path.startswith('/user-access-ui.'):
            response.headers['Cache-Control']='no-store'
            response.headers['X-Content-Type-Options']='nosniff'
        if request.path=='/' and response.mimetype=='text/html':
            text=response.get_data(as_text=True)
            marker='<script defer src="./user-access-ui.js"></script>'
            if marker not in text:
                response.set_data(text.replace('</head>','<link rel="stylesheet" href="./user-access-ui.css">'+marker+'</head>',1))
        return response


def register_backend(app,admin_request,same_origin_request,verify_view_key,*,backend,
                     allowed_origins,**options):
    """Adapt the root-owned authoritative identity/lifecycle backend.

    Required methods: list_users(), subject(target_id), overview(),
    arm(subject, actor=..., operation_id=..., reason=...), audit(**filters).
    Optional state(subject) avoids the bounded overview lookup for one target.
    """
    class Facade:
        def state(self,subject):
            if callable(getattr(backend,'state',None)):
                return backend.state(subject)
            for row in backend.overview():
                if str(row.get('client_id'))==str(subject.client_id):
                    if row.get('username')!=subject.username:
                        raise Problem('operation_conflict',409)
                    return row
            return None
        def overview(self,**kwargs): return backend.overview()
        def arm(self,subject,**kwargs): return backend.arm(subject,**kwargs)
        def restore(self,subject,**kwargs): return backend.restore(subject,**kwargs)
        def audit(self,**kwargs): return backend.audit(**kwargs)
    def subject_factory(username,target_id):
        subject=backend.subject(target_id)
        if str(subject.client_id)!=target_id or subject.username!=username:
            raise Problem('target_not_eligible',404)
        return subject
    def identities():
        result=[]
        for row in backend.list_users():
            if not isinstance(row,dict):
                continue
            target_id=str(row.get('target_id',''))
            subject=subject_factory(row.get('username'),target_id)
            revision=row.get('revision')
            if not isinstance(revision,str) or not re.fullmatch(r'[0-9a-f]{64}',revision):
                revision=digest(json.dumps([subject.username,str(subject.client_id)],ensure_ascii=False,separators=(',',':')))
            enabled=row.get('enabled',True)
            reason=row.get('unavailable_reason','')
            if type(enabled) is not bool or reason not in INVENTORY_REASONS:
                raise RuntimeError('inventory_metadata_invalid')
            result.append({'client_id':target_id,'username':subject.username,'revision':revision,
                           'eligible':row.get('eligible') is True,
                           'enabled':enabled,'unavailable_reason':reason})
        return result
    return register(app,admin_request,same_origin_request,verify_view_key,
        lifecycle=Facade(),list_eligible=identities,subject_factory=subject_factory,
        allowed_origins=allowed_origins,**options)
