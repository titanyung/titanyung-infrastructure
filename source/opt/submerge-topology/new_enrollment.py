"""Incremental admission for DMIT, ByteVirt and the shared Zoro transport.

Only ByteVirt receives a remote per-user credential. Zoro's private SS hop is
shared by DMIT and is deliberately absent from this coordinator. Deployment
and route probes are injected: this module never guesses a remote service,
management key, proxy port or certificate setting.
"""
from __future__ import annotations

from contextlib import contextmanager, closing
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import tempfile
import threading
from typing import Callable, Optional

try:
    import fcntl
except ImportError:
    fcntl = None  # Synthetic Windows tests use the process lock below.


DB = Path('/usr/local/s-ui/db/s-ui.db')
PRIVATE = Path('/etc/dmit-direct-staging/private.json')
MAPS = (Path('/var/lib/submerge-staging/dmit-direct-users.json'),
        Path('/var/lib/submerge-public/dmit-users.json'))
READY = Path('/var/lib/submerge-public/ready-users.json')
STATE = Path('/root/topology-enrollment-20261105')
NAME = re.compile(r'^[A-Za-z0-9_+.-]{1,64}$')
MAX_JSON = 16 * 1024 * 1024
_locks_guard = threading.Lock()
_locks = {}


class EnrollmentError(RuntimeError):
    """Stable error code; no credential-bearing callback text is propagated."""


def _topology_id():
    path = Path('/etc/submerge-topology/network-plan.json')
    if not os.path.lexists(str(path)):
        return '20261105-dmit-bytevirt-zoro'
    try:
        from network_runtime import load_network_plan
        plan = load_network_plan(path)
        if plan is None:
            raise ValueError('missing intent')
        return plan.get('server_policy', {}).get('id', plan['plan'])
    except Exception:
        raise EnrollmentError('network_plan_invalid') from None


def _access_control_check(name):
    if not os.environ.get('USER_ACCESS_CONTROL_DB'):
        return
    import sys
    if '/opt/submerge-user-access' not in sys.path:
        sys.path.insert(0, '/opt/submerge-user-access')
    from access_policy import admission_allowed
    if not admission_allowed(name):
        raise EnrollmentError('user_access_suspended')


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _encode(value):
    return (json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False) + '\n').encode()


def _name(value, allow_trial=False):
    if (not isinstance(value, str) or not NAME.fullmatch(value) or value in {'.', '..'} or
            (value == 'test' and not allow_trial)):
        raise EnrollmentError('invalid_subscription_identity')
    return value


def _pairs(rows):
    result = {}
    for key, value in rows:
        if key in result:
            raise EnrollmentError('duplicate_private_json_key')
        result[key] = value
    return result


def _json(raw):
    try:
        return json.loads(raw, object_pairs_hook=_pairs)
    except (ValueError, TypeError, UnicodeError):
        raise EnrollmentError('invalid_private_json') from None


@dataclass(frozen=True, repr=False)
class Identity:
    client_id: int
    name: str
    sub_secret: str
    sui_password: str
    revision: str = ''

    def __repr__(self):
        return 'Identity(name={!r}, client_id={}, credentials=<redacted>)'.format(self.name, self.client_id)

    @property
    def fingerprint(self):
        return _sha(_encode([self.client_id, self.name, self.sub_secret,
                             self.sui_password, self.revision]))


def read_sui_identity(subid, db_path=DB, *, allow_trial=False, allow_disabled=False):
    """Read one unique S-UI identity with existing inbound 1 access.

    This never grants legacy inbounds 2–4 or rewrites S-UI route settings.
    Invalid unrelated rows are isolated; an actual password collision is not.
    Normal admission requires enabled=1. Explicit administrative revocation
    may inspect an already-disabled identity without enabling or admitting it.
    """
    if type(allow_disabled) is not bool:
        raise EnrollmentError('invalid_disabled_read_policy')
    _name(subid, allow_trial=allow_trial)
    try:
        uri = Path(db_path).resolve().as_uri() + '?mode=ro'
        with closing(sqlite3.connect(uri, uri=True, timeout=10)) as db:
            db.execute('PRAGMA query_only=ON')
            rows = db.execute('SELECT id,enable,name,sub_secret,config,inbounds '
                              'FROM clients WHERE sub_secret=? OR name=?', (subid, subid)).fetchall()
            if len(rows) != 1:
                raise EnrollmentError('sui_identity_not_unique')
            client_id, enabled, name, secret, raw, inbound_raw = rows[0]
            if ((enabled not in (0, 1) if allow_disabled else enabled != 1) or name != subid or secret != subid or
                    type(client_id) is not int or client_id <= 0):
                raise EnrollmentError('sui_identity_not_eligible')
            config, inbounds = _json(raw), _json(inbound_raw or '[]')
            eligible_grant = (inbounds == [2, 3, 4] if subid == 'test' and allow_trial else
                              isinstance(inbounds, list) and 1 in inbounds)
            if (not isinstance(inbounds, list) or not eligible_grant or
                    any(type(value) is not int or value <= 0 for value in inbounds) or
                    len(set(inbounds)) != len(inbounds)):
                raise EnrollmentError('sui_inbound_one_required')
            anytls = config.get('anytls') if isinstance(config, dict) else None
            if (not isinstance(anytls, dict) or anytls.get('name') != name or
                    not isinstance(anytls.get('password'), str) or len(anytls['password']) < 10):
                raise EnrollmentError('sui_anytls_identity_invalid')
            password = anytls['password']
            for other_raw, other_inbounds in db.execute(
                    'SELECT config,inbounds FROM clients WHERE enable=1 AND id!=?', (client_id,)):
                try:
                    other, grants = _json(other_raw), _json(other_inbounds or '[]')
                except EnrollmentError:
                    continue
                if not isinstance(grants, list) or not grants:
                    continue
                if (isinstance(other, dict) and isinstance(other.get('anytls'), dict) and
                        other['anytls'].get('password') == password):
                    raise EnrollmentError('sui_password_not_unique')
    except sqlite3.Error:
        raise EnrollmentError('sui_identity_read_failed') from None
    revision = _sha(_encode([config, inbounds, enabled]))
    return Identity(client_id, name, secret, password, revision)


def _pack(value):
    if isinstance(value, bytes):
        import base64
        return {'__topology_bytes__': base64.b64encode(value).decode('ascii')}
    if isinstance(value, dict):
        if '__topology_bytes__' in value:
            raise EnrollmentError('reserved_plan_field')
        return {key: _pack(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_pack(item) for item in value]
    if value is None or type(value) in (str, int, float, bool):
        return value
    raise EnrollmentError('bytevirt_plan_not_serializable')


def _unpack(value):
    if isinstance(value, dict) and set(value) == {'__topology_bytes__'}:
        import base64
        return base64.b64decode(value['__topology_bytes__'], validate=True)
    if isinstance(value, dict):
        return {key: _unpack(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_unpack(item) for item in value]
    return value


class EnrollmentCoordinator:
    """On-demand, single-user admission with durable, root-only journals.

    Callback contracts:
      prepare_bytevirt(identity) -> JSON-compatible plan (bytes are supported)
      apply_bytevirt(plan) / rollback_bytevirt(plan) -> idempotent guarded CAS
      reload_dmit() -> validate/reload the already-written private user file
      probe(identity, dmit_password) -> True only after all enabled routes pass
      verify_published(identity) -> optional final HTTPS/provider/profile check

    Remote rollback must preserve unrelated credentials added since prepare.
    No callback may log passwords, source URLs, whole configs or profile bodies.
    """
    def __init__(self, *, prepare_bytevirt: Callable, apply_bytevirt: Callable,
                 rollback_bytevirt: Callable, reload_dmit: Callable,
                 probe: Callable, verify_published: Optional[Callable] = None,
                 read_identity: Optional[Callable] = None, db_path=DB,
                 dmit_private=PRIVATE, dmit_maps=MAPS, ready=READY,
                 state_dir=STATE, password_factory=None, require_root=True):
        callbacks = (prepare_bytevirt, apply_bytevirt, rollback_bytevirt, reload_dmit, probe)
        if not all(callable(item) for item in callbacks):
            raise EnrollmentError('deployment_and_probe_callbacks_required')
        self.prepare_bytevirt, self.apply_bytevirt = prepare_bytevirt, apply_bytevirt
        self.rollback_bytevirt, self.reload_dmit, self.probe = rollback_bytevirt, reload_dmit, probe
        self.verify_published = verify_published
        self._default_identity_reader = read_identity is None
        self.read_identity = read_identity or (lambda subid: read_sui_identity(subid, db_path))
        self.private, self.maps, self.ready = Path(dmit_private), tuple(map(Path, dmit_maps)), Path(ready)
        if len(self.maps) != 2 or len(set(self.maps)) != 2:
            raise EnrollmentError('two_distinct_dmit_maps_required')
        self.state_dir = Path(state_dir)
        self.password_factory = password_factory or (lambda: secrets.token_urlsafe(32))
        self.require_root = require_root

    @staticmethod
    def _invoke(callback, code, *args):
        try:
            return callback(*args)
        except Exception:
            raise EnrollmentError(code) from None

    def _read(self, path):
        path = Path(path)
        try:
            flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
            fd = os.open(str(path), flags)
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_size > MAX_JSON or
                        (self.require_root and (info.st_uid != 0 or info.st_mode & 0o077))):
                    raise EnrollmentError('private_file_permissions_invalid')
                raw = stream.read(MAX_JSON + 1)
        except OSError:
            raise EnrollmentError('private_file_unavailable') from None
        if len(raw) > MAX_JSON:
            raise EnrollmentError('private_file_too_large')
        value = _json(raw)
        if not isinstance(value, dict):
            raise EnrollmentError('private_document_not_object')
        return value, raw

    def _write(self, path, value, expected):
        path = Path(path)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(path.parent, 0o700)
        descriptor, temp_name = tempfile.mkstemp(prefix='.' + path.name + '.topology-', dir=str(path.parent))
        temporary = Path(temp_name)
        try:
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(_encode(value))
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            if expected is None:
                if os.path.lexists(str(path)):
                    raise EnrollmentError('private_compare_and_swap_conflict')
            else:
                _, current = self._read(path)
                if current != expected:
                    raise EnrollmentError('private_compare_and_swap_conflict')
            os.replace(str(temporary), str(path))
            if os.name != 'nt':
                directory = os.open(str(path.parent), os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        finally:
            if temporary.exists():
                temporary.unlink()

    @contextmanager
    def _lock(self):
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.state_dir, 0o700)
        key = str(self.state_dir.resolve())
        with _locks_guard:
            lock = _locks.setdefault(key, threading.RLock())
        with lock:
            with open(self.state_dir / 'lock', 'a+b') as stream:
                os.chmod(self.state_dir / 'lock', 0o600)
                if fcntl is not None:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
                elif self.require_root:
                    raise EnrollmentError('production_file_lock_unavailable')
                try:
                    yield
                finally:
                    if fcntl is not None:
                        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def _identity(self, subid):
        identity = (self.read_identity(subid) if self._default_identity_reader else
                    self._invoke(self.read_identity, 'identity_reader_callback_failed', subid))
        if not isinstance(identity, Identity):
            raise EnrollmentError('identity_reader_contract_invalid')
        if (identity.name != subid or identity.sub_secret != subid or
                type(identity.client_id) is not int or identity.client_id <= 0 or
                not isinstance(identity.sui_password, str) or len(identity.sui_password) < 10):
            raise EnrollmentError('identity_reader_contract_invalid')
        return identity

    def _manifest(self):
        manifest, raw = self._read(self.ready)
        users = manifest.get('users')
        if (set(manifest) != {'schema', 'users'} or manifest['schema'] != 1 or not isinstance(users, dict) or
                any(not isinstance(key, str) or not isinstance(value, str) or not key or not value for key, value in users.items()) or
                len(set(users.values())) != len(users)):
            raise EnrollmentError('ready_manifest_invalid')
        return manifest, raw

    def _private_users(self):
        document, raw = self._read(self.private)
        users = document.get('users')
        if (not isinstance(users, list) or any(not isinstance(row, dict) or
                not isinstance(row.get('name'), str) or not row['name'] or
                not isinstance(row.get('password'), str) or not row['password'] for row in users)):
            raise EnrollmentError('dmit_private_users_invalid')
        names, passwords = [row['name'] for row in users], [row['password'] for row in users]
        if len(set(names)) != len(names) or len(set(passwords)) != len(passwords):
            raise EnrollmentError('dmit_private_credentials_not_unique')
        return document, raw

    def _map(self, path):
        mapping, raw = self._read(path)
        if (any(not isinstance(key, str) or not key or not isinstance(value, str) or not value for key, value in mapping.items()) or
                len(set(mapping.values())) != len(mapping)):
            raise EnrollmentError('dmit_map_invalid')
        return mapping, raw

    def _credentials(self, identity):
        private, _ = self._private_users()
        rows = [row for row in private['users'] if row['name'] == identity.name]
        found = [rows[0]['password'] if rows else None]
        for path in self.maps:
            mapping, _ = self._map(path)
            found.append(mapping.get(identity.sub_secret))
        if all(value is not None for value in found):
            if len(set(found)) != 1:
                raise EnrollmentError('existing_pending_credentials_conflict')
            return found[0], True
        if any(value is not None for value in found):
            raise EnrollmentError('partial_existing_pending_credentials')
        return None, False

    def _ready_identity(self, identity):
        manifest, _ = self._manifest()
        if identity.sub_secret not in manifest['users']:
            if identity.name in manifest['users'].values():
                raise EnrollmentError('ready_identity_conflict')
            return False
        if manifest['users'][identity.sub_secret] != identity.name:
            raise EnrollmentError('ready_identity_conflict')
        password, adopted = self._credentials(identity)
        if not adopted or not isinstance(password, str) or len(password) < 24:
            raise EnrollmentError('ready_dmit_credentials_incomplete')
        return True

    def _journal_path(self, subid):
        return self.state_dir / ('enroll-v2-' + _sha(subid.encode())[:24]) / 'journal.json'

    def _save(self, path, state):
        expected = self._read(path)[1] if path.exists() else None
        self._write(path, state, expected)

    def _prepare(self, identity, retained_password=None):
        password, adopted = self._credentials(identity)
        if password is None:
            password = retained_password or self._invoke(self.password_factory, 'password_factory_failed')
            if not isinstance(password, str) or len(password) < 24:
                raise EnrollmentError('new_dmit_password_invalid')
            private, _ = self._private_users()
            used = {row['password'] for row in private['users']}
            for path in self.maps:
                mapping, _ = self._map(path)
                used.update(mapping.values())
            if password in used:
                raise EnrollmentError('new_dmit_password_not_unique')
        elif len(password) < 24:
            raise EnrollmentError('existing_pending_password_invalid')
        plan = self._invoke(self.prepare_bytevirt, 'bytevirt_prepare_failed', identity)
        if not isinstance(plan, dict):
            raise EnrollmentError('bytevirt_plan_contract_invalid')
        packed = _pack(plan)
        _encode(packed)
        return {'schema': 2, 'topology': _topology_id(),
                'name': identity.name, 'secret': identity.sub_secret,
                'identity_fingerprint': identity.fingerprint,
                'dmit_password': password, 'adopted_local_credentials': adopted,
                'bytevirt_plan': packed, 'phase': 'prepared', 'dmit_reloaded': False}

    def _install_private(self, identity, state):
        document, raw = self._private_users()
        rows = [row for row in document['users'] if row['name'] == identity.name]
        if rows:
            if rows[0]['password'] != state['dmit_password']:
                raise EnrollmentError('dmit_private_user_changed')
            return False
        if state['adopted_local_credentials']:
            raise EnrollmentError('adopted_dmit_private_user_missing')
        if state['dmit_password'] in {row['password'] for row in document['users']}:
            raise EnrollmentError('dmit_private_password_collision')
        document['users'].append({'name': identity.name, 'password': state['dmit_password']})
        self._write(self.private, document, raw)
        return True

    def _install_maps(self, identity, state):
        for path in self.maps:
            mapping, raw = self._map(path)
            current = mapping.get(identity.sub_secret)
            if current is not None and current != state['dmit_password']:
                raise EnrollmentError('dmit_map_user_changed')
            if current is None:
                if state['adopted_local_credentials'] or state['dmit_password'] in mapping.values():
                    raise EnrollmentError('dmit_map_credential_conflict')
                mapping[identity.sub_secret] = state['dmit_password']
                self._write(path, mapping, raw)

    def _commit_ready(self, identity):
        manifest, raw = self._manifest()
        current = manifest['users'].get(identity.sub_secret)
        if current == identity.name:
            return
        if current is not None or identity.name in manifest['users'].values():
            raise EnrollmentError('ready_identity_conflict')
        manifest['users'][identity.sub_secret] = identity.name
        self._write(self.ready, manifest, raw)

    def _rollback(self, identity, state):
        """Remove this candidate only; never restore an entire cohort snapshot."""
        manifest, raw = self._manifest()
        if manifest['users'].get(identity.sub_secret) == identity.name:
            del manifest['users'][identity.sub_secret]
            self._write(self.ready, manifest, raw)
        elif identity.sub_secret in manifest['users']:
            raise EnrollmentError('ready_changed_before_rollback')
        if not state['adopted_local_credentials']:
            for path in self.maps:
                mapping, raw = self._map(path)
                if identity.sub_secret not in mapping:
                    continue
                if mapping[identity.sub_secret] != state['dmit_password']:
                    raise EnrollmentError('dmit_map_changed_before_rollback')
                del mapping[identity.sub_secret]
                self._write(path, mapping, raw)
            document, raw = self._private_users()
            rows = [row for row in document['users'] if row['name'] == identity.name]
            if rows:
                if rows[0]['password'] != state['dmit_password']:
                    raise EnrollmentError('dmit_user_changed_before_rollback')
                document['users'] = [row for row in document['users'] if row['name'] != identity.name]
                self._write(self.private, document, raw)
                self._invoke(self.reload_dmit, 'dmit_reload_failed')
        self._invoke(self.rollback_bytevirt, 'bytevirt_rollback_failed', _unpack(state['bytevirt_plan']))
        state['dmit_reloaded'] = False
        state['phase'] = 'rolled_back'

    def ensure(self, subid):
        """Admit one eligible subscriber or return an already-ready identity.

        Ready subscribers do not wait for pending users' network probes. Their
        S-UI identity and own local credential parity are still checked fresh.
        """
        _name(subid)
        _access_control_check(subid)
        if self.require_root and (not hasattr(os, 'geteuid') or os.geteuid() != 0):
            raise EnrollmentError('root_required')
        identity = self._identity(subid)
        if self._ready_identity(identity):
            return {'status': 'ready', 'name': identity.name, 'newly_enrolled': False}
        with self._lock():
            _access_control_check(subid)
            identity = self._identity(subid)
            if self._ready_identity(identity):
                return {'status': 'ready', 'name': identity.name, 'newly_enrolled': False}
            journal = self._journal_path(subid)
            if journal.exists():
                state, _ = self._read(journal)
                if (state.get('schema') != 2 or state.get('topology') not in {
                        '20261105-dmit-bytevirt-zoro', _topology_id()} or
                        state.get('name') != identity.name or state.get('secret') != identity.sub_secret):
                    raise EnrollmentError('enrollment_journal_identity_conflict')
                if state.get('identity_fingerprint') != identity.fingerprint:
                    raise EnrollmentError('identity_changed_since_prepare')
                if state.get('phase') == 'rolled_back':
                    state = self._prepare(identity, retained_password=state['dmit_password'])
            else:
                state = self._prepare(identity)
            self._save(journal, state)
            try:
                self._invoke(self.apply_bytevirt, 'bytevirt_apply_failed', _unpack(state['bytevirt_plan']))
                state['phase'] = 'bytevirt_applied'
                self._save(journal, state)
                changed = self._install_private(identity, state)
                # Credential maps are protected by the separate ready manifest.
                # Stage them before rendering so every newly loaded listener
                # has an exact private/staging/public credential binding.
                self._install_maps(identity, state)
                state['phase'] = 'maps_staged'
                self._save(journal, state)
                if changed or not state['dmit_reloaded']:
                    self._invoke(self.reload_dmit, 'dmit_reload_failed')
                    state['dmit_reloaded'] = True
                state['phase'] = 'dmit_applied'
                self._save(journal, state)
                if self._identity(subid).fingerprint != identity.fingerprint:
                    raise EnrollmentError('identity_changed_before_probe')
                contract = _topology_id()
                if self._invoke(self.probe, 'new_user_three_route_probe_failed', identity, state['dmit_password']) is not True:
                    raise EnrollmentError('new_user_three_route_probe_failed')
                if _topology_id() != contract:
                    raise EnrollmentError('network_plan_changed_during_probe')
                state['verified_topology'] = contract
                state['phase'] = 'routes_verified'
                self._save(journal, state)
                if self._identity(subid).fingerprint != identity.fingerprint:
                    raise EnrollmentError('identity_changed_before_ready')
                _access_control_check(subid)
                self._commit_ready(identity)
                state['phase'] = 'ready_committed'
                self._save(journal, state)
                if self.verify_published is not None and self._invoke(self.verify_published, 'new_user_published_profile_failed', identity) is not True:
                    raise EnrollmentError('new_user_published_profile_failed')
                state['phase'] = 'ready'
                self._save(journal, state)
                return {'status': 'ready', 'name': identity.name, 'newly_enrolled': True}
            except Exception as error:
                state['last_error_type'] = type(error).__name__
                try:
                    self._rollback(identity, state)
                except Exception as rollback_error:
                    state['phase'] = 'rollback_incomplete'
                    state['rollback_error_type'] = type(rollback_error).__name__
                    try:
                        self._save(journal, state)
                    except Exception:
                        pass
                    raise EnrollmentError('enrollment_failed_rollback_incomplete') from None
                self._save(journal, state)
                code = str(error) if isinstance(error, EnrollmentError) else 'enrollment_operation_failed'
                raise EnrollmentError(code) from None


def validate_profile(document, provider_document=None, *, network_plan_path=None):
    """Check the new layout without relying on obsolete absolute group slots."""
    marker = Path(network_plan_path or '/etc/submerge-topology/network-plan.json')
    if isinstance(document, dict) and 'x-submerge-routing-revision' in document:
        try:
            from network_runtime import load_network_plan, revised
            from routing_client_v4 import _gate_context, validate_projected, CLIENT_GATE_PATH
            plan = load_network_plan(marker)
            if (not revised(plan) or _gate_context(CLIENT_GATE_PATH) is None or
                    document.get('x-submerge-server-policy') != plan['server_policy']['id']):
                raise ValueError('revised_profile_plan_or_gate_mismatch')
            return validate_projected(document)
        except Exception:
            raise EnrollmentError('published_revised_profile_invalid') from None
    requested = isinstance(document, dict) and document.get('x-submerge-plan') == 'six-server-20261106'
    if requested or os.path.lexists(str(marker)):
        if not requested:
            raise EnrollmentError('published_network_plan_version_missing')
        try:
            from new_topology import validate_network_profile
            if os.path.lexists(str(marker)):
                from network_runtime import load_network_plan, server_policy_enabled, SERVER_POLICY_ID
                plan = load_network_plan(marker)
                if server_policy_enabled(plan) and document.get('x-submerge-server-policy') != SERVER_POLICY_ID:
                    raise ValueError('server policy contract missing')
            return validate_network_profile(document, provider_document)
        except Exception:
            raise EnrollmentError('published_network_plan_profile_invalid') from None
    from new_topology import (ALL, AUTO, GOOGLE, HK, STREAMING, VPS, OTHER,
                              CHINA, GLOBAL, DMIT, BYTEVIRT, TAIWAN, PAOLUZ,
                              AIRPORT_FAST, AIRPORT_AUTO, HEALTH_URL,
                              HEALTH_INTERVAL, HEALTH_TIMEOUT, ZORO_EMERGENCY_PROVIDER,
                              DNS_OVERSEAS, DNS_GOOGLE, UDP_FALLBACK_GUARD)
    if not isinstance(document, dict):
        raise EnrollmentError('published_profile_not_object')
    rules = document.get('rules')
    if (not isinstance(rules, list) or rules[-2:] != ['MATCH,' + ALL, UDP_FALLBACK_GUARD]
            or rules.count(UDP_FALLBACK_GUARD) != 1):
        raise EnrollmentError('published_udp_fallback_guard_invalid')
    groups = document.get('proxy-groups')
    if not isinstance(groups, list) or not groups or groups[0].get('name') != GLOBAL:
        raise EnrollmentError('published_global_order_invalid')
    by_name = {group.get('name'): group for group in groups if isinstance(group, dict)}
    if len(by_name) != len(groups):
        raise EnrollmentError('published_group_identity_invalid')
    visible = [group['name'] for group in groups if not group.get('hidden')]
    if visible != [ALL, GOOGLE, HK, STREAMING, VPS, OTHER]:
        raise EnrollmentError('published_six_group_shape_invalid')
    google = by_name[GOOGLE].get('proxies')
    if (not isinstance(google, list) or len(google) not in (2, 3) or google[-1] != DMIT
            or google[1:-1] not in ([], [TAIWAN])):
        raise EnrollmentError('published_ai_routes_invalid')
    zoro = google[0]
    after_zoro = google[1:-1]
    airport_prefix = [AIRPORT_AUTO, zoro, *after_zoro]
    required = {ALL: [AUTO, GOOGLE, HK, STREAMING, VPS, OTHER], HK: [BYTEVIRT],
                VPS: [DMIT, BYTEVIRT, zoro, *after_zoro],
                GLOBAL: [GOOGLE, HK, STREAMING, VPS, CHINA, OTHER], AUTO: [OTHER],
                DNS_OVERSEAS: [AIRPORT_AUTO], DNS_GOOGLE: [GOOGLE]}
    if any(by_name.get(name, {}).get('proxies') != members for name, members in required.items()):
        raise EnrollmentError('published_route_order_invalid')
    for name in (STREAMING, OTHER):
        group = by_name[name]
        members = group.get('proxies')
        provider_form = group.get('use') == ['paoluz'] and members == airport_prefix
        explicit_form = (not group.get('use') and isinstance(members, list) and
                         len(members) >= len(airport_prefix) and members[:len(airport_prefix)] == airport_prefix)
        if (group.get('type') != 'select' or not (provider_form or explicit_form) or
                group.get('empty-fallback') != 'REJECT' or
                group.get('default-selected') != AIRPORT_AUTO):
            raise EnrollmentError('published_airport_provider_group_invalid')
    fastest, automatic = by_name.get(AIRPORT_FAST, {}), by_name.get(AIRPORT_AUTO, {})
    if (fastest.get('type') != 'url-test' or fastest.get('use') != ['paoluz'] or
            fastest.get('tolerance') != 0 or fastest.get('proxies') or
            automatic.get('type') != 'fallback' or automatic.get('proxies') != [AIRPORT_FAST] or
            automatic.get('use') != ['paoluz', ZORO_EMERGENCY_PROVIDER]):
        raise EnrollmentError('published_airport_priority_invalid')
    for group in (fastest, automatic):
        if (not group.get('hidden') or group.get('url') != HEALTH_URL or
                group.get('interval') != HEALTH_INTERVAL or group.get('timeout') != HEALTH_TIMEOUT or
                group.get('expected-status') != 204 or
                group.get('lazy') is not False or group.get('empty-fallback') != 'REJECT'):
            raise EnrollmentError('published_airport_health_invalid')
    if PAOLUZ in by_name:
        raise EnrollmentError('published_obsolete_airport_helper')
    dns = document.get('dns') or {}
    if (not dns.get('nameserver') or
            not all(url.endswith('#' + DNS_OVERSEAS) for url in dns['nameserver']) or
            not all(url.endswith('#' + DNS_GOOGLE) for url in
                dns.get('nameserver-policy', {}).get('geosite:google,youtube,category-ai-!cn', []))):
        raise EnrollmentError('published_dns_proxy_alias_invalid')
    provider = (document.get('proxy-providers') or {}).get('paoluz')
    if not isinstance(provider, dict) or provider.get('type') != 'http' or provider.get('proxy') != 'DIRECT':
        raise EnrollmentError('published_airport_provider_invalid')
    if provider.get('health-check') != {'enable': True, 'url': HEALTH_URL,
            'interval': HEALTH_INTERVAL, 'timeout': HEALTH_TIMEOUT, 'lazy': False, 'expected-status': 204}:
        raise EnrollmentError('published_airport_provider_health_invalid')
    proxies = document.get('proxies')
    if not isinstance(proxies, list):
        raise EnrollmentError('published_proxies_invalid')
    nodes = {node.get('name'): node for node in proxies if isinstance(node, dict)}
    if len(nodes) != len(proxies) or not {DMIT, BYTEVIRT, zoro, *after_zoro}.issubset(nodes):
        raise EnrollmentError('published_semantic_routes_missing')
    if (TAIWAN in nodes) != bool(after_zoro):
        raise EnrollmentError('published_taiwan_route_shape_invalid')
    explicit_groups = [by_name[name] for name in (STREAMING, OTHER) if not by_name[name].get('use')]
    if explicit_groups:
        direct = by_name.get(CHINA, {}).get('proxies', [])
        if (len(explicit_groups) != 2 or len(direct) != 1 or
                nodes.get(direct[0], {}).get('type') != 'direct'):
            raise EnrollmentError('published_explicit_airport_shape_invalid')
        own = {DMIT, BYTEVIRT, zoro, *after_zoro, direct[0]}
        airport_names = [node['name'] for node in proxies if node['name'] not in own]
        if (not airport_names or any(group['proxies'] != airport_prefix + airport_names
                                     for group in explicit_groups)):
            raise EnrollmentError('published_explicit_airport_members_invalid')
    emergency = (document.get('proxy-providers') or {}).get(ZORO_EMERGENCY_PROVIDER)
    if (not isinstance(emergency, dict) or emergency.get('type') != 'inline' or
            emergency.get('payload') != [nodes[zoro]] or
            emergency.get('health-check') != provider.get('health-check')):
        raise EnrollmentError('published_emergency_route_invalid')
    if any(node.get('dialer-proxy') not in (None, 'DIRECT') and node['dialer-proxy'] not in nodes
           for node in nodes.values()):
        raise EnrollmentError('published_dialer_missing')
    if provider_document is not None:
        items = provider_document.get('proxies') if isinstance(provider_document, dict) else None
        if not isinstance(items, list) or not items or any(not isinstance(item, dict) or
                not isinstance(item.get('name'), str) or not item['name'] or
                not isinstance(item.get('type'), str) or not item['type'] for item in items):
            raise EnrollmentError('published_provider_cache_empty')
        if len({item['name'] for item in items}) != len(items):
            raise EnrollmentError('published_provider_node_identity_duplicate')
        if explicit_groups and ([item['name'] for item in items] != airport_names or
                any(nodes.get(item['name']) != item for item in items)):
            raise EnrollmentError('published_explicit_airport_cache_mismatch')
    return True
