"""Targeted, retryable revocation adapters; importing performs no I/O.

The caller MUST durably deny subscription/enrollment before invoking revoke.
Failure keeps that deny in force and journals pending work; it never restores
credentials automatically. Shared DMIT-to-exit hop credentials are never changed.
"""
from __future__ import annotations

import copy
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import time
import urllib.parse

HERE = Path(__file__).resolve().parent
for candidate in (HERE.parent / 'topology-20261105', Path('/opt/submerge-topology')):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from new_enrollment import EnrollmentCoordinator, PRIVATE, MAPS, READY, STATE, DB


class RevokeError(RuntimeError):
    """Only stable, non-secret error codes may leave an adapter."""


def _name(value):
    if (not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_+.-]{1,64}', value)
            or value in {'.', '..'}):
        raise RevokeError('invalid_user_identity')
    return value


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _encode(value):
    return (json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False) + '\n').encode()


def _require(condition, code):
    if not condition:
        raise RevokeError(code)


class LocalCredentialAdapter:
    """Use the existing admission lock, permission checks, fsync, and file CAS."""
    def __init__(self, *, private=PRIVATE, maps=MAPS, ready=READY,
                 enrollment_state=STATE, require_root=True):
        self.io = EnrollmentCoordinator(prepare_bytevirt=lambda *_: {},
            apply_bytevirt=lambda *_: None, rollback_bytevirt=lambda *_: None,
            reload_dmit=lambda: None, probe=lambda *_: False,
            dmit_private=private, dmit_maps=maps, ready=ready,
            state_dir=enrollment_state, require_root=require_root)
        self.paths = {'private': self.io.private, 'map0': self.io.maps[0],
                      'map1': self.io.maps[1], 'ready': self.io.ready}

    def lock(self):
        return self.io._lock()

    def prepare(self, name):
        _name(name)
        entries = []
        backups = {}
        for kind, path in self.paths.items():
            document, raw = self.io._read(path)
            backups[kind] = document
            if kind == 'private':
                rows = document.get('users')
                _require(isinstance(rows, list) and all(isinstance(row, dict)
                    and isinstance(row.get('name'), str) for row in rows),
                    'private_user_schema_invalid')
                matching = [row for row in rows if row['name'] == name]
                _require(len(matching) <= 1, 'private_user_not_unique')
                before = matching[0] if matching else None
            elif kind == 'ready':
                _require(document.get('schema') == 1 and isinstance(document.get('users'), dict),
                         'ready_schema_invalid')
                _require(not any(key != name and value == name for key, value in document['users'].items()),
                         'ready_user_alias_conflict')
                before = document['users'].get(name)
                _require(before in (None, name), 'ready_identity_mismatch')
            else:
                before = document.get(name)
            entries.append({'kind': kind, 'path': str(path), 'before': copy.deepcopy(before),
                            'baseline_sha256': _sha(raw)})
        passwords = [entry['before']['password'] if entry['kind'] == 'private'
                     and entry['before'] is not None else entry['before']
                     for entry in entries if entry['kind'] != 'ready' and entry['before'] is not None]
        _require(all(isinstance(password, str) and password for password in passwords),
                 'local_user_credential_invalid')
        _require(len(set(passwords)) <= 1, 'local_user_credentials_disagree')
        return {'schema': 1, 'name': name, 'entries': entries, 'backups': backups,
                'dmit_password': passwords[0] if passwords else None}

    def _change(self, plan, *, restore=False, authorized=None, include_ready=True):
        name = _name(plan.get('name'))
        _require(plan.get('schema') == 1, 'local_revoke_plan_invalid')
        if restore:
            _require(callable(authorized) and authorized(name) is True,
                     'explicit_restore_authorization_required')
        entries = plan.get('entries')
        _require(isinstance(entries, list) and {entry.get('kind') for entry in entries} == set(self.paths),
                 'local_revoke_plan_invalid')
        # Hide ready first during revoke; restore it only in a separate final step.
        order = {'ready': 0, 'map0': 1, 'map1': 2, 'private': 3}
        for entry in sorted(entries, key=lambda item: order[item['kind']]):
            kind = entry['kind']
            if kind == 'ready' and not include_ready:
                continue
            path = self.paths[kind]
            _require(entry.get('path') == str(path), 'local_revoke_plan_path_changed')
            document, raw = self.io._read(path)
            if kind == 'private':
                rows = document.get('users')
                _require(isinstance(rows, list), 'private_user_schema_invalid')
                found = [row for row in rows if isinstance(row, dict) and row.get('name') == name]
                _require(len(found) <= 1, 'private_user_not_unique')
                current = found[0] if found else None
            elif kind == 'ready':
                _require(isinstance(document.get('users'), dict), 'ready_schema_invalid')
                current = document['users'].get(name)
            else:
                current = document.get(name)
            expected, desired = ((None, entry['before']) if restore else (entry['before'], None))
            if current == desired:
                continue
            _require(current == expected, 'local_target_user_changed')
            if kind == 'private':
                if desired is None:
                    document['users'] = [row for row in rows if row.get('name') != name]
                else:
                    _require(not any(row.get('name') != name and row.get('password') == desired.get('password')
                                     for row in rows), 'private_restore_password_collision')
                    document['users'].append(copy.deepcopy(desired))
            else:
                values = document['users'] if kind == 'ready' else document
                if desired is None:
                    values.pop(name, None)
                else:
                    _require(not any(key != name and value == desired for key, value in values.items()),
                             'local_restore_value_collision')
                    values[name] = copy.deepcopy(desired)
            self.io._write(path, document, raw)

    def remove(self, plan):
        self._change(plan)

    def restore(self, plan, *, authorized, include_ready=False):
        self._change(plan, restore=True, authorized=authorized, include_ready=include_ready)

    def absent(self, name):
        plan = self.prepare(name)
        return all(entry['before'] is None for entry in plan['entries'])


class SuiDisableAdapter:
    """Disable one exact S-UI row transactionally; never replace the database."""
    def __init__(self, path=DB):
        self.path = Path(path)

    @staticmethod
    def _select(db, name):
        rows = db.execute('SELECT id,name,sub_secret,enable,config,inbounds FROM clients '
                          'WHERE name=? OR sub_secret=?', (name, name)).fetchall()
        _require(len(rows) == 1, 'sui_revoke_identity_not_unique')
        row = rows[0]
        _require(type(row[0]) is int and row[0] > 0 and row[1] == name and row[2] == name
                 and row[3] in (0, 1), 'sui_revoke_identity_mismatch')
        # Root-only journals are JSON. Retain BLOB storage type and exact bytes
        # for future per-row CAS rather than serializing raw SQLite bytes.
        values = [({'sqlite_blob_hex': bytes(value).hex()}
                   if isinstance(value, (bytes, bytearray, memoryview)) else value) for value in row]
        return dict(zip(('id', 'name', 'sub_secret', 'enable', 'config', 'inbounds'), values))

    def prepare(self, name):
        _name(name)
        with closing(sqlite3.connect(self.path.resolve().as_uri() + '?mode=ro', uri=True, timeout=10)) as db:
            db.execute('PRAGMA query_only=ON')
            row = self._select(db, name)
        try:
            config = row['config']
            if isinstance(config, dict) and set(config) == {'sqlite_blob_hex'}:
                config = bytes.fromhex(config['sqlite_blob_hex'])
            anytls = json.loads(config)['anytls']
            _require(anytls.get('name') == name and isinstance(anytls.get('password'), str)
                     and len(anytls['password']) >= 10, 'sui_revoke_credential_invalid')
        except (ValueError, KeyError, TypeError):
            raise RevokeError('sui_revoke_credential_invalid') from None
        return {'schema': 1, 'name': name, 'row': row, 'sui_password': anytls['password']}

    def _change(self, plan, *, restore=False, authorized=None):
        name = _name(plan.get('name'))
        _require(plan.get('schema') == 1 and isinstance(plan.get('row'), dict), 'sui_revoke_plan_invalid')
        if restore:
            _require(callable(authorized) and authorized(name) is True,
                     'explicit_restore_authorization_required')
        before = plan['row']
        desired = 1 if restore else 0
        with closing(sqlite3.connect(self.path, timeout=10)) as db:
            db.execute('PRAGMA busy_timeout=10000')
            db.execute('BEGIN IMMEDIATE')
            try:
                current = self._select(db, name)
                _require(all(current[key] == before[key] for key in before if key != 'enable'),
                         'sui_target_user_changed')
                expected_states = (0, 1) if restore else (before['enable'], desired)
                _require(current['enable'] in expected_states, 'sui_enable_changed')
                if current['enable'] != desired:
                    result = db.execute('UPDATE clients SET enable=? WHERE id=? AND enable=?',
                                        (desired, before['id'], current['enable']))
                    _require(result.rowcount == 1, 'sui_enable_compare_and_swap_failed')
                db.commit()
            except Exception:
                db.rollback()
                raise

    def disable(self, plan):
        self._change(plan)

    def restore(self, plan, *, authorized):
        self._change(plan, restore=True, authorized=authorized)


class ByteVirtRevokeAdapter:
    """Remove exactly one authenticated AnyTLS2443 row using audited transport."""
    def __init__(self, adapter=None):
        if adapter is None:
            from topology_enrollment_runtime import ByteVirtAdapter
            adapter = ByteVirtAdapter()
        self.adapter = adapter

    @staticmethod
    def _parse(raw):
        from topology_enrollment_runtime import _config
        return _config(raw)

    def prepare(self, name, password):
        _name(name)
        raw = self.adapter._transport(name).read_config()
        _, inbound = self._parse(raw)
        matching = [row for row in inbound['users'] if row['name'] == name]
        before = matching[0] if matching else None
        _require(before is None or before.get('password') == password,
                 'bytevirt_target_credential_mismatch')
        return {'schema': 1, 'name': name, 'previous': copy.deepcopy(before),
                'baseline_sha256': _sha(raw)}

    def _change(self, plan, *, restore=False, authorized=None):
        name = _name(plan.get('name'))
        _require(plan.get('schema') == 1, 'bytevirt_revoke_plan_invalid')
        if restore:
            _require(callable(authorized) and authorized(name) is True,
                     'explicit_restore_authorization_required')
        reader = self.adapter._transport(name)
        raw = reader.read_config()
        document, inbound = self._parse(raw)
        current = next((row for row in inbound['users'] if row['name'] == name), None)
        expected, desired = ((None, plan['previous']) if restore else (plan['previous'], None))
        if current == desired:
            # A process may have stopped after file CAS but before reloading.
            reader.restart_and_check()
            return
        _require(current == expected, 'bytevirt_target_user_changed')
        if desired is None:
            inbound['users'] = [row for row in inbound['users'] if row['name'] != name]
        else:
            _require(not any(row['name'] != name and row['password'] == desired['password']
                             for row in inbound['users']), 'bytevirt_restore_password_collision')
            inbound['users'].append(copy.deepcopy(desired))
        candidate = _encode(document)
        self._parse(candidate)
        writer = self.adapter._transport(name, raw, candidate, 'rollback' if restore else 'apply')
        writer.install_if_hash(_sha(raw), candidate)
        _, checked = self._parse(writer.read_config())
        actual = next((row for row in checked['users'] if row['name'] == name), None)
        _require(actual == desired and writer.active(), 'bytevirt_revoke_runtime_verification_failed')

    def remove(self, plan):
        self._change(plan)

    def restore(self, plan, *, authorized):
        self._change(plan, restore=True, authorized=authorized)


class ScopedSessionCloser:
    """Close UUIDs matched by native authenticated user + audited inbound.

    ``authenticated_snapshot`` must return a complete current native snapshot
    with raw UUID ``id``, authenticated ``user`` and ``inbound``. It must not
    infer users from IP, destination, time, or historical access records.
    """
    def __init__(self, authenticated_snapshot, delete_connection, *, inbounds):
        _require(callable(authenticated_snapshot) and callable(delete_connection),
                 'scoped_session_callbacks_required')
        _require(isinstance(inbounds, (set, frozenset)) and inbounds
                 and all(isinstance(tag, str) and tag for tag in inbounds),
                 'scoped_session_inbounds_required')
        self.snapshot, self.delete, self.inbounds = authenticated_snapshot, delete_connection, set(inbounds)

    def close(self, name):
        _name(name)
        rows = self.snapshot()
        _require(isinstance(rows, list), 'authenticated_session_snapshot_invalid')
        identifiers = set()
        for row in rows:
            _require(isinstance(row, dict), 'authenticated_session_snapshot_invalid')
            if row.get('user') != name or row.get('inbound') not in self.inbounds:
                continue
            identifier = row.get('id')
            _require(isinstance(identifier, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', identifier),
                     'authenticated_session_id_invalid')
            identifiers.add(identifier)
        for identifier in sorted(identifiers):
            self.delete(identifier)
        # New authenticated rows can race the first sweep before runtime reload.
        # The coordinator repeats this after credential reload as a final sweep.
        return {'matched_sessions': len(identifiers), 'scope': 'exact_authenticated_user'}


class RevocationCoordinator:
    """Forward-recover revocation; never automatically regrant failed access."""
    def __init__(self, *, local, sui, bytevirt, deny_guard, reload_dmit,
                 refresh_sui, close_sessions, verify_denied,
                 state_dir='/var/lib/user-access-control/runtime-revocations', clock=time.time):
        callbacks = (deny_guard, reload_dmit, refresh_sui, close_sessions, verify_denied)
        _require(all(callable(callback) for callback in callbacks), 'revocation_callbacks_required')
        self.local, self.sui, self.bytevirt = local, sui, bytevirt
        self.deny_guard, self.reload_dmit, self.refresh_sui = deny_guard, reload_dmit, refresh_sui
        self.close_sessions, self.verify_denied = close_sessions, verify_denied
        self.state_dir, self.clock = Path(state_dir), clock

    def _guard(self, name):
        _require(self.deny_guard(name) is True, 'durable_deny_must_precede_runtime_revoke')

    def _save(self, path, state):
        raw = self.local.io._read(path)[1] if path.exists() else None
        self.local.io._write(path, state, raw)

    def revoke(self, name, *, expected_client_id=None, generation=None):
        _name(name)
        _require(expected_client_id is None or (type(expected_client_id) is int and expected_client_id > 0),
                 'expected_client_id_invalid')
        _require(generation is None or (type(generation) is int and generation > 0),
                 'runtime_generation_invalid')
        self._guard(name)
        with self.local.lock():
            self._guard(name)
            user_directory = self.state_dir / ('user-' + _sha(name.encode())[:24])
            path = (user_directory / 'journal.json' if generation is None else
                    user_directory / ('revoke-' + str(generation)) / 'journal.json')
            if path.exists():
                state, _ = self.local.io._read(path)
                _require(state.get('schema') == 1 and state.get('name') == name,
                         'runtime_revoke_journal_identity_mismatch')
                _require(state.get('generation') == generation, 'runtime_revoke_journal_generation_mismatch')
                _require(expected_client_id is None or state.get('sui', {}).get('row', {}).get('id') == expected_client_id,
                         'runtime_revoke_claim_binding_mismatch')
                if state.get('status') == 'complete':
                    try:
                        current = self.sui.prepare(name)
                        clean = (current['row']['enable'] == 0 and self.local.absent(name)
                                 and self.verify_denied(state) is True)
                    except Exception:
                        clean = False
                    if clean:
                        return {'status': 'complete', 'name': name, 'already_complete': True}
                    # Detect later credential drift; do not trust an old success
                    # marker forever or prepare a new identity silently.
                    state['status'] = 'pending'
                    state['completed'] = []
                    state['errors'] = {'verification': 'completed_revoke_state_drifted'}
                    self._save(path, state)
            else:
                sui_plan = self.sui.prepare(name)
                _require(expected_client_id is None or sui_plan['row']['id'] == expected_client_id,
                         'runtime_revoke_claim_binding_mismatch')
                state = {'schema': 1, 'name': name, 'generation': generation, 'created_at': int(self.clock()),
                    'sui': sui_plan, 'local': self.local.prepare(name),
                    'bytevirt': self.bytevirt.prepare(name, sui_plan['sui_password']),
                    'completed': [], 'errors': {}, 'status': 'pending'}
                # Backups/plans are durable root-only BEFORE the first mutation.
                self._save(path, state)
            self._guard(name)
            pointer = user_directory / 'latest-revocation.json'
            self._save(pointer, {'schema': 1, 'name': name, 'generation': generation,
                'client_id': state['sui']['row']['id']})
            operations = [
                ('sui_disabled', lambda: self.sui.disable(state['sui'])),
                ('local_removed', lambda: self.local.remove(state['local'])),
                ('sessions_closed_before_reload', lambda: self.close_sessions(name)),
                ('bytevirt_removed', lambda: self.bytevirt.remove(state['bytevirt'])),
                ('sui_refreshed', lambda: self.refresh_sui(name)),
                ('dmit_reloaded', self.reload_dmit),
                ('sessions_closed_after_reload', lambda: self.close_sessions(name)),
            ]
            for step, operation in operations:
                self._guard(name)
                if step in state['completed']:
                    continue
                try:
                    evidence = operation()
                    state['completed'].append(step)
                    state['errors'].pop(step, None)
                    if isinstance(evidence, dict):
                        allowed = {'matched_sessions', 'scope', 'native_status', 'fallback',
                                   'error_type', 'unit', 'before_pid', 'after_pid', 'restart_verified',
                                   'runtime_mode', 'stop_verified'}
                        state.setdefault('evidence', {})[step] = {
                            key: value for key, value in evidence.items() if key in allowed
                            and (value is None or type(value) in (int, bool)
                                 or (isinstance(value, str) and len(value) <= 128))}
                    invalidated = {
                        'sui_disabled': {'sui_refreshed', 'dmit_reloaded', 'sessions_closed_after_reload'},
                        'local_removed': {'dmit_reloaded', 'sessions_closed_after_reload'},
                    }.get(step, set())
                    state['completed'] = [item for item in state['completed'] if item not in invalidated]
                except Exception as error:
                    # Still revoke the other runtimes even if one component is
                    # temporarily unavailable. Retrying reuses the exact plans.
                    code = str(error) if isinstance(error, RevokeError) else type(error).__name__
                    state['errors'][step] = code if re.fullmatch(r'[A-Za-z0-9_]{1,100}', code) else type(error).__name__
                state['updated_at'] = int(self.clock())
                state['status'] = 'pending'
                self._save(path, state)
            self._guard(name)
            try:
                _require(self.local.absent(name), 'local_runtime_credentials_not_absent')
                _require(self.verify_denied(state) is True, 'runtime_denial_verification_failed')
                state['errors'].pop('verification', None)
            except Exception as error:
                code = str(error) if isinstance(error, RevokeError) else type(error).__name__
                state['errors']['verification'] = code if re.fullmatch(r'[A-Za-z0-9_]{1,100}', code) else type(error).__name__
                if not any(step != 'verification' for step in state['errors']):
                    # All mutation callbacks claimed success but loaded state
                    # disagrees. A retry must actually resynchronize runtimes,
                    # rather than loop forever rechecking a stale success flag.
                    state['completed'] = []
            state['status'] = 'complete' if not state['errors'] else 'pending'
            state['updated_at'] = int(self.clock())
            self._save(path, state)
            return {'status': state['status'], 'name': name, 'already_complete': False,
                    'completed_steps': list(state['completed']), 'pending_steps': sorted(state['errors']),
                    'durable_deny_preserved': True}
