"""Generation-fenced restoration; public access stays denied until caller commit.

Original strong DMIT credentials are reused. A never-provisioned subject gets
one durable strong credential, strict ordinary identity validation and the
same real admission proof for every configured route. Only this user's rows
are restored. Historical journal step names remain unchanged for safe resume.
"""
from __future__ import annotations

import copy
from pathlib import Path
import re
import secrets
import time

from runtime_revoke import RevokeError, _name, _require, _sha
from new_enrollment import EnrollmentError


# Only fixed, non-secret probe labels may be persisted for restore diagnosis.
# Route names in the probe currently contain hyphens; normalize them only
# after an exact allowlist match so journal codes remain lowercase identifiers.
_PROBE_ROUTES = frozenset(kind + '-' + tail
    for kind in ('desktop', 'mobile')
    for tail in ('dmit', 'bytevirt', 'bytevirt-tw', 'lazycat-starhub',
                 'lazycat-hkt', 'uzuma-singtel', 'uzuma-hkt'))
_PROBE_FAILURES = frozenset({
    'route_https_request_failed', 'trace_response_invalid',
    'trace_http_or_tls_failed', 'trace_country_missing',
    'isolated_selector_not_applied', 'controller_response_too_large',
    'egress_mismatch',
})
_PROBE_ERRORS = frozenset({
    'network_probe_profile_invalid', 'probe_dmit_credential_invalid',
    'candidate_probe_core_validation_failed', 'candidate_probe_core_exited',
    'candidate_probe_route_group_unavailable',
    'candidate_network_probe_egress_mismatch',
    'candidate_physical_network_probe_invalid',
    'candidate_ordinary_network_probe_invalid',
    'physical_test_identity_invalid', 'physical_test_runtime_permissions_invalid',
    'physical_test_runtime_oversize', 'physical_test_runtime_unavailable',
    'physical_test_front_missing', 'physical_test_binding_missing',
    'physical_test_binding_disagrees', 'physical_probe_failed',
    'ordinary_probe_failed',
}) | frozenset(prefix + route + '_' + failure
    for prefix in ('candidate_probe_', 'candidate_ordinary_probe_')
    for route in _PROBE_ROUTES for failure in _PROBE_FAILURES)


class RestorationCoordinator:
    def __init__(self, *, local, sui, bytevirt, restore_guard, read_identity,
                 refresh_sui, reload_dmit, close_sessions, probe,
                 verify_loaded, verify_revoked=None,
                 state_dir='/var/lib/user-access-control/runtime-revocations',
                 password_factory=None, clock=time.time):
        callbacks = (restore_guard, read_identity, refresh_sui, reload_dmit,
                     close_sessions, probe, verify_loaded)
        _require(all(callable(callback) for callback in callbacks), 'restoration_callbacks_required')
        self.local, self.sui, self.bytevirt = local, sui, bytevirt
        self.guard, self.read_identity = restore_guard, read_identity
        self.refresh_sui, self.reload_dmit, self.close_sessions = refresh_sui, reload_dmit, close_sessions
        self.probe, self.verify_loaded, self.verify_revoked = probe, verify_loaded, verify_revoked
        self.state_dir, self.clock = Path(state_dir), clock
        self.password_factory = password_factory or (lambda: secrets.token_urlsafe(32))

    def _guard(self, name):
        _require(self.guard(name) is True, 'restore_generation_fenced')

    def _save(self, path, state):
        before = self.local.io._read(path)[1] if path.exists() else None
        self.local.io._write(path, state, before)

    def _source(self, name, client_id, directory):
        pointer = directory / 'latest-revocation.json'
        if pointer.exists():
            latest, _ = self.local.io._read(pointer)
            _require(latest.get('schema') == 1 and latest.get('name') == name
                     and latest.get('client_id') == client_id, 'restore_source_binding_mismatch')
            generation = latest.get('generation')
            _require(generation is None or (type(generation) is int and generation > 0),
                     'restore_source_generation_invalid')
            source = (directory / 'journal.json' if generation is None else
                      directory / ('revoke-' + str(generation)) / 'journal.json')
        elif (directory / 'journal.json').exists():
            source = directory / 'journal.json'
        else:
            # The revoked intent can be restored before its old worker ever
            # began. Snapshot current exact state; do not require prior admission.
            sui = self.sui.prepare(name)
            _require(sui['row']['id'] == client_id, 'restore_source_binding_mismatch')
            return {'schema': 1, 'name': name, 'generation': None, 'sui': sui,
                    'local': self.local.prepare(name),
                    'bytevirt': self.bytevirt.prepare(name, sui['sui_password'])}
        value, _ = self.local.io._read(source)
        _require(value.get('schema') == 1 and value.get('name') == name
                 and value.get('sui', {}).get('row', {}).get('id') == client_id,
                 'restore_source_binding_mismatch')
        return value

    def _prepare(self, name, client_id, generation, directory):
        source = self._source(name, client_id, directory)
        local = copy.deepcopy(source['local'])
        password = local.get('dmit_password')
        if password is None:
            password = self.password_factory()
        _require(isinstance(password, str) and len(password) >= 24, 'restore_strong_credential_invalid')
        local['dmit_password'] = password
        for entry in local['entries']:
            if entry['kind'] == 'private':
                row = copy.deepcopy(entry['before']) if entry['before'] is not None else {'name': name}
                row['password'] = password
                entry['before'] = row
            elif entry['kind'] == 'ready':
                entry['before'] = name
            else:
                entry['before'] = password
        if hasattr(self.bytevirt, 'restoration_plan'):
            bytevirt = self.bytevirt.restoration_plan(source['bytevirt'], name, source['sui']['sui_password'])
        else:
            bytevirt = copy.deepcopy(source['bytevirt'])
            if bytevirt.get('previous') is None:
                bytevirt['previous'] = {'name': name, 'password': source['sui']['sui_password']}
            _require(bytevirt['previous'].get('name') == name and
                     bytevirt['previous'].get('password') == source['sui']['sui_password'],
                     'restore_bytevirt_source_credential_changed')
        return {'schema': 1, 'name': name, 'client_id': client_id, 'generation': generation,
                'source_generation': source.get('generation'), 'sui': copy.deepcopy(source['sui']),
                'local': local, 'bytevirt': bytevirt, 'dmit_password': password,
                'generated_dmit_credential': source['local'].get('dmit_password') is None,
                'created_at': int(self.clock()), 'completed': [], 'evidence': {},
                'status': 'pending', 'errors': {}}

    def _identity(self, state):
        self._guard(state['name'])
        identity = self.read_identity(state['name'])
        _require(identity.name == state['name'] and identity.sub_secret == state['name']
                 and identity.client_id == state['client_id']
                 and identity.sui_password == state['sui']['sui_password'],
                 'restore_identity_binding_changed')
        return identity

    @staticmethod
    def _code(error):
        if isinstance(error, RevokeError):
            value = str(error)
        elif isinstance(error, EnrollmentError):
            raw = str(error)
            value = raw.replace('-', '_') if raw in _PROBE_ERRORS else type(error).__name__
            if value != type(error).__name__ and re.fullmatch(r'[a-z0-9_]{1,100}', value) is None:
                value = type(error).__name__
        else:
            value = type(error).__name__
        return value if re.fullmatch(r'[A-Za-z0-9_]{1,100}', value) else type(error).__name__

    @staticmethod
    def _evidence(value):
        allowed = {'matched_sessions', 'scope', 'native_status', 'fallback', 'error_type',
                   'unit', 'before_pid', 'after_pid', 'restart_verified', 'runtime_mode', 'stop_verified'}
        return {key: item for key, item in value.items() if key in allowed
                and (item is None or type(item) in (int, bool)
                     or (isinstance(item, str) and len(item) <= 128))}

    def _compensate(self, state):
        name = state['name']
        disabled = copy.deepcopy(state['sui'])
        disabled['row']['enable'] = 1
        result = {'name': name, 'evidence': {}, 'errors': {}}
        operations = [
            ('sui_disabled', lambda: self.sui.disable(disabled)),
            ('local_removed', lambda: self.local.remove(state['local'])),
            ('bytevirt_removed', lambda: self.bytevirt.remove(state['bytevirt'])),
            ('sui_refreshed', lambda: self.refresh_sui(name)),
            ('dmit_reloaded', self.reload_dmit),
            ('sessions_closed_after_reload', lambda: self.close_sessions(name))]
        for step, operation in operations:
            self._guard(name)
            try:
                value = operation()
                if isinstance(value, dict):
                    result['evidence'][step] = self._evidence(value)
            except Exception as error:
                result['errors'][step] = self._code(error)
        if self.verify_revoked is not None:
            try:
                _require(self.verify_revoked(result) is True, 'restore_compensation_not_verified')
            except Exception as error:
                result['errors']['verification'] = self._code(error)
        return result

    def restore(self, name, *, expected_client_id, generation):
        _name(name)
        _require(type(expected_client_id) is int and expected_client_id > 0,
                 'expected_client_id_invalid')
        _require(type(generation) is int and generation > 0, 'runtime_generation_invalid')
        self._guard(name)
        with self.local.lock():
            self._guard(name)
            directory = self.state_dir / ('user-' + _sha(name.encode())[:24])
            path = directory / ('restore-' + str(generation)) / 'journal.json'
            if path.exists():
                state, _ = self.local.io._read(path)
                _require(state.get('schema') == 1 and state.get('name') == name
                         and state.get('client_id') == expected_client_id
                         and state.get('generation') == generation,
                         'restore_journal_binding_mismatch')
            else:
                state = self._prepare(name, expected_client_id, generation, directory)
                self._save(path, state)
            if state.get('status') == 'complete':
                identity = self._identity(state)
                try:
                    clean = (self.verify_loaded(state) is True
                             and self.probe(identity, state['dmit_password']) is True)
                except Exception:
                    clean = False
                if clean:
                    return {'status': 'complete', 'action': 'restore', 'name': name,
                            'generation': generation, 'already_complete': True}
                # Enrollment of an unrelated user can legitimately restart the
                # front after this job succeeded but before its queue ack. Reuse
                # the same targeted CAS plans and refresh the runtime proofs.
                state['status'], state['completed'], state['evidence'] = 'pending', [], {}
                self._save(path, state)
            try:
                operations = [
                    ('sui_enabled', lambda: self.sui.restore(state['sui'], authorized=self.guard)),
                    ('identity_verified', lambda: self._identity(state)),
                    ('local_restored', lambda: self.local.restore(state['local'], authorized=self.guard)),
                    ('bytevirt_restored', lambda: self.bytevirt.restore(state['bytevirt'], authorized=self.guard)),
                    ('sui_refreshed', lambda: self.refresh_sui(name)),
                    ('dmit_reloaded', self.reload_dmit),
                    ('three_routes_verified', lambda: _require(
                        self.probe(self._identity(state), state['dmit_password']) is True,
                        'restore_three_route_positive_proof_failed')),
                    ('ready_committed', lambda: self.local.restore(
                        state['local'], authorized=self.guard, include_ready=True)),
                    ('loaded_state_verified', lambda: _require(self.verify_loaded(state) is True,
                                                              'restored_runtime_verification_failed'))]
                for step, operation in operations:
                    self._guard(name)
                    if step in state['completed']:
                        continue
                    value = operation()
                    self._guard(name)
                    if isinstance(value, dict):
                        state['evidence'][step] = self._evidence(value)
                    state['completed'].append(step)
                    state['updated_at'] = int(self.clock())
                    self._save(path, state)
                state['status'], state['errors'] = 'complete', {}
                self._save(path, state)
                return {'status': 'complete', 'action': 'restore', 'name': name,
                        'generation': generation, 'already_complete': False,
                        'generated_dmit_credential': state['generated_dmit_credential'],
                        'public_gate_still_blocked': True}
            except Exception as error:
                if self.guard(name) is not True:
                    raise RevokeError('restore_generation_fenced') from None
                state['status'] = 'pending'
                state['errors'] = {'restore': self._code(error)}
                self._save(path, state)
                state['compensation'] = self._compensate(state)
                state['completed'], state['evidence'] = [], {}
                self._save(path, state)
                return {'status': 'pending', 'action': 'restore', 'name': name,
                        'generation': generation, 'pending_steps': sorted(state['errors']),
                        'compensated_to_revoked': not state['compensation']['errors'],
                        'public_gate_still_blocked': True}
