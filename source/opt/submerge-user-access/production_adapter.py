"""Wire existing production paths to the additive revocation coordinator.

The caller must provide its durable deny predicate. No subscription registry
schema or administrator authorization is guessed here. Import/construct does
not connect to a proxy host or restart any service; revoke(name) does the work.
"""
from __future__ import annotations

from pathlib import Path
from contextlib import closing
import sqlite3
import subprocess

from runtime_revoke import (ByteVirtRevokeAdapter, LocalCredentialAdapter,
    RevocationCoordinator, RevokeError, SuiDisableAdapter, _require)

TAIWAN_TRANSPORT = Path('/etc/submerge-topology/taiwan-transport.json')
NETWORK_PLAN_PATH = Path('/etc/submerge-topology/network-plan.json')
BASE_FRONTS = {'dmit-direct-stage': 31117, 'dmit-zorocloud': 29513}
TAIWAN_FRONT = {'dmit-taiwan': 29514}


def _network_plan(path=NETWORK_PLAN_PATH, document=None):
    from topology_enrollment_runtime import _network_plan as read_plan
    try:
        plan = read_plan(path)
    except Exception:
        raise RevokeError('network_plan_invalid') from None
    declared = (isinstance(document, dict) and any(isinstance(item, dict) and
        (item.get('tag') in {'dmit-starhub', 'dmit-hkt', 'dmit-singtel', 'dmit-hk'} or
         str(item.get('tag', '')).startswith('mobile-dmit-'))
        for item in document.get('inbounds', [])))
    _require(plan is not None or not declared, 'network_plan_intent_missing')
    return plan


class PolicyAwareRevokeAdapter:
    """DMIT owns the new shared HK auth; old independent HK keeps its adapter."""
    def __init__(self, *, network_plan_path=NETWORK_PLAN_PATH, legacy_factory=None):
        self.network_plan_path = network_plan_path
        self.legacy_factory = legacy_factory or ByteVirtRevokeAdapter
        self._legacy_instance = None

    def _legacy(self):
        if self._legacy_instance is None:
            self._legacy_instance = self.legacy_factory()
        return self._legacy_instance

    def _enabled(self):
        from network_runtime import server_policy_enabled
        return server_policy_enabled(_network_plan(self.network_plan_path))

    def prepare(self, name, password):
        if not self._enabled():
            return self._legacy().prepare(name, password)
        from runtime_revoke import _name
        from network_runtime import SERVER_POLICY_ID
        return {'schema':1, 'scope':SERVER_POLICY_ID, 'name':_name(name), 'previous':None}

    def restoration_plan(self, source, name, password):
        if self._enabled():
            return self.prepare(name, password)
        from network_runtime import SERVER_POLICY_ID
        _require(source.get('scope') != SERVER_POLICY_ID, 'shared_hk_policy_intent_missing')
        import copy
        plan = copy.deepcopy(source)
        if plan.get('previous') is None:
            plan['previous'] = {'name':name, 'password':password}
        _require(plan['previous'].get('name') == name and plan['previous'].get('password') == password,
                 'restore_bytevirt_source_credential_changed')
        return plan

    def _change(self, plan, *, restore=False, authorized=None):
        from runtime_revoke import _name
        from network_runtime import SERVER_POLICY_ID
        _require(isinstance(plan,dict) and plan.get('schema') == 1, 'bytevirt_revoke_plan_invalid')
        name = _name(plan.get('name'))
        if restore:
            _require(callable(authorized) and authorized(name) is True, 'explicit_restore_authorization_required')
        if self._enabled():
            # Credentials are removed/restored on all twelve DMIT frontends.
            # Legacy 2443 is rejected and independently closed to client access.
            return
        _require(plan.get('scope') != SERVER_POLICY_ID, 'shared_hk_policy_intent_missing')
        if restore:
            return self._legacy().restore(plan, authorized=authorized)
        return self._legacy().remove(plan)

    def remove(self, plan): self._change(plan)

    def restore(self, plan, *, authorized): self._change(plan, restore=True, authorized=authorized)

    @property
    def adapter(self): return self._legacy().adapter

    @staticmethod
    def _parse(raw): return ByteVirtRevokeAdapter._parse(raw)


def _verify_shared_policy(document, network_plan_path):
    plan = _network_plan(network_plan_path, document)
    from network_runtime import server_policy_enabled, validate_loaded_server_policy
    if not server_policy_enabled(plan):
        return False
    try:
        validate_loaded_server_policy(document, plan)
    except Exception:
        raise RevokeError('loaded_shared_hk_policy_invalid') from None
    return True


def expected_fronts(document=None, *, taiwan_transport=TAIWAN_TRANSPORT,
                    network_plan_path=NETWORK_PLAN_PATH, network_plan=None):
    """Persistent Taiwan intent cannot be hidden by a missing loaded inlet.

    Older two-inlet fixtures stay supported. A loaded Taiwan tag also opts in
    to validation, even before the marker is committed during a staged change.
    The shared hop file is only tested for existence, never read or modified.
    """
    plan = network_plan if network_plan is not None else _network_plan(network_plan_path, document)
    if plan is not None:
        try:
            from network_runtime import expected_fronts as network_fronts
            return network_fronts(plan)
        except Exception:
            raise RevokeError('network_front_inventory_invalid') from None
    expected = dict(BASE_FRONTS)
    declared = (isinstance(document, dict) and any(isinstance(item, dict) and
        item.get('tag') == 'dmit-taiwan' for item in document.get('inbounds', [])))
    if declared or (taiwan_transport is not None and Path(taiwan_transport).is_file()):
        expected.update(TAIWAN_FRONT)
    return expected


def loaded_fronts(document, *, taiwan_transport=TAIWAN_TRANSPORT,
                  network_plan_path=NETWORK_PLAN_PATH, network_plan=None):
    plan = network_plan if network_plan is not None else _network_plan(network_plan_path, document)
    if plan is not None:
        try:
            from network_runtime import validate_loaded_fronts
            return validate_loaded_fronts(document, plan)
        except Exception:
            raise RevokeError('network_loaded_front_inventory_invalid') from None
    expected = expected_fronts(document, taiwan_transport=taiwan_transport,
                               network_plan_path=network_plan_path)
    rows = [item for item in document.get('inbounds', []) if isinstance(item, dict)
            and item.get('tag') in expected]
    actual = {item['tag']: item for item in rows}
    _require(len(actual) == len(rows) and set(actual) == set(expected)
             and all(item.get('type') == 'anytls' for item in rows),
             'loaded_front_inbound_inventory_changed')
    for tag, port in expected.items():
        _require(actual[tag].get('listen_port') == port and isinstance(actual[tag].get('users'), list),
                 'loaded_front_endpoint_changed')
    return expected, actual


def _pid(unit, runner):
    result = runner(['systemctl', 'show', unit, '--property=MainPID', '--value'],
                    capture_output=True, timeout=10, check=False)
    value = result.stdout.decode('ascii', 'replace').strip()
    _require(result.returncode == 0 and value.isdigit(), 'runtime_pid_unavailable')
    return int(value)


def _active(unit, runner):
    result = runner(['systemctl', 'is-active', '--quiet', unit],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
    return result.returncode == 0


def restart_with_pid_proof(unit, *, runner=subprocess.run, reload_callback=None):
    before = _pid(unit, runner)
    if reload_callback is None:
        result = runner(['systemctl', 'restart', unit], stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, timeout=60, check=False)
        _require(result.returncode == 0, 'runtime_restart_failed')
    else:
        reload_callback()
    after = _pid(unit, runner)
    _require(after > 0 and after != before and _active(unit, runner), 'runtime_restart_pid_not_verified')
    return {'unit': unit, 'before_pid': before, 'after_pid': after, 'restart_verified': True}


def explicitly_empty_cohort(local, sui):
    document, _ = local.io._read(local.io.private)
    users = document.get('users')
    _require(isinstance(users, list) and all(isinstance(row, dict)
             and isinstance(row.get('name'), str) and row['name'] for row in users),
             'private_cohort_schema_invalid')
    names = [row['name'] for row in users]
    if not names:
        return True
    placeholders = ','.join('?' for _ in names)
    with closing(sqlite3.connect(sui.path.resolve().as_uri() + '?mode=ro', uri=True, timeout=10)) as db:
        db.execute('PRAGMA query_only=ON')
        # Be conservative if an enabled name/secret alias exists: let the
        # normal renderer validate it rather than stop another user's front.
        enabled = db.execute('SELECT 1 FROM clients WHERE enable=1 AND (name IN (' +
            placeholders + ') OR sub_secret IN (' + placeholders + ')) LIMIT 1', names + names).fetchone()
    return enabled is None


def runtime_reloader(local, sui, *, runner=subprocess.run):
    from topology_enrollment_runtime import systemd_reload
    reload_core = systemd_reload('dmit-direct-staging.service', runner=runner)
    def reload():
        if explicitly_empty_cohort(local, sui):
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
            result = runner(['systemctl', 'stop', 'dmit-direct-public.socket',
                'dmit-direct-public.service', 'dmit-direct-staging.service'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60, check=False)
            _require(result.returncode == 0 and _pid('dmit-direct-staging.service', runner) == 0
                     and not _active('dmit-direct-staging.service', runner)
                     and not _active('dmit-direct-public.socket', runner),
                     'empty_cohort_front_stop_not_verified')
            return {'unit': 'dmit-direct-staging.service', 'before_pid': before, 'after_pid': 0,
                    'runtime_mode': 'stopped_empty_cohort', 'stop_verified': True}
        return restart_with_pid_proof('dmit-direct-staging.service',
                                      runner=runner, reload_callback=reload_core)
    return reload


def create_coordinator(*, deny_guard, verify_denied=None, refresh_sui=None,
                       reload_dmit=None, close_sessions=None,
                       runtime_config='/run/dmit-direct-staging/config.json',
                       native_secret='/etc/REPLACE_AT_DEPLOY/native-secret',
                       taiwan_transport=TAIWAN_TRANSPORT,
                       network_plan_path=NETWORK_PLAN_PATH,
                       state_dir='/var/lib/user-access-control/runtime-revocations',
                       local=None, sui=None, bytevirt=None, runner=subprocess.run):
    """Factory for the root worker after it validates claimed client ID/name.

    `deny_guard` must include purge_issued/revoking/revoked/binding-mismatch.
    The worker must retry pending results and mark success only for complete.
    S-UI and DMIT restart fallback briefly reconnects other users, while their
    credentials and the shared Zoro backend remain unchanged.
    """
    _require(callable(deny_guard), 'durable_deny_callback_required')
    local = local or LocalCredentialAdapter()
    sui = sui or SuiDisableAdapter()
    bytevirt = bytevirt or PolicyAwareRevokeAdapter(network_plan_path=network_plan_path)
    if reload_dmit is None:
        reload_dmit = runtime_reloader(local, sui, runner=runner)
    if refresh_sui is None:
        refresh_sui = lambda _: restart_with_pid_proof('s-ui.service', runner=runner)

    def native_close(name):
        # This optional scoped sweep must never prevent the other credential
        # removals. Verified full runtime restarts provide the fallback closure.
        api = None
        try:
            from native_sessions import NativeSessionControl
            secret_file = native_secret if native_secret and Path(native_secret).is_file() else None
            api = NativeSessionControl.from_runtime(runtime_config, secret_file=secret_file)
            result = api.scoped(inbounds=frozenset(expected_fronts(
                taiwan_transport=taiwan_transport, network_plan_path=network_plan_path))).close(name)
            result['native_status'] = 'closed_exact_authenticated_user'
            return result
        except Exception as error:
            return {'native_status': 'unavailable', 'fallback': 'verified_runtime_restart',
                    'error_type': type(error).__name__}
        finally:
            if api is not None:
                api.shutdown()

    def production_verify(state):
        name = state['name']
        _require(sui.prepare(name)['row']['enable'] == 0, 'sui_user_not_disabled')
        _require(local.absent(name), 'local_credentials_not_absent')
        expected = expected_fronts(taiwan_transport=taiwan_transport, network_plan_path=network_plan_path)
        dmit_evidence = state.get('evidence', {}).get('dmit_reloaded') or {}
        stopped_empty = dmit_evidence.get('runtime_mode') == 'stopped_empty_cohort'
        if stopped_empty:
            _require(explicitly_empty_cohort(local, sui) and dmit_evidence.get('stop_verified') is True
                     and _pid('dmit-direct-staging.service', runner) == 0
                     and not _active('dmit-direct-staging.service', runner)
                     and not _active('dmit-direct-public.socket', runner),
                     'empty_cohort_front_stop_not_verified')
        else:
            document, _ = local.io._read(Path(runtime_config))
            expected, actual = loaded_fronts(document, taiwan_transport=taiwan_transport,
                                              network_plan_path=network_plan_path)
            for tag, port in expected.items():
                _require(not any(row.get('name') == name for row in actual[tag]['users']),
                         'loaded_front_still_contains_user')
        from network_runtime import server_policy_enabled
        shared = server_policy_enabled(_network_plan(network_plan_path))
        if shared:
            if not stopped_empty:
                _require(_verify_shared_policy(document, network_plan_path), 'loaded_shared_hk_policy_invalid')
        else:
            remote = bytevirt.adapter._transport(name)
            _, inbound = bytevirt._parse(remote.read_config())
            _require(not any(row['name'] == name for row in inbound['users']) and remote.active(),
                     'bytevirt_runtime_not_revoked')
        for step, unit in (('sui_refreshed', 's-ui.service'),
                           ('dmit_reloaded', 'dmit-direct-staging.service')):
            if step == 'dmit_reloaded' and stopped_empty:
                continue
            evidence = state.get('evidence', {}).get(step) or {}
            _require(evidence.get('restart_verified') is True
                     and evidence.get('unit') == unit
                     and evidence.get('after_pid') == _pid(unit, runner)
                     and _active(unit, runner), 'runtime_pid_proof_missing_or_changed')
        api = None
        try:
            from native_sessions import NativeSessionControl
            secret_file = native_secret if native_secret and Path(native_secret).is_file() else None
            api = NativeSessionControl.from_runtime(runtime_config, secret_file=secret_file)
            rows = api.snapshot()
        except Exception as error:
            state.setdefault('evidence', {})['session_verification'] = {
                'native_status': 'unavailable', 'fallback': 'verified_runtime_restart',
                'error_type': type(error).__name__}
        else:
            _require(not any(row.get('user') == name and row.get('inbound') in expected for row in rows),
                     'revoked_user_still_has_authenticated_session')
            state.setdefault('evidence', {})['session_verification'] = {
                'native_status': 'verified_absent', 'matched_sessions': 0}
        finally:
            if api is not None:
                api.shutdown()
        if verify_denied is not None:
            _require(verify_denied(state) is True, 'caller_runtime_denial_verification_failed')
        return True

    return RevocationCoordinator(local=local, sui=sui, bytevirt=bytevirt,
        deny_guard=deny_guard, reload_dmit=reload_dmit, refresh_sui=refresh_sui,
        close_sessions=close_sessions or native_close, verify_denied=production_verify,
        state_dir=state_dir)


def create_restoration_coordinator(*, restore_guard, probe=None, read_identity=None,
                                  verify_loaded=None, **options):
    """Construct the reverse operation while its public gate remains blocked.

    The guard must bind the claimed client ID, generation, and restore action.
    No lock-recursive normal admission is used. Successful return still needs
    the lifecycle queue's generation-fenced finish_job commit to grant access.
    """
    from new_enrollment import read_sui_identity
    from topology_enrollment_runtime import three_route_probe
    from runtime_restore import RestorationCoordinator
    _require(callable(restore_guard), 'restore_generation_guard_required')
    runtime_config = options.get('runtime_config', '/run/dmit-direct-staging/config.json')
    taiwan_transport = options.get('taiwan_transport', TAIWAN_TRANSPORT)
    network_plan_path = options.get('network_plan_path', NETWORK_PLAN_PATH)
    runner = options.get('runner', subprocess.run)
    revoke = create_coordinator(deny_guard=restore_guard, **options)
    local, sui, bytevirt = revoke.local, revoke.sui, revoke.bytevirt

    def production_loaded(state):
        name = state['name']
        expected_id = state['client_id']
        current = sui.prepare(name)
        _require(current['row']['id'] == expected_id and current['row']['enable'] == 1
                 and current['sui_password'] == state['sui']['sui_password'],
                 'restored_sui_binding_not_loaded')
        actual_local = local.prepare(name)
        expected_entries = {entry['kind']: entry['before'] for entry in state['local']['entries']}
        _require(actual_local['dmit_password'] == state['dmit_password']
                 and all(entry['before'] == expected_entries[entry['kind']]
                         for entry in actual_local['entries']),
                 'restored_local_credentials_not_committed')
        document, _ = local.io._read(Path(runtime_config))
        expected_inbounds, actual = loaded_fronts(document, taiwan_transport=taiwan_transport,
                                                  network_plan_path=network_plan_path)
        for tag, port in expected_inbounds.items():
            inbound = actual[tag]
            rows = inbound.get('users')
            _require(inbound.get('listen_port') == port and isinstance(rows, list),
                     'loaded_front_endpoint_changed')
            matching = [row for row in rows if isinstance(row, dict) and row.get('name') == name]
            _require(len(matching) == 1 and matching[0].get('password') == state['dmit_password'],
                     'restored_loaded_front_credential_missing')
        if not _verify_shared_policy(document, network_plan_path):
            remote = bytevirt.adapter._transport(name)
            _, inbound = bytevirt._parse(remote.read_config())
            matching = [row for row in inbound['users'] if row['name'] == name]
            _require(len(matching) == 1 and matching[0] == state['bytevirt']['previous'] and remote.active(),
                     'restored_bytevirt_runtime_missing')
        for step, unit in (('sui_refreshed', 's-ui.service'),
                           ('dmit_reloaded', 'dmit-direct-staging.service')):
            evidence = state.get('evidence', {}).get(step) or {}
            _require(evidence.get('restart_verified') is True and evidence.get('unit') == unit
                     and evidence.get('after_pid') == _pid(unit, runner) and _active(unit, runner),
                     'restored_runtime_pid_proof_missing_or_changed')
        _require(_active('dmit-direct-public.socket', runner), 'restored_public_socket_inactive')
        return True

    return RestorationCoordinator(local=local, sui=sui, bytevirt=bytevirt,
        restore_guard=restore_guard,
        read_identity=read_identity or (lambda name: read_sui_identity(name, sui.path)),
        refresh_sui=revoke.refresh_sui, reload_dmit=revoke.reload_dmit,
        close_sessions=revoke.close_sessions, probe=probe or three_route_probe,
        verify_loaded=verify_loaded or production_loaded, verify_revoked=revoke.verify_denied,
        state_dir=revoke.state_dir)
