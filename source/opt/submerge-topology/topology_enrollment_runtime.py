"""Production adapters for the narrow DMIT + ByteVirt enrollment coordinator.

Importing this module neither connects to hosts nor changes any files.
The route probe is mandatory and supplied by the caller; it must test the
candidate credentials directly, before that identity enters the ready cohort.
"""
from __future__ import annotations

import copy
from contextlib import closing
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from types import SimpleNamespace

from new_enrollment import (EnrollmentCoordinator, EnrollmentError, DB,
                            read_sui_identity, _unpack)

TAIWAN_TRANSPORT_PATH = Path('/etc/submerge-topology/taiwan-transport.json')
TAIWAN_PROBE_ROUTE = 'ByteVirt-TW'
NETWORK_PLAN_PATH = Path('/etc/submerge-topology/network-plan.json')
POLICY_TRACE_URL = 'https://cloudflare.com/cdn-cgi/trace'
LOADED_RUNTIME_PATH = Path('/run/dmit-direct-staging/config.json')


def _network_plan(path=None):
    """Optional durable plan; invalid intent never silently selects old routes."""
    path = Path(path) if path is not None else NETWORK_PLAN_PATH
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        raise EnrollmentError('network_plan_unavailable') from None
    try:
        from network_runtime import load_network_plan
        return load_network_plan(path)
    except Exception:
        raise EnrollmentError('network_plan_invalid') from None


def _taiwan_probe_enabled(path=None):
    """The durable transport file enables the fourth route; do not read secrets."""
    path = Path(path) if path is not None else TAIWAN_TRANSPORT_PATH
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        raise EnrollmentError('taiwan_probe_flag_unavailable') from None
    if not stat.S_ISREG(info.st_mode):
        raise EnrollmentError('taiwan_probe_flag_invalid')
    return True


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _encode(document):
    return (json.dumps(document, ensure_ascii=False, separators=(',', ':')) + '\n').encode()


def _pairs(items):
    output = {}
    for key, value in items:
        if key in output:
            raise EnrollmentError('bytevirt_duplicate_json_key')
        output[key] = value
    return output


def _config(raw):
    try:
        document = json.loads(raw, object_pairs_hook=_pairs)
    except Exception:
        raise EnrollmentError('bytevirt_config_invalid') from None
    if not isinstance(document, dict) or not isinstance(document.get('inbounds'), list):
        raise EnrollmentError('bytevirt_config_invalid')
    matches = [item for item in document['inbounds'] if isinstance(item, dict)
               and item.get('type') == 'anytls' and item.get('listen_port') == 2443]
    if len(matches) != 1:
        raise EnrollmentError('bytevirt_anytls_inbound_ambiguous')
    inbound = matches[0]
    users = inbound.get('users')
    if not isinstance(users, list):
        raise EnrollmentError('bytevirt_users_invalid')
    if any(not isinstance(row, dict) or not isinstance(row.get('name'), str) or
           not row['name'] or not isinstance(row.get('password'), str) or
           len(row['password']) < 10 for row in users):
        raise EnrollmentError('bytevirt_users_invalid')
    if len({row['name'] for row in users}) != len(users) or len({row['password'] for row in users}) != len(users):
        raise EnrollmentError('bytevirt_credentials_not_unique')
    return document, inbound


def _legacy_primitives(path=None):
    candidates = [Path(path)] if path is not None else [
        Path('/opt/subscription-user-enrollment/reconcile.py'),
        Path(__file__).resolve().parents[1] / 'subscription-user-enrollment' / 'reconcile.py']
    source = next((item for item in candidates if item.is_file()), None)
    if source is None:
        raise EnrollmentError('bytevirt_transport_not_installed')
    name = '_topology_enrollment_transport'
    spec = importlib.util.spec_from_file_location(name, source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class ByteVirtAdapter:
    """Merge only one AnyTLS row, with fresh remote file CAS on each change.

    ``transport_factory(transaction)`` may be injected for an audited transport
    or synthetic tests. No S-UI settings, grants, or outbound routes are changed.
    Plans contain credentials and must remain inside the root-only journal.
    """
    def __init__(self, transport_factory=None, *, primitives_path=None):
        if transport_factory is None:
            primitives = _legacy_primitives(primitives_path)
            service = primitives.Service('bytevirt', '61.15.36.199', 8586,
                '/root/.ssh/hk-submerge-transfer', None,
                '/etc/sing-box/config.json', 'sing-box.service', '/usr/bin/sing-box')
            transport_factory = lambda transaction: primitives.SSHTransport(service, transaction)
        self.transport_factory = transport_factory

    def _transport(self, name, raw=b'', candidate=b'', operation='read'):
        identity = _digest(name.encode())[:12]
        transaction = 'topology-bv-' + operation + '-' + identity
        if raw:
            transaction += '-' + _digest(raw)[:12] + '-' + _digest(candidate)[:12]
        return self.transport_factory(transaction)

    @staticmethod
    def _row(inbound, name):
        return next((row for row in inbound['users'] if row['name'] == name), None)

    @staticmethod
    def _check_plan(plan):
        if (not isinstance(plan, dict) or plan.get('schema') != 1 or
            plan.get('service') != 'bytevirt-anytls-2443' or
            not isinstance(plan.get('name'), str) or
            not re.fullmatch(r'[A-Za-z0-9_+.-]{1,64}', plan['name']) or
            plan['name'] in {'.', '..'} or not isinstance(plan.get('desired'), dict) or
            plan['desired'].get('name') != plan['name'] or
            not isinstance(plan['desired'].get('password'), str) or
            len(plan['desired']['password']) < 10 or
            (plan.get('previous') is not None and not isinstance(plan['previous'], dict))):
            raise EnrollmentError('bytevirt_plan_invalid')

    def prepare(self, identity):
        raw = self._transport(identity.name).read_config()
        _, inbound = _config(raw)
        previous = copy.deepcopy(self._row(inbound, identity.name))
        desired = copy.deepcopy(previous) if previous is not None else {'name': identity.name}
        desired['password'] = identity.sui_password
        if any(row['name'] != identity.name and row['password'] == identity.sui_password
               for row in inbound['users']):
            raise EnrollmentError('bytevirt_password_collision')
        plan = {'schema': 1, 'service': 'bytevirt-anytls-2443', 'name': identity.name,
                'previous': previous, 'desired': desired, 'baseline_sha256': _digest(raw)}
        self._check_plan(plan)
        return plan

    def _change(self, plan, rollback=False):
        self._check_plan(plan)
        name = plan['name']
        reader = self._transport(name)
        raw = reader.read_config()
        document, inbound = _config(raw)
        current = self._row(inbound, name)
        expected, target = ((plan['desired'], plan['previous']) if rollback else
                            (plan['previous'], plan['desired']))
        if current == target:
            # A prior process can have stopped after the atomic file replace.
            # Pending admission must still establish that the file is loaded.
            if not rollback:
                reader.restart_and_check()
            return
        if current != expected:
            raise EnrollmentError('bytevirt_target_user_changed')
        if target is not None and any(row['name'] != name and row['password'] == target['password']
                                      for row in inbound['users']):
            raise EnrollmentError('bytevirt_password_collision')
        if target is None:
            inbound['users'] = [row for row in inbound['users'] if row['name'] != name]
        elif current is None:
            inbound['users'].append(copy.deepcopy(target))
        else:
            inbound['users'][inbound['users'].index(current)] = copy.deepcopy(target)
        candidate = _encode(document)
        _config(candidate)
        writer = self._transport(name, raw, candidate, 'rollback' if rollback else 'apply')
        writer.install_if_hash(_digest(raw), candidate)
        verification = writer.read_config()
        _, verified = _config(verification)
        if self._row(verified, name) != target or not writer.active():
            raise EnrollmentError('bytevirt_install_verification_failed')

    def apply(self, plan):
        self._change(plan)

    def rollback(self, plan):
        self._change(plan, rollback=True)


class PolicyAwareByteVirtAdapter:
    """New decrypted HK authenticates only at DMIT; retain old journal recovery.

    No new per-user credential belongs on the private shared HK transport.
    Legacy prepared journals still dispatch to the original guarded adapter.
    """
    SERVICE = 'dmit-managed-hk-policy'

    def __init__(self, legacy_factory=None):
        self.legacy_factory = legacy_factory or ByteVirtAdapter
        self._legacy_instance = None

    def _legacy(self):
        if self._legacy_instance is None:
            self._legacy_instance = self.legacy_factory()
        return self._legacy_instance

    def prepare(self, identity):
        from network_runtime import server_policy_enabled, SERVER_POLICY_ID
        if not server_policy_enabled(_network_plan()):
            return self._legacy().prepare(identity)
        return {'schema':1, 'service':self.SERVICE, 'policy':SERVER_POLICY_ID,
                'name':identity.name, 'identity_fingerprint':identity.fingerprint}

    @staticmethod
    def _check(plan):
        from network_runtime import SERVER_POLICY_ID
        if (not isinstance(plan,dict) or set(plan) != {'schema','service','policy','name','identity_fingerprint'} or
            plan.get('schema') != 1 or plan.get('service') != PolicyAwareByteVirtAdapter.SERVICE or
            plan.get('policy') != SERVER_POLICY_ID or not isinstance(plan.get('name'),str) or
            not re.fullmatch(r'[A-Za-z0-9_+.-]{1,64}',plan['name']) or plan['name'] in {'.','..'} or
            not isinstance(plan.get('identity_fingerprint'),str) or
            not re.fullmatch(r'[0-9a-f]{64}',plan['identity_fingerprint'])):
            raise EnrollmentError('dmit_managed_hk_plan_invalid')

    def apply(self, plan):
        if isinstance(plan,dict) and plan.get('service') == self.SERVICE:
            self._check(plan)
            from network_runtime import server_policy_enabled
            if not server_policy_enabled(_network_plan()):
                raise EnrollmentError('dmit_managed_hk_policy_missing')
            return
        return self._legacy().apply(plan)

    def rollback(self, plan):
        if isinstance(plan,dict) and plan.get('service') == self.SERVICE:
            self._check(plan)
            return  # This plan never changed a remote HK account.
        return self._legacy().rollback(plan)


def systemd_reload(unit='dmit-direct-staging.service', *, runner=subprocess.run):
    """Return a secret-silent restart and active-state check callback."""
    if not re.fullmatch(r'[A-Za-z0-9_.@-]+\.service', unit):
        raise EnrollmentError('dmit_service_invalid')
    def reload():
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
        if unit == 'dmit-direct-staging.service':
            # Incoming connections during a core restart can leave socket
            # activation rate-limited. Recover the audited public relay only
            # after the loopback core has become healthy again.
            commands.extend([
                ['systemctl', 'reset-failed', 'dmit-direct-public.socket', 'dmit-direct-public.service'],
                ['systemctl', 'start', 'dmit-direct-public.socket'],
                ['systemctl', 'is-active', '--quiet', 'dmit-direct-public.socket']])
        with restart_lease:
            for argv in commands:
                try:
                    result = runner(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    timeout=45, check=False)
                except (OSError, subprocess.TimeoutExpired):
                    raise EnrollmentError('dmit_service_unavailable') from None
                if result.returncode != 0:
                    raise EnrollmentError('dmit_service_unavailable')
    return reload


def _available_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def candidate_probe_profile(identity, dmit_password, *, node_factory=None,
                            bytevirt_fingerprint=None, taiwan_transport_path=None,
                            network_plan_path=None, network_plan=None):
    """Minimal authenticated paths; deliberately independent of ready gating."""
    if node_factory is None:
        import public_five_group as public
        node_factory = public._anytls
    if bytevirt_fingerprint is None:
        from pc_only_stage import BYTEVIRT_CERT_FINGERPRINT
        bytevirt_fingerprint = BYTEVIRT_CERT_FINGERPRINT
    plan = network_plan if network_plan is not None else _network_plan(network_plan_path)
    if plan is not None:
        try:
            from network_runtime import candidate_probe_profile as network_probe_profile
            return network_probe_profile(identity, dmit_password, plan, node_factory=node_factory,
                                         bytevirt_fingerprint=bytevirt_fingerprint)
        except Exception:
            raise EnrollmentError('network_probe_profile_invalid') from None
    if not isinstance(dmit_password, str) or len(dmit_password) < 24:
        raise EnrollmentError('probe_dmit_credential_invalid')
    direct = node_factory('DMIT', 'dmit', '179.255.136.79', 31117, dmit_password)
    zoro = node_factory('zorocloud', 'dmit', '179.255.136.79', 29513, dmit_password)
    bytevirt = {'name': 'ByteVirt', 'type': 'anytls', 'server': '61.15.36.199',
                'port': 2443, 'password': identity.sui_password, 'tls': True,
                'skip-cert-verify': True, 'fingerprint': bytevirt_fingerprint,
                'dialer-proxy': 'DMIT', 'udp': False}
    nodes = [direct, bytevirt, zoro]
    if _taiwan_probe_enabled(taiwan_transport_path):
        taiwan = node_factory(TAIWAN_PROBE_ROUTE, 'dmit', '179.255.136.79', 29514, dmit_password)
        taiwan['udp'] = False
        nodes.append(taiwan)
    # GLOBAL is synthesized by Mihomo and can replace a user-defined group of
    # the same name. Use a private ordinary selector and one routing rule.
    return {'mode': 'rule', 'log-level': 'silent', 'allow-lan': False,
            'bind-address': '127.0.0.1', 'ipv6': False, 'dns': {'enable': False},
            'tun': {'enable': False}, 'profile': {'store-selected': False},
            'proxies': nodes,
            'proxy-groups': [{'name': 'TOPOLOGY_QA_ROUTE', 'type': 'select',
                              'proxies': [node['name'] for node in nodes]}],
            'rules': ['MATCH,TOPOLOGY_QA_ROUTE']}


def _loaded_physical_test_identity(plan, runtime_path=LOADED_RUNTIME_PATH):
    """Read the private, loaded test credential; never infer it from a user."""
    from network_runtime import front_routes
    users = plan['server_policy']['routing_revision']['test_users']
    if not isinstance(users, list) or len(users) != 1:
        raise EnrollmentError('physical_test_identity_invalid')
    try:
        fd = os.open(str(runtime_path), os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
                raise EnrollmentError('physical_test_runtime_permissions_invalid')
            raw = stream.read(2_000_001)
        if len(raw) > 2_000_000:
            raise EnrollmentError('physical_test_runtime_oversize')
        document = json.loads(raw)
    except (OSError, ValueError, UnicodeError, TypeError):
        raise EnrollmentError('physical_test_runtime_unavailable') from None
    inbounds = {item.get('tag'): item for item in document.get('inbounds', [])
                if isinstance(item, dict)}
    passwords = []
    for route in front_routes(plan):
        inbound = inbounds.get(route['tag'])
        if not isinstance(inbound, dict) or inbound.get('listen_port') != route['port']:
            raise EnrollmentError('physical_test_front_missing')
        matches = [item for item in inbound.get('users', []) if isinstance(item, dict)
                   and item.get('name') == users[0]]
        if len(matches) != 1 or not isinstance(matches[0].get('password'), str) or len(matches[0]['password']) < 24:
            raise EnrollmentError('physical_test_binding_missing')
        passwords.append(matches[0]['password'])
    if len(set(passwords)) != 1:
        raise EnrollmentError('physical_test_binding_disagrees')
    return SimpleNamespace(name=users[0], sui_password=''), passwords[0]


def _policy_curl_trace(port, timeout):
    """Use the same HTTPS, TLS and IP proof at a non-reserved trace hostname."""
    from verify_topology_live import require
    marker = '\n__CURL_META__:'
    command = ['curl', '--noproxy', '', '--proxy', 'http://127.0.0.1:' + str(port),
        '--silent', '--show-error', '--connect-timeout', '6', '--max-time', str(timeout),
        '--max-filesize', '65536', '--write-out',
        marker + '%{http_code}:%{size_download}:%{size_upload}:%{time_total}:%{ssl_verify_result}',
        POLICY_TRACE_URL]
    result = subprocess.run(command, capture_output=True, timeout=timeout + 3)
    require(result.returncode == 0, 'route_https_request_failed')
    text = result.stdout.decode('utf-8', 'replace')
    require(marker in text and len(text) <= 70000, 'trace_response_invalid')
    body, metadata = text.rsplit(marker, 1)
    fields = metadata.strip().split(':')
    require(len(fields) == 5 and fields[0] == '200' and fields[4] == '0',
            'trace_http_or_tls_failed')
    trace = dict(line.split('=', 1) for line in body.splitlines() if '=' in line)
    address = str(ipaddress.ip_address(trace.get('ip', '')))
    country = trace.get('loc')
    require(isinstance(country, str) and len(country) == 2, 'trace_country_missing')
    return {'ip': address, 'country': country, 'http_status': int(fields[0]),
            'probe_download_bytes': int(float(fields[1])),
            'probe_upload_bytes': int(float(fields[2])),
            'seconds': float(fields[3]), 'tls_verified': True}


def _route_probe_once(identity, dmit_password, *, core=None, timeout=15,
                      private_parent='/root', taiwan_transport_path=None,
                      network_plan_path=None, network_plan=None, probe_mode='physical'):
    """Verify all enabled routes in a private core, including optional dynamic TW.

    The public name remains compatible with existing admission/restore callers.
    Taiwan's residential IPv4 can change; verify a public IPv4 and TW country
    through the configured authenticated route rather than pinning today's IP.
    """
    import yaml
    from verify_topology_live import Controller, curl_trace
    core = core or '/var/lib/submerge-staging/mihomo-v1.19.32-stage'
    mixed, controller_port = _available_port(), _available_port()
    while mixed == controller_port:
        controller_port = _available_port()
    plan = network_plan if network_plan is not None else _network_plan(network_plan_path)
    policy_probe = False
    if plan is not None:
        from network_runtime import revised
        policy_probe = revised(plan)
    profile = candidate_probe_profile(identity, dmit_password,
                                      taiwan_transport_path=taiwan_transport_path,
                                      network_plan_path=network_plan_path, network_plan=plan)
    routes = [('DMIT', 'US', '179.255.136.79'),
              ('ByteVirt', 'HK', '61.15.36.199'), ('zorocloud', 'MY', '218.208.109.3')]
    if plan is not None:
        from network_runtime import probe_expectations
        routes = probe_expectations(plan,subid=identity.name)
    elif any(node.get('name') == TAIWAN_PROBE_ROUTE for node in profile.get('proxies', [])):
        routes.append((TAIWAN_PROBE_ROUTE, 'TW', None))
    expected_routes = {name for name, _, _ in routes}
    secret = secrets.token_urlsafe(32)
    profile.update({'mixed-port': mixed, 'external-controller': '127.0.0.1:' + str(controller_port),
                    'secret': secret, 'port': 0, 'socks-port': 0,
                    'redir-port': 0, 'tproxy-port': 0})
    process = None
    with tempfile.TemporaryDirectory(prefix='topology-admission-probe-', dir=private_parent) as temporary:
        folder = Path(temporary)
        folder.chmod(0o700)
        path = folder / 'config.yaml'
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            yaml.safe_dump(profile, stream, allow_unicode=True, sort_keys=False)
        try:
            checked = subprocess.run([core, '-t', '-d', temporary, '-f', str(path)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=False)
            if checked.returncode:
                raise EnrollmentError('candidate_probe_core_validation_failed')
            process = subprocess.Popen([core, '-d', temporary, '-f', str(path)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, start_new_session=True)
            controller = Controller(controller_port, secret)
            deadline = time.monotonic() + 12
            while True:
                if process.poll() is not None:
                    raise EnrollmentError('candidate_probe_core_exited')
                try:
                    controller.request('/version', timeout=.5)
                    group = controller.request('/proxies/TOPOLOGY_QA_ROUTE', timeout=.5)
                    if (isinstance(group, dict) and isinstance(group.get('all'), list) and
                            expected_routes.issubset(group['all'])):
                        break
                except (OSError, ValueError):
                    pass
                if time.monotonic() >= deadline:
                    raise EnrollmentError('candidate_probe_route_group_unavailable') from None
                time.sleep(.15)
            time.sleep(.2)
            for name, country, address in routes:
                try:
                    controller.request('/connections', method='DELETE')
                    controller.select('TOPOLOGY_QA_ROUTE', name)
                    trace = (_policy_curl_trace(mixed, timeout) if policy_probe
                             else curl_trace(mixed, timeout))
                except Exception as error:
                    # Only the known verifier's fixed labels may be retained.
                    from verify_topology_live import ProbeFailure
                    fixed = {'route_https_request_failed', 'trace_response_invalid',
                             'trace_http_or_tls_failed', 'trace_country_missing',
                             'isolated_selector_not_applied', 'controller_response_too_large'}
                    code = str(error) if isinstance(error, ProbeFailure) and str(error) in fixed else type(error).__name__
                    prefix = 'candidate_probe_' if probe_mode == 'physical' else 'candidate_ordinary_probe_'
                    raise EnrollmentError(prefix + name.lower() + '_' + code) from None
                if plan is not None:
                    try:
                        from network_runtime import validate_probe_trace
                        if probe_mode == 'physical':
                            validate_probe_trace(name, trace, plan, subid=identity.name)
                        else:
                            address = ipaddress.ip_address(trace['ip'])
                            if not (address.version == 4 and address.is_global and
                                    trace['tls_verified'] is True and trace['http_status'] == 200):
                                raise ValueError('ordinary_access_not_reachable')
                    except Exception:
                        raise EnrollmentError('candidate_' + probe_mode + '_network_probe_invalid') from None
                    continue
                valid_address = trace.get('ip') == address
                if name == TAIWAN_PROBE_ROUTE:
                    try:
                        observed = ipaddress.ip_address(trace.get('ip'))
                        valid_address = (observed.version == 4 and observed.is_global
                                         and not observed.is_multicast and not observed.is_reserved)
                    except (ValueError, TypeError):
                        valid_address = False
                if trace.get('country') != country or not valid_address or trace.get('tls_verified') is not True:
                    raise EnrollmentError('candidate_probe_' + name.lower() + '_egress_mismatch')
            return True
        finally:
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)


def three_route_probe(identity, dmit_password, *, core=None, timeout=15,
                      private_parent='/root', taiwan_transport_path=None,
                      network_plan_path=None):
    """Prove physical exits with the policy test identity and user access separately."""
    plan = _network_plan(network_plan_path)
    if plan is None:
        return _route_probe_once(identity, dmit_password, core=core, timeout=timeout,
                                 private_parent=private_parent,
                                 taiwan_transport_path=taiwan_transport_path,
                                 network_plan_path=network_plan_path)
    from network_runtime import revised
    if not revised(plan):
        return _route_probe_once(identity, dmit_password, core=core, timeout=timeout,
                                 private_parent=private_parent,
                                 taiwan_transport_path=taiwan_transport_path,
                                 network_plan_path=network_plan_path, network_plan=plan)
    physical_identity, physical_password = _loaded_physical_test_identity(plan)
    if _route_probe_once(physical_identity, physical_password, core=core, timeout=timeout,
                         private_parent=private_parent, network_plan=plan) is not True:
        raise EnrollmentError('physical_probe_failed')
    if _route_probe_once(identity, dmit_password, core=core, timeout=timeout,
                         private_parent=private_parent, network_plan=plan,
                         probe_mode='ordinary') is not True:
        raise EnrollmentError('ordinary_probe_failed')
    return True


def create_coordinator(*, probe=None, verify_published=None, bytevirt_adapter=None,
                       reload_dmit=None, dmit_unit='dmit-direct-staging.service', **paths):
    """Build an admission controller. ``probe`` must verify every enabled route.

    The authenticated HTTP identity gate should call ``coordinator.ensure(id)``
    only for eligible ordinary S-UI identities missing from the ready manifest,
    and then re-read its normal ready gate. Trial bootstrap stays explicit.
    """
    probe = three_route_probe if probe is None else probe
    if not callable(probe):
        raise EnrollmentError('three_route_probe_required')
    adapter = bytevirt_adapter if bytevirt_adapter is not None else PolicyAwareByteVirtAdapter()
    return EnrollmentCoordinator(prepare_bytevirt=adapter.prepare,
        apply_bytevirt=adapter.apply, rollback_bytevirt=adapter.rollback,
        reload_dmit=reload_dmit or systemd_reload(dmit_unit), probe=probe,
        verify_published=verify_published, **paths)


_coordinator = None
_coordinator_lock = threading.Lock()


def admit(subid):
    """On-demand ordinary admission. The caller must re-read its auth gate."""
    global _coordinator
    with _coordinator_lock:
        if _coordinator is None:
            _coordinator = create_coordinator()
    return _coordinator.ensure(subid)


def bootstrap_trial(*, coordinator=None, db_path=DB):
    """Explicit one-off test[2,3,4] bootstrap; never enters ordinary ready map.

    Journal contains protected private/maps baselines and the ByteVirt per-row
    plan. All mutation runs under the same global coordinator lock. No other
    unusual grant is admitted through this exception.
    """
    coordinator = coordinator or create_coordinator()
    identity = read_sui_identity('test', db_path, allow_trial=True)
    with coordinator._lock():
        journal = coordinator.state_dir / 'explicit-trial-test' / 'journal.json'
        if journal.exists():
            state, _ = coordinator._read(journal)
            if state.get('identity_fingerprint') != identity.fingerprint:
                raise EnrollmentError('trial_identity_changed_since_prepare')
            if state.get('phase') == 'trial_ready':
                password, adopted = coordinator._credentials(identity)
                if not adopted:
                    raise EnrollmentError('trial_ready_binding_missing')
                return {'status': 'trial_ready', 'newly_enrolled': False}
            if state.get('phase') == 'rolled_back':
                state = coordinator._prepare(identity, retained_password=state['dmit_password'])
        else:
            state = coordinator._prepare(identity)
        if 'backups' not in state:
            state['backups'] = {str(path): coordinator._read(path)[0]
                               for path in (coordinator.private,) + coordinator.maps}
        coordinator._save(journal, state)
        original_marker = state['backups'][str(coordinator.private)].get('topology_trial_test_enabled')
        phase = 'bytevirt_apply'
        try:
            coordinator.apply_bytevirt(_unpack(state['bytevirt_plan']))
            phase = 'install_private_and_maps'
            coordinator._install_private(identity, state)
            coordinator._install_maps(identity, state)
            private, raw = coordinator._private_users()
            private['topology_trial_test_enabled'] = True
            coordinator._write(coordinator.private, private, raw)
            phase = 'dmit_reload'
            coordinator.reload_dmit()
            phase = 'identity_recheck'
            if read_sui_identity('test', db_path, allow_trial=True).fingerprint != identity.fingerprint:
                raise EnrollmentError('trial_identity_changed_before_probe')
            phase = 'three_route_probe'
            if coordinator.probe(identity, state['dmit_password']) is not True:
                raise EnrollmentError('trial_three_route_probe_failed')
            state['phase'] = 'trial_ready'
            coordinator._save(journal, state)
            return {'status': 'trial_ready', 'newly_enrolled': True}
        except Exception as error:
            # Exception text may contain a callback's credential-bearing
            # payload. Preserve only our own stable code plus frame locations.
            state['failure_phase'] = phase
            state['failure_type'] = type(error).__name__
            state['failure_location'] = [Path(frame.filename).name + ':' + str(frame.lineno)
                for frame in traceback.extract_tb(error.__traceback__)[-4:]]
            code = str(error) if isinstance(error, EnrollmentError) else type(error).__name__
            if not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', code):
                code = type(error).__name__
            state['failure_code'] = code
            coordinator._save(journal, state)
            try:
                coordinator._rollback(identity, state)
                private, raw = coordinator._private_users()
                if original_marker is None:
                    private.pop('topology_trial_test_enabled', None)
                else:
                    private['topology_trial_test_enabled'] = original_marker
                coordinator._write(coordinator.private, private, raw)
                coordinator.reload_dmit()
                coordinator._save(journal, state)
            except Exception as rollback_error:
                state['phase'] = 'rollback_incomplete'
                state['rollback_failure_type'] = type(rollback_error).__name__
                coordinator._save(journal, state)
                raise EnrollmentError('trial_bootstrap_' + phase + '_failed_rollback_incomplete') from None
            raise EnrollmentError('trial_bootstrap_' + phase + '_' + code) from None


def pending(*, coordinator=None, db_path=DB):
    coordinator = coordinator or create_coordinator()
    try:
        with closing(sqlite3.connect(Path(db_path).resolve().as_uri() + '?mode=ro', uri=True)) as db:
            db.execute('PRAGMA query_only=ON')
            candidates = [row[0] for row in db.execute('SELECT sub_secret FROM clients WHERE enable=1')]
    except sqlite3.Error:
        raise EnrollmentError('pending_identity_query_failed') from None
    counts = {'ready': 0, 'added': 0, 'ineligible': 0, 'failed': 0}
    for name in dict.fromkeys(candidates):
        try:
            read_sui_identity(name, db_path)
        except (EnrollmentError, TypeError):
            counts['ineligible'] += 1
            continue
        try:
            result = coordinator.ensure(name)
            counts['added' if result['newly_enrolled'] else 'ready'] += 1
        except EnrollmentError:
            counts['failed'] += 1
    return counts


if __name__ == '__main__':
    import argparse
    import os
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('pending', 'admit', 'bootstrap-trial'))
    parser.add_argument('subid', nargs='?')
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise EnrollmentError('root_required')
        if args.action == 'pending':
            result = pending()
        elif args.action == 'bootstrap-trial':
            result = bootstrap_trial()
        else:
            if args.subid is None:
                raise EnrollmentError('subscription_identity_required')
            result = admit(args.subid)
        print(json.dumps(result, ensure_ascii=False))
        if result.get('failed', 0):
            raise SystemExit(1)
    except EnrollmentError as error:
        raise SystemExit('topology enrollment failed: ' + str(error)) from None
