#!/usr/bin/env python3
"""Prove cached credentials denied on all configured independently tested inlets.

Only a synthetic codex-revoke-* subject is accepted. A live unrelated control
credential must succeed immediately before AND after every denied attempt.
ByteVirt is checked directly, rather than hidden behind an already denied
DMIT dialer. This script changes no account/runtime/production configuration.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
import time

import yaml

HERE = Path(__file__).resolve().parent
for path in (HERE, HERE.parent / 'topology-20261105', HERE.parent / 'lazycat-hkt',
             Path('/opt/submerge-topology'), Path('/opt/submerge')):
    sys.path.insert(0, str(path))
from runtime_revoke import RevokeError, _require
from new_enrollment import Identity, read_sui_identity
from topology_enrollment_runtime import candidate_probe_profile
from verify_topology_live import Controller


def read_private(path):
    fd = os.open(str(path), os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        _require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077,
                 'verification_private_file_permissions_invalid')
        raw = stream.read(16 * 1024 * 1024 + 1)
    _require(len(raw) <= 16 * 1024 * 1024, 'verification_private_file_too_large')
    return json.loads(raw)


def unused():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def subject_credentials(journal):
    name = journal.get('name')
    _require(isinstance(name, str) and name.startswith('codex-revoke-'),
             'only_synthetic_revocation_subject_permitted')
    sui = journal.get('sui') or {}
    row = sui.get('row') or {}
    password = (journal.get('local') or {}).get('dmit_password')
    _require(row.get('name') == name and row.get('sub_secret') == name
             and type(row.get('id')) is int and isinstance(sui.get('sui_password'), str)
             and isinstance(password, str) and len(password) >= 24,
             'synthetic_revocation_backup_invalid')
    return Identity(row['id'], name, name, sui['sui_password']), password


def qa_profile(subject, subject_password, control, control_password, *,
               taiwan_transport=Path('/etc/submerge-topology/taiwan-transport.json'),
               network_plan_path=Path('/etc/submerge-topology/network-plan.json')):
    from topology_enrollment_runtime import _network_plan
    plan = _network_plan(network_plan_path)
    if plan is not None:
        subject_profile = candidate_probe_profile(subject, subject_password, network_plan=plan)
        control_profile = candidate_probe_profile(control, control_password, network_plan=plan)
        try:
            from network_runtime import independent_negative_pairs
            nodes, pairs = independent_negative_pairs(subject_profile, control_profile, plan)
        except Exception:
            raise RevokeError('network_revocation_probe_inventory_invalid') from None
        return {'mode': 'rule', 'log-level': 'silent', 'allow-lan': False,
                'bind-address': '127.0.0.1', 'ipv6': False,
                'dns': {'enable': False}, 'tun': {'enable': False},
                'profile': {'store-selected': False}, 'proxies': nodes,
                'proxy-groups': [{'name': 'REVOKE_QA', 'type': 'select',
                                  'proxies': [node['name'] for node in nodes]}],
                'rules': ['MATCH,REVOKE_QA']}, pairs
    subject_profile = candidate_probe_profile(subject, subject_password)
    control_profile = candidate_probe_profile(control, control_password)
    mandatory = ('DMIT', 'ByteVirt', 'zorocloud')
    subject_nodes = {node['name']: node for node in subject_profile['proxies']}
    control_nodes = {node['name']: node for node in control_profile['proxies']}
    _require(len(subject_nodes) == len(subject_profile['proxies']) and
             len(control_nodes) == len(control_profile['proxies']) and
             set(subject_nodes) == set(control_nodes) and set(mandatory).issubset(subject_nodes),
             'revocation_probe_route_inventory_mismatch')
    extra = [name for name in subject_nodes if name not in mandatory]
    _require(len(extra) <= 1 and all(subject_nodes[name].get('port') == 29514 and
             control_nodes[name].get('port') == 29514 and
             subject_nodes[name].get('server') == '179.255.136.79' and
             control_nodes[name].get('server') == '179.255.136.79' for name in extra),
             'revocation_probe_unexpected_route')
    _require(taiwan_transport is None or not Path(taiwan_transport).is_file() or bool(extra),
             'taiwan_revocation_probe_missing')
    nodes = []
    pairs = []
    for route in mandatory + tuple(extra):
        pair = []
        for kind, profile in (('control', control_profile), ('subject', subject_profile)):
            node = next(item.copy() for item in profile['proxies'] if item['name'] == route)
            node['name'] = kind + '-' + route
            # Otherwise denied DMIT credentials would mask a surviving ByteVirt
            # password. Each managed authentication inlet is tested independently.
            node.pop('dialer-proxy', None)
            nodes.append(node)
            pair.append(node['name'])
        pairs.append((route, pair[0], pair[1]))
    return {'mode': 'rule', 'log-level': 'silent', 'allow-lan': False,
            'bind-address': '127.0.0.1', 'ipv6': False,
            'dns': {'enable': False}, 'tun': {'enable': False},
            'profile': {'store-selected': False}, 'proxies': nodes,
            'proxy-groups': [{'name': 'REVOKE_QA', 'type': 'select',
                              'proxies': [node['name'] for node in nodes]}],
            'rules': ['MATCH,REVOKE_QA']}, pairs


def request_allowed(port, timeout=8):
    result = subprocess.run(['curl', '--noproxy', '', '--proxy', 'http://127.0.0.1:' + str(port),
        '--silent', '--show-error', '--connect-timeout', '3', '--max-time', str(timeout),
        '--max-filesize', '65536', '--output', os.devnull,
        '--write-out', '%{http_code}:%{ssl_verify_result}',
        'https://www.cloudflare.com/cdn-cgi/trace'], capture_output=True, timeout=timeout + 3)
    values = result.stdout.decode('ascii', 'replace').strip().split(':')
    code = int(values[0]) if values and values[0].isdigit() else 0
    tls = values[1] if len(values) == 2 else None
    # Any verified HTTPS HTTP response proves the proxy accepted credentials;
    # HTTP403/5xx must not be misreported as an authentication denial.
    return {'allowed': result.returncode == 0 and 100 <= code <= 599 and tls == '0',
            'curl_exit': result.returncode, 'http_status': code,
            'tls_verified': tls == '0'}


def verify(subject, subject_password, control, control_password, *,
           core='/var/lib/submerge-staging/mihomo-v1.19.32-stage', timeout=8,
           private_parent='/root'):
    _require(subject.name.startswith('codex-revoke-') and control.name != subject.name,
             'synthetic_subject_and_unrelated_control_required')
    profile, pairs = qa_profile(subject, subject_password, control, control_password)
    mixed, api = unused(), unused()
    while mixed == api:
        api = unused()
    secret = secrets.token_urlsafe(32)
    profile.update({'mixed-port': mixed, 'external-controller': '127.0.0.1:' + str(api),
                    'secret': secret, 'port': 0, 'socks-port': 0,
                    'redir-port': 0, 'tproxy-port': 0})
    process = None
    report = {'status': 'fail', 'subject': subject.name, 'routes': [],
              'production_modified': False,
              'independent_bytevirt_auth_test': not any(name.startswith('Mobile-') for name, _, _ in pairs),
              'independent_managed_front_auth_test': True, 'managed_front_auth_count': len(pairs)}
    with tempfile.TemporaryDirectory(prefix='user-revoke-qa-', dir=private_parent) as directory:
        folder = Path(directory)
        folder.chmod(0o700)
        config = folder / 'config.yaml'
        config.write_text(yaml.safe_dump(profile, allow_unicode=True, sort_keys=False), encoding='utf-8')
        config.chmod(0o600)
        with (folder / 'core.log').open('wb') as log:
            try:
                checked = subprocess.run([core, '-t', '-d', directory, '-f', str(config)],
                    stdout=log, stderr=log, timeout=15)
                _require(checked.returncode == 0, 'revocation_qa_syntax_failed')
                process = subprocess.Popen([core, '-d', directory, '-f', str(config)],
                    stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
                controller = Controller(api, secret)
                deadline = time.monotonic() + 12
                while True:
                    _require(process.poll() is None, 'revocation_qa_core_exited')
                    try:
                        controller.request('/version', timeout=.5)
                        break
                    except Exception:
                        _require(time.monotonic() < deadline, 'revocation_qa_controller_unavailable')
                        time.sleep(.15)
                for route, control_node, subject_node in pairs:
                    result = {'route': route}
                    for key, selected in (('control_before', control_node),
                                          ('subject', subject_node), ('control_after', control_node)):
                        # This is our isolated QA core only.
                        controller.request('/connections', method='DELETE')
                        controller.select('REVOKE_QA', selected)
                        result[key] = request_allowed(mixed, timeout)
                    result['denied_with_healthy_control'] = (
                        result['control_before']['allowed'] and not result['subject']['allowed']
                        and result['control_after']['allowed'])
                    report['routes'].append(result)
                _require(all(row['denied_with_healthy_control'] for row in report['routes']),
                         'cached_credentials_not_denied_or_control_unhealthy')
                report['status'] = 'pass'
            except Exception as error:
                report['error'] = str(error) if isinstance(error, RevokeError) else type(error).__name__
            finally:
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
                report['isolated_core_stopped'] = process is None or process.poll() is not None
    report['private_profile_removed'] = True
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--journal', required=True)
    parser.add_argument('--control', default='wrt')
    parser.add_argument('--core', default='/var/lib/submerge-staging/mihomo-v1.19.32-stage')
    parser.add_argument('--timeout', type=int, default=8)
    args = parser.parse_args()
    _require(os.geteuid() == 0, 'root_required')
    subject, password = subject_credentials(read_private(args.journal))
    control = read_sui_identity(args.control)
    ready = read_private('/var/lib/submerge-public/ready-users.json')
    mapping = read_private('/var/lib/submerge-public/dmit-users.json')
    _require(ready.get('users', {}).get(args.control) == args.control,
             'unrelated_control_not_ready')
    control_password = mapping.get(args.control)
    _require(isinstance(control_password, str) and len(control_password) >= 24,
             'unrelated_control_credential_missing')
    report = verify(subject, password, control, control_password, core=args.core, timeout=args.timeout)
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report['status'] == 'pass' else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except RevokeError as error:
        print(json.dumps({'status': 'fail', 'error': str(error), 'credentials': 'hidden'}))
        raise SystemExit(1)
