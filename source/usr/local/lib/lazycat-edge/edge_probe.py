#!/usr/bin/env python3
"""One-shot edge-local AI egress probe; stdlib only and no main-core mutation.

The controller invokes this over its pinned SSH channel. One temporary native
core copies the installed SG transports verbatim, and three loopback clients
probe them concurrently. ChatGPT and Claude determine AI health; Cloudflare
is diagnostic only because the provider may split ordinary and AI traffic.
Neither transport server IPs nor an SG country alone verify a residential exit.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time

try:
    import fcntl
except ImportError:
    fcntl = None

LABELS = ('zoro-sg', 'uzuma-singtel', 'lazycat-starhub')
ALL_LABELS = LABELS + ('uzuma-starhub',)
SITES = ('chatgpt.com', 'claude.ai', 'www.cloudflare.com')
AI_SITES = frozenset(SITES[:2])
MAX_BODY = 64 * 1024
MAX_CONFIG = 8 * 1024 * 1024
MAX_MANIFEST = 128 * 1024
FORBIDDEN_BINDS = frozenset(('179.255.136.79', '2605:52c0:2:6f85:be24:11ff:fea8:a90c'))
TAG = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}$')
SAFE_CODES = frozenset(('invalid_runtime', 'installation_unavailable', 'probe_busy',
    'core_failed', 'probe_timeout', 'invalid_expectations', 'unexpected_probe_error'))


class ProbeError(ValueError):
    pass


def need(condition, code):
    if not condition:
        raise ProbeError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode('utf-8')


def _digest_file(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(64 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def _regular(path, limit, *, private, require_root_owner):
    need(not path.is_symlink(), 'installation_unavailable')
    info = path.stat()
    need(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= limit, 'installation_unavailable')
    if os.name != 'nt':
        need(not info.st_mode & (0o077 if private else 0o022), 'installation_unavailable')
        if require_root_owner:
            need(os.geteuid() == 0 and info.st_uid == 0, 'installation_unavailable')
    elif require_root_owner:
        raise ProbeError('installation_unavailable')
    return info


def _read_json(path, limit, *, private=True, require_root_owner=True):
    _regular(path, limit, private=private, require_root_owner=require_root_owner)
    try:
        value = json.loads(path.read_bytes())
    except (ValueError, UnicodeError):
        raise ProbeError('installation_unavailable') from None
    need(isinstance(value, dict), 'installation_unavailable')
    return value


def load_installation(install_root, *, require_root_owner=True):
    """Read a complete, acknowledged generation; never follow an escaping link."""
    root = Path(install_root).absolute()
    for path in (root, *root.parents):
        need(not path.is_symlink(), 'installation_unavailable')
    need(root.is_dir(), 'installation_unavailable')
    if os.name != 'nt':
        info = root.stat()
        need(not info.st_mode & 0o077, 'installation_unavailable')
        if require_root_owner:
            need(os.geteuid() == 0 and info.st_uid == 0, 'installation_unavailable')
    state = _read_json(root / 'state.json', MAX_MANIFEST, require_root_owner=require_root_owner)
    generation = state.get('current_generation')
    need(type(generation) is int and generation > 0, 'installation_unavailable')
    revision = root / 'generations' / str(generation).zfill(20)
    need((root / 'current').is_symlink() and (root / 'current').resolve(strict=True) == revision.resolve(strict=True),
        'installation_unavailable')
    need(not (root / 'generations').is_symlink() and not revision.is_symlink(), 'installation_unavailable')
    for name in ('bin', 'config'):
        need(not (revision / name).is_symlink(), 'installation_unavailable')
    manifest = _read_json(revision / 'manifest.json', MAX_MANIFEST, require_root_owner=require_root_owner)
    need(manifest.get('schema') == 1 and manifest.get('generation') == generation
        and manifest.get('edge_id') == state.get('edge_id')
        and manifest.get('install_root') == str(root)
        and manifest.get('binary_path') == 'bin/sing-box'
        and manifest.get('config_path') == 'config/runtime.json'
        and manifest.get('binary_version') == '1.14.3', 'installation_unavailable')
    need(hashlib.sha256(canonical(manifest)).hexdigest() == state.get('current_manifest_sha256'),
        'installation_unavailable')
    inventory = {row['path']: row for row in manifest.get('files', [])}
    need('bin/sing-box' in inventory and 'config/runtime.json' in inventory, 'installation_unavailable')
    binary, config_path = revision / 'bin/sing-box', revision / 'config/runtime.json'
    binary_info = _regular(binary, 100 * 1024 * 1024, private=False, require_root_owner=require_root_owner)
    _regular(config_path, MAX_CONFIG, private=True, require_root_owner=require_root_owner)
    for relative, path in (('bin/sing-box', binary), ('config/runtime.json', config_path)):
        row = inventory[relative]
        need(path.stat().st_size == row.get('size') and _digest_file(path) == row.get('sha256'),
            'installation_unavailable')
    if os.name != 'nt':
        need(bool(binary_info.st_mode & 0o100), 'installation_unavailable')
    config = _read_json(config_path, MAX_CONFIG, require_root_owner=require_root_owner)
    after = _read_json(root / 'state.json', MAX_MANIFEST, require_root_owner=require_root_owner)
    need(after.get('current_generation') == generation
        and after.get('current_manifest_sha256') == state.get('current_manifest_sha256'),
        'installation_unavailable')
    return {'root': root, 'revision': revision, 'binary': binary, 'config': config,
        'edge_id': manifest['edge_id'], 'generation': generation}


def normalize_expectations(document):
    need(isinstance(document, dict) and set(document) <= set(ALL_LABELS), 'invalid_expectations')
    output = {}
    for label, row in document.items():
        need(isinstance(row, dict) and set(row) == {'ips', 'countries'}, 'invalid_expectations')
        ips, countries = row['ips'], row['countries']
        need(isinstance(ips, list) and 0 < len(ips) <= 64 and len(set(ips)) == len(ips), 'invalid_expectations')
        need(isinstance(countries, list) and 0 < len(countries) <= 8
            and all(isinstance(code, str) and re.fullmatch(r'[A-Z]{2}', code) for code in countries),
            'invalid_expectations')
        for value in ips:
            try:
                address = ipaddress.ip_address(value)
            except (ValueError, TypeError):
                raise ProbeError('invalid_expectations') from None
            need(str(address) == value and address.is_global, 'invalid_expectations')
        output[label] = {'ips': set(ips), 'countries': set(countries)}
    return output


def _walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def make_probe_config(runtime, ports, revision, *, authority_host=False):
    """Only duplicate selected transports; never copy main inbounds or APIs."""
    need(isinstance(runtime, dict) and isinstance(runtime.get('outbounds'), list), 'invalid_runtime')
    seen = set(); chosen = {}
    for row in runtime['outbounds']:
        need(isinstance(row, dict) and isinstance(row.get('tag'), str)
            and TAG.fullmatch(row['tag']) and row['tag'] not in seen, 'invalid_runtime')
        seen.add(row['tag'])
        if row['tag'] not in ALL_LABELS:
            continue
        need(row.get('type') in ('shadowsocks', 'anytls', 'socks') and not row.get('detour'), 'invalid_runtime')
        try:
            address = ipaddress.ip_address(row.get('server'))
        except (ValueError, TypeError):
            raise ProbeError('invalid_runtime') from None
        need(not address.is_unspecified and not address.is_multicast and not address.is_link_local,
            'invalid_runtime')
        need(type(row.get('server_port')) is int and 0 < row['server_port'] < 65536, 'invalid_runtime')
        for nested in _walk(row):
            for key, value in nested.items():
                if key in ('inet4_bind_address', 'inet6_bind_address'):
                    need(authority_host or value not in FORBIDDEN_BINDS, 'invalid_runtime')
                    try: ipaddress.ip_address(value)
                    except (ValueError, TypeError): raise ProbeError('invalid_runtime') from None
                if key.endswith('_path'):
                    need(isinstance(value, str), 'invalid_runtime')
                    path = Path(value)
                    try: path.resolve(strict=True).relative_to(revision.resolve(strict=True))
                    except (ValueError, OSError): raise ProbeError('invalid_runtime') from None
                    need(path.is_absolute() and not path.is_symlink() and path.is_file(), 'invalid_runtime')
        chosen[row['tag']] = copy.deepcopy(row)
    need(set(ports) == set(chosen), 'invalid_runtime')
    config = {'log': {'level': 'error'}, 'inbounds': [],
        'outbounds': [chosen[label] for label in ALL_LABELS if label in chosen], 'route': {'rules': []}}
    for label in ALL_LABELS:
        if label not in chosen:
            continue
        port = ports[label]
        need(type(port) is int and 0 < port < 65536, 'invalid_runtime')
        inbound = 'probe-' + label
        config['inbounds'].append({'type': 'mixed', 'tag': inbound, 'listen': '127.0.0.1', 'listen_port': port})
        config['route']['rules'].append({'inbound': [inbound], 'outbound': label})
    return config


def _allocate_ports(labels):
    sockets, ports = [], {}
    try:
        for label in labels:
            stream = socket.socket(); stream.bind(('127.0.0.1', 0)); sockets.append(stream)
            ports[label] = stream.getsockname()[1]
        return ports
    finally:
        for stream in sockets: stream.close()


class TemporaryCore:
    def __init__(self, binary, document, directory):
        self.binary, self.document, self.directory, self.process = binary, document, directory, None

    def start(self):
        path = self.directory / 'probe.json'
        descriptor = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, 'wb') as stream: stream.write(canonical(self.document))
        self.process = subprocess.Popen([str(self.binary), 'run', '-c', str(path)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=(os.name != 'nt'))
        deadline = time.monotonic() + 2
        for inbound in self.document['inbounds']:
            while True:
                need(self.process.poll() is None, 'core_failed')
                try:
                    with socket.create_connection(('127.0.0.1', inbound['listen_port']), timeout=.1): break
                except OSError:
                    need(time.monotonic() < deadline, 'core_failed'); time.sleep(.03)

    def close(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try: self.process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait(timeout=1)


def parse_trace(body):
    need(isinstance(body, bytes) and len(body) <= MAX_BODY, 'invalid_trace')
    try: text = body.decode('utf-8')
    except UnicodeError: raise ProbeError('invalid_trace') from None
    values = {}
    for line in text.splitlines():
        if '=' not in line: continue
        key, value = line.split('=', 1)
        if key not in ('ip', 'loc'): continue
        need(key not in values, 'invalid_trace')
        values[key] = value
    try: address = ipaddress.ip_address(values.get('ip'))
    except (ValueError, TypeError): raise ProbeError('invalid_trace') from None
    need(address.is_global and re.fullmatch(r'[A-Z]{2}', values.get('loc', '')), 'invalid_trace')
    return {'ip': str(address), 'loc': values['loc']}


def fetch_trace(port, site, remaining, body_path):
    result = {'site': site, 'status': 'request_failed', 'returncode': None,
        'http_status': None, 'ip': None, 'loc': None, 'time_seconds': None,
        'diagnostic_only': site not in AI_SITES}
    if remaining <= .05:
        result['status'] = 'budget_exhausted'; return result
    environment = {key: value for key, value in os.environ.items() if not key.upper().endswith('_PROXY')
        and key.upper() != 'ALL_PROXY'}
    command = ['curl', '-q', '-4', '--silent', '--noproxy', '', '--socks5-hostname',
        '127.0.0.1:' + str(port), '--connect-timeout', str(min(4, remaining)),
        '--max-time', str(remaining), '--max-filesize', str(MAX_BODY), '--output', str(body_path),
        '--write-out', '%{json}', 'https://' + site + '/cdn-cgi/trace']
    started = time.monotonic()
    try:
        fetched = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=environment, timeout=remaining + .4)
        result['returncode'] = fetched.returncode
        try: metrics = json.loads(fetched.stdout)
        except (ValueError, UnicodeError): metrics = {}
        result['http_status'] = metrics.get('http_code')
        if fetched.returncode != 0:
            return result
        if metrics.get('http_code') != 200:
            result['status'] = 'http_failed'; return result
        need(body_path.stat().st_size <= MAX_BODY, 'invalid_trace')
        result.update(parse_trace(body_path.read_bytes())); result['status'] = 'observed'
    except subprocess.TimeoutExpired:
        result['status'] = 'request_timeout'
    except Exception:
        result['status'] = 'invalid_trace'
    finally:
        result['time_seconds'] = round(time.monotonic() - started, 4)
    return result


def assess_path(label, checks, policy, elapsed):
    qualified = []
    for check in checks:
        if check['site'] not in AI_SITES:
            continue
        passed = (policy is not None and check.get('status') == 'observed'
            and check.get('returncode') == 0 and check.get('http_status') == 200
            and check.get('ip') in policy['ips'] and check.get('loc') in policy['countries'])
        qualified.append(passed)
    healthy = len(qualified) == 2 and all(qualified)
    status = 'verified' if healthy else ('unverified_policy' if policy is None else 'ai_unverified_or_failed')
    ai = [row for row in checks if row['site'] in AI_SITES]
    return {'label': label, 'healthy': healthy, 'status': status,
        'ip': next((row['ip'] for row in ai if row.get('ip')), None),
        'loc': next((row['loc'] for row in ai if row.get('loc')), None),
        'time_seconds': round(elapsed, 4), 'checks': checks}


def _failure(label, status):
    return {'label': label, 'healthy': False, 'status': status, 'ip': None,
        'loc': None, 'time_seconds': None, 'checks': []}


@contextlib.contextmanager
def _probe_lock(root):
    path = root / 'probe.lock'
    need(not path.is_symlink(), 'probe_busy')
    descriptor = os.open(str(path), os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        if fcntl is not None:
            try: fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: raise ProbeError('probe_busy') from None
        yield
    finally:
        os.close(descriptor)


def run_probe(install_root, *, expected_exits, timeout_seconds=12,
        temporary_root='/run', require_root_owner=True):
    """Return only safe observations. Healthy never follows from an exception."""
    labels=LABELS
    result = {'schema': 1, 'started_at': int(time.time()), 'status': 'failed',
        'paths': [_failure(label, 'not_measured') for label in LABELS],
        'main_core_or_network_changed': False, 'temporary_cleanup': True}
    core, temporary = None, None
    try:
        need(isinstance(timeout_seconds, (int, float)) and not isinstance(timeout_seconds, bool)
            and 0 < timeout_seconds <= 12, 'probe_timeout')
        policies = normalize_expectations(expected_exits)
        installed = load_installation(install_root, require_root_owner=require_root_owner)
        result.update(edge_id=installed['edge_id'], generation=installed['generation'])
        with _probe_lock(installed['root']):
            labels=ALL_LABELS if any(row.get('tag')=='uzuma-starhub' for row in installed['config'].get('outbounds',[])) else LABELS
            present = [label for label in labels if any(row.get('tag') == label
                for row in installed['config'].get('outbounds', []))]
            ports = _allocate_ports(present)
            document = make_probe_config(installed['config'], ports, installed['revision'],
                authority_host=installed['edge_id']=='dmit-ai-20261108')
            paths = {label: _failure(label, 'outbound_missing') for label in labels}
            if present:
                with tempfile.TemporaryDirectory(prefix='lazycat-edge-probe-', dir=str(temporary_root)) as name:
                    temporary = Path(name); core = TemporaryCore(installed['binary'], document, temporary)
                    try:
                        core.start(); deadline = time.monotonic() + timeout_seconds
                        def check(label):
                            started = time.monotonic(); checks = []
                            for site in SITES:
                                remaining = min(timeout_seconds, deadline - time.monotonic())
                                checks.append(fetch_trace(ports[label], site, remaining,
                                    temporary / (label + '-' + site + '.body')))
                            return assess_path(label, checks, policies.get(label), time.monotonic() - started)
                        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                            jobs = {label: pool.submit(check, label) for label in present}
                            for label, job in jobs.items():
                                try: paths[label] = job.result()
                                except Exception: paths[label] = _failure(label, 'unexpected_probe_error')
                    finally:
                        core.close()
            result.update(status='completed', paths=[paths[label] for label in labels])
    except Exception as error:
        code = str(error) if isinstance(error, ProbeError) and str(error) in SAFE_CODES else 'installation_unavailable'
        result.update(status=code, paths=[_failure(label, code) for label in labels])
    finally:
        if core is not None:
            try: core.close()
            except Exception: result['temporary_cleanup'] = False
        if temporary is not None and temporary.exists(): result['temporary_cleanup'] = False
        result['finished_at'] = int(time.time())
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', default='/var/lib/lazycat-edge')
    parser.add_argument('--expected-exits', required=True, type=Path,
        help='root-owned JSON with explicit per-tag ips and countries')
    parser.add_argument('--timeout', type=float, default=12)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        policies = _read_json(args.expected_exits, MAX_MANIFEST, private=False)
        value = run_probe(args.root, expected_exits=policies, timeout_seconds=args.timeout)
    except Exception:
        value = {'schema': 1, 'status': 'invalid_expectations',
            'paths': [_failure(label, 'invalid_expectations') for label in LABELS],
            'main_core_or_network_changed': False, 'temporary_cleanup': True}
    print(json.dumps(value, sort_keys=True, ensure_ascii=False))
    return 0 if value['status'] == 'completed' and value['temporary_cleanup'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
