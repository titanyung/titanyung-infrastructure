#!/usr/bin/env python3
"""One-shot, root-only edge release transaction. Importing never changes services.

The controller sends an authenticated SSH stream plus its expected manifest hash.
Only the independent lazycat-edge service is restarted; DMIT is never contacted.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import time
import urllib.request
import uuid

try:
    import fcntl
except ImportError:
    fcntl = None

MAX_TOTAL = 128 * 1024 * 1024
MAX_BINARY = 100 * 1024 * 1024
MAX_FILE = 8 * 1024 * 1024
MAX_MANIFEST = 128 * 1024
MAX_FILES = 64
LOG_LIMIT = 64 * 1024
SCHEMA_KEYS = {'schema', 'edge_id', 'generation', 'install_root', 'config_path',
    'binary_path', 'binary_version', 'initial_clash_mode', 'cohort_inbound_count',
    'accounts', 'files', 'total_bytes'}
OPTIONAL_KEYS = {'requires_local_endpoints', 'reviewed_outbound_overrides','routing_revision','routing_execution_front'}
HEX = re.compile(r'^[a-f0-9]{64}$')
EDGE_ID = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$')
FRONT_TAGS = {
    2: {'dmit-starhub', 'dmit-singtel'},
    4: {'dmit-starhub', 'dmit-singtel', 'dmit-starhub-lazycat', 'dmit-starhub-uzuma'},
    14: {'dmit-direct-stage', 'dmit-hk', 'dmit-taiwan', 'dmit-starhub', 'dmit-hkt',
         'dmit-singtel', 'mobile-dmit-direct', 'mobile-dmit-hk', 'mobile-dmit-taiwan',
         'mobile-dmit-starhub', 'mobile-dmit-hkt', 'mobile-dmit-singtel',
         'dmit-zoro-sg', 'mobile-dmit-zoro-sg'},
}


class ApplyError(RuntimeError):
    """Codes are safe for the remote controller and contain no raw diagnostics."""


class _InstalledReference:
    def __init__(self, path):
        self.path = Path(path)


def need(condition, code):
    if not condition:
        raise ApplyError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate_json_key')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ApplyError('invalid_json_number')))
    except (ValueError, UnicodeError):
        raise ApplyError('invalid_json') from None


def safe_relative(name):
    need(isinstance(name, str) and 0 < len(name) <= 240 and
         not any(c in name for c in ('\\', '\x00', ':')),
         'invalid_bundle_path')
    path = PurePosixPath(name)
    need(not path.is_absolute() and name == path.as_posix() and
         all(part not in ('', '.', '..') for part in name.split('/')),
         'invalid_bundle_path')
    need(name in ('bin/sing-box', 'config/runtime.json') or
         name.startswith(('assets/', 'tls/')), 'unexpected_bundle_path')
    return name


def private_root(root, require_root_owner):
    root = Path(root).absolute()
    for item in (root, *root.parents):
        need(not item.is_symlink(), 'symlink_install_root')
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = root.stat()
    need(stat.S_ISDIR(info.st_mode), 'install_root_not_directory')
    if os.name != 'nt':
        need(not info.st_mode & 0o077, 'install_root_not_private')
        if require_root_owner:
            need(os.geteuid() == 0 and info.st_uid == 0, 'root_owner_required')
    elif require_root_owner:
        raise ApplyError('linux_root_required')
    return root


def read_private(path, limit, require_root_owner=True):
    path = Path(path)
    need(not path.is_symlink(), 'symlink_private_file')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(str(path), flags)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_size <= limit, 'invalid_private_file')
        if os.name != 'nt':
            need(not info.st_mode & 0o077, 'private_file_permissions')
            if require_root_owner:
                need(info.st_uid == 0 and os.geteuid() == 0, 'root_owner_required')
        return stream.read(limit + 1)


def atomic(path, raw, mode=0o600):
    path = Path(path)
    need(not path.is_symlink(), 'symlink_atomic_target')
    temporary = path.with_name('.' + path.name + '-' + uuid.uuid4().hex)
    fd = os.open(str(temporary), os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
            if os.name != 'nt':
                os.fchmod(stream.fileno(), mode)
        os.replace(str(temporary), str(path))
        sync_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


def sync_directory(path):
    if os.name != 'nt':
        fd = os.open(str(path), os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def validate_manifest(manifest, expected_hash, root, edge_id):
    need(isinstance(manifest, dict) and SCHEMA_KEYS.issubset(manifest) and
         set(manifest).issubset(SCHEMA_KEYS | OPTIONAL_KEYS), 'manifest_fields')
    need(isinstance(expected_hash, str) and bool(HEX.fullmatch(expected_hash)) and
         digest(canonical(manifest)) == expected_hash, 'manifest_sha256_mismatch')
    need(manifest['schema'] == 1 and type(manifest['schema']) is int, 'manifest_schema')
    need(isinstance(edge_id, str) and bool(EDGE_ID.fullmatch(edge_id)) and
         manifest['edge_id'] == edge_id, 'edge_identity_mismatch')
    generation = manifest['generation']
    need(type(generation) is int and 0 < generation < 10 ** 20, 'invalid_generation')
    need(isinstance(manifest['install_root'], str) and
         Path(manifest['install_root']).absolute() == root, 'install_root_mismatch')
    need(manifest['config_path'] == 'config/runtime.json' and
         manifest['binary_path'] == 'bin/sing-box', 'fixed_entrypoint_required')
    need(manifest['binary_version'] == '1.14.3', 'unreviewed_binary_version')
    need(type(manifest['cohort_inbound_count']) is int and
         manifest['cohort_inbound_count'] in FRONT_TAGS, 'unreviewed_inbound_count')
    if 'routing_revision' in manifest:
        from routing_contract import validate
        validate(manifest['routing_revision'])
        need(manifest['cohort_inbound_count']==4 and manifest.get('routing_execution_front') in ('dmit','lazycat'),'revision_execution_scope')
    else:need('routing_execution_front' not in manifest,'execution_front_without_revision')
    mode = manifest['initial_clash_mode']
    need(isinstance(mode, str) and re.fullmatch(r'ai-z[01]s[01]l[01](?:p[uln])?', mode), 'invalid_initial_mode')
    accounts = manifest['accounts']
    need(isinstance(accounts, dict) and set(accounts) == {'usernames', 'cohort_sha256'}, 'account_manifest_fields')
    names = accounts['usernames']
    need(isinstance(names, list) and len(names) <= 1000 and
         all(isinstance(name, str) and 0 < len(name) <= 128 and
             not any(ord(c) < 32 for c in name) for name in names), 'invalid_account_names')
    need(names == sorted(set(names)) and isinstance(accounts['cohort_sha256'], str) and
         bool(HEX.fullmatch(accounts['cohort_sha256'])), 'invalid_account_cohort')
    records = manifest['files']
    need(isinstance(records, list) and 2 <= len(records) <= MAX_FILES, 'file_inventory_limit')
    inventory = {}
    for row in records:
        need(isinstance(row, dict) and set(row) == {'path', 'sha256', 'size', 'mode'}, 'file_record_fields')
        name = safe_relative(row['path'])
        need(name not in inventory and isinstance(row['sha256'], str) and
             bool(HEX.fullmatch(row['sha256'])), 'duplicate_or_invalid_file_hash')
        need(type(row['size']) is int and 0 < row['size'] <=
             (MAX_BINARY if name == 'bin/sing-box' else MAX_FILE), 'file_size_limit')
        wanted_modes = {0o700} if name == 'bin/sing-box' else ({0o600} if name == 'config/runtime.json' else {0o600, 0o644})
        need(type(row['mode']) is int and row['mode'] in wanted_modes, 'unsafe_bundle_mode')
        inventory[name] = row
    need(list(inventory) == sorted(inventory) and
         {'bin/sing-box', 'config/runtime.json'}.issubset(inventory), 'unordered_or_missing_files')
    total = sum(row['size'] for row in records)
    need(type(manifest['total_bytes']) is int and manifest['total_bytes'] == total and
         total <= MAX_TOTAL, 'total_size_limit')
    dependencies = manifest.get('requires_local_endpoints', [])
    need(isinstance(dependencies, list) and len(dependencies) <= 8, 'dependency_inventory')
    seen = set()
    for row in dependencies:
        need(isinstance(row, dict) and set(row) == {'tag', 'server', 'server_port'} and
             isinstance(row['tag'], str) and row['tag'] not in seen and
             row['server'] in ('127.0.0.1', '::1') and type(row['server_port']) is int and
             1024 <= row['server_port'] <= 65535, 'dependency_invalid')
        seen.add(row['tag'])
    overrides = manifest.get('reviewed_outbound_overrides', {})
    need(overrides in ({}, {'direct': {'original_type': 'direct', 'replacement_type': 'socks'}}),
         'unreviewed_outbound_override')
    return inventory


def loopback_endpoint(address):
    need(isinstance(address, str), 'management_api_not_loopback')
    try:
        if address.startswith('['):
            host, port = address[1:].split(']:', 1)
        else:
            host, port = address.rsplit(':', 1)
        need(ipaddress.ip_address(host).is_loopback and port.isdigit() and
             0 < int(port) < 65536, 'management_api_not_loopback')
        return host, int(port)
    except (ValueError, TypeError):
        raise ApplyError('management_api_not_loopback') from None


def legal_health_modes(document):
    result = set()
    def visit(value):
        if isinstance(value, dict):
            mode = value.get('clash_mode')
            if isinstance(mode, str) and re.fullmatch(r'ai-z[01]s[01]l[01](?:p[uln])?', mode):
                result.add(mode)
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)
    visit(document.get('route', {}).get('rules', []))
    return result


def verified_hot_mode(root, edge_id, manifest, expected_hash, document, require_root_owner=True):
    path = Path(root) / 'health-state.json'
    if not path.exists():
        return None
    value = strict_json(read_private(path, MAX_MANIFEST, require_root_owner))
    need(isinstance(value, dict) and value.get('schema') == 1, 'invalid_health_state')
    if (value.get('edge_id'), value.get('generation'), value.get('manifest_sha256')) != (
            edge_id, manifest['generation'], expected_hash):
        return None
    need(value.get('mode') in legal_health_modes(document), 'invalid_bound_health_mode')
    return value['mode']


def verify_process(pid, binary, config):
    need(type(pid) is int and pid > 0, 'invalid_running_pid')
    proc = Path('/proc') / str(pid)
    try:
        need((proc / 'exe').resolve() == Path(binary).resolve(), 'running_binary_not_candidate')
        raw = (proc / 'cmdline').read_bytes()
    except OSError:
        raise ApplyError('running_process_unavailable') from None
    need(0 < len(raw) <= 16384, 'process_command_limit')
    arguments = [value.decode('utf-8', 'surrogateescape') for value in raw.split(b'\0') if value]
    need('run' in arguments and not any(value in ('-C', '--config-directory') or
         value.startswith('--config-directory=') for value in arguments), 'unexpected_core_command')
    indexes = [index for index, value in enumerate(arguments) if value in ('-c', '--config')]
    need(len(indexes) == 1 and indexes[0] + 1 < len(arguments) and
         Path(arguments[indexes[0] + 1]).resolve() == Path(config).resolve(),
         'running_config_not_candidate')
    return {'pid': pid, 'binary_matches': True, 'config_matches': True}


def validate_config(document, manifest, revision):
    need(isinstance(document, dict) and not document.get('endpoints'), 'edge_config_object_required')
    names = manifest['accounts']['usernames']
    incoming = document.get('inbounds')
    count = manifest['cohort_inbound_count']
    need(isinstance(incoming, list) and len(incoming) == count, 'inbound_inventory')
    tags, ports, common = set(), set(), None
    for row in incoming:
        need(isinstance(row, dict) and row.get('type') == 'anytls' and
             isinstance(row.get('tag'), str) and row['tag'] not in tags,
             'authenticated_inbound_required')
        tags.add(row['tag'])
        need(type(row.get('listen_port')) is int and 0 < row['listen_port'] <= 65535 and
             row['listen_port'] not in ports, 'inbound_port_collision')
        ports.add(row['listen_port'])
        cohort = row.get('users')
        need(isinstance(cohort, list), 'inbound_users_required')
        normalized = []
        for item in cohort:
            need(isinstance(item, dict) and set(item) == {'name', 'password'} and
                 isinstance(item['name'], str) and isinstance(item['password'], str) and
                 24 <= len(item['password']) <= 4096, 'invalid_inbound_credential')
            normalized.append({'name': item['name'], 'password': item['password']})
        normalized.sort(key=lambda item: item['name'])
        need([item['name'] for item in normalized] == names and
             digest(canonical(normalized)) == manifest['accounts']['cohort_sha256'],
             'account_cohort_mismatch')
        need(common is None or common == normalized, 'inbound_cohort_disagreement')
        common = normalized
        need(row.get('tls', {}).get('enabled') is True and
             row['tls'].get('insecure', False) is False, 'inbound_tls_required')
    need(tags == FRONT_TAGS[count], 'unreviewed_inbound_tags')
    if count in (2, 4):
        try:
            from edge_ai_policy import validate_ai_runtime
        except ImportError:
            raise ApplyError('ai_policy_validator_unavailable') from None
        try:
            validate_ai_runtime(document,**({'routing_revision':manifest['routing_revision'],
                'execution_front':manifest['routing_execution_front']} if 'routing_revision' in manifest else {}))
        except Exception:
            raise ApplyError('ai_only_policy_rejected') from None
    experimental = document.get('experimental') or {}
    clash = experimental.get('clash_api') or {}
    loopback_endpoint(clash.get('external_controller'))
    need(isinstance(clash.get('secret'), str) and len(clash['secret']) >= 32,
         'private_api_auth_required')
    need(clash.get('default_mode') == manifest['initial_clash_mode'], 'startup_mode_must_be_embedded')
    need(manifest['initial_clash_mode'] in legal_health_modes(document), 'initial_mode_missing_from_rules')
    need(not any(clash.get(name) for name in ('external_controller_tls', 'external_controller_unix',
             'external_controller_pipe', 'external_ui_download_url')), 'extra_api_exposure')
    if experimental.get('v2ray_api', {}).get('listen'):
        loopback_endpoint(experimental['v2ray_api']['listen'])
    need(not experimental.get('cache_file', {}).get('enabled'), 'persistent_core_cache_not_allowed')
    for service in document.get('services', []):
        need(service.get('type') == 'api' and service.get('listen') in ('127.0.0.1', '::1') and
             type(service.get('listen_port')) is int and 0 < service['listen_port'] < 65536 and
             isinstance(service.get('secret'), str) and len(service['secret']) >= 32,
             'native_api_not_private')
    inventory = {row['path']: row for row in manifest['files']}
    def validate_path(value, secret=False):
        need(isinstance(value, str) and value.startswith(revision.as_posix() + '/'),
             'config_path_outside_generation')
        rel = value[len(revision.as_posix()) + 1:]
        need(rel in inventory, 'config_path_not_in_manifest')
        if secret:
            need(inventory[rel]['mode'] == 0o600, 'private_key_mode')
    def visit(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in ('certificate_path', 'key_path'):
                    validate_path(item, key == 'key_path')
                else:
                    visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)
    visit(document)
    for row in document.get('route', {}).get('rule_set', []):
        need(row.get('type') == 'local', 'unbundled_remote_rule_set')
        validate_path(row.get('path'))
    need(document.get('log', {}).get('output') in (None, ''),
         'unbounded_core_file_log')
    deps = {row['tag']: row for row in manifest.get('requires_local_endpoints', [])}
    seen_deps = set()
    for row in document.get('outbounds', []):
        if row.get('server') in ('127.0.0.1', '::1'):
            wanted = {key: row.get(key) for key in ('tag', 'server', 'server_port')}
            need(deps.get(row.get('tag')) == wanted, 'undeclared_local_dependency')
            seen_deps.add(row['tag'])
    need(seen_deps == set(deps), 'unused_local_dependency')
    direct = next((row for row in document.get('outbounds', []) if row.get('tag') == 'direct'), {})
    need(count != 14 or bool(direct), 'legacy_direct_outbound_missing')
    if direct and direct.get('type') != 'direct':
        need(direct.get('type') == 'socks' and 'direct' in deps and
             manifest.get('reviewed_outbound_overrides') ==
             {'direct': {'original_type': 'direct', 'replacement_type': 'socks'}}, 'unreviewed_direct_semantics')
    return document


class SystemdRunner:
    def __init__(self, unit='lazycat-edge.service'):
        need(unit == 'lazycat-edge.service', 'wrong_service_scope')
        self.unit = unit

    @staticmethod
    def command(args, timeout=25):
        # Diagnostics are deliberately not copied into ACK/logs: a parser could
        # quote a private configuration value. Neither shell nor command strings.
        try:
            result = subprocess.run(args, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            raise ApplyError('edge_command_timeout_or_unavailable') from None
        need(result.returncode == 0, 'edge_command_failed')

    def version(self, binary):
        try:
            result = subprocess.run([str(binary), 'version'], capture_output=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            raise ApplyError('core_version_unavailable') from None
        need(result.returncode == 0 and len(result.stdout) <= 16384, 'core_version_failed')
        first = result.stdout.decode('utf-8', 'replace').splitlines()[0]
        need(first == 'sing-box version 1.14.3', 'core_version_mismatch')
        return '1.14.3'

    def check(self, binary, config):
        self.command([str(binary), 'check', '-c', str(config)], timeout=30)

    def status(self):
        result = subprocess.run(['systemctl', 'show', self.unit,
            '--property=MainPID,ActiveState'], capture_output=True, text=True, timeout=10)
        need(result.returncode == 0, 'edge_status_unavailable')
        value = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        pid = value.get('MainPID', '0')
        need(pid.isdigit(), 'invalid_edge_pid')
        return {'active': value.get('ActiveState') == 'active', 'pid': int(pid)}

    def restart(self):
        self.command(['systemctl', 'restart', self.unit], timeout=40)

    def stop(self):
        self.command(['systemctl', 'stop', self.unit], timeout=30)

    def check_dependencies(self, manifest):
        checked = []
        for row in manifest.get('requires_local_endpoints', []):
            try:
                with socket.create_connection((row['server'], row['server_port']), timeout=1):
                    checked.append(row['tag'])
            except OSError:
                raise ApplyError('required_local_endpoint_unavailable') from None
        return checked

    @staticmethod
    def control(config, method='GET', payload=None):
        document = strict_json(Path(config).read_bytes())
        clash = document['experimental']['clash_api']
        host, port = loopback_endpoint(clash['external_controller'])
        address = '[' + host + ']' if ':' in host else host
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        request = urllib.request.Request('http://' + address + ':' + str(port) + '/configs',
            data=canonical(payload) if payload is not None else None, method=method,
            headers={'Authorization': 'Bearer ' + clash['secret'], 'Content-Type': 'application/json'})
        with opener.open(request, timeout=2) as response:
            raw = response.read(65537)
            need(len(raw) <= 65536, 'health_reply_limit')
            return strict_json(raw) if raw else {}

    def set_mode(self, config, mode):
        self.control(config, 'PATCH', {'mode': mode})
        value = self.control(config)
        need(value.get('mode') == mode, 'edge_mode_not_confirmed')
        return {'mode': mode}

    def health(self, config, initial_mode, previous_pid):
        document = strict_json(Path(config).read_bytes())
        clash = document['experimental']['clash_api']
        host, port = loopback_endpoint(clash['external_controller'])
        address = '[' + host + ']' if ':' in host else host
        url = 'http://' + address + ':' + str(port) + '/configs'
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        def query(method='GET', payload=None):
            body = canonical(payload) if payload is not None else None
            request = urllib.request.Request(url, data=body, method=method,
                headers={'Authorization': 'Bearer ' + clash['secret'], 'Content-Type': 'application/json'})
            with opener.open(request, timeout=2) as response:
                data = response.read(65537)
                need(len(data) <= 65536, 'health_reply_limit')
                return strict_json(data) if data else {}
        deadline = time.monotonic() + 15
        while True:
            try:
                before = query()
                break
            except (OSError, ValueError):
                if time.monotonic() >= deadline:
                    raise ApplyError('edge_health_unavailable') from None
                time.sleep(.15)
        # Startup must already embed the intended safe policy. PATCH is a
        # verification step, never an asynchronous repair of a wrong default.
        need(before.get('mode') == initial_mode, 'unsafe_initial_mode')
        query('PATCH', {'mode': initial_mode})
        after = query()
        status = self.status()
        need(status['active'] and status['pid'] > 0 and status['pid'] != previous_pid,
             'edge_new_process_not_confirmed')
        need(previous_pid <= 0 or not (Path('/proc') / str(previous_pid)).exists(),
             'old_edge_process_still_running')
        need(after.get('mode') == initial_mode, 'edge_mode_not_confirmed')
        verify_process(status['pid'], Path(config).parents[1] / 'bin/sing-box', config)
        return {'healthy': True, 'pid': status['pid'], 'initial_mode': before['mode'],
                'mode': after['mode'], 'previous_pid_exited': True}


class EdgeApply:
    def __init__(self, root, edge_id, runner, require_root_owner=True):
        self.root = private_root(root, require_root_owner)
        self.edge_id, self.runner, self.require_root_owner = edge_id, runner, require_root_owner
        self.generations = self.root / 'generations'
        need(not self.generations.is_symlink(), 'symlink_generations')
        self.generations.mkdir(mode=0o700, exist_ok=True)

    @contextlib.contextmanager
    def lock(self):
        path = self.root / 'apply.lock'
        need(not path.is_symlink(), 'symlink_lock')
        fd = os.open(str(path), os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        with os.fdopen(fd, 'a+b') as stream:
            if fcntl is not None:
                fcntl.flock(stream, fcntl.LOCK_EX)
            yield

    def state(self):
        path = self.root / 'state.json'
        if not path.exists():
            return {'schema': 1, 'edge_id': self.edge_id, 'highest_generation': 0,
                    'highest_manifest_sha256': None, 'current_generation': None,
                    'current_manifest_sha256': None, 'previous_generation': None,
                    'current_enforcement': None, 'pending_generation': None,
                    'pending_enforcement': None, 'prepared_generation': None}
        value = strict_json(read_private(path, MAX_MANIFEST, self.require_root_owner))
        need(value.get('schema') == 1 and value.get('edge_id') == self.edge_id,
             'state_identity_mismatch')
        need(type(value.get('highest_generation')) is int and value['highest_generation'] >= 0,
             'state_generation_invalid')
        return value

    def save(self, state):
        atomic(self.root / 'state.json', canonical(state))

    def log(self, event, generation, code=None):
        path = self.root / 'apply.log'
        need(not path.is_symlink(), 'symlink_log')
        row = {'time': int(time.time()), 'event': event, 'generation': generation}
        if code:
            row['code'] = code
        raw = canonical(row) + b'\n'
        if path.exists() and path.stat().st_size + len(raw) > LOG_LIMIT:
            old = self.root / 'apply.log.1'
            need(not old.is_symlink(), 'symlink_log_backup')
            os.replace(str(path), str(old))
        fd = os.open(str(path), os.O_CREAT | os.O_WRONLY | os.O_APPEND |
                     getattr(os, 'O_NOFOLLOW', 0), 0o600)
        with os.fdopen(fd, 'ab') as stream:
            stream.write(raw)

    def revision(self, generation):
        return self.generations / ('%020d' % generation)

    def point(self, name, generation):
        path = self.root / name
        if generation is None:
            if path.is_symlink():
                path.unlink()
            else:
                need(not path.exists(), 'unexpected_pointer_file')
            return
        need(not path.exists() or path.is_symlink(), 'unexpected_pointer_file')
        target = self.revision(generation)
        need(target.is_dir() and not target.is_symlink(), 'missing_generation')
        temporary = self.root / ('.' + name + '-' + uuid.uuid4().hex)
        os.symlink(str(Path('generations') / target.name), str(temporary), target_is_directory=True)
        if os.name == 'nt' and path.is_symlink():
            # Windows directory reparse points cannot be replaced by rename.
            # Only the explicitly non-production offline API permits Windows;
            # the real root CLI rejects it. Linux keeps the atomic rename.
            need(not self.require_root_owner, 'linux_root_required')
            path.unlink()
        os.replace(str(temporary), str(path))
        sync_directory(self.root)

    def prune(self, state):
        keep = {value for value in (state.get('current_generation'), state.get('previous_generation'),
                                   state.get('pending_generation'), state.get('prepared_generation')) if value is not None}
        for path in self.generations.iterdir():
            need(not path.is_symlink(), 'symlink_generation')
            if path.is_dir() and (path.name.startswith('.stage-') or
               (re.fullmatch(r'\d{20}', path.name) and int(path.name) not in keep)):
                shutil.rmtree(str(path))

    def dependencies(self, manifest):
        if not manifest.get('requires_local_endpoints'):
            return []
        need(hasattr(self.runner, 'check_dependencies'), 'dependency_checker_required')
        return self.runner.check_dependencies(manifest)

    def installed_reference(self, name, wanted):
        """No caller-supplied path: references only confirmed current/previous."""
        state = self.state()
        for generation, expected_hash in (
            (state.get('current_generation'), state.get('current_manifest_sha256')),
            (state.get('previous_generation'), None)):
            if generation is None:
                continue
            revision = self.revision(generation)
            need(not revision.is_symlink() and revision.is_dir(), 'reference_generation_invalid')
            manifest = strict_json(read_private(revision / 'manifest.json', MAX_MANIFEST,
                                               self.require_root_owner))
            if expected_hash is not None:
                need(digest(canonical(manifest)) == expected_hash, 'reference_manifest_changed')
            need(manifest.get('edge_id') == self.edge_id and manifest.get('generation') == generation,
                 'reference_identity_mismatch')
            row = next((row for row in manifest.get('files', []) if row.get('path') == name), None)
            if row != wanted:
                continue
            path = revision / safe_relative(name)
            for part in (path, *path.parents):
                if part == revision.parent:
                    break
                need(not part.is_symlink(), 'symlink_reference_path')
            info = path.stat()
            need(stat.S_ISREG(info.st_mode) and info.st_size == wanted['size'], 'reference_file_changed')
            if os.name != 'nt':
                need(stat.S_IMODE(info.st_mode) == wanted['mode'] and
                     (not self.require_root_owner or info.st_uid == 0), 'reference_permissions_changed')
            return _InstalledReference(path)
        raise ApplyError('delta_reference_not_installed')

    def confirmed_health(self, manifest, revision, previous_pid, allow_hot=False):
        wanted = manifest['initial_clash_mode']
        if allow_hot:
            document = strict_json((revision / manifest['config_path']).read_bytes())
            wanted = verified_hot_mode(self.root, self.edge_id, manifest,
                digest(canonical(manifest)), document, self.require_root_owner) or wanted
        health = self.runner.health(revision / manifest['config_path'],
                                    wanted, previous_pid)
        need(isinstance(health, dict) and health.get('healthy') is True and
             type(health.get('pid')) is int and health['pid'] > 0 and health['pid'] != previous_pid and
             health.get('previous_pid_exited') is True and
             health.get('initial_mode') == wanted and
             health.get('mode') == wanted, 'activation_not_verified')
        self.dependencies(manifest)
        return health

    def restore_hot_mode(self, manifest, revision):
        document = strict_json((revision / manifest['config_path']).read_bytes())
        mode = verified_hot_mode(self.root, self.edge_id, manifest, digest(canonical(manifest)),
                                 document, self.require_root_owner)
        if mode is not None and mode != manifest['initial_clash_mode']:
            need(hasattr(self.runner, 'set_mode'), 'hot_mode_restorer_required')
            result = self.runner.set_mode(revision / manifest['config_path'], mode)
            need(isinstance(result, dict) and result.get('mode') == mode, 'hot_mode_restore_failed')

    def acknowledge(self, state, manifest, expected_hash, health, idempotent=False):
        return {'schema': 1, 'status': 'applied', 'edge_id': self.edge_id,
            'generation': manifest['generation'], 'manifest_sha256': expected_hash,
            'cohort_sha256': manifest['accounts']['cohort_sha256'],
            'cohort_inbound_count': manifest['cohort_inbound_count'],
            'active_user_count': len(manifest['accounts']['usernames']),
            'enforcement': state['current_enforcement'],
            'health': {key: value for key, value in health.items() if key in
                {'healthy', 'pid', 'initial_mode', 'mode', 'previous_pid_exited', 'service_stopped'}},
            'idempotent': idempotent, 'acknowledged_at': int(time.time())}

    def recover(self, state):
        if state.get('pending_generation') is None:
            return
        if state.get('pending_enforcement') == 'service_stopped_no_accounts':
            # An intended all-account revocation must never resurrect an older
            # cohort on a retry after interruption.
            generation = state['pending_generation']
            revision = self.revision(generation)
            manifest = strict_json((revision / 'manifest.json').read_bytes())
            self.verify_revision(revision, manifest)
            need(not manifest['accounts']['usernames'], 'deny_all_recovery_mismatch')
            self.point('current', generation)
            self.runner.stop()
            status = self.runner.status()
            need(not status['active'] and status['pid'] == 0, 'deny_all_not_confirmed')
            previous = state.get('current_generation')
            self.point('previous', previous)
            state.update(current_generation=generation,
                current_manifest_sha256=state['highest_manifest_sha256'],
                previous_generation=previous, pending_generation=None, pending_enforcement=None,
                prepared_generation=None, current_enforcement='service_stopped_no_accounts')
            self.save(state)
            self.prune(state)
            self.log('recovered_deny_all', generation)
            return
        # A crashed, unacknowledged switch is not silently accepted on the next
        # call. Restore the last confirmed release before processing new input.
        self.point('current', state.get('current_generation'))
        if state.get('current_generation') is None or state.get('current_enforcement') == 'service_stopped_no_accounts':
            self.runner.stop()
        else:
            revision = self.revision(state['current_generation'])
            previous_manifest = strict_json((revision / 'manifest.json').read_bytes())
            old_pid = self.runner.status()['pid']
            self.runner.restart()
            self.confirmed_health(previous_manifest, revision, old_pid)
            self.restore_hot_mode(previous_manifest, revision)
        state['pending_generation'] = None
        state['pending_enforcement'] = None
        self.save(state)
        self.prune(state)
        self.log('recovered_unacknowledged_switch', state['highest_generation'])

    def apply(self, manifest, sources, expected_hash, prepare_only=False):
        inventory = validate_manifest(manifest, expected_hash, self.root, self.edge_id)
        generation = manifest['generation']
        with self.lock():
            state = self.state()
            need(not prepare_only or state.get('pending_generation') is None,
                 'pending_activation_requires_explicit_recovery')
            self.recover(state)
            need(generation >= state['highest_generation'], 'generation_rollback_rejected')
            if generation == state['highest_generation']:
                need(state['highest_manifest_sha256'] == expected_hash, 'same_generation_different_manifest')
                if state['current_generation'] == generation:
                    revision = self.revision(generation)
                    self.verify_revision(revision, manifest)
                    if prepare_only:
                        return {'schema': 1, 'status': 'prepared', 'edge_id': self.edge_id,
                                'generation': generation, 'manifest_sha256': expected_hash,
                                'acknowledged': False}
                    if not manifest['accounts']['usernames']:
                        self.runner.stop()
                        status = self.runner.status()
                        need(not status['active'] and status['pid'] == 0, 'deny_all_not_confirmed')
                        health = {'healthy': True, 'service_stopped': True, 'pid': 0}
                    else:
                        # Idempotent ACK still verifies the running policy. No
                        # earlier PID is supplied because no restart is needed.
                        health = self.confirmed_health(manifest, revision, 0, allow_hot=True)
                    return self.acknowledge(state, manifest, expected_hash, health, True)
            # The authenticated controller assigned this immutable generation.
            # Even a failed transfer/check cannot later reuse it for other data.
            state['highest_generation'] = generation
            state['highest_manifest_sha256'] = expected_hash
            self.save(state)
            revision = self.revision(generation)
            if revision.exists():
                need(not revision.is_symlink() and state['current_generation'] != generation and
                     state['previous_generation'] != generation, 'generation_directory_collision')
                shutil.rmtree(str(revision))
            stage = self.generations / ('.stage-' + uuid.uuid4().hex)
            stage.mkdir(mode=0o700)
            try:
                count = set()
                for name, stream in sources:
                    need(name in inventory and name not in count, 'unexpected_or_duplicate_archive_member')
                    count.add(name)
                    row = inventory[name]
                    target = stage / name
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    if isinstance(stream, _InstalledReference):
                        # Local, verified hardlinks deduplicate unchanged cores
                        # without accepting archive links or external paths.
                        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
                        fd = os.open(str(stream.path), flags)
                        with os.fdopen(fd, 'rb') as source:
                            info = os.fstat(source.fileno())
                            hasher, count_bytes = hashlib.sha256(), 0
                            for chunk in iter(lambda: source.read(65536), b''):
                                count_bytes += len(chunk)
                                need(count_bytes <= row['size'], 'reference_size_changed')
                                hasher.update(chunk)
                            need(count_bytes == row['size'] and hasher.hexdigest() == row['sha256'],
                                 'reference_sha256_changed')
                            try:
                                os.link(str(stream.path), str(target), follow_symlinks=False)
                            except (OSError, NotImplementedError):
                                source.seek(0)
                                with target.open('xb') as output:
                                    shutil.copyfileobj(source, output, 65536)
                                    output.flush(); os.fsync(output.fileno())
                                target.chmod(row['mode'])
                            else:
                                linked = target.stat()
                                need((linked.st_dev, linked.st_ino) == (info.st_dev, info.st_ino),
                                     'reference_changed_during_link')
                        continue
                    hasher, size = hashlib.sha256(), 0
                    fd = os.open(str(target), os.O_CREAT | os.O_EXCL | os.O_WRONLY, row['mode'])
                    with os.fdopen(fd, 'wb') as output:
                        while True:
                            chunk = stream.read(65536)
                            if not chunk:
                                break
                            size += len(chunk)
                            need(size <= row['size'], 'archive_member_size_mismatch')
                            hasher.update(chunk)
                            output.write(chunk)
                        output.flush()
                        os.fsync(output.fileno())
                        if os.name != 'nt':
                            os.fchmod(output.fileno(), row['mode'])
                    need(size == row['size'] and hasher.hexdigest() == row['sha256'], 'file_sha256_mismatch')
                need(count == set(inventory), 'missing_archive_files')
                atomic(stage / 'manifest.json', canonical(manifest))
                for directory in sorted((path for path in stage.rglob('*') if path.is_dir()),
                                        key=lambda path: len(path.parts), reverse=True):
                    sync_directory(directory)
                sync_directory(stage)
                os.replace(str(stage), str(revision))
                sync_directory(self.generations)
                self.verify_revision(revision, manifest)
                document = strict_json((revision / manifest['config_path']).read_bytes())
                validate_config(document, manifest, revision)
                need(self.runner.version(revision / manifest['binary_path']) == manifest['binary_version'], 'core_version_mismatch')
                self.runner.check(revision / manifest['binary_path'], revision / manifest['config_path'])
                if prepare_only:
                    # Prepared is deliberately not an enforcement ACK. No
                    # service action or local dependency probe occurs here.
                    state['prepared_generation'] = generation
                    self.save(state)
                    self.prune(state)
                    self.log('prepared_not_activated', generation)
                    return {'schema': 1, 'status': 'prepared', 'edge_id': self.edge_id,
                            'generation': generation, 'manifest_sha256': expected_hash,
                            'acknowledged': False}
                self.dependencies(manifest)
                old_pid = self.runner.status()['pid']
                previous = state['current_generation']
                rollback_state = dict(state)
                rollback_state['prepared_generation'] = None
                state['pending_generation'] = generation
                state['pending_enforcement'] = ('running_verified' if manifest['accounts']['usernames']
                                                else 'service_stopped_no_accounts')
                self.save(state)
                self.point('current', generation)
                try:
                    if not manifest['accounts']['usernames']:
                        self.runner.stop()
                        current_status = self.runner.status()
                        need(not current_status['active'] and current_status['pid'] == 0, 'deny_all_not_confirmed')
                        health = {'healthy': True, 'service_stopped': True, 'pid': 0}
                        enforcement = 'service_stopped_no_accounts'
                    else:
                        self.runner.restart()
                        health = self.confirmed_health(manifest, revision, old_pid)
                        enforcement = 'running_verified'
                    self.point('previous', previous)
                    state.update(current_generation=generation, current_manifest_sha256=expected_hash,
                        previous_generation=previous, pending_generation=None, pending_enforcement=None,
                        prepared_generation=None, current_enforcement=enforcement)
                    self.save(state)
                except Exception:
                    if not manifest['accounts']['usernames']:
                        # Preserve the deny-all intent/current pointer so a
                        # service auto-start cannot revive the previous users.
                        self.log('deny_all_pending_no_ack', generation, 'stop_not_confirmed')
                        raise ApplyError('deny_all_stop_not_confirmed') from None
                    self.point('current', previous)
                    if previous is None or state.get('current_enforcement') == 'service_stopped_no_accounts':
                        self.runner.stop()
                    else:
                        old_revision = self.revision(previous)
                        old_manifest = strict_json((old_revision / 'manifest.json').read_bytes())
                        failed_pid = self.runner.status()['pid']
                        self.runner.restart()
                        self.confirmed_health(old_manifest, old_revision, failed_pid)
                        self.restore_hot_mode(old_manifest, old_revision)
                    self.point('previous', rollback_state.get('previous_generation'))
                    state = rollback_state
                    state['pending_generation'] = state['pending_enforcement'] = None
                    self.save(state)
                    self.prune(state)
                    self.log('rolled_back_no_ack', generation, 'activation_failed')
                    raise ApplyError('activation_failed_rolled_back') from None
                self.prune(state)
                self.log('applied_verified', generation)
                return self.acknowledge(state, manifest, expected_hash, health)
            finally:
                if stage.exists():
                    shutil.rmtree(str(stage))
                self.prune(state)

    def verify_revision(self, revision, manifest):
        need(revision.is_dir() and not revision.is_symlink(), 'invalid_generation_directory')
        if os.name != 'nt':
            info = revision.stat()
            need(not info.st_mode & 0o077 and (not self.require_root_owner or info.st_uid == 0),
                 'generation_directory_not_private')
        expected = {row['path']: row for row in manifest['files']}
        actual = set()
        for path in revision.rglob('*'):
            need(not path.is_symlink(), 'symlink_generation_member')
            if path.is_file():
                rel = path.relative_to(revision).as_posix()
                if rel == 'manifest.json':
                    continue
                need(rel in expected, 'unexpected_generation_file')
                actual.add(rel)
                info = path.stat()
                need(info.st_size == expected[rel]['size'], 'generation_size_changed')
                if os.name != 'nt':
                    need(stat.S_IMODE(info.st_mode) == expected[rel]['mode'] and
                         (not self.require_root_owner or info.st_uid == 0), 'generation_permissions_changed')
                hasher = hashlib.sha256()
                with path.open('rb') as stream:
                    for chunk in iter(lambda: stream.read(65536), b''):
                        hasher.update(chunk)
                need(hasher.hexdigest() == expected[rel]['sha256'], 'generation_sha256_changed')
        need(actual == set(expected), 'generation_files_missing')
        need(strict_json(read_private(revision / 'manifest.json', MAX_MANIFEST,
             self.require_root_owner)) == manifest, 'generation_manifest_changed')


def apply_bundle(manifest, files, expected_manifest_sha256, *, root,
                 edge_id, runner, prepare_only=False, require_root_owner=True):
    """Offline-friendly API; injected runner must scope all actions to its edge.

    A controller/QA may supply {relative_path: bytes}; CLI production uses a
    streaming tar instead and never holds the ~81MB core in Python memory.
    """
    need(isinstance(files, dict), 'bundle_files_mapping_required')
    sources = ((name, io.BytesIO(raw)) for name, raw in sorted(files.items()))
    return EdgeApply(root, edge_id, runner, require_root_owner).apply(
        manifest, sources, expected_manifest_sha256, prepare_only)


def apply_tar_stream(stream, expected_manifest_sha256, *, root, edge_id,
                     runner, prepare_only=False, require_root_owner=True, delta=False):
    """Strict uncompressed tar, manifest first, regular files only, no links."""
    try:
        with tarfile.open(fileobj=stream, mode='r|') as archive:
            first = archive.next()
            need(first is not None and first.name == 'manifest.json' and first.isfile() and
                 0 < first.size <= MAX_MANIFEST and not first.pax_headers, 'manifest_first_required')
            manifest_raw = archive.extractfile(first).read(MAX_MANIFEST + 1)
            manifest = strict_json(manifest_raw)
            need(canonical(manifest) == manifest_raw, 'manifest_not_canonical')
            inventory = validate_manifest(manifest, expected_manifest_sha256, Path(root).absolute(), edge_id)
            manager = EdgeApply(root, edge_id, runner, require_root_owner)
            def sources():
                seen = set()
                while True:
                    item = archive.next()
                    if item is None:
                        break
                    need(item.isfile() and not item.pax_headers and item.name in inventory and
                         item.name not in seen, 'unexpected_or_duplicate_archive_member')
                    row = inventory[item.name]
                    need(item.size == row['size'] and stat.S_IMODE(item.mode) == row['mode'], 'archive_member_metadata')
                    seen.add(item.name)
                    yield item.name, archive.extractfile(item)
                if delta:
                    for name in sorted(set(inventory) - seen):
                        yield name, manager.installed_reference(name, inventory[name])
            return manager.apply(
                manifest, sources(), expected_manifest_sha256, prepare_only)
    except (tarfile.TarError, EOFError):
        raise ApplyError('invalid_uncompressed_tar') from None


def apply_delta_tar_stream(stream, expected_manifest_sha256, **kwargs):
    """Full manifest + changed files; missing bytes may only be installed refs."""
    need('delta' not in kwargs, 'delta_flag_not_allowed')
    return apply_tar_stream(stream, expected_manifest_sha256, delta=True, **kwargs)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--identity', default='/etc/lazycat-edge/identity.json')
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--bundle', default='-', help='root-private uncompressed tar; - is authenticated SSH stdin')
    parser.add_argument('--prepare-only', action='store_true')
    parser.add_argument('--delta', action='store_true', help='reuse exact current/previous assets for undeclared payloads')
    args = parser.parse_args(argv)
    try:
        identity = strict_json(read_private(args.identity, 16384))
        need(isinstance(identity, dict) and set(identity) == {'edge_id', 'install_root', 'unit'} and
             identity['unit'] == 'lazycat-edge.service', 'invalid_local_edge_identity')
        runner = SystemdRunner(identity['unit'])
        if args.bundle == '-':
            response = apply_tar_stream(sys.stdin.buffer, args.manifest_sha256,
                root=identity['install_root'], edge_id=identity['edge_id'], runner=runner,
                prepare_only=args.prepare_only, delta=args.delta)
        else:
            # Ownership/mode validation before opening; streaming preserves the
            # low-memory path rather than read_private() buffering the archive.
            path = Path(args.bundle)
            need(not path.is_symlink(), 'symlink_bundle')
            fd = os.open(str(path), os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                need(os.geteuid() == 0 and info.st_uid == 0 and not info.st_mode & 0o077 and
                     stat.S_ISREG(info.st_mode) and info.st_size <= MAX_TOTAL + 1024 * 1024,
                     'private_bundle_required')
                response = apply_tar_stream(stream, args.manifest_sha256,
                    root=identity['install_root'], edge_id=identity['edge_id'], runner=runner,
                    prepare_only=args.prepare_only, delta=args.delta)
        print(canonical(response).decode('utf-8'))
        return 0
    except Exception as error:
        code = str(error) if isinstance(error, ApplyError) else type(error).__name__.lower()
        if not re.fullmatch(r'[a-z0-9_]{1,96}', code):
            code = 'edge_apply_failed'
        print(json.dumps({'status': 'failed', 'code': code, 'acknowledged': False}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
