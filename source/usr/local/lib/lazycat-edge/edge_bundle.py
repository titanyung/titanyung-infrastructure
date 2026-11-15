"""Pure, private export of an authoritative native runtime for a small edge.

There is deliberately no S-UI lookup, network call, filesystem read, or key
generation here.  Callers supply already verified binary/assets/TLS bytes.
The returned runtime, manifest and tar contain credentials: never commit them
to ordinary Git or print their contents to a deployment log.

``source_ipv4``/``source_ipv6`` mean *local bind addresses*, not the public IP
observed beyond a NAT.  Public egress admission must be checked separately.
Installing a bundle, checking monotonic generations, verifying SSH pins and
health, and atomically activating it are responsibilities of edge_apply.
"""
from __future__ import annotations

from dataclasses import dataclass
import copy
import hashlib
import io
import ipaddress
import json
from pathlib import PurePosixPath
import re
import tarfile
from typing import Any, Dict, Mapping, Optional

MAX_FILES = 64
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_BINARY_BYTES = 100 * 1024 * 1024
MAX_OTHER_BYTES = 8 * 1024 * 1024
BINARY_VERSION = '1.14.3'
CONFIG_PATH = 'config/runtime.json'
BINARY_PATH = 'bin/sing-box'
DMIT_BIND_ADDRESSES = frozenset(('179.255.136.79',
    '2605:52c0:2:6f85:be24:11ff:fea8:a90c'))
_TLS_PATH_KEYS = frozenset(('certificate_path', 'key_path',
    'client_certificate_path', 'client_key_path'))
_BIND_KEYS = frozenset(('inet4_bind_address', 'inet6_bind_address'))


class BundleError(ValueError):
    """Errors intentionally identify a field, never a password or file bytes."""


def _need(value, code):
    if not value:
        raise BundleError(code)


def canonical_json(value):
    """The wire contract shared with the independent edge applier."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode('utf-8')


def sha256_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class EdgeBundle:
    manifest: Dict[str, Any]
    files: Dict[str, bytes]
    manifest_sha256: str

    @property
    def manifest_bytes(self):
        return canonical_json(self.manifest)


def _path(value, *, absolute):
    _need(isinstance(value, str) and value and '\\' not in value
        and not any(ord(c) < 32 for c in value), 'invalid_path')
    path = PurePosixPath(value)
    _need(path.is_absolute() == absolute and '..' not in path.parts
        and str(path) == value and value != '/', 'noncanonical_path')
    return value


def generation_directory(install_root, generation):
    _path(install_root, absolute=True)
    _need(len(PurePosixPath(install_root).parts) >= 3, 'install_root_too_broad')
    _need(type(generation) is int and 0 < generation <= 2**63-1, 'invalid_generation')
    return install_root + '/generations/' + str(generation).zfill(20)


def _address(value, *, version=None, bind=False, authority_host=False):
    _need(isinstance(value, str) and '%' not in value, 'invalid_ip_address')
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise BundleError('literal_ip_required') from None
    _need(str(address) == value, 'noncanonical_ip_address')
    _need(version is None or address.version == version, 'wrong_ip_family')
    _need(not address.is_multicast and not address.is_unspecified
        and not address.is_link_local, 'unsafe_ip_address')
    if bind:
        _need(not address.is_loopback, 'loopback_is_not_egress_bind')
        _need(authority_host or value not in DMIT_BIND_ADDRESSES, 'dmit_bind_must_not_migrate')
    return address


def _cohort(inbounds):
    common = None
    for inbound in inbounds:
        _need(isinstance(inbound, dict) and inbound.get('type') == 'anytls',
            'authoritative_anytls_inbound_required')
        users = inbound.get('users')
        _need(isinstance(users, list), 'authoritative_users_required')
        rows, names = [], set()
        for user in users:
            _need(isinstance(user, dict) and set(user) == {'name', 'password'},
                'unreviewed_user_status_or_fields')
            name, password = user['name'], user['password']
            _need(isinstance(name, str) and name and len(name) <= 256
                and not any(ord(c) < 32 for c in name), 'invalid_account_name')
            _need(isinstance(password, str) and password, 'invalid_account_credential')
            _need(name not in names, 'duplicate_account_name')
            names.add(name); rows.append({'name': name, 'password': password})
        rows.sort(key=lambda row: row['name'])
        if common is None:
            common = rows
        _need(rows == common, 'authoritative_cohort_mismatch')
    # Empty cohorts are valid.  The applier must enforce deny-all by stopping
    # the edge service, rather than roll back to previously enabled accounts.
    common = [] if common is None else common
    return {'usernames': [row['name'] for row in common],
        'cohort_sha256': sha256_bytes(canonical_json(common))}


def _endpoint(value):
    _need(isinstance(value, Mapping) and set(value) == {'server', 'server_port'},
        'explicit_endpoint_required')
    _address(value['server'])
    _need(type(value['server_port']) is int and 0 < value['server_port'] < 65536,
        'invalid_endpoint_port')
    return {'server': value['server'], 'server_port': value['server_port']}


def _check_api_addresses(config):
    clash = config.get('experimental', {}).get('clash_api')
    _need(isinstance(clash, dict), 'private_clash_api_required')
    controller = clash.get('external_controller')
    _need(isinstance(controller, str), 'private_clash_controller_required')
    try:
        host, raw_port = controller.rsplit(':', 1)
        host = host[1:-1] if host.startswith('[') and host.endswith(']') else host
        address = ipaddress.ip_address(host)
        port = int(raw_port)
    except (ValueError, TypeError):
        raise BundleError('invalid_clash_controller') from None
    _need(address.is_loopback and 0 < port < 65536, 'nonlocal_clash_api_forbidden')
    _need(not clash.get('external_ui'), 'external_ui_requires_separate_review')
    services = config.get('services') or []
    _need(isinstance(services, list) and len(services) <= 8, 'invalid_native_services')
    for service in services:
        if 'listen' in service:
            try:
                local = ipaddress.ip_address(service['listen']).is_loopback
            except ValueError:
                local = False
            _need(local, 'nonlocal_native_api_forbidden')


def _all_dicts(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _all_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _all_dicts(child)


def build_bundle(runtime, *, edge_id, identity_generation, binary, assets,
        tls_files, endpoint_mapping, source_ipv4, source_ipv6, health_mode,
        install_root='/var/lib/lazycat-edge', inbound_listen='127.0.0.1',
        outbound_overrides=None, local_outbound_services=None,
        expected_inbound_count=14, binary_version=BINARY_VERSION,
        authority_host=False, inbound_port_mapping=None,routing_revision=None,execution_front=None):
    """Build one complete private generation; do not mutate the source runtime.

    ``assets`` and ``tls_files`` map source absolute paths to verified bytes.
    ``endpoint_mapping`` must explicitly cover every resulting server-bearing
    outbound, including declared local SSH forwards.  Only the ``direct`` tag
    can change type: an explicitly reviewed SOCKS loopback replacement retains
    the original DMIT-direct contract.  It is never an automatic fallback.

    A loopback outbound requires an exact ``local_outbound_services`` entry.
    This records a dependency, not proof that it is present: activation must
    verify it on the target.  Missing IPv6 bindings never inherit DMIT's IPv6.
    """
    _need(isinstance(runtime, dict), 'runtime_object_required')
    _need(isinstance(edge_id, str) and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}', edge_id),
        'invalid_edge_id')
    generation_dir = generation_directory(install_root, identity_generation)
    _need(binary_version == BINARY_VERSION, 'unreviewed_binary_version')
    _need(isinstance(binary, bytes) and 0 < len(binary) <= MAX_BINARY_BYTES,
        'invalid_binary_payload')
    _need(isinstance(assets, Mapping) and isinstance(tls_files, Mapping), 'explicit_source_bytes_required')
    _need(isinstance(endpoint_mapping, Mapping), 'explicit_endpoint_mapping_required')
    _need(isinstance(health_mode, str) and re.fullmatch(r'ai-z[01]s[01]l[01](?:p[uln])?', health_mode),
        'unknown_health_mode')
    _need(not authority_host or (edge_id == 'dmit-ai-20261108' and expected_inbound_count in (2,4)
        and source_ipv4 == '179.255.136.79'), 'authority_execution_scope_invalid')
    source4 = _address(source_ipv4, version=4, bind=True,authority_host=authority_host) if source_ipv4 is not None else None
    source6 = _address(source_ipv6, version=6, bind=True,authority_host=authority_host) if source_ipv6 is not None else None
    _need(source4 is not None, 'explicit_edge_ipv4_bind_required')
    listen = ipaddress.ip_address(inbound_listen)
    _need(not listen.is_multicast and not listen.is_link_local, 'unsafe_inbound_listen')
    _need(inbound_listen not in DMIT_BIND_ADDRESSES, 'dmit_listen_must_not_migrate')
    config = copy.deepcopy(runtime)
    inbounds = config.get('inbounds')
    _need(expected_inbound_count in (2,4,14), 'unreviewed_inbound_count')
    _need(isinstance(inbounds, list) and len(inbounds) == expected_inbound_count,
        'inbound_inventory_changed')
    _need(len({row.get('tag') for row in inbounds}) == len(inbounds), 'duplicate_inbound_tag')
    accounts = _cohort(inbounds)
    ports={} if inbound_port_mapping is None else dict(inbound_port_mapping)
    _need(not ports or (expected_inbound_count in (2,4) and set(ports)=={row['tag'] for row in inbounds}
        and all(type(value) is int and 1024<=value<=65535 for value in ports.values())
        and len(set(ports.values()))==expected_inbound_count), 'unreviewed_inbound_ports')
    for inbound in inbounds:
        inbound['listen'] = inbound_listen
        if ports:inbound['listen_port']=ports[inbound['tag']]
    modes = {row.get('clash_mode') for row in config.get('route', {}).get('rules', [])}
    _need(health_mode in modes, 'health_mode_missing_from_policy')
    _check_api_addresses(config)
    config['experimental']['clash_api']['default_mode'] = health_mode

    outbounds = config.get('outbounds')
    _need(isinstance(outbounds, list) and outbounds, 'outbound_inventory_required')
    _need(len({row.get('tag') for row in outbounds}) == len(outbounds), 'duplicate_outbound_tag')
    overrides = {} if outbound_overrides is None else dict(outbound_overrides)
    _need(set(overrides) <= {'direct'}, 'unreviewed_outbound_type_override')
    reviewed = {}
    for index, outbound in enumerate(outbounds):
        tag = outbound.get('tag')
        if tag in overrides:
            replacement = copy.deepcopy(overrides[tag])
            _need(outbound.get('type') == 'direct' and isinstance(replacement, dict)
                and replacement.get('tag', tag) == tag and replacement.get('type') == 'socks',
                'direct_override_must_be_explicit_socks')
            _need(set(replacement) <= {'tag', 'type', 'server', 'server_port', 'version',
                'username', 'password', 'connect_timeout'}, 'unreviewed_direct_override_fields')
            endpoint = _endpoint({key: replacement.get(key) for key in ('server', 'server_port')})
            _need(ipaddress.ip_address(endpoint['server']).is_loopback,
                'direct_override_requires_local_tunnel')
            replacement['tag'] = tag; outbounds[index] = replacement
            reviewed[tag] = {'original_type': 'direct', 'replacement_type': 'socks'}
    _need(set(overrides) == set(reviewed), 'override_target_missing')
    endpoint_tags = {row['tag'] for row in outbounds if 'server' in row}
    _need(set(endpoint_mapping) == endpoint_tags, 'endpoint_inventory_mismatch')
    local_declared = {} if local_outbound_services is None else dict(local_outbound_services)
    local_required = []
    for outbound in outbounds:
        tag = outbound['tag']
        _need(not outbound.get('bind_interface'), 'interface_binding_requires_review')
        for field in _BIND_KEYS:
            outbound.pop(field, None)
        if 'server' not in outbound:
            if outbound.get('type') == 'direct':
                outbound['inet4_bind_address'] = str(source4)
                if source6 is not None:
                    outbound['inet6_bind_address'] = str(source6)
            continue
        endpoint = _endpoint(endpoint_mapping[tag]); outbound.update(endpoint)
        address = ipaddress.ip_address(endpoint['server'])
        if tag in reviewed:
            _need(address.is_loopback, 'direct_tunnel_mapping_must_stay_local')
        if address.is_loopback:
            _need(tag in local_declared and _endpoint(local_declared[tag]) == endpoint,
                'undeclared_local_outbound_dependency')
            local_required.append(dict(endpoint, tag=tag))
        elif address.version == 4:
            outbound['inet4_bind_address'] = str(source4)
        else:
            _need(source6 is not None, 'explicit_edge_ipv6_bind_required')
            outbound['inet6_bind_address'] = str(source6)
    _need(set(local_declared) == {row['tag'] for row in local_required},
        'local_dependency_inventory_mismatch')

    files, file_modes = {}, {}
    def put(path, raw, mode):
        _path(path, absolute=False)
        limit = MAX_BINARY_BYTES if path == BINARY_PATH else MAX_OTHER_BYTES
        _need(isinstance(raw, bytes) and 0 < len(raw) <= limit, 'payload_size_or_type_invalid')
        _need(path not in files or files[path] == raw, 'payload_path_collision')
        files[path] = raw; file_modes[path] = mode
        return generation_dir + '/' + path
    put(BINARY_PATH, binary, 0o700)

    used_assets = set()
    rule_sets = config.get('route', {}).get('rule_set') or []
    _need(isinstance(rule_sets, list) and rule_sets, 'verified_local_rule_sets_required')
    for row in rule_sets:
        _need(isinstance(row, dict) and row.get('type') == 'local', 'remote_rule_assets_forbidden')
        source = _path(row.get('path'), absolute=True)
        _need(source in assets, 'verified_rule_asset_missing')
        raw = assets[source]
        _need(isinstance(raw, bytes), 'rule_asset_bytes_required')
        suffix = '.srs' if row.get('format', 'binary') == 'binary' else '.json'
        row['path'] = put('assets/' + sha256_bytes(raw) + suffix, raw, 0o644)
        used_assets.add(source)
    _need(set(assets) == used_assets, 'unexpected_rule_asset')
    used_tls = set()
    for row in _all_dicts(config):
        _need(not (isinstance(row.get('acme'), dict) and row['acme'].get('enabled')),
            'edge_acme_requires_separate_review')
        for key in _TLS_PATH_KEYS & set(row):
            source = _path(row[key], absolute=True)
            _need(source in tls_files, 'verified_tls_file_missing')
            raw = tls_files[source]
            _need(isinstance(raw, bytes), 'tls_bytes_required')
            private = 'key' in key
            suffix = '-key.pem' if private else '-cert.pem'
            row[key] = put('tls/' + sha256_bytes(raw) + suffix, raw, 0o600 if private else 0o644)
            used_tls.add(source)
    _need(set(tls_files) == used_tls, 'unexpected_tls_file')
    _need(bool(used_tls), 'explicit_static_tls_required')
    # The service owns bounded stderr logging.  Never reuse a DMIT log path.
    config.setdefault('log', {}).pop('output', None)
    cache = config.get('experimental', {}).get('cache_file')
    if isinstance(cache, dict) and 'path' in cache:
        cache['path'] = generation_dir + '/config/cache.db'
    for row in _all_dicts(config):
        for key in _BIND_KEYS & set(row):
            _need(authority_host or row[key] not in DMIT_BIND_ADDRESSES, 'dmit_bind_survived_export')
        _need(not row.get('bind_interface'), 'unreviewed_interface_survived_export')
    dns = config.get('dns') or {}
    _need(len(dns.get('servers') or []) >= 3 and len(dns.get('rules') or []) >= 7,
        'dns_failover_inventory_missing')
    put(CONFIG_PATH, canonical_json(config), 0o600)
    _need(len(files) <= MAX_FILES, 'too_many_bundle_files')
    total = sum(len(raw) for raw in files.values())
    _need(total <= MAX_TOTAL_BYTES, 'bundle_total_size_exceeded')
    manifest = {'schema': 1, 'edge_id': edge_id, 'generation': identity_generation,
        'cohort_inbound_count': expected_inbound_count,
        'install_root': install_root, 'config_path': CONFIG_PATH, 'binary_path': BINARY_PATH,
        'binary_version': binary_version, 'initial_clash_mode': health_mode,
        'accounts': accounts, 'files': [{'path': path, 'sha256': sha256_bytes(files[path]),
            'size': len(files[path]), 'mode': file_modes[path]} for path in sorted(files)],
        'total_bytes': total,
        'requires_local_endpoints': sorted(local_required, key=lambda row: row['tag']),
        'reviewed_outbound_overrides': reviewed}
    if routing_revision is not None:
        from routing_contract import validate
        _need(expected_inbound_count==4 and execution_front in ('dmit','lazycat'),'revision_execution_scope')
        manifest.update(routing_revision=validate(routing_revision),routing_execution_front=execution_front)
    else:_need(execution_front is None,'execution_front_without_revision')
    return EdgeBundle(manifest, files, sha256_bytes(canonical_json(manifest)))


def to_tar_bytes(bundle):
    """Create the private uncompressed wire archive; no paths are read/written."""
    _need(isinstance(bundle, EdgeBundle), 'edge_bundle_required')
    _need(sha256_bytes(bundle.manifest_bytes) == bundle.manifest_sha256, 'manifest_modified')
    rows = {row['path']: row for row in bundle.manifest['files']}
    _need(set(rows) == set(bundle.files), 'bundle_file_inventory_modified')
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        material = [('manifest.json', bundle.manifest_bytes, 0o600)]
        for path in sorted(bundle.files):
            raw, row = bundle.files[path], rows[path]
            _need(len(raw) == row['size'] and sha256_bytes(raw) == row['sha256'], 'bundle_file_modified')
            material.append((path, raw, row['mode']))
        for path, raw, mode in material:
            _path(path, absolute=False)
            entry = tarfile.TarInfo(path); entry.size = len(raw); entry.mode = mode
            entry.uid = entry.gid = entry.mtime = 0; entry.uname = entry.gname = ''
            archive.addfile(entry, io.BytesIO(raw))
    return payload.getvalue()
