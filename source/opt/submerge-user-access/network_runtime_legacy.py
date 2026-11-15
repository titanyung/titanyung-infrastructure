"""Pure six-server runtime contract. Importing this module makes no changes.

The legacy branch has five DMIT fronts and an independently authenticated HK
hop. An explicit, fully validated server policy upgrades this to twelve DMIT
fronts (six desktop/router and six mobile) and a private HK transport. Importing
or rendering never downloads rules or changes public services.
"""
from __future__ import annotations

import copy
import ipaddress
import json
import os
from pathlib import Path
import re
import stat

NETWORK_PLAN_PATH = Path('/etc/submerge-topology/network-plan.json')
PLAN_ID = 'six-server-20261106'
SERVER_POLICY_ID = 'dmit-domain-routing-20261106'
DMIT_SERVER = '179.255.136.79'
BYTEVIRT_HK_SERVER = '61.15.36.199'
BT_TAG = 'violation-bt-quarantine'
TRANSPORT_KEYS = ('bytevirt-tw', 'lazycat-starhub', 'lazycat-hkt', 'uzuma-singtel')
# The existing HK AnyTLS inlet lives on ByteVirt; it is not duplicated on DMIT.
ROUTES = (
    {'key': 'dmit', 'probe': 'DMIT', 'country': 'US', 'expected_ip': DMIT_SERVER,
     'tag': 'dmit-direct-stage', 'port': 31117, 'listen': '127.0.0.1', 'outbound': 'direct'},
    {'key': 'bytevirt-hk', 'probe': 'ByteVirt', 'country': 'HK',
     'expected_ip': BYTEVIRT_HK_SERVER, 'tag': None, 'port': 2443,
     'server': BYTEVIRT_HK_SERVER},
    {'key': 'bytevirt-tw', 'probe': 'ByteVirt-TW', 'country': 'TW', 'expected_ip': None,
     'tag': 'dmit-taiwan', 'port': 29514, 'listen': '0.0.0.0', 'outbound': 'bytevirt-taiwan'},
    {'key': 'lazycat-starhub', 'probe': 'LazyCat-StarHub', 'country': 'SG', 'expected_ip': None,
     'tag': 'dmit-starhub', 'port': 29515, 'listen': '0.0.0.0', 'outbound': 'lazycat-starhub'},
    {'key': 'lazycat-hkt', 'probe': 'LazyCat-HKT', 'country': 'HK', 'expected_ip': None,
     'tag': 'dmit-hkt', 'port': 29516, 'listen': '0.0.0.0', 'outbound': 'lazycat-hkt'},
    {'key': 'uzuma-singtel', 'probe': 'Uzuma-Singtel', 'country': 'SG', 'expected_ip': None,
     'tag': 'dmit-singtel', 'port': 29517, 'listen': '0.0.0.0', 'outbound': 'uzuma-singtel'},
)
MANAGED_ROUTES = tuple(row for row in ROUTES if row['tag'])


def _policy_fronts():
    desktop = copy.deepcopy(list(ROUTES))
    for row in desktop:
        row.update(country='TW', expected_ip=None, client_kind='desktop',
                   probe='Desktop-' + row['probe'])
        if row['key'] == 'bytevirt-hk':
            row.update(tag='dmit-hk', port=29518, listen='0.0.0.0', outbound='bytevirt-hk')
            row.pop('server', None)
    mobile = copy.deepcopy(desktop)
    for row in mobile:
        row.update(client_kind='mobile', probe=row['probe'].replace('Desktop-', 'Mobile-', 1),
                   tag='mobile-' + row['tag'].replace('-stage', ''), listen='0.0.0.0',
                   port=29611 if row['key'] == 'dmit' else row['port'] + 100)
    return tuple(desktop + mobile)


SERVER_POLICY_FRONTS = _policy_fronts()
_CLIENT_KEYS = {'dmit': 'dmit', 'bytevirt-hk': 'bytevirt_hk', 'bytevirt-tw': 'bytevirt_tw',
                'lazycat-starhub': 'lazycat_sg', 'lazycat-hkt': 'lazycat_hkt',
                'uzuma-singtel': 'uzuma_sg','zoro-sg':'zoro_sg'}


class NetworkPlanError(ValueError):
    """Only fixed, credential-silent labels are raised."""


def _require(value, label):
    if not value:
        raise NetworkPlanError(label)


def _pairs(items):
    value = {}
    for key, item in items:
        _require(key not in value, 'network_plan_duplicate_key')
        value[key] = item
    return value


def _host(value):
    _require(isinstance(value, str) and 0 < len(value) <= 253, 'network_transport_host_invalid')
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        _require(bool(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', value))
                 and '..' not in value, 'network_transport_host_invalid')
    else:
        _require(address.is_global and not address.is_multicast and not address.is_reserved,
                 'network_transport_host_not_public')


def validate_network_plan(document):
    """Validate private transports without connecting or exposing their values.

    A marker is committed only after the release verifies every backend. Missing
    or partial inventories fail closed rather than silently reinstating Zoro.
    """
    _require(isinstance(document, dict) and document.get('schema') == 1 and
             document.get('plan') == PLAN_ID, 'network_plan_schema_invalid')
    transports = document.get('transports')
    _require(isinstance(transports, dict) and set(transports) == set(TRANSPORT_KEYS),
             'network_plan_transport_inventory_invalid')
    allowed = {'type', 'server', 'server_port', 'password', 'method', 'tls',
               'connect_timeout', 'inet4_bind_address', 'inet6_bind_address',
               'bind_interface', 'domain_resolver', 'multiplex'}
    for value in transports.values():
        _require(isinstance(value, dict) and not (set(value) - allowed),
                 'network_transport_fields_invalid')
        _require(value.get('type') in {'shadowsocks', 'anytls'}, 'network_transport_protocol_invalid')
        _host(value.get('server'))
        _require(type(value.get('server_port')) is int and 1 <= value['server_port'] <= 65535,
                 'network_transport_port_invalid')
        _require(isinstance(value.get('password'), str) and len(value['password']) >= 16,
                 'network_transport_password_invalid')
        if value['type'] == 'shadowsocks':
            _require(value.get('method') in {'chacha20-ietf-poly1305', 'aes-128-gcm',
                     'aes-256-gcm', '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
                     '2022-blake3-chacha20-poly1305'}, 'network_transport_cipher_invalid')
            _require('tls' not in value, 'network_transport_tls_not_applicable')
        else:
            tls = value.get('tls')
            _require('method' not in value and isinstance(tls, dict) and tls.get('enabled') is True
                     and tls.get('insecure', False) is False,
                     'network_transport_tls_verification_required')
            _require(isinstance(tls.get('server_name'), str) and tls['server_name'],
                     'network_transport_tls_identity_required')
        for field, version in (('inet4_bind_address', 4), ('inet6_bind_address', 6)):
            if field in value:
                try:
                    address = ipaddress.ip_address(value[field])
                except (ValueError, TypeError):
                    raise NetworkPlanError('network_transport_bind_address_invalid') from None
                _require(address.version == version and address.is_global,
                         'network_transport_bind_address_invalid')
        if 'bind_interface' in value:
            _require(isinstance(value['bind_interface'], str) and
                     bool(re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', value['bind_interface'])),
                     'network_transport_bind_interface_invalid')
        if 'connect_timeout' in value:
            _require(isinstance(value['connect_timeout'], str) and
                     bool(re.fullmatch(r'[1-9][0-9]?(?:s|ms)', value['connect_timeout'])),
                     'network_transport_timeout_invalid')
        if 'multiplex' in value:
            multiplex = value['multiplex']
            _require(isinstance(multiplex, dict) and set(multiplex) == {'enabled'} and
                     type(multiplex['enabled']) is bool, 'network_transport_multiplex_invalid')
    if 'server_policy' in document:
        _validate_server_policy(document['server_policy'])
    return copy.deepcopy(document)


def _validate_server_policy(policy):
    from server_route_policy import ASSET_KEYS, POLICY_ID
    allowed = {'schema', 'id', 'hk_transport', 'rule_sets', 'service_ip_routes', 'remote_domains','zoro_transport'}
    _require(isinstance(policy, dict) and not set(policy) - allowed and
             policy.get('schema') == 1 and policy.get('id') == POLICY_ID == SERVER_POLICY_ID,
             'network_server_policy_schema_invalid')
    hop = policy.get('hk_transport')
    _require(isinstance(hop, dict) and hop.get('type') == 'shadowsocks' and
             hop.get('server') == BYTEVIRT_HK_SERVER and hop.get('server_port') == 2448,
             'network_server_policy_hk_transport_invalid')
    # Reuse protocol/credential validation without recursively enabling policy.
    validate_network_plan({'schema': 1, 'plan': PLAN_ID,
                           'transports': {key: copy.deepcopy(hop) for key in TRANSPORT_KEYS}})
    if 'zoro_transport' in policy:
        validate_network_plan({'schema':1,'plan':PLAN_ID,'transports':{key:copy.deepcopy(policy['zoro_transport']) for key in TRANSPORT_KEYS}})
    manifest = policy.get('rule_sets')
    _require(isinstance(manifest, dict) and set(manifest) == set(ASSET_KEYS),
             'network_server_policy_rule_inventory_invalid')
    for value in manifest.values():
        _require(isinstance(value, dict) and set(value) == {'path', 'format', 'sha256', 'source'} and
                 isinstance(value.get('path'), str) and Path(value['path']).is_absolute() and
                 value.get('format') in {'source', 'binary'} and
                 isinstance(value.get('sha256'), str) and
                 bool(re.fullmatch(r'[0-9a-f]{64}', value['sha256'])) and
                 isinstance(value.get('source'), str) and 0 < len(value['source']) <= 2048 and
                 '\n' not in value['source'] and not re.search(r'(?:token|password|secret)=', value['source'], re.I),
                 'network_server_policy_rule_asset_invalid')
    domains = policy.get('remote_domains', [])
    _require(isinstance(domains, list) and len(domains) <= 100 and
             all(isinstance(value, str) for value in domains) and len(set(domains)) == len(domains),
             'network_server_policy_remote_domains_invalid')
    for value in domains:
        _require(isinstance(value, str) and bool(re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', value))
                 and '.' in value and '..' not in value and len(value) <= 253,
                 'network_server_policy_remote_domains_invalid')
    services = policy.get('service_ip_routes', [])
    _require(isinstance(services, list) and len(services) <= 100,
             'network_server_policy_service_routes_invalid')
    seen = set()
    for row in services:
        _require(isinstance(row, dict) and set(row) == {'ip_cidr', 'target'} and
                 row.get('target') in {'direct', 'hk', 'taiwan', 'starhub', 'hkt', 'singtel'},
                 'network_server_policy_service_routes_invalid')
        try:
            address = ipaddress.ip_network(row.get('ip_cidr'), strict=True)
        except (ValueError, TypeError):
            raise NetworkPlanError('network_server_policy_service_routes_invalid') from None
        _require(address.prefixlen == address.max_prefixlen and address.network_address.is_global and
                 str(address) not in seen and str(address.network_address) != DMIT_SERVER,
                 'network_server_policy_service_routes_invalid')
        seen.add(str(address))


def server_policy_enabled(plan):
    return isinstance(plan, dict) and 'server_policy' in plan


def front_routes(plan):
    validate_network_plan(plan)
    if not server_policy_enabled(plan):return ROUTES
    extra=()
    if plan['server_policy'].get('zoro_transport'):
        extra=({'key':'zoro-sg','probe':'Desktop-ZORO-SG','country':'TW','expected_ip':None,'tag':'dmit-zoro-sg','port':29519,'listen':'0.0.0.0','outbound':'zoro-sg','client_kind':'desktop'},
               {'key':'zoro-sg','probe':'Mobile-ZORO-SG','country':'TW','expected_ip':None,'tag':'mobile-dmit-zoro-sg','port':29619,'listen':'0.0.0.0','outbound':'zoro-sg','client_kind':'mobile'})
    return SERVER_POLICY_FRONTS+extra


def managed_routes(plan):
    return tuple(row for row in front_routes(plan) if row['tag'])


def client_fronts(plan, client_kind='desktop'):
    _require(server_policy_enabled(validate_network_plan(plan)), 'network_server_policy_not_enabled')
    _require(client_kind in {'mobile', 'desktop', 'router'}, 'network_client_kind_invalid')
    family = 'mobile' if client_kind == 'mobile' else 'desktop'
    return {_CLIENT_KEYS[row['key']]: {'server': DMIT_SERVER, 'port': row['port'], 'tag': row['tag']}
            for row in front_routes(plan) if row['client_kind'] == family and row['key']!='zoro-sg'}


def load_network_plan(path=NETWORK_PLAN_PATH):
    """None means legacy operation; malformed or unsafe markers never do."""
    path = Path(path)
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    except FileNotFoundError:
        return None
    except OSError:
        raise NetworkPlanError('network_plan_unavailable') from None
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        _require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077,
                 'network_plan_private_permissions_invalid')
        raw = stream.read(1024 * 1024 + 1)
    _require(len(raw) <= 1024 * 1024, 'network_plan_document_too_large')
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
    except NetworkPlanError:
        raise
    except Exception:
        raise NetworkPlanError('network_plan_json_invalid') from None
    return validate_network_plan(value)


def expected_fronts(plan):
    return {row['tag']: row['port'] for row in managed_routes(plan)}


def session_fronts(plan):
    return frozenset(expected_fronts(plan))


def _users(users):
    _require(isinstance(users, list) and users and all(isinstance(row, dict) and
             isinstance(row.get('name'), str) and row['name'] and
             isinstance(row.get('password'), str) and len(row['password']) >= 24 for row in users),
             'network_runtime_users_invalid')
    _require(len({row['name'] for row in users}) == len(users) and
             len({row['password'] for row in users}) == len(users),
             'network_runtime_users_not_unique')


def build_network_config(source, plan, *, users=None, ports=None, listen=None,
                         clash_port=None, api_port=None, rule_set_loader=None):
    """Replace only topology front/route inventories, retaining audited controls.

    The caller filters current S-UI/deny bindings before passing ``users``. All
    five inlets receive exactly that cohort and existing verified TLS material.
    Optional per-tag ports/listen maps are solely for isolated staging.
    """
    plan = validate_network_plan(plan)
    active_fronts = managed_routes(plan)
    _require(isinstance(source, dict), 'network_runtime_source_invalid')
    origins = [row for row in source.get('inbounds', []) if isinstance(row, dict) and
               row.get('type') == 'anytls' and row.get('tag') == 'dmit-direct-stage']
    _require(len(origins) == 1, 'network_runtime_direct_template_invalid')
    template = origins[0]
    _require(isinstance(template.get('tls'), dict) and template['tls'].get('enabled') is True,
             'network_runtime_inbound_tls_required')
    cohort = copy.deepcopy(template.get('users') if users is None else users)
    _users(cohort)
    direct = [row for row in source.get('outbounds', []) if isinstance(row, dict) and
              row.get('tag') == 'direct' and row.get('type') == 'direct']
    quarantine = [row for row in source.get('outbounds', []) if isinstance(row, dict) and row.get('tag') == BT_TAG]
    _require(len(direct) == 1, 'network_runtime_direct_outbound_missing')
    _require(len(quarantine) == 1 and quarantine[0].get('type') == 'socks' and
             quarantine[0].get('server') == '127.0.0.1' and quarantine[0].get('server_port') == 18115,
             'network_runtime_bt_quarantine_missing')
    ports, listen = ports or {}, listen or {}
    tags = {row['tag'] for row in active_fronts}
    _require(isinstance(ports, dict) and isinstance(listen, dict) and
             set(ports).issubset(tags) and set(listen).issubset(tags),
             'network_runtime_override_inventory_invalid')
    actual_ports = [ports.get(row['tag'], row['port']) for row in active_fronts]
    _require(all(type(port) is int and 1 <= port <= 65535 for port in actual_ports) and
             len(set(actual_ports)) == len(actual_ports), 'network_runtime_ports_invalid')
    output = copy.deepcopy(source)
    output['inbounds'], output['outbounds'] = [], [copy.deepcopy(direct[0])]
    rules = [{'action': 'sniff'},
             {'protocol': ['bittorrent'], 'action': 'route', 'outbound': BT_TAG},
             {'protocol': ['bittorrent'], 'action': 'reject'},
             {'inbound': [row['tag'] for row in active_fronts], 'network': ['udp'], 'action': 'reject'}]
    for row in active_fronts:
        inbound = copy.deepcopy(template)
        address = listen.get(row['tag'], row['listen'])
        _require(address in {'127.0.0.1', '0.0.0.0', '::1', '::'}, 'network_runtime_listen_invalid')
        inbound.update(tag=row['tag'], listen=address,
                       listen_port=ports.get(row['tag'], row['port']), users=copy.deepcopy(cohort))
        output['inbounds'].append(inbound)
        rules.append({'inbound': [row['tag']], 'action': 'route', 'outbound': row['outbound']})
    for row in MANAGED_ROUTES:
        if row['key'] != 'dmit':
            outbound = copy.deepcopy(plan['transports'][row['key']])
            outbound['tag'] = row['outbound']
            outbound.setdefault('connect_timeout', '8s')
            output['outbounds'].append(outbound)
    if server_policy_enabled(plan):
        outbound = copy.deepcopy(plan['server_policy']['hk_transport'])
        outbound.update(tag='bytevirt-hk')
        outbound.setdefault('connect_timeout', '8s')
        output['outbounds'].append(outbound)
    if server_policy_enabled(plan) and plan['server_policy'].get('zoro_transport'):
        output['outbounds'].append(dict(copy.deepcopy(plan['server_policy']['zoro_transport']),tag='zoro-sg'))
    output['outbounds'].append(copy.deepcopy(quarantine[0]))
    rules.append({'action': 'reject'})
    output['route'] = {'rules': rules, 'final': 'direct'}
    clash = output.get('experimental', {}).get('clash_api')
    _require(isinstance(clash, dict) and isinstance(clash.get('secret'), str) and
             len(clash['secret']) >= 24, 'network_runtime_authenticated_clash_api_required')
    if clash_port is not None:
        _require(type(clash_port) is int and 1 <= clash_port <= 65535,
                 'network_runtime_clash_port_invalid')
        clash['external_controller'] = '127.0.0.1:' + str(clash_port)
    services = [row for row in output.get('services', []) if isinstance(row, dict) and row.get('type') == 'api']
    _require(len(services) == 1 and services[0].get('listen') == '127.0.0.1',
             'network_runtime_native_api_required')
    if api_port is not None:
        _require(type(api_port) is int and 1 <= api_port <= 65535,
                 'network_runtime_native_port_invalid')
        services[0]['listen_port'] = api_port
    if server_policy_enabled(plan):
        from server_route_policy import build_server_route_policy, load_rule_sets
        from client_policy import load_policy
        policy = plan['server_policy']
        loader = load_rule_sets if rule_set_loader is None else rule_set_loader
        output = build_server_route_policy(
            output, rule_sets=loader(policy['rule_sets']),
            service_ip_routes=policy.get('service_ip_routes'),
            remote_domains=policy.get('remote_domains', []), client_policy=load_policy(),zoro_transport=policy.get('zoro_transport'))
    return output


def validate_loaded_fronts(document, plan):
    expected = expected_fronts(plan)
    _require(isinstance(document, dict) and isinstance(document.get('inbounds'), list),
             'network_loaded_front_document_invalid')
    rows = document['inbounds']
    _require(len(rows) == len(expected) and all(isinstance(row, dict) for row in rows),
             'network_loaded_front_inventory_changed')
    actual = {row.get('tag'): row for row in rows}
    _require(len(actual) == len(rows) and set(actual) == set(expected),
             'network_loaded_front_inventory_changed')
    cohort, tls = None, None
    for tag, port in expected.items():
        row = actual[tag]
        _require(row.get('type') == 'anytls' and row.get('listen_port') == port,
                 'network_loaded_front_endpoint_changed')
        _users(row.get('users'))
        current = {item['name']: item['password'] for item in row['users']}
        if cohort is None:
            cohort, tls = current, row.get('tls')
        _require(current == cohort and row.get('tls') == tls and isinstance(tls, dict)
                 and tls.get('enabled') is True, 'network_loaded_front_binding_changed')
    return expected, actual


def validate_loaded_server_policy(document, plan, *, rule_set_loader=None):
    """Revoke/restore proof for decrypted fronts, private hops and native policy.

    This cannot prove a remote firewall ACL. The release must audit the private
    peer ACL independently; that state is never inferred from a DMIT JSON file.
    """
    plan = validate_network_plan(plan)
    _require(server_policy_enabled(plan), 'network_server_policy_not_enabled')
    result = validate_loaded_fronts(document, plan)
    from server_route_policy import build_server_route_policy, load_rule_sets
    from client_policy import load_policy
    policy = plan['server_policy']
    loader = load_rule_sets if rule_set_loader is None else rule_set_loader
    expected = build_server_route_policy(document, rule_sets=loader(policy['rule_sets']),
        service_ip_routes=policy.get('service_ip_routes'), remote_domains=policy.get('remote_domains', []),
        client_policy=load_policy(),zoro_transport=policy.get('zoro_transport'))
    _require(document.get('route') == expected['route'] and document.get('dns') == expected['dns'],
             'network_loaded_server_policy_changed')
    actual = {row['tag']: row for row in document['outbounds']}
    for row in MANAGED_ROUTES:
        if row['key'] == 'dmit':
            continue
        wanted = copy.deepcopy(plan['transports'][row['key']])
        wanted.update(tag=row['outbound'])
        wanted.setdefault('connect_timeout', '8s')
        _require(actual.get(row['outbound']) == wanted, 'network_loaded_private_hop_changed')
    wanted = copy.deepcopy(policy['hk_transport']); wanted.update(tag='bytevirt-hk')
    wanted.setdefault('connect_timeout', '8s')
    _require(actual.get('bytevirt-hk') == wanted, 'network_loaded_private_hop_changed')
    if policy.get('zoro_transport'):
        _require(actual.get('zoro-sg')==dict(policy['zoro_transport'],tag='zoro-sg'),'network_loaded_zoro_hop_changed')
    return result


def candidate_probe_profile(identity, dmit_password, plan, *, node_factory, bytevirt_fingerprint,
                            ports=None, dmit_server=DMIT_SERVER):
    validate_network_plan(plan)
    _require(isinstance(dmit_password, str) and len(dmit_password) >= 24,
             'network_probe_dmit_credential_invalid')
    ports = ports or {}
    _require(isinstance(ports, dict) and set(ports).issubset({row['tag'] for row in managed_routes(plan)}),
             'network_probe_override_inventory_invalid')
    nodes = []
    from client_policy import load_policy, front_ports as revision_ports
    revision = load_policy() if server_policy_enabled(plan) else None
    manual = revision is not None and identity.name in revision['test_users']
    for row in front_routes(plan):
        if row['key'] == 'bytevirt-hk' and not server_policy_enabled(plan):
            _require(isinstance(getattr(identity, 'sui_password', None), str) and identity.sui_password,
                     'network_probe_hk_credential_invalid')
            node = {'name': row['probe'], 'type': 'anytls', 'server': row['server'],
                    'port': row['port'], 'password': identity.sui_password, 'tls': True,
                    'skip-cert-verify': True, 'fingerprint': bytevirt_fingerprint,
                    'dialer-proxy': 'DMIT', 'udp': False}
        else:
            port = row['port']
            if revision is not None:
                port = revision_ports(row['client_kind'],test_mode=manual)[_CLIENT_KEYS[row['key']]]
            node = node_factory(row['probe'], 'dmit', dmit_server,
                                ports.get(row['tag'], port), dmit_password)
            node['udp'] = False
        nodes.append(node)
    return {'mode': 'rule', 'log-level': 'silent', 'allow-lan': False,
            'bind-address': '127.0.0.1', 'ipv6': False, 'dns': {'enable': False},
            'tun': {'enable': False}, 'profile': {'store-selected': False}, 'proxies': nodes,
            'proxy-groups': [{'name': 'TOPOLOGY_QA_ROUTE', 'type': 'select',
                              'proxies': [row['name'] for row in nodes]}],
            'rules': ['MATCH,TOPOLOGY_QA_ROUTE']}


def probe_expectations(plan, *, subid=None):
    from client_policy import load_policy
    revision = load_policy() if subid is not None and server_policy_enabled(plan) else None
    physical = {row['key']:row for row in ROUTES}
    physical['zoro-sg']={'country':'SG','expected_ip':None}
    manual = revision is not None and subid in revision['test_users']
    return [(row['probe'],(physical[row['key']] if manual else row)['country'],
             (physical[row['key']] if manual else row)['expected_ip']) for row in front_routes(plan)]


def validate_probe_trace(name, trace, plan, *, subid=None):
    expected = {key: (country, address) for key, country, address in probe_expectations(plan,subid=subid)}
    _require(name in expected and isinstance(trace, dict), 'network_probe_route_invalid')
    country, fixed_ip = expected[name]
    try:
        address = ipaddress.ip_address(trace.get('ip'))
    except (ValueError, TypeError):
        raise NetworkPlanError('network_probe_egress_mismatch') from None
    _require(address.version == 4 and address.is_global and not address.is_reserved and
             not address.is_multicast and (fixed_ip is None or str(address) == fixed_ip) and
             trace.get('country') == country and trace.get('tls_verified') is True,
             'network_probe_egress_mismatch')
    return {'route': name, 'country': country, 'ip': str(address), 'tls_verified': True}


def independent_negative_pairs(subject_profile, control_profile, plan):
    """Remove HK dialer so denied DMIT cannot mask a surviving HK credential."""
    expected = [row[0] for row in probe_expectations(plan)]
    profiles = []
    for profile in (subject_profile, control_profile):
        _require(isinstance(profile, dict) and isinstance(profile.get('proxies'), list),
                 'network_negative_probe_inventory_invalid')
        nodes = {row.get('name'): row for row in profile['proxies'] if isinstance(row, dict)}
        _require(len(nodes) == len(profile['proxies']) and set(nodes) == set(expected),
                 'network_negative_probe_inventory_invalid')
        profiles.append(nodes)
    output, pairs = [], []
    for name in expected:
        pair = []
        for kind, nodes in (('control', profiles[1]), ('subject', profiles[0])):
            node = copy.deepcopy(nodes[name])
            node['name'] = kind + '-' + name
            node.pop('dialer-proxy', None)
            output.append(node)
            pair.append(node['name'])
        pairs.append((name, pair[0], pair[1]))
    return output, pairs
