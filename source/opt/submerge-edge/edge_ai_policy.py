"""Pure projection of the authoritative runtime to a quota-limited AI edge.

No files, hosts, services or databases are accessed. The caller supplies three
already downloaded assets and their authoritative semantic role/hash records.
The two entrances express StarHub/Singtel preference, never fastest selection.
Unknown and non-AI traffic fails closed, including unresolved IP-only targets.
The legacy ``ai-z0sSlL`` mode spelling retains compatibility; no ZORO transport
or ZORO DNS dependency is part of this projected policy.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
from pathlib import PurePosixPath
import re

POLICY_ID = 'lazycat-edge-ai-only-20261108-v1'
INBOUND_TAGS = ('dmit-starhub', 'dmit-singtel')
PEER_TAGS = ('lazycat-starhub', 'uzuma-singtel')
FALLBACK_TAG = 'dmit-google-fallback'
ASSET_ROLES = ('ai', 'google', 'youtube')
ASSET_TAGS = {role: 'server-' + role for role in ASSET_ROLES}
MODES = tuple('ai-z0s' + str(s) + 'l' + str(l) for s in (0, 1) for l in (0, 1))
DNS_TAGS = ('edge-ai-dns-starhub', 'edge-ai-dns-singtel', 'edge-ai-dns-singtel-secondary')
YOUTUBE_SUFFIXES = ('youtube.com', 'youtu.be', 'youtube-nocookie.com', 'googlevideo.com',
    'ytimg.com', 'youtube.googleapis.com', 'youtubei.googleapis.com', 'youtubemusic.com', 'yt.be')
SENSITIVE_SUFFIXES = ('openai.com', 'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com',
    'anthropic.com', 'claude.ai', 'claudeusercontent.com', 'gemini.google.com',
    'gemini.google', 'bard.google.com', 'aistudio.google.com', 'makersuite.google.com',
    'generativelanguage.googleapis.com', 'aisandbox-pa.googleapis.com')
AI_TEST_SUFFIXES = ('ippure.com', 'ipinfo.io')
# Complete hostnames only: an IP destination with these sniffed names is
# re-resolved to that exact service. Arbitrary sniffed suffixes are not trusted
# as authority to forward to the client's original unrelated public IP.
EXACT_AI_HOSTS = ('chatgpt.com', 'www.chatgpt.com', 'chat.openai.com', 'api.openai.com',
    'auth.openai.com', 'platform.openai.com', 'claude.ai', 'www.claude.ai',
    'api.anthropic.com', 'console.anthropic.com', 'www.google.com', 'google.com',
    'accounts.google.com', 'gemini.google.com', 'aistudio.google.com',
    'generativelanguage.googleapis.com', 'ippure.com', 'my.ippure.com',
    'www.ippure.com', 'ipinfo.io', 'www.ipinfo.io')
RESERVED = ('0.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '224.0.0.0/4',
    '240.0.0.0/4', '::/128', '::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8')
HEX = re.compile(r'^[a-f0-9]{64}$')


class AIPolicyError(ValueError):
    """Fixed, credential-free validation codes."""


def need(value, code):
    if not value:
        raise AIPolicyError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode('utf-8')


def _cohort(inbounds):
    need(isinstance(inbounds, list) and len(inbounds) >= 2, 'authoritative_inbounds_required')
    cohorts, tags = [], set()
    for inbound in inbounds:
        need(isinstance(inbound, dict) and inbound.get('type') == 'anytls'
            and isinstance(inbound.get('tag'), str) and inbound['tag'] not in tags,
            'authoritative_anytls_inventory_invalid')
        tags.add(inbound['tag']); rows, names = [], set()
        need(isinstance(inbound.get('users'), list), 'authoritative_users_required')
        for user in inbound['users']:
            need(isinstance(user, dict) and set(user) == {'name', 'password'}, 'unreviewed_account_fields')
            need(isinstance(user['name'], str) and user['name'] and user['name'] not in names
                and isinstance(user['password'], str) and user['password'], 'invalid_account')
            names.add(user['name']); rows.append({'name': user['name'], 'password': user['password']})
        cohorts.append(sorted(rows, key=lambda row: row['name']))
    need(all(rows == cohorts[0] for rows in cohorts), 'authoritative_cohort_mismatch')
    return {'usernames': [row['name'] for row in cohorts[0]],
        'cohort_sha256': hashlib.sha256(canonical(cohorts[0])).hexdigest()}


def _definitions(document):
    rows = document.get('route', {}).get('rule_set')
    need(isinstance(rows, list), 'local_asset_definitions_required')
    by_tag = {}
    for row in rows:
        need(isinstance(row, dict) and isinstance(row.get('tag'), str)
            and row['tag'] not in by_tag, 'duplicate_asset_tag')
        by_tag[row['tag']] = row
    selected = []
    for role in ASSET_ROLES:
        need(ASSET_TAGS[role] in by_tag, 'required_ai_asset_missing')
        row = by_tag[ASSET_TAGS[role]]
        need(set(row) == {'type', 'tag', 'format', 'path'} and row['type'] == 'local'
            and row['format'] in ('binary', 'source'), 'unreviewed_asset_definition')
        path = PurePosixPath(row['path']) if isinstance(row.get('path'), str) else None
        need(path is not None and path.is_absolute() and str(path) == row['path']
            and '..' not in path.parts and '\\' not in row['path'], 'invalid_asset_path')
        selected.append(copy.deepcopy(row))
    need(len({row['path'] for row in selected}) == len(selected), 'asset_roles_share_path')
    return selected


def _verified_definitions(source, asset_roles, asset_bytes):
    need(isinstance(asset_roles, dict) and set(asset_roles) == set(ASSET_ROLES),
        'explicit_verified_asset_roles_required')
    need(isinstance(asset_bytes, dict), 'explicit_verified_asset_bytes_required')
    definitions = _definitions(source); proof = {}
    for role, definition in zip(ASSET_ROLES, definitions):
        row = asset_roles[role]
        need(isinstance(row, dict) and set(row) == {'path', 'format', 'sha256', 'source'},
            'verified_asset_role_fields_invalid')
        need(row['path'] == definition['path'] and row['format'] == definition['format'],
            'verified_asset_role_binding_mismatch')
        need(isinstance(row['sha256'], str) and HEX.fullmatch(row['sha256']), 'invalid_asset_hash')
        need(isinstance(row['source'], str) and 0 < len(row['source']) <= 2048
            and '\n' not in row['source'] and not re.search(r'(?:token|password|secret)=', row['source'], re.I),
            'invalid_asset_provenance')
        raw = asset_bytes.get(row['path'])
        need(isinstance(raw, bytes) and 0 < len(raw) <= 8*1024*1024
            and hashlib.sha256(raw).hexdigest() == row['sha256'], 'verified_asset_content_mismatch')
        proof[role] = dict(row, tag=ASSET_TAGS[role], size=len(raw))
    need(set(asset_bytes) == {row['path'] for row in definitions}, 'unexpected_asset_payload')
    return definitions, proof


def _endpoint(endpoint):
    need(isinstance(endpoint, dict) and set(endpoint) == {'server', 'server_port'},
        'explicit_google_fallback_endpoint_required')
    try: address = ipaddress.ip_address(endpoint['server'])
    except (ValueError, TypeError): raise AIPolicyError('invalid_google_fallback_endpoint') from None
    need(address.is_loopback and str(address) == endpoint['server']
        and type(endpoint['server_port']) is int and 0 < endpoint['server_port'] < 65536,
        'google_fallback_must_be_loopback')
    return copy.deepcopy(endpoint)


def _dns():
    upstreams = [(DNS_TAGS[0], '1.1.1.1', 'cloudflare-dns.com', PEER_TAGS[0]),
        (DNS_TAGS[1], '8.8.8.8', 'dns.google', PEER_TAGS[1]),
        (DNS_TAGS[2], '1.0.0.1', 'cloudflare-dns.com', PEER_TAGS[1])]
    servers = [{'type': 'https', 'tag': tag, 'server': server, 'server_port': 443,
        'path': '/dns-query', 'tls': {'enabled': True, 'server_name': name}, 'detour': peer}
        for tag, server, name, peer in upstreams]
    rules = []
    for index, timeout in ((0, '1200ms'), (1, '1500ms')):
        rules += [{'action': 'evaluate', 'server': DNS_TAGS[index], 'timeout': timeout},
            {'match_response': True, 'response_rcode': 'NOERROR', 'action': 'respond'},
            {'match_response': True, 'response_rcode': 'NXDOMAIN', 'action': 'respond'}]
    rules.append({'action': 'route', 'server': DNS_TAGS[2], 'timeout': '1500ms'})
    return {'servers': servers, 'rules': rules, 'final': DNS_TAGS[2], 'strategy': 'ipv4_only'}


def _sensitive():
    return {'type': 'logical', 'mode': 'or', 'rules': [
        {'rule_set': [ASSET_TAGS['ai']]},
        {'domain_suffix': list(SENSITIVE_SUFFIXES + AI_TEST_SUFFIXES)}]}


def _rules():
    rules = []
    def add(match, action='reject', **options):
        match = copy.deepcopy(match)
        if match.get('type') == 'logical':
            # Native LogicalRule has only mode/rules/invert, not the default
            # match fields. Scope and health conditions belong in an AND child.
            logical = {key: match.pop(key) for key in ('type', 'mode', 'rules', 'invert') if key in match}
            scope = {'inbound': list(INBOUND_TAGS), **match}
            row = {'type': 'logical', 'mode': 'and', 'rules': [scope, logical],
                'action': action, **options}
        else:
            row = {'inbound': list(INBOUND_TAGS), **match, 'action': action, **options}
        rules.append(row)
    add({'type': 'logical', 'mode': 'or', 'rules': [{'clash_mode': mode} for mode in MODES], 'invert': True})
    add({'network': ['udp']})
    add({'network': ['tcp']}, 'sniff', sniffer=['tls', 'http', 'bittorrent'], timeout='1s')
    add({'protocol': ['bittorrent']})
    add({'ip_is_private': True})
    add({'ip_cidr': list(RESERVED)})
    add({'domain_suffix': list(YOUTUBE_SUFFIXES)})
    add({'rule_set': [ASSET_TAGS['youtube']]})
    for host in EXACT_AI_HOSTS:
        add({'domain': [host]}, 'route-options', override_address=host)
    # No suffix-based SNI rule can authorize an arbitrary original IP target.
    add({'ip_cidr': ['0.0.0.0/0', '::/0']})
    allow = {'type': 'logical', 'mode': 'or', 'rules': [
        {'rule_set': [ASSET_TAGS['ai'], ASSET_TAGS['google']]},
        {'domain_suffix': list(SENSITIVE_SUFFIXES + AI_TEST_SUFFIXES)}], 'invert': True}
    add(allow)
    add({**_sensitive(), 'clash_mode': 'ai-z0s0l0'})
    # Both SG paths may also have lost DNS. Forward an approved Google domain
    # before local resolve; the dedicated DMIT receiver must repeat Google/YT,
    # resolve and private-target guards before using its existing Taiwan path.
    add({'rule_set': [ASSET_TAGS['google']], 'clash_mode': 'ai-z0s0l0'},
        'route', outbound=FALLBACK_TAG)
    add({}, 'resolve', strategy='ipv4_only', timeout='5s')
    add({'ip_is_private': True})
    add({'ip_cidr': list(RESERVED)})
    for mode in MODES:
        singtel, starhub = mode[6] == '1', mode[8] == '1'
        if not (singtel or starhub):
            continue
        for inbound in INBOUND_TAGS:
            preferred = PEER_TAGS[0] if inbound == INBOUND_TAGS[0] else PEER_TAGS[1]
            if preferred == PEER_TAGS[0]: target = PEER_TAGS[0] if starhub else PEER_TAGS[1]
            else: target = PEER_TAGS[1] if singtel else PEER_TAGS[0]
            add({'inbound': [inbound], 'clash_mode': mode}, 'route', outbound=target)
    # Unscoped final denial protects even a mistakenly added/unmatched inlet.
    rules.append({'action': 'reject'})
    return rules


def _route(definitions):
    return {'rules': _rules(), 'rule_set': definitions, 'final': PEER_TAGS[1],
        'default_domain_resolver': {'server': DNS_TAGS[2], 'strategy': 'ipv4_only'}}


def project_ai_runtime(runtime, *, asset_roles, asset_bytes, google_fallback_endpoint,
        health_mode='ai-z0s0l0'):
    """Return (private native config, safe source-proof metadata); no I/O."""
    need(isinstance(runtime, dict) and health_mode in MODES, 'unknown_ai_health_mode')
    accounts = _cohort(runtime.get('inbounds'))
    definitions, proof = _verified_definitions(runtime, asset_roles, asset_bytes)
    inbound = {row['tag']: row for row in runtime['inbounds']}
    need(set(INBOUND_TAGS) <= set(inbound), 'required_preference_inbound_missing')
    outbounds = runtime.get('outbounds')
    need(isinstance(outbounds, list) and len({row.get('tag') for row in outbounds}) == len(outbounds),
        'source_outbound_inventory_invalid')
    outbound = {row['tag']: row for row in outbounds}
    need(set(PEER_TAGS) <= set(outbound), 'required_sg_transport_missing')
    need(all(outbound[tag].get('type') == 'shadowsocks' and not outbound[tag].get('detour')
        for tag in PEER_TAGS), 'unreviewed_sg_transport')
    endpoint = _endpoint(google_fallback_endpoint)
    config = {key: copy.deepcopy(runtime[key]) for key in ('log', 'experimental', 'services') if key in runtime}
    config['inbounds'] = [copy.deepcopy(inbound[tag]) for tag in INBOUND_TAGS]
    config['outbounds'] = [copy.deepcopy(outbound[tag]) for tag in PEER_TAGS]
    config['outbounds'].append(dict(endpoint, type='socks', tag=FALLBACK_TAG, version='5', connect_timeout='5s'))
    need(isinstance(config.get('experimental', {}).get('clash_api'), dict), 'private_clash_api_required')
    config['experimental']['clash_api']['default_mode'] = health_mode
    config['route'] = _route(definitions); config['dns'] = _dns()
    validate_ai_runtime(config)
    metadata = {'schema': 1, 'policy_id': POLICY_ID, 'accounts': accounts,
        'source_inbound_count': len(runtime['inbounds']), 'cohort_inbound_count': 2,
        'asset_roles': proof, 'allowed_inbounds': list(INBOUND_TAGS), 'sg_outbounds': list(PEER_TAGS),
        'dns_transport_count': 3, 'dns_independent_egress_count': 2,
        'initial_clash_mode': health_mode, 'non_ai_policy': 'reject',
        'ip_only_policy': 'reject_unless_exact_hostname_rewritten',
        'google_fallback': dict(endpoint, tag=FALLBACK_TAG, receiver_must_enforce_google_only=True)}
    return config, metadata


def validate_ai_runtime(document,*,routing_revision=None,execution_front=None):
    """Strict structural gate used by the applier after its file/hash checks.

    This does not replace source-role verification performed by projection or
    the applier's exact manifest content hashes. Peer IPs/binds and generation
    paths are intentionally variable; route actions and DNS topology are not.
    """
    # A V2 generation is an opt-in, exact additional transport inventory. Keep
    # V1's full validator below unchanged so current/previous generations can
    # still be inspected and rolled back while V2 code is staged.
    rows = document.get('outbounds') if isinstance(document, dict) else None
    if isinstance(rows,list) and any(isinstance(row,dict) and row.get('tag')=='paoluz-sg-fallback' for row in rows):
        from edge_ai_policy_v4 import validate_ai_runtime_v4
        return validate_ai_runtime_v4(document,routing_revision=routing_revision,execution_front=execution_front)
    need(routing_revision is None and execution_front is None,'legacy_policy_contract_collision')
    incoming = document.get('inbounds') if isinstance(document, dict) else None
    if isinstance(incoming, list) and len(incoming) == 4:
        from edge_ai_policy_v3 import validate_ai_runtime_v3
        return validate_ai_runtime_v3(document)
    rows = document.get('outbounds') if isinstance(document, dict) else None
    if isinstance(rows, list) and any(isinstance(row, dict) and row.get('tag') == 'uzuma-starhub' for row in rows):
        from edge_ai_policy_v2 import validate_ai_runtime_v2
        return validate_ai_runtime_v2(document)
    need(isinstance(document, dict), 'ai_runtime_required')
    inbounds = document.get('inbounds')
    need(isinstance(inbounds, list) and len(inbounds) == 2
        and [row.get('tag') for row in inbounds] == list(INBOUND_TAGS), 'ai_inbound_inventory_changed')
    accounts = _cohort(inbounds)
    definitions = _definitions(document)
    need(len(document['route']['rule_set']) == 3
        and [row['tag'] for row in document['route']['rule_set']] == [ASSET_TAGS[role] for role in ASSET_ROLES],
        'ai_asset_inventory_changed')
    need(document['route'] == _route(definitions), 'ai_route_policy_changed')
    need(document.get('dns') == _dns(), 'ai_dns_policy_changed')
    need(document.get('experimental', {}).get('clash_api', {}).get('default_mode') in MODES,
        'unknown_ai_health_mode')
    outbounds = document.get('outbounds')
    need(isinstance(outbounds, list) and [row.get('tag') for row in outbounds] == list(PEER_TAGS) + [FALLBACK_TAG],
        'ai_outbound_inventory_changed')
    for peer in outbounds[:2]:
        need(peer.get('type') == 'shadowsocks' and not peer.get('detour'), 'unreviewed_sg_transport')
        try: address = ipaddress.ip_address(peer.get('server'))
        except (ValueError, TypeError): raise AIPolicyError('invalid_sg_endpoint') from None
        need(not address.is_unspecified and not address.is_multicast
            and type(peer.get('server_port')) is int and 0 < peer['server_port'] < 65536,
            'invalid_sg_endpoint')
    fallback = outbounds[2]
    _endpoint({key: fallback.get(key) for key in ('server', 'server_port')})
    need(fallback.get('type') == 'socks' and fallback.get('version') == '5'
        and not fallback.get('detour') and set(fallback) <= {'type', 'tag', 'server', 'server_port',
            'version', 'connect_timeout'}, 'unreviewed_google_fallback')
    return {'policy_id': POLICY_ID, 'cohort_inbound_count': 2, 'accounts': accounts,
        'asset_tags': [row['tag'] for row in definitions], 'ordinary_traffic': 'reject',
        'dns_transport_count': 3, 'dns_independent_egress_count': 2}
