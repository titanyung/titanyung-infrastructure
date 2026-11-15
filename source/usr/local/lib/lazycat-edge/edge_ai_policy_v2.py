"""Pure AI policy with a controller-verified fastest StarHub pool.

The two stable authenticated entrances and their cohort are unchanged. The
controller chooses exactly one healthy StarHub: legacy ``z`` means selected
Uzuma StarHub, ``l`` means selected Lazycat StarHub, and ``s`` is Singtel health.
The bit names are an internal compatibility spelling, never a ZORO transport.
Importing/projecting does not read files, query a host or change a service.
"""
from __future__ import annotations

import copy
import ipaddress

import edge_ai_policy as v1

POLICY_ID = 'lazycat-edge-ai-starhub-pool-20261108-v2'
INBOUND_TAGS = v1.INBOUND_TAGS
PEER_TAGS = ('lazycat-starhub', 'uzuma-singtel', 'uzuma-starhub')
FALLBACK_TAG = v1.FALLBACK_TAG
ASSET_ROLES, ASSET_TAGS = v1.ASSET_ROLES, v1.ASSET_TAGS
DNS_TAGS = ('edge-ai-dns-lazycat-starhub', 'edge-ai-dns-uzuma-starhub', 'edge-ai-dns-singtel')
MODE_SEMANTICS = {'z': 'selected_uzuma_starhub', 's': 'singtel_healthy',
                  'l': 'selected_lazycat_starhub'}
MODES = tuple('ai-z' + str(uzuma) + 's' + str(singtel) + 'l' + str(lazycat)
    for uzuma in (0, 1) for singtel in (0, 1) for lazycat in (0, 1)
    if not (uzuma and lazycat))
need = v1.need
AIPolicyError = v1.AIPolicyError


def selected_outbound(mode, inbound):
    """Fixed selection truth table; health/latency qualification is upstream.

    Desktop's existing StarHub entrance uses the selected valid StarHub, with
    Singtel as the existing last resort. Mobile's Singtel entrance retains its
    preference and only falls back to the selected valid StarHub when needed.
    All-unavailable yields no transport and cannot fall back to DMIT direct.
    """
    need(mode in MODES and inbound in INBOUND_TAGS, 'unknown_ai_health_mode')
    chosen_starhub = ('uzuma-starhub' if mode[4] == '1' else
                     'lazycat-starhub' if mode[8] == '1' else None)
    singtel = 'uzuma-singtel' if mode[6] == '1' else None
    return ((singtel or chosen_starhub) if inbound == INBOUND_TAGS[1]
            else (chosen_starhub or singtel))


def _dns():
    # Distinct authenticated paths, not just distinct resolver addresses.
    # These exact address/SNI/path pairs passed the authenticated production
    # transport matrix; other resolver addresses can be routed differently by
    # the exit providers even when the hostname and protocol are identical.
    upstreams = ((DNS_TAGS[0], '8.8.8.8', 'dns.google', PEER_TAGS[0]),
                 (DNS_TAGS[1], '1.1.1.1', 'cloudflare-dns.com', PEER_TAGS[2]),
                 (DNS_TAGS[2], '8.8.4.4', 'dns.google', PEER_TAGS[1]))
    servers = [{'type': 'https', 'tag': tag, 'server': address, 'server_port': 443,
        'path': '/dns-query', 'tls': {'enabled': True, 'server_name': name}, 'detour': peer}
        for tag, address, name, peer in upstreams]
    rules = []
    for index, timeout in ((0, '1200ms'), (1, '1500ms')):
        rules += [{'action': 'evaluate', 'server': DNS_TAGS[index], 'timeout': timeout},
            {'match_response': True, 'response_rcode': 'NOERROR', 'action': 'respond'},
            {'match_response': True, 'response_rcode': 'NXDOMAIN', 'action': 'respond'}]
    rules.append({'action': 'route', 'server': DNS_TAGS[2], 'timeout': '1500ms'})
    return {'servers': servers, 'rules': rules, 'final': DNS_TAGS[2], 'strategy': 'ipv4_only'}


def _rules():
    rules = []
    def add(match, action='reject', **options):
        match = copy.deepcopy(match)
        if match.get('type') == 'logical':
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
    add({'ip_cidr': list(v1.RESERVED)})
    add({'domain_suffix': list(v1.YOUTUBE_SUFFIXES)})
    add({'rule_set': [ASSET_TAGS['youtube']]})
    for host in v1.EXACT_AI_HOSTS:
        add({'domain': [host]}, 'route-options', override_address=host)
    add({'ip_cidr': ['0.0.0.0/0', '::/0']})
    add({'type': 'logical', 'mode': 'or', 'rules': [
        {'rule_set': [ASSET_TAGS['ai'], ASSET_TAGS['google']]},
        {'domain_suffix': list(v1.SENSITIVE_SUFFIXES + v1.AI_TEST_SUFFIXES)}], 'invert': True})
    add({**v1._sensitive(), 'clash_mode': 'ai-z0s0l0'})
    # This branch precedes local resolve: all SG transports may also have lost
    # DNS. The dedicated DMIT receiver repeats the Google-only destination gate.
    add({'rule_set': [ASSET_TAGS['google']], 'clash_mode': 'ai-z0s0l0'},
        'route', outbound=FALLBACK_TAG)
    add({}, 'resolve', strategy='ipv4_only', timeout='5s')
    add({'ip_is_private': True})
    add({'ip_cidr': list(v1.RESERVED)})
    for mode in MODES:
        for inbound in INBOUND_TAGS:
            target = selected_outbound(mode, inbound)
            if target:
                add({'inbound': [inbound], 'clash_mode': mode}, 'route', outbound=target)
    rules.append({'action': 'reject'})
    return rules


def _route(definitions):
    return {'rules': _rules(), 'rule_set': definitions, 'final': PEER_TAGS[1],
        'default_domain_resolver': {'server': DNS_TAGS[2], 'strategy': 'ipv4_only'}}


def project_ai_runtime(runtime, *, asset_roles, asset_bytes, google_fallback_endpoint,
        health_mode='ai-z0s0l0', extra_transport=None):
    """Project the authority's cohort plus an explicitly supplied new SS peer.

    The caller can instead append that verified peer to its private runtime
    copy and omit extra_transport. Neither form mutates the authoritative input.
    It must validate the original authority before adding the extra transport.
    """
    need(isinstance(runtime, dict) and health_mode in MODES, 'unknown_ai_health_mode')
    accounts = v1._cohort(runtime.get('inbounds'))
    definitions, proof = v1._verified_definitions(runtime, asset_roles, asset_bytes)
    inbound = {row['tag']: row for row in runtime['inbounds']}
    need(set(INBOUND_TAGS) <= set(inbound), 'required_preference_inbound_missing')
    rows = runtime.get('outbounds')
    need(isinstance(rows, list) and all(isinstance(row, dict) for row in rows)
        and len({row.get('tag') for row in rows}) == len(rows), 'source_outbound_inventory_invalid')
    outbound = {row['tag']: copy.deepcopy(row) for row in rows}
    if extra_transport is not None:
        need(isinstance(extra_transport, dict) and extra_transport.get('tag') == PEER_TAGS[2]
            and PEER_TAGS[2] not in outbound, 'new_starhub_transport_conflict')
        outbound[PEER_TAGS[2]] = copy.deepcopy(extra_transport)
    need(set(PEER_TAGS) <= set(outbound), 'required_sg_transport_missing')
    need(all(outbound[tag].get('type') == 'shadowsocks' and not outbound[tag].get('detour')
        for tag in PEER_TAGS), 'unreviewed_sg_transport')
    endpoint = v1._endpoint(google_fallback_endpoint)
    config = {key: copy.deepcopy(runtime[key]) for key in ('log', 'experimental', 'services') if key in runtime}
    config['inbounds'] = [copy.deepcopy(inbound[tag]) for tag in INBOUND_TAGS]
    config['outbounds'] = [copy.deepcopy(outbound[tag]) for tag in PEER_TAGS]
    config['outbounds'].append(dict(endpoint, type='socks', tag=FALLBACK_TAG, version='5', connect_timeout='5s'))
    need(isinstance(config.get('experimental', {}).get('clash_api'), dict), 'private_clash_api_required')
    config['experimental']['clash_api']['default_mode'] = health_mode
    config['route'], config['dns'] = _route(definitions), _dns()
    validate_ai_runtime(config)
    metadata = {'schema': 1, 'policy_id': POLICY_ID, 'accounts': accounts,
        'source_inbound_count': len(runtime['inbounds']), 'cohort_inbound_count': 2,
        'asset_roles': proof, 'allowed_inbounds': list(INBOUND_TAGS), 'sg_outbounds': list(PEER_TAGS),
        'dns_transport_count': 3, 'dns_independent_egress_count': 3,
        'initial_clash_mode': health_mode, 'non_ai_policy': 'reject',
        'health_mode_semantics': dict(MODE_SEMANTICS), 'starhub_selection': 'verified_fastest_one_hot',
        'ip_only_policy': 'reject_unless_exact_hostname_rewritten',
        'google_fallback': dict(endpoint, tag=FALLBACK_TAG, receiver_must_enforce_google_only=True)}
    return config, metadata


project_v2 = project_ai_runtime


def validate_ai_runtime(document):
    """Exact V2 validator; the V1 public dispatcher retains exact V1 support."""
    need(isinstance(document, dict), 'ai_runtime_required')
    incoming = document.get('inbounds')
    need(isinstance(incoming, list) and len(incoming) == 2
        and [row.get('tag') for row in incoming] == list(INBOUND_TAGS), 'ai_inbound_inventory_changed')
    accounts = v1._cohort(incoming)
    definitions = v1._definitions(document)
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
    for peer in outbounds[:3]:
        need(peer.get('type') == 'shadowsocks' and not peer.get('detour'), 'unreviewed_sg_transport')
        try: address = ipaddress.ip_address(peer.get('server'))
        except (ValueError, TypeError): raise AIPolicyError('invalid_sg_endpoint') from None
        need(not address.is_unspecified and not address.is_multicast
            and type(peer.get('server_port')) is int and 0 < peer['server_port'] < 65536,
            'invalid_sg_endpoint')
    fallback = outbounds[3]
    v1._endpoint({key: fallback.get(key) for key in ('server', 'server_port')})
    need(fallback.get('type') == 'socks' and fallback.get('version') == '5'
        and not fallback.get('detour') and set(fallback) <= {'type', 'tag', 'server', 'server_port',
            'version', 'connect_timeout'}, 'unreviewed_google_fallback')
    return {'policy_id': POLICY_ID, 'cohort_inbound_count': 2, 'accounts': accounts,
        'asset_tags': [row['tag'] for row in definitions], 'ordinary_traffic': 'reject',
        'health_mode_semantics': dict(MODE_SEMANTICS),
        'dns_transport_count': 3, 'dns_independent_egress_count': 3}


validate_ai_runtime_v2 = validate_ai_runtime
