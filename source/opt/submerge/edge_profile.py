"""Pure LC-first AI client projection; never fetches a provider or changes a mode.

Only ordinary profiles are projected. Independent manual-test subscriptions keep
their previous contract. The caller supplies the existing client_policy module.
"""
from __future__ import annotations

import copy
import ipaddress
import re

MARKER = 'x-submerge-lazycat-ai'
POLICY = 'lc-first-ai-20261108-v1'
# Mihomo URLTest sends HEAD: cdn-cgi/trace returns 404 for that method even
# when its GET is healthy. robots.txt is verified HEAD 200 on all four paths.
HEALTH_URL = 'https://chatgpt.com/robots.txt'
RAW = {
    'lc_starhub': '__LC_AI_RAW_STARHUB', 'lc_singtel': '__LC_AI_RAW_SINGTEL',
    'dmit_starhub': '__DMIT_AI_RAW_STARHUB', 'dmit_singtel': '__DMIT_AI_RAW_SINGTEL',
}
CARDS = {
    'lc_starhub': '🔷 新懒猫 → StarHub', 'lc_singtel': '🔷 新懒猫 → Singtel',
    'dmit_starhub': '🔷 DMIT → StarHub', 'dmit_singtel': '🔷 DMIT → Singtel',
}
PREFERENCES = ('starhub', 'singtel')
META_KEYS = {'schema', 'policy', 'settings', 'ai_group', 'legacy_ai_positions',
             'legacy_ai_default_key', 'outer_groups', 'added_direct_rule'}


class ProfileError(ValueError):
    pass


def need(value, code):
    if not value:
        raise ProfileError(code)


def settings_document(value):
    required = {'public_ip', 'public_ports', 'certificate_fingerprint', 'server_name'}
    need(isinstance(value, dict) and required.issubset(value) and
         set(value).issubset(required | {'dmit_public_ports'}), 'edge_profile_settings_fields')
    try:
        address = ipaddress.ip_address(value['public_ip'])
    except (ValueError, TypeError):
        raise ProfileError('edge_public_ipv4_required') from None
    need(address.version == 4 and address.is_global, 'edge_public_ipv4_required')
    ports = value['public_ports']
    need(isinstance(ports, dict) and set(ports) == set(PREFERENCES) and
         all(type(port) is int and 0 < port < 65536 for port in ports.values()) and
         len(set(ports.values())) == 2, 'two_distinct_public_preference_ports_required')
    fingerprint = value['certificate_fingerprint']
    need(isinstance(fingerprint, str), 'edge_certificate_pin_required')
    fingerprint = fingerprint.replace(':', '').lower()
    need(re.fullmatch(r'[a-f0-9]{64}', fingerprint), 'edge_certificate_pin_required')
    server_name = value['server_name']
    need(isinstance(server_name, str) and 0 < len(server_name) <= 253 and
         all(re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', part)
             for part in server_name.split('.')), 'edge_tls_server_name_required')
    output = {'public_ip': str(address), 'public_ports': dict(ports),
              'certificate_fingerprint': fingerprint, 'server_name': server_name}
    if 'dmit_public_ports' in value:
        overrides = value['dmit_public_ports']
        need(isinstance(overrides, dict) and set(overrides) == set(PREFERENCES) and
             all(type(port) is int and 0 < port < 65536 for port in overrides.values()) and
             len(set(overrides.values())) == 2, 'two_distinct_dmit_ports_required')
        output['dmit_public_ports'] = dict(overrides)
    return output


def direct_rule(settings):
    return 'IP-CIDR,' + settings['public_ip'] + '/32,DIRECT,no-resolve'


def legacy_validate(document, policy, provider_document):
    result = (policy.validate_profile(document, provider_document) if provider_document is not None
              else policy.validate_profile(document))
    need(result is True, 'legacy_profile_not_validated')


def layout(document, policy):
    nodes = document.get('proxies')
    rows = document.get('proxy-groups')
    need(isinstance(nodes, list) and isinstance(rows, list), 'profile_inventory_required')
    indexed = {row.get('name'): row for row in nodes}
    groups = {row.get('name'): row for row in rows}
    need(len(indexed) == len(nodes) and len(groups) == len(rows), 'unique_profile_inventory_required')
    visible = [row['name'] for row in rows if not row.get('hidden')]
    need(len(visible) == 8, 'eight_visible_groups_required')
    ai = visible[2]
    all_name = visible[0]
    other, auto = visible[6], visible[1]
    need('GLOBAL' in groups and document.get('rules', [])[-2] == 'MATCH,' + all_name,
         'legacy_roots_required')
    need(ai in groups and policy.AI_AUTO in indexed, 'legacy_ai_inventory_required')
    return indexed, groups, {'ai': ai, 'all': all_name, 'global': 'GLOBAL', 'other': other, 'auto': auto}


def legacy_ai_nodes(base, kind, policy):
    result = []
    node = copy.deepcopy(base)
    node.update(name=policy.AI_AUTO, desc=''.join(policy.NOTICE))
    result.append(node)
    for key, name in policy.ai_manual_names().items():
        node = copy.deepcopy(base)
        node.update(name=name, port=(30200 if kind == 'mobile' else 30100) + policy.ai_offset(key),
                    desc='IP检测：' + policy.ai_site(key))
        result.append(node)
    return result


def fallback(name, members):
    return {'name': name, 'type': 'fallback', 'proxies': list(members),
        'url': HEALTH_URL, 'expected-status': 200, 'interval': 60,
        'timeout': 5000, 'lazy': False, 'hidden': True}


def assert_roots_do_not_reach_lc(document, roots):
    groups = {row['name']: row for row in document['proxy-groups']}
    lc_nodes = {RAW['lc_starhub'], RAW['lc_singtel']}
    def visit(name, stack):
        need(name not in lc_nodes, 'non_ai_root_reaches_new_edge')
        if name not in groups:
            return
        need(name not in stack, 'proxy_group_cycle')
        for member in groups[name].get('proxies', []):
            visit(member, stack | {name})
    for root in roots:
        visit(root, set())


def _transform(source, settings, policy):
    output = copy.deepcopy(source)
    indexed, groups, names = layout(source, policy)
    kind = source.get('x-submerge-client-kind')
    need(kind in ('mobile', 'desktop', 'router'), 'client_platform_required')
    old_names = [policy.AI_AUTO, *policy.ai_manual_names().values()]
    need(all(name in indexed for name in old_names), 'legacy_ai_nodes_missing')
    reserved = {*RAW.values(), *CARDS.values()}
    need(not reserved.intersection(set(indexed) | set(groups)), 'edge_name_collision')
    need(policy.AI_AUTO not in groups, 'ai_auto_group_collision')
    legacy_positions = [next(i for i, row in enumerate(source['proxies']) if row['name'] == name)
                        for name in old_names]
    default_names = {'auto': policy.AI_AUTO, **policy.ai_manual_names()}
    previous_default = groups[names['ai']].get('default-selected')
    need(previous_default in default_names.values(), 'legacy_ai_default_invalid')
    default_key = next(key for key, value in default_names.items() if value == previous_default)
    original_outer = {name: {'proxies': list(groups[name]['proxies']),
        'default_selected': groups[name].get('default-selected')} for name in (names['all'], names['global'])}
    output['proxies'] = [row for row in output['proxies'] if row['name'] not in set(old_names)]
    manual = policy.ai_manual_names()
    for preference, key in (('starhub', 'lazycat_sg'), ('singtel', 'uzuma_sg')):
        original = indexed[manual[key]]
        raw_dmit = copy.deepcopy(original)
        raw_dmit['name'] = RAW['dmit_' + preference]
        if 'dmit_public_ports' in settings:
            raw_dmit['port'] = settings['dmit_public_ports'][preference]
        output['proxies'].append(raw_dmit)
        raw_lc = copy.deepcopy(original)
        raw_lc.update(name=RAW['lc_' + preference], server=settings['public_ip'],
            port=settings['public_ports'][preference], sni=settings['server_name'],
            fingerprint=settings['certificate_fingerprint'], **{'skip-cert-verify': False})
        need(raw_lc.get('type') == 'anytls' and raw_lc.get('password') and
             raw_lc.get('dialer-proxy', 'DIRECT') == 'DIRECT', 'new_edge_tls_transport_invalid')
        output['proxies'].append(raw_lc)
    by_name = {row['name']: row for row in output['proxy-groups']}
    ai = by_name[names['ai']]
    ai['proxies'] = list(policy.NOTICE) + [policy.AI_AUTO, *CARDS.values()]
    ai['default-selected'] = policy.AI_AUTO
    for name in (names['all'], names['global']):
        row = by_name[name]
        row['proxies'] = [member for member in row['proxies'] if member != names['ai']]
        if row.get('default-selected') == names['ai']:
            row['default-selected'] = next((candidate for candidate in (names['other'], names['auto'])
                if candidate in row['proxies']), None)
            need(row['default-selected'] is not None, 'no_safe_global_default')
    preferred = 'singtel' if kind == 'mobile' else 'starhub'
    output['proxy-groups'].append(fallback(policy.AI_AUTO,
        [RAW['lc_' + preferred], RAW['dmit_' + preferred]]))
    for preference in PREFERENCES:
        output['proxy-groups'].append(fallback(CARDS['lc_' + preference],
            [RAW['lc_' + preference], RAW['dmit_' + preference]]))
    for preference in PREFERENCES:
        raw = RAW['dmit_' + preference]
        output['proxy-groups'].append({'name': CARDS['dmit_' + preference], 'type': 'select',
            'proxies': [raw], 'default-selected': raw, 'hidden': True})
    rule = direct_rule(settings)
    added = rule not in output['rules']
    if added:
        output['rules'].insert(6, rule)
    else:
        index = output['rules'].index(rule)
        # The six existing site-test rules are a fixed legacy prefix; the one
        # for ipinfo may itself be AI. A transport DIRECT rule follows that
        # prefix and must precede actual DNS/AI application dispatch.
        dispatch = [i for i, value in enumerate(output['rules']) if i >= 6 and value.endswith(',' + names['ai'])]
        need(index >= 6 and (not dispatch or index < min(dispatch)), 'edge_direct_rule_too_late')
    output[MARKER] = {'schema': 1, 'policy': POLICY, 'settings': settings,
        'ai_group': names['ai'], 'legacy_ai_positions': legacy_positions,
        'legacy_ai_default_key': default_key, 'outer_groups': original_outer,
        'added_direct_rule': added}
    assert_roots_do_not_reach_lc(output, (names['all'], names['global']))
    need([row['name'] for row in output['proxy-groups'] if not row.get('hidden')] ==
         [row['name'] for row in source['proxy-groups'] if not row.get('hidden')],
         'visible_groups_changed')
    return output


def reverse_adapter(projected, *, legacy_policy):
    """Rebuild the legacy validator view without retaining an old secret node."""
    if isinstance(projected.get(MARKER), dict) and projected[MARKER].get('schema') == 2:
        from edge_profile_v2 import reverse_adapter as reverse_v2
        return reverse_v2(projected, legacy_policy=legacy_policy)
    document = copy.deepcopy(projected)
    meta = document.pop(MARKER, None)
    need(isinstance(meta, dict) and set(meta) == META_KEYS and meta.get('schema') == 1 and
         meta.get('policy') == POLICY, 'edge_profile_metadata_invalid')
    settings_document(meta['settings'])
    need(type(meta['added_direct_rule']) is bool, 'edge_profile_metadata_invalid')
    positions = meta['legacy_ai_positions']
    need(isinstance(positions, list) and len(positions) == 4 and len(set(positions)) == 4 and
         all(type(value) is int and value >= 0 for value in positions), 'legacy_proxy_positions_invalid')
    raw_names = set(RAW.values())
    need(sum(row.get('name') in raw_names for row in document['proxies']) == 4, 'new_raw_inventory_changed')
    document['proxies'] = [row for row in document['proxies'] if row.get('name') not in raw_names]
    helper_names = {legacy_policy.AI_AUTO, *CARDS.values()}
    need(sum(row.get('name') in helper_names for row in document['proxy-groups']) == 5,
         'edge_helper_inventory_changed')
    document['proxy-groups'] = [row for row in document['proxy-groups'] if row.get('name') not in helper_names]
    groups = {row['name']: row for row in document['proxy-groups']}
    ai_name = meta['ai_group']
    need(ai_name in groups, 'ai_group_missing')
    kind = document.get('x-submerge-client-kind')
    base_name = legacy_policy.displayed_routes()['dmit']
    base = next((row for row in document['proxies'] if row['name'] == base_name), None)
    need(base is not None, 'legacy_dmit_base_missing')
    restored = legacy_ai_nodes(base, kind, legacy_policy)
    need(all(position < len(document['proxies']) + 4 for position in positions), 'legacy_proxy_positions_invalid')
    for position, node in sorted(zip(positions, restored), key=lambda row: row[0]):
        document['proxies'].insert(position, node)
    ai = groups[ai_name]
    ai['proxies'] = list(legacy_policy.NOTICE) + [legacy_policy.AI_AUTO,
        *[legacy_policy.ai_manual_names()[key] for key in legacy_policy.ai_keys(kind)]]
    default_names = {'auto': legacy_policy.AI_AUTO, **legacy_policy.ai_manual_names()}
    need(meta['legacy_ai_default_key'] in default_names, 'legacy_ai_default_invalid')
    ai['default-selected'] = default_names[meta['legacy_ai_default_key']]
    outer = meta['outer_groups']
    need(isinstance(outer, dict) and len(outer) == 2 and 'GLOBAL' in outer,
         'legacy_outer_metadata_invalid')
    for name, snapshot in outer.items():
        need(name in groups and isinstance(snapshot, dict) and
             set(snapshot) == {'proxies', 'default_selected'} and isinstance(snapshot['proxies'], list) and
             all(isinstance(value, str) for value in snapshot['proxies']) and
             (snapshot['default_selected'] is None or isinstance(snapshot['default_selected'], str)),
             'legacy_outer_metadata_invalid')
        groups[name]['proxies'] = list(snapshot['proxies'])
        if snapshot['default_selected'] is None:
            groups[name].pop('default-selected', None)
        else:
            groups[name]['default-selected'] = snapshot['default_selected']
    if meta['added_direct_rule']:
        rule = direct_rule(meta['settings'])
        need(len(document['rules']) > 6 and document['rules'][6] == rule,
             'edge_direct_rule_changed')
        del document['rules'][6]
    return document


def project_profile(source, settings, *, legacy_policy, provider_document=None):
    if isinstance(settings, dict) and 'manual_settings' in settings:
        from edge_profile_v2 import project_profile as project_v2
        return project_v2(source, settings, legacy_policy=legacy_policy,
                          provider_document=provider_document)
    if MARKER in source:
        validate_profile(source, legacy_policy=legacy_policy, provider_document=provider_document)
        source = reverse_adapter(source, legacy_policy=legacy_policy)
    legacy_validate(source, legacy_policy, provider_document)
    if source.get('x-submerge-manual-test') is True:
        return copy.deepcopy(source)
    settings = settings_document(settings)
    output = _transform(source, settings, legacy_policy)
    validate_profile(output, legacy_policy=legacy_policy, provider_document=provider_document)
    return output


def validate_profile(projected, *, legacy_policy, provider_document=None):
    if isinstance(projected.get(MARKER), dict) and projected[MARKER].get('schema') == 2:
        from edge_profile_v2 import validate_profile as validate_v2
        return validate_v2(projected, legacy_policy=legacy_policy,
                           provider_document=provider_document)
    if MARKER not in projected:
        return legacy_validate(projected, legacy_policy, provider_document) is None
    need(projected.get('x-submerge-manual-test') is False, 'manual_test_projection_forbidden')
    source = reverse_adapter(projected, legacy_policy=legacy_policy)
    legacy_validate(source, legacy_policy, provider_document)
    expected = _transform(source, settings_document(projected[MARKER]['settings']), legacy_policy)
    need(expected == projected, 'edge_projection_differs_from_reviewed_transform')
    return True
