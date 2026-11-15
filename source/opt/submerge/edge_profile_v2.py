"""Pure client projection for independent StarHub provider choices.

The original projector and schema 1 stay valid.  Schema 2 adds two genuine
manual DMIT transports on independent reviewed ports.  Optional Lazycat manual
transports require two additional distinct public ports; the original automatic
ports are never reused for manual choices.  All transports retain the canonical
account password.  This module does not read settings, fetch subscriptions,
touch a server, or change a client's mode or TUN.
"""
from __future__ import annotations

import copy
import re

import edge_profile as v1

MARKER = v1.MARKER
POLICY = 'lc-first-ai-provider-manual-20261108-v2'
HEALTH_URL = v1.HEALTH_URL
ProfileError = v1.ProfileError
RAW = v1.RAW
CARDS = dict(v1.CARDS, lc_starhub='🔷 新懒猫 → StarHub 自动',
             dmit_starhub='🔷 DMIT → StarHub 自动')
MANUAL_KEYS = ('lazycat_starhub', 'uzuma_starhub')
MANUAL_RAW = {
    'lc_lazycat_starhub': '__LC_AI_MANUAL_LAZYCAT_STARHUB',
    'lc_uzuma_starhub': '__LC_AI_MANUAL_UZUMA_STARHUB',
    'dmit_lazycat_starhub': '__DMIT_AI_MANUAL_LAZYCAT_STARHUB',
    'dmit_uzuma_starhub': '__DMIT_AI_MANUAL_UZUMA_STARHUB',
}
MANUAL_CARDS = {
    'lc_lazycat_starhub': '🔷 Lazycat SG → Lazycat starhub',
    'lc_uzuma_starhub': '🔷 Lazycat SG → uzumaru StarHub',
    'dmit_lazycat_starhub': '🔷 DMIT → Lazycat starhub',
    'dmit_uzuma_starhub': '🔷 DMIT → uzumaru StarHub',
}
META_KEYS = v1.META_KEYS
need = v1.need


def _base_settings(settings):
    return {key: copy.deepcopy(value) for key, value in settings.items()
            if key != 'manual_settings'}


def settings_document(value):
    need(isinstance(value, dict), 'edge_profile_settings_fields')
    base = v1.settings_document(_base_settings(value))
    if 'manual_settings' not in value:
        return base
    manual = value['manual_settings']
    required = {'server_names', 'certificate_fingerprint', 'dmit_public_ports'}
    need(isinstance(manual, dict) and required <= set(manual) and
         set(manual) <= required | {'lazycat_public_ports'},
        'manual_settings_fields')
    names = manual['server_names']
    need(isinstance(names, dict) and set(names) == set(MANUAL_KEYS),
         'manual_sni_inventory')
    normalized = {}
    for key, name in names.items():
        need(isinstance(name, str) and 0 < len(name) <= 253 and
             all(re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', part)
                 for part in name.split('.')), 'manual_tls_server_name_required')
        normalized[key] = name.lower()
    need(len(set(normalized.values())) == 2 and
         base['server_name'].lower() not in normalized.values(),
         'manual_sni_must_identify_distinct_receivers')
    fingerprint = manual['certificate_fingerprint']
    need(isinstance(fingerprint, str), 'manual_certificate_pin_required')
    fingerprint = fingerprint.replace(':', '').lower()
    need(re.fullmatch(r'[a-f0-9]{64}', fingerprint), 'manual_certificate_pin_required')
    ports = manual['dmit_public_ports']
    need(isinstance(ports, dict) and set(ports) == set(MANUAL_KEYS) and
         all(type(port) is int and 0 < port < 65536 for port in ports.values()) and
         len(set(ports.values())) == 2, 'two_distinct_dmit_manual_ports_required')
    need(not set(ports.values()).intersection(base.get('dmit_public_ports', {}).values()),
         'manual_dmit_ports_conflict_with_auto')
    output = {
        'server_names': normalized, 'certificate_fingerprint': fingerprint,
        'dmit_public_ports': dict(ports)}
    if 'lazycat_public_ports' in manual:
        lc_ports = manual['lazycat_public_ports']
        need(isinstance(lc_ports, dict) and set(lc_ports) == set(MANUAL_KEYS) and
             all(type(port) is int and 0 < port < 65536 for port in lc_ports.values()) and
             len(set(lc_ports.values())) == 2, 'two_distinct_lazycat_manual_ports_required')
        need(not set(lc_ports.values()).intersection(base['public_ports'].values()),
             'manual_lazycat_ports_conflict_with_auto')
        output['lazycat_public_ports'] = dict(lc_ports)
    return dict(base, manual_settings=output)


def manual_raws(settings):
    """Only explicitly configured manual endpoints belong in the profile."""
    include_lc = 'lazycat_public_ports' in settings['manual_settings']
    return {key: name for key, name in MANUAL_RAW.items()
            if include_lc or key.startswith('dmit_')}


def manual_cards(settings):
    include = manual_raws(settings)
    return {key: name for key, name in MANUAL_CARDS.items() if key in include}


def direct_rule(settings):
    return v1.direct_rule(settings)


def _rename_cards(document, mapping):
    for group in document['proxy-groups']:
        group['name'] = mapping.get(group['name'], group['name'])
        if 'proxies' in group:
            group['proxies'] = [mapping.get(name, name) for name in group['proxies']]
        if 'default-selected' in group:
            group['default-selected'] = mapping.get(group['default-selected'], group['default-selected'])


def assert_roots_do_not_reach_lc(document, roots):
    groups = {row['name']: row for row in document['proxy-groups']}
    lc_nodes = {RAW['lc_starhub'], RAW['lc_singtel'],
                MANUAL_RAW['lc_lazycat_starhub'], MANUAL_RAW['lc_uzuma_starhub']}
    def visit(name, stack):
        need(name not in lc_nodes, 'non_ai_root_reaches_new_edge')
        if name not in groups:
            return
        need(name not in stack, 'proxy_group_cycle')
        for member in groups[name].get('proxies', []):
            visit(member, stack | {name})
    for root in roots:
        visit(root, set())


def _transform(source, settings, policy, provider_document=None):
    inventory = {row['name'] for row in source['proxies'] + source['proxy-groups']}
    reserved = set(MANUAL_RAW.values()) | set(MANUAL_CARDS.values()) | {
        CARDS['lc_starhub'], CARDS['dmit_starhub']}
    need(not reserved.intersection(inventory), 'manual_profile_name_collision')
    output = v1.project_profile(source, _base_settings(settings),
        legacy_policy=policy, provider_document=provider_document)
    meta = output[MARKER]
    names = meta['ai_group'], next(row['name'] for row in output['proxy-groups']
                                 if not row.get('hidden'))
    nodes = {row['name']: row for row in output['proxies']}
    manual = settings['manual_settings']
    base_ports = {nodes[RAW['dmit_' + key]]['port'] for key in v1.PREFERENCES}
    need(not base_ports.intersection(manual['dmit_public_ports'].values()),
         'manual_dmit_ports_conflict_with_auto')
    rename = {v1.CARDS[key]: CARDS[key] for key in CARDS if v1.CARDS[key] != CARDS[key]}
    _rename_cards(output, rename)
    for preference in v1.PREFERENCES:
        name = CARDS['dmit_' + preference]
        group = next(row for row in output['proxy-groups'] if row['name'] == name)
        group.clear()
        group.update(v1.fallback(name, [RAW['dmit_' + preference], RAW['lc_' + preference]]))
    fronts = ('lc', 'dmit') if 'lazycat_public_ports' in manual else ('dmit',)
    for front in fronts:
        for provider in MANUAL_KEYS:
            key = front + '_' + provider
            node = copy.deepcopy(nodes[RAW[front + '_starhub']])
            node.update(name=MANUAL_RAW[key], sni=manual['server_names'][provider],
                fingerprint=manual['certificate_fingerprint'], **{'skip-cert-verify': False})
            if front == 'lc':
                node['port'] = manual['lazycat_public_ports'][provider]
            else:
                node['port'] = manual['dmit_public_ports'][provider]
            need(node.get('type') == 'anytls' and node.get('password') and
                 node.get('dialer-proxy', 'DIRECT') == 'DIRECT', 'manual_tls_transport_invalid')
            output['proxies'].append(node)
    if 'lazycat_public_ports' in manual:
        for provider in MANUAL_KEYS:
            lc, dmit = 'lc_' + provider, 'dmit_' + provider
            output['proxy-groups'].append(v1.fallback(MANUAL_CARDS[lc],
                [MANUAL_RAW[lc], MANUAL_RAW[dmit]]))
    for provider in MANUAL_KEYS:
        key = 'dmit_' + provider
        if 'lazycat_public_ports' in manual:
            output['proxy-groups'].append(v1.fallback(MANUAL_CARDS[key],
                [MANUAL_RAW[key], MANUAL_RAW['lc_' + provider]]))
        else:
            output['proxy-groups'].append({'name': MANUAL_CARDS[key], 'type': 'select',
                'proxies': [MANUAL_RAW[key]], 'default-selected': MANUAL_RAW[key], 'hidden': True})
    ai = next(row for row in output['proxy-groups'] if row['name'] == names[0])
    ai['proxies'] = list(policy.NOTICE) + [policy.AI_AUTO, *CARDS.values(), *manual_cards(settings).values()]
    ai['default-selected'] = policy.AI_AUTO
    meta.update(schema=2, policy=POLICY, settings=copy.deepcopy(settings))
    assert_roots_do_not_reach_lc(output, (names[1], 'GLOBAL'))
    return output


def reverse_adapter(projected, *, legacy_policy):
    meta = projected.get(MARKER)
    if isinstance(meta, dict) and meta.get('schema') == 1:
        return v1.reverse_adapter(projected, legacy_policy=legacy_policy)
    need(isinstance(meta, dict) and set(meta) == META_KEYS and meta.get('schema') == 2
         and meta.get('policy') == POLICY, 'manual_profile_metadata_invalid')
    settings = settings_document(meta['settings'])
    need('manual_settings' in settings, 'manual_profile_settings_missing')
    document = copy.deepcopy(projected)
    active_raws, active_cards = set(manual_raws(settings).values()), set(manual_cards(settings).values())
    for name in MANUAL_RAW.values():
        need(sum(row.get('name') == name for row in document['proxies']) == int(name in active_raws),
             'manual_raw_inventory_changed')
    for name in MANUAL_CARDS.values():
        need(sum(row.get('name') == name for row in document['proxy-groups']) == int(name in active_cards),
             'manual_helper_inventory_changed')
    document['proxies'] = [row for row in document['proxies']
                           if row.get('name') not in MANUAL_RAW.values()]
    document['proxy-groups'] = [row for row in document['proxy-groups']
                                if row.get('name') not in MANUAL_CARDS.values()]
    ai = next((row for row in document['proxy-groups'] if row.get('name') == meta['ai_group']), None)
    need(ai is not None, 'ai_group_missing')
    ai['proxies'] = [name for name in ai['proxies'] if name not in MANUAL_CARDS.values()]
    rename = {CARDS[key]: v1.CARDS[key] for key in CARDS if v1.CARDS[key] != CARDS[key]}
    _rename_cards(document, rename)
    document[MARKER].update(schema=1, policy=v1.POLICY, settings=_base_settings(settings))
    return v1.reverse_adapter(document, legacy_policy=legacy_policy)


def project_profile(source, settings, *, legacy_policy, provider_document=None):
    if MARKER in source:
        validate_profile(source, legacy_policy=legacy_policy, provider_document=provider_document)
        source = reverse_adapter(source, legacy_policy=legacy_policy)
    v1.legacy_validate(source, legacy_policy, provider_document)
    if source.get('x-submerge-manual-test') is True:
        return copy.deepcopy(source)
    settings = settings_document(settings)
    if 'manual_settings' not in settings:
        return v1.project_profile(source, settings, legacy_policy=legacy_policy,
                                  provider_document=provider_document)
    output = _transform(source, settings, legacy_policy, provider_document)
    validate_profile(output, legacy_policy=legacy_policy, provider_document=provider_document)
    return output


def validate_profile(projected, *, legacy_policy, provider_document=None):
    if MARKER not in projected:
        return v1.validate_profile(projected, legacy_policy=legacy_policy,
                                   provider_document=provider_document)
    meta = projected[MARKER]
    if isinstance(meta, dict) and meta.get('schema') == 1:
        return v1.validate_profile(projected, legacy_policy=legacy_policy,
                                   provider_document=provider_document)
    need(projected.get('x-submerge-manual-test') is False, 'manual_test_projection_forbidden')
    source = reverse_adapter(projected, legacy_policy=legacy_policy)
    v1.legacy_validate(source, legacy_policy, provider_document)
    expected = _transform(source, settings_document(meta['settings']), legacy_policy, provider_document)
    need(expected == projected, 'manual_projection_differs_from_reviewed_transform')
    return True
