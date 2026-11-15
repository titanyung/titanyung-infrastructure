"""Pure, fail-closed five-group builder for *public* per-user ingress.

This is a release candidate, not a running service. It consumes an already
merged ordinary user's Clash document, verified per-user private maps and
route evidence. Unlike ``pc_only_stage``, none of its emitted nodes use the
client's loopback or an SSH forward. Installing public listeners, wiring this
into the merger and verifying actual exit IP/DNS remain separate operations.
"""

from __future__ import annotations

import copy
import hmac
from datetime import datetime
from typing import Mapping, Optional, Sequence

from expiry_policy import expired_services
from five_group_stage import (
    ALL_KEYS, ROUTE_SERVICES, ProviderMatch, RouteBinding,
    build_five_group_stage,
)
from pc_only_stage import (
    BYTEVIRT_CERT_FINGERPRINT, EXISTING_SHAPES, EXISTING_SOURCES,
    HKT_PUBLIC_CIPHER, HKT_PUBLIC_PORT, HKT_PUBLIC_SERVER, TLS,
)
PUBLIC_NAMES = {
    'vps_dmit': '__PUB-DMIT-direct',
    'vps_bwh': '__PUB-BWH-direct',
    'nex_dmit': '__PUB-DMIT-NexIP',
    'nex_bwh': '__PUB-BWH-NexIP',
    'ip2_dmit': '__PUB-DMIT-ip2up',
    'ip2_bwh': '__PUB-BWH-ip2up',
    'ph_dmit': '__PUB-DMIT-proxyhive',
    'sg_bwh': '__PUB-BWH-SG',
    'ph_bwh': '__PUB-BWH-proxyhive',
    'kk_bwh': '__PUB-BWH-kookey',
    'hkt_dmit': '__PUB-DMIT-HKT',
    'hkt_bwh': '__PUB-BWH-HKT',
    'bv_dmit': '__PUB-DMIT-ByteVirt',
    'bv_bwh': '__PUB-BWH-ByteVirt',
}
EXISTING_DIRECT = {'sg_dmit', 'kk_dmit'}
if set(PUBLIC_NAMES) | EXISTING_DIRECT != ALL_KEYS:
    raise RuntimeError('public_route_inventory_mismatch')


def active_route_keys(now: Optional[datetime] = None) -> frozenset[str]:
    expired = expired_services(now)
    return frozenset(key for key in ALL_KEYS
                     if not ROUTE_SERVICES[key].intersection(expired))


def required_credential_services(now: Optional[datetime] = None) -> frozenset[str]:
    active = active_route_keys(now)
    required = {'dmit'}
    if any('bwh' in ROUTE_SERVICES[key] for key in active):
        required.add('bwh')
    if any(key.startswith('hkt_') for key in active):
        required.add('hkt')
    return frozenset(required)


def validate_active_credential_maps(
    maps: Mapping[str, Mapping[str, str]], ordinary: frozenset[str],
    trial: Optional[str], *, now: Optional[datetime] = None,
    subscriber: Optional[str] = None,
) -> None:
    """Validate the requested ready user without coupling them to new rows.

    With no ``subscriber``, validate the entire ready cohort for offline
    release audits. Extra, not-yet-committed map entries are never rendered.
    """
    if (not isinstance(ordinary, frozenset) or not ordinary or
            (trial is not None and (not isinstance(trial, str) or
                                    trial in ordinary)) or
            any(not isinstance(value, str) or not value for value in ordinary)):
        raise ValueError('public_ordinary_cohort_invalid')
    if subscriber is not None and subscriber not in ordinary:
        raise ValueError('public_subscriber_not_ordinary')
    if not isinstance(maps, Mapping):
        raise ValueError('public_credential_maps_invalid')
    needed = required_credential_services(now)
    if not needed.issubset(maps):
        raise ValueError('public_active_credential_maps_missing')
    if set(maps).difference({'dmit', 'bwh', 'hkt'}):
        raise ValueError('public_unexpected_credential_map')
    targets = ordinary if subscriber is None else (subscriber,)
    for service in needed:
        values = maps[service]
        if not isinstance(values, Mapping):
            raise ValueError('public_active_credential_cohort_invalid_' + service)
        for secret in targets:
            value = values.get(secret)
            if not isinstance(value, str) or len(value) < 24:
                raise ValueError('public_active_credential_cohort_invalid_' + service)
            if service == 'hkt' and value.count(':') != 1:
                raise ValueError('public_hkt_credential_format_invalid')
            # Credential reuse between ready identities is a cross-account
            # leak. An unready, partially staged account is not a consumer.
            if any(other != secret and values.get(other) == value
                   for other in ordinary):
                raise ValueError('public_active_credential_duplicate_' + service)


def _anytls(name: str, service: str, server: str, port: int, password: str,
            *, dialer: Optional[str] = None) -> dict:
    if (not isinstance(server, str) or not server or
            not isinstance(port, int) or not 1 <= port <= 65535 or
            not isinstance(password, str) or len(password) < 24):
        raise ValueError('public_anytls_input_invalid')
    sni, fingerprint, skip_verify = TLS[service]
    node = {
        'name': name, 'type': 'anytls', 'server': server, 'port': port,
        'password': password, 'sni': sni, 'fingerprint': fingerprint,
        'skip-cert-verify': skip_verify, 'udp': False,
    }
    if dialer:
        node['dialer-proxy'] = dialer
    return node


def _hkt(name: str, password: str, dialer: str) -> dict:
    if (not isinstance(password, str) or len(password) < 24 or
            ':' not in password):
        raise ValueError('public_hkt_password_invalid')
    return {
        'name': name, 'type': 'ss', 'server': HKT_PUBLIC_SERVER,
        'port': HKT_PUBLIC_PORT, 'cipher': HKT_PUBLIC_CIPHER,
        'password': password, 'dialer-proxy': dialer, 'udp': False,
    }


def _bytevirt(template: dict, name: str, dialer: str) -> dict:
    if (not isinstance(template, dict) or template.get('type') != 'anytls' or
            template.get('tls') is not True or
            not isinstance(template.get('password'), str) or
            len(template['password']) < 10):
        raise ValueError('public_bytevirt_template_invalid')
    node = copy.deepcopy(template)
    node.update({
        'name': name, 'server': '61.15.36.199', 'port': 2443,
        'tls': True, 'skip-cert-verify': True,
        'fingerprint': BYTEVIRT_CERT_FINGERPRINT,
        'dialer-proxy': dialer, 'udp': False,
    })
    node.pop('sni', None)
    node.pop('servername', None)
    return node


def _source_nodes(base: dict) -> dict:
    nodes = {}
    for node in base.get('proxies') or []:
        if not isinstance(node, dict) or not isinstance(node.get('name'), str):
            raise ValueError('public_base_node_invalid')
        if node['name'] in nodes:
            raise ValueError('public_base_node_duplicate')
        nodes[node['name']] = node
    return nodes


def build_public_five_group(
    base: dict, *, sub_secret: str, ordinary: frozenset[str], trial: Optional[str],
    credential_maps: Mapping[str, Mapping[str, str]],
    route_evidence: Mapping[str, str],
    provider_matches: Mapping[str, Sequence[ProviderMatch]],
    now: Optional[datetime] = None,
    direct_country: Optional[str] = None,
) -> dict:
    """Render one committed ordinary user; reject stale source/path binding."""
    if not isinstance(base, dict) or sub_secret not in ordinary or sub_secret == trial:
        raise ValueError('public_subscriber_not_ordinary')
    validate_active_credential_maps(credential_maps, ordinary, trial, now=now,
                                    subscriber=sub_secret)
    active = active_route_keys(now)
    if (not isinstance(route_evidence, Mapping) or
            not active.issubset(route_evidence) or
            any(not isinstance(route_evidence[key], str) or
                not route_evidence[key].strip() or
                route_evidence[key].startswith('PENDING') for key in active)):
        raise ValueError('public_route_evidence_incomplete')
    original = _source_nodes(base)
    # Every retained legacy node must have the exact audited non-secret shape.
    # No substring selection or guessed chain rewrites are permitted.
    needed_legacy = EXISTING_DIRECT | {'bv_dmit', 'bv_bwh'}
    for key in active & needed_legacy:
        name = EXISTING_SOURCES[key]
        source = original.get(name)
        if not isinstance(source, dict):
            raise ValueError('public_legacy_source_missing_' + key)
        shape = tuple(source.get(field, 'DIRECT') for field in
                      ('type', 'server', 'port', 'dialer-proxy'))
        if shape != EXISTING_SHAPES[key]:
            raise ValueError('public_legacy_source_drift_' + key)
    if set(PUBLIC_NAMES.values()).intersection(original):
        raise ValueError('public_source_name_collision')

    def credential(service: str) -> str:
        return credential_maps[service][sub_secret]

    nodes = {}
    # Public first hops are dedicated, direct, per-user authenticated ports.
    nodes['vps_dmit'] = _anytls(PUBLIC_NAMES['vps_dmit'], 'dmit',
                               '179.255.136.79', 31117, credential('dmit'))
    # Dedicated public routes are candidate ports. Do not release until the
    # matching authenticated listeners and their real exit IPs are verified.
    for key, port in (('nex_dmit', 29510), ('ip2_dmit', 29511),
                      ('ph_dmit', 29512)):
        nodes[key] = _anytls(PUBLIC_NAMES[key], 'dmit',
                            '179.255.136.79', port, credential('dmit'))
    if 'vps_bwh' in active:
        for key, port in (('vps_bwh', 31107), ('kk_bwh', 31108),
                          ('ph_bwh', 31109), ('sg_bwh', 31110),
                          ('nex_bwh', 31111), ('ip2_bwh', 31112)):
            nodes[key] = _anytls(PUBLIC_NAMES[key], 'bwh', '45.78.70.23',
                                 port, credential('bwh'))

    hkt_ancestors = {
        'hkt_dmit': 'vps_dmit', 'hkt_bwh': 'vps_bwh',
    }
    for key, ancestor in hkt_ancestors.items():
        if key not in active:
            continue
        dialer = PUBLIC_NAMES.get(ancestor, ancestor)
        nodes[key] = _hkt(PUBLIC_NAMES[key], credential('hkt'), dialer)

    # This per-user ByteVirt credential is sourced from the existing S-UI
    # merged document and cross-checked with every active legacy relay.
    bytevirt_source = original.get(EXISTING_SOURCES['bv_dmit'])
    if not isinstance(bytevirt_source, dict):
        raise ValueError('public_bytevirt_source_missing')
    bytevirt_password = bytevirt_source.get('password')
    if not isinstance(bytevirt_password, str) or len(bytevirt_password) < 10:
        raise ValueError('public_bytevirt_auth_invalid')
    for key in active & {'bv_bwh'}:
        source = original[EXISTING_SOURCES[key]]
        password = source.get('password')
        if (not isinstance(password, str) or
                not hmac.compare_digest(password, bytevirt_password)):
            raise ValueError('public_bytevirt_auth_mismatch_' + key)
    bytevirt_ancestors = {
        'bv_dmit': 'vps_dmit', 'bv_bwh': 'vps_bwh',
    }
    for key, ancestor in bytevirt_ancestors.items():
        if key not in active:
            continue
        dialer = PUBLIC_NAMES.get(ancestor, ancestor)
        nodes[key] = _bytevirt(bytevirt_source, PUBLIC_NAMES[key], dialer)

    if active.difference(set(nodes) | EXISTING_DIRECT):
        raise ValueError('public_active_routes_unbuilt')
    result = copy.deepcopy(base)
    result.setdefault('proxies', []).extend(nodes.values())
    bindings = {
        key: RouteBinding(
            source_name=(EXISTING_SOURCES[key] if key in EXISTING_DIRECT
                         else PUBLIC_NAMES[key]),
            evidence=route_evidence[key],
        )
        for key in active
    }
    return build_five_group_stage(
        result, bindings=bindings, provider_matches=provider_matches,
        now=now, direct_country=direct_country,
    )
