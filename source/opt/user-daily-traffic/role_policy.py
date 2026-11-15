"""Explicit application-byte role claims for the audited live topology.

This module never calls application counters physical NIC measurements. It
uses verified route classes or exact proxy endpoints, never display names.
"""
from datetime import datetime, timezone
import ipaddress
import re

FIRST_HOPS = frozenset({'DMIT', 'BWH'})
ACTIVE_EXITS = frozenset({'ByteVirt-HK ISP', 'Lazycat-SG', 'Lazycat-HKT'})
ROUTE_PEERS = {
    'bytevirt_taiwan': 'ByteVirt-TW',
    'zorocloud': 'zorocloud',
    'kookeey': 'Kookeey', 'nexip_sg': 'NexIP SG',
    'ip2up': 'ip2up.com', 'proxyhive': 'proxyhive.io',
    'bytevirt_hk_isp': 'ByteVirt-HK ISP', 'lazycat': 'Lazycat-SG',
    'lazycat_hkt': 'Lazycat-HKT',
}
# Non-secret, exact endpoint evidence from the current published topology.
# A changed endpoint must be audited and updated; no domain substring guesses.
RELAY_ENDPOINTS = {
    '[2001:b030:112d:711:11b0::]:2448': 'ByteVirt-TW',
    '2001:b030:112d:711:11b0:::2448': 'ByteVirt-TW',
    '218.208.109.3:2448': 'zorocloud',
    '61.15.36.199:2443': 'ByteVirt-HK ISP',
    '149.104.4.71:31101': 'Lazycat-HKT',
    '216.195.195.125:39873': 'Lazycat-SG',
    '216.195.195.125:28746': 'Lazycat-SG',
    '202.52.109.23:7058': 'NexIP SG',
    '130.12.43.237:1337': 'ip2up.com',
    '178.93.182.237:45224': 'proxyhive.io',
    'sp-us1.kookeey.info:21629': 'Kookeey',
}

try:
    import network_stats as _network_stats
except ImportError:
    _network_stats = None
_NETWORK_MANIFEST = _network_stats.read_optional_manifest() if _network_stats else None
if _NETWORK_MANIFEST:
    ACTIVE_EXITS = ACTIVE_EXITS | frozenset(_network_stats.ACTIVE_HOSTS[1:])
    if _network_stats.is_revision(_NETWORK_MANIFEST):
        FIRST_HOPS = FIRST_HOPS | frozenset({'Lazycat-SG-Front'})
        ACTIVE_EXITS = frozenset(_network_stats.active_host_names(_NETWORK_MANIFEST)) - frozenset({'DMIT','Lazycat-SG-Front'})
        for _route,_peer in _network_stats.POOL_CLASSES.values():
            ROUTE_PEERS[_route] = _peer
    for _spec in _NETWORK_MANIFEST['verified_routes']:
        ROUTE_PEERS[_spec['route_class']] = _spec['host']
        _endpoint = _spec['server'].lower() + ':' + str(_spec['server_port'])
        RELAY_ENDPOINTS[_endpoint] = _spec['host']
        try:
            if ipaddress.ip_address(_spec['server']).version == 6:
                RELAY_ENDPOINTS['[' + _spec['server'].lower() + ']:' + str(_spec['server_port'])] = _spec['host']
        except ValueError:
            pass


def iso_created_ms(value):
    if not isinstance(value, str):
        raise ValueError('invalid source start time')
    # Go emits nanoseconds; Python 3.8-3.10 accepts at most microseconds.
    value = re.sub(r'(\.\d{6})\d+(?=(?:Z|[+-]\d\d:\d\d)?$)', r'\1', value)
    stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if stamp.tzinfo is None:
        raise ValueError('source start time has no zone')
    delta = stamp.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1000 + delta.microseconds // 1000


def _claim(role, peer, source, basis, estimated=False, priority=100, zero=False):
    return dict(role=role, peer=peer, source=source, meter_basis=basis,
                estimated=bool(estimated), priority=priority, zero=bool(zero))


def roles_for_route(host, route_class, destination='', source='sui-session-poll',
                    *, exit_observation=False, relay_endpoints=None):
    """Return claims for one proven application stream.

    Forwarder egress is explicitly an estimate of bytes sent via that exit,
    not a second sensor on the residential provider. A real exit observer has
    priority 200 and contributes only egress, never another first hop.
    """
    if exit_observation:
        if host not in ACTIVE_EXITS:
            raise ValueError('unapproved or retired exit observer')
        return [_claim('egress', host, source, 'exit_observed_application', priority=200)]
    if host not in FIRST_HOPS:
        raise ValueError('unapproved or retired first hop')
    claims = [_claim('ingress', host, source, 'authenticated_inbound_application')]
    if route_class in ('reject', 'block'):
        claims.extend([
            _claim('relay', host, source, 'confirmed_reject_no_relay', zero=True),
            _claim('egress', host, source, 'confirmed_reject_no_egress', zero=True),
        ])
        return claims
    peer = ROUTE_PEERS.get(route_class)
    if route_class == 'direct':
        endpoints = RELAY_ENDPOINTS if relay_endpoints is None else relay_endpoints
        peer = endpoints.get(str(destination).lower())
        if peer is None:
            claims.extend([
                _claim('relay', host, source, 'confirmed_direct_no_relay', zero=True),
                _claim('egress', host, source, 'direct_destination_application'),
            ])
            return claims
    if peer:
        claims.extend([
            _claim('relay', peer, source, 'confirmed_proxy_forwarding_application'),
            _claim('egress', peer, source, 'forwarded_application', estimated=True),
        ])
    # Unclassified routes contribute a proven first hop only. The adapter must
    # also record a coverage gap; missing relay/egress never becomes zero.
    return claims


def routes_for_config(config):
    """Normalize non-secret outbound shapes from the actual runtime config."""
    if _network_stats and any(row.get('tag') in _network_stats.POLICY_EXCLUSIVE_FRONTS
            for row in config.get('inbounds', []) if isinstance(row, dict)) and not _network_stats.server_policy_enabled(_NETWORK_MANIFEST):
        raise ValueError('observed server policy lacks statistics manifest guard')
    routes = {}
    for outbound in config.get('outbounds', []):
        tag, kind = outbound.get('tag'), outbound.get('type')
        if not isinstance(tag, str) or not tag:
            continue
        server = str(outbound.get('server') or '').lower()
        port = str(outbound.get('server_port') or '')
        endpoint = server + ':' + port
        if kind == 'direct':
            routes[tag] = 'direct'
        elif kind in ('block', 'reject'):
            routes[tag] = 'reject'
        elif kind == 'socks' and endpoint == '202.52.109.23:7058':
            routes[tag] = 'nexip_sg'
        elif kind in ('socks', 'http') and endpoint == '130.12.43.237:1337':
            routes[tag] = 'ip2up'
        elif kind in ('socks', 'http') and endpoint == '178.93.182.237:45224':
            routes[tag] = 'proxyhive'
        elif kind == 'socks' and endpoint == 'sp-us1.kookeey.info:21629':
            routes[tag] = 'kookeey'
        elif kind == 'anytls' and endpoint == '61.15.36.199:2443':
            routes[tag] = 'bytevirt_hk_isp'
        elif kind == 'shadowsocks' and endpoint in ('216.195.195.125:39873', '216.195.195.125:28746'):
            routes[tag] = 'lazycat'
        elif kind == 'shadowsocks' and endpoint == '149.104.4.71:31101':
            routes[tag] = 'lazycat_hkt'
        elif kind == 'shadowsocks' and endpoint == '218.208.109.3:2448':
            routes[tag] = 'zorocloud'
        elif kind == 'shadowsocks' and port == '2448':
            try:
                if ipaddress.ip_address(server) == ipaddress.ip_address('2001:b030:112d:711:11b0::'):
                    routes[tag] = 'bytevirt_taiwan'
            except ValueError:
                pass
    if _NETWORK_MANIFEST:
        expected = {item['outbound_tag']: item for item in _NETWORK_MANIFEST['verified_routes']
                    if item['outbound_tag'] is not None}
        for outbound in config.get('outbounds', []):
            spec = expected.get(outbound.get('tag'))
            if spec is None:
                continue
            if any(outbound.get(key) != spec[key] for key in ('type', 'server', 'server_port')):
                raise ValueError('verified relay endpoint differs')
            routes[outbound['tag']] = spec['route_class']
        if _network_stats.server_policy_enabled(_NETWORK_MANIFEST) and any(
                row.get('tag') in _network_stats.SERVER_POLICY_FRONTS
                for row in config.get('inbounds', []) if isinstance(row, dict)):
            # A managed policy runtime must present the complete audited
            # actual-outbound contract; inlet labels are never exit evidence.
            routes.update(_network_stats.runtime_route_classes(config, _NETWORK_MANIFEST))
    return routes


def sui_observations(connections, normalized_rows, host):
    """Use only users already proven by the existing S-UI collector."""
    raw = {str(item.get('id')): item for item in connections if isinstance(item, dict)}
    observations, unclassified = [], []
    for row in normalized_rows:
        uid = str(row[0])
        if not uid.startswith('sui:'):
            continue
        uid = uid[4:]
        item = raw.get(uid)
        if not item:
            continue
        claims = roles_for_route(host, row[12], row[3])
        if len(claims) == 1:
            unclassified.append(str(row[1]))
        observations.append(dict(host=host, runtime='sui', connection_id=uid,
            created_at_ms=iso_created_ms(item['start']), user=str(row[1]),
            upload=int(item['upload']), download=int(item['download']),
            closed=False, roles=claims))
    return observations, unclassified
