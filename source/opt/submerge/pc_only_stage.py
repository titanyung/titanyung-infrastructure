"""Pure builder for a PC-only, tunnel-backed five-group subscription.

The caller must serve its result from a separate loopback-only listener. Do
not attach this builder to the public /test/sub path: its new server addresses
are Windows-PC loopback ports, not publicly reachable proxy endpoints.

Every source and its physical-path evidence is explicit. The builder never
guesses that an old NoSLA-to-HKT/ByteVirt relay is NoSLA's own direct exit.
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


# These are exact names in the currently verified 21-node staging mirror.
# A drifted source name fails closed; the function never matches substrings.
EXISTING_SOURCES = {
    'sg_dmit': 'DMIT→LAZYCAT（测试）',
    'ph_dmit': 'DMIT→proxyhive.io（测试）',
    'kk_dmit': 'DMIT→kookey（2027-01-15 01:42到期）-节点',
    'hkt_dmit': 'DMIT→LazyCat HKT',
    'hkt_bwh': 'BWH→LazyCat HKT',
    'hkt_dmit_nosla': 'DMIT→NoSLA→LazyCat HKT',
    'hkt_bwh_nosla': 'BWH→NoSLA→LazyCat HKT',
    'hkt_gomami_nosla': 'GoMami→NoSLA→LazyCat HKT',
    'hkt_nosla': 'NoSLA→LazyCat HKT',
    'bv_dmit': 'DMIT→ByteVirt香港ISP',
    'bv_bwh': 'BWH→ByteVirt香港ISP（11.22到期）',
    'bv_dmit_nosla': 'DMIT→NoSLA→ByteVirt香港ISP',
    'bv_bwh_nosla': 'BWH→NoSLA→ByteVirt香港ISP',
    'bv_gomami_nosla': 'GoMami→NoSLA→ByteVirt香港ISP',
    'bv_nosla': 'NoSLA→ByteVirt香港ISP',
}

# Non-secret shape guard from the 2026-10-18 emitted staging snapshot. It
# complements, but does not replace, the external keyed full-node HMAC check.
EXISTING_SHAPES = {
    'sg_dmit': ('anytls', 'dnode.titanyung.click', 29504, 'DIRECT'),
    'ph_dmit': ('anytls', 'dnode.titanyung.click', 29503, 'DIRECT'),
    'kk_dmit': ('anytls', 'dnode.titanyung.click', 443, 'DIRECT'),
    'hkt_dmit': ('anytls', 'dnode.titanyung.click', 29505, 'DIRECT'),
    'hkt_bwh': ('ss', '45.78.70.23', 31104, 'DIRECT'),
    'hkt_dmit_nosla': ('ss', '179.255.136.79', 31102, 'DIRECT'),
    'hkt_bwh_nosla': ('ss', '45.78.70.23', 31106, 'DIRECT'),
    'hkt_gomami_nosla': ('ss', '216.23.117.226', 2446,
                          'GoMami-新加坡-10.22到期'),
    'hkt_nosla': ('ss', '216.23.117.226', 2446, 'DIRECT'),
    'bv_dmit': ('anytls', 'dnode.titanyung.click', 443, 'DIRECT'),
    'bv_bwh': ('anytls', '45.78.70.23', 2445, 'DIRECT'),
    'bv_dmit_nosla': ('anytls', '179.255.136.79', 31103, 'DIRECT'),
    'bv_bwh_nosla': ('anytls', '45.78.70.23', 31105, 'DIRECT'),
    'bv_gomami_nosla': ('anytls', '216.23.117.226', 2443,
                          'GoMami-新加坡-10.22到期'),
    'bv_nosla': ('anytls', '216.23.117.226', 2443, 'DIRECT'),
}

# These two legacy routes are deliberately replaced by independently
# authenticated PC-only stage nodes; no existing production HKT node is
# required for their operation or their post-expiry lifecycle.
REPLACED_HKT_SOURCES = frozenset({'hkt_dmit', 'hkt_bwh'})

STAGE_SOURCES = {
    'bv_dmit': '__PC-DMIT-ByteVirt',
    'bv_bwh': '__PC-BWH-ByteVirt-noSNI',
    'bv_dmit_nosla': '__PC-DMIT-NoSLA-ByteVirt-noSNI',
    'bv_bwh_nosla': '__PC-BWH-NoSLA-ByteVirt-noSNI',
    'bv_nosla': '__PC-NoSLA-ByteVirt-noSNI',
    'hkt_dmit': '__PC-DMIT-HKT-direct',
    'hkt_bwh': '__PC-BWH-HKT-direct',
    'vps_dmit': '__PC-DMIT-direct',
    'vps_bwh': '__PC-BWH-direct',
    'vps_gomami': '__PC-GoMami-direct',
    'vps_nosla': '__PC-NoSLA-direct',
    'vps_dmit_nosla': '__PC-DMIT-to-NoSLA-direct',
    'vps_bwh_nosla': '__PC-BWH-to-NoSLA-direct',
    'sg_bwh': '__PC-BWH-SG',
    'sg_gomami': '__PC-GoMami-SG',
    'ph_bwh': '__PC-BWH-proxyhive',
    'ph_gomami': '__PC-GoMami-proxyhive',
    'kk_bwh': '__PC-BWH-kookey',
    'kk_gomami': '__PC-GoMami-kookey',
}

if set(EXISTING_SHAPES) != set(EXISTING_SOURCES):
    raise RuntimeError('pc_stage_route_inventory_mismatch')

TLS = {
    'dmit': (
        'dnode.titanyung.click',
        'C0:49:F3:18:B4:AA:D3:11:83:9B:79:99:01:C6:B9:46:'
        'FC:19:4E:FC:E8:F8:A6:99:7D:74:B6:30:51:8B:7A:BE', False,
    ),
    'bwh': (
        'node.titanyungty.top',
        'A5:79:2D:71:B9:21:36:DB:EB:0B:7C:94:45:5F:4E:82:'
        '62:6D:9D:15:1D:B8:FE:BF:A2:17:4E:F5:A4:E1:28:1C', False,
    ),
    'gomami': (
        'node.titanyung.click',
        'F1:BA:58:E7:62:E3:39:ED:02:48:C6:8A:69:54:BC:BC:'
        '78:41:D4:DD:FC:5B:06:39:92:B2:FA:8D:11:63:A9:7A', False,
    ),
    'nosla': (
        'nosla-hk.internal',
        '83:3B:63:CD:42:88:BB:E3:19:30:FF:ED:DD:B9:C5:D5:'
        '82:36:6A:1D:0B:6A:83:62:D3:3F:F7:85:76:32:1F:12', True,
    ),
}

# SHA-256 of the ByteVirt 2443 leaf certificate established by the isolated
# direct-DMIT probe. A changed certificate must fail closed during PC testing.
BYTEVIRT_CERT_FINGERPRINT = (
    '48:24:90:34:21:D0:FA:BE:CE:7F:53:13:2A:EC:55:FB:'
    '32:54:53:0D:DB:95:0D:07:8C:24:5C:0F:5C:CC:8E:0F'
)

HKT_PUBLIC_SERVER = '149.104.4.71'
HKT_PUBLIC_PORT = 31101
HKT_PUBLIC_CIPHER = '2022-blake3-aes-128-gcm'


def _node(name: str, service: str, port: int, password: str,
          *, dialer: Optional[str] = None) -> dict:
    sni, fingerprint, skip_verify = TLS[service]
    if not isinstance(password, str) or len(password) < 24:
        raise ValueError('missing or weak stage credential for ' + service)
    node = {
        'name': name, 'type': 'anytls', 'server': '127.0.0.1',
        'port': port, 'password': password, 'sni': sni,
        'fingerprint': fingerprint, 'skip-cert-verify': skip_verify,
        'udp': False,
    }
    if dialer is not None:
        node['dialer-proxy'] = dialer
    return node


def _hkt_public_node(name: str, password: str, first_hop: str) -> dict:
    if (not isinstance(password, str) or len(password) < 24 or
            ':' not in password):
        raise ValueError('pc_hkt_public_user_credential_invalid')
    return {
        'name': name, 'type': 'ss',
        'server': HKT_PUBLIC_SERVER, 'port': HKT_PUBLIC_PORT,
        'cipher': HKT_PUBLIC_CIPHER, 'password': password,
        'dialer-proxy': first_hop, 'udp': False,
    }


def _pinned_bytevirt_no_sni_node(template: dict, name: str) -> dict:
    """Keep the audited physical route but omit its blocked outer TLS SNI."""
    node = copy.deepcopy(template)
    node['name'] = name
    node.pop('sni', None)
    node['fingerprint'] = BYTEVIRT_CERT_FINGERPRINT
    node['udp'] = False
    return node


def build_pc_only_stage(
    base: dict, *, sub_secret: str,
    credential_maps: Mapping[str, Mapping[str, str]],
    route_evidence: Mapping[str, str],
    provider_matches: Mapping[str, Sequence[ProviderMatch]],
    bwh_nosla_bridge_verified: bool = False,
    hkt_direct_paths_verified: bool = False,
    now: Optional[datetime] = None,
    trial_account: bool = False,
) -> dict:
    """Generate one user's PC-only candidate after merger account isolation.

    `credential_maps` is supplied by a root-only caller. It has per-service
    mappings from DMIT `clients.sub_secret` to fresh *staging* passwords;
    neither source production passwords nor other-user values are used.
    `route_evidence` must attest every currently active route separately.
    The BWH→NoSLA own-egress path is disabled until its separate BWH-local
    restricted forwarding bridge has passed the real hop/egress checks.
    """
    if not isinstance(base, dict):
        raise ValueError('base_document_invalid')
    if trial_account:
        return copy.deepcopy(base)
    if not isinstance(sub_secret, str) or not sub_secret:
        raise ValueError('sub_secret_missing')
    expired = expired_services(now)
    active = {key for key in ALL_KEYS
              if not ROUTE_SERVICES[key].intersection(expired)}
    if active.difference(set(EXISTING_SOURCES) | set(STAGE_SOURCES)):
        raise ValueError('pc_stage_new_routes_require_public_sources')
    if 'vps_bwh_nosla' in active and not bwh_nosla_bridge_verified:
        raise ValueError('bwh_nosla_own_egress_bridge_unverified')
    if active.intersection({'hkt_dmit', 'hkt_bwh'}) and not hkt_direct_paths_verified:
        raise ValueError('hkt_direct_public_paths_unverified')
    if set(route_evidence) & active != active:
        raise ValueError('active_route_evidence_incomplete')
    if any(not isinstance(route_evidence[key], str) or
           not route_evidence[key].strip() for key in active):
        raise ValueError('active_route_evidence_invalid')

    def credential(service: str) -> str:
        mapping = credential_maps.get(service)
        if not isinstance(mapping, Mapping) or sub_secret not in mapping:
            raise ValueError('stage_user_credential_missing_for_' + service)
        return mapping[sub_secret]

    result = copy.deepcopy(base)
    original_nodes = {proxy.get('name'): proxy
                      for proxy in result.get('proxies', [])
                      if isinstance(proxy, dict)}
    original_names = set(original_nodes)
    for key in sorted((set(EXISTING_SOURCES) - REPLACED_HKT_SOURCES) & active):
        node = original_nodes.get(EXISTING_SOURCES[key])
        if node is None:
            raise ValueError('pc_existing_source_missing_for_' + key)
        shape = tuple(node.get(field) for field in
                      ('type', 'server', 'port', 'dialer-proxy'))
        if shape != EXISTING_SHAPES[key]:
            raise ValueError('pc_existing_source_drift_for_' + key)
    if original_names.intersection(STAGE_SOURCES.values()):
        raise ValueError('pc_stage_source_name_collision')
    added = []

    if 'vps_dmit' in active:
        added.append(_node(STAGE_SOURCES['vps_dmit'], 'dmit', 52117,
                           credential('dmit')))
    if active.intersection({'hkt_dmit', 'hkt_bwh'}):
        # Unlike NoSLA's relayed node, this independent per-user HKT map
        # survives NoSLA's expiry. Before that date the audited NoSLA node
        # cross-checks the same public HKT listener's authentication secret.
        hkt_password = credential('hkt')
        if (not isinstance(hkt_password, str) or len(hkt_password) < 24 or
                ':' not in hkt_password):
            raise ValueError('pc_hkt_public_user_credential_invalid')
        if 'hkt_nosla' in active:
            relay = original_nodes.get(EXISTING_SOURCES['hkt_nosla'])
            if (not isinstance(relay, dict) or
                    relay.get('cipher') != HKT_PUBLIC_CIPHER or
                    not isinstance(relay.get('password'), str) or
                    not hmac.compare_digest(relay['password'], hkt_password)):
                raise ValueError('pc_hkt_public_auth_mismatch')
        for key, first_hop_key in (
            ('hkt_dmit', 'vps_dmit'), ('hkt_bwh', 'vps_bwh'),
        ):
            if key in active:
                added.append(_hkt_public_node(
                    STAGE_SOURCES[key], hkt_password,
                    STAGE_SOURCES[first_hop_key],
                ))
    if 'bv_dmit' in active:
        # The old dnode:443 node is destination-routed by DMIT S-UI: only
        # Hong Kong destinations reach ByteVirt, while other destinations
        # reach kookey. The old node remains an audited per-user credential
        # source, but is NEVER emitted as the ByteVirt route. This avoids a
        # runtime dependency on NoSLA after its expiry in September 2027.
        ordinary = original_nodes.get(EXISTING_SOURCES['bv_dmit'])
        if (not isinstance(ordinary, dict) or
                not isinstance(ordinary.get('password'), str) or
                # The current S-UI ByteVirt cohort has 13 valid 10-character
                # passwords and three 18-character passwords. Keep the
                # observed lower bound; exact per-user equality with the
                # NoSLA relay and the full-node HMAC are checked separately.
                len(ordinary['password']) < 10):
            raise ValueError('pc_bytevirt_direct_auth_or_tls_unverified')
        direct_bytevirt = copy.deepcopy(ordinary)
        direct_bytevirt.update({
            'name': STAGE_SOURCES['bv_dmit'],
            'server': '61.15.36.199',
            'port': 2443,
            'tls': True,
            'sni': 'hk.titanyung.internal',
            'skip-cert-verify': True,
            'fingerprint': BYTEVIRT_CERT_FINGERPRINT,
            'dialer-proxy': STAGE_SOURCES['vps_dmit'],
            'udp': False,
        })
        added.append(direct_bytevirt)
        # The four old direct AnyTLS endpoints expose ByteVirt's internal
        # SNI on the PC's network. Read-only isolated Mihomo probes verified
        # that omitting SNI preserves all four ByteVirt exits and TVB access,
        # and that a wrong pinned certificate is rejected. Keep each exact
        # server, port, dialer and per-user password; omit SNI, pin the
        # audited certificate and disable UDP in this PC-only candidate.
        for key in ('bv_bwh', 'bv_dmit_nosla', 'bv_bwh_nosla', 'bv_nosla'):
            if key not in active:
                continue
            old = original_nodes.get(EXISTING_SOURCES[key])
            if (not isinstance(old, dict) or
                    old.get('tls') is not True or
                    old.get('sni') != 'hk.titanyung.internal' or
                    'servername' in old or
                    old.get('skip-cert-verify') is not True or
                    not isinstance(old.get('password'), str) or
                    not hmac.compare_digest(
                        old['password'].encode('utf-8'),
                        ordinary['password'].encode('utf-8'))):
                raise ValueError('pc_bytevirt_direct_auth_or_tls_unverified')
            added.append(_pinned_bytevirt_no_sni_node(
                old, STAGE_SOURCES[key],
            ))
    if 'vps_bwh' in active:
        bwh = credential('bwh')
        for key, port in (
            ('vps_bwh', 52107), ('kk_bwh', 52108),
            ('ph_bwh', 52109), ('sg_bwh', 52110),
        ):
            added.append(_node(STAGE_SOURCES[key], 'bwh', port, bwh))
    if 'vps_gomami' in active:
        gomami = credential('gomami')
        for key, port in (
            ('vps_gomami', 52111), ('kk_gomami', 52112),
            ('ph_gomami', 52113), ('sg_gomami', 52114),
        ):
            added.append(_node(STAGE_SOURCES[key], 'gomami', port, gomami))
    if 'vps_nosla' in active:
        nosla = credential('nosla')
        added.append(_node(STAGE_SOURCES['vps_nosla'], 'nosla', 52250,
                           nosla))
        added.append(_node(
            STAGE_SOURCES['vps_dmit_nosla'], 'nosla', 32150, nosla,
            dialer=STAGE_SOURCES['vps_dmit'],
        ))
        if 'vps_bwh_nosla' in active:
            added.append(_node(
                STAGE_SOURCES['vps_bwh_nosla'], 'nosla', 32150, nosla,
                dialer=STAGE_SOURCES['vps_bwh'],
            ))

    result.setdefault('proxies', []).extend(added)
    bindings = {
        key: RouteBinding(
            source_name=(STAGE_SOURCES.get(key) or EXISTING_SOURCES[key]),
            evidence=route_evidence[key],
        )
        for key in active
    }
    return build_five_group_stage(
        result, bindings=bindings, provider_matches=provider_matches,
        now=now, trial_account=False,
    )
