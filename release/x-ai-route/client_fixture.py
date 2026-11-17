"""Synthetic inputs for offline tests; never use them as deployment defaults.

No files, providers or network services are accessed. The canonical DMIT IP
matches the source renderer's required transport identity; 1.1.1.1 only meets
its literal-global-IP validation. Neither address is contacted by these tests.
All names, passwords, pins, pool ports and cache contents below are fixtures.
"""
from __future__ import annotations

import routing_client_v4 as client_v4
import routing_contract as contract_module


DMIT_SERVER = '179.255.136.79'
FRONTEND_IP = '1.1.1.1'
FIXTURE_PASSWORD = 'REPLACE_OFFLINE_FIXTURE_PASSWORD'
FIXTURE_PIN = '0' * 64
DEFAULT_AS_OF = contract_module.UZUMA_HKT_RETIRE_AT - 3600


def _sites():
    return {
        key: {'url': 'https://' + key.replace('_', '-') + '.route-fixture.invalid/',
              'domains': [key.replace('_', '-') + '.route-fixture.invalid']}
        for key in client_v4.ROUTE_PAIRS
    }


def routing_contract(*, as_of=DEFAULT_AS_OF):
    """Return a fresh strict contract, including all twelve IP-test routes."""
    sites = _sites()
    return contract_module.validate({
        'schema': 1,
        'id': contract_module.REVISION,
        'as_of': as_of,
        # Keep other retirements separate from the HKT boundary under test.
        'taiwan_retire_at': contract_module.UZUMA_HKT_RETIRE_AT + 86400,
        'lazycat_hkt_retire_at': contract_module.UZUMA_HKT_RETIRE_AT + 172800,
        'pools': {region: {'server': '127.0.0.1', 'server_port': 18080 + index}
                  for index, region in enumerate(('SG', 'HK', 'ALL'), start=1)},
        'ip_tests': [
            {'front': front, 'outbound': outbound, 'domains': sites[key]['domains']}
            for key, (front, outbound) in client_v4.ROUTE_PAIRS.items()
        ],
        'vps_domains': {provider: [provider + '.vps-fixture.invalid']
                        for provider in contract_module.PROVIDERS},
        'mytvsuper_domains': ['tv.fixture.invalid'],
        'hk_domains': ['hk.fixture.invalid'],
        'remote_domains': ['remote.fixture.invalid'],
        'test_users': ['route-fixture-user'],
        'protected_endpoints': [{'server': DMIT_SERVER, 'server_port': 443}],
    })


def projection_inputs(*, kind='mobile', as_of=DEFAULT_AS_OF, test_mode=False):
    """Build independent client, transport, airport and contract input graphs."""
    profile = {
        'x-submerge-client-kind': kind,
        'x-submerge-manual-test': test_mode,
        'x-submerge-server-policy': 'dmit-domain-routing-20261106',
        'proxies': [{
            'name': 'fixture-canonical-dmit', 'type': 'anytls',
            'server': DMIT_SERVER, 'port': 30000,
            'password': FIXTURE_PASSWORD, 'tls': True,
            'sni': 'dmit.fixture.invalid', 'fingerprint': FIXTURE_PIN,
            'skip-cert-verify': False,
        }],
        'proxy-groups': [],
        'rules': ['IP-CIDR,10.0.0.0/8,DIRECT,no-resolve',
                  'GEOSITE,cn,DIRECT', 'GEOIP,CN,DIRECT', 'NETWORK,UDP,REJECT'],
    }
    settings = {
        'public_ip': FRONTEND_IP,
        'server_name': 'edge.fixture.invalid',
        'certificate_fingerprint': FIXTURE_PIN,
        'public_ports': {'starhub': 31101, 'singtel': 31102},
        'dmit_public_ports': {'starhub': 31201, 'singtel': 31202},
        'manual_settings': {
            'certificate_fingerprint': FIXTURE_PIN,
            'server_names': {'lazycat_starhub': 'lazycat.fixture.invalid',
                             'uzuma_starhub': 'uzuma.fixture.invalid'},
            'dmit_public_ports': {'lazycat_starhub': 31301, 'uzuma_starhub': 31302},
            'lazycat_public_ports': {'lazycat_starhub': 31401, 'uzuma_starhub': 31402},
        },
    }
    nodes = [
        {'name': 'fixture-' + region, 'type': 'ss',
         'server': region + '.airport-fixture.invalid', 'port': 8443,
         'cipher': 'aes-128-gcm', 'password': FIXTURE_PASSWORD}
        for region in ('sg', 'hk')
    ]
    airport_cache = {
        'proxies': nodes,
        'proxy-groups': [{'name': 'fixture-auto', 'type': 'url-test',
                          'proxies': [node['name'] for node in nodes],
                          'url': 'https://health.fixture.invalid/', 'interval': 60}],
        'provider_auto_roots': ['fixture-auto'],
        'region_members': {'SG': ['fixture-sg'], 'HK': ['fixture-hk'],
                           'ALL': ['fixture-sg', 'fixture-hk']},
    }
    front_bindings = {
        role: {
            platform: {
                key: {'server': DMIT_SERVER,
                      'port': 32000 + role_index * 1000 + platform_index * 100 + index,
                      'sni': 'dmit.fixture.invalid', 'fingerprint': FIXTURE_PIN,
                      'skip-cert-verify': False}
                for index, key in enumerate(client_v4.DMIT_BOUND)
            }
            for platform_index, platform in enumerate(('mobile', 'desktop', 'router'))
        }
        for role_index, role in enumerate(('ordinary', 'test'))
    }
    return profile, {
        'settings': settings,
        'routing_contract': routing_contract(as_of=as_of),
        'airport_cache': airport_cache,
        'sites': _sites(),
        'as_of': as_of,
        'front_bindings': front_bindings,
        'test_mode': test_mode,
    }
