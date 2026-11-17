"""Offline X routing checks against the checked-in source snapshot."""
from __future__ import annotations

from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parents[1] / 'source' / 'opt'
sys.path[:0] = [str(HERE), str(SOURCE / 'submerge-routing'),
                str(SOURCE / 'submerge-client-policy')]

import client_fixture
import client_policy
import routing_client_v4 as client_v4
import routing_contract
import server_route_policy as server

new_topology = types.ModuleType('new_topology')
new_topology.ALL = '🌐 全部节点'
new_topology.PLAN_GOOGLE = '🤖 chatgpt、claude、google（不含youtube）'
new_topology.PLAN_YOUTUBE_SUFFIXES = ('youtube.com', 'youtu.be')
new_topology.UDP_FALLBACK_GUARD = 'NETWORK,UDP,REJECT'
new_topology.PLAN_ROUTE_NAMES = {key: key for key in client_policy.SITES}
X_SUFFIXES = ('x.com', 'twitter.com', 'twimg.com', 't.co')


class XAiRouteTests(unittest.TestCase):
    def setUp(self):
        # Only the legacy display constants are synthetic. Policy generation
        # and validation run through the real checked-in modules.
        topology_patch = patch.dict(sys.modules, {'new_topology': new_topology})
        topology_patch.start()
        self.addCleanup(topology_patch.stop)

    def test_server_routes_x_before_geographic_fallback(self):
        self.assertEqual(server.X_SUFFIXES, X_SUFFIXES)
        contract = client_fixture.routing_contract()
        incoming = [{'tag': tag, 'users': []} for tag in
                    ('dmit-direct-stage', 'mobile-dmit-direct',
                     'dmit-starhub', 'mobile-dmit-singtel')]
        rules = server._rules(contract, incoming, [], [])
        youtube = next(i for i, row in enumerate(rules)
                       if row.get('rule_set') == ['server-youtube'])
        hk_ip = next(i for i, row in enumerate(rules)
                     if row.get('rule_set') == ['server-hk-ip'])
        last = next(i for i, row in enumerate(rules)
                    if row.get('network') == ['tcp'] and row.get('outbound') == 'business-other')
        for tag, target in (('dmit-direct-stage', 'business-ai-desktop'),
                            ('mobile-dmit-direct', 'business-ai-mobile'),
                            ('dmit-starhub', 'business-ai-lazycat'),
                            ('mobile-dmit-singtel', 'business-ai-singtel')):
            with self.subTest(tag=tag):
                matched = [(i, row) for i, row in enumerate(rules)
                           if row.get('inbound') == [tag]
                           and row.get('domain_suffix') == list(X_SUFFIXES)]
                self.assertEqual(len(matched), 1)
                position, row = matched[0]
                self.assertEqual(row['outbound'], target)
                self.assertLess(youtube, position)
                self.assertLess(position, hk_ip)
                self.assertLess(position, last)
        resolve = next(i for i, row in enumerate(rules) if row.get('action') == 'resolve')
        for host in server.X_EXACT_DOMAINS:
            with self.subTest(exact_host=host):
                corrected = [i for i, row in enumerate(rules)
                             if row.get('action') == 'route-options'
                             and row.get('domain') == [host]
                             and row.get('override_address') == host]
                self.assertEqual(len(corrected), 1)
                self.assertLess(corrected[0], resolve)

    def test_client_projects_x_to_ai_without_changing_device_default_or_retirement(self):
        cutoff = routing_contract.UZUMA_HKT_RETIRE_AT
        for kind in ('mobile', 'desktop', 'router'):
            for epoch in (cutoff - 1, cutoff):
                with self.subTest(kind=kind, epoch=epoch):
                    profile, inputs = client_fixture.projection_inputs(kind=kind, as_of=epoch)
                    profile['rules'] = client_policy.simplified_rules(profile)
                    rendered = client_v4.project_profile(profile, **inputs)
                    ai = client_v4.GROUP_IDS['ai']
                    for suffix in X_SUFFIXES:
                        self.assertIn('DOMAIN-SUFFIX,' + suffix + ',' + ai, rendered['rules'])
                    youtube = 'DOMAIN-SUFFIX,youtube.com,' + client_v4.GROUP_IDS['other']
                    self.assertIn(youtube, rendered['rules'])
                    self.assertLess(rendered['rules'].index(youtube),
                                    rendered['rules'].index('DOMAIN-SUFFIX,x.com,' + ai))
                    self.assertLess(rendered['rules'].index('DOMAIN-SUFFIX,x.com,' + ai),
                                    rendered['rules'].index('GEOSITE,cn,DIRECT'))
                    groups = {row['name']: row for row in rendered['proxy-groups']}
                    preferred = 'singtel' if kind == 'mobile' else 'lazycat_starhub'
                    self.assertEqual(groups[client_v4.AI_DEFAULT]['proxies'][0],
                                     client_v4.ROUTE_LABELS['lc_' + preferred])
                    hkt = client_v4.ROUTE_LABELS['dmit_uzuma_hkt']
                    self.assertEqual(hkt in {row['name'] for row in rendered['proxies']},
                                     epoch < cutoff)
                    self.assertEqual(server.selection_orders(inputs['routing_contract'])['other'][0],
                                     'bytevirt-hk')

    def test_test_subscription_keeps_explicit_route_semantics(self):
        cutoff = routing_contract.UZUMA_HKT_RETIRE_AT
        for kind in ('mobile', 'desktop', 'router'):
            for epoch in (cutoff - 1, cutoff):
                with self.subTest(kind=kind, epoch=epoch):
                    profile, inputs = client_fixture.projection_inputs(
                        kind=kind, as_of=epoch, test_mode=True)
                    profile['rules'] = client_policy.simplified_rules(profile, test_mode=True)
                    rendered = client_v4.project_profile(profile, **inputs)
                    self.assertFalse(any(rule.startswith('DOMAIN-SUFFIX,' + suffix + ',')
                                         for suffix in X_SUFFIXES for rule in rendered['rules']))
                    groups = {row['name']: row for row in rendered['proxy-groups']}
                    self.assertEqual(groups[client_v4.GROUP_IDS['all']]['default-selected'],
                                     client_v4.ROUTE_LABELS['dmit'])


if __name__ == '__main__':
    unittest.main()
