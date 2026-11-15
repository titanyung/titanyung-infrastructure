"""Exact, test-account-only retirement plus one corrected BWH date label.

The trial account has six legacy nodes, unlike the 27 public ordinary-user
routes. Dependencies here were audited against its actual 2026-10-18 merged
profile. No name substring heuristic or new proxy credential is used.
"""

from __future__ import annotations

import copy
from datetime import datetime
from typing import Optional

from expiry_policy import expired_services


OLD_BWH_LABEL = 'BWH→ByteVirt香港ISP（11.22到期）'
NEW_BWH_LABEL = 'BWH→ByteVirt香港ISP（2026-11-24到期）'
NODE_SHAPES = {
    'DMIT→proxyhive.io（测试）': ('anytls', 'dnode.titanyung.click', 29503, 'DIRECT'),
    'DMIT→LAZYCAT（测试）': ('anytls', 'dnode.titanyung.click', 29504, 'DIRECT'),
    'DMIT→LazyCat HKT': ('anytls', 'dnode.titanyung.click', 29505, 'DIRECT'),
    '备用-LA': ('anytls', 'node.titanyungty.top', 443, 'DIRECT'),
    'NoSLA→ByteVirt香港ISP': ('anytls', '216.23.117.226', 2443, 'DIRECT'),
    NEW_BWH_LABEL: ('anytls', '45.78.70.23', 2445, 'DIRECT'),
}
NODE_SERVICES = {
    'DMIT→proxyhive.io（测试）': frozenset({'proxyhive'}),
    'DMIT→LAZYCAT（测试）': frozenset({'lazycat_sg'}),
    'DMIT→LazyCat HKT': frozenset({'lazycat_hkt'}),
    '备用-LA': frozenset({'bwh'}),
    'NoSLA→ByteVirt香港ISP': frozenset({'nosla'}),
    NEW_BWH_LABEL: frozenset({'bwh'}),
}
BWH_ONLY_GROUPS = frozenset({'BWH', '备用-BWHLA'})
BUILTIN = frozenset({'DIRECT', 'REJECT', 'REJECT-DROP', 'PASS'})
TRIAL_GROUP_TARGETS = {
    # The test account still has its legacy selectors, not the public five
    # groups. Translate only new canonical rule targets for this account.
    # This legacy HK selector contains NoSLA/BWH ByteVirt options, but defaults
    # to HKT. It is a compatibility target, not the public six-route selector.
    'google全系 & AI': 'AI工具',
    '🤖 谷歌全系 & AI': 'AI工具',
    'HK&HK流媒体': '大陆-TVB→解锁TVB',
    '🇭🇰 HK&HK流媒体': '大陆-TVB→解锁TVB',
    '非中国大陆&HK流媒体的流媒体': '大陆-TVB→解锁TVB',
    '🎬 非中国大陆&HK流媒体的流媒体': '大陆-TVB→解锁TVB',
    'VPS访问': '全部节点',
    '🖥️ VPS访问': '全部节点',
    '非中国大陆的其他': '全部节点',
    '🌍 非中国大陆的其他': '全部节点',
    '🌐 全部节点': '全部节点',
}


def _rule_target(rule: str) -> str:
    parts = rule.split(',')
    if len(parts) < 2:
        raise ValueError('trial_rule_invalid')
    return parts[-2] if parts[-1] == 'no-resolve' else parts[-1]


def _trial_rule_target(rule: str) -> str:
    parts = rule.split(',')
    if len(parts) < 2:
        return rule
    target_index = -2 if parts[-1] == 'no-resolve' else -1
    replacement = TRIAL_GROUP_TARGETS.get(parts[target_index])
    if replacement is None:
        return rule
    parts[target_index] = replacement
    return ','.join(parts)


def prune_trial_profile(base: dict, *, now: Optional[datetime] = None) -> dict:
    expired = expired_services(now)
    if not isinstance(base, dict):
        raise ValueError('trial_profile_invalid')
    # Correct the legacy BWH label's wrong 11.22 date. Its server, port,
    # authentication and all routing parameters remain untouched.
    present = {node.get('name') for node in base.get('proxies', [])
               if isinstance(node, dict)}
    if OLD_BWH_LABEL in present and NEW_BWH_LABEL in present:
        raise ValueError('trial_bwh_label_collision')
    if any(not isinstance(rule, str) or _rule_target(rule) in
           {OLD_BWH_LABEL, NEW_BWH_LABEL}
           for rule in base.get('rules', [])):
        raise ValueError('trial_bwh_direct_rule_target_drift')
    if OLD_BWH_LABEL in present:
        normalized = copy.deepcopy(base)
        for node in normalized['proxies']:
            if node.get('name') == OLD_BWH_LABEL:
                node['name'] = NEW_BWH_LABEL
        for group in normalized.get('proxy-groups', []):
            group['proxies'] = [NEW_BWH_LABEL if member == OLD_BWH_LABEL
                                else member for member in group['proxies']]
    else:
        normalized = base
    source_rules = normalized.get('rules')
    if isinstance(source_rules, list):
        compatible_rules = [_trial_rule_target(rule) if isinstance(rule, str)
                            else rule for rule in source_rules]
        if compatible_rules != source_rules:
            required_groups = {
                TRIAL_GROUP_TARGETS[_rule_target(rule)]
                for rule in source_rules if isinstance(rule, str) and ',' in rule
                and _rule_target(rule) in TRIAL_GROUP_TARGETS
            }
            groups = normalized.get('proxy-groups')
            available = ({group.get('name') for group in groups
                          if isinstance(group, dict)}
                         if isinstance(groups, list) else set())
            if not required_groups.issubset(available):
                raise ValueError('trial_compat_group_missing')
            normalized = copy.deepcopy(normalized)
            normalized['rules'] = compatible_rules
    if not expired.intersection({'bwh', 'nosla', 'proxyhive',
                                 'lazycat_sg', 'lazycat_hkt'}):
        return normalized
    source_nodes = normalized.get('proxies')
    source_groups = normalized.get('proxy-groups')
    rules = normalized.get('rules')
    if not all(isinstance(value, list) for value in
               (source_nodes, source_groups, rules)):
        raise ValueError('trial_profile_sections_invalid')
    nodes = {}
    for node in source_nodes:
        if not isinstance(node, dict) or not isinstance(node.get('name'), str):
            raise ValueError('trial_node_invalid')
        if node['name'] in nodes:
            raise ValueError('trial_node_duplicate')
        nodes[node['name']] = node
    if set(nodes) != set(NODE_SHAPES):
        raise ValueError('trial_node_inventory_drift')
    for name, node in nodes.items():
        actual = (node.get('type'), node.get('server'), node.get('port'),
                  node.get('dialer-proxy', 'DIRECT'))
        if actual != NODE_SHAPES[name]:
            raise ValueError('trial_node_shape_drift')
    groups = {}
    for group in source_groups:
        if (not isinstance(group, dict) or not isinstance(group.get('name'), str)
                or group['name'] in groups or
                not isinstance(group.get('proxies'), list)):
            raise ValueError('trial_group_invalid')
        groups[group['name']] = group
    if '全部节点' not in groups or '大陆-TVB→解锁TVB' not in groups:
        raise ValueError('trial_required_group_missing')
    for name in BWH_ONLY_GROUPS:
        if name not in groups or groups[name]['proxies'] != ['备用-LA']:
            raise ValueError('trial_bwh_only_group_drift')
    references = {(group['name'], member)
                  for group in source_groups for member in group['proxies']
                  if member in BWH_ONLY_GROUPS | {NEW_BWH_LABEL, '备用-LA'}}
    expected_references = {
        ('全部节点', '备用-BWHLA'),
        ('全部节点', NEW_BWH_LABEL),
        ('大陆-TVB→解锁TVB', NEW_BWH_LABEL),
        ('BWH', '备用-LA'), ('备用-BWHLA', '备用-LA'),
    }
    if references != expected_references:
        raise ValueError('trial_bwh_reference_drift')
    if any(not isinstance(rule, str) or
           _rule_target(rule) in BWH_ONLY_GROUPS | {NEW_BWH_LABEL, '备用-LA'}
           for rule in rules):
        raise ValueError('trial_bwh_rule_target_drift')
    retired_nodes = frozenset(name for name, services in NODE_SERVICES.items()
                              if services.intersection(expired))
    retired_groups = BWH_ONLY_GROUPS if 'bwh' in expired else frozenset()
    result = copy.deepcopy(normalized)
    result['proxies'] = [node for node in result['proxies']
                         if node['name'] not in retired_nodes]
    result['proxy-groups'] = [group for group in result['proxy-groups']
                              if group['name'] not in retired_groups]
    names = {node['name'] for node in result['proxies']}
    names.update(group['name'] for group in result['proxy-groups'])
    for group in result['proxy-groups']:
        group['proxies'] = [member for member in group['proxies']
                            if member not in retired_nodes and
                            member not in retired_groups]
        if not group['proxies'] or any(member not in names | BUILTIN
                                      for member in group['proxies']):
            raise ValueError('trial_group_dangling_after_expiry')
    if any(not isinstance(rule, str) or _rule_target(rule) not in names | BUILTIN
           for rule in rules):
        raise ValueError('trial_rule_dangling_after_expiry')
    return result
