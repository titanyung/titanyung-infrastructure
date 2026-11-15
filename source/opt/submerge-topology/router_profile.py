"""Candidate only: explicit airport cards for older dashboard proxy maps.

No fetches or side effects. Input must be the verified replacement topology,
not an arbitrary legacy profile. The HTTP provider and hidden automatic graph
remain authoritative for health and airport-priority fallback.
"""
import copy

from new_topology import (GOOGLE, HK, VPS, STREAMING, OTHER, CHINA,
                          DMIT, BYTEVIRT, TAIWAN, AIRPORT_AUTO, BUILTINS,
                          PLAN_VERSION, PLAN_ROUTE_NAMES, PLAN_PAOLUZ, AIRPORT_FAST,
                          validate_network_profile)


def _mirror_network_backup(profile, provider):
    # Validate the old materialization independently of the newly refreshed
    # cache, so removed airport nodes can be replaced without retaining them.
    validate_network_profile(profile)
    output = copy.deepcopy(profile)
    groups = {item['name']: item for item in output['proxy-groups']}
    indexed = {node['name']: node for node in output['proxies']}
    own_names = set(PLAN_ROUTE_NAMES.values()) | set(groups[CHINA]['proxies'])
    pending = list(own_names)
    while pending:
        dialer = indexed[pending.pop()].get('dialer-proxy')
        if dialer and dialer != 'DIRECT' and dialer not in own_names:
            own_names.add(dialer)
            pending.append(dialer)
    reserved = own_names | set(groups) | set(BUILTINS)
    nodes = provider.get('proxies')
    if not isinstance(nodes, list):
        raise ValueError('provider_proxy_list_required')
    names = []
    for node in nodes:
        if (not isinstance(node, dict) or not isinstance(node.get('name'), str)
                or not node['name'] or not isinstance(node.get('type'), str)):
            raise ValueError('provider_node_identity_invalid')
        if node['name'] in reserved or node['name'] in names:
            raise ValueError('provider_node_name_collision')
        names.append(node['name'])
    backup = groups[PLAN_PAOLUZ]
    backup.pop('use', None)
    backup['proxies'] = [AIRPORT_FAST, *names]
    output['proxies'] = [node for node in output['proxies'] if node['name'] in own_names] + copy.deepcopy(nodes)
    validate_network_profile(output, provider)
    return output


def mirror_airport_into_visible_groups(profile, provider):
    if not isinstance(profile, dict) or not isinstance(provider, dict):
        raise ValueError('profile_and_provider_required')
    if profile.get('x-submerge-plan') == PLAN_VERSION:
        return _mirror_network_backup(profile, provider)
    output = copy.deepcopy(profile)
    groups = {item['name']: item for item in output.get('proxy-groups', [])}
    if len(groups) != len(output.get('proxy-groups', [])):
        raise ValueError('duplicate_group_name')
    try:
        google = groups[GOOGLE]['proxies']
        if not isinstance(google, list) or len(google) not in (2, 3):
            raise ValueError('replacement_ai_topology_required')
        zoro, dmit = google[0], google[-1]
        after_zoro = google[1:-1]
        if (dmit != DMIT or not isinstance(zoro, str) or 'DMIT→zorocloud' not in zoro
                or after_zoro not in ([], [TAIWAN])):
            raise ValueError('replacement_ai_topology_required')
        if (groups[HK]['proxies'] != [BYTEVIRT] or
                groups[VPS]['proxies'] != [dmit, BYTEVIRT, zoro, *after_zoro]):
            raise ValueError('replacement_vps_topology_required')
        directs = groups[CHINA]['proxies']
        if len(directs) != 1:
            raise ValueError('replacement_direct_topology_required')
    except (KeyError, TypeError):
        raise ValueError('replacement_topology_required') from None
    wanted = {dmit, BYTEVIRT, zoro, *after_zoro, directs[0]}
    by_name = {item['name']: item for item in output.get('proxies', [])}
    if len(by_name) != len(output.get('proxies', [])) or not wanted.issubset(by_name):
        raise ValueError('own_proxy_inventory_invalid')
    own = [item for item in output['proxies'] if item['name'] in wanted]
    # Reapplying to a previously mirrored profile discards stale airport nodes.
    # Only these current verified own routes and the new cache survive.
    reserved = wanted | set(groups) | set(BUILTINS)
    nodes = provider.get('proxies')
    if not isinstance(nodes, list):
        raise ValueError('provider_proxy_list_required')
    names = []
    for node in nodes:
        if (not isinstance(node, dict) or not isinstance(node.get('name'), str)
                or not node['name'] or not isinstance(node.get('type'), str)):
            raise ValueError('provider_node_identity_invalid')
        name = node['name']
        if name in reserved or name in names:
            raise ValueError('provider_node_name_collision')
        names.append(name)
    prefix = [AIRPORT_AUTO, zoro, *after_zoro]
    for name in (STREAMING, OTHER):
        group = groups[name]
        if (group.get('type') != 'select' or group.get('proxies', [])[:len(prefix)] != prefix
                or group.get('use', ['paoluz']) != ['paoluz']):
            raise ValueError('visible_airport_group_shape_changed')
        group.pop('use', None)
        group['proxies'] = [*prefix, *names]
    output['proxies'] = own + copy.deepcopy(nodes)
    return output
