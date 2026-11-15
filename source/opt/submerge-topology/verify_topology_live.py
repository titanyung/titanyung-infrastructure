#!/usr/bin/env python3
"""Probe the three routes in a private Mihomo instance; never edits production.

Run on DMIT with the existing Submerge environment loaded.  --server-port
points provider downloads at an already running local candidate server.  A
stage direct/zoro port also defaults that node's endpoint to 127.0.0.1.
The probe disables its own DNS listener and uses the system resolver; this
tests route transport/egress, not client DNS leak behavior.
"""
import argparse
import copy
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, '/opt/submerge')
sys.path.insert(0, str(HERE))

DEFAULT_CORE = '/var/lib/submerge-staging/mihomo-v1.19.32-stage'
DEFAULT_GEODATA = '/root/china-direct-repair-20261027/geodata'
TRACE_URL = 'https://www.cloudflare.com/cdn-cgi/trace'


class ProbeFailure(Exception):
    pass


def require(condition, label):
    if not condition:
        raise ProbeFailure(label)


def unused_port(port):
    require(type(port) is int and 1 <= port <= 65535, 'invalid_isolated_port')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(('127.0.0.1', port))


def selected_identity(topology, username):
    ordinary, trial = topology.auth._ordinary_accounts()
    ready = topology.auth._private_json(topology.auth.READY_PATH)['users']
    matches = [identity for identity in ordinary if ready.get(identity) == username]
    if username == 'test' and trial is not None:
        matches = [trial]
    require(len(matches) == 1, 'probe_identity_not_available')
    return matches[0]


def isolate_profile(profile, identity, folder, args, controller_secret):
    from new_topology import DMIT, BYTEVIRT
    profile = copy.deepcopy(profile)
    proxies = {node['name']: node for node in profile['proxies']}
    zoro_names = [name for name in proxies if name.replace(' ', '').endswith('DMIT→zorocloud')]
    require(len(zoro_names) == 1 and DMIT in proxies and BYTEVIRT in proxies,
            'three_verified_routes_missing')
    for name, port, host in ((DMIT, args.direct_port, args.direct_host),
                             (zoro_names[0], args.zoro_port, args.zoro_host)):
        if port is not None:
            require(1 <= port <= 65535, 'invalid_stage_listener')
            proxies[name]['port'] = port
            proxies[name]['server'] = host or '127.0.0.1'
        elif host is not None:
            proxies[name]['server'] = host
    for key in ('port', 'socks-port', 'redir-port', 'tproxy-port'):
        profile[key] = 0
    profile.update({'mixed-port': args.mixed_port,
                    'external-controller': '127.0.0.1:' + str(args.controller_port),
                    'secret': controller_secret, 'allow-lan': False,
                    'bind-address': '127.0.0.1', 'mode': 'global',
                    'log-level': 'silent', 'ipv6': False, 'geo-auto-update': False,
                    'geodata-mode': False,
                    'geox-url': {'geosite': 'http://127.0.0.1:1/no-download',
                                 'mmdb': 'http://127.0.0.1:1/no-download'}})
    profile['tun'] = {'enable': False}
    profile.setdefault('profile', {})['store-selected'] = False
    for key in ('external-controller-tls', 'external-controller-unix',
                'external-controller-pipe', 'external-ui', 'external-ui-url',
                'listeners'):
        profile.pop(key, None)
    providers = profile.get('proxy-providers') or {}
    require(set(providers) in ({'paoluz'}, {'paoluz', 'zoro-emergency'}), 'unexpected_provider_inventory')
    if 'zoro-emergency' in providers:
        require(providers['zoro-emergency'].get('type') == 'inline', 'invalid_emergency_provider')
        providers['zoro-emergency']['payload'] = [copy.deepcopy(proxies[zoro_names[0]])]
    provider = providers['paoluz']
    if args.server_port:
        require(1 <= args.server_port <= 65535, 'invalid_candidate_server_port')
        original = urllib.parse.urlsplit(provider['url'])
        query = urllib.parse.parse_qs(original.query)
        query['format'] = ['provider']
        provider['url'] = ('http://127.0.0.1:' + str(args.server_port) +
            '/merge/' + urllib.parse.quote(identity, safe='') + '?' +
            urllib.parse.urlencode(query, doseq=True))
    provider['path'] = str(folder / 'providers/paoluz.yaml')
    provider['proxy'] = 'DIRECT'
    return profile, [('DMIT', DMIT, 'US', None),
                     ('ByteVirt', BYTEVIRT, 'HK', None),
                     ('zorocloud', zoro_names[0], 'MY', args.expect_zoro_ip)]


def install_geodata(source, target):
    source = Path(source)
    for candidates, names in ((('geosite.dat', 'GeoSite.dat'), ('geosite.dat', 'GeoSite.dat')),
                              (('country.mmdb', 'Country.mmdb'), ('country.mmdb', 'Country.mmdb'))):
        actual = next((source / name for name in candidates if (source / name).is_file()), None)
        require(actual is not None, 'verified_geodata_missing')
        for name in names:
            (target / name).symlink_to(actual.resolve())


class Controller:
    def __init__(self, port, secret):
        self.base = 'http://127.0.0.1:' + str(port)
        self.secret = secret
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(self, path, *, method='GET', payload=None, timeout=2):
        body = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(self.base + path, data=body, method=method,
            headers={'Authorization': 'Bearer ' + self.secret, 'Content-Type': 'application/json'})
        with self.opener.open(request, timeout=timeout) as response:
            raw = response.read(1_000_001)
            require(len(raw) <= 1_000_000, 'controller_response_too_large')
            return json.loads(raw) if raw else None

    def select(self, group, name):
        endpoint = '/proxies/' + urllib.parse.quote(group, safe='')
        deadline = time.monotonic() + 10
        while True:
            try:
                available = self.request(endpoint)
                if name in available.get('all', []):
                    break
            except urllib.error.HTTPError as error:
                if error.code != 404:
                    raise
            if time.monotonic() >= deadline:
                raise ProbeFailure('isolated_selector_not_ready')
            time.sleep(.2)
        self.request(endpoint, method='PUT', payload={'name': name})
        require(self.request(endpoint).get('now') == name, 'isolated_selector_not_applied')
        time.sleep(.2)


def curl_trace(port, timeout):
    marker = '\n__CURL_META__:'
    command = ['curl', '--noproxy', '', '--proxy', 'http://127.0.0.1:' + str(port),
        '--silent', '--show-error', '--connect-timeout', '6', '--max-time', str(timeout),
        '--max-filesize', '65536', '--write-out',
        marker + '%{http_code}:%{size_download}:%{size_upload}:%{time_total}:%{ssl_verify_result}', TRACE_URL]
    result = subprocess.run(command, capture_output=True, timeout=timeout + 3)
    require(result.returncode == 0, 'route_https_request_failed')
    text = result.stdout.decode('utf-8', 'replace')
    require(marker in text and len(text) <= 70000, 'trace_response_invalid')
    body, metadata = text.rsplit(marker, 1)
    fields = metadata.strip().split(':')
    require(len(fields) == 5 and fields[0] == '200' and fields[4] == '0',
            'trace_http_or_tls_failed')
    trace = dict(line.split('=', 1) for line in body.splitlines() if '=' in line)
    address = str(ipaddress.ip_address(trace.get('ip', '')))
    country = trace.get('loc')
    require(isinstance(country, str) and len(country) == 2, 'trace_country_missing')
    return {'ip': address, 'country': country, 'http_status': int(fields[0]),
            'probe_download_bytes': int(float(fields[1])),
            'probe_upload_bytes': int(float(fields[2])),
            'seconds': float(fields[3]), 'tls_verified': True}


def airport_snapshot(controller):
    """Read real provider leaves separately from the visible manual choices."""
    provider = controller.request('/providers/proxies/paoluz')
    leaves = provider.get('proxies') if isinstance(provider, dict) else None
    require(isinstance(leaves, list), 'airport_provider_inventory_invalid')
    require(all(isinstance(node, dict) and isinstance(node.get('name'), str)
                and node['name'] for node in leaves), 'airport_provider_node_invalid')
    names = [node['name'] for node in leaves]
    require(len(set(names)) == len(names), 'airport_provider_node_names_not_unique')
    response = controller.request('/proxies')
    inventory = response.get('proxies') if isinstance(response, dict) else None
    require(isinstance(inventory, dict), 'runtime_proxy_inventory_invalid')
    measured = [node for node in leaves if isinstance(node.get('history'), list)
                and node['history']]
    alive = [node['name'] for node in measured if node.get('alive') is True
             and isinstance(node['history'][-1], dict)
             and isinstance(node['history'][-1].get('delay'), (int, float))
             and node['history'][-1]['delay'] > 0]
    return {'nodes': {node['name']: node for node in leaves},
            'names': names, 'measured': len(measured), 'alive': alive,
            'inventory': inventory}


def wait_airport_health(controller, timeout=60):
    deadline = time.monotonic() + timeout
    while True:
        try:
            snapshot = airport_snapshot(controller)
            if snapshot['names'] and snapshot['measured'] == len(snapshot['names']):
                return snapshot
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
        require(time.monotonic() < deadline, 'airport_provider_health_not_ready')
        time.sleep(.25)


def selected_leaf(snapshot, name):
    """Follow one atomic group map; never address slash-bearing node labels."""
    chain = []
    while True:
        require(name not in chain, 'airport_selected_group_cycle')
        chain.append(name)
        node = snapshot['inventory'].get(name, snapshot['nodes'].get(name))
        require(isinstance(node, dict), 'airport_selected_node_missing')
        choices = node.get('all')
        if not isinstance(choices, list):
            return name, chain
        selected = node.get('now')
        require(isinstance(selected, str) and selected in choices,
                'airport_selected_group_not_ready')
        name = selected


def validate_airport_choices(snapshot, zoro):
    from five_group_stage import OTHER, STREAMING
    from new_topology import AIRPORT_AUTO
    expected = set(snapshot['names']) | {AIRPORT_AUTO, zoro}
    counts = {}
    for label, name in (('streaming', STREAMING), ('other', OTHER)):
        group = snapshot['inventory'].get(name)
        require(isinstance(group, dict) and isinstance(group.get('all'), list),
                'airport_manual_group_missing')
        require(len(group['all']) == len(expected) and set(group['all']) == expected,
                'airport_manual_group_inventory_mismatch')
        require(group.get('now') == AIRPORT_AUTO, 'airport_default_is_not_automatic')
        require(group.get('emptyFallback') == 'REJECT', 'airport_empty_group_not_fail_closed')
        counts[label] = len(group['all'])
    return counts


def wait_airport_default(controller, zoro, timeout=25):
    from five_group_stage import OTHER
    deadline = time.monotonic() + timeout
    while True:
        snapshot = airport_snapshot(controller)
        counts = validate_airport_choices(snapshot, zoro)
        leaf, chain = selected_leaf(snapshot, OTHER)
        healthy = set(snapshot['alive'])
        # A cached URL-test wrapper can briefly refer to an unhealthy leaf;
        # allow its next scheduled selection, but never mistake it for Zoro.
        expected = leaf in healthy if healthy else leaf == zoro
        if expected:
            return snapshot, counts, leaf, chain
        require(time.monotonic() < deadline, 'airport_automatic_selected_wrong_leaf')
        time.sleep(.25)


def main(args):
    require(os.geteuid() == 0, 'root_required_for_private_profile')
    require(args.mixed_port != args.controller_port, 'isolated_ports_collide')
    unused_port(args.mixed_port)
    unused_port(args.controller_port)
    import topology_server as topology
    from five_group_stage import GLOBAL, VPS
    identity = selected_identity(topology, args.user)
    original = topology.build_profile(identity, refresh=False)
    report = {'syntax': 'pending', 'routes': [], 'production_modified': False,
              'dns_scope': 'system resolver; route-only verification',
              'byte_basis': 'curl HTTP body bytes; not interface counters'}
    process = None
    phase = 'prepare'
    with tempfile.TemporaryDirectory(prefix='topology-route-qa-', dir=args.private_parent) as temporary:
        folder = Path(temporary)
        folder.chmod(0o700)
        (folder / 'providers').mkdir(mode=0o700)
        install_geodata(args.geodata, folder)
        secret = secrets.token_urlsafe(24)
        profile, routes = isolate_profile(original, identity, folder, args, secret)
        path = folder / 'config.yaml'
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            yaml.safe_dump(profile, stream, allow_unicode=True, sort_keys=False)
        log_path = folder / 'core.log'
        fd = os.open(str(log_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as log:
            try:
                phase = 'syntax'
                checked = subprocess.run([args.core, '-t', '-d', temporary, '-f', str(path)],
                    stdout=log, stderr=log, timeout=20)
                require(checked.returncode == 0, 'isolated_syntax_failed')
                report['syntax'] = 'pass'
                # DNS is unrelated to these path probes and must not depend on
                # an airport node while its provider is initializing.
                profile['dns'] = {'enable': False}
                path.write_text(yaml.safe_dump(profile, allow_unicode=True, sort_keys=False), encoding='utf-8')
                phase = 'startup'
                process = subprocess.Popen([args.core, '-d', temporary, '-f', str(path)],
                    stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
                controller = Controller(args.controller_port, secret)
                ready = False
                for _ in range(60):
                    require(process.poll() is None, 'isolated_core_exited')
                    try:
                        controller.request('/version', timeout=.7)
                        ready = True
                        break
                    except (OSError, ValueError):
                        time.sleep(.2)
                require(ready, 'isolated_controller_unavailable')
                if getattr(args, 'airport', False):
                    phase = 'airport_health_startup'
                    health = wait_airport_health(controller, timeout=max(60, args.timeout * 2))
                    report['airport_health'] = {'provider_nodes': len(health['names']),
                        'tested_nodes': health['measured'], 'healthy_nodes': len(health['alive'])}
                    # Provider downloads are tracked connections too. Wait for
                    # completion before the route probes close old sessions.
                controller.select(GLOBAL, VPS)
                for label, name, country, expected_ip in routes:
                    phase = 'probe_' + label
                    controller.request('/connections', method='DELETE')
                    controller.select(VPS, name)
                    value = curl_trace(args.mixed_port, args.timeout)
                    value['route'] = label
                    value['expected_country'] = country
                    value['matches_expected'] = value['country'] == country and (
                        expected_ip is None or value['ip'] == expected_ip)
                    report['routes'].append(value)
                require(all(item['matches_expected'] for item in report['routes']),
                        'egress_country_or_ip_mismatch')
                if getattr(args, 'airport', False):
                    from five_group_stage import OTHER
                    from new_topology import AIRPORT_AUTO
                    phase = 'probe_paoluz'
                    controller.request('/connections', method='DELETE')
                    controller.select(GLOBAL, OTHER)
                    zoro = next(name for label, name, _, _ in routes if label == 'zorocloud')
                    snapshot, counts, leaf, chain = wait_airport_default(controller, zoro)
                    healthy = set(snapshot['alive'])
                    report['airport_provider_nodes'] = len(snapshot['names'])
                    report['airport_manual_choices'] = counts['other']
                    report['airport_selected_node'] = AIRPORT_AUTO
                    report['airport_actual_leaf'] = leaf
                    report['airport_selection_chain'] = chain
                    report['airport_group_counts'] = counts
                    report['airport_healthy_nodes'] = len(healthy)
                    value = curl_trace(args.mixed_port, args.timeout)
                    value.update(route='paoluz', selected_node=AIRPORT_AUTO,
                                 actual_leaf=leaf, selection_chain=chain,
                                 expected_source='airport' if healthy else 'zorocloud',
                                 matches_expected=leaf in healthy if healthy else leaf == zoro)
                    if not healthy:
                        value['matches_expected'] = value['matches_expected'] and (
                            value['ip'] == args.expect_zoro_ip and value['country'] == 'MY')
                    report['airport'] = value
                    require(value['matches_expected'], 'airport_automatic_egress_mismatch')
                report['status'] = 'pass'
            except Exception as error:
                report.update(status='fail', phase=phase, error_type=type(error).__name__)
                if isinstance(error, ProbeFailure): report['failure'] = str(error)
            finally:
                if process is not None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
                    report['isolated_core_stopped'] = process.poll() is not None
    report['private_profile_removed'] = True
    output = json.dumps(report, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(output + '\n', encoding='utf-8')
    print(output)
    return 0 if report.get('status') == 'pass' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--user', default='wrt')
    parser.add_argument('--server-port', type=int, default=0,
                        help='Local topology HTTP port; 0 preserves the published provider URL')
    parser.add_argument('--direct-port', '--stage-direct-port', type=int)
    parser.add_argument('--direct-host')
    parser.add_argument('--zoro-port', '--stage-zoro-port', type=int)
    parser.add_argument('--zoro-host')
    parser.add_argument('--mixed-port', type=int, default=18091)
    parser.add_argument('--controller-port', type=int, default=18092)
    parser.add_argument('--timeout', type=int, default=15)
    parser.add_argument('--airport', action='store_true', help='Also probe the default cached airport route')
    parser.add_argument('--core', default=DEFAULT_CORE)
    parser.add_argument('--geodata', default=DEFAULT_GEODATA)
    parser.add_argument('--private-parent', default='/root')
    parser.add_argument('--expect-zoro-ip', default='218.208.109.3')
    parser.add_argument('--output')
    try:
        raise SystemExit(main(parser.parse_args()))
    except Exception as error:
        # Exception strings can contain authenticated provider URLs.
        print(json.dumps({'status': 'fail', 'error_type': type(error).__name__,
                          'credentials': 'hidden', 'production_modified': False}))
        raise SystemExit(1)
