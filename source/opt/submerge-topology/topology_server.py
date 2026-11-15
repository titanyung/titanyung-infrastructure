"""Authenticated three-route subscription adapter and offline Paoluz delivery.

This is a candidate entry point. Importing it performs no upstream request.
The private policy's ``paoluz_refresh_enabled`` defaults to False; the operator
must obtain the user's authorization-window acknowledgement before setting it.
"""
import copy
from contextlib import closing
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, unquote, urlsplit

import yaml

import merge_sub as legacy
import public_five_group as public
import public_five_group_hook as auth
from pc_only_stage import BYTEVIRT_CERT_FINGERPRINT
from five_group_stage import SINGAPORE_TZ
from new_topology import (build_new_topology, build_network_plan, prioritize_provider,
                          PLAN_ROUTE_NAMES)
from router_profile import mirror_airport_into_visible_groups
from paoluz_cache import PaoluzCache
from new_enrollment import EnrollmentError, read_sui_identity
from zoro_runtime import TAIWAN_TRANSPORT_PATH, validate_taiwan_transport

POLICY_PATH = Path(os.environ.get('TOPOLOGY_POLICY_PATH',
                                 '/var/lib/submerge-public/topology-20261105.json'))
MIHOMO = os.environ.get('TOPOLOGY_MIHOMO',
                       '/var/lib/submerge-staging/mihomo-v1.19.32-stage')
DMIT_ADDRESS = '179.255.136.79'
BYTEVIRT_ADDRESS = '61.15.36.199'
ZORO_ADDRESS = '218.208.109.3'
ZORO_NAME = '🔷 🌀 🇲🇾 DMIT→zorocloud'
_CACHES = {}
_CACHE_LOCK = threading.Lock()
NETWORK_PLAN_FILE = Path(os.environ.get('TOPOLOGY_NETWORK_PLAN_PATH',
                                       '/etc/submerge-topology/network-plan.json'))


def private_policy():
    if not POLICY_PATH.exists():
        return {'paoluz_refresh_enabled': False}
    policy = auth._private_json(POLICY_PATH)
    if not isinstance(policy, dict):
        raise ValueError('topology policy must be an object')
    enabled = policy.get('paoluz_refresh_enabled', False)
    if type(enabled) is not bool:
        raise ValueError('Paoluz refresh flag must be boolean')
    if type(policy.get('on_demand_enrollment', False)) is not bool:
        raise ValueError('on-demand enrollment flag must be boolean')
    if type(policy.get('local_identity_source', False)) is not bool:
        raise ValueError('local identity source flag must be boolean')
    return policy


def validate_full_provider(document):
    return validate_provider(document, _full_graph=True)


def validate_provider(document, *, _full_graph=False):
    """Validate materialized nodes/groups with the existing native parser."""
    required = {'proxies', 'proxy-groups'} if _full_graph else {'proxies'}
    if not isinstance(document, dict) or set(document) != required:
        raise ValueError('provider must be materialized')
    directory = Path(os.environ.get('TOPOLOGY_VALIDATOR_DIR',
                                   '/run/submerge-paoluz-validation'))
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(str(directory), 0o700)
    with tempfile.TemporaryDirectory(prefix='check-', dir=str(directory)) as temporary:
        config = Path(temporary) / 'config.json'
        carrier = dict(document, **{'mode': 'rule', 'log-level': 'silent',
                                   'rules': ['MATCH,DIRECT'], 'dns': {'enable': False}})
        fd = os.open(str(config), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(carrier, stream, ensure_ascii=False)
        result = subprocess.run([MIHOMO, '-t', '-d', temporary, '-f', str(config)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=8, check=False)
        if result.returncode != 0:
            raise ValueError('provider core validation failed')


def provider_cache():
    source_file = Path(os.environ.get('TOPOLOGY_PAOLUZ_SOURCE_FILE',
                                     '/etc/submerge-topology/paoluz-source.json'))
    source = auth._private_json(source_file) if source_file.is_file() else {}
    upstream = source.get('url', legacy.PAOLUZ_URL)
    cache_file = os.environ.get('TOPOLOGY_CACHE_FILE', '/var/lib/submerge/paoluz-provider.yaml')
    metadata_file = os.environ.get('TOPOLOGY_CACHE_METADATA_FILE', cache_file + '.metadata.json')
    seed = os.environ.get('TOPOLOGY_CACHE_SEED_FILE', legacy.PAOLUZ_CACHE_FILE)
    cache_type, extra, validator = PaoluzCache, {}, validate_provider
    network = active_network_plan()
    if isinstance(network, dict) and network.get('server_policy', {}).get('id') == 'dmit-domain-routing-20261109-v2':
        from full_graph_cache import FullGraphPaoluzCache
        cache_type = FullGraphPaoluzCache
        validator = validate_full_provider
        seed = os.environ.get('TOPOLOGY_FULL_GRAPH_SEED_FILE')
        snapshot = os.environ.get('TOPOLOGY_FULL_GRAPH_SNAPSHOT_FILE', cache_file + '.full.snapshot.json')
        if not isinstance(seed, str) or not Path(seed).is_absolute() or not Path(snapshot).is_absolute():
            raise ValueError('explicit_full_graph_seed_and_snapshot_required')
        extra = {'snapshot_file': snapshot}
        identity = (upstream, cache_file, metadata_file, seed, cache_type.__name__, snapshot)
    else:
        identity = (upstream, cache_file, metadata_file, seed)
    with _CACHE_LOCK:
        if identity not in _CACHES:
            _CACHES[identity] = cache_type(upstream, cache_file=cache_file,
                metadata_file=metadata_file, seed_file=seed, validator=validator,
                timeout=5, refresh_guard=5, **extra)
        return _CACHES[identity]


def _identity(subid):
    if not isinstance(subid, str) or not re.fullmatch(r'[A-Za-z0-9._~+=-]+', subid):
        raise ValueError('invalid subscription identity')
    if os.environ.get('USER_ACCESS_CONTROL_DB'):
        if '/opt/submerge-user-access' not in sys.path:
            sys.path.insert(0, '/opt/submerge-user-access')
        from access_policy import require_admission
        require_admission(subid)
    ordinary, trial = auth._ordinary_accounts()
    allowed = set(ordinary) | ({trial} if trial is not None else set())
    if subid not in allowed and private_policy().get('on_demand_enrollment', False):
        try:
            read_sui_identity(subid)
        except EnrollmentError:
            # Unknown, disabled, ambiguous, or ungranted identities are an
            # authentication miss, not a temporary provisioning failure.
            raise PermissionError('subscription identity is not enabled') from None
        # Admission verifies S-UI eligibility before any remote operation and
        # commits ready only after the candidate's three real paths pass.
        # Re-read the normal gate; admission itself never bypasses auth.
        from topology_enrollment_runtime import admit
        admit(subid)
        ordinary, trial = auth._ordinary_accounts()
        allowed = set(ordinary) | ({trial} if trial is not None else set())
    if subid not in allowed:
        raise PermissionError('subscription identity is not enabled')
    return allowed


def _dmit_credential(subid, allowed):
    credentials = auth._private_json(auth.MAP_PATHS['dmit'])
    if not isinstance(credentials, dict):
        raise ValueError('DMIT credential map invalid')
    value = credentials.get(subid)
    if not isinstance(value, str) or len(value) < 24:
        raise ValueError('DMIT subscriber has not been provisioned')
    if any(other != subid and credentials.get(other) == value for other in allowed):
        raise ValueError('DMIT subscriber credential is not unique')
    return value


def cached_provider(subid):
    """Authenticate first; downloading a provider never triggers its source."""
    allowed = _identity(subid)
    _dmit_credential(subid, allowed)
    cache = provider_cache()
    policy = private_policy()
    return prioritize_provider(cache.get(refresh=False, authorized=False),
        preferred_name=policy.get('paoluz_preferred_node'),
        preferred_type=policy.get('paoluz_preferred_type'))


def active_network_plan():
    """The absent marker retains the old plan; an unsafe marker never does."""
    if not os.path.lexists(str(NETWORK_PLAN_FILE)):
        return None
    from network_runtime import load_network_plan
    return load_network_plan(NETWORK_PLAN_FILE)


def classify_client_kind(user_agent=None, *, explicit=None, remark=None):
    """Select only an initial group preference, never an authorization policy."""
    if explicit is not None:
        if explicit not in {'mobile', 'desktop', 'router'}:
            raise ValueError('client kind must be mobile, desktop or router')
        return explicit
    ua = user_agent.casefold() if isinstance(user_agent, str) else ''
    if any(word in ua for word in ('openclash', 'openwrt', 'router')):
        return 'router'
    if re.search(r'\bios\b', ua) or any(word in ua for word in ('android', 'iphone', 'ipad', 'ipod', 'ios/', ' ios ',
                                   'clashforandroid', 'clash meta for android', 'shadowrocket',
                                   'stash/', 'mobile')):
        return 'mobile'
    if any(word in ua for word in ('windows', 'macintosh', 'macos', 'mac os', 'linux',
                                   'clashforwindows', 'clash for windows')):
        return 'desktop'
    # Generic FlClash/Dart UAs carry no operating-system identity. Use only
    # explicit device words stored in this verified user's own S-UI remarks.
    note = remark.casefold() if isinstance(remark, str) else ''
    if any(word in note for word in ('软路由', '路由器', 'openclash', 'openwrt', 'router')):
        return 'router'
    if any(word in note for word in ('手机', '安卓', '红米', '小米', '平板', '鸿蒙', '荣耀',
                                     'iphone', 'ipad', 'android', 'pixel', 'vivo', 'oppo')) or re.search(r'\bios\b', note):
        return 'mobile'
    if any(word in note for word in ('电脑', '台式', '笔记本', 'windows', 'macbook', 'linux')) or re.search(r'\b(?:pc|mac)\b', note):
        return 'desktop'
    return 'desktop'


def identity_device_remarks(subid, db_path=None):
    """Read only non-secret description fields for one authenticated identity."""
    if not isinstance(subid, str) or not re.fullmatch(r'[A-Za-z0-9._~+=-]+', subid):
        raise ValueError('invalid subscription identity')
    if db_path is None:
        from new_enrollment import DB
        db_path = DB
    try:
        uri = Path(db_path).resolve().as_uri() + '?mode=ro'
        with closing(sqlite3.connect(uri, uri=True, timeout=2)) as db:
            db.execute('PRAGMA query_only=ON')
            columns = {row[1] for row in db.execute('PRAGMA table_info(clients)')}
            selected = [column for column in ('desc', 'remark', 'description') if column in columns]
            if not selected:
                return ''
            # Column names come solely from the fixed allowlist above.
            query = 'SELECT ' + ','.join('"' + column + '"' for column in selected)
            query += ' FROM clients WHERE name=? AND sub_secret=? AND enable=1'
            rows = db.execute(query, (subid, subid)).fetchmany(2)
            if len(rows) != 1:
                return ''
            return ' '.join(value[:1024] for value in rows[0] if isinstance(value, str))
    except (sqlite3.Error, OSError, ValueError):
        # A missing optional remark must not prevent an otherwise valid user
        # from importing; the documented conservative default is desktop.
        return ''


def _network_client_kind(subid, client_kind=None, user_agent=None):
    if client_kind is not None:
        return classify_client_kind(explicit=client_kind)
    if not user_agent:
        return 'desktop'  # Admission and offline generation have no client UA.
    direct = classify_client_kind(user_agent)
    ua = user_agent.casefold() if isinstance(user_agent, str) else ''
    known = ('openclash', 'openwrt', 'router', 'android', 'iphone', 'ipad', 'ipod',
             'ios/', ' ios ', 'clashforandroid', 'shadowrocket', 'stash/', 'mobile',
             'windows', 'macintosh', 'macos', 'mac os', 'linux', 'clashforwindows')
    if re.search(r'\bios\b', ua) or any(word in ua for word in known):
        return direct
    return classify_client_kind(user_agent, remark=identity_device_remarks(subid))


def build_profile(subid, direct_country=None, now=None, refresh=True, client_kind=None,
                  user_agent=None):
    allowed = _identity(subid)
    dmit_password = _dmit_credential(subid, allowed)
    policy = private_policy()
    network = active_network_plan()
    cache = provider_cache()
    # False is explicit: even the first profile request must not touch Paoluz
    # before the operator has opened and confirmed its authorization window.
    provider = cache.get(refresh=bool(refresh),
                         authorized=None if policy.get('paoluz_refresh_enabled', False) else False)
    provider = prioritize_provider(provider,
        preferred_name=policy.get('paoluz_preferred_node'),
        preferred_type=policy.get('paoluz_preferred_type'))
    digest = hashlib.sha256(PaoluzCache._serialize(provider)).hexdigest()
    if policy.get('local_identity_source', False):
        identity = read_sui_identity(subid, allow_trial=subid == 'test')
        if identity.name != subid or identity.sub_secret != subid:
            raise ValueError('local S-UI identity binding invalid')
        bytevirt_password = identity.sui_password
        source_path = policy.get('profile_base_file', '/etc/submerge-topology/profile-base.json')
        if not isinstance(source_path, str) or not Path(source_path).is_absolute():
            raise ValueError('profile base path must be absolute')
        sui = auth._private_json(Path(source_path))
        if not isinstance(sui, dict):
            raise ValueError('profile base invalid')
        forbidden = {'proxies', 'proxy-groups', 'proxy-providers', 'rule-providers', 'rules',
            'authentication', 'secret', 'external-controller', 'external-controller-tls',
            'external-controller-unix', 'external-controller-pipe', 'external-ui',
            'external-ui-url', 'listeners'}
        if forbidden.intersection(sui):
            raise ValueError('profile base contains private routing or control fields')
        sui = copy.deepcopy(sui)
    else:
        sui_url = legacy.SUI_URL_TEMPLATE.replace('{subid}', quote(subid, safe=''))
        sui_text = legacy.request_text(sui_url, timeout=8)
        sui = legacy.parse_yaml(sui_text, 'S-UI')
        if not isinstance(sui, dict):
            raise ValueError('S-UI subscription invalid')
        sources = sui.get('proxies') or []
        if not isinstance(sources, list):
            raise ValueError('S-UI proxy list invalid')
        bytevirt_password = next((node.get('password') for node in sources
            if isinstance(node, dict) and str(node.get('type', '')).lower() == 'anytls'
            and isinstance(node.get('password'), str) and len(node['password']) >= 10), None)
    secondary = False
    if network is not None:
        from network_runtime import server_policy_enabled
        secondary = server_policy_enabled(network)
    if bytevirt_password is None and not secondary:
        raise ValueError('ByteVirt subscriber credential unavailable')
    dmit = public._anytls('__TOPOLOGY-DMIT-direct', 'dmit', DMIT_ADDRESS, 31117, dmit_password)
    bytevirt = {'name': '__TOPOLOGY-DMIT-ByteVirt', 'type': 'anytls',
                'server': BYTEVIRT_ADDRESS, 'port': 2443, 'password': bytevirt_password,
                'tls': True, 'skip-cert-verify': True, 'fingerprint': BYTEVIRT_CERT_FINGERPRINT,
                'dialer-proxy': dmit['name'], 'udp': False}
    if network is not None:
        kind = _network_client_kind(subid, client_kind, user_agent)
        routes = {'dmit': dmit, 'bytevirt_hk': bytevirt}
        transport_routes = (('bytevirt_tw', 'bytevirt-tw', 29514),
                            ('lazycat_sg', 'lazycat-starhub', 29515),
                            ('lazycat_hkt', 'lazycat-hkt', 29516),
                            ('uzuma_sg', 'uzuma-singtel', 29517))
        for key, transport, port in transport_routes:
            routes[key] = public._anytls(PLAN_ROUTE_NAMES[key], 'dmit', DMIT_ADDRESS, port, dmit_password)
        if secondary:
            from network_runtime import client_fronts
            routes = {key: public._anytls(PLAN_ROUTE_NAMES[key], 'dmit', endpoint['server'],
                         endpoint['port'], dmit_password)
                      for key, endpoint in client_fronts(network, kind).items()}
            # All roots authenticate at DMIT; the private HK hop remains server-side.
            bytevirt = routes['bytevirt_hk']
        base = copy.deepcopy(sui)
        base.setdefault('proxies', []).extend(routes.values())
        bootstrap = 'IP-CIDR,{}/32,DIRECT,no-resolve'.format(DMIT_ADDRESS)
        route_rules = [bootstrap,
            'IP-CIDR,{}/32,{},no-resolve'.format(BYTEVIRT_ADDRESS, bytevirt['name'])]
        import ipaddress
        for key, transport, port in transport_routes:
            if transport not in network['transports']:
                # Legacy carrier templates stay internal until the V4 final
                # projector removes retired routes. No retired endpoint or
                # transport credential is loaded to make the old renderer work.
                if network.get('server_policy', {}).get('id') == 'dmit-domain-routing-20261109-v2':
                    continue
            address = network['transports'][transport]['server']
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                route_rules.append('DOMAIN,{},{}'.format(address, routes[key]['name']))
            else:
                # DMIT's own public listener address always remains DIRECT;
                # these rules describe service access, not the dialer's setup.
                if str(ip) != DMIT_ADDRESS:
                    family = 'IP-CIDR6' if ip.version == 6 else 'IP-CIDR'
                    route_rules.append('{},{}/{},{},no-resolve'.format(
                        family, ip, ip.max_prefixlen, routes[key]['name']))
        base['rules'] = route_rules + legacy.load_route_admin_rules()
        url = ('https://node.titanyung.click:31877/sub/' + quote(subid, safe='')
               + '?format=provider&v=' + digest)
        result = build_network_plan(base, routes=routes, paoluz_provider_url=url,
            client_kind=kind, direct_country=direct_country,
            now=now or datetime.now(SINGAPORE_TZ), server_policy=secondary)
        result['rules'] = [bootstrap] + [rule for rule in result['rules'] if rule != bootstrap]
        result = mirror_airport_into_visible_groups(result, provider)
        if secondary:
            from client_policy import load_policy, simplify_profile
            client_policy = load_policy()
            if client_policy is not None:
                result = simplify_profile(result, test_mode=subid in client_policy['test_users'])
        if network.get('server_policy', {}).get('id') == 'dmit-domain-routing-20261109-v2':
            # Retired legacy templates are internal-only. A partially enabled
            # release must never export the carrier as a current subscription.
            if ('x-submerge-routing-revision' not in result or
                    result.get('x-submerge-server-policy') != network['server_policy']['id']):
                raise ValueError('revised_client_projection_required')
        return result
    zoro = public._anytls(ZORO_NAME, 'dmit', DMIT_ADDRESS, 29513, dmit_password)
    taiwan=None
    if TAIWAN_TRANSPORT_PATH.exists():
        validate_taiwan_transport(auth._private_json(TAIWAN_TRANSPORT_PATH))
        from new_topology import TAIWAN
        taiwan=public._anytls(TAIWAN, 'dmit', DMIT_ADDRESS, 29514, dmit_password)
    base = copy.deepcopy(sui)
    base.setdefault('proxies', []).extend((dmit, bytevirt, zoro)+((taiwan,) if taiwan else ()))
    bootstrap = 'IP-CIDR,{}/32,DIRECT,no-resolve'.format(DMIT_ADDRESS)
    route_rules = [bootstrap,
        'IP-CIDR,{}/32,{},no-resolve'.format(BYTEVIRT_ADDRESS, bytevirt['name']),
        'IP-CIDR,{}/32,{},no-resolve'.format(ZORO_ADDRESS, zoro['name']),
        'DOMAIN,zorocloud.one,' + zoro['name'],
        'DOMAIN,dmit.io,' + dmit['name'], 'DOMAIN,www.dmit.io,' + dmit['name']]
    base['rules'] = route_rules + legacy.load_route_admin_rules()
    url = ('https://node.titanyung.click:31877/sub/' + quote(subid, safe='')
           + '?format=provider&v=' + digest)
    result = build_new_topology(base, dmit_node=dmit, bytevirt_node=bytevirt,
        zoro_node=zoro, paoluz_provider_url=url, direct_country=direct_country,
        now=now or datetime.now(SINGAPORE_TZ),taiwan_node=taiwan)
    result['rules'] = [bootstrap] + [rule for rule in result['rules'] if rule != bootstrap]
    return mirror_airport_into_visible_groups(result, provider)


class TopologyHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        # URL paths are subscription credentials; the existing Nginx access
        # collector remains the authority for auditing/rate limiting.
        pass

    def _send(self, code, document=None):
        body = (yaml.safe_dump(document, allow_unicode=True, sort_keys=False,
                               default_flow_style=False, width=4096).encode('utf-8')
                if document is not None else b'subscription unavailable\n')
        self.send_response(code)
        self.send_header('Content-Type', 'text/yaml; charset=utf-8')
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Content-Length', str(len(body)))
        if document is not None:
            self.send_header('Content-Disposition', 'inline; filename="subscription.yaml"')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlsplit(self.path)
        if not parsed.path.startswith('/merge/'):
            return self._send(404)
        subid = unquote(parsed.path[len('/merge/'):].strip('/'))
        if not re.fullmatch(r'[A-Za-z0-9._~+=-]+', subid):
            return self._send(400)
        try:
            query = parse_qs(parsed.query, keep_blank_values=True)
            if any(len(values) != 1 for values in query.values()):
                return self._send(400)
            selected = query.get('format', ['clash'])[0].lower()
            # Match the existing access gateway's full-profile/provider codecs.
            # This normalization does not grant a device or test identity.
            if selected in ('clash-provider',):
                selected = 'provider'
            elif selected in ('clashmeta', 'clash-meta', 'mihomo', 'yaml', 'openclash'):
                selected = 'clash'
            if selected == 'provider':
                return self._send(200, cached_provider(subid))
            # Shadowrocket's Config importer accepts a complete Clash YAML;
            # its Home subscription importer only extracts the node list.
            if selected not in ('clash', 'shadowrocket', ''):
                return self._send(400)
            refresh = query.get('refresh', ['1'])[0]
            if refresh not in ('0', '1'):
                return self._send(400)
            client_kind = query.get('client', [None])[0]
            if selected == 'shadowrocket' and client_kind is None:
                client_kind = 'mobile'
            if client_kind is not None and client_kind not in ('mobile', 'desktop', 'router'):
                return self._send(400)
            real_ip = self.headers.get_all('X-Real-IP') or []
            country = legacy.country_from_request(self.client_address[0],
                real_ip[0] if len(real_ip) == 1 else None)
            options = {'direct_country': country, 'refresh': refresh == '1'}
            user_agent = self.headers.get('User-Agent', '')
            if user_agent:
                options['user_agent'] = user_agent[:1024]
            if client_kind is not None:
                options['client_kind'] = client_kind
            return self._send(200, build_profile(subid, **options))
        except PermissionError:
            return self._send(404)
        except Exception as error:
            print('topology_request_failed ' + type(error).__name__, file=sys.stderr, flush=True)
            return self._send(503)


def main():
    if '{subid}' not in legacy.SUI_URL_TEMPLATE:
        raise ValueError('S-UI URL template invalid')
    private_policy()
    # Startup is deliberately offline, including the first candidate launch.
    provider_cache().get(refresh=False, authorized=False)
    port = int(os.environ.get('STAGE_LISTEN_PORT', legacy.LISTEN_PORT))
    host = ('127.0.0.1' if 'STAGE_LISTEN_PORT' in os.environ else legacy.LISTEN_HOST)
    ThreadingHTTPServer((host, port), TopologyHandler).serve_forever()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('topology_start_failed ' + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
