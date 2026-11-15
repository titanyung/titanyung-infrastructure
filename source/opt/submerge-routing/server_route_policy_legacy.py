"""Pure sing-box 1.14.3 second-stage policy for decrypted DMIT requests.

This does not provision listeners, credentials, rule databases, or a proxy hop.
In particular, ByteVirt HK must first migrate from a client-nested AnyTLS hop
to its own authenticated DMIT frontend and dedicated, verified server outbound.
No HTTP User-Agent exists here: explicit SG inlet hints win, then the mobile or
desktop inlet identity. Audited S-UI remarks are only an opt-in legacy fallback.

Server DIRECT means DMIT's network, never the remote client's local network.
Domestic requests that have already reached DMIT use Taiwan, including WeChat
and audited remote domains. Client-local DIRECT rules are outside this module.
TLS ECH or IP-only traffic without an observable hostname can only be classified
by audited IP rule sets; unknown traffic goes to Taiwan, never implicit DIRECT.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat

from domain_destination_override import inject_exact_domain_overrides, EXACT_SERVICE_DOMAINS

POLICY_ID = 'dmit-domain-routing-20261106'
ASSET_KEYS = ('cn_domain', 'cn_ip', 'hk_ip', 'google', 'ai', 'youtube', 'netflix', 'entertainment')
INBOUNDS = {'direct': 'dmit-direct-stage', 'hk': 'dmit-hk', 'taiwan': 'dmit-taiwan',
            'starhub': 'dmit-starhub', 'hkt': 'dmit-hkt', 'singtel': 'dmit-singtel',
            'mobile_direct': 'mobile-dmit-direct', 'mobile_hk': 'mobile-dmit-hk',
            'mobile_taiwan': 'mobile-dmit-taiwan', 'mobile_starhub': 'mobile-dmit-starhub',
            'mobile_hkt': 'mobile-dmit-hkt', 'mobile_singtel': 'mobile-dmit-singtel'}
OUTBOUNDS = {'direct': 'direct', 'hk': 'bytevirt-hk', 'taiwan': 'bytevirt-taiwan',
             'starhub': 'lazycat-starhub', 'hkt': 'lazycat-hkt', 'singtel': 'uzuma-singtel',
             'bt': 'violation-bt-quarantine'}
CONTROL_DOMAINS = ('node.titanyung.click', 'dnode.titanyung.click')
DMIT_IP = '179.255.136.79'
RESOLVER_TAG = 'server-policy-dns'
TVB_SUFFIXES = ('tvb.com', 'tvb.com.au', 'mytvsuper.com', 'tvbanywhere.com',
                'tvbanywhereplus.com', 'viu.tv', 'viutv.hk', 'viu.com')
YOUTUBE_SUFFIXES = ('youtube.com', 'youtu.be', 'youtube-nocookie.com', 'googlevideo.com',
                    'ytimg.com', 'youtube.googleapis.com', 'youtubei.googleapis.com',
                    'youtubemusic.com', 'yt.be')
NETFLIX_SUFFIXES = ('netflix.com', 'netflix.net', 'nflxvideo.net', 'nflximg.net', 'nflxso.net', 'nflxext.com')
GOOGLE_AI_SUFFIXES = ('google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com',
                     'ggpht.com', 'gvt1.com', 'gvt2.com', 'openai.com', 'chatgpt.com',
                     'oaistatic.com', 'oaiusercontent.com', 'anthropic.com', 'claude.ai',
                     'claudeusercontent.com', 'perplexity.ai', 'generativelanguage.googleapis.com')
WECHAT_SUFFIXES = ('weixin.qq.com', 'wechat.com', 'weixinbridge.com', 'qpic.cn', 'qlogo.cn', 'wx.qq.com')
BINANCE_SUFFIXES = ('binance.com', 'binance.me', 'binance.info', 'binancefuture.com',
                   'binance.cloud', 'bnbstatic.com', 'bnappzh.com')
_BUNDLE_TOKEN = object()


class ServerPolicyError(ValueError):
    """Fixed errors deliberately contain no credential or subscription content."""


def _require(condition, label):
    if not condition:
        raise ServerPolicyError('server_policy_' + label)


class VerifiedRuleSets:
    def __init__(self, definitions, proof, token):
        _require(token is _BUNDLE_TOKEN, 'verified_rule_sets_required')
        self._definitions = json.dumps(definitions, sort_keys=True)
        self._proof = json.dumps(proof, sort_keys=True)

    @property
    def definitions(self):
        return json.loads(self._definitions)

    @property
    def proof(self):
        return json.loads(self._proof)


def load_rule_sets(manifest, *, require_root=True):
    """Verify eight already-downloaded local rule assets; never fetch anything.

    Each semantic key maps to path, format(source/binary), sha256 and source.
    Source is a credential-free provenance description or pinned upstream URL.
    The publisher must repeat this hash check after staging and before commit.
    """
    _require(isinstance(manifest, dict) and set(manifest) == set(ASSET_KEYS), 'rule_set_inventory_invalid')
    definitions, proof = [], {}
    for key in ASSET_KEYS:
        entry = manifest[key]
        _require(isinstance(entry, dict) and set(entry) == {'path', 'format', 'sha256', 'source'}, 'rule_set_fields_invalid')
        path = Path(entry['path']) if isinstance(entry.get('path'), str) else Path()
        _require(path.is_absolute() and entry.get('format') in {'source', 'binary'}, 'rule_set_path_invalid')
        digest = entry.get('sha256')
        _require(isinstance(digest, str) and bool(re.fullmatch(r'[0-9a-f]{64}', digest)), 'rule_set_hash_invalid')
        provenance = entry.get('source')
        _require(isinstance(provenance, str) and 0 < len(provenance) <= 2048 and
                 '\n' not in provenance and not re.search(r'(?:token|password|secret)=', provenance, re.I),
                 'rule_set_source_invalid')
        try:
            fd = os.open(str(path), os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                posix_mode_safe = not info.st_mode & 0o022 or (os.name == 'nt' and not require_root)
                root_safe = not require_root or (os.name != 'nt' and info.st_uid == 0)
                _require(stat.S_ISREG(info.st_mode) and posix_mode_safe and root_safe,
                         'rule_set_permissions_invalid')
                raw = stream.read(64 * 1024 * 1024 + 1)
        except OSError:
            raise ServerPolicyError('server_policy_rule_set_unavailable') from None
        _require(0 < len(raw) <= 64 * 1024 * 1024 and hashlib.sha256(raw).hexdigest() == digest,
                 'rule_set_content_changed')
        if entry['format'] == 'source':
            try:
                content = json.loads(raw)
            except (ValueError, UnicodeError):
                raise ServerPolicyError('server_policy_rule_set_source_invalid') from None
            _require(isinstance(content, dict) and type(content.get('version')) is int and
                     content['version'] in {1, 2, 3, 4} and isinstance(content.get('rules'), list) and
                     bool(content['rules']), 'rule_set_source_invalid')
        tag = 'server-' + key.replace('_', '-')
        definitions.append({'type': 'local', 'tag': tag, 'format': entry['format'], 'path': str(path)})
        proof[key] = {'sha256': digest, 'source': provenance, 'size': len(raw)}
    return VerifiedRuleSets(definitions, proof, _BUNDLE_TOKEN)


def _inventory(config, inbound_tags, outbound_tags):
    _require(isinstance(config, dict), 'config_required')
    _require(set(inbound_tags) in (set(INBOUNDS),set(INBOUNDS)|{'zoro','mobile_zoro'}) and len(set(inbound_tags.values())) == len(inbound_tags),
             'inbound_mapping_invalid')
    _require(set(outbound_tags) in (set(OUTBOUNDS),set(OUTBOUNDS)|{'zoro'}) and len(set(outbound_tags.values())) == len(outbound_tags),
             'outbound_mapping_invalid')
    ins, outs = config.get('inbounds'), config.get('outbounds')
    _require(isinstance(ins, list) and isinstance(outs, list) and
             all(isinstance(row, dict) and isinstance(row.get('tag'), str) for row in ins + outs),
             'runtime_inventory_invalid')
    inbound = {row['tag']: row for row in ins}
    outbound = {row['tag']: row for row in outs}
    _require(len(inbound) == len(ins) and set(inbound) == set(inbound_tags.values()), 'twelve_decrypted_fronts_required')
    _require(len(outbound) == len(outs) and set(outbound_tags.values()) == set(outbound), 'outbound_inventory_invalid')
    cohort, tls = None, None
    ports = []
    for row in ins:
        _require(row.get('type') == 'anytls' and isinstance(row.get('users'), list) and row['users'] and
                 isinstance(row.get('tls'), dict) and row['tls'].get('enabled') is True,
                 'authenticated_front_required')
        _require(type(row.get('listen_port')) is int and 1 <= row['listen_port'] <= 65535,
                 'front_port_invalid')
        ports.append(row['listen_port'])
        users = row['users']
        _require(all(isinstance(user, dict) and isinstance(user.get('name'), str) and user['name'] and
                     isinstance(user.get('password'), str) and len(user['password']) >= 24 for user in users),
                 'front_users_invalid')
        current = {user['name']: user['password'] for user in users}
        _require(len(current) == len(users), 'front_users_invalid')
        if cohort is None:
            cohort, tls = current, row['tls']
        _require(current == cohort and row['tls'] == tls, 'front_user_or_tls_mismatch')
    _require(len(set(ports)) == len(ports), 'front_port_collision')
    _require(outbound[outbound_tags['direct']].get('type') == 'direct', 'direct_outbound_invalid')
    hk = outbound[outbound_tags['hk']]
    _require(hk.get('type') in {'anytls', 'shadowsocks'}, 'dedicated_hk_transport_required')
    if hk['type'] == 'anytls':
        _require(isinstance(hk.get('tls'), dict) and hk['tls'].get('enabled') is True and
                 hk['tls'].get('insecure', False) is False, 'hk_tls_verification_required')
    quarantine = outbound[outbound_tags['bt']]
    _require(quarantine.get('type') == 'socks' and quarantine.get('server') == '127.0.0.1' and
             quarantine.get('server_port') == 18115, 'bt_quarantine_changed')
    for key in ('hk', 'taiwan', 'starhub', 'hkt', 'singtel')+ (('zoro',) if 'zoro' in outbound_tags else ()):
        row = outbound[outbound_tags[key]]
        _require(row.get('type') in {'anytls', 'shadowsocks'} and
                 isinstance(row.get('password'), str) and len(row['password']) >= 16 and
                 isinstance(row.get('server'), str) and row['server'] and
                 type(row.get('server_port')) is int and 1 <= row['server_port'] <= 65535,
                 'verified_transport_required')
        _require(row.get('detour') in (None, '', outbound_tags['direct']), 'transport_detour_cycle_forbidden')
        _require(not (row['server'] in {DMIT_IP, *CONTROL_DOMAINS, '127.0.0.1', '::1'} and
                      row['server_port'] in ports), 'self_transport_cycle_forbidden')
        if row['type'] == 'shadowsocks':
            _require(row.get('method') in {'chacha20-ietf-poly1305', 'aes-128-gcm', 'aes-256-gcm',
                     '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
                     '2022-blake3-chacha20-poly1305'}, 'encrypted_transport_required')
    return inbound, outbound, cohort


def build_server_route_policy(config, *, rule_sets, user_platforms=None, service_ip_routes=None,
                              private_endpoints=None, remote_domains=(),
                              inbound_tags=None, outbound_tags=None, resolver_tag=RESOLVER_TAG,
                              legacy_inbounds=(), client_policy=None,zoro_transport=None):
    """Apply native domain/IP policy to all twelve decrypted AnyTLS frontends.

    Mobile/desktop inlets identify platform without changing user credentials.
    Explicit SG inlet choices win; remarks apply only to caller-designated
    legacy inlets. IP bindings come from the current transport audit.
    """
    _require(isinstance(rule_sets, VerifiedRuleSets), 'verified_rule_sets_required')
    inbound_tags, outbound_tags = dict(inbound_tags or INBOUNDS), dict(outbound_tags or OUTBOUNDS)
    if zoro_transport is not None:
        inbound_tags.update(zoro='dmit-zoro-sg',mobile_zoro='mobile-dmit-zoro-sg');outbound_tags['zoro']='zoro-sg'
    inbound, outbound, cohort = _inventory(config, inbound_tags, outbound_tags)
    platforms = dict(user_platforms or {})
    _require(set(platforms).issubset(cohort) and all(isinstance(value, str) and value in {'mobile', 'desktop', 'router'}
             for value in platforms.values()), 'user_platform_mapping_invalid')
    legacy = set(legacy_inbounds)
    _require(legacy.issubset(set(inbound_tags.values())) and not legacy.intersection(
             tag for key, tag in inbound_tags.items() if key.startswith('mobile_') or
             key in {'starhub', 'singtel'}), 'legacy_inlet_hint_invalid')
    tags = list(inbound_tags.values())
    output = copy.deepcopy(config)
    rules = []
    def add(match, target=None, action='route', **extra):
        row = {'inbound': tags, **copy.deepcopy(match), 'action': action, **extra}
        if target is not None:
            row['outbound'] = outbound_tags[target]
        rules.append(row)
    add({'network': ['tcp']}, action='sniff', sniffer=['tls', 'http', 'bittorrent'], timeout='1s')
    add({'protocol': ['bittorrent']}, 'bt')
    add({'protocol': ['bittorrent']}, action='reject')
    add({'network': ['udp']}, action='reject')
    # Resolve before private-endpoint guards so a DNS alias cannot turn a
    # client request into a nested transport or a recursion through DMIT.
    # Existing clients already query two DoH IPs concurrently. Keep each on an
    # independent authenticated egress, before any server-side DNS resolution.
    # These exact public endpoints and TCP 443 do not bypass private-target guards.
    for address, target in (('1.1.1.1/32','taiwan'),('1.0.0.1/32','zoro' if 'zoro' in outbound_tags else 'singtel'),
                            ('8.8.8.8/32','singtel')):
        add({'ip_cidr':[address], 'network':['tcp'], 'port':[443]},target)
    add({}, action='resolve', strategy='ipv4_only', timeout='5s')
    endpoint_rows = list(private_endpoints or [])
    # Cached old HK chains would otherwise carry another encrypted proxy
    # session, hiding the real target from second-stage domain inspection.
    endpoint_rows.append({'server': '61.15.36.199', 'port': 2443})
    for key in ('hk', 'taiwan', 'starhub', 'hkt', 'singtel')+ (('zoro',) if 'zoro' in outbound_tags else ()):
        row = outbound[outbound_tags[key]]
        endpoint_rows.append({'server': row['server'], 'port': row['server_port']})
    front_ports = [row['listen_port'] for row in inbound.values()]
    endpoint_rows.extend({'server': DMIT_IP, 'port': port} for port in front_ports)
    if client_policy is not None:
        from client_policy import front_ports as revision_ports
        alias_ports = {port for kind in ('mobile','desktop') for test in (False,True)
                       for port in revision_ports(kind,test_mode=test).values()}
        alias_ports.update({30115,30117,30119,30215,30217,30219})
        endpoint_rows.extend({'server': DMIT_IP, 'port': port} for port in sorted(alias_ports))
    seen = set()
    for endpoint in endpoint_rows:
        _require(isinstance(endpoint, dict) and set(endpoint) == {'server', 'port'} and
                 isinstance(endpoint['server'], str) and type(endpoint['port']) is int and
                 1 <= endpoint['port'] <= 65535, 'private_endpoint_invalid')
        host, port = endpoint['server'], endpoint['port']
        if (host, port) in seen:
            continue
        seen.add((host, port))
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            _require(bool(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', host)), 'endpoint_host_invalid')
            add({'domain': [host], 'port': [port]}, action='reject')
        else:
            add({'ip_cidr': [str(address) + '/' + str(address.max_prefixlen)], 'port': [port]}, action='reject')
    # Do not expose DMIT's loopback/private management network through VPN.
    # Client LAN DIRECT remains a client rule and never reaches this server.
    add({'ip_is_private': True}, action='reject')
    add({'ip_cidr': ['0.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '224.0.0.0/4',
                     '::/128', '::1/128', 'fe80::/10', 'ff00::/8']}, action='reject')
    if client_policy is not None:
        from client_policy import REVISION, SITES
        _require(client_policy.get('revision') == REVISION, 'client_policy_revision_invalid')
        # Dedicated IP-test destinations always use their documented physical exit.
        for _, domain, target in SITES.values():
            if domain != 'ipinfo.io':
                add({'domain_suffix': [domain]}, target)
        manual = sorted(set(client_policy['test_users']).intersection(cohort))
        # The independent test subscription binds choice to authenticated ingress.
        # Guards against private destinations, recursion, BT and UDP remain first.
        if manual:
            for key, tag in inbound_tags.items():
                target = key[7:] if key.startswith('mobile_') else key
                add({'inbound':[tag], 'auth_user':manual}, target)
    add({'domain': list(CONTROL_DOMAINS)}, 'direct')
    add({'ip_cidr': [DMIT_IP + '/32']}, 'direct')
    add({'domain_suffix': list(WECHAT_SUFFIXES)}, 'taiwan')
    if remote_domains:
        _require(all(isinstance(domain, str) and re.fullmatch(r'[A-Za-z0-9.-]+', domain)
                     for domain in remote_domains), 'remote_domain_invalid')
        add({'domain_suffix': list(remote_domains)}, 'taiwan')
    for host, target in (('dmit.io', 'direct'), ('www.dmit.io', 'direct'),
                         ('bytevirt.com', 'hk'), ('www.bytevirt.com', 'hk'),
                         ('dash.lazycat.wiki', 'starhub'), ('uzuma.ru', 'singtel')):
        add({'domain': [host]}, target)
    service_targets = {}
    for binding in service_ip_routes or []:
        _require(isinstance(binding, dict) and set(binding) == {'ip_cidr', 'target'} and
                 isinstance(binding['target'], str) and binding['target'] in set(OUTBOUNDS) - {'bt'},
                 'service_ip_binding_invalid')
        try:
            network = ipaddress.ip_network(binding['ip_cidr'], strict=True)
        except (ValueError, TypeError):
            raise ServerPolicyError('server_policy_service_ip_binding_invalid') from None
        _require(network.prefixlen == network.max_prefixlen and network.is_global,
                 'service_ip_binding_must_be_exact_public_host')
        _require(str(network.network_address) != DMIT_IP or binding['target'] == 'direct',
                 'dmit_bootstrap_loop_forbidden')
        _require(str(network) not in service_targets or service_targets[str(network)] == binding['target'],
                 'service_ip_binding_conflict')
        if str(network) in service_targets:
            continue
        service_targets[str(network)] = binding['target']
        add({'ip_cidr': [str(network)]}, binding['target'])
    asset = {key: 'server-' + key.replace('_', '-') for key in ASSET_KEYS}
    # Once a request reaches DMIT, domestic classification overrides normal
    # business categories. Only audited bootstrap/provider exceptions precede it.
    add({'rule_set': [asset['cn_domain']]}, 'taiwan')
    add({'rule_set': [asset['cn_ip']]}, 'taiwan')
    add({'domain_suffix': list(TVB_SUFFIXES)}, 'hk')
    add({'domain_suffix': list(NETFLIX_SUFFIXES)}, 'hkt')
    add({'rule_set': [asset['netflix']]}, 'hkt')
    add({'domain_suffix': list(YOUTUBE_SUFFIXES + BINANCE_SUFFIXES)}, 'taiwan')
    add({'rule_set': [asset['youtube']]}, 'taiwan')
    singtel_tags = [tag for key, tag in inbound_tags.items() if key in {'singtel', 'mobile_singtel'}]
    starhub_tags = [tag for key, tag in inbound_tags.items() if key in {'starhub', 'mobile_starhub'}]
    mobile_tags = [tag for key, tag in inbound_tags.items() if key.startswith('mobile_') and
                   key not in {'mobile_starhub', 'mobile_singtel','mobile_zoro'}]
    desktop_tags = [tag for key, tag in inbound_tags.items() if not key.startswith('mobile_') and
                    key not in {'starhub', 'singtel','zoro'} and tag not in legacy]
    mobile = sorted(user for user, kind in platforms.items() if kind == 'mobile')
    desktop = sorted(user for user, kind in platforms.items() if kind in {'desktop', 'router'})
    criteria = [{'domain_suffix': list(GOOGLE_AI_SUFFIXES)}, {'rule_set': [asset['google'], asset['ai']]}]
    if client_policy is not None:
        from client_policy import SENSITIVE_SUFFIXES
        criteria.insert(0, {'domain_suffix':list(SENSITIVE_SUFFIXES)+['ipinfo.io']})
    for index, criterion in enumerate(criteria):
        if client_policy is not None:
            if zoro_transport is not None:
                zoro_tags=[tag for key,tag in inbound_tags.items() if key in {'zoro','mobile_zoro'}]
                # Lazycat is a manual-only option. It is never an automatic
                # backup, even if its access-network check later recovers.
                for z in (False,True):
                    for u in (False,True):
                        for l in (False,True):
                            mode='ai-z'+str(int(z))+'s'+str(int(u))+'l'+str(int(l))
                            desktop_target='zoro' if z else 'singtel' if u else None
                            mobile_target='singtel' if u else 'zoro' if z else None
                            for fronts,target in [(starhub_tags,'starhub' if l else desktop_target),
                                                  (singtel_tags,mobile_target),(zoro_tags,desktop_target),
                                                  (mobile_tags,mobile_target),(desktop_tags,desktop_target)]:
                                if target and fronts:add({**criterion,'clash_mode':mode,'inbound':fronts},target)
            else:
                add({**criterion,'clash_mode':'sg-singtel-only'},'singtel')
                add({**criterion,'clash_mode':'sg-starhub-only'},'starhub')
                add({**criterion,'clash_mode':'sg-both','inbound':singtel_tags},'singtel')
                add({**criterion,'clash_mode':'sg-both','inbound':starhub_tags},'starhub')
                add({**criterion,'clash_mode':'sg-both','inbound':mobile_tags},'singtel')
                add({**criterion,'clash_mode':'sg-both','inbound':desktop_tags},'starhub')
            if index == 0:add(criterion, action='reject')
            else:add(criterion,'taiwan')
            continue
        if singtel_tags:
            add({**criterion, 'inbound': singtel_tags}, 'singtel')
        if starhub_tags:
            add({**criterion, 'inbound': starhub_tags}, 'starhub')
        add({**criterion, 'inbound': mobile_tags}, 'singtel')
        if desktop_tags:
            add({**criterion, 'inbound': desktop_tags}, 'starhub')
        if legacy:
            if mobile:
                add({**criterion, 'inbound': sorted(legacy), 'auth_user': mobile}, 'singtel')
            if desktop:
                add({**criterion, 'inbound': sorted(legacy), 'auth_user': desktop}, 'starhub')
            add({**criterion, 'inbound': sorted(legacy)}, 'starhub')
    add({'rule_set': [asset['entertainment']]}, 'taiwan')
    add({'rule_set': [asset['hk_ip']]}, 'hkt')
    add({'network': ['tcp']}, 'taiwan')
    rules.append({'action': 'reject'})
    route = copy.deepcopy(output.get('route') or {})
    rules = inject_exact_domain_overrides(rules, inbounds=tags)
    # sing-box 1.14 requires a legal generic-dialer bootstrap. All managed
    # requests resolve earlier through DNS rules (the resolve action has no server).
    # Only a previously unresolved generic dialer uses this independent last path.
    route.update(rules=rules, rule_set=rule_sets.definitions, final=outbound_tags['taiwan'],
                 default_domain_resolver={'server': resolver_tag+'-singtel', 'strategy': 'ipv4_only'})
    route.pop('geosite', None)
    route.pop('geoip', None)
    output['route'] = route
    # Literal upstream addresses avoid a bootstrap dependency. Each request
    # retries independent providers over independent authenticated egress paths.
    primary = {'type':'https','tag':resolver_tag,'server':'1.1.1.1','server_port':443,
               'path':'/dns-query','tls':{'enabled':True,'server_name':'cloudflare-dns.com'},
               'detour':outbound_tags['taiwan']}
    secondary_tag, tertiary_tag = resolver_tag+'-sptel', resolver_tag+'-singtel'
    secondary = {'type':'https','tag':secondary_tag,'server':'8.8.8.8','server_port':443,
                 'path':'/dns-query','tls':{'enabled':True,'server_name':'dns.google'},
                 'detour':outbound_tags.get('zoro',outbound_tags['singtel'])}
    tertiary = {'type':'https','tag':tertiary_tag,'server':'8.8.8.8','server_port':443,
                'path':'/dns-query','tls':{'enabled':True,'server_name':'dns.google'},
                'detour':outbound_tags['singtel']}
    definitions = [primary,secondary,tertiary]
    tags = {row['tag'] for row in definitions}
    fallback_rules = [
        {'action':'evaluate','server':resolver_tag,'timeout':'1200ms'},
        {'match_response':True,'response_rcode':'NOERROR','action':'respond'},
        {'match_response':True,'response_rcode':'NXDOMAIN','action':'respond'},
        {'action':'evaluate','server':secondary_tag,'timeout':'1500ms'},
        {'match_response':True,'response_rcode':'NOERROR','action':'respond'},
        {'match_response':True,'response_rcode':'NXDOMAIN','action':'respond'},
        {'action':'route','server':tertiary_tag,'timeout':'1500ms'},
    ]
    dns = copy.deepcopy(output.get('dns') or {})
    servers = dns.get('servers') or []
    _require(isinstance(servers,list) and all(isinstance(row,dict) for row in servers),'dns_inventory_invalid')
    for row in servers:
        if row.get('tag') in tags:
            _require(row == next(item for item in definitions if item['tag']==row['tag']),'dns_tag_collision')
    _require(not dns.get('rules') or dns['rules']==fallback_rules,'dns_rules_collision')
    dns['servers'] = [row for row in servers if row.get('tag') not in tags] + definitions
    dns.update(rules=fallback_rules,final=tertiary_tag,strategy='ipv4_only')
    output['dns'] = dns
    if client_policy is not None:
        output.setdefault('experimental',{}).setdefault('clash_api',{})['default_mode']='sg-none'
    return output


def policy_report(config, *, user_platforms=None):
    """Credential-free operator report; this is not a native configuration field."""
    cohort = {user['name'] for row in config.get('inbounds', []) for user in row.get('users', [])}
    platforms = user_platforms or {}
    return {'policy': POLICY_ID, 'classifier': 'native sniff/domain/rule_set/ip',
            'exact_destination_overrides': len(EXACT_SERVICE_DOMAINS),
            'destination_override_scope': 'known complete sniffed hostnames only; unknown subdomains and ECH excluded',
            'platform_source': 'mobile/desktop authenticated frontend, SG selection hint first',
            'ai_unknown_default': 'ZORO when enabled; legacy StarHub otherwise', 'users_without_device_hint': sorted(cohort - set(platforms)),
            'server_direct_egress': 'DMIT, not the remote client local network',
            'domestic_requests_received_by_dmit': 'Taiwan HINET NAT; client-local DIRECT rules unchanged',
            'wechat_and_remote_requests_received_by_dmit': 'Taiwan HINET NAT',
            'opaque_nested_proxy_inspection': False, 'unobservable_hostname_fallback': 'Taiwan',
            'unobservable_hostname_limit': 'Audited IP categories still apply; ECH cannot be reconstructed',
            'native_rules': len((config.get('route') or {}).get('rules', [])),
            'dns_failover': 'per-request Taiwan/Cloudflare -> SPTel/Google -> Singtel/Google',
            'client_doh_egress': '1.1.1.1/Taiwan; 1.0.0.1/SPTel; 8.8.8.8/Singtel'}
