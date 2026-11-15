"""Topology retirement overlay; no schema changes or history deletion."""
import copy
from contextlib import closing
import ipaddress
import json
import os
from pathlib import Path
import sqlite3
import stat
import time

try:
    import network_stats as _network_stats
except ImportError:
    _network_stats = None

MANIFEST = '/var/lib/sg-traffic-dashboard/topology-20261105.json'
ACTIVE_HOSTS = ('DMIT', 'ByteVirt-HK ISP', 'zorocloud')
TAIWAN_HOST = 'ByteVirt-TW'
SUPPORTED_ACTIVE_HOSTS = ACTIVE_HOSTS + (TAIWAN_HOST,)
RELAY_PEERS = {'zorocloud': 'zorocloud', 'bytevirt_taiwan': TAIWAN_HOST}
ACTIVE_ORIGINS = frozenset({'dmit', 'hk'})
PEER_FIELDS = frozenset({'kookeey', 'lazycat', 'lazycat_hkt', 'static_outbound',
                        'static_wire', 'static_wire_sampled_at',
                        'static_wire_started_at', 'static_wire_discontinuities',
                        'static_provider_expiry'})
_CACHE = {}


def active_host_names(manifest=None):
    if _network_stats and _network_stats.is_network_manifest(manifest):
        _network_stats.validate_manifest(manifest)
        return _network_stats.active_host_names(manifest)
    names = tuple((manifest or {}).get('active_hosts', ACTIVE_HOSTS))
    if names not in (ACTIVE_HOSTS, SUPPORTED_ACTIVE_HOSTS):
        raise ValueError('unexpected active topology')
    return names


def read_manifest(path=None):
    path = Path(path or os.environ.get('TOPOLOGY_ARCHIVE_MANIFEST', MANIFEST))
    info = path.stat()
    key = (str(path.resolve()), info.st_mtime_ns, info.st_size)
    if key in _CACHE:
        return _CACHE[key]
    if info.st_size > 4 * 1024 * 1024 or not stat.S_ISREG(info.st_mode):
        raise ValueError('invalid topology manifest file')
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError('topology manifest must be root private')
    value = json.loads(path.read_text(encoding='utf-8'))
    if _network_stats and _network_stats.is_network_manifest(value):
        _network_stats.validate_manifest(value)
        _CACHE.clear()
        _CACHE[key] = value
        return value
    if value.get('schema') != 1 or 'active_hosts' not in value:
        raise ValueError('unexpected active topology')
    active = active_host_names(value)
    if type(value.get('cutoff')) is not int or value['cutoff'] <= 0:
        raise ValueError('invalid topology cutoff')
    for field in ('retired_host_cards', 'retired_user_usage', 'peer_snapshots', 'sample_commands'):
        if not isinstance(value.get(field, {}), dict):
            raise ValueError('invalid topology object')
    retired = value.get('retired_host_cards', {})
    if set(retired).intersection(active) or any(not isinstance(card, dict) for card in retired.values()):
        raise ValueError('active host cannot be archived')
    commands = value.get('sample_commands', {})
    if set(commands).difference({'zorocloud', TAIWAN_HOST}) or set(commands).difference(active):
        raise ValueError('unexpected new sampling host')
    for command in commands.values():
        if not isinstance(command, list) or not command or any(not isinstance(item, str) or not item for item in command):
            raise ValueError('invalid sampling command')
    _CACHE.clear()
    _CACHE[key] = value
    return value


def extend_manifest_with_taiwan(manifest, sample_command, exit_observation=None):
    """Add this active host without rebuilding or retiming any old snapshot."""
    active_host_names(manifest)
    if (not isinstance(sample_command, list) or not sample_command or
            any(not isinstance(item, str) or not item for item in sample_command)):
        raise ValueError('invalid Taiwan sampling command')
    if TAIWAN_HOST in manifest.get('retired_host_cards', {}):
        raise ValueError('Taiwan is already archived')
    result = copy.deepcopy(manifest)
    result['active_hosts'] = list(SUPPORTED_ACTIVE_HOSTS)
    result.setdefault('sample_commands', {})[TAIWAN_HOST] = list(sample_command)
    if exit_observation is not None:
        result.setdefault('exit_observations', {})[TAIWAN_HOST] = copy.deepcopy(exit_observation)
    return result


def attach_exit_observations(result, manifest, now):
    for peer, observation in (manifest or {}).get('exit_observations', {}).items():
        network = _network_stats and _network_stats.is_network_manifest(manifest)
        if (peer not in (_network_stats.active_host_names(manifest) if network else (TAIWAN_HOST,)) or
                peer not in result.get('servers', {}) or not isinstance(observation, dict)):
            continue
        try:
            address = ipaddress.ip_address(observation.get('ip', ''))
            measured_at = observation.get('observed_at')
            if not address.is_global or type(measured_at) is not int or not 0 < measured_at <= now:
                continue
        except ValueError:
            continue
        result['servers'][peer]['exit_observation'] = {
            'ip': str(address), 'observed_at': measured_at,
            'basis': 'point_in_time_public_exit_probe', 'dynamic': True}
    return result


def build_manifest(payload, cutoff, sample_commands=None):
    """Construct an immutable snapshot from the protected current API payload."""
    whole = payload['whole']
    cards = {name: copy.deepcopy(card) for name,card in whole['servers'].items()
             if name not in ACTIVE_HOSTS}
    preserved_users = {name for name,card in cards.items()
                       if card.get('expired') and isinstance(card.get('historical_user_usage'), list)}
    users = {name: copy.deepcopy(card['historical_user_usage']) if name in preserved_users else []
             for name,card in cards.items()}
    for row in payload.get('server_user_usage', []):
        if row.get('server') in users and row['server'] not in preserved_users:
            users[row['server']].append({'user': row['user'], 'total': int(row['total'])})
    peers = {name: {field: copy.deepcopy(card[field]) for field in PEER_FIELDS if field in card}
             for name,card in whole['servers'].items() if name in ACTIVE_HOSTS}
    return {'schema': 1, 'cutoff': int(cutoff), 'active_hosts': list(ACTIVE_HOSTS),
            'retired_host_cards': cards, 'retired_user_usage': users,
            'peer_snapshots': peers, 'sample_commands': sample_commands or {},
            'bootstrap_payload': copy.deepcopy(payload)}


def install_collector(base, manifest=None):
    """Whitelist both NIC polling and access export; preserve stored records."""
    manifest = manifest or read_manifest()
    if _network_stats and _network_stats.is_network_manifest(manifest):
        commands = dict(base.HOSTS)
        commands.update(manifest.get('sample_commands', {}))
        base.HOSTS = {name: command for name, command in commands.items()
                      if name in _network_stats.active_host_names(manifest)}
        if set(base.HOSTS) != set(_network_stats.active_host_names(manifest)):
            raise ValueError('six-server sampling commands incomplete')
        base.RECORD_HOSTS = {name: command for name, command in base.RECORD_HOSTS.items()
                            if name in ACTIVE_ORIGINS}
        original_sample, original_route, original_store = base.sample, base.route, base.store
        base.sample = lambda item: _network_stats.collector_sample(original_sample, item, manifest)
        def network_route(origin, row):
            peers = dict(_network_stats.relay_peer_names(manifest), zorocloud='zorocloud')
            if origin == 'dmit' and _network_stats.server_policy_enabled(manifest) and row.get('route_class') == 'direct':
                return 'DMIT', '直连', '直连'
            if origin == 'dmit' and row.get('route_class') in peers:
                return 'DMIT', '中转', peers[row['route_class']]
            return original_route(origin, row)
        base.route = network_route
        base.store = lambda db, host, item, error: _network_stats.store_epoch_sample(
            original_store, db, host, item, error, manifest)
        return base
    commands = dict(base.HOSTS)
    commands.update(manifest.get('sample_commands', {}))
    base.HOSTS = {name: command for name,command in commands.items() if name in active_host_names(manifest)}
    base.RECORD_HOSTS = {name: command for name,command in base.RECORD_HOSTS.items()
                         if name in ACTIVE_ORIGINS}
    original_sample = base.sample
    original_route = base.route
    def sample(item):
        server,value,error = original_sample(item)
        if not error and value and set(RELAY_PEERS).intersection(value.get('static_egress', {})):
            value = copy.deepcopy(value)
            for route,peer in RELAY_PEERS.items():
                if route not in value['static_egress']:
                    continue
                amount = value['static_egress'].pop(route)
                if type(amount) is not int or amount < 0:
                    return server,None,'InvalidRelayApplicationCounter'
                value.setdefault('sui_outbound', {})['topology:' + route] = amount
        return server,value,error
    def route(origin,row):
        if origin == 'dmit' and row.get('route_class') in RELAY_PEERS:
            return 'DMIT','中转',RELAY_PEERS[row['route_class']]
        return original_route(origin,row)
    base.sample = sample
    base.route = route
    return base


def empty_card():
    result = {field: None for field in ('in', 'out', 'today_in', 'today_out', 'sampled_at',
              'proxy_app', 'proxy_wire', 'mapping_wire', 'direct', 'kookeey', 'bytevirt',
              'lazycat', 'lazycat_hkt', 'static_wire_sampled_at', 'static_wire_started_at',
              'static_wire_discontinuities')}
    result.update(static_outbound={}, static_wire={}, details={})
    return result


def add_relay_application_observation(live, db_path, peer, now=None, traffic_start=0):
    """Attach confirmed DMIT-side bytes without inventing a Zoro meter.

    Rows are unique by (origin,id) and updated in place by the collector, so
    summing their current counters counts a session once. This is the same
    30-day session-start window as active_user_usage, not a lifetime S-UI
    counter and not an additional term in physical NIC totals.
    """
    if peer not in RELAY_PEERS.values():
        raise ValueError('unsupported relay observation')
    card=live.get('servers',{}).get(peer)
    if card is None or not Path(db_path).is_file():
        return live
    now=int(time.time() if now is None else now)
    start=max(int(traffic_start),now-30*86400)
    with closing(sqlite3.connect(Path(db_path).resolve().as_uri()+'?mode=ro',uri=True,timeout=2)) as db:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='unified_records'").fetchone():
            card['application_observation']=None
            card['application_observation_state']='source_table_unavailable'
            return live
        # This partial covering index starts with origin,relay,started. Only
        # the confirmed Zoro slice needs table lookups for ingress/changed;
        # retired provider histories are never scanned.
        deadline=time.monotonic()+2
        db.set_progress_handler(lambda:time.monotonic()>deadline,10000)
        row=db.execute('SELECT COUNT(*),COUNT(DISTINCT user),SUM(upload),SUM(download),'
            'MIN(started),MAX(started),MAX(changed) FROM unified_records '
            'INDEXED BY idx_unified_hk_usage '
            "WHERE origin='dmit' AND relay=? AND started>=? AND started<=? "
            "AND traffic_known=1 AND route_type='中转' AND ingress='DMIT' "
            'AND upload>=0 AND download>=0 AND changed<=?',(peer,start,now,now)).fetchone()
    if not row[0]:
        card['application_observation']=None
        card['application_observation_state']='no_confirmed_sessions_in_window'
        return live
    observation={'observed_on':'DMIT','first_hop':'DMIT','relay':peer,'route_type':'中转',
        'source':'unified_records','meter_basis':'confirmed_proxy_forwarding_application',
        'estimated':True,'independent_egress_meter':False,
        'upload':int(row[2]),'download':int(row[3]),'bytes':int(row[2])+int(row[3]),
        'sessions':int(row[0]),'users':int(row[1]),
        'first_session_started':int(row[4]),'latest_session_started':int(row[5]),
        'last_observed_at':int(row[6]),'window_start':start,'window_end':now}
    card['application_observation']=observation
    card['application_observation_state']='confirmed_forwarding_observation'
    # The same bytes are measured at the DMIT relay boundary; this map is a
    # classified path view, not a second source to add to existing totals.
    dmit=live.get('servers',{}).get('DMIT')
    if dmit is not None:
        dmit.setdefault('relay_observations',{})[peer]=dict(observation,estimated=False)
    return live


def add_zoro_application_observation(live, db_path, now=None, traffic_start=0):
    for peer in RELAY_PEERS.values():
        if peer in live.get('servers', {}):
            add_relay_application_observation(live, db_path, peer, now, traffic_start)
    return live


def add_zoro_from_samples(live, db_path, now=None, traffic_start=0):
    """Use the same normal NIC sample table; an absent sample is never zero."""
    result = copy.deepcopy(live)
    result.setdefault('servers', {})
    now = int(time.time() if now is None else now)
    if 'zorocloud' in result['servers']:
        return add_zoro_application_observation(result,db_path,now,traffic_start)
    card = empty_card()
    result['servers']['zorocloud'] = card
    if not Path(db_path).is_file():
        return result
    start = max(int(traffic_start), now - 30 * 86400)
    today = now - ((now + 8 * 3600) % 86400)
    with closing(sqlite3.connect(Path(db_path).resolve().as_uri() + '?mode=ro', uri=True, timeout=5)) as db:
        row = db.execute('SELECT COUNT(*),SUM(delta_rx),SUM(delta_tx),'
            'SUM(CASE WHEN ts>=? THEN delta_rx ELSE 0 END),'
            'SUM(CASE WHEN ts>=? THEN delta_tx ELSE 0 END),MAX(ts) '
            'FROM samples WHERE server=? AND ts>=?', (today,today,'zorocloud',start)).fetchone()
        if not row[0]:
            return add_zoro_application_observation(result,db_path,now,traffic_start)
        card.update({'in': int(row[1] or 0), 'out': int(row[2] or 0),
                     'today_in': int(row[3] or 0), 'today_out': int(row[4] or 0),
                     'sampled_at': int(row[5])})
        raw = db.execute('SELECT sui_json FROM samples WHERE server=? AND ts<=? '
                         'ORDER BY ts DESC LIMIT 1', ('zorocloud',now)).fetchone()
        try:
            counters = json.loads(raw[0]) if raw else {}
            counters = {str(key): int(value) for key,value in counters.items() if int(value) >= 0}
        except (TypeError, ValueError, AttributeError):
            counters = {}
        if counters:
            card['proxy_app'] = sum(counters.values())
            card['direct'] = counters.get('direct')
            card['details'] = {'outbound_tags': counters}
    summary = result.setdefault('summary', {})
    for field,key in (('month_in','in'),('month_out','out'),('today_in','today_in'),('today_out','today_out')):
        summary[field] = int(summary.get(field) or 0) + card[key]
    return add_zoro_application_observation(result,db_path,now,traffic_start)


def overlay_archives(live, manifest=None):
    manifest = manifest or read_manifest()
    result = copy.deepcopy(live)
    result.setdefault('servers', {})
    result.setdefault('summary', {})
    cutoff = manifest['cutoff']
    active = active_host_names(manifest)
    for name,saved in manifest.get('retired_host_cards', {}).items():
        prior = result['servers'].get(name) or {}
        # The old expiry overlay has already removed previously expired hosts.
        if prior.get('sampled_at') and not prior.get('expired'):
            for total,field in (('month_in','in'),('month_out','out'),('today_in','today_in'),('today_out','today_out')):
                result['summary'][total] = max(0, int(result['summary'].get(total) or 0) - int(prior.get(field) or 0))
        card = copy.deepcopy(saved)
        card['archived'] = True
        card['expired'] = True
        card.setdefault('expires_at', cutoff)
        card.setdefault('freeze_at', cutoff - 1)
        card.setdefault('last_measured_at', card.get('sampled_at'))
        card.setdefault('archive_reason', '2026-11-05 topology replacement')
        card['historical_user_usage'] = copy.deepcopy(manifest.get('retired_user_usage', {}).get(name, []))
        result['servers'][name] = card
    for host,snapshot in manifest.get('peer_snapshots', {}).items():
        if host not in active or host not in result['servers']:
            continue
        card = result['servers'][host]
        for field,value in snapshot.items():
            if field in PEER_FIELDS:
                if field in ('static_outbound','static_wire','static_provider_expiry') and isinstance(value,dict):
                    current = dict(card.get(field) or {})
                    current.update(copy.deepcopy(value))
                    card[field] = current
                else:
                    card[field] = copy.deepcopy(value)
        card['retired_peers_frozen_at'] = cutoff - 1
    result['topology'] = {'active_hosts': list(active),
                          'archived_hosts': list(manifest.get('retired_host_cards', {})),
                          'cutoff': cutoff}
    if _network_stats and _network_stats.is_network_manifest(manifest):
        for host in active:
            card = result['servers'].get(host)
            if card is not None:
                for field in ('archived', 'expired', 'expires_at', 'freeze_at', 'archive_reason'):
                    card.pop(field, None)
        return _network_stats.attach_inventory(result, manifest)
    return result


def apply_daily_archive(policy, manifest=None):
    """Freeze obsolete host/peer daily counters without changing old snapshots.

    Call on each load_policy result. The original mtime-cached policy is never
    mutated, and this manifest has its own mtime cache.
    """
    if policy is None:
        return None
    manifest = manifest or read_manifest()
    if _network_stats and _network_stats.is_network_manifest(manifest):
        return _network_stats.apply_daily_archive(policy, manifest)
    result = copy.deepcopy(policy)
    peers = set(manifest.get('archived_peers',
        ('NexIP SG', 'ip2up.com', 'proxyhive.io', 'Kookeey', 'Lazycat-SG', 'Lazycat-HKT')))
    for name in set(manifest.get('retired_host_cards', {})) | peers:
        service = result.canonical(name)
        result.cutoffs[service] = min(result.cutoffs.get(service, manifest['cutoff']), manifest['cutoff'])
    return result


def active_whole_payload(db_path, traffic_start=0, now=None, manifest=None):
    """Read current NIC cards without rescanning retired-provider sessions.

    The old whole_payload performs three non-covering scans over historical
    provider records on every cold start. Those peers are immutable snapshots
    in this topology, so only normal samples and categories are needed here.
    """
    if _network_stats and _network_stats.is_network_manifest(manifest):
        return _network_stats.active_whole_payload(db_path, traffic_start, now, manifest, empty_card)
    now = int(time.time() if now is None else now)
    start = max(int(traffic_start), now - 30 * 86400)
    today = max(int(traffic_start), now - ((now + 8 * 3600) % 86400))
    active = active_host_names(manifest)
    result = {'started': int(traffic_start),
              'servers': {name: empty_card() for name in active},
              'summary': dict(today_in=0, today_out=0, month_in=0, month_out=0)}
    if not Path(db_path).is_file():
        return attach_exit_observations(result, manifest, now)
    with closing(sqlite3.connect(Path(db_path).resolve().as_uri() + '?mode=ro', uri=True, timeout=5)) as db:
        for name in active:
            row = db.execute('SELECT COUNT(*),SUM(delta_rx),SUM(delta_tx),'
                'SUM(CASE WHEN ts>=? THEN delta_rx ELSE 0 END),'
                'SUM(CASE WHEN ts>=? THEN delta_tx ELSE 0 END),MAX(ts) '
                'FROM samples WHERE server=? AND ts>=?', (today,today,name,start)).fetchone()
            if not row[0]:
                continue
            card = result['servers'][name]
            card.update({'in': int(row[1] or 0), 'out': int(row[2] or 0),
                         'today_in': int(row[3] or 0), 'today_out': int(row[4] or 0),
                         'sampled_at': int(row[5])})
            raw = db.execute('SELECT sui_json,hk_json FROM samples WHERE server=? '
                             'ORDER BY ts DESC LIMIT 1', (name,)).fetchone()
            try:
                counters = json.loads(raw[1] if name == 'ByteVirt-HK ISP' else raw[0])
                counters = {str(key): int(value) for key,value in counters.items() if int(value) >= 0}
            except (TypeError, ValueError, AttributeError):
                counters = {}
            if counters:
                card['proxy_app'] = sum(counters.values())
                if name == 'ByteVirt-HK ISP':
                    card['direct'] = card['proxy_app']
                    card['details'] = {'routes': counters}
                else:
                    card['direct'] = counters.get('direct')
                    card['details'] = {'outbound_tags': counters}
                    if name == 'DMIT':
                        for route,peer in RELAY_PEERS.items():
                            if 'topology:' + route in counters:
                                card['static_outbound'][peer] = counters['topology:' + route]
            row = db.execute('SELECT SUM(mapping_wire) FROM categories '
                             'WHERE server=? AND ts>=?', (name,start)).fetchone()
            if row and row[0] is not None:
                card['mapping_wire'] = int(row[0])
            for total,field in (('month_in','in'),('month_out','out'),('today_in','today_in'),('today_out','today_out')):
                result['summary'][total] += card[field]
    return attach_exit_observations(add_zoro_application_observation(result,db_path,now,traffic_start),manifest,now)


def active_user_usage(db_path, traffic_start=0, now=None, manifest=None):
    """Retain exact historical attribution while skipping retired host scans."""
    if not Path(db_path).is_file():
        return []
    now = int(time.time() if now is None else now)
    start = max(int(traffic_start), now - 30 * 86400)
    totals = {}
    queries = (
        ('DMIT', 1, 'SELECT user,SUM(upload+download) FROM unified_records INDEXED BY idx_unified_dashboard_cover '
         "WHERE started>=? AND traffic_known=1 AND route_type IN ('直连','中转') AND ingress='DMIT' GROUP BY user"),
        ('DMIT', -1, 'SELECT user,SUM(upload+download) FROM unified_records INDEXED BY idx_unified_hk_firsthop_cover '
         "WHERE started>=? AND origin='hk' AND traffic_known=1 AND route_type IN ('直连','中转') AND ingress='DMIT' GROUP BY user"),
        ('DMIT', 1, 'SELECT user,SUM(upload+download) FROM unified_records INDEXED BY idx_unified_unverified_count '
         "WHERE started>=? AND traffic_known=1 AND route_type='待核实' AND ingress='DMIT' AND origin!='hk' GROUP BY user"),
        ('ByteVirt-HK ISP', 1, 'SELECT user,SUM(upload+download) FROM unified_records INDEXED BY idx_unified_hk_usage '
         "WHERE started>=? AND origin='hk' AND traffic_known=1 AND route_type='中转' AND relay='ByteVirt-HK ISP' GROUP BY user"),
        ('ByteVirt-HK ISP', 1, 'SELECT user,SUM(upload+download) FROM unified_records INDEXED BY idx_unified_ingress '
         "WHERE started>=? AND origin='hk' AND ingress='进站待核实' AND traffic_known=1 AND route_type='待核实' AND relay='ByteVirt-HK ISP' GROUP BY user"),
        ('zorocloud', 1, 'SELECT user,SUM(upload+download) FROM unified_records INDEXED BY idx_unified_hk_usage '
         "WHERE started>=? AND origin='dmit' AND traffic_known=1 AND route_type='中转' AND relay='zorocloud' GROUP BY user"),
    )
    if TAIWAN_HOST in active_host_names(manifest):
        queries += ((TAIWAN_HOST, 1, 'SELECT user,SUM(upload+download) FROM unified_records INDEXED BY idx_unified_hk_usage '
         "WHERE started>=? AND origin='dmit' AND traffic_known=1 AND route_type='中转' AND relay='ByteVirt-TW' GROUP BY user"),)
    network = _network_stats and _network_stats.is_network_manifest(manifest)
    if network:
        queries = tuple(item for item in queries if item[0] in _network_stats.active_host_names(manifest))
    with closing(sqlite3.connect(Path(db_path).resolve().as_uri() + '?mode=ro', uri=True, timeout=5)) as db:
        for server,sign,query in queries:
            args = (start,)
            if network and _network_stats.server_policy_enabled(manifest) and server == 'ByteVirt-HK ISP':
                query = query.replace('WHERE started>=?', 'WHERE started>=? AND started<?', 1)
                args = (start, manifest['server_policy_activated_at'])
            for user,total in db.execute(query,args):
                key=(server,user)
                totals[key]=totals.get(key,0)+sign*int(total or 0)
    result=[]
    for (server,user),total in sorted(totals.items(), key=lambda item:(item[0][0],-item[1])):
        if total <= 0:
            continue
        row={'server':server,'user':user,'total':total}
        if server in RELAY_PEERS.values():
            row.update(estimated=True,basis='DMIT forwarding application bytes')
        result.append(row)
    if network:
        return _network_stats.extend_active_user_usage(result, db_path, traffic_start, now, manifest)
    return result


def install_dashboard(base, manifest_path=None):
    # The only retained remote aggregate is ByteVirt. Historical BWH rows stay
    # in the central databases and immutable manifest instead of new SSH reads.
    base.REMOTE_SOURCES = tuple(item for item in base.REMOTE_SOURCES if item[0] != 'BWHLA')
    current = read_manifest(manifest_path)
    if _network_stats and _network_stats.is_revision(current):
        base.FIRST_HOP_INGRESSES = tuple(dict.fromkeys(tuple(base.FIRST_HOP_INGRESSES) + ('Lazycat-SG-Front',)))
    def whole():
        return active_whole_payload(base.WHOLE_DB_PATH, base.TRAFFIC_START_TS, manifest=read_manifest(manifest_path))
    def users():
        manifest = read_manifest(manifest_path)
        retired = manifest.get('retired_host_cards', {})
        asof = int(time.time())
        result = active_user_usage(base.WHOLE_DB_PATH, base.TRAFFIC_START_TS, now=asof, manifest=manifest)
        for host,rows in manifest.get('retired_user_usage', {}).items():
            result.extend(dict(row,server=host) for row in rows)
        base.server_user_usage_snapshot_at = asof
        return result
    base.whole_payload = whole
    base.server_user_usage = users
    return base


def bootstrap_dashboard(base, manifest=None, start_refresh=True, defer_user_usage=False):
    """Seed the existing stale-while-refresh cache from the protected snapshot.

    A cold restart otherwise synchronously scans 30 days of S-UI stats plus
    access counts before any response. Return the actual captured records,
    with the current active NIC cards and explicit snapshot time, while the
    original background refresher replaces the aggregate. No stored traffic
    row or measurement clock is rewritten.
    """
    import threading
    manifest = manifest or read_manifest()
    saved = manifest.get('bootstrap_payload')
    if not isinstance(saved,dict) or not isinstance(saved.get('records'),list):
        raise ValueError('protected bootstrap payload missing')
    payload = copy.deepcopy(saved)
    payload['whole'] = base.whole_payload()
    payload['bootstrap_saved_at'] = int(manifest.get('snapshot_saved_at',manifest['cutoff'] - 1))
    # The socket must not depend on a costly SQLite aggregation. The protected
    # captured rows stay explicitly dated; missing current rows are pending,
    # never substituted with an invented user, total, or zero measurement.
    payload['server_user_usage_state'] = 'pending'
    payload['server_user_usage_asof'] = payload['bootstrap_saved_at']
    payload['server_user_usage_pending_hosts'] = list(active_host_names(manifest))
    if not defer_user_usage:
        try:
            payload['server_user_usage'] = base.server_user_usage()
            payload['server_user_usage_state'] = 'ready'
            payload['server_user_usage_asof'] = getattr(base,'server_user_usage_snapshot_at',int(time.time()))
            payload['server_user_usage_pending_hosts'] = []
        except sqlite3.Error as error:
            payload['server_user_usage_error_type'] = type(error).__name__
    now = time.monotonic()
    base.base_cache['data'] = (now - 61,payload)
    base.api_cache[''] = (now,json.dumps(payload,ensure_ascii=False).encode())
    if start_refresh and base.base_refresh_lock.acquire(blocking=False):
        base.base_refresh_state['attempted_at'] = now
        threading.Thread(target=base.refresh_base_payload,daemon=True).start()
    return payload
