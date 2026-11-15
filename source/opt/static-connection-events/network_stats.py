"""Six-server inventory and measurement boundaries for the 2026-11-06 plan.

Pure migration helpers: this module neither contacts a host nor writes a DB.
All record attribution uses verified transport endpoints and runtime tags.
Renewal dates describe billing, never automatic retirement of active services.
"""
import calendar
import copy
from contextlib import closing
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import time

TZ = timezone(timedelta(hours=8), 'Asia/Kuala_Lumpur')
PLAN_VERSION = 'network-plan-20261106'
SERVER_POLICY_ID = 'dmit-domain-routing-20261106'
SERVER_POLICY_FRONTS = {
    'dmit-direct-stage': 31117, 'dmit-taiwan': 29514, 'dmit-starhub': 29515,
    'dmit-hkt': 29516, 'dmit-singtel': 29517, 'dmit-hk': 29518,
    'mobile-dmit-direct': 29611, 'mobile-dmit-taiwan': 29614, 'mobile-dmit-starhub': 29615,
    'mobile-dmit-hkt': 29616, 'mobile-dmit-singtel': 29617, 'mobile-dmit-hk': 29618,'dmit-zoro-sg':29519,'mobile-dmit-zoro-sg':29619}
POLICY_OUTBOUNDS = {
    'bytevirt-hk': ('ByteVirt-HK ISP', 'bytevirt_hk_isp', 'dmit-hk'),
    'bytevirt-taiwan': ('ByteVirt-TW', 'bytevirt_taiwan', 'dmit-taiwan'),
    'lazycat-starhub': ('Lazycat-SG', 'lazycat', 'dmit-starhub'),
    'lazycat-hkt': ('Lazycat-HKT', 'lazycat_hkt', 'dmit-hkt'),
    'uzuma-singtel': ('Uzuma-SG-Singtel1', 'uzuma_singtel', 'dmit-singtel'),'zoro-sg':('ZORO-SG','zoro_sg','dmit-zoro-sg')}
POLICY_EXCLUSIVE_FRONTS = frozenset({'dmit-hk', *(tag for tag in SERVER_POLICY_FRONTS if tag.startswith('mobile-'))})
ACTIVE_HOSTS = ('DMIT', 'ByteVirt-HK ISP', 'ByteVirt-TW', 'Lazycat-SG',
                'Lazycat-HKT', 'Uzuma-SG-Singtel1','ZORO-SG')
RELAY_PEERS = {'bytevirt_hk_isp': 'ByteVirt-HK ISP',
               'bytevirt_taiwan': 'ByteVirt-TW', 'lazycat': 'Lazycat-SG',
               'lazycat_hkt': 'Lazycat-HKT', 'uzuma_singtel': 'Uzuma-SG-Singtel1','zoro_sg':'ZORO-SG'}
# Hong Kong already supplies its independently observed application meter.
# Re-aggregating its large DMIT forwarding history is redundant and must not
# delay current physical NIC cards for the four forwarding-only exits.
FORWARDED_OBSERVATION_PEERS = ('ByteVirt-TW', 'Lazycat-SG', 'Lazycat-HKT', 'Uzuma-SG-Singtel1','ZORO-SG')
PHYSICAL_COVER_INDEX = 'idx_network_samples_wire_cover'
DMIT_LOCAL_SAMPLE_COMMAND = ('python3', '/opt/sg-traffic-dashboard/host-traffic-sample.py')
DMIT_LOCAL_SAMPLE_TIMEOUT = 45
REACTIVATED = frozenset({'Lazycat-SG', 'Lazycat-HKT'})
INVENTORY = {
    'DMIT': {'display_name': 'DMIT', 'network': '三网直连', 'country': 'US',
             'currency': 'USD', 'amount': '20.9', 'period': 'month', 'day': 29},
    'ByteVirt-HK ISP': {'display_name': 'Bytevirt HK ISP', 'network': '香港宽频',
             'country': 'HK', 'currency': 'USD', 'amount': '55',
             'period': 'year', 'month': 9, 'day': 24},
    'ByteVirt-TW': {'display_name': 'Bytevirt HINET NAT', 'network': '台湾中华电信',
             'country': 'TW', 'currency': 'USD', 'amount': '4.7',
             'period': 'month', 'day': 5},
    'Lazycat-SG': {'display_name': 'Lazycat starhub', 'network': '新加坡 StarHub',
             'country': 'SG', 'currency': 'CNY', 'amount': '35',
             'period': 'month', 'day': 17},
    'Lazycat-HKT': {'display_name': 'Lazycat HKT', 'network': '香港 HKT',
             'country': 'HK', 'currency': 'CNY', 'amount': '16',
             'period': 'month', 'day': 17},
    'Uzuma-SG-Singtel1': {'display_name': 'uzuma SG-Singtel1',
             'network': '新加坡电信移动', 'country': 'SG', 'currency': 'USD',
             'amount': '7.72', 'period': 'month', 'day': 7},
}
INVENTORY['ZORO-SG']={'display_name':'zorocloud sptel','network':'新加坡 SPTel','country':'SG','period':'unknown','amount':None,'currency':None,'traffic_total_gb':1500,'traffic_reset_at':1796592360}
_PEER_SCALARS = {'lazycat': 'Lazycat-SG', 'lazycat_hkt': 'Lazycat-HKT'}


def is_network_manifest(manifest):
    return isinstance(manifest, dict) and manifest.get('network_plan') == PLAN_VERSION


def server_policy_enabled(manifest):
    if not isinstance(manifest, dict) or 'server_policy' not in manifest:
        return False
    if manifest['server_policy'] != SERVER_POLICY_ID:
        raise ValueError('statistics server policy version invalid')
    return True


def verified_routes_from_observed_runtime(config):
    """Read actual six-egress/12-inlet identities, never entry-label inference."""
    if not isinstance(config, dict) or not isinstance(config.get('inbounds'), list):
        raise ValueError('observed server policy runtime invalid')
    inbounds = {row.get('tag'): row for row in config['inbounds'] if isinstance(row, dict)}
    if len(inbounds) != len(config['inbounds']) or set(inbounds) != set(SERVER_POLICY_FRONTS):
        raise ValueError('observed server policy front inventory invalid')
    for tag, port in SERVER_POLICY_FRONTS.items():
        row = inbounds[tag]
        if row.get('type') != 'anytls' or row.get('listen_port') != port:
            raise ValueError('observed server policy front endpoint invalid')
    rows = config.get('outbounds')
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError('observed server policy outbounds invalid')
    outbounds = {row.get('tag'): row for row in rows}
    if len(outbounds) != len(rows) or outbounds.get('direct', {}).get('type') != 'direct':
        raise ValueError('observed server policy direct identity invalid')
    result = []
    for tag, (host, route, front) in POLICY_OUTBOUNDS.items():
        row = outbounds.get(tag, {})
        if row.get('type') not in ('shadowsocks', 'anytls'):
            raise ValueError('observed private relay outbound invalid')
        result.append(dict(host=host, route_class=route, inbound_tag=front,
            outbound_tag=tag, type=row.get('type'), server=row.get('server'),
            server_port=row.get('server_port')))
    hk = result[0]
    if (hk['type'], hk['server'], hk['server_port']) != ('shadowsocks', '61.15.36.199', 2448):
        raise ValueError('observed private Hong Kong transport differs')
    return normalize_verified_routes(result)


def enable_server_policy_manifest(previous, observed_runtime, activated_at, *, hk_daily_baseline=None):
    """Update only actual route identities and explicit policy evidence."""
    validate_manifest(previous)
    routes = verified_routes_from_observed_runtime(observed_runtime)
    activated_at = _epoch(activated_at, 'server policy activation')
    result = copy.deepcopy(previous)
    if server_policy_enabled(previous):
        if result['verified_routes'] != routes:
            raise ValueError('active server policy transport drift')
        return result
    _validate_hk_daily_baseline(hk_daily_baseline, activated_at)
    result.update(server_policy=SERVER_POLICY_ID, server_policy_activated_at=activated_at,
        server_policy_managed_fronts=dict(SERVER_POLICY_FRONTS),
        server_policy_previous_verified_routes=copy.deepcopy(previous['verified_routes']),
        verified_routes=routes, server_policy_hk_daily_baseline=copy.deepcopy(hk_daily_baseline))
    return validate_manifest(result)


_DAILY_IDENTITY = ('owner', 'day', 'user', 'role', 'host', 'peer', 'source',
                   'meter_basis', 'estimated', 'priority')


def _daily_identity(row):
    return tuple(row[key] for key in _DAILY_IDENTITY)


def _validate_hk_daily_baseline(value, cutoff):
    day = datetime.fromtimestamp(cutoff, TZ).date().isoformat()
    if (not isinstance(value, dict) or value.get('schema') != 1 or
            value.get('captured_at') != cutoff or value.get('day') != day or
            not isinstance(value.get('rows'), list) or not isinstance(value.get('chosen_before'), list)):
        raise ValueError('real Hong Kong daily cutover baseline required')
    identities = set()
    for row in value['rows']:
        if (not isinstance(row, dict) or any(key not in row for key in _DAILY_IDENTITY) or
                row['day'] != day or row['role'] != 'egress' or row['peer'] != 'ByteVirt-HK ISP' or
                any(type(row.get(key)) is not int or row[key] < 0 for key in ('upload', 'download', 'updated_at')) or
                row['updated_at'] > cutoff or _daily_identity(row) in identities):
            raise ValueError('invalid Hong Kong daily baseline row')
        identities.add(_daily_identity(row))
    for row in value['chosen_before']:
        if row not in value['rows']:
            raise ValueError('Hong Kong authority baseline not captured')
    priorities = {}
    for row in value['rows']:
        priorities[row['user']] = max(priorities.get(row['user'], -1), row['priority'])
    chosen = [row for row in value['rows'] if row['priority'] == priorities[row['user']]]
    if sorted(json.dumps(row, sort_keys=True) for row in chosen) != sorted(
            json.dumps(row, sort_keys=True) for row in value['chosen_before']):
        raise ValueError('Hong Kong before authority selection incomplete')
    return value


def capture_hk_daily_baseline(previous, daily_db_path, cutoff):
    """Read only today's HK egress slices, preserving the old authority.

    Publisher should pause the old native/exit accounting writers briefly,
    capture this barrier and switch the core/manifest before resuming them.
    An observed row from after the requested cutoff rejects a false barrier.
    """
    validate_manifest(previous)
    cutoff = _epoch(cutoff, 'server policy activation')
    if server_policy_enabled(previous):
        return copy.deepcopy(previous['server_policy_hk_daily_baseline'])
    day = datetime.fromtimestamp(cutoff, TZ).date().isoformat()
    with closing(sqlite3.connect(Path(daily_db_path).resolve().as_uri() + '?mode=ro', uri=True, timeout=2)) as db:
        db.row_factory = sqlite3.Row
        deadline = time.monotonic() + 2
        db.set_progress_handler(lambda: time.monotonic() > deadline, 1000)
        db.execute('BEGIN')
        meta = dict(db.execute('SELECT key,value FROM ledger_meta'))
        owner = meta.get('source_key')
        if not isinstance(owner, str) or not owner:
            raise ValueError('daily ledger source identity unavailable')
        # PK(day,user,...) and PK(owner,day,user,...) keep this strictly in
        # the cutover day; no query scans the full retained ledger.
        rows = [dict(row, owner=owner) for row in db.execute(
            "SELECT * FROM daily_usage WHERE day=? AND role='egress' AND peer='ByteVirt-HK ISP'", (day,))]
        owners = [row[0] for row in db.execute('SELECT source_key FROM mirror_sources')]
        for key in owners:
            rows.extend(dict(row) for row in db.execute(
                "SELECT * FROM mirrored_usage WHERE owner=? AND day=? AND role='egress' AND peer='ByteVirt-HK ISP'", (key, day)))
    priorities = {}
    for row in rows:
        priorities[row['user']] = max(priorities.get(row['user'], -1), row['priority'])
    before = [copy.deepcopy(row) for row in rows if row['priority'] == priorities[row['user']]]
    value = {'schema': 1, 'day': day, 'captured_at': cutoff, 'rows': rows,
        'chosen_before': before, 'basis': 'readonly_daily_ledger_cutover_barrier'}
    return _validate_hk_daily_baseline(value, cutoff)


def adjust_hk_daily_rows(rows, manifest, from_day, to_day, *, user='', host=''):
    """Combine disjoint before/after HK authorities without rewriting a row."""
    if not server_policy_enabled(manifest):
        return rows
    cutoff = manifest['server_policy_activated_at']
    baseline = _validate_hk_daily_baseline(manifest.get('server_policy_hk_daily_baseline'), cutoff)
    day = baseline['day']
    # Older dates retain the exact existing priority logic. On and after
    # cutover, the new private shared exit has no independent per-user meter.
    result = [row for row in rows if not (row['role'] == 'egress' and
              row['peer'] == 'ByteVirt-HK ISP' and row['day'] >= day)]
    if from_day <= day <= to_day:
        for old in baseline['chosen_before']:
            if (not user or old['user'] == user) and (not host or old['host'] == host):
                result.append(dict(old, policy_segment='before', policy_cutover_at=cutoff))
    seen = {_daily_identity(row): row for row in baseline['rows']}
    for row in rows:
        if not (row['role'] == 'egress' and row['peer'] == 'ByteVirt-HK ISP' and row['day'] >= day and
                row['host'] == 'DMIT' and row['source'] == 'singbox-native' and
                row['meter_basis'] == 'forwarded_application' and row['estimated'] == 1):
            continue
        before = seen.get(_daily_identity(row)) if row['day'] == day else None
        up = row['upload'] - (before['upload'] if before else 0)
        down = row['download'] - (before['download'] if before else 0)
        if up < 0 or down < 0:
            raise ValueError('Hong Kong daily counter fell below captured baseline')
        if up or down:
            result.append(dict(row, upload=up, download=down,
                               policy_segment='after', policy_cutover_at=cutoff))
    return result


def actual_closed_route(manifest, host, inbound, outbound, created_at_ms):
    """None requests the historical fixed-inlet adapter, not guessed routing."""
    if host != 'DMIT':
        return None
    if not server_policy_enabled(manifest):
        if inbound in POLICY_EXCLUSIVE_FRONTS:
            raise ValueError('server policy event intent missing from statistics manifest')
        return None
    if type(created_at_ms) is not int or created_at_ms <= 0:
        raise ValueError('server policy closed event start invalid')
    if created_at_ms < manifest['server_policy_activated_at'] * 1000:
        return None
    if inbound not in SERVER_POLICY_FRONTS:
        raise ValueError('server policy event inlet not managed')
    if outbound == 'direct':
        return 'direct', 'DMIT'
    identity = POLICY_OUTBOUNDS.get(outbound)
    if identity is None:
        raise ValueError('server policy event outbound not verified')
    return identity[1], identity[0]


def _epoch(value, name):
    if type(value) is not int or value <= 0:
        raise ValueError('invalid ' + name)
    return value


def next_billing_at(host, now=None):
    """Return next local midnight renewal date, never an expiry cutoff."""
    item = INVENTORY[host]
    if item.get('period') not in ('month','year'):return None
    now = datetime.now(TZ) if now is None else now
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError('billing clock must be timezone-aware')
    now = now.astimezone(TZ)
    year, month = now.year, item.get('month', now.month)
    while True:
        day = min(item['day'], calendar.monthrange(year, month)[1])
        candidate = datetime(year, month, day, tzinfo=TZ)
        if candidate > now:
            return int(candidate.timestamp())
        if item['period'] == 'year':
            year += 1
        else:
            month += 1
            if month == 13:
                year, month = year + 1, 1


def inventory(now=None):
    result = copy.deepcopy(INVENTORY)
    for host, item in result.items():
        item.update(next_billing_at=next_billing_at(host, now),
                    auto_expire=False, billing_timezone='Asia/Kuala_Lumpur')
    return result


def normalize_verified_routes(routes):
    """Extract only the non-secret transport identity from audited route specs.

    Caller shape: host, inbound_tag, outbound_tag, route_class, type, server,
    server_port. No passwords, user lists or arbitrary config are retained.
    """
    if not isinstance(routes, list):
        raise ValueError('verified routes must be a list')
    result, seen_hosts, seen_inbounds, seen_outbounds = [], set(), set(), set()
    for route in routes:
        if not isinstance(route, dict):
            raise ValueError('invalid verified route')
        item = {key: route.get(key) for key in ('host', 'inbound_tag', 'outbound_tag',
                'route_class', 'type', 'server', 'server_port')}
        if (item['host'] not in RELAY_PEERS.values() or
                RELAY_PEERS.get(item['route_class']) != item['host'] or
                item['type'] not in ('anytls', 'shadowsocks', 'socks', 'http') or
                type(item['server_port']) is not int or
                not 1 <= item['server_port'] <= 65535):
            raise ValueError('invalid verified transport')
        for key in ('inbound_tag', 'outbound_tag', 'server'):
            if item['host'] == 'ByteVirt-HK ISP' and key != 'server' and item[key] is None:
                continue
            if not isinstance(item[key], str) or not item[key] or any(c.isspace() for c in item[key]):
                raise ValueError('invalid verified identity')
        if (item['host'] in seen_hosts or (item['inbound_tag'] is not None and item['inbound_tag'] in seen_inbounds) or
                (item['outbound_tag'] is not None and item['outbound_tag'] in seen_outbounds)):
            raise ValueError('duplicate verified transport')
        seen_hosts.add(item['host'])
        if item['inbound_tag'] is not None: seen_inbounds.add(item['inbound_tag'])
        if item['outbound_tag'] is not None: seen_outbounds.add(item['outbound_tag'])
        result.append(item)
    if seen_hosts != set(RELAY_PEERS.values()):
        raise ValueError('all five relay transports must be verified')
    return result


def routes_from_runtime_marker(marker):
    """Convert the runtime marker into credential-free accounting identities."""
    if (not isinstance(marker, dict) or marker.get('schema') != 1 or
            marker.get('plan') != 'six-server-20261106'):
        raise ValueError('invalid runtime network marker')
    assignments = {
        'bytevirt-tw': ('ByteVirt-TW', 'dmit-taiwan', 'bytevirt-taiwan', 'bytevirt_taiwan'),
        'lazycat-starhub': ('Lazycat-SG', 'dmit-starhub', 'lazycat-starhub', 'lazycat'),
        'lazycat-hkt': ('Lazycat-HKT', 'dmit-hkt', 'lazycat-hkt', 'lazycat_hkt'),
        'uzuma-singtel': ('Uzuma-SG-Singtel1', 'dmit-singtel', 'uzuma-singtel', 'uzuma_singtel'),
    }
    transports = marker.get('transports')
    if not isinstance(transports, dict) or set(transports) != set(assignments):
        raise ValueError('runtime transport inventory differs')
    result = [{'host': 'ByteVirt-HK ISP', 'inbound_tag': None, 'outbound_tag': None,
               'route_class': 'bytevirt_hk_isp', 'type': 'anytls',
               'server': '61.15.36.199', 'server_port': 2443}]
    policy = marker.get('server_policy')
    if policy is not None:
        if not isinstance(policy, dict) or policy.get('id') != SERVER_POLICY_ID:
            raise ValueError('runtime server policy identity invalid')
        hk = policy.get('hk_transport')
        if not isinstance(hk, dict) or (hk.get('type'), hk.get('server'), hk.get('server_port')) != (
                'shadowsocks', '61.15.36.199', 2448):
            raise ValueError('runtime private Hong Kong transport invalid')
        result[0].update(inbound_tag='dmit-hk', outbound_tag='bytevirt-hk',
                         type=hk['type'], server=hk['server'], server_port=hk['server_port'])
    for key, assignment in assignments.items():
        transport = transports[key]
        if not isinstance(transport, dict):
            raise ValueError('runtime transport invalid')
        item = dict(zip(('host', 'inbound_tag', 'outbound_tag', 'route_class'), assignment))
        item.update({field: transport.get(field) for field in ('type', 'server', 'server_port')})
        result.append(item)
    if isinstance(policy,dict) and policy.get('zoro_transport'):
        hop=policy['zoro_transport'];result.append({'host':'ZORO-SG','inbound_tag':'dmit-zoro-sg','outbound_tag':'zoro-sg','route_class':'zoro_sg',**{k:hop[k] for k in ('type','server','server_port')}})
    return normalize_verified_routes(result)


def _sample_command(command):
    if not isinstance(command, list) or not command or any(
            not isinstance(item, str) or not item for item in command):
        raise ValueError('invalid host sample command')
    return list(command)


def validate_manifest(manifest):
    if not is_network_manifest(manifest) or tuple(manifest.get('active_hosts', ())) != ACTIVE_HOSTS:
        raise ValueError('unexpected six-server topology')
    _epoch(manifest.get('cutoff'), 'legacy cutoff')
    _epoch(manifest.get('network_activated_at'), 'network activation')
    for key in ('retired_host_cards', 'retired_user_usage', 'peer_snapshots',
                'sample_commands', 'active_since', 'archive_epochs'):
        if not isinstance(manifest.get(key), dict):
            raise ValueError('invalid manifest object: ' + key)
    if set(ACTIVE_HOSTS).intersection(manifest['retired_host_cards']):
        raise ValueError('active host cannot be archived')
    for host, command in manifest['sample_commands'].items():
        if host not in ACTIVE_HOSTS:
            raise ValueError('inactive sampling host')
        _sample_command(command)
    for host, value in manifest['active_since'].items():
        if host not in ACTIVE_HOSTS or _epoch(value, 'active epoch') > (manifest.get('zoro_sg_activated_at',manifest['network_activated_at']) if host=='ZORO-SG' else manifest['network_activated_at']):
            raise ValueError('invalid active epoch')
    normalize_verified_routes(manifest.get('verified_routes'))
    if server_policy_enabled(manifest):
        if manifest.get('server_policy_managed_fronts') != SERVER_POLICY_FRONTS:
            raise ValueError('statistics managed server fronts differ')
        if _epoch(manifest.get('server_policy_activated_at'), 'server policy activation') < manifest['network_activated_at']:
            raise ValueError('server policy predates network activation')
        expected = {row['outbound_tag']: row for row in manifest['verified_routes']}
        if set(expected) != set(POLICY_OUTBOUNDS):
            raise ValueError('statistics actual outbound inventory incomplete')
        hk = expected['bytevirt-hk']
        if (hk['type'], hk['server'], hk['server_port']) != ('shadowsocks', '61.15.36.199', 2448):
            raise ValueError('statistics Hong Kong runtime endpoint not updated')
        _validate_hk_daily_baseline(manifest.get('server_policy_hk_daily_baseline'), manifest['server_policy_activated_at'])
    return manifest


def extend_network_manifest(previous, payload, cutoff, sample_commands, verified_routes,
                            exit_observations=None):
    """Archive Zoro, resume Lazycat epochs and preserve every old frozen byte.

    Reactivated cards/users leave the active archive map but are copied exactly
    into archive_epochs. Raw historical DB rows and old measurement timestamps
    are neither deleted nor relabelled as current.
    """
    cutoff = _epoch(cutoff, 'network activation')
    if not isinstance(previous, dict) or previous.get('schema') != 1:
        raise ValueError('existing protected manifest required')
    routes = normalize_verified_routes(verified_routes)
    if not isinstance(sample_commands, dict) or set(sample_commands).difference(ACTIVE_HOSTS):
        raise ValueError('invalid sample command hosts')
    commands = {host: _sample_command(command) for host, command in sample_commands.items()}
    # Every new/non-base host must have an explicit restricted sampler. The
    # baseline collector already owns DMIT and ByteVirt-HK ISP commands.
    if not set(ACTIVE_HOSTS[2:]).issubset(commands):
        raise ValueError('new and resumed host samplers required')
    if is_network_manifest(previous):
        validate_manifest(previous)
        if previous['verified_routes'] != routes:
            raise ValueError('route change requires a new migration version')
        return copy.deepcopy(previous)
    servers = ((payload or {}).get('whole') or {}).get('servers')
    if not isinstance(servers, dict) or not isinstance(servers.get('zorocloud'), dict):
        raise ValueError('real Zoro card required for retirement')
    zoro = copy.deepcopy(servers['zorocloud'])
    measured = zoro.get('last_measured_at') or zoro.get('sampled_at')
    if type(measured) is not int or not 0 < measured < cutoff:
        raise ValueError('Zoro sample must be real and before cutoff')
    if any(zoro.get(key) is None for key in ('in', 'out')):
        raise ValueError('Zoro NIC totals unavailable')
    result = copy.deepcopy(previous)
    result.update(network_plan=PLAN_VERSION, network_activated_at=cutoff,
                  active_hosts=list(ACTIVE_HOSTS), sample_commands=commands,
                  verified_routes=routes, inventory=inventory(datetime.fromtimestamp(cutoff, TZ)))
    retired = result.setdefault('retired_host_cards', {})
    users = result.setdefault('retired_user_usage', {})
    if 'zorocloud' not in retired:
        zoro.update(archived=True, expired=True, expires_at=cutoff,
                    freeze_at=cutoff - 1, last_measured_at=measured,
                    archive_reason='2026-11-06 network plan replacement')
        retired['zorocloud'] = zoro
        users['zorocloud'] = [copy.deepcopy(row) for row in payload.get('server_user_usage', [])
                             if row.get('server') == 'zorocloud']
    epochs = result.setdefault('archive_epochs', {})
    active_since = result.setdefault('active_since', {})
    for host in REACTIVATED:
        old_card, old_users = retired.pop(host, None), users.pop(host, None)
        if old_card is not None:
            epochs.setdefault(host, []).append({'card': old_card, 'users': old_users or [],
                 'closed_at': cutoff, 'snapshot_basis': 'unchanged_previous_archive'})
        active_since[host] = cutoff
    active_since['Uzuma-SG-Singtel1'] = cutoff
    # Remove only resumed fields from the active frozen overlay. Preserve the
    # full old object alongside the historical cards for audit/review.
    result['historical_peer_snapshots'] = copy.deepcopy(previous.get('peer_snapshots', {}))
    for snapshot in result.setdefault('peer_snapshots', {}).values():
        for field in _PEER_SCALARS:
            snapshot.pop(field, None)
        for field in ('static_outbound', 'static_wire', 'static_provider_expiry'):
            if isinstance(snapshot.get(field), dict):
                for peer in REACTIVATED:
                    snapshot[field].pop(peer, None)
    result['archived_peers'] = sorted((set(previous.get('archived_peers',
        ('NexIP SG', 'ip2up.com', 'proxyhive.io', 'Kookeey', 'Lazycat-SG', 'Lazycat-HKT')))
        - set(ACTIVE_HOSTS)) | {'zorocloud'})
    observations = result.setdefault('exit_observations', {})
    for host, observation in (exit_observations or {}).items():
        if host not in ACTIVE_HOSTS or not isinstance(observation, dict):
            raise ValueError('invalid exit observation host')
        address = ipaddress.ip_address(observation.get('ip', ''))
        measured_at = _epoch(observation.get('observed_at'), 'exit observation')
        if not address.is_global or measured_at > cutoff:
            raise ValueError('invalid real exit observation')
        observations[host] = {'ip': str(address), 'observed_at': measured_at,
                              'dynamic': True, 'basis': 'point_in_time_public_exit_probe'}
    return validate_manifest(result)


def attach_inventory(live, manifest, now=None):
    result = copy.deepcopy(live)
    now = int(time.time() if now is None else now)
    current_inventory = inventory(datetime.fromtimestamp(now, TZ))
    for host in ACTIVE_HOSTS:
        card = result.get('servers', {}).get(host)
        if card is not None:
            card['inventory'] = current_inventory[host]
            card['display_name'] = current_inventory[host]['display_name']
            if host in manifest.get('active_since', {}):
                card['monitoring_epoch_started_at'] = manifest['active_since'][host]
    result.setdefault('topology', {}).update(active_hosts=list(ACTIVE_HOSTS),
        network_plan=PLAN_VERSION, network_activated_at=manifest['network_activated_at'],
        archived_hosts=list(manifest.get('retired_host_cards', {})),
        historical_monitoring_epochs=copy.deepcopy(manifest.get('archive_epochs', {})))
    if server_policy_enabled(manifest):
        result['topology'].update(server_policy=SERVER_POLICY_ID,
            server_policy_activated_at=manifest['server_policy_activated_at'])
    return result


def apply_daily_archive(policy, manifest):
    """Active renewal schedules override obsolete retirement cutoffs only."""
    if policy is None:
        return None
    result = copy.deepcopy(policy)
    for host in ACTIVE_HOSTS:
        result.cutoffs.pop(result.canonical(host), None)
    for name in set(manifest.get('retired_host_cards', {})) | set(manifest.get('archived_peers', ())):
        service = result.canonical(name)
        end = (manifest['network_activated_at'] if name == 'zorocloud' else manifest['cutoff'])
        result.cutoffs[service] = min(result.cutoffs.get(service, end), end)
    return result


def runtime_route_classes(config, manifest):
    """Require exact audited outbound identities, without exposing credentials."""
    specs = normalize_verified_routes(manifest['verified_routes'])
    if any(row.get('tag') in POLICY_EXCLUSIVE_FRONTS for row in config.get('inbounds', [])
           if isinstance(row, dict)) and not server_policy_enabled(manifest):
        raise ValueError('observed server policy missing statistics manifest guard')
    outbounds = {}
    for item in config.get('outbounds', []):
        if not isinstance(item, dict) or not isinstance(item.get('tag'), str):
            raise ValueError('invalid runtime outbound')
        if item['tag'] in outbounds:
            raise ValueError('duplicate runtime outbound')
        outbounds[item['tag']] = item
    result = {}
    for spec in specs:
        if spec['outbound_tag'] is None:
            continue
        item = outbounds.get(spec['outbound_tag'])
        if item is None or any(item.get(key) != spec[key] for key in ('type', 'server', 'server_port')):
            raise ValueError('audited relay outbound missing or differs')
        result[spec['outbound_tag']] = spec['route_class']
    if server_policy_enabled(manifest):
        if outbounds.get('direct', {}).get('type') != 'direct':
            raise ValueError('actual direct outbound missing')
        fronts = {row.get('tag'): row for row in config.get('inbounds', []) if isinstance(row, dict)}
        if set(fronts) != set(SERVER_POLICY_FRONTS) or any(
                fronts[tag].get('listen_port') != port or fronts[tag].get('type') != 'anytls'
                for tag, port in SERVER_POLICY_FRONTS.items()):
            raise ValueError('actual policy authentication front inventory differs')
        result['direct'] = 'direct'
    return result


def configure_source_adapters(manifest, *, subscriber=None, finalization=None,
                              retention=None, role_policy=None):
    """Extend exact tag maps; leave historical replay maps intact."""
    for spec in normalize_verified_routes(manifest['verified_routes']):
        peer, route, tag = spec['host'], spec['route_class'], spec['outbound_tag']
        if subscriber is not None and tag is not None:
            subscriber.PROVIDERS[tag] = peer
        if finalization is not None and tag is not None:
            finalization.ROUTES.setdefault('DMIT', {})[spec['inbound_tag']] = (tag, route)
        if retention is not None and tag is not None:
            retention.PROVIDERS[tag] = (route, peer)
        if role_policy is not None:
            role_policy.ROUTE_PEERS[route] = peer
            endpoint = spec['server'].lower() + ':' + str(spec['server_port'])
            role_policy.RELAY_ENDPOINTS[endpoint] = peer
            try:
                if ipaddress.ip_address(spec['server']).version == 6:
                    role_policy.RELAY_ENDPOINTS['[' + spec['server'].lower() + ']:' + str(spec['server_port'])] = peer
            except ValueError:
                pass
    if server_policy_enabled(manifest):
        if subscriber is not None: subscriber.PROVIDERS['direct'] = 'DMIT'
        if retention is not None: retention.PROVIDERS['direct'] = ('direct', 'DMIT')
    return manifest


def collector_sample(base_sample, item, manifest):
    # The audited local DMIT command reads NIC counters before its indexed
    # 30-day S-UI aggregation. At cutover that read can exceed the legacy
    # remote sampler's 17s deadline despite being healthy. Give ONLY this
    # exact local read-only command a bounded deadline; never retry an old
    # sample, replace its measured timestamp, or widen any remote command.
    if (isinstance(item, (list, tuple)) and len(item) == 2 and item[0] == 'DMIT'
            and isinstance(item[1], (list, tuple)) and tuple(item[1]) == DMIT_LOCAL_SAMPLE_COMMAND):
        server = 'DMIT'
        try:
            raw = subprocess.check_output(list(DMIT_LOCAL_SAMPLE_COMMAND), text=True,
                timeout=DMIT_LOCAL_SAMPLE_TIMEOUT, stderr=subprocess.DEVNULL)
            value = json.loads(raw)
            if (not isinstance(value, dict) or type(value.get('ts')) is not int
                    or abs(int(time.time()) - value['ts']) > 120
                    or not isinstance(value.get('boot'), str) or not value['boot']
                    or not isinstance(value.get('nic'), dict)
                    or any(type(value['nic'].get(key)) is not int or value['nic'][key] < 0
                           for key in ('rx', 'tx'))):
                raise ValueError('invalid actual local measurement')
            error = ''
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired,
                ValueError, KeyError, TypeError) as exception:
            return server, None, type(exception).__name__
    else:
        server, value, error = base_sample(item)
    if error or not value:
        return server, value, error
    value = copy.deepcopy(value)
    for route, peer in dict(RELAY_PEERS, zorocloud='zorocloud', direct='DMIT').items():
        if route in value.get('static_egress', {}):
            amount = value['static_egress'].pop(route)
            if type(amount) is not int or amount < 0:
                return server, None, 'InvalidRelayApplicationCounter'
            value.setdefault('sui_outbound', {})['topology:' + route] = amount
    return server, value, error


def store_epoch_sample(base_store, db, host, item, error, manifest):
    """First resumed sample establishes a new baseline; no gap traffic invented.

    Only the newly inserted sample can be adjusted. Real timestamps, real boot
    IDs, old samples, and all raw cumulative NIC counters stay intact.
    """
    beginning = manifest.get('active_since', {}).get(host)
    baseline = False
    if beginning and not error and item is not None:
        if int(item['ts']) < beginning:
            raise ValueError('sample predates active epoch')
        previous = db.execute('SELECT ts FROM samples WHERE server=? ORDER BY ts DESC LIMIT 1',
                              (host,)).fetchone()
        baseline = previous is None or int(previous[0]) < beginning
    result = base_store(db, host, item, error)
    if baseline:
        db.execute('UPDATE samples SET delta_rx=0,delta_tx=0 WHERE server=? AND ts=?',
                   (host, int(item['ts'])))
    return result


def attach_relay_observations(live, db_path, manifest, now=None, traffic_start=0):
    """Bounded indexed reads of confirmed DMIT sessions, not NIC estimates."""
    if not Path(db_path).is_file():
        return live
    now = int(time.time() if now is None else now)
    with closing(sqlite3.connect(Path(db_path).resolve().as_uri() + '?mode=ro', uri=True, timeout=2)) as db:
        peers = FORWARDED_OBSERVATION_PEERS + (('ByteVirt-HK ISP',) if server_policy_enabled(manifest) else ())
        for peer in peers:
            if peer not in live.get('servers', {}):
                continue
            card = live['servers'][peer]
            start = max(int(traffic_start), now - 30 * 86400,
                        int(manifest.get('active_since', {}).get(peer, 0)))
            if peer == 'ByteVirt-HK ISP':
                # Its old independent observations remain historical. Only
                # the new shared private-hop period uses DMIT estimates.
                start = max(start, manifest['server_policy_activated_at'])
            # Application slices refresh independently. One interrupted or
            # unavailable application aggregate cannot freeze physical NIC
            # samples, nor prevent the other verified exits from refreshing.
            deadline = time.monotonic() + 1
            db.set_progress_handler(lambda: time.monotonic() > deadline, 10000)
            try:
                row = db.execute('SELECT COUNT(*),COUNT(DISTINCT user),SUM(upload),SUM(download),'
                    'MIN(started),MAX(started),MAX(changed) FROM unified_records '
                    'INDEXED BY idx_unified_hk_usage '
                    "WHERE origin='dmit' AND relay=? AND started>=? AND started<=? "
                    "AND traffic_known=1 AND route_type='中转' AND ingress='DMIT' "
                    'AND upload>=0 AND download>=0 AND changed<=?', (peer, start, now, now)).fetchone()
            except sqlite3.Error as error:
                card.update(application_observation=None,
                            application_observation_state='temporarily_unavailable',
                            application_refresh_error_type=type(error).__name__,
                            application_refresh_attempted_at=now)
                continue
            finally:
                db.set_progress_handler(None, 0)
            if not row[0]:
                card.update(application_observation=None,
                            application_observation_state='no_confirmed_sessions_in_window')
                continue
            observation = {'observed_on': 'DMIT', 'first_hop': 'DMIT', 'relay': peer,
                'route_type': '中转', 'source': 'unified_records',
                'meter_basis': 'confirmed_proxy_forwarding_application', 'estimated': True,
                'independent_egress_meter': False, 'upload': int(row[2]), 'download': int(row[3]),
                'bytes': int(row[2]) + int(row[3]), 'sessions': int(row[0]), 'users': int(row[1]),
                'first_session_started': int(row[4]), 'latest_session_started': int(row[5]),
                'last_observed_at': int(row[6]), 'window_start': start, 'window_end': now}
            card.update(application_observation=observation,
                        application_observation_state='confirmed_forwarding_observation')
            if 'DMIT' in live['servers']:
                live['servers']['DMIT'].setdefault('relay_observations', {})[peer] = dict(observation, estimated=False)
    return live


def read_optional_manifest(path=None):
    """Load private plan metadata only when the new manifest is installed."""
    path = Path(path or os.environ.get('TOPOLOGY_ARCHIVE_MANIFEST',
        '/var/lib/sg-traffic-dashboard/topology-20261105.json'))
    if not path.is_file():
        return None
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 4 * 1024 * 1024:
        raise ValueError('invalid network manifest file')
    if hasattr(os, 'geteuid') and os.geteuid() == 0 and (
            info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600):
        raise ValueError('network manifest must be root private')
    value = json.loads(path.read_text(encoding='utf-8'))
    return validate_manifest(value) if is_network_manifest(value) else None


def active_whole_payload(db_path, traffic_start, now, manifest, empty_card):
    now = int(time.time() if now is None else now)
    start = max(int(traffic_start), now - 30 * 86400)
    today = max(int(traffic_start), now - ((now + 8 * 3600) % 86400))
    result = {'started': int(traffic_start),
              'servers': {host: empty_card() for host in ACTIVE_HOSTS},
              'summary': dict(today_in=0, today_out=0, month_in=0, month_out=0)}
    if Path(db_path).is_file():
        with closing(sqlite3.connect(Path(db_path).resolve().as_uri() + '?mode=ro', uri=True, timeout=2)) as db:
            # A release may explicitly add this covering index after auditing
            # storage and runtime cost. The API never creates or alters it.
            # It avoids loading large per-sample JSON pages just to sum bytes.
            use_cover = any(row[1] == PHYSICAL_COVER_INDEX and len(row) > 4 and row[4] == 0
                            for row in db.execute("PRAGMA index_list('samples')"))
            if use_cover:
                use_cover = [row[2] for row in db.execute('PRAGMA index_info(' + PHYSICAL_COVER_INDEX + ')')] == [
                    'server', 'ts', 'delta_rx', 'delta_tx']
            sample_from = 'samples' + (' INDEXED BY ' + PHYSICAL_COVER_INDEX if use_cover else '')
            for host in ACTIVE_HOSTS:
                # The original shared 4s deadline covered all six sources and
                # their cold on-disk row lookups. It could expire after valid
                # earlier sources and discard every fresh card. Bound each
                # indexed host slice independently; HTTP serving stays async.
                deadline = time.monotonic() + 4
                db.set_progress_handler(lambda: time.monotonic() > deadline, 10000)
                epoch = max(start, int(manifest.get('active_since', {}).get(host, 0)))
                row = db.execute('SELECT COUNT(*),SUM(delta_rx),SUM(delta_tx),'
                    'SUM(CASE WHEN ts>=? THEN delta_rx ELSE 0 END),'
                    'SUM(CASE WHEN ts>=? THEN delta_tx ELSE 0 END),MAX(ts) '
                    'FROM ' + sample_from + ' WHERE server=? AND ts>=?', (today, today, host, epoch)).fetchone()
                if not row[0]:
                    continue
                card = result['servers'][host]
                card.update({'in': int(row[1] or 0), 'out': int(row[2] or 0),
                    'today_in': int(row[3] or 0), 'today_out': int(row[4] or 0),
                    'sampled_at': int(row[5])})
                raw = db.execute('SELECT sui_json,hk_json FROM samples WHERE server=? AND ts>=? '
                                 'ORDER BY ts DESC LIMIT 1', (host, epoch)).fetchone()
                try:
                    counters = json.loads(raw[1] if host == 'ByteVirt-HK ISP' else raw[0])
                    counters = {str(key): int(value) for key, value in counters.items() if int(value) >= 0}
                except (TypeError, ValueError, AttributeError):
                    counters = {}
                if counters:
                    card['proxy_app'] = sum(counters.values())
                    card['direct'] = card['proxy_app'] if host == 'ByteVirt-HK ISP' else counters.get(
                        'topology:direct', counters.get('direct'))
                    card['details'] = {'routes' if host == 'ByteVirt-HK ISP' else 'outbound_tags': counters}
                    if host == 'DMIT':
                        for route, peer in RELAY_PEERS.items():
                            if 'topology:' + route in counters:
                                card['static_outbound'][peer] = counters['topology:' + route]
                row = db.execute('SELECT SUM(mapping_wire) FROM categories WHERE server=? AND ts>=?',
                                 (host, epoch)).fetchone()
                if row and row[0] is not None:
                    card['mapping_wire'] = int(row[0])
                for total, field in (('month_in', 'in'), ('month_out', 'out'),
                                     ('today_in', 'today_in'), ('today_out', 'today_out')):
                    result['summary'][total] += card[field]
        try:
            attach_relay_observations(result, db_path, manifest, now, traffic_start)
        except sqlite3.Error as error:
            # The independently collected NIC totals above remain valid even
            # if the application connection cannot be opened at this instant.
            for host in FORWARDED_OBSERVATION_PEERS + (('ByteVirt-HK ISP',) if server_policy_enabled(manifest) else ()):
                result['servers'][host].update(application_observation=None,
                    application_observation_state='temporarily_unavailable',
                    application_refresh_error_type=type(error).__name__,
                    application_refresh_attempted_at=now)
    for host, observation in manifest.get('exit_observations', {}).items():
        if host in result['servers']:
            result['servers'][host]['exit_observation'] = copy.deepcopy(observation)
    return attach_inventory(result, manifest, now)


def extend_active_user_usage(rows, db_path, traffic_start, now, manifest):
    """Keep independently observed HK totals; add each new DMIT relay once."""
    result = [row for row in rows if row.get('server') in ACTIVE_HOSTS and
              row.get('server') not in ('Lazycat-SG', 'Lazycat-HKT', 'Uzuma-SG-Singtel1')]
    if not Path(db_path).is_file():
        return result
    now = int(time.time() if now is None else now)
    with closing(sqlite3.connect(Path(db_path).resolve().as_uri() + '?mode=ro', uri=True, timeout=2)) as db:
        deadline = time.monotonic() + 3
        db.set_progress_handler(lambda: time.monotonic() > deadline, 10000)
        peers = ('Lazycat-SG', 'Lazycat-HKT', 'Uzuma-SG-Singtel1') + (('ByteVirt-HK ISP',) if server_policy_enabled(manifest) else ())
        for peer in peers:
            start = max(int(traffic_start), now - 30 * 86400,
                        int(manifest.get('active_since', {}).get(peer, 0)))
            if peer == 'ByteVirt-HK ISP':
                start = max(start, manifest['server_policy_activated_at'])
            query = ('SELECT user,SUM(upload+download) FROM unified_records '
                'INDEXED BY idx_unified_hk_usage '
                "WHERE origin='dmit' AND relay=? AND started>=? AND traffic_known=1 "
                "AND route_type='中转' AND ingress='DMIT' GROUP BY user")
            for user, amount in db.execute(query, (peer, start)):
                if amount and amount > 0:
                    prior = next((row for row in result if row['server'] == peer and row['user'] == user), None)
                    if prior is not None:
                        prior['total'] += int(amount)
                        prior.update(estimated=True, basis='independent HK before policy; DMIT forwarding after policy')
                    else:
                        result.append({'server': peer, 'user': user, 'total': int(amount),
                                       'estimated': True, 'basis': 'DMIT forwarding application bytes'})
    return result
