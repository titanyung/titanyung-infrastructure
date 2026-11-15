"""DMIT-owned audit/accounting adapter for two isolated AI native runtimes.

Preparation only: importing this module opens no database or socket. The CLI
must be explicitly installed/run by the operator; it never alters units,
accounts, firewall rules, a core, or a client mode. API endpoints are loopback.

Only cumulative native snapshots are billable. Delta-only UPDATE has no native
sequence ID, so it cannot safely be persistently deduplicated after a retry.
It records a coverage gap; the next full NEW/CLOSED snapshot reconciles totals.
Thus live daily displays can lag until CLOSED. Rejections absent from the
native API remain a documented log-coverage gap, never a fabricated zero.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import time
from types import SimpleNamespace

from edge_ai_policy import INBOUND_TAGS, validate_ai_runtime
from edge_apply import canonical, digest, read_private, strict_json, validate_manifest

DEFAULT_AUDIT_DB = '/var/lib/submerge-edge/events.db'
DEFAULT_DAILY_DB = '/var/lib/user-daily-traffic/daily.db'
MAX_MIRROR = 4 * 1024 * 1024
MAX_EVENTS = 5000
PAIRS = {('DMIT', 'ai-secondary'): '127.0.0.1:32093',
         ('Lazycat-AI', 'ai-primary'): '127.0.0.1:32193'}
RETENTION_DAYS = 31


class EventError(ValueError):
    pass


def need(value, code):
    if not value:
        raise EventError(code)


def text(value, code, limit=1024, empty=False):
    need(isinstance(value, str) and len(value) <= limit and
         (empty or value) and not any(ord(c) < 32 for c in value), code)
    return value


def integer(value, code, *, zero=False):
    need(type(value) is int and (value >= 0 if zero else value > 0) and value < 2**63, code)
    return value


def endpoint_document(value):
    need(isinstance(value, dict) and set(value) ==
         {'edge_id', 'host', 'runtime', 'address', 'mirror_path'}, 'endpoint_fields')
    text(value['edge_id'], 'edge_id', 64)
    need(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}', value['edge_id']), 'edge_id')
    need(PAIRS.get((value['host'], value['runtime'])) == value['address'], 'unreviewed_endpoint')
    need(isinstance(value['mirror_path'], str) and Path(value['mirror_path']).is_absolute(),
         'absolute_mirror_path_required')
    return dict(value)


def verify_mirror(mirror, edge_id, now=None):
    """Verify the ACK plus the separate live-status proof bound to exact config.

    Passwords and API secrets remain in this private in-memory document. Neither
    this function nor the audit serialization returns or stores those fields.
    """
    need(isinstance(mirror, dict) and set(mirror) ==
         {'schema', 'checked_at', 'manifest', 'manifest_sha256', 'config', 'ack', 'loaded_status'}, 'mirror_fields')
    need(mirror['schema'] == 1, 'mirror_schema')
    now = int(time.time()) if now is None else integer(now, 'mirror_current_time')
    checked = integer(mirror['checked_at'], 'mirror_checked_at')
    need(now - 120 <= checked <= now + 10, 'mirror_status_stale_or_future')
    manifest, config = mirror['manifest'], mirror['config']
    validate_manifest(manifest, mirror['manifest_sha256'],
                      Path(manifest['install_root']).absolute(), edge_id)
    need(manifest['cohort_inbound_count'] in (2,4), 'ai_inbound_inventory_required')
    metadata = validate_ai_runtime(config,**({'routing_revision':manifest['routing_revision'],
        'execution_front':manifest['routing_execution_front']} if 'routing_revision' in manifest else {}))
    need(metadata['cohort_inbound_count'] == manifest['cohort_inbound_count'], 'mirror_inbound_count_mismatch')
    need(metadata['accounts'] == manifest['accounts'], 'mirror_cohort_mismatch')
    record = next(row for row in manifest['files'] if row['path'] == manifest['config_path'])
    encoded = canonical(config)
    need(record['sha256'] == digest(encoded) and record['size'] == len(encoded), 'mirror_config_hash')
    ack, status = mirror['ack'], mirror['loaded_status']
    need(isinstance(ack, dict) and isinstance(status, dict), 'mirror_proofs_required')
    for proof in (ack, status):
        for key, expected in (('edge_id', edge_id), ('generation', manifest['generation']),
                ('manifest_sha256', mirror['manifest_sha256']),
                ('cohort_sha256', manifest['accounts']['cohort_sha256']),
                ('active_user_count', len(manifest['accounts']['usernames']))):
            need(proof.get(key) == expected, 'mirror_proof_' + key)
    need(ack.get('status') == 'applied' and status.get('verified') is True and
         status.get('active_usernames') == manifest['accounts']['usernames'], 'mirror_unverified_status')
    if manifest['accounts']['usernames']:
        need(ack.get('enforcement') == status.get('enforcement') == 'running_verified' and
             status.get('active') is True and type(status.get('pid')) is int and status['pid'] > 0 and
             isinstance(ack.get('health'), dict) and ack['health'].get('healthy') is True and
             type(ack['health'].get('pid')) is int and ack['health']['pid'] > 0,
             'mirror_core_not_running')
        # The immutable apply ACK proves its original process. A supervised
        # restart can legitimately produce a new PID in the same verified
        # generation. Fresh loaded_status independently re-hashes the installed
        # generation and verifies /proc/PID/exe plus its exact -c config. The
        # stream's GetStartedAt supplies a separate audit epoch; do not mutate
        # the original ACK or fabricate a new apply just to match current PID.
    else:
        need(ack.get('enforcement') == status.get('enforcement') == 'service_stopped_no_accounts' and
             status.get('active') is False and status.get('pid') == 0, 'mirror_empty_cohort_not_stopped')
    apis = config.get('services', [])
    need(len(apis) == 1 and apis[0].get('type') == 'api' and
         apis[0].get('listen') == '127.0.0.1' and apis[0].get('listen_port') == 32093 and
         isinstance(apis[0].get('secret'), str) and len(apis[0]['secret']) >= 24,
         'unreviewed_native_api')
    return copy.deepcopy(mirror)


def read_mirror(endpoint, require_root_owner=True):
    raw = read_private(endpoint['mirror_path'], MAX_MIRROR, require_root_owner)
    return verify_mirror(strict_json(raw), endpoint['edge_id'])


def route_peers(network_manifest):
    """The Singtel host label comes only from the authoritative stats manifest."""
    candidates = [row.get('host') for row in (network_manifest or {}).get('verified_routes', [])
                  if isinstance(row, dict) and row.get('outbound_tag') == 'uzuma-singtel']
    singtel = candidates[0] if len(candidates) == 1 else None
    if singtel is not None:
        text(singtel, 'invalid_singtel_host', 160)
    # This new tag is admitted only by the strict V2 policy inventory. Its
    # dedicated host label is never inferred from an arbitrary display name or
    # loopback endpoint, and all existing first-hop/runtime namespaces stay put.
    return {'lazycat-starhub': 'Lazycat-SG', 'uzuma-singtel': singtel,
            'uzuma-starhub':'Uzuma-SG-StarHub',
            'dmit-google-fallback': 'ByteVirt-TW','paoluz-sg-fallback':'Paoluz-SG'}


def claims(host, outbound, peers):
    source = 'edge-native-cumulative'
    def claim(role, peer, basis, estimated=False):
        return dict(role=role, peer=peer, source=source, meter_basis=basis,
                    estimated=estimated, priority=100, zero=False)
    result = [claim('ingress', host, 'authenticated_inbound_application')]
    if outbound=='direct':
        result.append(claim('egress',host,'direct_destination_application'))
        return result
    peer = peers.get(outbound)
    if peer:
        via_dmit = outbound in ('dmit-google-fallback','paoluz-sg-fallback')
        result += [claim('relay', peer,
            'multihop_via_dmit_forwarded_application' if via_dmit else 'confirmed_proxy_forwarding_application',
            via_dmit), claim('egress', peer,
            'multihop_via_dmit_forwarded_application' if via_dmit else 'forwarded_application', True)]
    # Unknown paths retain only proven authenticated ingress; no made-up zero.
    return result


def make_daily_adapter(base_class, endpoint, peers, epoch):
    """Reuse the installed NativeBatchAdapter.apply, scoped to reviewed hosts."""
    class AIAdapter(base_class):
        def __init__(self):
            # Base constructor only approves its legacy FIRST_HOPS. The audited
            # new source is explicitly admitted here without modifying it.
            self.host, self.runtime = endpoint['host'], endpoint['runtime']
            self.exit_observation, self.max_active, self.active = False, 20000, {}
            self.routes = dict(peers)

        def _observation(self, item):
            return dict(host=self.host, runtime=self.runtime,
                connection_id='edge:' + digest(canonical([endpoint['edge_id'], epoch, item['connection_id']])),
                created_at_ms=item['created_at_ms'], user=item['user'],
                upload=item['upload'], download=item['download'], closed=item['closed'],
                roles=claims(self.host, item['outbound'], self.routes))
    return AIAdapter()


SCHEMA = '''
CREATE TABLE IF NOT EXISTS edge_connections(
 edge_id TEXT NOT NULL,epoch INTEGER NOT NULL,connection_id TEXT NOT NULL,
 generation INTEGER NOT NULL,manifest_sha256 TEXT NOT NULL,created_at_ms INTEGER NOT NULL,
 closed_at_ms INTEGER,username TEXT,inbound TEXT,source_address TEXT,source_status TEXT NOT NULL,
 network TEXT,protocol TEXT,rule TEXT,destination TEXT,domain TEXT,outbound TEXT,outbound_type TEXT,
 chain_json TEXT NOT NULL,upload_bytes INTEGER NOT NULL,download_bytes INTEGER NOT NULL,
 first_seen_ms INTEGER NOT NULL,last_seen_ms INTEGER NOT NULL,
 PRIMARY KEY(edge_id,epoch,connection_id));
CREATE INDEX IF NOT EXISTS edge_connections_received ON edge_connections(last_seen_ms);
CREATE TABLE IF NOT EXISTS edge_gaps(
 edge_id TEXT NOT NULL,epoch INTEGER NOT NULL,minute INTEGER NOT NULL,reason TEXT NOT NULL,
 username TEXT NOT NULL,host TEXT NOT NULL,runtime TEXT NOT NULL,observed_at_ms INTEGER NOT NULL,
 PRIMARY KEY(edge_id,epoch,minute,reason,username));
CREATE TABLE IF NOT EXISTS edge_security_candidates(
 event_key TEXT PRIMARY KEY,edge_id TEXT NOT NULL,epoch INTEGER NOT NULL,connection_id TEXT NOT NULL,
 kind TEXT NOT NULL,payload TEXT NOT NULL,observed_at_ms INTEGER NOT NULL,ingest_receipt TEXT);
CREATE INDEX IF NOT EXISTS edge_security_pending ON edge_security_candidates(ingest_receipt,observed_at_ms);
CREATE TABLE IF NOT EXISTS edge_daily_outbox(
 edge_id TEXT NOT NULL,epoch INTEGER NOT NULL,connection_id TEXT NOT NULL,
 payload TEXT NOT NULL,observed_at_ms INTEGER NOT NULL,
 PRIMARY KEY(edge_id,epoch,connection_id));
'''


class EventAudit:
    def __init__(self, path, retention_days=RETENTION_DAYS):
        need(type(retention_days) is int and 1 <= retention_days <= 365, 'retention_bound')
        target = Path(path)
        need(not target.is_symlink(), 'audit_db_symlink')
        target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if os.name != 'nt':
            need(not target.parent.stat().st_mode & 0o077, 'audit_parent_not_private')
        previous_umask = os.umask(0o077)
        try:
            self.db = sqlite3.connect(str(target), timeout=10)
            target.chmod(0o600)
            self.db.row_factory = sqlite3.Row
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA busy_timeout=10000')
            self.db.executescript(SCHEMA)
        finally:
            os.umask(previous_umask)
        self.retention_days = retention_days

    def close(self):
        self.db.close()

    def gap(self, endpoint, epoch, reason, user='', now_ms=None):
        now_ms = int(time.time() * 1000) if now_ms is None else now_ms
        reason, user = text(reason, 'gap_reason', 100), text(user, 'gap_user', 128, True)
        with self.db:
            changed = self.db.execute('INSERT OR IGNORE INTO edge_gaps VALUES(?,?,?,?,?,?,?,?)',
                (endpoint['edge_id'], epoch, now_ms // 60000, reason, user,
                 endpoint['host'], endpoint['runtime'], now_ms)).rowcount
        return bool(changed)

    def save(self, endpoint, epoch, mirror, row, observation, now_ms):
        key = (endpoint['edge_id'], epoch, row['connection_id'])
        old = self.db.execute('SELECT * FROM edge_connections WHERE edge_id=? AND epoch=? AND connection_id=?',
                              key).fetchone()
        if old:
            for name in ('created_at_ms', 'username', 'inbound', 'source_address', 'outbound'):
                need(not old[name] or not row[name] or old[name] == row[name], 'connection_identity_or_route_changed')
            need(row['upload_bytes'] >= old['upload_bytes'] and row['download_bytes'] >= old['download_bytes'],
                 'native_counter_regression')
        payload = dict(row, edge_id=endpoint['edge_id'], epoch=epoch,
            generation=mirror['manifest']['generation'], manifest_sha256=mirror['manifest_sha256'],
            first_seen_ms=old['first_seen_ms'] if old else now_ms, last_seen_ms=now_ms)
        if old:
            for name in ('username', 'inbound', 'source_address', 'network', 'protocol', 'rule',
                         'destination', 'domain', 'outbound', 'outbound_type'):
                payload[name] = payload[name] or old[name]
            payload['closed_at_ms'] = max(payload['closed_at_ms'] or 0, old['closed_at_ms'] or 0) or None
        names = list(payload)
        with self.db:
            self.db.execute('INSERT OR REPLACE INTO edge_connections (' + ','.join(names) +
                            ') VALUES (' + ','.join('?' for _ in names) + ')', [payload[n] for n in names])
            if observation is not None:
                self.db.execute('INSERT OR REPLACE INTO edge_daily_outbox VALUES(?,?,?,?,?)',
                    (*key, canonical(observation).decode(), now_ms))
            kinds = []
            if (payload['protocol'] or '').casefold() in ('bittorrent', 'torrent'):
                kinds.append('native_bittorrent_protocol')
            if payload['outbound_type'] in ('block', 'reject') or 'reject' in (payload['rule'] or '').casefold():
                kinds.append('native_reject_marker')
            for kind in kinds:
                event_key = digest(canonical([*key, kind]))
                candidate = {k: payload[k] for k in ('edge_id', 'epoch', 'connection_id', 'username',
                    'source_address', 'source_status', 'protocol', 'rule', 'destination', 'outbound')}
                candidate.update(kind=kind, confidence='native_observed_marker',
                                 automatic_enforcement_eligible=False, rejection_coverage_complete=False)
                self.db.execute('INSERT OR IGNORE INTO edge_security_candidates VALUES(?,?,?,?,?,?,?,NULL)',
                    (event_key, *key, kind, canonical(candidate).decode(), now_ms))

    def drain_daily(self, ledger, limit=500):
        need(type(limit) is int and 1 <= limit <= 5000, 'outbox_limit')
        count = 0
        for row in self.db.execute('SELECT * FROM edge_daily_outbox ORDER BY observed_at_ms LIMIT ?', (limit,)).fetchall():
            # Crash after ledger commit but before deletion is safe: the ledger
            # consumes cumulative totals and deduplicates the identical replay.
            result = ledger.record([json.loads(row['payload'])], observed_at=row['observed_at_ms'] // 1000)
            need(not result.get('rejected'), 'daily_snapshot_rejected')
            with self.db:
                self.db.execute('DELETE FROM edge_daily_outbox WHERE edge_id=? AND epoch=? AND connection_id=? AND payload=?',
                    (row['edge_id'], row['epoch'], row['connection_id'], row['payload']))
            count += 1
        return count

    def pending_security(self, limit=100):
        need(type(limit) is int and 1 <= limit <= 1000, 'security_limit')
        return [dict(event_key=row['event_key'], **json.loads(row['payload'])) for row in
            self.db.execute('SELECT event_key,payload FROM edge_security_candidates WHERE ingest_receipt IS NULL '
                            'ORDER BY observed_at_ms LIMIT ?', (limit,))]

    def acknowledge_security(self, event_key, ingest_receipt):
        need(re.fullmatch(r'[a-f0-9]{64}', event_key), 'security_event_key')
        text(ingest_receipt, 'security_ingest_receipt', 256)
        with self.db:
            self.db.execute('UPDATE edge_security_candidates SET ingest_receipt=? WHERE event_key=? AND ingest_receipt IS NULL',
                            (ingest_receipt, event_key))

    def prune(self, now_ms, limit=5000):
        need(type(limit) is int and 1 <= limit <= 10000, 'prune_limit')
        cutoff = now_ms - self.retention_days * 86400000
        count = 0
        with self.db:
            for table, column in (('edge_connections', 'last_seen_ms'), ('edge_gaps', 'observed_at_ms'),
                                  ('edge_security_candidates', 'observed_at_ms')):
                count += self.db.execute('DELETE FROM ' + table + ' WHERE rowid IN (SELECT rowid FROM ' + table +
                                        ' WHERE ' + column + '<? LIMIT ?)', (cutoff, limit)).rowcount
        # Undelivered accounting outbox is never silently pruned.
        return count


def snapshot_row(event, epoch, now_ms, retention_days):
    connection = getattr(event, 'connection', None)
    need(connection is not None, 'native_snapshot_missing')
    uid = text(str(getattr(event, 'id', '') or ''), 'native_id', 256)
    need(not getattr(connection, 'id', '') or str(connection.id) == uid, 'native_id_mismatch')
    created = integer(getattr(connection, 'createdAt', None), 'native_created')
    need(created <= now_ms + 120000, 'native_future_created')
    closed = int(getattr(connection, 'closedAt', 0) or getattr(event, 'closedAt', 0) or 0)
    need(closed >= 0 and (not closed or created <= closed <= now_ms + 120000), 'native_closed')
    need(not closed or closed >= now_ms - retention_days * 86400000, 'native_replay_expired')
    def field(name, limit=1024):
        return text(str(getattr(connection, name, '') or ''), 'native_text_field', limit, True) or None
    source = field('source', 256)
    source_status = 'missing'
    if source:
        try:
            address = source[1:source.index(']')] if source.startswith('[') else source.rsplit(':', 1)[0]
            ip = ipaddress.ip_address(address)
            source_status = 'loopback_not_client' if ip.is_loopback or ip.is_unspecified else 'native_reported'
        except (ValueError, IndexError):
            source_status = 'unparseable'
    chain = list(getattr(connection, 'chainList', []))
    need(len(chain) <= 16, 'native_chain_limit')
    chain = [text(str(item), 'native_chain', 256) for item in chain]
    return dict(connection_id=uid, created_at_ms=created, closed_at_ms=closed or None,
        username=field('user', 128), inbound=field('inbound', 128), source_address=source,
        source_status=source_status, network=field('network', 32), protocol=field('protocol', 64),
        rule=field('rule', 2048), destination=field('destination', 1024), domain=field('domain', 253),
        outbound=field('outbound', 128), outbound_type=field('outboundType', 64),
        chain_json=canonical(chain).decode(),
        upload_bytes=integer(getattr(connection, 'uplinkTotal', None), 'native_upload', zero=True),
        download_bytes=integer(getattr(connection, 'downlinkTotal', None), 'native_download', zero=True))


class EdgeCollector:
    def __init__(self, endpoint, mirror, epoch, audit, ledger, native_adapter_class, network_manifest=None):
        self.endpoint = endpoint_document(endpoint)
        self.mirror = verify_mirror(mirror, endpoint['edge_id'])
        self.epoch = integer(epoch, 'native_epoch')
        self.audit, self.ledger = audit, ledger
        self.peers = route_peers(network_manifest)
        if 'routing_revision' in self.mirror['manifest']:
            import routing_contract as contract
            revision=self.mirror['manifest']['routing_revision']
            self.peers['dmit-google-fallback']='ByteVirt-TW' if contract.available(revision,'bytevirt-taiwan') else 'Uzuma-HKT'
            self.peers['direct']=endpoint['host']
        self.adapter = make_daily_adapter(native_adapter_class, self.endpoint, self.peers, epoch)
        self.users = set(mirror['manifest']['accounts']['usernames'])
        self.inbounds = frozenset(row['tag'] for row in self.mirror['config']['inbounds'])
        self.ledger.register_users(sorted(self.users), host=endpoint['host'], runtime=endpoint['runtime'])

    def gap(self, reason, user='', now_ms=None):
        if self.audit.gap(self.endpoint, self.epoch, reason, user, now_ms):
            self.ledger.record_gap(reason, user=user, host=self.endpoint['host'],
                runtime=self.endpoint['runtime'], observed_at=None if now_ms is None else now_ms // 1000)

    def apply(self, batch, now_ms=None):
        now_ms = int(time.time() * 1000) if now_ms is None else integer(now_ms, 'observation_time')
        events = list(getattr(batch, 'events', []))
        need(len(events) <= MAX_EVENTS, 'native_batch_limit')
        self.gap('native_reject_log_coverage_incomplete', now_ms=now_ms)
        if self.peers['uzuma-singtel'] is None:
            self.gap('uzuma_host_mapping_unavailable', now_ms=now_ms)
        if bool(getattr(batch, 'reset', False)):
            self.adapter.active.clear()
            if sum(bool(getattr(getattr(e, 'connection', None), 'closedAt', 0)) for e in events) >= 1000:
                self.gap('grpc_replay_limit', now_ms=now_ms)
        accepted = 0
        for event in events:
            try:
                kind = int(getattr(event, 'type', -1))
                need(kind in (0, 1, 2), 'invalid_native_type')
                try:
                    has_full = event.HasField('connection')
                except (AttributeError, ValueError):
                    has_full = getattr(event, 'connection', None) is not None
                if not has_full:
                    self.gap('delta_only_accounting_deferred' if kind == 1 else 'native_event_without_snapshot', now_ms=now_ms)
                    continue
                row = snapshot_row(event, self.epoch, now_ms, self.audit.retention_days)
                if kind == 2 and row['closed_at_ms'] is None:
                    raise EventError('native_closed_timestamp_missing')
                user = row['username'] or ''
                observation = None
                if row['source_status'] != 'native_reported':
                    self.gap('native_client_source_unavailable', user, now_ms)
                if user not in self.users:
                    self.gap('native_user_not_in_ack_cohort', user, now_ms)
                elif row['inbound'] not in self.inbounds:
                    self.gap('native_inbound_not_in_ai_inventory', user, now_ms)
                else:
                    # Only full snapshots enter the existing delta adapter.
                    values, gaps = self.adapter.apply(SimpleNamespace(events=[event], reset=False))
                    for reason, gap_user in gaps:
                        self.gap(reason, gap_user, now_ms)
                    if values:
                        observation = values[0]
                    if not self.peers.get(row['outbound']):
                        self.gap('native_outbound_unclassified', user, now_ms)
                self.audit.save(self.endpoint, self.epoch, self.mirror, row, observation, now_ms)
                accepted += 1
            except (EventError, ValueError, TypeError, OverflowError) as error:
                code = str(error) if isinstance(error, EventError) else 'invalid_native_snapshot'
                self.gap(code, now_ms=now_ms)
        delivered = self.audit.drain_daily(self.ledger, limit=MAX_EVENTS)
        return {'snapshots_saved': accepted, 'daily_snapshots_delivered': delivered,
                'delta_only_accounting': 'deferred_until_cumulative_snapshot',
                'native_rejection_coverage_complete': False}


def follow(endpoint, audit, ledger, *, protobuf_dir='/opt/static-connection-events'):
    """One endpoint per process. Root controls any later service installation."""
    sys.path[:0] = ['/opt/user-daily-traffic', '/opt/submerge-topology', protobuf_dir]
    import grpc
    import queue
    import threading
    from google.protobuf import empty_pb2
    from daily_subscriber import NativeBatchAdapter
    import network_stats
    pb = importlib.import_module('connection_events_pb2')
    rpc = importlib.import_module('connection_events_pb2_grpc')
    delay = 1
    while True:
        epoch = 1
        try:
            mirror = read_mirror(endpoint)
            if not mirror['manifest']['accounts']['usernames']:
                time.sleep(5)
                continue
            secret = mirror['config']['services'][0]['secret']
            metadata = (('authorization', 'Bearer ' + secret),)
            network = network_stats.read_optional_manifest()
            with grpc.insecure_channel(endpoint['address']) as channel:
                stub = rpc.StartedServiceStub(channel)
                epoch = integer(stub.GetStartedAt(empty_pb2.Empty(), metadata=metadata, timeout=10).startedAt,
                                'native_epoch')
                collector = EdgeCollector(endpoint, mirror, epoch, audit, ledger, NativeBatchAdapter, network)
                audit.drain_daily(ledger)
                stream = stub.SubscribeConnections(pb.SubscribeConnectionsRequest(interval=0),
                    metadata=metadata, wait_for_ready=True)
                # A bounded reader lets the single SQLite owner check mirrors,
                # drain a crash-recovery outbox, and prune even on a quiet core.
                inbox, stop, end = queue.Queue(maxsize=4), threading.Event(), object()
                def send(value):
                    while not stop.is_set():
                        try:
                            inbox.put(value, timeout=1)
                            return
                        except queue.Full:
                            pass
                def receive():
                    try:
                        for value in stream:
                            send(value)
                            if stop.is_set():
                                return
                    except Exception:
                        send(EventError('native_stream_unavailable'))
                    finally:
                        send(end)
                reader = threading.Thread(target=receive, daemon=True, name='edge-native-reader')
                reader.start()
                checked, pruned, delay = time.monotonic(), time.monotonic(), 1
                try:
                    while True:
                        if time.monotonic() - checked > 30:
                            checked = time.monotonic()
                            current = read_mirror(endpoint)
                            if current['manifest_sha256'] != mirror['manifest_sha256']:
                                break
                        audit.drain_daily(ledger, limit=MAX_EVENTS)
                        if time.monotonic() - pruned > 300:
                            audit.prune(int(time.time() * 1000))
                            pruned = time.monotonic()
                        try:
                            value = inbox.get(timeout=5)
                        except queue.Empty:
                            continue
                        if value is end:
                            break
                        if isinstance(value, EventError):
                            raise value
                        collector.apply(value)
                finally:
                    stop.set()
                    stream.cancel()
                    reader.join(timeout=3)
        except Exception:
            # No secret, source address, destination, username or protocol dump.
            if audit.gap(endpoint, epoch, 'native_stream_or_mirror_unavailable'):
                ledger.record_gap('native_stream_or_mirror_unavailable', host=endpoint['host'],
                                  runtime=endpoint['runtime'])
            print('edge native reconnect: unavailable', file=sys.stderr, flush=True)
            time.sleep(delay)
            delay = min(delay * 2, 30)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--edge-id', required=True)
    parser.add_argument('--host', choices=('DMIT', 'Lazycat-AI'), required=True)
    parser.add_argument('--runtime', choices=('ai-secondary', 'ai-primary'), required=True)
    parser.add_argument('--address', choices=tuple(PAIRS.values()), required=True)
    parser.add_argument('--mirror', required=True)
    parser.add_argument('--audit-db', default=DEFAULT_AUDIT_DB)
    parser.add_argument('--daily-db', default=DEFAULT_DAILY_DB)
    parser.add_argument('--protobuf-dir', default='/opt/static-connection-events')
    args = parser.parse_args(argv)
    need(os.name != 'nt' and os.geteuid() == 0, 'root_collector_required')
    endpoint = endpoint_document(dict(edge_id=args.edge_id, host=args.host, runtime=args.runtime,
                                     address=args.address, mirror_path=args.mirror))
    sys.path.insert(0, '/opt/user-daily-traffic')
    from daily_accounting import DailyLedger
    audit, ledger = EventAudit(args.audit_db), DailyLedger(args.daily_db, source_key='DMIT')
    try:
        follow(endpoint, audit, ledger, protobuf_dir=args.protobuf_dir)
    finally:
        ledger.close()
        audit.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
