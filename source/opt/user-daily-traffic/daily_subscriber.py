#!/usr/bin/env python3
"""Independent all-route native daily accounting stream.

This daemon does not change the existing static CLOSED-event recorder or its
database. It reads the same localhost API and writes only the daily ledger.
"""
import argparse
import importlib
import json
from pathlib import Path
import sys
import time

from daily_accounting import DailyLedger
from daily_expiry import load_policy
from role_policy import FIRST_HOPS, ACTIVE_EXITS, roles_for_route, routes_for_config


def _has_connection(event):
    try:
        return event.HasField('connection')
    except (AttributeError, ValueError):
        return getattr(event, 'connection', None) is not None


def _snapshot(connection, event_id):
    uid = str(getattr(connection, 'id', '') or event_id)
    if not uid or (event_id and uid != event_id):
        raise ValueError('native connection id mismatch')
    user = str(getattr(connection, 'user', '') or '')
    created = int(getattr(connection, 'createdAt', 0))
    up, down = int(getattr(connection, 'uplinkTotal', -1)), int(getattr(connection, 'downlinkTotal', -1))
    if not user or created <= 0 or up < 0 or down < 0:
        raise ValueError('native connection lacks identity or valid counters')
    return dict(connection_id=uid, user=user, created_at_ms=created,
        upload=up, download=down, outbound=str(getattr(connection, 'outbound', '') or ''),
        destination=str(getattr(connection, 'destination', '') or ''),
        closed=bool(getattr(connection, 'closedAt', 0)))


class NativeBatchAdapter:
    """Convert NEW/full counters, UPDATE/deltas and CLOSED/finals to totals."""
    def __init__(self, host, config, runtime='dedicated', exit_observation=False, max_active=20000):
        if host not in (ACTIVE_EXITS if exit_observation else FIRST_HOPS):
            raise ValueError('daily stream target is not an approved active host')
        self.host, self.runtime = host, runtime
        self.exit_observation = bool(exit_observation)
        self.routes = routes_for_config(config)
        self.active = {}
        self.max_active = int(max_active)

    def _observation(self, item):
        route = self.routes.get(item['outbound'], 'unknown')
        claims = roles_for_route(self.host, route, item['destination'],
            source='exit-native' if self.exit_observation else 'singbox-native',
            exit_observation=self.exit_observation)
        return dict(host=self.host, runtime=self.runtime,
            connection_id=item['connection_id'], created_at_ms=item['created_at_ms'],
            user=item['user'], upload=item['upload'], download=item['download'],
            closed=item['closed'], roles=claims)

    def apply(self, batch):
        observations, gaps = [], set()
        events = list(getattr(batch, 'events', []))
        if bool(getattr(batch, 'reset', False)):
            self.active.clear()
            replayed_closed = sum(getattr(event, 'type', -1) == 2 or
                (_has_connection(event) and getattr(event.connection, 'closedAt', 0) > 0)
                for event in events)
            if replayed_closed >= 1000:
                gaps.add(('grpc_replay_limit', ''))
        for event in events:
            uid = str(getattr(event, 'id', '') or '')
            event_type = int(getattr(event, 'type', -1))
            try:
                if event_type not in (0, 1, 2) or not uid:
                    raise ValueError('invalid native event')
                if _has_connection(event) and getattr(event.connection, 'user', ''):
                    item = _snapshot(event.connection, uid)
                elif event_type == 1:
                    prior = self.active.get(uid)
                    if prior is None:
                        gaps.add(('grpc_update_without_identity', ''))
                        continue
                    up = int(getattr(event, 'uplinkDelta', -1))
                    down = int(getattr(event, 'downlinkDelta', -1))
                    if up < 0 or down < 0:
                        raise ValueError('negative native delta')
                    item = dict(prior)
                    item['upload'] += up
                    item['download'] += down
                else:
                    gaps.add(('grpc_event_without_identity', ''))
                    continue
                item['closed'] = bool(item['closed'] or event_type == 2 or getattr(event, 'closedAt', 0) > 0)
                if not item['closed'] and uid not in self.active and len(self.active) >= self.max_active:
                    gaps.add(('grpc_active_state_limit', item['user']))
                    continue
                observation = self._observation(item)
                observations.append(observation)
                if len(observation['roles']) == 1 and not self.exit_observation:
                    gaps.add(('unclassified_native_route', item['user']))
                if item['closed']:
                    self.active.pop(uid, None)
                else:
                    self.active[uid] = item
            except (ValueError, TypeError, OverflowError):
                gaps.add(('invalid_native_event', ''))
        return observations, sorted(gaps)


def load_secret(path):
    target = Path(path)
    if not target.is_file() or target.stat().st_mode & 0o077:
        raise ValueError('API secret must be a private regular file')
    secret = target.read_text(encoding='utf-8').strip()
    if not secret:
        raise ValueError('API secret is empty')
    return secret


def configured_users(config):
    return sorted({user['name'] for inbound in config.get('inbounds', [])
                   for user in inbound.get('users', [])
                   if isinstance(user, dict) and isinstance(user.get('name'), str) and user['name']})


def follow(args):
    if not args.address.startswith('127.0.0.1:'):
        raise ValueError('daily native API must use localhost')
    sys.path.insert(0, args.protobuf_dir)
    import grpc
    from google.protobuf import empty_pb2
    pb = importlib.import_module('connection_events_pb2')
    rpc = importlib.import_module('connection_events_pb2_grpc')
    ledger = DailyLedger(args.db, source_key=args.host)
    load_policy(required=True)
    secret = load_secret(args.secret_file)
    metadata = (('authorization', 'Bearer ' + secret),)
    last_gap = {}

    def gap(reason, user='', observed_at=None):
        now = int(observed_at or time.time())
        if now - last_gap.get((reason, user), 0) < 60:
            return
        ledger.record_gap(reason, observed_at=now, user=user, host=args.host, runtime=args.runtime)
        last_gap[(reason, user)] = now

    delay = 1
    while True:
        if load_policy(required=True).expired(args.host,time.time()):
            return
        try:
            with open(args.config, encoding='utf-8') as source:
                config = json.load(source)
            ledger.register_users(configured_users(config), host=args.host, runtime=args.runtime)
            adapter = NativeBatchAdapter(args.host, config, args.runtime, args.exit_observation)
            last_config = int(time.time())
            last_prune = 0
            with grpc.insecure_channel(args.address, options=[
                    ('grpc.keepalive_time_ms', 10000), ('grpc.keepalive_timeout_ms', 5000),
                    ('grpc.keepalive_permit_without_calls', 1)]) as channel:
                stub = rpc.StartedServiceStub(channel)
                if stub.GetStartedAt(empty_pb2.Empty(), metadata=metadata, timeout=10).startedAt <= 0:
                    raise RuntimeError('native process epoch is unavailable')
                stream = stub.SubscribeConnections(pb.SubscribeConnectionsRequest(interval=0),
                    metadata=metadata, wait_for_ready=True)
                delay = 1
                for batch in stream:
                    now = int(time.time())
                    if load_policy(required=True).expired(args.host,now):
                        return
                    if now - last_prune >= 300:
                        ledger.prune(now=now, limit=5000)
                        last_prune = now
                    if now - last_config >= 60:
                        last_config = now
                        try:
                            with open(args.config, encoding='utf-8') as source:
                                config = json.load(source)
                            ledger.register_users(configured_users(config), host=args.host,
                                                  runtime=args.runtime, observed_at=now)
                            adapter.routes = routes_for_config(config)
                        except (OSError, ValueError, TypeError):
                            gap('native_cohort_unavailable', observed_at=now)
                    observations, gaps = adapter.apply(batch)
                    result = ledger.record(observations, observed_at=now)
                    for reason, user in gaps:
                        gap(reason, user, now)
                    if result.get('rejected'):
                        gap('daily_observation_rejected', observed_at=now)
        except Exception as error:
            # Do not print endpoints, usernames, protocol payloads or secrets.
            try:
                gap('grpc_stream_unavailable')
            except Exception:
                pass
            print('daily native reconnect: ' + type(error).__name__, file=sys.stderr, flush=True)
            time.sleep(delay)
            delay = min(delay * 2, 30)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--runtime', default='dedicated')
    parser.add_argument('--address', required=True)
    parser.add_argument('--config', required=True)
    parser.add_argument('--secret-file', required=True)
    parser.add_argument('--db', default='/var/lib/user-daily-traffic/daily.db')
    parser.add_argument('--protobuf-dir', default='/opt/static-connection-events')
    parser.add_argument('--exit-observation', action='store_true')
    follow(parser.parse_args())


if __name__ == '__main__':
    main()
