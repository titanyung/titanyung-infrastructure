#!/usr/bin/env python3
"""Persist sing-box 1.14.3 API CLOSED connection events without polling loss.

Only audited relay-provider outbounds are stored. This candidate does not deploy or
modify sing-box, subscriptions, firewall rules, or the dashboard.
"""

import argparse
import os
from pathlib import Path
import sqlite3
import sys
import time

import grpc
from google.protobuf import empty_pb2

import connection_events_pb2 as pb
import connection_events_pb2_grpc as rpc


PROVIDERS = {"nexip": "NexIP SG", "ip2up": "ip2up.com",
             "proxyhive": "proxyhive.io", "zorocloud": "zorocloud", "bytevirt-taiwan": "ByteVirt-TW"}
try:
    import network_stats as _network_stats
    _network_manifest = _network_stats.read_optional_manifest
except ImportError:
    _network_manifest = None
    _network_stats = None
_network = _network_manifest() if _network_manifest else None
if _network:
    for _spec in _network['verified_routes']:
        if _spec['outbound_tag'] is not None:
            PROVIDERS[_spec['outbound_tag']] = _spec['host']
    if _network_stats.server_policy_enabled(_network):
        PROVIDERS['direct'] = 'DMIT'
EVENT_RETENTION_MS = (31 * 86400 - 3600) * 1000


def database(path):
    os.makedirs(os.path.dirname(os.path.abspath(path)), mode=0o700, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.executescript("""
      CREATE TABLE IF NOT EXISTS closed_static_connections (
        host TEXT NOT NULL,
        started_at_ms INTEGER NOT NULL,
        connection_id TEXT NOT NULL,
        created_at_ms INTEGER NOT NULL,
        closed_at_ms INTEGER NOT NULL,
        username TEXT NOT NULL,
        inbound TEXT NOT NULL,
        outbound TEXT NOT NULL,
        provider TEXT NOT NULL,
        destination TEXT NOT NULL,
        upload_bytes INTEGER NOT NULL,
        download_bytes INTEGER NOT NULL,
        last_seen_at_ms INTEGER NOT NULL,
        PRIMARY KEY (host, started_at_ms, connection_id)
      );
      CREATE INDEX IF NOT EXISTS closed_static_by_time
        ON closed_static_connections(host, closed_at_ms);
      CREATE INDEX IF NOT EXISTS closed_static_by_received
        ON closed_static_connections(host,last_seen_at_ms,started_at_ms,connection_id);
      CREATE TABLE IF NOT EXISTS stream_health (
        host TEXT PRIMARY KEY,
        started_at_ms INTEGER NOT NULL,
        last_batch_at_ms INTEGER NOT NULL,
        last_closed_at_ms INTEGER NOT NULL DEFAULT 0,
        reconnects INTEGER NOT NULL DEFAULT 0,
        replay_at_limit INTEGER NOT NULL DEFAULT 0,
        rejected_events INTEGER NOT NULL DEFAULT 0,
        last_error TEXT NOT NULL DEFAULT ''
      );
    """)
    return conn


def closed_row(host, started_at_ms, event, now_ms, replay=False):
    is_closed = event.type == pb.CONNECTION_EVENT_CLOSED
    is_replayed_close = (replay and event.type == pb.CONNECTION_EVENT_NEW and
                         event.HasField("connection") and event.connection.closedAt > 0)
    if not (is_closed or is_replayed_close):
        return None
    if not event.HasField("connection"):
        raise ValueError("closed event has no final connection payload")
    c = event.connection
    if c.outbound not in PROVIDERS:
        return None
    if not (event.id and c.user and c.createdAt > 0 and
            c.uplinkTotal >= 0 and c.downlinkTotal >= 0):
        raise ValueError("static closed event lacks identity or final counters")
    if globals().get('_network'):
        actual = _network_stats.actual_closed_route(_network, host, c.inbound, c.outbound, c.createdAt)
        if actual is not None and actual[1] != PROVIDERS[c.outbound]:
            raise ValueError('closed actual outbound provider differs')
    if c.id and c.id != event.id:
        raise ValueError("connection ID mismatch")
    closed_at = event.closedAt or c.closedAt
    if closed_at <= 0:
        raise ValueError("static closed event lacks close timestamp")
    # Pruned replay must not repopulate a 31-day access archive or totals.
    # The one-hour margin lets the retention job verify source/unified copies
    # before their existing 31-day physical cleanup can run.
    if closed_at < now_ms - EVENT_RETENTION_MS:
        return None
    return (host, started_at_ms, event.id, c.createdAt, closed_at,
            c.user, c.inbound, c.outbound, PROVIDERS[c.outbound], c.destination,
            c.uplinkTotal, c.downlinkTotal, now_ms)


def apply_batch(conn, host, started_at_ms, batch, now_ms=None):
    """Idempotently upsert final counters, including replayed CLOSED events."""
    now_ms = now_ms or int(time.time() * 1000)
    replay_closed = sum(e.type == pb.CONNECTION_EVENT_CLOSED or
                        (e.type == pb.CONNECTION_EVENT_NEW and
                         e.HasField("connection") and e.connection.closedAt > 0)
                        for e in batch.events)
    rejected = 0
    accepted = 0
    max_closed = 0
    with conn:
        for event in batch.events:
            try:
                row = closed_row(host, started_at_ms, event, now_ms, batch.reset)
            except ValueError:
                rejected += 1
                continue
            if row is None:
                continue
            conn.execute("""
              INSERT INTO closed_static_connections VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
              ON CONFLICT(host, started_at_ms, connection_id) DO UPDATE SET
                closed_at_ms=MAX(closed_static_connections.closed_at_ms, excluded.closed_at_ms),
                upload_bytes=MAX(closed_static_connections.upload_bytes, excluded.upload_bytes),
                download_bytes=MAX(closed_static_connections.download_bytes, excluded.download_bytes),
                last_seen_at_ms=excluded.last_seen_at_ms
              WHERE closed_static_connections.created_at_ms=excluded.created_at_ms
            """, row)
            accepted += 1
            max_closed = max(max_closed, row[4])
        conn.execute("""
          INSERT INTO stream_health(host,started_at_ms,last_batch_at_ms,
                                    last_closed_at_ms,replay_at_limit,rejected_events)
          VALUES (?,?,?,?,?,?)
          ON CONFLICT(host) DO UPDATE SET
            started_at_ms=excluded.started_at_ms,
            last_batch_at_ms=excluded.last_batch_at_ms,
            last_closed_at_ms=MAX(stream_health.last_closed_at_ms,excluded.last_closed_at_ms),
            replay_at_limit=stream_health.replay_at_limit+excluded.replay_at_limit,
            rejected_events=stream_health.rejected_events+excluded.rejected_events,
            last_error=''
        """, (host, started_at_ms, now_ms, max_closed,
              int(batch.reset and replay_closed >= 1000), rejected))
    return accepted, rejected


def record_reconnect(conn, host, error):
    with conn:
        conn.execute("""
          INSERT INTO stream_health(host,started_at_ms,last_batch_at_ms,reconnects,last_error)
          VALUES (?,0,0,1,?)
          ON CONFLICT(host) DO UPDATE SET reconnects=reconnects+1,
            last_error=excluded.last_error
        """, (host, error[:300]))


def load_secret(path):
    p = Path(path)
    info = p.stat()
    if not p.is_file() or info.st_mode & 0o077:
        raise ValueError("secret file must be a private regular file (0600)")
    secret = p.read_text(encoding="utf-8").strip()
    if not secret:
        raise ValueError("empty API secret")
    return secret


def follow(args):
    if not args.address.startswith("127.0.0.1:"):
        raise ValueError("API address must bind loopback IPv4")
    if not args.host or not all(c.isalnum() or c in "_-" for c in args.host):
        raise ValueError("invalid host label")
    secret = load_secret(args.secret_file)
    metadata = (("authorization", "Bearer " + secret),)
    conn = database(args.db)
    delay = 1
    while True:
        try:
            with grpc.insecure_channel(args.address, options=[
                ("grpc.keepalive_time_ms", 10000),
                ("grpc.keepalive_timeout_ms", 5000),
                ("grpc.keepalive_permit_without_calls", 1),
            ]) as channel:
                stub = rpc.StartedServiceStub(channel)
                # The process epoch is required for dedupe across server reloads.
                started = stub.GetStartedAt(empty_pb2.Empty(), metadata=metadata,
                                            timeout=10).startedAt
                if started <= 0:
                    raise RuntimeError("sing-box start epoch unavailable")
                stream = stub.SubscribeConnections(
                    pb.SubscribeConnectionsRequest(interval=0),
                    metadata=metadata, wait_for_ready=True)
                delay = 1
                for batch in stream:
                    accepted, rejected = apply_batch(conn, args.host, started, batch)
                    if rejected:
                        print(f"REJECTED_EVENTS={rejected} host={args.host}",
                              file=sys.stderr, flush=True)
                    if accepted:
                        print(f"CLOSED_STATIC={accepted} host={args.host}", flush=True)
        except (grpc.RpcError, OSError, RuntimeError, sqlite3.Error) as exc:
            record_reconnect(conn, args.host, type(exc).__name__)
            print(f"STREAM_RECONNECT host={args.host} reason={type(exc).__name__}",
                  file=sys.stderr, flush=True)
            time.sleep(delay)
            delay = min(delay * 2, 30)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="DMIT or BWH")
    parser.add_argument("--address", required=True, help="127.0.0.1:port")
    parser.add_argument("--secret-file", required=True)
    parser.add_argument("--db", required=True)
    args = parser.parse_args()
    follow(args)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
