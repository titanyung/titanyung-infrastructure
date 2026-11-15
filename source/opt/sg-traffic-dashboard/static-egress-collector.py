#!/usr/bin/env python3
"""Measure audited dedicated relay sessions via the loopback Clash API.

No new administrator token is needed. Ambiguous matches are never assigned to
a user; their journal events remain as explicitly unmeasured access records.
"""

import collections
import datetime
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import threading
import time
import urllib.request

import static_finalization

try:
    import network_stats as _network_stats
except ImportError:
    _network_stats = None


DB_PATH = os.environ.get("TRAFFIC_DB", "/var/lib/sg-traffic-dashboard/traffic.db")
EVENTS_DB = os.environ.get("TRAFFIC_CLOSED_EVENTS_DB",
                           "/var/lib/static-connection-events/events.db")
STATIC_HOST = "BWH" if "/bwh-traffic-dashboard/" in DB_PATH else "DMIT"
STAGE_CONFIG = os.environ["TRAFFIC_STAGE_CONFIG"]
STAGE_UNIT = os.environ["TRAFFIC_STAGE_UNIT"]
STAGE_CONTROLLER = os.environ["TRAFFIC_STAGE_CONTROLLER"]
STAGE_SECRET_FILE = os.environ["TRAFFIC_STAGE_SECRET_FILE"]
STAGE_INBOUND_TAGS = set(os.environ["TRAFFIC_STAGE_INBOUND_TAGS"].split(","))
PATH_LABEL = os.environ.get("TRAFFIC_PATH_LABEL") or (
    "BWHLA" if "/bwh-traffic-dashboard/" in DB_PATH else "DMIT-静态IP")
if "TRAFFIC_SESSION_START_TS" in os.environ:
    CUTOVER = int(os.environ["TRAFFIC_SESSION_START_TS"])
else:
    with open(os.path.join(os.path.dirname(DB_PATH), "session-cutover.txt"),
              encoding="ascii") as cutoff_source:
        CUTOVER = int(cutoff_source.read().strip())
POLL_SECONDS = 1.0
RETENTION = 31 * 86400
ACCESS_RE = re.compile(
    r"inbound/anytls\[([^]]+)\](?::\s*)?\[([^]]+)\]\s+"
    r"inbound(?: packet)? connection to\s+(\S+)"
)


def connect():
    db = sqlite3.connect(DB_PATH, timeout=20)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=20000")
    columns = {row[1] for row in db.execute("PRAGMA table_info(access_records)")}
    required = {"id", "user", "source", "destination", "path", "protocol",
                "started", "last_seen", "ended", "upload", "download", "status"}
    if not required <= columns:
        raise RuntimeError("access_records schema differs from audited dashboard")
    if "route_class" not in columns:
        db.execute("ALTER TABLE access_records ADD COLUMN route_class TEXT")
    if "traffic_known" not in columns:
        db.execute("ALTER TABLE access_records ADD COLUMN traffic_known INTEGER NOT NULL DEFAULT 0")
    db.execute(
        "CREATE TABLE IF NOT EXISTS static_egress_seen ("
        "id TEXT PRIMARY KEY, provider TEXT NOT NULL, "
        "upload INTEGER NOT NULL, download INTEGER NOT NULL)"
    )
    db.execute(
        "CREATE TABLE IF NOT EXISTS static_egress_totals ("
        "provider TEXT PRIMARY KEY, upload INTEGER NOT NULL, "
        "download INTEGER NOT NULL, updated INTEGER NOT NULL)"
    )
    static_finalization.ensure_schema(db)
    db.commit()
    return db


def start_timestamp(value):
    if not isinstance(value, str):
        raise ValueError("invalid connection start")
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def session_config():
    with open(STAGE_CONFIG, encoding="utf-8") as source:
        config = json.load(source)
    clash = (config.get("experimental") or {}).get("clash_api") or {}
    controller = clash.get("external_controller")
    secret = clash.get("secret")
    with open(STAGE_SECRET_FILE, encoding="ascii") as source:
        expected_secret = source.read().strip()
    if controller != STAGE_CONTROLLER or not secret or secret != expected_secret:
        raise RuntimeError("dedicated loopback Clash API configuration differs")
    manifest = _network_stats.read_optional_manifest() if _network_stats else None
    if manifest and STATIC_HOST == 'DMIT':
        routes = _network_stats.runtime_route_classes(config, manifest)
        return "http://" + controller + "/connections", secret, routes
    legacy = {
        "nexip": ("socks", "202.52.109.23", "7058", "nexip_sg"),
        "ip2up": ("socks", "130.12.43.237", "1337", "ip2up"),
    }
    zoro = {"zorocloud": ("shadowsocks", "218.208.109.3", "2448", "zorocloud"),
            "bytevirt-taiwan": ("shadowsocks", "2001:b030:112d:711:11b0::", "2448", "bytevirt_taiwan")}
    expected = zoro if STATIC_HOST == "DMIT" else legacy
    optional = {
        "proxyhive": ("http", "178.93.182.237", "45224", "proxyhive"),
    }
    optional.update(legacy if STATIC_HOST == "DMIT" else zoro)
    routes = {}
    for outbound in config.get("outbounds", []):
        tag = outbound.get("tag")
        if tag in expected or tag in optional:
            kind, server, port, route_class = {**expected, **optional}[tag]
            if (outbound.get("type"), outbound.get("server"),
                    str(outbound.get("server_port"))) != (kind, server, port):
                raise RuntimeError("dedicated static outbound differs: " + tag)
            routes[tag] = route_class
    if not set(expected) <= set(routes):
        raise RuntimeError("dedicated static outbounds missing")
    return "http://" + controller + "/connections", secret, routes


def fetch_connections(url, secret):
    request = urllib.request.Request(url,
                                     headers={"Authorization": "Bearer " + secret})
    with urllib.request.urlopen(request, timeout=5) as response:
        payload = json.load(response)
    rows = payload.get("connections")
    if not isinstance(rows, list):
        raise ValueError("Clash API response shape changed")
    return rows


def aggregate_sessions(db, connections, routes, now, finalized):
    """Count every observed static session, even when user matching is ambiguous."""
    increments = collections.defaultdict(lambda: [0, 0])
    with db:
        for item in connections:
            if not isinstance(item, dict) or not item.get("id"):
                raise ValueError("Clash connection missing id")
            outbound = next((tag for tag in item.get("chains") or [] if tag in routes), None)
            provider = routes.get(outbound)
            if not provider:
                continue
            session_id = "static:" + str(item["id"])
            if session_id in finalized:
                continue
            upload, download = int(item["upload"]), int(item["download"])
            if upload < 0 or download < 0:
                raise ValueError("negative Clash connection bytes")
            previous = db.execute(
                "SELECT provider,upload,download FROM static_egress_seen WHERE id=?",
                (session_id,),
            ).fetchone()
            if previous and (previous[0] != provider or upload < previous[1]
                             or download < previous[2]):
                raise ValueError("static session counter changed")
            before_up, before_down = (previous[1], previous[2]) if previous else (0, 0)
            if upload == before_up and download == before_down:
                continue
            db.execute(
                "INSERT INTO static_egress_seen(id,provider,upload,download) "
                "VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
                "upload=excluded.upload,download=excluded.download",
                (session_id, provider, upload, download),
            )
            increments[provider][0] += upload - before_up
            increments[provider][1] += download - before_down
        for provider, (up, down) in increments.items():
            db.execute(
                "INSERT INTO static_egress_totals(provider,upload,download,updated) "
                "VALUES(?,?,?,?) ON CONFLICT(provider) DO UPDATE SET "
                "upload=upload+excluded.upload,download=download+excluded.download,"
                "updated=excluded.updated",
                (provider, up, down, now),
            )


def known_users_for_connections(db, connections):
    """Read only users referenced by this poll's active S-UI sessions.

    ``normalize`` never consults historical IDs absent from ``connections``.
    Exact primary-key lookups preserve its user attribution while avoiding a
    full scan of the 31-day access history on every one-second poll. Keep
    batches below SQLite's older 999-variable limit.
    """
    session_ids = set()
    for item in connections:
        if not isinstance(item, dict) or not item.get("id"):
            raise ValueError("Clash connection missing id")
        session_ids.add("static:" + str(item["id"]))
    ordered = sorted(session_ids)
    known_users = {}
    for offset in range(0, len(ordered), 400):
        batch = ordered[offset:offset + 400]
        placeholders = ",".join("?" for _ in batch)
        for session_id, user in db.execute(
                "SELECT id,user FROM access_records WHERE id IN (" +
                placeholders + ")", batch):
            known_users[session_id] = user
    return known_users


class Journal:
    def __init__(self):
        self.lock = threading.Lock()
        self.pending_from = max(CUTOVER, int(time.time()) - 5)
        self.events = collections.defaultdict(list)
        self.pending = {}
        self.removed_fallbacks = set()
        self.security = []
        self.seen_cursors = {}
        self.claims = set()
        self.sequence = 0

    def add(self, line):
        try:
            entry = json.loads(line)
            cursor = entry.get("__CURSOR")
            message = entry.get("MESSAGE") or ""
            if isinstance(message, list):
                # journald serializes ANSI-colored sing-box output as a byte
                # array in JSON.  str(list) loses the searchable log text.
                message = bytes(message).decode("utf-8", errors="replace")
            elif not isinstance(message, str):
                return
            matched = ACCESS_RE.search(message)
            if not matched or matched.group(1) not in STAGE_INBOUND_TAGS:
                return
            timestamp = int(entry["__REALTIME_TIMESTAMP"]) / 1_000_000
        except (ValueError, TypeError, KeyError):
            return
        with self.lock:
            if cursor and cursor in self.seen_cursors:
                return
            if cursor:
                self.seen_cursors[cursor] = timestamp
            self.sequence += 1
            event_id = hashlib.sha256(
                (str(cursor or self.sequence) + ":" + str(timestamp)).encode()
            ).hexdigest()
            _, user, destination = matched.groups()
            event = {"id": event_id, "ts": timestamp, "user": user,
                     "destination": destination, "used": False}
            self.events[destination].append(event)
            if timestamp >= self.pending_from:
                self.pending[event_id] = event
                if "bittorrent" in message.lower():
                    self.security.append((int(timestamp), user, "", "bt-block",
                                          destination))

    def match(self, candidates, started):
        with self.lock:
            possible = {}
            for destination in candidates:
                for event in self.events.get(destination, ()):
                    if not event["used"] and abs(event["ts"] - started) <= 2:
                        possible[event["id"]] = event
            users = {event["user"] for event in possible.values()}
            if len(users) != 1:
                return None
            event = min(possible.values(),
                        key=lambda item: (abs(item["ts"] - started), item["id"]))
            event["used"] = True
            self.claims.add(event["id"])
            self.pending.pop(event["id"], None)
            self.removed_fallbacks.add("log:static:" + event["id"])
            return event["user"]

    def confirm_claims(self):
        with self.lock:
            self.claims.clear()

    def rollback_claims(self):
        with self.lock:
            for events in self.events.values():
                for event in events:
                    if event["id"] in self.claims:
                        event["used"] = False
                        if event["ts"] >= self.pending_from:
                            self.pending[event["id"]] = event
                        self.removed_fallbacks.discard("log:static:" + event["id"])
            self.claims.clear()

    def drain(self, now):
        with self.lock:
            fallback = [event for event in self.pending.values()
                        if event["ts"] <= now - 5 and not event["used"]]
            for event in fallback:
                self.pending.pop(event["id"], None)
            removed = self.removed_fallbacks
            security = self.security
            self.removed_fallbacks = set()
            self.security = []
            return fallback, removed, security

    def restore_drain(self, fallback, removed, security):
        with self.lock:
            for event in fallback:
                if not event["used"]:
                    self.pending[event["id"]] = event
            self.removed_fallbacks.update(removed)
            self.security.extend(security)

    def prune(self, now):
        cutoff = now - 600
        with self.lock:
            for destination in list(self.events):
                kept = [event for event in self.events[destination]
                        if event["ts"] >= cutoff]
                if kept:
                    self.events[destination] = kept
                else:
                    del self.events[destination]
            self.seen_cursors = {
                cursor: timestamp for cursor, timestamp in self.seen_cursors.items()
                if timestamp >= cutoff
            }


def follow_journal(journal):
    command = ["journalctl", "-u", STAGE_UNIT, "--follow", "--since",
               "-30 seconds", "--output=json", "--no-pager"]
    while True:
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, text=True)
            for line in process.stdout:
                journal.add(line)
            process.wait(timeout=5)
        except (OSError, subprocess.SubprocessError):
            pass
        time.sleep(2)


def normalize(connections, journal, known_users, routes, now, finalized):
    rows = []
    for item in connections:
        if not isinstance(item, dict) or not item.get("id"):
            raise ValueError("Clash connection missing id")
        started = start_timestamp(item.get("start"))
        session_id = "static:" + str(item["id"])
        if session_id in finalized:
            continue
        if started < CUTOVER and session_id not in known_users:
            continue
        if started > now + 60:
            raise ValueError("Clash connection start outside retention")
        # An already observed connection may remain active for more than 31
        # days.  Keep its exact ID; ignore an unknown ancient ID rather than
        # failing the entire polling batch.
        if started < now - RETENTION and session_id not in known_users:
            continue
        metadata = item.get("metadata") or {}
        if not isinstance(metadata, dict):
            raise ValueError("Clash metadata shape changed")
        port = str(metadata.get("destinationPort") or "")
        hosts = [str(metadata.get(name) or "") for name in ("host", "destinationIP")]
        candidates = {host + ":" + port for host in hosts if host and port}
        user = known_users.get(session_id) or journal.match(candidates, started)
        if not user:
            continue
        upload, download = int(item["upload"]), int(item["download"])
        if upload < 0 or download < 0:
            raise ValueError("negative Clash connection bytes")
        chains = item.get("chains") or []
        outbound = next((tag for tag in chains if tag in routes), None)
        route_class = routes.get(outbound, "unknown")
        if route_class == "unknown":
            continue
        destination = (hosts[0] or hosts[1]) + (":" + port if port else "")
        source = str(metadata.get("sourceIP") or "")
        source_port = str(metadata.get("sourcePort") or "")
        if source and source_port:
            source += ":" + source_port
        rows.append((session_id, user, source, destination, PATH_LABEL,
                     str(metadata.get("network") or ""), int(started), now, None,
                     upload, download, "active", route_class, 1))
    if len({row[0] for row in rows}) != len(rows):
        raise ValueError("duplicate Clash connection id")
    return rows


def ingest(db, rows, journal, now):
    current = {row[0] for row in rows}
    previous = [tuple(row) for row in db.execute(
        "SELECT id,last_seen,started FROM access_records "
        "WHERE id>=? AND id<? AND status='active'", ("static:", "static;"))]
    fallback, removed, security = journal.drain(now)
    try:
        with db:
            db.executemany(
                "INSERT INTO access_records "
                "(id,user,source,destination,path,protocol,started,last_seen,ended,"
                "upload,download,status,route_class,traffic_known) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET "
                "user=excluded.user,source=excluded.source,destination=excluded.destination,"
                "last_seen=excluded.last_seen,ended=NULL,upload=excluded.upload,"
                "download=excluded.download,status='active',"
                "route_class=excluded.route_class,traffic_known=1", rows)
            for session_id, last_seen, started in previous:
                if session_id not in current:
                    ended = max(started, now if now - last_seen <= 5 else last_seen)
                    db.execute("UPDATE access_records SET last_seen=?,ended=?,status='closed' "
                               "WHERE id=? AND status='active'", (ended, ended, session_id))
            db.executemany(
                "INSERT OR IGNORE INTO static_unmatched_journal "
                "(id,user,source,destination,path,protocol,started,last_seen,ended,"
                "upload,download,status,route_class,traffic_known,moved_at,reason) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (("log:static:" + event["id"], event["user"], "", event["destination"],
                  PATH_LABEL, "", int(event["ts"]), now,
                  now, 0, 0, "closed", "unknown", 0, now,
                  "journal has no shared CLOSED connection ID")
                 for event in fallback),
            )
            if security:
                db.executemany("INSERT INTO security_events(ts,user,source,kind,detail) "
                               "VALUES(?,?,?,?,?)", security)
            # The existing S-UI collector owns retention.  Running a second
            # whole-table prune every second would add needless I/O.
    except Exception:
        journal.restore_drain(fallback, removed, security)
        raise
    journal.confirm_claims()


def main():
    db = connect()
    journal = Journal()
    threading.Thread(target=follow_journal, args=(journal,), daemon=True).start()
    url, secret, routes = session_config()
    last_config = last_prune = last_reconcile = last_backfill = 0
    while True:
        began = time.monotonic()
        now = int(time.time())
        try:
            if now - last_config >= 60:
                url, secret, routes = session_config()
                last_config = now
            connections = fetch_connections(url, secret)
            finalized = static_finalization.finalized_ids(db, connections)
            aggregate_sessions(db, connections, routes, now, finalized)
            known_users = known_users_for_connections(db, connections)
            rows = normalize(connections, journal, known_users, routes, now, finalized)
            ingest(db, rows, journal, now)
            applied, replayed, expired, rejected = static_finalization.apply_pending(
                db, EVENTS_DB, STATIC_HOST, PATH_LABEL, now)
            if applied:
                print("CLOSED_FINALIZED=" + str(applied) + " host=" + STATIC_HOST,
                      flush=True)
            if rejected:
                print("CLOSED_FINAL_REJECTED=" + str(rejected) + " host=" + STATIC_HOST,
                      flush=True)
            if now - last_reconcile >= 30:
                moved = static_finalization.migrate_fallbacks(db, now)
                if moved:
                    print("STATIC_JOURNAL_DIAGNOSTIC_MOVED=" + str(moved) +
                          " host=" + STATIC_HOST, flush=True)
                last_reconcile = now
            if now - last_backfill >= 300:
                queued, scanned = static_finalization.backfill_retention_queue(
                    db, EVENTS_DB, STATIC_HOST, now=now)
                if queued:
                    print("STATIC_RETENTION_BACKFILLED=" + str(queued) +
                          " host=" + STATIC_HOST, flush=True)
                last_backfill = now
            if now - last_prune >= 60:
                journal.prune(now)
                last_prune = now
        except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
            journal.rollback_claims()
            print("session poll failed: " + type(exc).__name__, flush=True)
            time.sleep(3)
            continue
        time.sleep(max(0.1, POLL_SECONDS - (time.monotonic() - began)))


if __name__ == "__main__":
    main()
