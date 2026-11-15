#!/usr/bin/env python3
"""Measure S-UI sessions via loopback Clash API and attribute from S-UI logs.

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


DB_PATH = os.environ.get("TRAFFIC_DB", "/var/lib/sg-traffic-dashboard/traffic.db")
SUI_DB = os.environ.get("SUI_DB", "/usr/local/s-ui/db/s-ui.db")
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
    r"\[[^]]+\]\[([^]]+)\]\s+inbound(?: packet)? connection to\s+(\S+)"
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
    db.commit()
    return db


def start_timestamp(value):
    if not isinstance(value, str):
        raise ValueError("invalid connection start")
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def session_config():
    db = sqlite3.connect("file:" + SUI_DB + "?mode=ro", uri=True, timeout=5)
    try:
        raw = db.execute("SELECT value FROM settings WHERE key='config'").fetchone()
        config = json.loads(raw[0]) if raw else {}
        clash = (config.get("experimental") or {}).get("clash_api") or {}
        controller = clash.get("external_controller")
        secret = clash.get("secret")
        if controller != "127.0.0.1:31990" or not secret:
            raise RuntimeError("audited loopback Clash API is not configured")
        routes = {}
        for tag, kind, raw_options in db.execute(
                "SELECT tag,type,options FROM outbounds"):
            options = json.loads(raw_options) if raw_options else {}
            if kind == "direct":
                routes[tag] = "direct"
            elif (kind == "socks" and isinstance(options, dict) and
                  str(options.get("server") or "").endswith(".kookeey.info")):
                routes[tag] = "kookeey"
            elif (kind == "socks" and isinstance(options, dict) and
                  options.get("server") == "202.52.109.23" and
                  str(options.get("server_port")) == "7058"):
                routes[tag] = "nexip_sg"
            elif (kind in ("socks", "http") and isinstance(options, dict) and
                  options.get("server") == "130.12.43.237" and
                  str(options.get("server_port")) == "1337"):
                routes[tag] = "ip2up"
            elif (kind in ("socks", "http") and isinstance(options, dict) and
                  options.get("server") == "178.93.182.237" and
                  str(options.get("server_port")) == "45224"):
                routes[tag] = "proxyhive"
            elif (kind == "anytls" and tag.startswith("hk-isp-") and
                  isinstance(options, dict) and
                  options.get("server") in ("216.23.117.226", "61.15.36.199") and
                  str(options.get("server_port")) == "2443"):
                routes[tag] = "bytevirt_hk_isp"
            elif (tag == "lazycat-sg-test" and kind == "shadowsocks" and
                  isinstance(options, dict) and
                  options.get("server") == "216.195.195.125" and
                  str(options.get("server_port")) == "39873"):
                routes[tag] = "lazycat"
            elif (tag == "lazycat-hkt" and kind == "shadowsocks" and
                  isinstance(options, dict) and
                  options.get("server") == "127.0.0.1" and
                  str(options.get("server_port")) == "31162"):
                routes[tag] = "lazycat_hkt"
            else:
                routes[tag] = "unknown"
        return "http://" + controller + "/connections", secret, routes
    finally:
        db.close()


def fetch_connections(url, secret):
    request = urllib.request.Request(url,
                                     headers={"Authorization": "Bearer " + secret})
    with urllib.request.urlopen(request, timeout=5) as response:
        payload = json.load(response)
    rows = payload.get("connections")
    if not isinstance(rows, list):
        raise ValueError("Clash API response shape changed")
    return rows


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
        session_ids.add("sui:" + str(item["id"]))
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
            message = str(entry.get("MESSAGE") or "")
            matched = ACCESS_RE.search(message)
            if not matched:
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
            user, destination = matched.groups()
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
            self.removed_fallbacks.add("log:" + event["id"])
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
                        self.removed_fallbacks.discard("log:" + event["id"])
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
    command = ["journalctl", "-u", "s-ui.service", "--follow", "--since",
               "-10 minutes", "--output=json", "--no-pager"]
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


def normalize(connections, journal, known_users, routes, now):
    rows = []
    for item in connections:
        if not isinstance(item, dict) or not item.get("id"):
            raise ValueError("Clash connection missing id")
        started = start_timestamp(item.get("start"))
        session_id = "sui:" + str(item["id"])
        if started < CUTOVER and session_id not in known_users:
            continue
        if started > now + 60 or started < now - RETENTION:
            raise ValueError("Clash connection start outside retention")
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
        "WHERE id LIKE 'sui:%' AND status='active'")]
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
            db.executemany("DELETE FROM access_records WHERE id=?",
                           ((record_id,) for record_id in removed))
            db.executemany(
                "INSERT OR IGNORE INTO access_records "
                "(id,user,source,destination,path,protocol,started,last_seen,ended,"
                "upload,download,status,route_class,traffic_known) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (("log:" + event["id"], event["user"], "", event["destination"],
                  PATH_LABEL, "", int(event["ts"]), now,
                  now, 0, 0, "closed", "unknown", 0)
                 for event in fallback),
            )
            if security:
                db.executemany("INSERT INTO security_events(ts,user,source,kind,detail) "
                               "VALUES(?,?,?,?,?)", security)
            cutoff = now - RETENTION
            prune_access_records(db, cutoff)
            db.execute("DELETE FROM security_events WHERE ts<?", (now - RETENTION,))
    except Exception:
        journal.restore_drain(fallback, removed, security)
        raise
    journal.confirm_claims()


def prune_access_records(db, cutoff):
    db.execute(
        "DELETE FROM access_records WHERE started<? AND ("
        "id NOT GLOB 'static:*' OR "
        "(status='closed' AND COALESCE(ended,last_seen,started)<?) OR "
        "(status='active' AND last_seen<?))",
        (cutoff, cutoff, cutoff))


def main():
    db = connect()
    daily = None
    if os.environ.get('DAILY_TRAFFIC_DB'):
        try:
            import sys
            sys.path.insert(0, os.environ.get('DAILY_TRAFFIC_LIB', '/opt/user-daily-traffic'))
            from daily_collector_hook import DailyCollectorHook
            daily = DailyCollectorHook.from_environment()
        except Exception as error:
            print('daily accounting init failed: ' + type(error).__name__, flush=True)
    journal = Journal()
    threading.Thread(target=follow_journal, args=(journal,), daemon=True).start()
    url, secret, routes = session_config()
    last_config = last_prune = 0
    while True:
        began = time.monotonic()
        now = int(time.time())
        try:
            if now - last_config >= 60:
                url, secret, routes = session_config()
                last_config = now
            connections = fetch_connections(url, secret)
            known_users = known_users_for_connections(db, connections)
            rows = normalize(connections, journal, known_users, routes, now)
            ingest(db, rows, journal, now)
            if daily is not None:
                daily.record_sui(connections, rows, now)
            if now - last_prune >= 60:
                journal.prune(now)
                last_prune = now
        except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
            if daily is not None:
                daily.gap('sui_poll_unavailable', now)
            journal.rollback_claims()
            print("session poll failed: " + type(exc).__name__, flush=True)
            time.sleep(3)
            continue
        time.sleep(max(0.1, POLL_SECONDS - (time.monotonic() - began)))


if __name__ == "__main__":
    main()
