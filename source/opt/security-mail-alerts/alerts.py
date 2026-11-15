#!/usr/bin/env python3
"""Persistent alerts for explicitly classified proxy-user violations.

The queue never changes proxy rules, users, or traffic databases. Source reads
are read-only. SMTP credentials remain in a root-only configuration file.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import ipaddress
import json
import math
import os
import re
import secrets
import shlex
import signal
import smtplib
import socket
import sqlite3
import ssl
import stat
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import format_datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

RECIPIENT = "titan@titanyung.top"
TZ = timezone(timedelta(hours=8), "Asia/Singapore")
DEFAULT_CONFIG = "/etc/security-mail-alerts.json"
DEFAULT_DB = "/var/lib/security-mail-alerts/alerts.db"
DEFAULT_KINDS = ("bt-block",)
MAX_BATCH = 1000


def safe_error(error):
    code = getattr(error, "smtp_code", None) or getattr(error, "code", None)
    label = type(error).__name__ + ("(" + str(code) + ")" if isinstance(code, int) else "")
    if isinstance(error, ValueError) and re.fullmatch(r"[a-z_]{1,100}", str(error)):
        label += ":" + str(error)
    return label


def private_json(path):
    info = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("configuration_not_regular_file")
    if os.name == "posix" and (info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077):
        raise ValueError("configuration_requires_root_0600")
    with open(path, "r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError("configuration_not_object")
    if value.get("recipient", RECIPIENT) != RECIPIENT:
        raise ValueError("recipient_is_fixed")
    sources = value.get("sources", [])
    if not isinstance(sources, list) or len(sources) > 16:
        raise ValueError("sources_configuration_invalid")
    ids = set()
    for source in sources:
        if not isinstance(source, dict) or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,80}", str(source.get("id", ""))):
            raise ValueError("source_id_invalid")
        if source["id"] in ids:
            raise ValueError("source_id_duplicate")
        ids.add(source["id"])
        kind = source.get("type")
        if kind not in ("sqlite", "https", "ssh"):
            raise ValueError("source_configuration_invalid")
        if kind in ("sqlite", "https") and not isinstance(source.get("path" if kind == "sqlite" else "url"), str):
            raise ValueError("source_configuration_invalid")
        if kind == "ssh":
            ssh_command(source, None, 0)
        interval = source.get("poll_seconds", 1 if kind == "sqlite" else 5)
        if type(interval) not in (int, float) or not math.isfinite(interval) or not 1 <= interval <= 60:
            raise ValueError("source_poll_interval_invalid")
    kinds = value.get("violation_kinds", list(DEFAULT_KINDS))
    if not isinstance(kinds, list) or any(not isinstance(kind, str) or not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,80}", kind) for kind in kinds):
        raise ValueError("violation_kinds_invalid")
    return value


def validate_smtp(raw):
    """Return (usable configuration, safe error). Missing config queues mail."""
    if not raw:
        return None, "smtp_not_configured"
    if not isinstance(raw, dict):
        return None, "smtp_configuration_invalid"
    required = ("host", "port", "mode", "sender")
    if any(not raw.get(key) for key in required):
        return None, "smtp_configuration_incomplete"
    host, mode, sender = raw["host"], raw["mode"], raw["sender"]
    if not isinstance(host, str) or any(c in host for c in "\r\n/\\"):
        return None, "smtp_host_invalid"
    if type(raw["port"]) is not int or not 1 <= raw["port"] <= 65535:
        return None, "smtp_port_invalid"
    if not isinstance(sender, str) or not re.fullmatch(r"[^\s<>@]+@[^\s<>@]+", sender):
        return None, "smtp_sender_invalid"
    if mode not in ("ssl", "starttls", "local_test"):
        return None, "smtp_tls_mode_required"
    if mode == "local_test":
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if not loopback or raw.get("username") or raw.get("password"):
            return None, "plaintext_only_allowed_for_local_test_without_credentials"
    elif not isinstance(raw.get("username"), str) or not raw["username"] or not isinstance(raw.get("password"), str) or not raw["password"]:
        return None, "smtp_credentials_incomplete"
    return dict(raw), None


def sanitized_detail(value):
    text = str(value or "")[:4096]
    text = re.sub(r"/(?:sub|merge)/[^\s/?]+(?:\?[^\s]*)?", "/sub/[redacted]", text)
    text = re.sub(r"(https?://[^\s?#]+)[?#][^\s]*", r"\1?[redacted]", text)
    return "".join(c for c in text if c in "\n\t" or ord(c) >= 32)[:2000]


def normalize_event(raw):
    if not isinstance(raw, dict) or type(raw.get("id")) is not int or raw["id"] <= 0:
        raise ValueError("source_event_id_required")
    if type(raw.get("ts")) not in (int, float) or raw["ts"] < 0:
        raise ValueError("source_event_timestamp_required")
    user = str(raw.get("user") or "").strip()
    if len(user) > 256 or any(ord(c) < 32 for c in user):
        raise ValueError("source_event_user_invalid")
    kind = str(raw.get("kind") or "")
    if not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,80}", kind):
        raise ValueError("source_event_kind_invalid")
    return {"id": raw["id"], "ts": int(raw["ts"]), "user": user,
            "source": sanitized_detail(raw.get("source")), "kind": kind,
            "detail": sanitized_detail(raw.get("detail"))}


class Store:
    def __init__(self, path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.connect() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS source_cursors(
              source_id TEXT PRIMARY KEY, cursor INTEGER NOT NULL,
              initialized_at INTEGER NOT NULL, last_polled_at INTEGER,
              last_error TEXT, high_water INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS events(
              event_key TEXT PRIMARY KEY,source_id TEXT NOT NULL,
              source_event_id INTEGER NOT NULL,ts INTEGER NOT NULL,
              user TEXT NOT NULL,source TEXT NOT NULL,kind TEXT NOT NULL,
              detail TEXT NOT NULL,eligible INTEGER NOT NULL,ignored_reason TEXT,
              UNIQUE(source_id,source_event_id));
            CREATE TABLE IF NOT EXISTS outbox(
              event_key TEXT PRIMARY KEY REFERENCES events(event_key),
              state TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,
              created_at INTEGER NOT NULL,next_attempt_at INTEGER NOT NULL,
              sent_at INTEGER,last_error TEXT,claimed_at INTEGER);
            CREATE INDEX IF NOT EXISTS outbox_due ON outbox(state,next_attempt_at);
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT);
            """)
        if os.name == "posix":
            os.chmod(self.path, 0o600)

    @contextlib.contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def recover_sending(self):
        # Only the daemon's locked startup invokes crash recovery. Read-only
        # callers constructing a Store must never reset another live claim.
        with self.connect() as db:
            db.execute("UPDATE outbox SET state='retry',claimed_at=NULL WHERE state='sending'")

    def cursor(self, source_id):
        with self.connect() as db:
            row = db.execute("SELECT cursor FROM source_cursors WHERE source_id=?", (source_id,)).fetchone()
        return None if row is None else row[0]

    def initialize_source(self, source_id, high_water, now):
        with self.connect() as db:
            db.execute("INSERT OR IGNORE INTO source_cursors VALUES(?,?,?,?,?,?)",
                       (source_id, high_water, now, now, None, high_water))

    def source_error(self, source_id, error, now):
        with self.connect() as db:
            db.execute("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                       ("source_error:" + source_id, json.dumps({"source_id": source_id, "at": now, "error": safe_error(error)})))
            db.execute("UPDATE source_cursors SET last_error=?,last_polled_at=? WHERE source_id=?",
                       (safe_error(error), now, source_id))

    def ingest(self, source_id, records, high_water, allowed_kinds, configured, now):
        normalized = [normalize_event(row) for row in records]
        ids = [row["id"] for row in normalized]
        if ids != sorted(set(ids)) or (ids and ids[-1] > high_water):
            raise ValueError("source_event_order_invalid")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT cursor FROM source_cursors WHERE source_id=?", (source_id,)).fetchone()
            if row is None:
                raise ValueError("source_baseline_required")
            cursor = row[0]
            if high_water < cursor:
                raise ValueError("source_cursor_regressed")
            for event in normalized:
                if event["id"] <= cursor:
                    continue
                unattributed = not event["user"] or event["user"].lower() in ("unknown", "n/a", "none", "-")
                reason = "unattributed_user" if unattributed else "kind_not_confirmed_violation" if event["kind"] not in allowed_kinds else None
                key = hashlib.sha256((source_id + "\0" + str(event["id"])).encode()).hexdigest()
                db.execute("INSERT OR IGNORE INTO events VALUES(?,?,?,?,?,?,?,?,?,?)",
                           (key, source_id, event["id"], event["ts"], event["user"], event["source"],
                            event["kind"], event["detail"], int(reason is None), reason))
                if reason is None:
                    db.execute("INSERT OR IGNORE INTO outbox(event_key,state,created_at,next_attempt_at) VALUES(?,?,?,?)",
                               (key, "queued" if configured else "pending_config", now, now))
                cursor = event["id"]
            db.execute("UPDATE source_cursors SET cursor=?,high_water=?,last_polled_at=?,last_error=NULL WHERE source_id=?",
                       (cursor, high_water, now, source_id))
            db.execute("DELETE FROM meta WHERE key=?", ("source_error:" + source_id,))

    def claim(self, configured, now):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if not configured:
                db.execute("UPDATE outbox SET state='pending_config' WHERE state IN ('queued','retry')")
                return None
            db.execute("UPDATE outbox SET state='queued',next_attempt_at=? WHERE state='pending_config'", (now,))
            row = db.execute("SELECT e.*,o.attempts FROM outbox o JOIN events e USING(event_key) "
                             "WHERE o.state IN ('queued','retry') AND o.next_attempt_at<=? "
                             "ORDER BY o.created_at,e.source_event_id LIMIT 1", (now,)).fetchone()
            if row is None:
                return None
            db.execute("UPDATE outbox SET state='sending',attempts=attempts+1,claimed_at=? WHERE event_key=?", (now, row["event_key"]))
            return dict(row)

    def sent(self, key, now):
        with self.connect() as db:
            db.execute("UPDATE outbox SET state='sent',sent_at=?,last_error=NULL,claimed_at=NULL WHERE event_key=?", (now, key))

    def failed(self, key, error, attempts, now):
        delay = min(900, 5 * 2 ** min(attempts, 8))
        with self.connect() as db:
            db.execute("UPDATE outbox SET state='retry',next_attempt_at=?,last_error=?,claimed_at=NULL WHERE event_key=?",
                       (now + delay, safe_error(error), key))

    def status(self, smtp_ready=False, config_error=None, configured_sources=(), kinds=DEFAULT_KINDS):
        with self.connect() as db:
            counts = dict(db.execute("SELECT state,COUNT(*) FROM outbox GROUP BY state"))
            sources = [dict(row) for row in db.execute("SELECT * FROM source_cursors ORDER BY source_id")]
            uninitialized = [json.loads(row[0]) for row in db.execute("SELECT value FROM meta WHERE key LIKE 'source_error:%'")]
            ignored = dict(db.execute("SELECT ignored_reason,COUNT(*) FROM events WHERE eligible=0 GROUP BY ignored_reason"))
            last_sent = db.execute("SELECT MAX(sent_at) FROM outbox").fetchone()[0]
            evidence = {row[0].split(':', 1)[1]: json.loads(row[1]) for row in db.execute(
                "SELECT key,value FROM meta WHERE key LIKE 'source_coverage:%'")}
        counts = {state: counts.get(state, 0) for state in ("pending_config", "queued", "retry", "sending", "sent")}
        initialized = {source["source_id"] for source in sources}
        coverage = {"confirmed_kinds": list(kinds), "subscription_risk_is_violation": False,
                    "sources": [{"id": source["id"], "type": source["type"],
                                 "poll_seconds": source.get("poll_seconds", 1 if source["type"] == "sqlite" else 5),
                                 "baseline_set": source["id"] in initialized,
                                 "coverage": public_coverage(evidence.get(source['id'], {}), int(time.time()))}
                                for source in configured_sources]}
        for item, source in zip(coverage['sources'], configured_sources):
            if source.get('evidence_gap'):
                item['error'] = 'evidence_verification_pending'
                for runtime in item['coverage']['sources']:
                    runtime['observable'] = False
                    runtime['last_error'] = 'evidence_verification_pending'
        healthy = bool(configured_sources) and all(
            item['baseline_set'] and item['coverage']['sources'] and all(x['observable'] for x in item['coverage']['sources'])
            for item in coverage['sources']) and not uninitialized
        state = "pending_config" if not smtp_ready else "degraded" if not healthy or counts["retry"] else "ready"
        return {"recipient": RECIPIENT, "smtp_ready": smtp_ready, "configured": smtp_ready,
                "state": state, "monitoring": bool(configured_sources), "monitoring_ready": healthy, "configuration_error": config_error,
                "queue": counts, "counts": counts, "last_sent_at": last_sent, "sources": sources,
                "source_errors": uninitialized, "ignored_events": ignored, "coverage": coverage}

    def cache_coverage(self, source_id, coverage):
        with self.connect() as db:
            db.execute("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                       ('source_coverage:' + source_id, json.dumps(coverage, ensure_ascii=False)))

    def recent_events(self, limit=100):
        with self.connect() as db:
            return [dict(row) for row in db.execute(
                "SELECT e.source_id,e.source_event_id,e.ts,e.user,e.source,e.kind,e.detail,"
                "e.eligible,e.ignored_reason,o.state,o.attempts,o.sent_at,o.last_error "
                "FROM events e LEFT JOIN outbox o USING(event_key) ORDER BY e.ts DESC LIMIT ?", (min(max(limit, 1), 100),))]

    def enqueue_test(self, now=None):
        now = int(time.time()) if now is None else int(now)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            last = db.execute("SELECT MAX(ts) FROM events WHERE kind='notification-test'").fetchone()[0]
            if last is not None and now - last < 30:
                raise ValueError("test_recently_requested")
            event_id = time.time_ns()
            key = hashlib.sha256(("manual-test:" + secrets.token_hex(20)).encode()).hexdigest()
            db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?)",
                       (key, "manual-test", event_id, now, "admin", "admin-console",
                        "notification-test", "管理员主动发送的通道测试通知", 1, None))
            db.execute("INSERT INTO outbox(event_key,state,created_at,next_attempt_at) VALUES(?,?,?,?)",
                       (key, "queued", now, now))
        return key


def source_sqlite(source, cursor, limit):
    path = str(Path(source["path"]).resolve())
    with contextlib.closing(sqlite3.connect("file:" + urllib.parse.quote(path, safe="/:") + "?mode=ro", uri=True, timeout=3)) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        high = db.execute("SELECT COALESCE(MAX(id),0) FROM security_events").fetchone()[0]
        try:
            sequence = db.execute("SELECT seq FROM sqlite_sequence WHERE name='security_events'").fetchone()
            high = max(high, sequence[0] if sequence else 0)
        except sqlite3.OperationalError:
            pass
        rows = [] if cursor is None else [dict(row) for row in db.execute(
            "SELECT id,ts,user,source,kind,detail FROM security_events WHERE id>? ORDER BY id LIMIT ?", (cursor, limit))]
    return int(high), rows


def env_token(path, key):
    info = os.stat(path, follow_symlinks=False)
    if os.name == "posix" and (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077):
        raise ValueError("source_token_file_not_private")
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        if name.strip() == key:
            values = shlex.split(value, comments=False)
            if len(values) != 1 or not values[0]:
                raise ValueError("source_token_invalid")
            return values[0]
    raise ValueError("source_token_missing")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def source_https(source, cursor, limit):
    parsed = urllib.parse.urlsplit(source["url"])
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("source_https_url_required")
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if any(key in ("after_id", "limit") for key, _ in query):
        raise ValueError("source_cursor_query_reserved")
    query.extend((("after_id", str(cursor or 0)), ("limit", str(0 if cursor is None else limit))))
    url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query), ""))
    headers = {"Accept": "application/json", "User-Agent": "Titanyung-Security-Alerts/1"}
    if source.get("token_env_file"):
        headers["X-Traffic-Token"] = env_token(source["token_env_file"], source.get("token_env_key", "AGGREGATE_TOKEN"))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                         urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    with opener.open(urllib.request.Request(url, headers=headers), timeout=5) as response:
        if response.status != 200:
            raise ValueError("source_http_status_invalid")
        raw = response.read(2_000_001)
    if len(raw) > 2_000_000:
        raise ValueError("source_response_too_large")
    payload = json.loads(raw)
    if not isinstance(payload, dict) or type(payload.get("max_id")) is not int or not isinstance(payload.get("events"), list):
        raise ValueError("source_incremental_schema_required")
    if len(payload["events"]) > MAX_BATCH:
        raise ValueError("source_batch_too_large")
    if cursor is None and payload["events"]:
        raise ValueError("source_baseline_must_not_return_history")
    return payload["max_id"], payload["events"]


def ssh_command(source, cursor, limit):
    host = source.get('host', '')
    port = source.get('port', 22)
    identity, known = source.get('identity'), source.get('known_hosts')
    if (not isinstance(host, str) or not re.fullmatch(r'[A-Za-z0-9_.@:-]{1,250}', host)
            or host.startswith('-') or type(port) is not int or not 1 <= port <= 65535
            or any(not isinstance(p, str) or not p.startswith('/') or any(ord(c) < 32 for c in p)
                   for p in (identity, known))):
        raise ValueError('ssh_source_configuration_invalid')
    if cursor is not None and (type(cursor) is not int or cursor < 0):
        raise ValueError('source_cursor_invalid')
    if type(limit) is not int or not 0 <= limit <= MAX_BATCH:
        raise ValueError('source_limit_invalid')
    return ['ssh', '-F', '/dev/null', '-T', '-p', str(port), '-i', identity,
            '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=8',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + known,
            '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes', host,
            'bt-events {} {}'.format(cursor or 0, 0 if cursor is None else limit)]


def bounded_process(command, timeout=10, maximum=2_000_000):
    """Bound transport memory and duration; never interpret remote output as code."""
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    finished, output, failure = threading.Event(), [], []
    def read():
        try:
            raw = process.stdout.read(maximum + 1)
            output.append(raw)
            if len(raw) > maximum:
                process.kill()
        except Exception as error:
            failure.append(error)
        finally:
            finished.set()
    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    try:
        if not finished.wait(timeout):
            raise ValueError('source_transport_timeout')
        process.wait(timeout=2)
        if failure or not output:
            raise ValueError('source_transport_failed')
        if len(output[0]) > maximum:
            raise ValueError('source_response_too_large')
        if process.returncode != 0:
            raise ValueError('source_transport_failed')
        return output[0]
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()
        reader.join(timeout=1)


def public_coverage(raw, now):
    """Allowlisted health only; exclude private paths, commands and credentials."""
    sources = []
    rows = raw.get('sources', []) if isinstance(raw, dict) else []
    for row in rows[:16] if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        policy = row.get('policy') or {}
        if not isinstance(policy, dict):
            policy = {}
        rules = policy.get('confirmed_rules', [])
        if not isinstance(rules, list):
            rules = []
        verified = row.get('policy_verified_at')
        fresh = type(verified) in (int, float) and 0 <= now - verified < 15
        sources.append({'source_id': str(row.get('source_id', ''))[:100],
            'last_seen': row.get('last_seen'), 'last_error': 'source_unavailable' if row.get('last_error') else None,
            'policy_verified_at': verified, 'observable': bool(policy.get('observable')) and fresh and not row.get('last_error'),
            'policy': {'observable': bool(policy.get('observable')), 'log_level': str(policy.get('log_level', ''))[:20],
                       'confirmed_rules': [str(x)[:200] for x in rules[:16]],
                       'evidence': str(policy.get('evidence', ''))[:250]}})
    return {'sources': sources, 'confirmed_kinds': ['bt-block'], 'subscription_risk_is_violation': False}


def sqlite_coverage(path):
    uri = 'file:' + urllib.parse.quote(str(Path(path).resolve()), safe='/:') + '?mode=ro'
    with contextlib.closing(sqlite3.connect(uri, uri=True, timeout=3)) as db:
        db.row_factory = sqlite3.Row
        result = []
        for row in db.execute('SELECT source_id,last_seen,last_error,policy_verified_at,policy_json FROM journal_state LIMIT 16'):
            row = dict(row)
            row['policy'] = json.loads(row.pop('policy_json') or '{}')
            result.append(row)
    return {'sources': result}


def source_ssh(source, cursor, limit):
    payload = json.loads(bounded_process(ssh_command(source, cursor, limit)))
    if (not isinstance(payload, dict) or type(payload.get('max_id')) is not int or payload['max_id'] < 0
            or not isinstance(payload.get('events'), list) or len(payload['events']) > MAX_BATCH):
        raise ValueError('source_incremental_schema_required')
    if cursor is None and payload['events']:
        raise ValueError('source_baseline_must_not_return_history')
    return payload['max_id'], payload['events'], payload.get('coverage', {})


def poll_once(store, source, kinds, smtp_ready, now=None):
    now = int(time.time()) if now is None else now
    source_id = source["id"]
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,80}", source_id):
        raise ValueError("source_id_invalid")
    cursor = store.cursor(source_id)
    reader = {'sqlite': source_sqlite, 'https': source_https, 'ssh': source_ssh}.get(source['type'])
    if reader is None:
        raise ValueError("source_type_invalid")
    response = reader(source, cursor, MAX_BATCH)
    high, rows = response[:2]
    if len(response) == 3:
        store.cache_coverage(source_id, public_coverage(response[2], now))
    elif source.get('coverage_db'):
        store.cache_coverage(source_id, public_coverage(sqlite_coverage(source['coverage_db']), now))
    if cursor is None:
        store.initialize_source(source_id, high, now)
        return
    if type(high) is not int or high < cursor:
        raise ValueError("source_cursor_regressed")
    if not rows and high > cursor:
        raise ValueError("source_incremental_events_missing")
    store.ingest(source_id, rows, high, kinds, smtp_ready, now)


def make_message(event, smtp):
    message = EmailMessage()
    message["From"] = smtp["sender"]
    message["To"] = RECIPIENT
    testing = event["kind"] == "notification-test"
    message["Subject"] = "[测试通知] 违规邮件告警通道" if testing else "[用户违规使用] " + event["kind"] + " · " + event["user"]
    message["Date"] = format_datetime(datetime.fromtimestamp(event["ts"], TZ))
    message["Message-ID"] = "<violation-" + event["event_key"] + "@" + smtp["sender"].split("@", 1)[1] + ">"
    message["X-Titanyung-Event-Key"] = event["event_key"]
    message.set_content(("这是管理员在安全中心主动请求的通道测试通知。\n\n" if testing else "已检测到现有规则认定的用户违规事件。\n\n") +
        "用户：{user}\n服务器：{source_id}\n事件：{kind}\n时间（新加坡）：{when}\n"
        "来源：{source}\n详情：{detail}\n\n事件编号：{event_key}\n"
        "此邮件不包含订阅链接、密码或访问令牌。\n".format(
            when=datetime.fromtimestamp(event["ts"], TZ).strftime("%Y-%m-%d %H:%M:%S"), **event))
    return message


def smtp_send(smtp, message):
    timeout = min(max(float(smtp.get("timeout_seconds", 15)), 1), 30)
    context = ssl.create_default_context()
    if smtp["mode"] == "ssl":
        client = smtplib.SMTP_SSL(smtp["host"], smtp["port"], timeout=timeout, context=context)
    else:
        client = smtplib.SMTP(smtp["host"], smtp["port"], timeout=timeout)
    with client:
        client.ehlo()
        if smtp["mode"] == "starttls":
            client.starttls(context=context)
            client.ehlo()
        if smtp.get("username"):
            client.login(smtp["username"], smtp["password"])
        refused = client.send_message(message, from_addr=smtp["sender"], to_addrs=[RECIPIENT])
        if refused:
            raise smtplib.SMTPRecipientsRefused(refused)


def deliver_one(store, smtp_raw, now=None, send=smtp_send):
    now = int(time.time()) if now is None else now
    smtp, error = validate_smtp(smtp_raw)
    event = store.claim(smtp is not None, now)
    if event is None:
        return False
    try:
        send(smtp, make_message(event, smtp))
    except Exception as exc:
        store.failed(event["event_key"], exc, event["attempts"], now)
    else:
        store.sent(event["event_key"], now)
    return True


def run(config_path, db_path, port):
    config = private_json(config_path)
    store = Store(db_path)
    lock = None
    if os.name == "posix":
        import fcntl
        lock = open(db_path + ".lock", "a", encoding="ascii")
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    store.recover_sending()
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())

    def current_config():
        try:
            value = private_json(config_path)
            smtp, error = validate_smtp(value.get("smtp"))
            return value, smtp, error
        except Exception as exc:
            return {}, None, safe_error(exc)

    def collector(source):
        interval = max(1, float(source.get("poll_seconds", 1 if source["type"] == "sqlite" else 5)))
        while not stop.is_set():
            cfg, smtp, _ = current_config()
            try:
                poll_once(store, source, frozenset(cfg.get("violation_kinds", DEFAULT_KINDS)), smtp is not None)
            except Exception as exc:
                store.source_error(source["id"], exc, int(time.time()))
            stop.wait(interval)

    def mailer():
        while not stop.is_set():
            cfg, _, _ = current_config()
            if not deliver_one(store, cfg.get("smtp")):
                stop.wait(1)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            return

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path
            cfg, smtp, error = current_config()
            if path == "/api/status":
                payload = store.status(smtp is not None, error, cfg.get("sources", []), cfg.get("violation_kinds", DEFAULT_KINDS))
            elif path == "/api/events":
                payload = {"events": store.recent_events()}
            elif path == "/api/health":
                payload = {"ok": True, "recipient": RECIPIENT}
            else:
                self.send_error(404)
                return
            raw = json.dumps(payload, ensure_ascii=False).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    for source in config.get("sources", []):
        threading.Thread(target=collector, args=(source,), daemon=True).start()
    threading.Thread(target=mailer, daemon=True).start()
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.timeout = 1
    try:
        while not stop.is_set():
            server.handle_request()
    finally:
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    parser.add_argument("--db", default=DEFAULT_DB)
    parser.add_argument("--port", type=int, default=18112)
    args = parser.parse_args()
    run(args.config, args.db, args.port)
