#!/usr/bin/env python3
"""Read-only journal watcher for explicit BT-rule evidence at INFO level."""
import argparse
import contextlib
import hashlib
import hmac
import json
import os
import queue
import re
import signal
import sqlite3
import subprocess
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from bt_policy import TAG, read_policy

AUTH = re.compile(r'\[(?P<cid>\d+) [^\]]+\] inbound/[^\[]+\[(?P<inbound>[^\]]+)\]: \[(?P<user>[^\]\r\n]{1,256})\] inbound (?:packet )?connection to (?P<destination>[^\r\n]+)$')
HIT = re.compile(r'\[(?P<cid>\d+) [^\]]+\] outbound/socks\[' + re.escape(TAG) + r'\]: outbound (?:packet )?connection to [^\r\n]+$')
DEBUG_BT = re.compile(r'\[(?P<cid>\d+) [^\]]+\] router: match\[\d+\] protocol=bittorrent => reject(?:\(.*\))?$')
ANSI = re.compile(r'\x1b\[[0-9;]*m')


def journal_message(entry):
    """journalctl JSON encodes non-printable fields as arrays of UTF-8 bytes.

    In particular, sing-box's ANSI color escapes make MESSAGE a byte array even
    while its content is ordinary text. Never stringify that array as Python
    list notation: doing so silently prevents connection/user correlation.
    """
    raw = entry.get('MESSAGE', '')
    if isinstance(raw, list):
        if len(raw) > 65536 or any(type(value) is not int or not 0 <= value <= 255 for value in raw):
            raise ValueError('journal_message_bytes_invalid')
        raw = bytes(raw)
    if isinstance(raw, bytes):
        raw = raw.decode('utf-8', errors='replace')
    if not isinstance(raw, str) or len(raw) > 65536:
        raise ValueError('journal_message_invalid')
    return ANSI.sub('', raw)


class JournalStore:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.db() as db:
            db.executescript('''
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS security_events(id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,user TEXT NOT NULL,source TEXT NOT NULL,kind TEXT NOT NULL,detail TEXT NOT NULL,
                proof TEXT NOT NULL UNIQUE);
            CREATE TABLE IF NOT EXISTS journal_state(source_id TEXT PRIMARY KEY,cursor TEXT,last_seen INTEGER,
                last_error TEXT,policy_verified_at INTEGER,policy_json TEXT);
            CREATE TABLE IF NOT EXISTS connection_context(source_id TEXT,epoch TEXT,cid TEXT,user TEXT,inbound TEXT,
                destination TEXT,ts INTEGER,auth_cursor TEXT,PRIMARY KEY(source_id,epoch,cid));
            ''')
            if 'auth_cursor' not in {r[1] for r in db.execute('PRAGMA table_info(connection_context)')}:
                db.execute('ALTER TABLE connection_context ADD COLUMN auth_cursor TEXT')
        os.chmod(path, 0o600)

    @contextlib.contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def initialize(self, source, cursor):
        with self.db() as db:
            db.execute('INSERT OR IGNORE INTO journal_state(source_id,cursor,last_seen) VALUES(?,?,?)',
                       (source, cursor, int(time.time())))

    def state(self, source):
        with self.db() as db:
            row = db.execute('SELECT * FROM journal_state WHERE source_id=?', (source,)).fetchone()
            return dict(row) if row else None

    def health(self, source, policy=None, error=None):
        with self.db() as db:
            db.execute('INSERT INTO journal_state(source_id,last_error,policy_verified_at,policy_json) VALUES(?,?,?,?) ON CONFLICT(source_id) DO UPDATE SET last_error=excluded.last_error,policy_verified_at=excluded.policy_verified_at,policy_json=excluded.policy_json',
                       (source, error, int(time.time()), json.dumps(policy or {}, ensure_ascii=False)))

    def consume(self, source, entry, policy_valid=True, _db=None):
        cursor = entry.get('__CURSOR')
        if not isinstance(cursor, str) or not cursor:
            raise ValueError('journal_cursor_missing')
        message = journal_message(entry)
        stamp = int(int(entry.get('__REALTIME_TIMESTAMP', 0)) / 1_000_000)
        if stamp <= 0:
            raise ValueError('journal_timestamp_missing')
        epoch = ':'.join(str(entry.get(x, '')) for x in ('_BOOT_ID', '_SYSTEMD_INVOCATION_ID', '_PID'))
        if not entry.get('_BOOT_ID') or not entry.get('_PID'):
            raise ValueError('journal_process_identity_missing')
        auth, hit = AUTH.search(message), HIT.search(message)
        # DEBUG fallback is optional evidence only; INFO quarantine requires the
        # loaded exclusive BT-only policy to be verified on every reconnect.
        debug = DEBUG_BT.search(message)
        inserted = False
        with self.db() if _db is None else contextlib.nullcontext(_db) as db:
            previous = db.execute('SELECT cursor FROM journal_state WHERE source_id=?', (source,)).fetchone()
            if previous and previous[0] == cursor:
                return False
            if auth:
                db.execute('INSERT OR REPLACE INTO connection_context VALUES(?,?,?,?,?,?,?,?)',
                           (source, epoch, auth['cid'], auth['user'], auth['inbound'], auth['destination'], stamp, cursor))
            evidence = hit if policy_valid else None
            evidence = evidence or debug
            if evidence:
                context = db.execute('SELECT * FROM connection_context WHERE source_id=? AND epoch=? AND cid=?',
                                     (source, epoch, evidence['cid'])).fetchone()
                if context and 0 <= stamp - context['ts'] <= 900 and context['user'].lower() not in ('unknown', '未采集', '-', '?'):
                    proof = hashlib.sha256((source + '\0' + epoch + '\0' + evidence['cid'] + '\0' + str(context['auth_cursor'])).encode()).hexdigest()
                    detail = json.dumps({'rule': 'bittorrent', 'action': 'blocked', 'inbound': context['inbound'],
                                         'destination': context['destination'], 'evidence': 'bt-only-loopback-quarantine' if hit else 'explicit-bt-reject',
                                         'connection_id': evidence['cid']}, ensure_ascii=False)
                    inserted = bool(db.execute('INSERT OR IGNORE INTO security_events(ts,user,source,kind,detail,proof) VALUES(?,?,?,?,?,?)',
                                               (stamp, context['user'], source, 'bt-block', detail, proof)).rowcount)
            db.execute('INSERT INTO journal_state(source_id,cursor,last_seen) VALUES(?,?,?) ON CONFLICT(source_id) DO UPDATE SET cursor=excluded.cursor,last_seen=excluded.last_seen',
                       (source, cursor, int(time.time())))
        return inserted

    def consume_many(self, entries):
        with self.db() as db:
            count = sum(self.consume(source, entry, policy_valid=valid, _db=db)
                        for source, entry, valid in entries)
            last = getattr(self, '_cleaned_at', 0)
            now = int(time.time())
            if now - last > 60:
                db.execute('DELETE FROM connection_context WHERE ts<?', (now - 900,))
                self._cleaned_at = now
        return count

    def events(self, after_id=0, limit=1000):
        with self.db() as db:
            high = db.execute("SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='security_events'),0)").fetchone()[0]
            rows = [dict(r) for r in db.execute('SELECT id,ts,user,source,kind,detail FROM security_events WHERE id>? ORDER BY id LIMIT ?', (after_id, max(0, min(limit, 1000))))]
        return {'max_id': high if limit == 0 or not rows else rows[-1]['id'], 'events': rows}

    def status(self):
        with self.db() as db:
            rows = [dict(r) for r in db.execute('SELECT source_id,last_seen,last_error,policy_verified_at,policy_json FROM journal_state ORDER BY source_id')]
        for row in rows:
            row['policy'] = json.loads(row.pop('policy_json') or '{}')
            row['observable'] = bool(row['policy'].get('observable')) and not row['last_error']
        return {'sources': rows, 'confirmed_kinds': ['bt-block'], 'subscription_risk_is_violation': False}


def baseline(unit):
    result = subprocess.run(['journalctl', '-u', unit, '-n', '1', '-o', 'json', '--no-pager'], capture_output=True, text=True, timeout=10, check=True)
    rows = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
    # No tail must not use --since=now (race). systemd service has startup logs;
    # refuse initial enable if there is no exact current cursor to establish.
    if not rows:
        raise ValueError('journal_baseline_unavailable')
    return rows[-1]['__CURSOR']


def follow(store, source, stop, event_queue):
    source_id, unit = source['id'], source['unit']
    while not stop.is_set():
        process = None
        try:
            if not store.state(source_id) or not store.state(source_id)['cursor']:
                store.initialize(source_id, baseline(unit))
                if not store.state(source_id)['cursor']:
                    with store.db() as db:
                        db.execute('UPDATE journal_state SET cursor=? WHERE source_id=?', (baseline(unit), source_id))
            policy = read_policy(source)
            store.health(source_id, policy)
            policy_ready = threading.Event()
            policy_ready.set()
            cursor = store.state(source_id)['cursor']
            process = subprocess.Popen(['journalctl', '-u', unit, '--after-cursor=' + cursor, '-f', '-o', 'json', '--no-pager'],
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
            # Reader avoids tying stop/health checks to new log arrival.
            def read_lines(journal=process):
                try:
                    last_checkpoint = time.monotonic()
                    for line in journal.stdout:
                        if line.startswith('{'):
                            entry = json.loads(line)
                            message = journal_message(entry)
                            relevant = AUTH.search(message) or HIT.search(message) or DEBUG_BT.search(message)
                            # Most journal lines have no security context. Keep
                            # their latest resume point at <=2 checkpoints/sec.
                            if not relevant and time.monotonic() - last_checkpoint < .5:
                                continue
                            valid = policy_ready.is_set()
                            if HIT.search(message):
                                try:
                                    read_policy(source)
                                except Exception:
                                    valid = False
                                    policy_ready.clear()
                                    store.health(source_id, error='quarantine_policy_not_verified')
                            event_queue.put((source_id, entry, valid))
                            last_checkpoint = time.monotonic()
                except Exception as exc:
                    store.health(source_id, error=type(exc).__name__)
            reader = threading.Thread(target=read_lines, daemon=True)
            reader.start()
            while not stop.wait(2) and process.poll() is None and reader.is_alive():
                try:
                    policy = read_policy(source)
                except Exception:
                    policy_ready.clear()
                    raise
                policy_ready.set()
                store.health(source_id, policy)
            if not stop.is_set():
                raise RuntimeError('journal_stream_ended')
        except Exception as exc:
            store.health(source_id, error=type(exc).__name__ + ':' + (str(exc) if isinstance(exc, ValueError) else 'source_unavailable'))
        finally:
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
        stop.wait(2)


def run(config_path, db_path, port, token_file):
    with open(config_path, encoding='utf-8') as stream:
        config = json.load(stream)
    store, stop = JournalStore(db_path), threading.Event()
    event_queue = queue.Queue(maxsize=2048)
    lock = None
    if os.name == 'posix':
        import fcntl
        lock = open(db_path + '.watcher-lock', 'a')
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    token = Path(token_file).read_text(encoding='ascii').strip() if token_file else None
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_GET(self):
            if token and not hmac.compare_digest(self.headers.get('X-Traffic-Token', ''), token):
                self.send_error(403); return
            request = urllib.parse.urlsplit(self.path)
            if request.path == '/api/status':
                value = store.status()
            elif request.path == '/api/events':
                query = urllib.parse.parse_qs(request.query)
                try:
                    value = store.events(int(query.get('after_id', ['0'])[0]), int(query.get('limit', ['1000'])[0]))
                    value['coverage'] = store.status()
                except ValueError:
                    self.send_error(400); return
            else:
                self.send_error(404); return
            raw = json.dumps(value, ensure_ascii=False).encode()
            self.send_response(200); self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Cache-Control', 'no-store'); self.send_header('Content-Length', str(len(raw)))
            self.end_headers(); self.wfile.write(raw)
    def persist():
        while not stop.is_set():
            try:
                batch = [event_queue.get(timeout=.2)]
            except queue.Empty:
                continue
            deadline = time.monotonic() + .2
            while len(batch) < 128 and time.monotonic() < deadline:
                try:
                    batch.append(event_queue.get(timeout=max(.001, deadline - time.monotonic())))
                except queue.Empty:
                    break
            try:
                store.consume_many(batch)
            except Exception as exc:
                for source_id in {row[0] for row in batch}:
                    store.health(source_id, error='event_persistence_failed:' + type(exc).__name__)
                stop.set()
    threading.Thread(target=persist, daemon=True).start()
    for source in config['sources']:
        threading.Thread(target=follow, args=(store, source, stop, event_queue), daemon=True).start()
    server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    server.timeout = 1
    while not stop.is_set():
        server.handle_request()
    server.server_close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='/etc/security-confirmed-events.json')
    parser.add_argument('--db', default='/var/lib/security-mail-alerts/confirmed-events.db')
    parser.add_argument('--port', type=int, default=18114)
    parser.add_argument('--token-file')
    args = parser.parse_args()
    run(args.config, args.db, args.port, args.token_file)
