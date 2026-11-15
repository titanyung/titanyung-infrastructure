"""Per-user application-byte ledger, bucketed by observation day in UTC+8.

This ledger never calls a byte count physical NIC traffic. A confirmed flow
can describe more than one logical boundary; those role columns are not an
addable total. Replayed cumulative counters advance only by their difference.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone
from daily_expiry import load_policy, source_metadata

try:
    import network_stats as _network_stats
except ImportError:
    _network_stats = None

TZ = timezone(timedelta(hours=8), 'Asia/Singapore')
ROLES = ('ingress', 'relay', 'egress')
RETENTION_DAYS = 31
DEFAULT_DB = '/var/lib/user-daily-traffic/daily.db'
USAGE_COLUMNS = ('day', 'user', 'role', 'host', 'peer', 'source', 'meter_basis',
                 'estimated', 'priority', 'upload', 'download', 'updated_at')
SCHEMA = '''
CREATE TABLE IF NOT EXISTS ledger_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS counter_seen(
 identity TEXT PRIMARY KEY,host TEXT NOT NULL,runtime TEXT NOT NULL,
 connection_id TEXT NOT NULL,created_at_ms INTEGER NOT NULL,user TEXT NOT NULL,
 claims TEXT NOT NULL,upload INTEGER NOT NULL,download INTEGER NOT NULL,
 observed_at INTEGER NOT NULL,closed INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS counter_seen_observed ON counter_seen(observed_at);
CREATE TABLE IF NOT EXISTS daily_usage(
 day TEXT NOT NULL,user TEXT NOT NULL,role TEXT NOT NULL,host TEXT NOT NULL,
 peer TEXT NOT NULL,source TEXT NOT NULL,meter_basis TEXT NOT NULL,
 estimated INTEGER NOT NULL,priority INTEGER NOT NULL,upload INTEGER NOT NULL,
 download INTEGER NOT NULL,updated_at INTEGER NOT NULL,
 PRIMARY KEY(day,user,role,host,peer,source,meter_basis,estimated,priority));
CREATE INDEX IF NOT EXISTS daily_usage_user ON daily_usage(user,day);
CREATE TABLE IF NOT EXISTS collection_gaps(
 id INTEGER PRIMARY KEY AUTOINCREMENT,ts INTEGER NOT NULL,day TEXT NOT NULL,
 user TEXT NOT NULL,host TEXT NOT NULL,runtime TEXT NOT NULL,
 reason TEXT NOT NULL,detail TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS collection_gaps_day ON collection_gaps(day,user);
CREATE INDEX IF NOT EXISTS collection_gaps_context ON collection_gaps(reason,user,host,runtime,ts);
CREATE TABLE IF NOT EXISTS bucket_imports(import_key TEXT PRIMARY KEY,
 identity TEXT NOT NULL,upload INTEGER NOT NULL,download INTEGER NOT NULL,day TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS bucket_imports_day ON bucket_imports(day);
CREATE TABLE IF NOT EXISTS cohort_users(
 host TEXT NOT NULL,runtime TEXT NOT NULL,user TEXT NOT NULL,
 first_seen INTEGER NOT NULL,last_seen INTEGER NOT NULL,active INTEGER NOT NULL,
 PRIMARY KEY(host,runtime,user));
CREATE TABLE IF NOT EXISTS mirror_sources(
 source_key TEXT PRIMARY KEY,instance_id TEXT NOT NULL,revision INTEGER NOT NULL,
 started_at INTEGER NOT NULL,generated_at INTEGER NOT NULL,received_at INTEGER NOT NULL,
 last_observed_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS mirrored_usage(
 owner TEXT NOT NULL,day TEXT NOT NULL,user TEXT NOT NULL,role TEXT NOT NULL,
 host TEXT NOT NULL,peer TEXT NOT NULL,source TEXT NOT NULL,meter_basis TEXT NOT NULL,
 estimated INTEGER NOT NULL,priority INTEGER NOT NULL,upload INTEGER NOT NULL,
 download INTEGER NOT NULL,updated_at INTEGER NOT NULL,
 PRIMARY KEY(owner,day,user,role,host,peer,source,meter_basis,estimated,priority));
CREATE INDEX IF NOT EXISTS mirrored_usage_user ON mirrored_usage(user,day);
CREATE TABLE IF NOT EXISTS mirrored_gaps(
 owner TEXT NOT NULL,id INTEGER NOT NULL,ts INTEGER NOT NULL,day TEXT NOT NULL,
 user TEXT NOT NULL,host TEXT NOT NULL,runtime TEXT NOT NULL,
 reason TEXT NOT NULL,detail TEXT NOT NULL,PRIMARY KEY(owner,id));
CREATE INDEX IF NOT EXISTS mirrored_gaps_day ON mirrored_gaps(day,user);
CREATE TABLE IF NOT EXISTS mirrored_cohort(
 owner TEXT NOT NULL,host TEXT NOT NULL,runtime TEXT NOT NULL,user TEXT NOT NULL,
 first_seen INTEGER NOT NULL,last_seen INTEGER NOT NULL,active INTEGER NOT NULL,
 PRIMARY KEY(owner,host,runtime,user));
'''


def day_string(timestamp):
    return datetime.fromtimestamp(float(timestamp), TZ).strftime('%Y-%m-%d')


def _day(value):
    parsed = datetime.strptime(value, '%Y-%m-%d').date()
    if parsed.isoformat() != value:
        raise ValueError('invalid day')
    return value


def _text(value, label, empty=False, limit=160):
    if not isinstance(value, str) or (not value and not empty) or len(value) > limit:
        raise ValueError('invalid ' + label)
    if any(ord(char) < 32 for char in value):
        raise ValueError('control character in ' + label)
    return value


def _counter(value):
    if type(value) is not int or value < 0 or value > 2**63 - 1:
        raise ValueError('invalid byte counter')
    return value


def _timestamp(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        raise ValueError('invalid timestamp')
    return int(value)


def _now(value):
    return _timestamp(time.time() if value is None else value)


def _frozen_sql(policy,now):
    aliases=policy.frozen_aliases(now) if policy else []
    if not aliases:return '0',[]
    marks=','.join('?' for _ in aliases)
    return '(lower(host) IN ('+marks+') OR lower(peer) IN ('+marks+'))',aliases+aliases


def _migrate_early_candidate(db):
    """Add columns used by pre-release fixtures without losing local counters."""
    tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if 'mirror_sources' in tables:
        columns = {row[1] for row in db.execute('PRAGMA table_info(mirror_sources)')}
        if 'last_observed_at' not in columns:
            db.execute('ALTER TABLE mirror_sources ADD COLUMN last_observed_at INTEGER NOT NULL DEFAULT 0')
    if 'bucket_imports' in tables:
        columns = {row[1] for row in db.execute('PRAGMA table_info(bucket_imports)')}
        if 'day' not in columns:
            db.execute("ALTER TABLE bucket_imports ADD COLUMN day TEXT NOT NULL DEFAULT ''")
            for key, identity in db.execute("SELECT import_key,identity FROM bucket_imports WHERE day=''"):
                try:
                    day = _day(json.loads(identity)[0])
                except (ValueError, TypeError, KeyError, IndexError):
                    continue
                db.execute('UPDATE bucket_imports SET day=? WHERE import_key=?', (day,key))
    db.commit()


def _claim(value):
    role = value.get('role')
    if role not in ROLES:
        raise ValueError('invalid role')
    priority = value.get('priority', 100)
    if type(priority) is not int or not 0 <= priority <= 1000:
        raise ValueError('invalid role priority')
    return {'role': role, 'peer': _text(value.get('peer', ''), 'peer', True),
            'source': _text(value.get('source', ''), 'source'),
            'meter_basis': _text(value.get('meter_basis', 'application'), 'meter basis'),
            'estimated': bool(value.get('estimated', False)), 'priority': priority,
            'zero': bool(value.get('zero', False))}


class DailyLedger:
    def __init__(self, path=DEFAULT_DB, started_at=None, source_key=None):
        if source_key is not None:
            _text(source_key, 'source key')
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA busy_timeout=10000')
        _migrate_early_candidate(self.db)
        self.db.executescript(SCHEMA)
        with self.db:
            initial = {'schema': '1', 'started_at': str(_now(started_at)),
                       'source_key': source_key or 'local', 'instance_id': str(uuid.uuid4()),
                       'revision': '0'}
            for key, value in initial.items():
                self.db.execute('INSERT OR IGNORE INTO ledger_meta VALUES(?,?)', (key, value))
        self.meta = dict(self.db.execute('SELECT key,value FROM ledger_meta'))
        self.started_at = int(self.meta['started_at'])
        if source_key and self.meta['source_key'] != source_key:
            raise ValueError('ledger source key differs')
        if os.name != 'nt':
            os.chmod(self.path, 0o600)

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _revision(self):
        self.db.execute("UPDATE ledger_meta SET value=CAST(value AS INTEGER)+1 WHERE key='revision'")

    def _gap(self, reason, now, user='', host='', runtime='', detail=''):
        if self.db.execute('SELECT 1 FROM collection_gaps WHERE reason=? AND user=? AND host=? AND runtime=? AND ts>=? LIMIT 1',
                           (reason, user, host, runtime, now-60)).fetchone():
            return
        self.db.execute('INSERT INTO collection_gaps(ts,day,user,host,runtime,reason,detail) VALUES(?,?,?,?,?,?,?)',
                        (now, day_string(now), user, host, runtime, reason, detail))

    def record_gap(self, reason, observed_at=None, user='', host='', runtime='', detail=''):
        now = _now(observed_at)
        policy=load_policy(required=self.path==DEFAULT_DB)
        if policy and (policy.expired(self.meta['source_key'],now) or policy.expired(host,now)):
            return
        reason = _text(reason, 'gap reason')
        for value, label in ((user, 'user'), (host, 'host'), (runtime, 'runtime'), (detail, 'detail')):
            _text(value, label, True, 500 if label == 'detail' else 160)
        with self.db:
            self._gap(reason, now, user, host, runtime, detail)
            self._revision()

    def register_users(self, users, host, runtime, observed_at=None):
        now = _now(observed_at)
        policy=load_policy(required=self.path==DEFAULT_DB)
        if policy and policy.expired(host,now):return
        host, runtime = _text(host,'host'), _text(runtime,'runtime')
        users = sorted({_text(user,'user') for user in users})
        with self.db:
            self.db.execute('UPDATE cohort_users SET active=0 WHERE host=? AND runtime=?', (host,runtime))
            for user in users:
                self.db.execute('''INSERT INTO cohort_users VALUES(?,?,?,?,?,1)
                  ON CONFLICT(host,runtime,user) DO UPDATE SET last_seen=excluded.last_seen,active=1''',
                  (host,runtime,user,now,now))
            self._revision()

    def _usage(self, day, user, host, claim, up, down, now):
        if claim['zero']:
            up = down = 0
        self.db.execute('''INSERT INTO daily_usage VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
          ON CONFLICT(day,user,role,host,peer,source,meter_basis,estimated,priority)
          DO UPDATE SET upload=upload+excluded.upload,download=download+excluded.download,
                        updated_at=MAX(updated_at,excluded.updated_at)''',
          (day, user, claim['role'], host, claim['peer'], claim['source'],
           claim['meter_basis'], int(claim['estimated']), claim['priority'], up, down, now))

    def record(self, observations, observed_at=None):
        now = _now(observed_at)
        policy=load_policy(required=self.path==DEFAULT_DB)
        result = dict(accepted=0, replayed=0, rejected=0, baselines=0, deltas=0,expired_skipped=0)
        if policy and policy.expired(self.meta['source_key'],now):
            result['expired_skipped']=len(observations)
            return result
        with self.db:
            for item in observations:
                try:
                    host = _text(item.get('host'), 'host')
                    runtime = _text(item.get('runtime'), 'runtime')
                    user = _text(item.get('user'), 'user')
                    uid = _text(str(item.get('connection_id') or ''), 'connection id', limit=256)
                    created = item.get('created_at_ms')
                    created = _timestamp(created) if created is not None else round(float(item['created_at']) * 1000)
                    if created <= 0 or created > (now + 120) * 1000:
                        raise ValueError('invalid creation time')
                    up, down = _counter(item['upload']), _counter(item['download'])
                    claims = [_claim(claim) for claim in item.get('roles', [])]
                    roles = [claim['role'] for claim in claims]
                    if len(roles) != len(set(roles)):
                        raise ValueError('duplicate flow role')
                    if policy and not policy.permits(host,claims,now):
                        result['expired_skipped']+=1
                        continue
                    encoded_claims = json.dumps(claims, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
                    # The hot dedup table stores only a fingerprint; repeating
                    # the same long route JSON for every connection wastes space.
                    claim_fingerprint = 'sha256:' + hashlib.sha256(encoded_claims.encode()).hexdigest()
                    identity = hashlib.sha256(json.dumps([host, runtime, uid, created], separators=(',', ':')).encode()).hexdigest()
                    old = self.db.execute('SELECT * FROM counter_seen WHERE identity=?', (identity,)).fetchone()
                    if old and (old['user'] != user or old['claims'] not in (claim_fingerprint,encoded_claims)):
                        self._gap('identity_or_route_changed', now, user, host, runtime)
                        result['rejected'] += 1
                        continue
                    if old and now < old['observed_at']:
                        result['replayed'] += 1
                        continue
                    if old and (up < old['upload'] or down < old['download']):
                        self._gap('counter_regression', now, user, host, runtime)
                        result['rejected'] += 1
                        continue
                    baseline = old is None and created < max(self.started_at, now-RETENTION_DAYS*86400) * 1000
                    if baseline:
                        delta_up = delta_down = 0
                        self._gap('preexisting_connection_baseline', now, user, host, runtime)
                        result['baselines'] += 1
                    else:
                        delta_up, delta_down = up - (old['upload'] if old else 0), down - (old['download'] if old else 0)
                        if not old or delta_up or delta_down:
                            for claim in claims:
                                self._usage(day_string(now), user, host, claim, delta_up, delta_down, now)
                        if delta_up or delta_down:
                            result['deltas'] += 1
                    if not claims and old is None:
                        self._gap('route_roles_unavailable', now, user, host, runtime)
                    self.db.execute('''INSERT INTO counter_seen VALUES(?,?,?,?,?,?,?,?,?,?,?)
                      ON CONFLICT(identity) DO UPDATE SET claims=excluded.claims,upload=excluded.upload,download=excluded.download,
                        observed_at=excluded.observed_at,closed=MAX(closed,excluded.closed)''',
                      (identity, host, runtime, uid, created, user, claim_fingerprint, up, down, now, int(bool(item.get('closed')))))
                    result['accepted'] += 1
                    if old and not delta_up and not delta_down:
                        result['replayed'] += 1
                except (ValueError, KeyError, TypeError, OverflowError, AttributeError):
                    result['rejected'] += 1
                    self._gap('invalid_observation', now)
            if result['accepted'] or result['rejected']:
                self._revision()
            self.db.execute('INSERT OR REPLACE INTO ledger_meta VALUES(?,?)', ('last_observed_at', str(now)))
        return result

    def add_usage(self, *, day, user, role, host, peer, upload, download,
                  source, meter_basis='observed_hourly_application', estimated=False,
                  priority=200, import_key, observed_at=None):
        """Idempotent source-bucket import; preserves reliable old hourly bins.

        import_key must include the source table/hour/user/route. Snapshot-style
        imports replace a previous bucket rather than repeatedly adding it.
        """
        day, now = _day(day), _now(observed_at)
        user, host = _text(user, 'user'), _text(host, 'host')
        claim = _claim(dict(role=role, peer=peer, source=source, meter_basis=meter_basis,
                            estimated=estimated, priority=priority))
        policy=load_policy(required=self.path==DEFAULT_DB)
        if policy and not policy.permits(host,[claim],now):
            return
        up, down = _counter(upload), _counter(download)
        key = 'bucket:' + _text(import_key, 'import key', limit=400)
        encoded = json.dumps([day, user, host, claim], sort_keys=True, ensure_ascii=False)
        with self.db:
            old = self.db.execute('SELECT identity,upload,download FROM bucket_imports WHERE import_key=?', (key,)).fetchone()
            if old and old[0] != encoded:
                raise ValueError('source bucket identity changed')
            if old and (up < old[1] or down < old[2]):
                raise ValueError('source bucket regressed')
            self._usage(day, user, host, claim, up - (old[1] if old else 0), down - (old[2] if old else 0), now)
            self.db.execute('INSERT OR REPLACE INTO bucket_imports VALUES(?,?,?,?,?)', (key, encoded, up, down, day))
            self._revision()

    def export_snapshot(self, now=None):
        return export_snapshot(self.path, now=now)

    def prune(self, now=None, limit=5000):
        now = _now(now)
        if type(limit) is not int or not 1 <= limit <= 10000:
            raise ValueError('invalid prune bound')
        cutoff = day_string(now - RETENTION_DAYS*86400)
        policy=load_policy(required=self.path==DEFAULT_DB)
        frozen,args=_frozen_sql(policy,now)
        removed = 0
        with self.db:
            cursor=self.db.execute('DELETE FROM daily_usage WHERE rowid IN (SELECT rowid FROM daily_usage WHERE day<? AND NOT '+frozen+' LIMIT ?)',[cutoff]+args+[limit])
            removed+=cursor.rowcount
            for table in ('bucket_imports','collection_gaps'):
                cursor = self.db.execute('DELETE FROM '+table+' WHERE rowid IN (SELECT rowid FROM '+table+' WHERE day<? LIMIT ?)', (cutoff,limit))
                removed += cursor.rowcount
            cursor = self.db.execute('DELETE FROM counter_seen WHERE identity IN (SELECT identity FROM counter_seen WHERE observed_at<? LIMIT ?)', (now-RETENTION_DAYS*86400,limit))
            removed += cursor.rowcount
            if removed:
                self._revision()
        return removed


def export_snapshot(path=DEFAULT_DB, now=None):
    """Read a live WAL database through SQLite, never copy its raw DB file."""
    if not Path(path).is_file():
        raise FileNotFoundError(path)
    db = sqlite3.connect('file:' + str(Path(path).resolve()) + '?mode=ro', uri=True, timeout=5)
    db.row_factory = sqlite3.Row
    try:
        now = _now(now)
        cutoff = day_string(now - RETENTION_DAYS * 86400)
        db.execute('BEGIN')
        meta = dict(db.execute('SELECT key,value FROM ledger_meta'))
        policy=load_policy(required=str(path)==DEFAULT_DB)
        frozen,args=_frozen_sql(policy,now)
        usage = [dict(row) for row in db.execute('SELECT * FROM daily_usage WHERE day>=? OR '+frozen+' ORDER BY day,user,role,host,peer,source', [cutoff]+args)]
        gaps = [dict(row) for row in db.execute('SELECT * FROM collection_gaps WHERE day>=? ORDER BY id', (cutoff,))]
        cohort = [dict(row) for row in db.execute('SELECT * FROM cohort_users ORDER BY host,runtime,user')]
        return dict(schema=1, source_key=meta['source_key'], instance_id=meta['instance_id'],
                    revision=int(meta['revision']), started_at=int(meta['started_at']),
                    generated_at=now, last_observed_at=int(meta.get('last_observed_at',0)), usage=usage, gaps=gaps,cohort=cohort)
    finally:
        db.close()


def import_snapshot(path, payload, expected_source_key=None, now=None):
    now = _now(now)
    if not isinstance(payload, dict) or payload.get('schema') != 1:
        raise ValueError('invalid snapshot schema')
    owner = _text(payload.get('source_key'), 'source key')
    if expected_source_key and owner != expected_source_key:
        raise ValueError('unexpected snapshot source')
    instance = str(uuid.UUID(payload['instance_id']))
    revision, started, generated = payload['revision'], _timestamp(payload['started_at']), _timestamp(payload['generated_at'])
    if type(revision) is not int or revision < 0 or generated > now + 120:
        raise ValueError('invalid snapshot revision/time')
    usage, gaps = payload.get('usage'), payload.get('gaps')
    cohort = payload.get('cohort',[])
    if not isinstance(usage, list) or not isinstance(gaps, list) or len(usage) > 200000 or len(gaps) > 100000:
        raise ValueError('snapshot size invalid')
    if not isinstance(cohort,list) or len(cohort)>10000:
        raise ValueError('snapshot cohort invalid')
    with DailyLedger(path) as ledger:
        if owner == ledger.meta['source_key']:
            raise ValueError('cannot mirror this ledger into itself')
        db = ledger.db
        policy=load_policy(required=str(path)==DEFAULT_DB)
        owner_cutoff=policy.cutoff(owner) if policy else None
        previous = db.execute('SELECT * FROM mirror_sources WHERE source_key=?', (owner,)).fetchone()
        if previous and previous['instance_id'] != instance:
            raise ValueError('source ledger instance changed; audit before replacing history')
        if previous and revision < previous['revision']:
            return {'status': 'older_revision_ignored', 'rows': 0}
        rows = []
        for item in usage:
            claim = _claim(item)
            rows.append((owner, _day(item['day']), _text(item['user'], 'user'), claim['role'],
                         _text(item['host'], 'host'), claim['peer'], claim['source'], claim['meter_basis'],
                         int(claim['estimated']), claim['priority'], _counter(item['upload']),
                         _counter(item['download']), _timestamp(item['updated_at'])))
        gap_rows = []
        for item in gaps:
            if type(item['id']) is not int or item['id'] < 1:
                raise ValueError('invalid gap id')
            gap_rows.append((owner, item['id'], _timestamp(item['ts']), _day(item['day']),
                _text(item['user'], 'user', True), _text(item['host'], 'host', True),
                _text(item['runtime'], 'runtime', True), _text(item['reason'], 'reason'),
                _text(item['detail'], 'detail', True, 500)))
        cohort_rows=[]
        for item in cohort:
            if item['active'] not in (0,1):raise ValueError('invalid cohort state')
            cohort_rows.append((owner,_text(item['host'],'host'),_text(item['runtime'],'runtime'),
              _text(item['user'],'user'),_timestamp(item['first_seen']),_timestamp(item['last_seen']),item['active']))
        rejected_boundary=0
        old_rows=[tuple(row) for row in db.execute('SELECT * FROM mirrored_usage WHERE owner=?',(owner,))]
        if policy:
            old_by_key={row[:10]:row for row in old_rows}
            filtered={}
            for row in rows:
                cutoff=policy.cutoff(owner,row[4],row[5])
                if cutoff is not None and row[12]>=cutoff:
                    rejected_boundary+=1
                    if row[:10] in old_by_key:filtered[row[:10]]=old_by_key[row[:10]]
                else:filtered[row[:10]]=row
            # A later remote retention sweep must not silently remove a sealed
            # source/peer snapshot. Valid final pre-cutoff deltas still win.
            for row in old_rows:
                cutoff=policy.cutoff(owner,row[4],row[5])
                if cutoff is not None and now>=cutoff:
                    filtered.setdefault(row[:10],row)
            rows=list(filtered.values())
        last_observed=int(payload.get('last_observed_at',0))
        if last_observed<0 or last_observed>now+120:raise ValueError('invalid last sample time')
        if owner_cutoff is not None:
            old_gaps=[tuple(row) for row in db.execute('SELECT * FROM mirrored_gaps WHERE owner=?',(owner,))]
            old_cohort=[tuple(row) for row in db.execute('SELECT * FROM mirrored_cohort WHERE owner=?',(owner,))]
            gap_by_id={row[1]:row for row in gap_rows if row[2]<owner_cutoff}
            cohort_by_key={row[:4]:row for row in cohort_rows if row[5]<owner_cutoff}
            if now>=owner_cutoff:
                for row in old_gaps:gap_by_id.setdefault(row[1],row)
                for row in old_cohort:cohort_by_key.setdefault(row[:4],row)
            gap_rows=list(gap_by_id.values());cohort_rows=list(cohort_by_key.values())
            if last_observed>=owner_cutoff:
                # Do not invent a sample at 23:59:59. Recover only a timestamp
                # backed by a real accepted measurement or prior snapshot.
                valid_times=[row[12] for row in rows if row[12]<owner_cutoff]
                if previous and previous['last_observed_at']<owner_cutoff:
                    valid_times.append(previous['last_observed_at'])
                last_observed=max(valid_times,default=0)
            if previous and now>=owner_cutoff:
                same=(sorted(rows)==sorted(old_rows) and sorted(gap_rows)==sorted(old_gaps)
                    and sorted(cohort_rows)==sorted(old_cohort) and last_observed==previous['last_observed_at'])
                if same:return {'status':'frozen_source_unchanged','rows':0,'boundary_rows_rejected':rejected_boundary}
        if previous and revision==previous['revision'] and last_observed==previous['last_observed_at']:
            return {'status':'same_revision_ignored','rows':0,'boundary_rows_rejected':rejected_boundary}
        with db:
            db.execute('DELETE FROM mirrored_usage WHERE owner=?', (owner,))
            db.execute('DELETE FROM mirrored_gaps WHERE owner=?', (owner,))
            db.execute('DELETE FROM mirrored_cohort WHERE owner=?', (owner,))
            db.executemany('INSERT INTO mirrored_usage VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)', rows)
            db.executemany('INSERT INTO mirrored_gaps VALUES(?,?,?,?,?,?,?,?,?)', gap_rows)
            db.executemany('INSERT INTO mirrored_cohort VALUES(?,?,?,?,?,?,?)',cohort_rows)
            db.execute('INSERT OR REPLACE INTO mirror_sources VALUES(?,?,?,?,?,?,?)',
                       (owner, instance, revision, started, generated, now, last_observed))
        return {'status': 'imported', 'rows': len(rows),'boundary_rows_rejected':rejected_boundary}


def read_daily(path=DEFAULT_DB, from_day=None, to_day=None, user='', host='', limit=100, offset=0):
    now = int(time.time())
    policy=load_policy(required=str(path)==DEFAULT_DB)
    end = _day(to_day or day_string(now))
    start = _day(from_day or day_string(now - 29 * 86400))
    if start > end:
        raise ValueError('invalid date range')
    if (datetime.strptime(end, '%Y-%m-%d') - datetime.strptime(start, '%Y-%m-%d')).days > 366:
        raise ValueError('date range too wide')
    _text(user, 'user', True); _text(host, 'host', True)
    if type(limit) is not int or not 1 <= limit <= 500 or type(offset) is not int or offset < 0:
        raise ValueError('invalid pagination')
    result = dict(available=False, rows=[], users=[], total=0, started_at=None,
                  timezone='Asia/Singapore', meter_basis='application', day_basis='observed_at',
                  from_day=start, to_day=end, sample_precision_seconds=1, sources=[], coverage_gaps=[], last_sampled_at=None)
    result['totals']={role:dict(bytes=None,upload=None,download=None,estimated=False,rows_covered=0,rows_missing=0) for role in ROLES}
    if not Path(path).is_file():
        return result
    db = sqlite3.connect('file:' + str(Path(path).resolve()) + '?mode=ro', uri=True, timeout=5)
    db.row_factory = sqlite3.Row
    try:
        db.execute('BEGIN')
        if not db.execute("SELECT 1 FROM sqlite_master WHERE name='daily_usage'").fetchone():
            return result
        meta = dict(db.execute('SELECT key,value FROM ledger_meta'))
        result.update(available=True, started_at=int(meta['started_at']), last_sampled_at=int(meta.get('last_observed_at',0)) or None)
        clause, args = 'day>=? AND day<=?', [start, end]
        if user: clause += ' AND user=?'; args.append(user)
        if host: clause += ' AND host=?'; args.append(host)
        rows = [dict(row, owner=meta['source_key']) for row in db.execute('SELECT * FROM daily_usage WHERE ' + clause, args)]
        rows += [dict(row) for row in db.execute('SELECT * FROM mirrored_usage WHERE ' + clause, args)]
        network_manifest = _network_stats.read_optional_manifest() if _network_stats else None
        if network_manifest and _network_stats.server_policy_enabled(network_manifest):
            rows = _network_stats.adjust_hk_daily_rows(rows, network_manifest, start, end, user=user, host=host)
        gap_clause, gap_args = 'day>=? AND day<=?', [start, end]
        if user: gap_clause += " AND (user=? OR user='')"; gap_args.append(user)
        if host: gap_clause += " AND (host=? OR host='')"; gap_args.append(host)
        gaps = [dict(row) for row in db.execute('SELECT * FROM collection_gaps WHERE ' + gap_clause, gap_args)]
        gaps += [dict(row) for row in db.execute('SELECT * FROM mirrored_gaps WHERE ' + gap_clause, gap_args)]
        cohort=[dict(row) for row in db.execute('SELECT * FROM cohort_users')]
        cohort += [dict(row) for row in db.execute('SELECT * FROM mirrored_cohort')]
        all_users={row['user'] for row in rows}|{row['user'] for row in cohort}|{row['user'] for row in gaps if row['user']}
        # Keep the filter list complete even when one username is selected.
        all_users.update(row[0] for row in db.execute('SELECT DISTINCT user FROM daily_usage WHERE day>=? AND day<=? UNION SELECT DISTINCT user FROM mirrored_usage WHERE day>=? AND day<=?', (start,end,start,end)))
        result['users']=sorted(all_users)
        # Choose one egress authority per day/user/peer. Exit-side observation
        # (200) supersedes forwarder inference (100), never adds to it.
        priorities = {}
        for row in rows:
            key = (row['day'], row['user'], row['role'], row['peer'])
            priorities[key] = max(priorities.get(key, -1), row['priority'])
        grouped = {}
        registered_since = {}
        for member in cohort:
            if user and member['user']!=user:continue
            if host and member['host']!=host:continue
            registered_since[member['user']] = min(registered_since.get(member['user'],member['first_seen']),member['first_seen'])
            day = datetime.strptime(start,'%Y-%m-%d').date()
            last = datetime.strptime(end,'%Y-%m-%d').date()
            while day<=last:
                day_value=day.isoformat()
                if member['active'] or day_value<=day_string(member['last_seen']):
                    key=(day_value,member['user'])
                    grouped.setdefault(key,dict(day=key[0],user=key[1],ingress=None,relay=None,egress=None,
                      partial=True,gaps=[],updated_at=0))
                day+=timedelta(days=1)
        for row in rows:
            key = (row['day'], row['user'])
            item = grouped.setdefault(key, dict(day=row['day'], user=row['user'], ingress=None,
                 relay=None, egress=None, partial=False, gaps=[], updated_at=0))
            if row['role']=='egress' and not row.get('policy_segment') and row['priority'] != priorities[(row['day'],row['user'],row['role'],row['peer'])]:
                continue
            role = item[row['role']]
            if role is None:
                role = item[row['role']] = dict(bytes=0, upload=0, download=0, estimated=False, sources=[])
            role['upload'] += row['upload']; role['download'] += row['download']
            role['bytes'] += row['upload'] + row['download']
            role['estimated'] = role['estimated'] or bool(row['estimated'])
            source={key: row[key] for key in
                ('host','peer','source','meter_basis','estimated','priority','upload','download','updated_at','owner')}
            if row.get('policy_segment'):
                source.update(policy_segment=row['policy_segment'], policy_cutover_at=row['policy_cutover_at'])
            source.update(source_metadata(policy,row['host'],row['peer'],now,row['updated_at']))
            if row.get('policy_segment') == 'before':
                source.update(frozen=True, freeze_at=row['policy_cutover_at'] - 1,
                    expires_at=row['policy_cutover_at'], real_sample_at=row['updated_at'])
            role['sources'].append(source)
            item['updated_at'] = max(item['updated_at'], row['updated_at'])
        for gap in gaps:
            if not gap['user']:
                result['coverage_gaps'].append({key:gap[key] for key in ('day','host','runtime','reason','ts')})
            keys = [(gap['day'], gap['user'])] if gap['user'] else [key for key in grouped if key[0] == gap['day']]
            for key in keys:
                item = grouped.setdefault(key, dict(day=key[0], user=key[1], ingress=None,
                    relay=None, egress=None, partial=True, gaps=[], updated_at=gap['ts']))
                item['gaps'].append({key: gap[key] for key in ('reason','host','runtime','ts')})
        for item in grouped.values():
            item['partial'] = bool(item['gaps']) or any(item[role] is None for role in ROLES)
            item['missing_roles']=[role for role in ROLES if item[role] is None]
            observed_since = registered_since.get(item['user'],int(meta['started_at']))
            item['status']=('partial' if item['partial'] else 'observed') if any(item[role] is not None for role in ROLES) else ('before_collection' if item['day']<day_string(observed_since) else 'not_observed')
            for role_name in ROLES:
                role=item[role_name]
                if role is not None:
                    role['real_sample_at']=max((source['updated_at'] for source in role['sources']),default=0) or None
                    role['frozen']=bool(role['sources']) and all(source['frozen'] for source in role['sources'])
                    role['freeze_at']=max((source['freeze_at'] or 0 for source in role['sources']),default=0) or None if role['frozen'] else None
        ordered = sorted(grouped.values(), key=lambda item: (-int(item['day'].replace('-','')), item['user']))
        for role in ROLES:
            covered=[item[role] for item in ordered if item[role] is not None]
            result['totals'][role]=dict(bytes=sum(item['bytes'] for item in covered) if covered else None,
                upload=sum(item['upload'] for item in covered) if covered else None,
                download=sum(item['download'] for item in covered) if covered else None,
                estimated=any(item['estimated'] for item in covered),rows_covered=len(covered),rows_missing=len(ordered)-len(covered))
        result['total'] = len(ordered)
        result['rows'] = ordered[offset:offset+limit]
        result['sources'] = [dict(source_key=meta['source_key'],started_at=int(meta['started_at']),last_observed_at=int(meta.get('last_observed_at',0)),local=True)]
        result['sources'] += [dict(row) for row in db.execute('SELECT source_key,started_at,generated_at,received_at,last_observed_at FROM mirror_sources ORDER BY source_key')]
        for source in result['sources']:
            source.update(source_metadata(policy,source['source_key'],now=now,real_sample_at=source['last_observed_at']))
        result['last_sampled_at'] = max((source.get('last_observed_at',0) for source in result['sources']),default=0) or None
        return result
    finally:
        db.close()
