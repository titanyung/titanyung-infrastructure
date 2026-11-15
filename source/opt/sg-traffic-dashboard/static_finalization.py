#!/usr/bin/env python3
"""Merge native sing-box CLOSED counters into existing static access IDs.

The live-session poller and this merger share one traffic database and one
`static:<UUID>` record per connection.  Provider totals advance only by the
final-minus-observed difference; a replay is idempotent.
"""

import sqlite3
import time


ROUTES = {
    'DMIT': {
        'dmit-taiwan': ('bytevirt-taiwan', 'bytevirt_taiwan'),
        'dmit-zorocloud': ('zorocloud', 'zorocloud'),
        'dmit-static-nexip': ('nexip', 'nexip_sg'),
        'dmit-static-ip2up': ('ip2up', 'ip2up'),
        'dmit-static-proxyhive': ('proxyhive', 'proxyhive'),
    },
    'BWH': {
        'bwh-nexip': ('nexip', 'nexip_sg'),
        'bwh-ip2up': ('ip2up', 'ip2up'),
        'bwh-proxyhive': ('proxyhive', 'proxyhive'),
    },
}
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
            ROUTES['DMIT'][_spec['inbound_tag']] = (_spec['outbound_tag'], _spec['route_class'])
RETENTION = 31 * 86400


def ensure_schema(db):
    db.executescript('''
      CREATE TABLE IF NOT EXISTS static_finalized (
        id TEXT PRIMARY KEY,
        process_started_ms INTEGER NOT NULL,
        created_at_ms INTEGER NOT NULL,
        closed_at INTEGER NOT NULL,
        imported_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_static_finalized_imported
        ON static_finalized(imported_at,id);
      CREATE TABLE IF NOT EXISTS static_final_cursor (
        host TEXT PRIMARY KEY,
        last_seen_ms INTEGER NOT NULL,
        process_started_ms INTEGER NOT NULL,
        connection_id TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS static_final_errors (
        host TEXT NOT NULL,process_started_ms INTEGER NOT NULL,
        connection_id TEXT NOT NULL,reason TEXT NOT NULL,
        first_seen_at INTEGER NOT NULL,last_seen_at INTEGER NOT NULL,
        attempts INTEGER NOT NULL,
        PRIMARY KEY(host,process_started_ms,connection_id)
      );
      CREATE TABLE IF NOT EXISTS static_retention_queue (
        id TEXT PRIMARY KEY,process_started_ms INTEGER NOT NULL,
        created_at_ms INTEGER NOT NULL,closed_at_ms INTEGER NOT NULL,
        provider TEXT NOT NULL,upload INTEGER NOT NULL,download INTEGER NOT NULL,
        imported_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_static_retention_queue_imported
        ON static_retention_queue(imported_at,id);
      CREATE TABLE IF NOT EXISTS static_retention_backfill_cursor (
        host TEXT PRIMARY KEY,imported_at INTEGER NOT NULL,id TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS static_retention_approved (
        id TEXT PRIMARY KEY,process_started_ms INTEGER NOT NULL,
        created_at_ms INTEGER NOT NULL,closed_at_ms INTEGER NOT NULL,
        provider TEXT NOT NULL,upload INTEGER NOT NULL,download INTEGER NOT NULL,
        approved_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS static_unmatched_journal (
        id TEXT PRIMARY KEY,user TEXT NOT NULL,source TEXT NOT NULL,
        destination TEXT NOT NULL,path TEXT NOT NULL,protocol TEXT NOT NULL,
        started INTEGER NOT NULL,last_seen INTEGER NOT NULL,ended INTEGER,
        upload INTEGER NOT NULL,download INTEGER NOT NULL,
        status TEXT NOT NULL,route_class TEXT,traffic_known INTEGER NOT NULL,
        moved_at INTEGER NOT NULL,reason TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_static_unmatched_started
        ON static_unmatched_journal(started,id);
    ''')


def finalized_ids(db, connections):
    """Exact primary-key lookups for current poll only, never a history scan."""
    ids = sorted({'static:' + str(item['id']) for item in connections
                  if isinstance(item, dict) and item.get('id')})
    result = set()
    for offset in range(0, len(ids), 400):
        batch = ids[offset:offset + 400]
        if batch:
            result.update(row[0] for row in db.execute(
                'SELECT id FROM static_finalized WHERE id IN (' +
                ','.join('?' for _ in batch) + ')', batch))
    return result


def _process_one(db, host, event, path_label, now):
    (received_ms, process_ms, connection_id, created_ms, closed_ms,
     username, inbound, outbound, destination, upload, download) = event
    if not connection_id or not username or not destination:
        raise ValueError('closed event missing identity or destination')
    actual = _network_stats.actual_closed_route(_network, host, inbound, outbound, created_ms) if _network else None
    if actual is not None:
        provider = actual[0]
    else:
        expected = ROUTES[host].get(inbound)
        if expected is None or outbound != expected[0]:
            raise ValueError('closed event inbound/outbound mismatch')
        provider = expected[1]
    if (process_ms <= 0 or created_ms <= 0 or closed_ms < created_ms or
            closed_ms > (now + 60) * 1000 or upload < 0 or download < 0):
        raise ValueError('closed event timestamps or counters invalid')
    started, ended = created_ms // 1000, closed_ms // 1000
    # A long connection can start before the visible history window and still
    # close today. Its final bytes belong to its close date, not its start.
    if ended < now - RETENTION:
        return 'expired'
    record_id = 'static:' + connection_id
    finalized = db.execute(
        'SELECT process_started_ms,created_at_ms FROM static_finalized WHERE id=?',
        (record_id,)).fetchone()
    already_finalized = finalized is not None
    if finalized is not None:
        if finalized != (process_ms, created_ms):
            raise ValueError('closed event ID reused by another process')
    previous = db.execute(
        'SELECT user,destination,started,upload,download,route_class,status '
        'FROM access_records WHERE id=?', (record_id,)).fetchone()
    if previous is not None:
        (old_user, old_destination, old_started, old_up, old_down,
         old_route, old_status) = previous
        if (old_user != username or old_destination != destination or
                abs(int(old_started) - started) > 2 or
                old_route not in (None, '', provider)):
            raise ValueError('polling and CLOSED identity mismatch')
        if int(old_up) > upload or int(old_down) > download:
            raise ValueError('CLOSED final counters below polling sample')
        if already_finalized and (old_up, old_down, old_route) == (
                upload, download, provider) and old_status == 'closed':
            snapshot = (process_ms, created_ms, closed_ms, provider,
                        upload, download)
            queued = db.execute(
                'SELECT process_started_ms,created_at_ms,closed_at_ms,provider,'
                'upload,download FROM static_retention_queue WHERE id=?',
                (record_id,)).fetchone()
            approved = db.execute(
                'SELECT process_started_ms,created_at_ms,closed_at_ms,provider,'
                'upload,download FROM static_retention_approved WHERE id=?',
                (record_id,)).fetchone()
            if queued == snapshot or approved == snapshot:
                return 'replay'
        db.execute(
            'UPDATE access_records SET user=?,destination=?,started=?,last_seen=?, '
            'ended=?,upload=?,download=?,status=?,route_class=?,traffic_known=1 '
            'WHERE id=?',
            (username, destination, started, now, ended, upload, download,
             'closed', provider, record_id))
    else:
        if already_finalized:
            raise ValueError('finalized access row disappeared')
        db.execute(
            'INSERT INTO access_records '
            '(id,user,source,destination,path,protocol,started,last_seen,ended,'
            'upload,download,status,route_class,traffic_known) '
            'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
            (record_id, username, '', destination, path_label, 'tcp', started,
             now, ended, upload, download, 'closed', provider, 1))
    seen = db.execute(
        'SELECT provider,upload,download FROM static_egress_seen WHERE id=?',
        (record_id,)).fetchone()
    if seen is not None and (seen[0] != provider or seen[1] > upload or
                             seen[2] > download):
        raise ValueError('provider total exceeds CLOSED final')
    prior_up, prior_down = (seen[1], seen[2]) if seen else (0, 0)
    db.execute(
        'INSERT INTO static_egress_seen(id,provider,upload,download) '
        'VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET '
        'upload=excluded.upload,download=excluded.download',
        (record_id, provider, upload, download))
    delta_up, delta_down = upload - prior_up, download - prior_down
    db.execute(
        'INSERT INTO static_egress_totals(provider,upload,download,updated) '
        'VALUES(?,?,?,?) ON CONFLICT(provider) DO UPDATE SET '
        'upload=upload+excluded.upload,download=download+excluded.download,'
        'updated=excluded.updated',
        (provider, delta_up, delta_down, now))
    if not already_finalized:
        db.execute(
            'INSERT INTO static_finalized '
            '(id,process_started_ms,created_at_ms,closed_at,imported_at) '
            'VALUES(?,?,?,?,?)', (record_id, process_ms, created_ms, ended, now))
    else:
        db.execute('UPDATE static_finalized SET closed_at=?,imported_at=? WHERE id=?',
                   (ended, now, record_id))
    db.execute(
        'INSERT INTO static_retention_queue VALUES(?,?,?,?,?,?,?,?) '
        'ON CONFLICT(id) DO UPDATE SET '
        'process_started_ms=excluded.process_started_ms,'
        'created_at_ms=excluded.created_at_ms,closed_at_ms=excluded.closed_at_ms,'
        'provider=excluded.provider,upload=excluded.upload,'
        'download=excluded.download,imported_at=excluded.imported_at',
        (record_id, process_ms, created_ms, closed_ms, provider, upload, download, now))
    # A corrected higher CLOSED replay invalidates an earlier approval until
    # the unified record is observed with precisely the new final counters.
    db.execute(
        'DELETE FROM static_retention_approved WHERE id=? AND '
        '(process_started_ms!=? OR created_at_ms!=? OR closed_at_ms!=? OR '
        'provider!=? OR upload!=? OR download!=?)',
        (record_id, process_ms, created_ms, closed_ms, provider, upload, download))
    # A sing-box journal line has a numeric logger sequence, whereas the
    # CLOSED event has a UUID.  Time/user/destination cannot prove identity.
    # Keep journal evidence separately, even when this final looks similar.
    return 'corrected' if already_finalized else 'finalized'


def backfill_retention_queue(db, events_path, host, now=None, limit=2000):
    """Queue already imported CLOSED rows using exact event/source primary keys."""
    now = int(time.time()) if now is None else int(now)
    cursor = db.execute(
        'SELECT imported_at,id FROM static_retention_backfill_cursor WHERE host=?',
        (host,)).fetchone() or (0, '')
    rows = db.execute(
        'SELECT f.id,f.process_started_ms,f.created_at_ms,f.closed_at '
        ',f.imported_at '
        'FROM static_finalized f INDEXED BY idx_static_finalized_imported '
        'WHERE (f.imported_at,f.id)>(?,?) '
        'AND NOT EXISTS(SELECT 1 FROM static_retention_queue q WHERE q.id=f.id) '
        'AND NOT EXISTS(SELECT 1 FROM static_retention_approved a WHERE a.id=f.id) '
        'ORDER BY f.imported_at,f.id LIMIT ?', (*cursor, limit)).fetchall()
    events = sqlite3.connect('file:' + events_path + '?mode=ro', uri=True)
    queued = 0
    try:
        with db:
            for record_id, process_ms, created_ms, ended, _ in rows:
                if not record_id.startswith('static:'):
                    continue
                uid = record_id[len('static:'):]
                event = events.execute(
                    'SELECT closed_at_ms,outbound,upload_bytes,download_bytes,inbound '
                    'FROM closed_static_connections WHERE host=? AND '
                    'started_at_ms=? AND connection_id=? AND created_at_ms=?',
                    (host, process_ms, uid, created_ms)).fetchone()
                if not event or event[0] // 1000 != ended:
                    continue
                actual = _network_stats.actual_closed_route(_network, host, event[4], event[1], created_ms) if _network else None
                route = actual[0] if actual is not None else next((value[1] for value in ROUTES[host].values()
                              if value[0] == event[1]), None)
                source = db.execute(
                    'SELECT upload,download,status,route_class,traffic_known '
                    'FROM access_records WHERE id=?', (record_id,)).fetchone()
                if source != (event[2], event[3], 'closed', route, 1):
                    continue
                db.execute('INSERT INTO static_retention_queue VALUES(?,?,?,?,?,?,?,?)',
                           (record_id, process_ms, created_ms, event[0], route,
                            event[2], event[3], now))
                queued += 1
            next_cursor = (rows[-1][4], rows[-1][0]) if len(rows) == limit else (0, '')
            db.execute(
                'INSERT INTO static_retention_backfill_cursor VALUES(?,?,?) '
                'ON CONFLICT(host) DO UPDATE SET imported_at=excluded.imported_at,'
                'id=excluded.id', (host, *next_cursor))
    finally:
        events.close()
    return queued, len(rows)


def apply_pending(db, events_path, host, path_label, now=None, limit=200):
    if host not in ROUTES:
        raise ValueError('unexpected static host')
    now = int(time.time()) if now is None else int(now)
    cursor = db.execute(
        'SELECT last_seen_ms,process_started_ms,connection_id '
        'FROM static_final_cursor WHERE host=?', (host,)).fetchone() or (0, 0, '')
    events = sqlite3.connect('file:' + events_path + '?mode=ro', uri=True,
                             timeout=5)
    try:
        rows = events.execute(
            'SELECT last_seen_at_ms,started_at_ms,connection_id,created_at_ms,'
            'closed_at_ms,username,inbound,outbound,destination,upload_bytes,'
            'download_bytes FROM closed_static_connections '
            'WHERE host=? AND (last_seen_at_ms,started_at_ms,connection_id)>(?,?,?) '
            'ORDER BY last_seen_at_ms,started_at_ms,connection_id LIMIT ?',
            (host, *cursor, limit)).fetchall()
    finally:
        events.close()
    applied = replayed = expired = rejected = 0
    for event in rows:
        with db:
            db.execute('SAVEPOINT static_final_event')
            try:
                outcome = _process_one(db, host, event, path_label, now)
            except ValueError as exc:
                db.execute('ROLLBACK TO static_final_event')
                db.execute('RELEASE static_final_event')
                db.execute(
                    'INSERT INTO static_final_errors VALUES(?,?,?,?,?,?,?) '
                    'ON CONFLICT(host,process_started_ms,connection_id) DO UPDATE SET '
                    'reason=excluded.reason,last_seen_at=excluded.last_seen_at,'
                    'attempts=static_final_errors.attempts+1',
                    (host, event[1], event[2], str(exc)[:200], now, now, 1))
                outcome = 'rejected'
            else:
                db.execute('RELEASE static_final_event')
                db.execute(
                    'DELETE FROM static_final_errors WHERE host=? AND '
                    'process_started_ms=? AND connection_id=?',
                    (host, event[1], event[2]))
            key = (event[0], event[1], event[2])
            db.execute(
                'INSERT INTO static_final_cursor VALUES(?,?,?,?) '
                'ON CONFLICT(host) DO UPDATE SET last_seen_ms=excluded.last_seen_ms,'
                'process_started_ms=excluded.process_started_ms,'
                'connection_id=excluded.connection_id', (host, *key))
        applied += outcome in ('finalized', 'corrected')
        replayed += outcome == 'replay'
        expired += outcome == 'expired'
        rejected += outcome == 'rejected'
    return applied, replayed, expired, rejected


def migrate_fallbacks(db, now=None, limit=200):
    """Move legacy journal-only rows to diagnostics without claiming a match."""
    now = int(time.time()) if now is None else int(now)
    rows = db.execute(
        'SELECT id,user,source,destination,path,protocol,started,last_seen,ended,'
        'upload,download,status,route_class,traffic_known '
        'FROM access_records WHERE id>=? AND id<? ORDER BY id LIMIT ?',
        ('log:static:', 'log:static;', limit)).fetchall()
    with db:
        db.executemany(
            'INSERT OR IGNORE INTO static_unmatched_journal VALUES('
            '?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
            (tuple(row) + (now, 'journal has no shared CLOSED connection ID')
             for row in rows))
        db.executemany('DELETE FROM access_records WHERE id=?',
                       ((row[0],) for row in rows))
    return len(rows)
