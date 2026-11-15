#!/usr/bin/env python3
"""Prune 30-day-visible static access details after exact source/unified sync.

Runs centrally on DMIT. BWH responds only to private authenticated SSH calls.
The provider lifetime counter keys remain intact to prevent replay double count.
"""
import json
import os
import sqlite3
import subprocess
import sys
import time

RETENTION_SECONDS = 31 * 86400 - 3600
LIMIT = 200
MAX_BATCHES = 20
HOSTS = {
    'DMIT': ('/var/lib/sg-traffic-dashboard/traffic.db',
             '/var/lib/static-connection-events/events.db', 'dmit'),
    'BWH': ('/var/lib/bwh-traffic-dashboard/traffic.db',
            '/var/lib/static-connection-events/events.db', 'bwh'),
}
PROVIDERS = {'nexip': ('nexip_sg', 'NexIP SG'),
             'zorocloud': ('zorocloud', 'zorocloud'),
             'bytevirt-taiwan': ('bytevirt_taiwan', 'ByteVirt-TW'),
             'ip2up': ('ip2up', 'ip2up.com'),
             'proxyhive': ('proxyhive', 'proxyhive.io')}
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
            PROVIDERS[_spec['outbound_tag']] = (_spec['route_class'], _spec['host'])
    if _network_stats.server_policy_enabled(_network):
        PROVIDERS['direct'] = ('direct', 'DMIT')
    if _network_stats.is_revision(_network):
        for _region,_spec in _network['pool_routes'].items():
            PROVIDERS[_spec['outbound_tag']] = _network_stats.POOL_CLASSES[_region]
WHOLE_DB = '/var/lib/sg-traffic-dashboard/whole.db'
CURSOR_FILE = '/var/lib/sg-traffic-dashboard/static-retention-cursor.json'
REMOTE = ['ssh', '-i', '/root/.ssh/id_ed25519_migrate', '-p', '26274',
          '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
          '-o', 'ConnectTimeout=8', 'root@45.78.70.23',
          'python3 /opt/bwh-traffic-dashboard/static-retention.py']


def open_db(path, readonly=False):
    if readonly:
        return sqlite3.connect('file:' + path + '?mode=ro', uri=True, timeout=5)
    db = sqlite3.connect(path, timeout=10)
    db.execute('PRAGMA busy_timeout=10000')
    return db


def verify_approval(source, event):
    host, process_ms, uid, created_ms, closed_ms, outbound, up, down = event
    provider = PROVIDERS.get(outbound)
    if not provider:
        return False
    record_id = 'static:' + uid
    approval = source.execute(
        'SELECT process_started_ms,created_at_ms,closed_at_ms,provider,'
        'upload,download FROM static_retention_approved WHERE id=?',
        (record_id,)).fetchone()
    if approval != (process_ms, created_ms, closed_ms, provider[0], up, down):
        return False
    final = source.execute(
        'SELECT process_started_ms,created_at_ms,closed_at FROM static_finalized '
        'WHERE id=?', (record_id,)).fetchone()
    record = source.execute(
        'SELECT upload,download,status,route_class,traffic_known '
        'FROM access_records WHERE id=?', (record_id,)).fetchone()
    seen = source.execute(
        'SELECT provider,upload,download FROM static_egress_seen WHERE id=?',
        (record_id,)).fetchone()
    errors = source.execute(
        'SELECT 1 FROM static_final_errors WHERE host=? AND process_started_ms=? '
        'AND connection_id=?', (host, process_ms, uid)).fetchone()
    # Existing source records must agree.  They may already have passed the
    # regular 31-day cleanup; the prior durable approval is the proof then.
    return ((final is None or final == (process_ms, created_ms, closed_ms // 1000))
            and (record is None or record ==
                 (up, down, 'closed', provider[0], 1))
            and seen == (provider[0], up, down) and errors is None)


def approval_queue(host, limit=LIMIT, after=None):
    source_path, _, _ = HOSTS[host]
    source = open_db(source_path, True)
    try:
        continuation = (' WHERE (imported_at,id)>(?,?)' if after is not None else '')
        rows = source.execute(
            'SELECT id,process_started_ms,created_at_ms,closed_at_ms,provider,'
            'upload,download,imported_at FROM static_retention_queue '
            + continuation + ' ORDER BY imported_at,id LIMIT ?',
            (*(after or ()), limit)).fetchall()
        return {'rows': [tuple(row) for row in rows], 'scanned': len(rows),
                'next_cursor': [rows[-1][7], rows[-1][0]] if rows else None}
    finally:
        source.close()


def verify_unified_queue(whole, host, row):
    record_id, _, _, _, provider, up, down, _ = row
    label = next((value[1] for value in PROVIDERS.values()
                  if value[0] == provider), None)
    if label is None:
        return False
    source = whole.execute(
        'SELECT ingress,route_type,relay,upload,download,status,traffic_known '
        'FROM unified_records WHERE origin=? AND id=?',
        (HOSTS[host][2], record_id)).fetchone()
    return source == (host, '中转', label, up, down, 'closed', 1)


def approve(host, rows, now):
    source_path, events_path, _ = HOSTS[host]
    source = open_db(source_path)
    events = open_db(events_path, True)
    count = 0
    try:
        for row in rows:
            row = tuple(row)
            if len(row) != 8 or not str(row[0]).startswith('static:'):
                raise ValueError('invalid approval row')
            record_id, process_ms, created_ms, closed_ms, provider, up, down, imported = row
            uid = record_id[len('static:'):]
            outbound = next((tag for tag, value in PROVIDERS.items()
                             if value[0] == provider), None)
            source.execute('BEGIN IMMEDIATE')
            try:
                current = source.execute(
                    'SELECT id,process_started_ms,created_at_ms,closed_at_ms,provider,'
                    'upload,download,imported_at FROM static_retention_queue WHERE id=?',
                    (record_id,)).fetchone()
                event = events.execute(
                    'SELECT closed_at_ms,outbound,upload_bytes,download_bytes '
                    'FROM closed_static_connections WHERE host=? AND started_at_ms=? '
                    'AND connection_id=? AND created_at_ms=?',
                    (host, process_ms, uid, created_ms)).fetchone()
                access = source.execute(
                    'SELECT upload,download,status,route_class,traffic_known '
                    'FROM access_records WHERE id=?', (record_id,)).fetchone()
                final = source.execute(
                    'SELECT process_started_ms,created_at_ms,closed_at '
                    'FROM static_finalized WHERE id=?', (record_id,)).fetchone()
                seen = source.execute(
                    'SELECT provider,upload,download FROM static_egress_seen WHERE id=?',
                    (record_id,)).fetchone()
                if (current != row or event != (closed_ms, outbound, up, down) or
                        access != (up, down, 'closed', provider, 1) or
                        final != (process_ms, created_ms, closed_ms // 1000) or
                        seen != (provider, up, down)):
                    source.rollback()
                    continue
                source.execute(
                    'INSERT INTO static_retention_approved VALUES(?,?,?,?,?,?,?,?) '
                    'ON CONFLICT(id) DO UPDATE SET '
                    'process_started_ms=excluded.process_started_ms,'
                    'created_at_ms=excluded.created_at_ms,'
                    'closed_at_ms=excluded.closed_at_ms,provider=excluded.provider,'
                    'upload=excluded.upload,download=excluded.download,'
                    'approved_at=excluded.approved_at',
                    (record_id, process_ms, created_ms, closed_ms, provider,
                     up, down, now))
                source.execute('DELETE FROM static_retention_queue WHERE id=? '
                               'AND imported_at=?', (record_id, imported))
                source.commit()
            except Exception:
                source.rollback()
                raise
            count += 1
        return count
    finally:
        source.close()
        events.close()


def inventory(host, now, limit=LIMIT, after=None):
    source_path, events_path, _ = HOSTS[host]
    cutoff_ms = (now - RETENTION_SECONDS) * 1000
    source = open_db(source_path, True)
    events = open_db(events_path, True)
    try:
        continuation = (' AND (closed_at_ms,started_at_ms,connection_id)>(?,?,?)'
                        if after is not None else '')
        rows = events.execute(
            'SELECT host,started_at_ms,connection_id,created_at_ms,closed_at_ms,'
            'outbound,upload_bytes,download_bytes '
            'FROM closed_static_connections INDEXED BY closed_static_by_time '
            'WHERE host=? AND closed_at_ms<?' + continuation +
            ' ORDER BY closed_at_ms,started_at_ms,connection_id LIMIT ?',
            (host, cutoff_ms, *(after or ()), limit)).fetchall()
        eligible = [tuple(row) for row in rows if verify_approval(source, row)]
        next_cursor = [rows[-1][4], rows[-1][1], rows[-1][2]] if rows else None
        return {'eligible': eligible, 'blocked': len(rows) - len(eligible),
                'scanned': len(rows), 'next_cursor': next_cursor}
    finally:
        source.close()
        events.close()


def verify_unified(whole, event):
    host, _, uid, _, _, outbound, up, down = event
    provider = PROVIDERS[outbound][1]
    origin = HOSTS[host][2]
    row = whole.execute(
        'SELECT ingress,route_type,relay,upload,download,status,traffic_known '
        'FROM unified_records WHERE origin=? AND id=?',
        (origin, 'static:' + uid)).fetchone()
    # inventory() already required the durable approval, which could only be
    # written while this exact unified row existed. At its 31-day physical
    # expiry absence is expected. A still-present row must remain identical.
    direct = PROVIDERS[outbound][0] == 'direct'
    return row is None or row == (host, '直连' if direct else '中转',
                                 '直连' if direct else provider, up, down, 'closed', 1)


def ensure_pending(source):
    source.execute('''CREATE TABLE IF NOT EXISTS static_retention_pending (
        id TEXT PRIMARY KEY,process_started_ms INTEGER NOT NULL,
        created_at_ms INTEGER NOT NULL,closed_at_ms INTEGER NOT NULL,
        outbound TEXT NOT NULL,upload INTEGER NOT NULL,download INTEGER NOT NULL,
        approved_at INTEGER NOT NULL)''')
    source.commit()


def recover_pending(source, events, host):
    pending = source.execute(
        'SELECT id,process_started_ms,created_at_ms,closed_at_ms,'
        'outbound,upload,download '
        'FROM static_retention_pending ORDER BY approved_at LIMIT 200').fetchall()
    recovered = 0
    for uid, process_ms, created_ms, closed_ms, outbound, up, down in pending:
        actual = events.execute(
            'SELECT created_at_ms,closed_at_ms,outbound,upload_bytes,download_bytes '
            'FROM closed_static_connections '
            'WHERE host=? AND started_at_ms=? AND connection_id=?',
            (host, process_ms, uid)).fetchone()
        snapshot = (created_ms, closed_ms, outbound, up, down)
        if actual is not None and actual != snapshot:
            with source:
                source.execute('DELETE FROM static_retention_pending WHERE id=?',
                               (uid,))
                source.execute('DELETE FROM static_retention_approved WHERE id=?',
                               ('static:' + uid,))
            continue
        approved = source.execute(
            'SELECT process_started_ms,created_at_ms,closed_at_ms,provider,'
            'upload,download FROM static_retention_approved WHERE id=?',
            ('static:' + uid,)).fetchone()
        provider = PROVIDERS.get(outbound)
        if provider is None or approved != (process_ms, created_ms, closed_ms,
                                           provider[0], up, down):
            continue
        with events:
            deleted = events.execute('DELETE FROM closed_static_connections WHERE host=? '
                           'AND started_at_ms=? AND connection_id=? AND '
                           'created_at_ms=? AND closed_at_ms=? AND outbound=? '
                           'AND upload_bytes=? AND download_bytes=?',
                           (host, process_ms, uid, *snapshot)).rowcount
        if actual is not None and deleted != 1:
            continue
        with source:
            source.execute('DELETE FROM static_finalized WHERE id=? AND '
                           'process_started_ms=? AND created_at_ms=? AND closed_at=?',
                           ('static:' + uid, process_ms, created_ms, closed_ms // 1000))
            source.execute('DELETE FROM static_retention_pending WHERE id=?', (uid,))
            source.execute('DELETE FROM static_retention_approved WHERE id=?',
                           ('static:' + uid,))
        recovered += 1
    return recovered


def apply(host, now, approved, after_event_delete=None):
    source_path, events_path, _ = HOSTS[host]
    cutoff_ms = (now - RETENTION_SECONDS) * 1000
    source = open_db(source_path)
    events = open_db(events_path)
    deleted = 0
    try:
        ensure_pending(source)
        deleted += recover_pending(source, events, host)
        for event in approved:
            event = tuple(event)
            if len(event) != 8 or event[0] != host or event[4] >= cutoff_ms:
                raise ValueError('invalid retention approval')
            actual = events.execute(
                'SELECT host,started_at_ms,connection_id,created_at_ms,closed_at_ms,'
                'outbound,upload_bytes,download_bytes '
                'FROM closed_static_connections WHERE host=? AND started_at_ms=? '
                'AND connection_id=?', (host, event[1], event[2])).fetchone()
            if actual != event or not verify_approval(source, event):
                continue
            with source:
                source.execute('INSERT OR IGNORE INTO static_retention_pending '
                    '(id,process_started_ms,created_at_ms,closed_at_ms,outbound,'
                    'upload,download,approved_at) VALUES(?,?,?,?,?,?,?,?)',
                    (event[2], event[1], event[3], event[4], event[5],
                     event[6], event[7], now))
            with events:
                event_deleted = events.execute(
                    'DELETE FROM closed_static_connections WHERE host=? '
                    'AND started_at_ms=? AND connection_id=? AND closed_at_ms=? '
                    'AND outbound=? AND upload_bytes=? AND download_bytes=?',
                    (host, event[1], event[2], event[4], event[5], event[6], event[7])).rowcount
            if event_deleted != 1:
                with source:
                    source.execute('DELETE FROM static_retention_pending WHERE id=?',
                                   (event[2],))
                continue
            if after_event_delete is not None:
                after_event_delete()
            with source:
                source.execute(
                    'DELETE FROM static_finalized WHERE id=? AND '
                    'process_started_ms=? AND created_at_ms=? AND closed_at=?',
                    ('static:' + event[2], event[1], event[3], event[4] // 1000))
                source.execute('DELETE FROM static_retention_pending WHERE id=?',
                               (event[2],))
                source.execute('DELETE FROM static_retention_approved WHERE id=?',
                               ('static:' + event[2],))
            deleted += 1
        return deleted
    finally:
        source.close()
        events.close()


def prune_diagnostics(path, table, now, id_cols, limit=LIMIT):
    cutoff = now - RETENTION_SECONDS
    db = open_db(path)
    try:
        total = 0
        clause = ' AND '.join(column + '=?' for column in id_cols)
        for _ in range(MAX_BATCHES):
            rows = db.execute(
                'SELECT ' + ','.join(id_cols) + ' FROM ' + table +
                ' WHERE started<? ORDER BY started LIMIT ?',
                (cutoff, limit)).fetchall()
            if rows:
                with db:
                    db.executemany('DELETE FROM ' + table + ' WHERE ' + clause, rows)
            total += len(rows)
            if len(rows) < limit:
                break
        return total
    finally:
        db.close()


def remote(mode, now, payload=None):
    cmd = REMOTE + [mode, 'BWH', str(now)]
    stdin_data = (json.dumps(payload) if payload is not None or
                  mode in ('inventory', 'approval-queue') else None)
    result = subprocess.run(cmd, input=stdin_data,
                            text=True, capture_output=True, check=True, timeout=30)
    return json.loads(result.stdout)


def load_cursors():
    try:
        with open(CURSOR_FILE, encoding='utf-8') as stream:
            result = json.load(stream)
        return result if isinstance(result, dict) else {}
    except FileNotFoundError:
        return {}


def save_cursors(value):
    temporary = CURSOR_FILE + '.tmp'
    with open(temporary, 'w', encoding='utf-8') as stream:
        json.dump(value, stream, separators=(',', ':'))
    os.chmod(temporary, 0o600)
    os.replace(temporary, CURSOR_FILE)


def master(now):
    whole = open_db(WHOLE_DB, True)
    results = {}
    cursors = load_cursors()
    try:
        for host in ('DMIT',):
            approved_total = blocked_total = deleted_total = 0
            approval_count = 0
            approval_key = host + ':approval'
            approval_cursor = cursors.get(approval_key)
            for _ in range(MAX_BATCHES):
                queue = (approval_queue(host, after=approval_cursor)
                         if host == 'DMIT' else
                         remote('approval-queue', now, approval_cursor))
                newly_synced = [row for row in queue['rows']
                                if verify_unified_queue(whole, host, row)]
                if newly_synced:
                    approval_count += (approve(host, newly_synced, now)
                                       if host == 'DMIT' else
                                       remote('approve', now, newly_synced)['approved'])
                approval_cursor = queue['next_cursor']
                if queue['scanned'] < LIMIT:
                    approval_cursor = None
                cursors[approval_key] = approval_cursor
                save_cursors(cursors)
                if queue['scanned'] < LIMIT:
                    break
            cursor = cursors.get(host)
            # Complete any event/source two-database deletion interrupted
            # after the event row was removed on a previous run.
            deleted_total += (apply(host, now, []) if host == 'DMIT'
                              else remote('apply', now, [])['deleted'])
            for _ in range(MAX_BATCHES):
                batch = (inventory(host, now, after=cursor) if host == 'DMIT'
                         else remote('inventory', now, cursor))
                eligible = batch['eligible']
                approved = [row for row in eligible if verify_unified(whole, row)]
                blocked_total += batch['blocked'] + len(eligible) - len(approved)
                approved_total += len(approved)
                if approved:
                    deleted_total += (apply(host, now, approved) if host == 'DMIT'
                                      else remote('apply', now, approved)['deleted'])
                cursor = batch['next_cursor']
                if batch['scanned'] < LIMIT:
                    # Completed one full pass. Revisit earlier blocked rows
                    # on the next timer run after an upstream sync recovers.
                    cursor = None
                cursors[host] = cursor
                save_cursors(cursors)
                if batch['scanned'] < LIMIT:
                    break
            diagnostic = (prune_diagnostics(HOSTS[host][0],
                                           'static_unmatched_journal', now, ['id'])
                          if host == 'DMIT' else remote('prune-diagnostic', now)['deleted'])
            results[host] = {'approved': approved_total, 'deleted': deleted_total,
                             'new_approvals': approval_count,
                             'blocked': blocked_total, 'diagnostic_deleted': diagnostic}
        results['whole_diagnostic_deleted'] = prune_diagnostics(
            WHOLE_DB, 'unified_static_unmatched_journal', now, ['origin', 'id'])
        return results
    finally:
        whole.close()


def main():
    mode = sys.argv[1]
    host = sys.argv[2] if len(sys.argv) > 2 else ''
    now = int(sys.argv[3]) if len(sys.argv) > 3 else int(time.time())
    if mode == 'master':
        if host or len(sys.argv) != 2:
            raise SystemExit('master uses system clock only')
        print(json.dumps(master(now), sort_keys=True))
    elif host in HOSTS and mode == 'inventory':
        raw = sys.stdin.read().strip()
        after = json.loads(raw) if raw else None
        print(json.dumps(inventory(host, now, after=after)))
    elif host in HOSTS and mode == 'approval-queue':
        raw = sys.stdin.read().strip()
        after = json.loads(raw) if raw else None
        print(json.dumps(approval_queue(host, after=after)))
    elif host in HOSTS and mode == 'approve':
        print(json.dumps({'approved': approve(host, json.load(sys.stdin), now)}))
    elif host in HOSTS and mode == 'apply':
        approved = json.load(sys.stdin)
        print(json.dumps({'deleted': apply(host, now, approved)}))
    elif host in HOSTS and mode == 'prune-diagnostic':
        print(json.dumps({'deleted': prune_diagnostics(
            HOSTS[host][0], 'static_unmatched_journal', now, ['id'])}))
    else:
        raise SystemExit('invalid retention mode')


if __name__ == '__main__':
    main()
