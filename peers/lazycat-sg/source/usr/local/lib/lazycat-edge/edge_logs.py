"""Bounded, pull-only edge evidence logs. Importing this module changes nothing.

SG runs journald plus a short-lived ``read`` command, never a Python collector.
DMIT owns the cursor and confirmed-events SQLite database. The 2MiB volatile
journal is a bounded spool, NOT a promise of complete/permanent source history.
Permanent confirmed evidence and explicit history gaps live on DMIT.

References (reviewed 2026-11-08): systemd journalctl(1), journald.conf(5).
In particular ``--lines=+N`` means oldest N, not the newest N after a cursor.
RuntimeMaxUse only removes archived files: active-file allocation/overhead and
journald RSS must be measured separately; this is not a 2MiB process-RAM cap.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import time
from pathlib import Path

NAMESPACE = 'lazycat-edge'
UNIT = 'lazycat-edge.service'
DEFAULT_DATABASE = '/var/lib/submerge-edge/confirmed-events.db'
MAX_BATCH = 200
MAX_RAW_BYTES = 4 * 1024 * 1024
MAX_REPLY_BYTES = 240 * 1024
MAX_EVIDENCE_MESSAGE = 4096
FIELDS = ('__CURSOR', '__REALTIME_TIMESTAMP', '_BOOT_ID',
          '_SYSTEMD_INVOCATION_ID', '_PID', '_SYSTEMD_UNIT',
          'MESSAGE', 'MESSAGE_ID', '_TRANSPORT', 'UNIT', 'OBJECT_SYSTEMD_UNIT')
KEEP_FIELDS = FIELDS[:6] + ('MESSAGE',)
ANSI = re.compile(r'\x1b\[[0-9;]*m')
# Deliberately identical to the installed confirmed_watcher evidence grammar.
AUTH = re.compile(r'\[(?P<cid>\d+) [^\]]+\] inbound/[^\[]+\[(?P<inbound>[^\]]+)\]: \[(?P<user>[^\]\r\n]{1,256})\] inbound (?:packet )?connection to (?P<destination>[^\r\n]+)$')
DEBUG_BT = re.compile(r'\[(?P<cid>\d+) [^\]]+\] router: match\[\d+\] protocol=bittorrent => reject(?:\(.*\))?$')
# Observed native 1.14.3 prints the reviewed inbound scope before protocol.
# This whole-line grammar permits only this AI2 rule, not arbitrary extra
# predicates/rules or a router-looking suffix inside an AUTH destination.
SCOPED_DEBUG_BT = re.compile(
    r'^(?P<prefix>(?:[+-]\d{4} \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} )?DEBUG )'
    r'(?P<connection>\[(?P<cid>\d+) [^\]\r\n]{1,64}\]) router: '
    r'(?P<match>match\[\d+\]) inbound=\[(?:dmit-starhub dmit-singtel|dmit-singtel dmit-starhub|'
    r'dmit-starhub dmit-singtel dmit-starhub-lazycat dmit-starhub-uzuma)\] '
    r'protocol=bittorrent => (?P<reject>reject(?:\([^()\r\n]{0,128}\))?)$')
SUPPRESSED = re.compile(r'\bSuppressed\s+(\d+)\s+messages\b', re.IGNORECASE)


class LogError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise LogError(code)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':')).encode('utf-8')


def valid_cursor(value, *, allow_none=True):
    if value is None and allow_none:
        return value
    require(isinstance(value, str) and 0 < len(value) <= 2048
            and all(33 <= ord(char) <= 126 for char in value), 'invalid_cursor')
    return value


def config_candidates():
    """Return explicit candidate files, without installing/restarting anything.

    Only this journal namespace is touched. LogsDirectory reset prevents the
    template's default persistent directory despite Storage=volatile.
    No MemoryMax is imposed on journald: real combined-guest usage needs QA.
    """
    return {
        '/etc/systemd/system/lazycat-edge.service.d/70-evidence-log.conf': (
            '[Service]\nLogNamespace=lazycat-edge\n'
            'StandardOutput=journal\nStandardError=journal\n'
            'LogRateLimitIntervalSec=10s\nLogRateLimitBurst=1000\n'),
        '/etc/systemd/journald@lazycat-edge.conf': (
            '[Journal]\nStorage=volatile\nCompress=yes\nSplitMode=none\n'
            'RuntimeMaxUse=2M\nRuntimeMaxFileSize=1M\nRuntimeMaxFiles=2\n'
            'RuntimeKeepFree=32M\nMaxRetentionSec=15min\nMaxFileSec=1min\n'
            'RateLimitIntervalSec=10s\nRateLimitBurst=1000\n'
            'ForwardToSyslog=no\nForwardToKMsg=no\nForwardToConsole=no\n'
            'ForwardToWall=no\nReadKMsg=no\n'),
        '/etc/systemd/system/systemd-journald@lazycat-edge.service.d/70-volatile-only.conf': (
            '[Service]\nLogsDirectory=\n'),
    }


def journal_argv(cursor=None, *, exact=False, limit=MAX_BATCH):
    """Fixed namespace/unit scope plus journald driver loss notifications.

    Explicit match disjunction is the unit's relevant journal fields OR driver
    messages. Using only ``-u lazycat-edge.service`` can omit journald's own
    Suppressed messages notification and silently hide a rate-limit gap.
    Cursor existence checks deliberately query the whole private namespace.
    """
    valid_cursor(cursor)
    require(type(limit) is int and 1 <= limit <= MAX_BATCH, 'invalid_batch_limit')
    argv = ['journalctl', '--namespace=' + NAMESPACE, '--no-pager', '-o', 'json',
            '--output-fields=' + ','.join(FIELDS), '--lines=+' + str(limit)]
    if cursor is not None:
        argv.append(('--cursor=' if exact else '--after-cursor=') + cursor)
    if not exact:
        argv += ['_SYSTEMD_UNIT=' + UNIT, '+', 'UNIT=' + UNIT, '+',
                 'OBJECT_SYSTEMD_UNIT=' + UNIT, '+', '_TRANSPORT=driver']
    return argv


def command(argv):
    """Short-lived fixed journalctl process; never starts a follower/daemon."""
    try:
        value = subprocess.run(argv, capture_output=True, timeout=10,
                               env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                                    'LC_ALL': 'C', 'SYSTEMD_PAGER': 'cat',
                                    'SYSTEMD_COLORS': '0'})
    except (OSError, subprocess.TimeoutExpired):
        raise LogError('journal_command_unavailable') from None
    require(len(value.stdout) <= MAX_RAW_BYTES and len(value.stderr) <= 65536,
            'journal_output_limit')
    return value.returncode, value.stdout, value.stderr


def rows_from(raw):
    if isinstance(raw, str):
        raw = raw.encode('utf-8')
    require(isinstance(raw, bytes) and len(raw) <= MAX_RAW_BYTES, 'journal_output_limit')
    result = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except (ValueError, UnicodeError):
            raise LogError('journal_json_invalid') from None
        require(isinstance(entry, dict), 'journal_json_invalid')
        require(len(result) < MAX_BATCH, 'journal_batch_over_limit')
        valid_cursor(entry.get('__CURSOR'), allow_none=False)
        result.append(entry)
    return result


def message(entry):
    raw = entry.get('MESSAGE')
    if isinstance(raw, list):
        require(len(raw) <= MAX_EVIDENCE_MESSAGE
                and all(type(byte) is int and 0 <= byte <= 255 for byte in raw),
                'journal_message_unavailable')
        raw = bytes(raw)
    if isinstance(raw, bytes):
        raw = raw.decode('utf-8', 'replace')
    require(isinstance(raw, str) and len(raw.encode('utf-8')) <= MAX_EVIDENCE_MESSAGE,
            'journal_message_unavailable')
    return ANSI.sub('', raw)


def identity(entry):
    return (isinstance(entry.get('_BOOT_ID'), str) and bool(entry['_BOOT_ID'])
            and isinstance(entry.get('_PID'), str) and entry['_PID'].isdigit()
            and isinstance(entry.get('_SYSTEMD_INVOCATION_ID'), str)
            and bool(entry['_SYSTEMD_INVOCATION_ID'])
            and str(entry.get('__REALTIME_TIMESTAMP', '')).isdigit()
            and int(entry['__REALTIME_TIMESTAMP']) > 0)


def relevant(text):
    auth = AUTH.search(text)
    if auth and 'router: match[' in text:
        return False
    debug = DEBUG_BT.search(text) or SCOPED_DEBUG_BT.fullmatch(text)
    # A destination/user string must never inject router evidence into the
    # suffix of an AUTH line. Native router and inbound lines are separate.
    return bool(auth) != bool(debug)


def canonical_evidence(text):
    """Remove only the observed fixed scope so the installed watcher can parse.

    Original native cid/duration/rule/reject stay unchanged. No generic reject,
    sniffed-protocol message, different inbound scope or extra condition is
    promoted into BT evidence. The old watcher remains unmodified.
    """
    scoped = SCOPED_DEBUG_BT.fullmatch(text)
    if scoped and not AUTH.search(text):
        return (scoped['prefix'] + scoped['connection'] + ' router: ' + scoped['match']
                + ' protocol=bittorrent => ' + scoped['reject'])
    return text


def parse_batch(rows, *, requested_cursor=None, cursor_found=True,
                cursor_still_present=True, limit=MAX_BATCH):
    """Pure projection: no unrelated messages or credentials leave the source.

    Events/gaps carry a scan index. Ingestion clears correlation context exactly
    at a gap, so AUTH before dropped records cannot prove a later BT hit.
    """
    valid_cursor(requested_cursor)
    require(type(limit) is int and 1 <= limit <= MAX_BATCH and len(rows) <= limit,
            'journal_batch_over_limit')
    require(isinstance(cursor_found, bool) and isinstance(cursor_still_present, bool),
            'cursor_proof_invalid')
    events, gaps = [], []
    if requested_cursor is None:
        gaps.append({'index': -1, 'code': 'initial_history_boundary_unknown'})
    elif not cursor_found:
        gaps.append({'index': -1, 'code': 'resume_cursor_missing'})
    elif not cursor_still_present:
        gaps.append({'index': -1, 'code': 'cursor_rotated_during_read'})
    previous = requested_cursor
    seen = set()
    for index, entry in enumerate(rows):
        require(isinstance(entry, dict), 'journal_json_invalid')
        cursor = valid_cursor(entry.get('__CURSOR'), allow_none=False)
        require(cursor not in seen and cursor != requested_cursor, 'journal_cursor_duplicate')
        seen.add(cursor)
        previous = cursor
        try:
            text = message(entry)
        except LogError:
            gaps.append({'index': index, 'code': 'journal_message_unavailable'})
            continue
        # Only journal driver metadata may announce source suppression. A user
        # destination or another unit cannot forge a suppression/gap event.
        suppressed = SUPPRESSED.search(text)
        if entry.get('_TRANSPORT') == 'driver' and suppressed and UNIT in text:
            gaps.append({'index': index, 'code': 'journal_rate_limited',
                         'dropped': min(int(suppressed[1]), 2**63 - 1)})
            continue
        if entry.get('_SYSTEMD_UNIT') != UNIT:
            continue
        if not relevant(text):
            continue
        if not identity(entry):
            gaps.append({'index': index, 'code': 'evidence_identity_missing'})
            continue
        projected = {field: entry[field] for field in KEEP_FIELDS if field in entry}
        projected['MESSAGE'] = canonical_evidence(text)
        event = {'index': index, 'entry': projected}
        # Bound the thin SSH reply even if all 200 AUTH destinations are long.
        if len(canonical({'events': events + [event], 'gaps': gaps})) > MAX_REPLY_BYTES - 40960:
            gaps.append({'index': index, 'code': 'evidence_reply_budget'})
            continue
        events.append(event)
    result = {'schema': 1, 'namespace': NAMESPACE, 'unit': UNIT,
              'requested_cursor': requested_cursor, 'next_cursor': previous,
              'scanned': len(rows), 'limit': limit, 'may_have_more': len(rows) == limit,
              'events': events, 'gaps': gaps,
              'retention': 'bounded_volatile_spool_not_complete_history'}
    require(len(canonical(result)) <= MAX_REPLY_BYTES, 'edge_log_reply_limit')
    return result


def read_batch(cursor=None, *, runner=command, limit=MAX_BATCH):
    """One pull. Missing cursor explicitly resynchronizes oldest retained logs.

    Check cursor both sides of the read: a rotation race becomes a visible gap.
    The result contains <=200 scanned source records, not the last/newest200.
    """
    valid_cursor(cursor)

    def exists():
        rc, raw, _stderr = runner(journal_argv(cursor, exact=True, limit=1))
        if rc:
            return False
        rows = rows_from(raw)
        return bool(rows and rows[0]['__CURSOR'] == cursor)

    found = exists() if cursor is not None else True
    rc, raw, stderr = runner(journal_argv(cursor if found else None, limit=limit))
    require(rc == 0, 'journal_read_unavailable')
    # A warning is never treated as silent completeness. journalctl may seek a
    # nearby entry even for a missing cursor; exact checks decide continuity.
    still_present = exists() if cursor is not None and found else found
    if stderr.strip():
        still_present = False
    return parse_batch(rows_from(raw), requested_cursor=cursor,
                       cursor_found=found, cursor_still_present=still_present, limit=limit)


def _gap_schema(store):
    with store.db() as db:
        db.execute('''CREATE TABLE IF NOT EXISTS edge_journal_gaps(
            id INTEGER PRIMARY KEY AUTOINCREMENT,source_id TEXT NOT NULL,
            ts INTEGER NOT NULL,code TEXT NOT NULL,requested_cursor TEXT,
            next_cursor TEXT,dropped INTEGER,proof TEXT NOT NULL UNIQUE)''')


def ingest_batch(store, source, batch):
    """DMIT only. Reuse installed JournalStore; never rewrite its source module.

    The Publisher must serialize pulls for this source (its existing edge lock).
    consume_many commits evidence before cursor checkpoint: a crash may replay
    an already deduplicated event but can never acknowledge uncommitted evidence.
    Gaps are permanent, distinct from user violations, and clear cid contexts.
    """
    require(isinstance(source, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', source),
            'source_id_invalid')
    require(isinstance(batch, dict) and batch.get('schema') == 1
            and batch.get('namespace') == NAMESPACE and batch.get('unit') == UNIT,
            'edge_batch_scope_invalid')
    require(type(batch.get('scanned')) is int and 0 <= batch['scanned'] <= MAX_BATCH
            and isinstance(batch.get('events'), list) and len(batch['events']) <= MAX_BATCH
            and isinstance(batch.get('gaps'), list) and len(batch['gaps']) <= MAX_BATCH + 1,
            'edge_batch_size_invalid')
    require(batch.get('retention') == 'bounded_volatile_spool_not_complete_history'
            and type(batch.get('may_have_more')) is bool, 'edge_batch_metadata_invalid')
    valid_cursor(batch.get('requested_cursor'))
    valid_cursor(batch.get('next_cursor'))
    state = store.state(source)
    require((state or {}).get('cursor') == batch['requested_cursor'], 'edge_cursor_changed')
    _gap_schema(store)
    items = []
    for event in batch['events']:
        require(isinstance(event, dict) and type(event.get('index')) is int
                and 0 <= event['index'] < batch['scanned'], 'edge_event_invalid')
        entry = event.get('entry')
        require(isinstance(entry, dict) and entry.get('_SYSTEMD_UNIT') == UNIT
                and identity(entry), 'edge_evidence_scope_invalid')
        valid_cursor(entry.get('__CURSOR'), allow_none=False)
        text = message(entry)
        require(relevant(text), 'edge_evidence_kind_invalid')
        # Even the remote thin reader cannot promote arbitrary HIT evidence:
        # no verified quarantine is installed here; policy_valid is alwaysFalse.
        items.append((event['index'], 1, dict(entry, MESSAGE=canonical_evidence(text))))
    allowed_gaps = {'initial_history_boundary_unknown', 'resume_cursor_missing',
                    'cursor_rotated_during_read', 'journal_message_unavailable',
                    'journal_rate_limited', 'evidence_identity_missing', 'evidence_reply_budget'}
    for gap in batch['gaps']:
        require(isinstance(gap, dict) and gap.get('code') in allowed_gaps
                and type(gap.get('index')) is int and -1 <= gap['index'] < max(1, batch['scanned']),
                'edge_gap_invalid')
        items.append((gap['index'], 0, gap))
    inserted = 0
    pending = []
    for _index, kind, value in sorted(items, key=lambda row: (row[0], row[1])):
        if kind:
            pending.append((source, value, False))
            continue
        if pending:
            inserted += store.consume_many(pending)
            pending = []
        proof = hashlib.sha256(canonical([source, batch['requested_cursor'],
                                         batch['next_cursor'], value])).hexdigest()
        with store.db() as db:
            db.execute('DELETE FROM connection_context WHERE source_id=?', (source,))
            db.execute('''INSERT OR IGNORE INTO edge_journal_gaps
                (source_id,ts,code,requested_cursor,next_cursor,dropped,proof)
                VALUES(?,?,?,?,?,?,?)''', (source, int(time.time()), value['code'],
                batch['requested_cursor'], batch['next_cursor'], value.get('dropped'), proof))
    if pending:
        inserted += store.consume_many(pending)
    with store.db() as db:
        db.execute('''INSERT INTO journal_state(source_id,cursor,last_seen)
            VALUES(?,?,?) ON CONFLICT(source_id) DO UPDATE SET
            cursor=excluded.cursor,last_seen=excluded.last_seen''',
            (source, batch['next_cursor'], int(time.time())))
        gap_count = db.execute('SELECT COUNT(*) FROM edge_journal_gaps WHERE source_id=?', (source,)).fetchone()[0]
    store.health(source, policy={'observable': True, 'evidence': 'explicit-bt-reject',
                                 'unit': UNIT, 'namespace': NAMESPACE,
                                 'gap_total': gap_count, 'last_pull_had_gap': bool(batch['gaps']),
                                 'retention': batch['retention']})
    return {'inserted': inserted, 'cursor': batch['next_cursor'], 'gap_total': gap_count,
            'last_pull_had_gap': bool(batch['gaps']), 'may_have_more': batch['may_have_more']}


def sqlite_alert_source(source_id='lazycat-edge-confirmed'):
    """Candidate only; caller must preserve existing mail configuration."""
    require(bool(re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', source_id)), 'source_id_invalid')
    return {'id': source_id, 'type': 'sqlite', 'path': DEFAULT_DATABASE, 'poll_seconds': 1}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    read = sub.add_parser('read')
    read.add_argument('--cursor')
    read.add_argument('--limit', type=int, default=MAX_BATCH)
    sub.add_parser('configs')
    args = parser.parse_args()
    result = read_batch(args.cursor, limit=args.limit) if args.action == 'read' else config_candidates()
    print(canonical(result).decode('utf-8'))


if __name__ == '__main__':
    main()
