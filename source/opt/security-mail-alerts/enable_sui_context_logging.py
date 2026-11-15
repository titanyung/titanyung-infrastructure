#!/usr/bin/env python3
"""Guarded logging-only SUI context formatter enable/restore."""
import argparse
import copy
import hashlib
import json
import os
import sqlite3
import subprocess
import time
from pathlib import Path

from deploy_bt_policy import ready

DATABASE = '/usr/local/s-ui/db/s-ui.db'


def candidate(original):
    modified = copy.deepcopy(original)
    options = modified.setdefault('log', {})
    options.update(level='info', output='stdout', timestamp=True)
    # Installed SUI-X 1.5.11 rejects log.disable_color. ANSI journal byte arrays
    # are explicitly supported by the watcher instead.
    if 'disable_color' in options:
        raise ValueError('unsupported_log_field_present')
    assert {k: v for k, v in modified.items() if k != 'log'} == {k: v for k, v in original.items() if k != 'log'}
    return modified


def digest(raw):
    return hashlib.sha256(raw.encode() if isinstance(raw, str) else raw).hexdigest()


def run(host, ports, apply=False, restore=None):
    with sqlite3.connect(DATABASE, timeout=30) as db:
        before = db.execute("SELECT value FROM settings WHERE key='config'").fetchone()[0]
        if restore:
            folder = Path(restore).resolve()
            if folder.parent != Path('/var/backups') or not folder.name.startswith('sui-context-log-'):
                raise ValueError('exact_logging_backup_required')
            manifest = json.loads((folder / 'manifest.json').read_text())
            if digest(before) != manifest['new_sha256']:
                raise ValueError('config_changed_after_logging_release')
            raw = (folder / 'config-before.bin').read_bytes()
            target = raw.decode() if manifest['old_type'] == 'str' else raw
        else:
            after = candidate(json.loads(before))
            target = json.dumps(after, ensure_ascii=False, separators=(',', ':'))
            if isinstance(before, bytes):
                target = target.encode()
            if not apply:
                print('SUI_LOGGING_AUDIT_OK changes=log_only level=info stdout_context=yes')
                return
            folder = Path('/var/backups') / ('sui-context-log-' + host + '-' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()))
            folder.mkdir(mode=0o700, exist_ok=False)
            (folder / 'config-before.bin').write_bytes(before.encode() if isinstance(before, str) else before)
            (folder / 'manifest.json').write_text(json.dumps({'old_type': type(before).__name__,
                'old_sha256': digest(before), 'new_sha256': digest(target), 'scope': 'logging-only'}))
            for path in folder.iterdir():
                os.chmod(path, 0o600)
        changed = False
        try:
            db.execute('BEGIN IMMEDIATE')
            if db.execute("UPDATE settings SET value=? WHERE key='config' AND value=?", (target, before)).rowcount != 1:
                raise RuntimeError('config_changed_during_logging_update')
            db.commit(); changed = True
            subprocess.run(['systemctl', 'restart', 's-ui'], check=True, timeout=45)
            ready('s-ui', ports)
            print('SUI_CONTEXT_LOGGING_' + ('RESTORED' if restore else 'ENABLED') + ' host=' + host + ' backup=' + str(folder) + ' nonlogging_config_unchanged=yes')
        except BaseException:
            db.rollback()
            if changed:
                if db.execute("UPDATE settings SET value=? WHERE key='config' AND value=?", (before, target)).rowcount != 1:
                    raise RuntimeError('logging_rollback_conflict')
                db.commit()
                subprocess.run(['systemctl', 'restart', 's-ui'], check=True, timeout=45)
            raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', choices=('DMIT', 'BWH'), required=True)
    parser.add_argument('--ports', nargs='+', type=int, required=True)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--restore')
    args = parser.parse_args()
    run(args.host, args.ports, args.apply, args.restore)
