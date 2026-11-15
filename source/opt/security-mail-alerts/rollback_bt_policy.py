#!/usr/bin/env python3
"""Restore only this release's SUI route/outbound + renderer, preserving users."""
import argparse
import json
import os
import sqlite3
import subprocess
from pathlib import Path

from bt_policy import TAG, OUTBOUND, apply_policy
from deploy_bt_policy import encoded, patch_renderer


def rollback(backup, renderer, unit):
    backup, renderer = Path(backup).resolve(), Path(renderer).resolve()
    if backup.parent != Path('/var/backups') or not backup.name.startswith('security-bt-'):
        raise ValueError('exact_release_backup_required')
    old_renderer = (backup / 'renderer.py').read_text()
    if renderer.read_text() != patch_renderer(old_renderer):
        raise ValueError('renderer_changed_after_release')
    old = sqlite3.connect('file:' + str(backup / 's-ui.sqlite') + '?mode=ro', uri=True)
    try:
        old_raw = old.execute("SELECT value FROM settings WHERE key='config'").fetchone()[0]
        old_outbound = old.execute('SELECT type,options FROM outbounds WHERE tag=?', (TAG,)).fetchone()
    finally:
        old.close()
    expected = encoded(apply_policy(json.loads(old_raw), add_outbound=False))
    if isinstance(old_raw, bytes):
        expected = expected.encode()
    with sqlite3.connect('/usr/local/s-ui/db/s-ui.db', timeout=30) as db:
        db.execute('BEGIN IMMEDIATE')
        if db.execute("SELECT value FROM settings WHERE key='config'").fetchone()[0] != expected:
            raise ValueError('sui_config_changed_after_release')
        row = db.execute('SELECT type,options FROM outbounds WHERE tag=?', (TAG,)).fetchone()
        if not row or dict(json.loads(row[1]), type=row[0], tag=TAG) != OUTBOUND:
            raise ValueError('quarantine_outbound_changed_after_release')
        db.execute("UPDATE settings SET value=? WHERE key='config'", (old_raw,))
        if not old_outbound:
            db.execute('DELETE FROM outbounds WHERE tag=?', (TAG,))
        db.commit()
    temporary = renderer.with_name(renderer.name + '.bt-rollback')
    temporary.write_text(old_renderer)
    os.chmod(temporary, renderer.stat().st_mode & 0o777)
    os.replace(temporary, renderer)
    subprocess.run(['systemctl', 'restart', unit], check=True, timeout=45)
    subprocess.run(['systemctl', 'restart', 's-ui'], check=True, timeout=45)
    subprocess.run(['systemctl', 'disable', '--now', 'security-confirmed-events', 'security-bt-quarantine'], check=True, timeout=30)
    print('BT_POLICY_ROLLBACK_COMPLETE users_unchanged=yes evidence_db_preserved=yes')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--backup', required=True)
    parser.add_argument('--renderer', required=True)
    parser.add_argument('--unit', required=True)
    args = parser.parse_args()
    rollback(args.backup, args.renderer, args.unit)
