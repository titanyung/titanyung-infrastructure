#!/usr/bin/env python3
"""Consistent independent backups, with no retention deletion of audit history."""
from datetime import datetime, timezone
from pathlib import Path
import os
import sqlite3


def backup(source, destination):
    source, destination = Path(source), Path(destination)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = destination.with_suffix('.pending')
    with sqlite3.connect(source.resolve().as_uri() + '?mode=ro', uri=True) as src:
        with sqlite3.connect(temporary) as dst:
            src.backup(dst)
            if dst.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise RuntimeError('backup_integrity_failed')
    os.chmod(temporary, 0o600)
    os.replace(temporary, destination)


if __name__ == '__main__':
    os.umask(0o077)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    for name in ('control.db', 'admin-ui.sqlite3'):
        source = Path('/var/lib/submerge-user-access') / name
        if source.exists():
            backup(source, Path('/var/backups/submerge-user-access') / stamp / name)

    source = Path('/var/lib/submerge-security-center/audit.sqlite3')
    if source.exists():
        backup(source, Path('/var/backups/submerge-security-center') / stamp / 'audit.sqlite3')
