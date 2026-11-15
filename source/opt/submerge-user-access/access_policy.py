"""Fail-closed read gates shared by profile delivery, admission and rendering."""
from contextlib import closing
import os
from pathlib import Path
import sqlite3

DEFAULT_DB = '/var/lib/submerge-user-access/control.db'
REVOCATION_STATES = frozenset({'purge_issued', 'revoking', 'revoked'})
RESTORATION_STATES = frozenset({'restore_pending', 'restoring'})


def policy_for_name(name, path=None):
    if not isinstance(name, str) or not name:
        raise ValueError('invalid_access_identity')
    path = Path(path or os.environ.get('USER_ACCESS_CONTROL_DB', DEFAULT_DB))
    if not path.is_file() or path.is_symlink():
        raise RuntimeError('access_registry_unavailable')
    with closing(sqlite3.connect(path.resolve().as_uri()+'?mode=ro', uri=True, timeout=3)) as db:
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA query_only=ON')
        row = db.execute('SELECT client_id,username,generation,state FROM subjects WHERE username=?', (name,)).fetchone()
    return dict(row) if row is not None else None


def admission_allowed(name, path=None):
    row = policy_for_name(name, path)
    return row is None or row['state'] in {'active', 'armed'}


def require_admission(name, path=None):
    if not admission_allowed(name, path):
        raise PermissionError('subscription_and_proxy_disabled')


def render_allowed(name, path=None):
    # A bound restore worker must load credentials for its positive probes
    # before delivery/admission is unlocked. No ordinary enrollment may do so.
    row = policy_for_name(name, path)
    return row is None or row['state'] in {'active', 'armed', 'restore_pending', 'restoring'}


def bound_job_allowed(name, client_id, generation, action, path=None):
    if action not in {'revoke', 'restore'} or type(generation) is not int or generation <= 0:
        return False
    row = policy_for_name(name, path)
    states = REVOCATION_STATES if action == 'revoke' else RESTORATION_STATES
    return bool(row and row['client_id'] == str(client_id) and row['generation'] == generation
                and row['state'] in states)
