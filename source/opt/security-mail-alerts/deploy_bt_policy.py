#!/usr/bin/env python3
"""Guarded narrow SUI + dedicated-renderer policy release, with rollback."""
import argparse
import ast
import hashlib
import json
import os
import py_compile
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path

from bt_policy import TAG, OUTBOUND, apply_policy, read_policy


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))


def patch_renderer(raw):
    if 'security_bt_policy_hook' in raw:
        return raw
    tree = ast.parse(raw)
    function = next(x for x in tree.body if isinstance(x, ast.FunctionDef) and x.name == 'build_config')
    returns = [n for n in ast.walk(function) if isinstance(n, ast.Return) and isinstance(n.value, ast.Name) and n.value.id == 'config']
    if len(returns) != 1:
        raise ValueError('renderer_config_return_ambiguous')
    line = returns[0]
    lines = raw.splitlines(True)
    indent = ' ' * line.col_offset
    lines[line.lineno - 1:line.lineno - 1] = [indent + '# security_bt_policy_hook\n',
        indent + 'import sys\n', indent + "sys.path.insert(0, '/opt/security-mail-alerts')\n",
        indent + 'from bt_policy import apply_policy\n', indent + 'config = apply_policy(config)\n']
    candidate = ''.join(lines)
    ast.parse(candidate)
    return candidate


def command(*args, timeout=45):
    environment = os.environ.copy()
    # SUI's embedded core accepts its existing legacy DNS resolver fields.
    # Isolated 1.14 checker needs this compatibility opt-in for that preexisting
    # config. This does not modify a service environment or any DNS setting.
    environment['ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER'] = 'true'
    result = subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout, env=environment)
    if result.returncode:
        raise RuntimeError('command_failed_' + Path(args[0]).name)


def ready(unit, ports):
    for _ in range(30):
        if not subprocess.run(['systemctl', 'is-active', '--quiet', unit], timeout=10).returncode:
            try:
                for port in ports:
                    with socket.create_connection(('127.0.0.1', port), timeout=1):
                        pass
                return
            except OSError:
                pass
        time.sleep(1)
    raise RuntimeError('service_not_ready_' + unit)


def main(args):
    db_path = '/usr/local/s-ui/db/s-ui.db'
    renderer = Path(args.renderer)
    original_renderer = renderer.read_text()
    new_renderer = patch_renderer(original_renderer)
    with sqlite3.connect(db_path, timeout=30) as db:
        original_raw = db.execute("SELECT value FROM settings WHERE key='config'").fetchone()[0]
        original = json.loads(original_raw)
        candidate = apply_policy(original, add_outbound=False)
        new_raw = encoded(candidate)
        if isinstance(original_raw, bytes):
            new_raw = new_raw.encode()
        existing = db.execute('SELECT type,options FROM outbounds WHERE tag=?', (TAG,)).fetchone()
        if existing and dict(json.loads(existing[1]), type=existing[0], tag=TAG) != OUTBOUND:
            raise ValueError('existing_quarantine_outbound_conflict')
        # Static-check every actual stored outbound and the resulting complete
        # route. Check never starts inbounds or touches listener ports.
        check = json.loads(new_raw)
        check['outbounds'] = [dict(json.loads(options), type=kind, tag=tag)
                              for kind, tag, options in db.execute('SELECT type,tag,options FROM outbounds')]
        if not existing:
            check['outbounds'].append(OUTBOUND)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as handle:
            os.chmod(handle.name, 0o600)
            json.dump(check, handle)
            check_path = handle.name
        try:
            command(args.binary, 'check', '-c', check_path)
        finally:
            os.unlink(check_path)
        if not args.apply:
            print('BT_POLICY_AUDIT_OK renderer_patch=' + str(new_renderer != original_renderer) + ' old_bt_reject_retained=yes')
            return
        backup = Path('/var/backups') / ('security-bt-' + args.host + '-' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()))
        backup.mkdir(mode=0o700, exist_ok=False)
        with sqlite3.connect(backup / 's-ui.sqlite') as target:
            db.backup(target)
        os.chmod(backup / 's-ui.sqlite', 0o600)
        (backup / 'renderer.py').write_text(original_renderer)
        os.chmod(backup / 'renderer.py', 0o600)
        changed_db = changed_renderer = False
        try:
            db.execute('BEGIN IMMEDIATE')
            if db.execute("SELECT value FROM settings WHERE key='config'").fetchone()[0] != original_raw:
                raise RuntimeError('sui_config_changed_during_plan')
            if not existing:
                options = {k: v for k, v in OUTBOUND.items() if k not in ('type', 'tag')}
                db.execute('INSERT INTO outbounds(type,tag,options) VALUES(?,?,?)', ('socks', TAG, encoded(options).encode()))
            db.execute("UPDATE settings SET value=? WHERE key='config'", (new_raw,))
            db.commit(); changed_db = True
            if renderer.read_text() != original_renderer:
                raise RuntimeError('renderer_changed_during_plan')
            temporary = renderer.with_name(renderer.name + '.bt-candidate')
            temporary.write_text(new_renderer)
            os.chmod(temporary, renderer.stat().st_mode & 0o777)
            py_compile.compile(str(temporary), doraise=True)
            os.replace(temporary, renderer); changed_renderer = True
            command('/usr/bin/python3', str(renderer))
            command(args.binary, 'check', '-c', args.runtime)
            command('systemctl', 'restart', args.unit)
            ready(args.unit, args.runtime_ports)
            command('systemctl', 'restart', 's-ui')
            ready('s-ui', args.sui_ports)
            read_policy({'policy_sqlite': db_path})
            read_policy({'policy_path': args.runtime})
            print('BT_POLICY_DEPLOYED host=' + args.host + ' backup=' + str(backup) + ' persistent_sui=yes persistent_renderer=yes old_bt_reject_retained=yes')
        except BaseException:
            db.rollback()
            if changed_renderer and renderer.read_text() == new_renderer:
                renderer.write_text(original_renderer)
                command('systemctl', 'restart', args.unit)
            if changed_db:
                db.execute('BEGIN IMMEDIATE')
                if db.execute("SELECT value FROM settings WHERE key='config'").fetchone()[0] != new_raw:
                    raise RuntimeError('rollback_conflict_sui_config_changed')
                db.execute("UPDATE settings SET value=? WHERE key='config'", (original_raw,))
                if not existing:
                    db.execute('DELETE FROM outbounds WHERE tag=?', (TAG,))
                db.commit()
                command('systemctl', 'restart', 's-ui')
            print('BT_POLICY_ROLLED_BACK host=' + args.host)
            raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True, choices=('DMIT', 'BWH'))
    parser.add_argument('--renderer', required=True)
    parser.add_argument('--runtime', required=True)
    parser.add_argument('--unit', required=True)
    parser.add_argument('--runtime-ports', type=int, nargs='+', required=True)
    parser.add_argument('--sui-ports', type=int, nargs='+', required=True)
    parser.add_argument('--binary', default='/root/lazycat-test-config/sing-box')
    parser.add_argument('--apply', action='store_true')
    arguments = parser.parse_args()
    try:
        main(arguments)
    except Exception as exc:
        # Do not print exceptions containing database/config secrets.
        print('BT_POLICY_FAILED reason=' + (str(exc) if isinstance(exc, (ValueError, RuntimeError)) else type(exc).__name__))
        raise SystemExit(1)
