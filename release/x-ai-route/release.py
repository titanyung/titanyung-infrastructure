#!/usr/bin/env python3
"""Guarded DMIT X-to-AI release. Run only on the audited DMIT host."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time

STAGE = Path('/root/x-ai-route-20261114/stage')
CANDIDATE = STAGE / 'candidate'
BACKUPS = Path('/root/x-ai-route-20261114/backups')
RECEIPT = Path('/var/lib/submerge-topology/full-layer-catchup.json')
EVIDENCE = Path('/var/lib/submerge-topology/full-layer-evidence.json')
PLAN = Path('/etc/submerge-topology/network-plan.json')
RUNTIME = Path('/run/dmit-direct-staging/config.json')
# The stage directory is never importable; it contains untrusted candidate bytes.
sys.path[:0] = ['/opt/submerge-routing', '/opt/submerge-topology',
                '/opt/submerge-user-access', '/opt/submerge-edge',
                '/opt/submerge-client-policy', '/opt/submerge']
OLD = {
    'server_route_policy.py': 'd011ae889331bd4a4a0835d01e64d95e1974a604927543b8ee6ab8ae5c64389b',
    'client_policy.py': '4b1240e74c26f485e0c2e7da75333b3a31f1a274cc55765f33e37f3363c127e4',
}
NEW = {
    'server_route_policy.py': 'd6f0c64f4e61864ff1db7b92552ccf76696a421a4c7efa0aab5ad5dda74a34d3',
    'client_policy.py': 'ec5e482b2c11ff1e1e4426e748797aa904c6cd6d31d4166e21213d97d9a9fce0',
}
PATHS = {
    'server_route_policy.py': tuple(Path(root) / 'server_route_policy.py' for root in (
        '/opt/submerge-routing', '/opt/submerge-topology',
        '/opt/submerge-user-access', '/opt/submerge-client-policy')),
    'client_policy.py': tuple(Path(root) / 'client_policy.py' for root in (
        '/opt/submerge', '/opt/submerge-topology',
        '/opt/submerge-user-access', '/opt/submerge-client-policy')),
}
TIMERS = ('dmit-routing-reconcile.timer', 'subscription-user-enrollment.timer')
WRITERS = ('submerge-access-worker.service', 'dmit-ai-edge-control.service',
           'dmit-main-business-health.service', 'paoluz-qualification.service',
           'paoluz-authority-reader.service')
WEB = ('submerge.service', 'submerge-user-access.service')
X_SUFFIXES = ('x.com', 'twitter.com', 'twimg.com', 't.co')
AI_GROUP = 'chatgpt、claude、google（不含youtube）'


def need(value, code):
    if not value:
        raise RuntimeError(code)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def command(*args, timeout=35):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout)
    need(result.returncode == 0, 'command_failed_' + Path(args[0]).name.replace('-', '_'))
    return result.stdout


def active(unit):
    return subprocess.run(['systemctl', 'is-active', '--quiet', unit],
                          stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, timeout=6).returncode == 0


def jobs_idle():
    with sqlite3.connect('file:/var/lib/submerge-user-access/control.db?mode=ro',
                         uri=True, timeout=3) as db:
        unfinished = db.execute("SELECT count(*) FROM revocation_jobs WHERE state!='done'").fetchone()[0]
        leased = db.execute('SELECT count(*) FROM revocation_jobs '
                            'WHERE lease_until IS NOT NULL AND lease_until>?',
                            (int(time.time()),)).fetchone()[0]
    need(unfinished == leased == 0, 'access_recovery_not_idle')


def receipt_current():
    from release_reconcile import authority_from_boot, load, receipt_for
    authority, _ = authority_from_boot()
    snapshot = authority.snapshot()
    need(load(RECEIPT) == receipt_for(snapshot), 'full_layer_receipt_not_current')
    need(snapshot['plan']['server_policy']['id'] == 'dmit-domain-routing-20261109-v2',
         'routing_revision_changed')
    return snapshot


def check():
    need(os.geteuid() == 0 and os.uname().nodename == 'DMIT-KQpKFYCIGs',
         'unexpected_host_or_user')
    need(STAGE.is_dir() and not STAGE.is_symlink() and stat.S_IMODE(STAGE.stat().st_mode) == 0o700,
         'private_stage_required')
    need(CANDIDATE.is_dir() and not CANDIDATE.is_symlink() and
         stat.S_IMODE(CANDIDATE.stat().st_mode) == 0o700, 'private_candidate_required')
    for name, paths in PATHS.items():
        candidate = CANDIDATE / name
        need(candidate.is_file() and not candidate.is_symlink() and sha(candidate) == NEW[name],
             'candidate_sha_changed_' + name)
        compile(candidate.read_bytes(), name, 'exec')
        expected_mode = 0o600 if name == 'client_policy.py' else 0o644
        for path in paths:
            need(path.is_file() and not path.is_symlink() and sha(path) == OLD[name] and
                 path.stat().st_uid == 0 and stat.S_IMODE(path.stat().st_mode) == expected_mode,
                 'production_baseline_changed_' + name)
    for path in (RECEIPT, PLAN, RUNTIME):
        need(path.is_file() and not path.is_symlink() and path.stat().st_uid == 0,
             'private_authority_file_changed')
    for unit in ('dmit-direct-staging.service', 'dmit-routing-raw-guard.service',
                 *WEB, *TIMERS, *WRITERS):
        need(active(unit), 'required_unit_inactive_' + unit.replace('.', '_').replace('-', '_'))
    for unit in ('dmit-routing-reconcile.service', 'subscription-user-enrollment.service'):
        need(not active(unit), 'periodic_writer_busy_' + unit.replace('.', '_').replace('-', '_'))
    jobs_idle()
    snapshot = receipt_current()
    print('x_ai_preflight=ok paths=8 plan_sha256=' + snapshot['source_plan_sha256'], flush=True)
    return snapshot


def atomic(path, raw):
    old = path.stat()
    fd, temporary = tempfile.mkstemp(prefix='.x-ai-route-', dir=str(path.parent))
    try:
        os.fchmod(fd, stat.S_IMODE(old.st_mode))
        os.fchown(fd, old.st_uid, old.st_gid)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def stop_writers():
    prior = {unit: active(unit) for unit in (*TIMERS, *WRITERS)}
    try:
        for unit in TIMERS:
            if prior[unit]:
                command('systemctl', 'stop', unit, timeout=25)
        for unit in ('dmit-routing-reconcile.service', 'subscription-user-enrollment.service'):
            need(not active(unit), 'periodic_writer_became_active')
        for unit in WRITERS:
            if prior[unit]:
                command('systemctl', 'stop', unit,
                        timeout=185 if unit == 'submerge-access-worker.service' else 30)
        jobs_idle()
        return prior
    except BaseException:
        resume_writers(prior)
        raise


def resume_writers(prior):
    failures = []
    for unit, was_active in reversed(list(prior.items())):
        if was_active:
            try:
                command('systemctl', 'start', unit, timeout=35)
            except Exception:
                failures.append(unit)
    need(not failures, 'writer_resume_needs_review')


def assert_x_runtime(runtime, expect):
    rules = runtime['route']['rules']
    youtube = [i for i, row in enumerate(rules)
               if row.get('rule_set') == ['server-youtube'] and
               row.get('outbound') == 'business-other']
    need(len(youtube) == 1, 'youtube_runtime_exception_missing')
    fallback = [i for i, row in enumerate(rules)
                if row.get('network') == ['tcp'] and row.get('outbound') == 'business-other']
    need(bool(fallback), 'runtime_tcp_fallback_missing')
    tags = [row['tag'] for row in runtime['inbounds']]
    need(bool(tags) and len(tags) == len(set(tags)), 'managed_inbounds_invalid')
    x_rows = [row for row in rules if row.get('domain_suffix') == list(X_SUFFIXES)]
    need(len(x_rows) == (len(tags) if expect == 'new' else 0),
         'unexpected_x_runtime_rule_count')
    for tag in tags:
        key = ('ai-lazycat' if tag in ('dmit-starhub', 'mobile-dmit-starhub') else
               'ai-singtel' if tag in ('dmit-singtel', 'mobile-dmit-singtel') else
               'ai-mobile' if tag.startswith('mobile-') else 'ai-desktop')
        target = 'business-' + key
        found = [i for i, row in enumerate(rules)
                 if row.get('inbound') == [tag] and
                 row.get('domain_suffix') == list(X_SUFFIXES) and
                 row.get('outbound') == target]
        if expect == 'new':
            need(len(found) == 1 and youtube[0] < found[0] < fallback[-1],
                 'x_runtime_rule_missing_' + tag.replace('-', '_'))
        else:
            need(not found, 'old_runtime_contains_x_rule_' + tag.replace('-', '_'))


def native(expect):
    from release_reconcile import (authority_from_boot, wait_current_main_ack,
                                   BINARY_SHA, atomic as private_atomic,
                                   write_json, systemctl, native_check)
    from main_policy_cas import Transaction
    from policy_inputs import policy
    from main_guard import ActualMainGuard
    from bootstrap_revision import durable_receipt, assert_fresh_boundary
    from raw_guard_install import apply as apply_raw_guard
    from prepared_restart import prepared_restart
    authority, boot = authority_from_boot()
    plan = authority.snapshot()['plan']
    assert_fresh_boundary(plan, int(time.time()))
    tx = Transaction(authority, rule_set_loader=policy.load_rule_sets)
    prepared = tx.prepare(plan)
    assert_x_runtime(prepared['runtime'], expect)
    native_check(prepared['runtime'])
    guard = ActualMainGuard(authority, rule_set_loader=policy.load_rule_sets,
                            expected_binary_sha256=BINARY_SHA)
    with tx.checked_install(prepared) as payload:
        private_atomic(PLAN, payload['plan_bytes'])
        private_atomic(RUNTIME, payload['runtime_bytes'])
        write_json(boot['durable_receipt'], durable_receipt(prepared))
        apply_raw_guard(plan)
        expected = {'source_plan_sha256': prepared['manifest']['plan_sha256'],
                    'source_runtime_sha256': prepared['manifest']['runtime_sha256'],
                    'cohort_sha256': prepared['manifest']['cohort_sha256'],
                    'desired_token_sha256': prepared['manifest']['desired_token_sha256']}
        with prepared_restart(authority):
            systemctl('restart', 'dmit-routing-raw-guard.service', timeout=30)
            systemctl('restart', 'dmit-direct-staging.service', timeout=35)
            proof = wait_current_main_ack(authority, guard, expected, timeout=25)
        need(proof.get('verified') is True, 'main_runtime_ack_missing')
    print('x_ai_main_runtime_ack=ok', flush=True)


def public_check(expect='new'):
    import yaml
    for user in ('wrt', 'hm15pro%2B'):
        url = 'https://node.titanyung.click:31877/sub/' + user + '?format=clash'
        # Type=simple reports active before the gateway binds 31877. Retry only
        # transport errors and known temporary HTTP statuses; never retry a
        # valid response whose YAML or routing rules fail validation.
        deadline = time.monotonic() + 30
        while True:
            try:
                result = subprocess.run(
                    ['curl', '--resolve', 'node.titanyung.click:31877:179.255.136.79',
                     '--max-time', '6', '-fsS', '--write-out', '%{http_code}', '--', url],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, timeout=8)
                status = int(result.stdout[-3:]) if (len(result.stdout) >= 3 and
                                                  result.stdout[-3:].isdigit()) else 0
                returncode = result.returncode
                raw = result.stdout[:-3] if status else b''
            except subprocess.TimeoutExpired:
                status, returncode, raw = 0, 28, b''
            if returncode == 0 and status == 200:
                break
            temporary = returncode in (7, 28, 35, 52, 55, 56) or status in (408, 429, 500, 502, 503, 504)
            remaining = deadline - time.monotonic()
            if not temporary or remaining <= 0:
                raise RuntimeError('public_fetch_http_' + str(status) if status else
                                   'public_fetch_curl_' + str(returncode))
            time.sleep(min(2, remaining))
        document = yaml.safe_load(raw)
        rules = document.get('rules', [])
        x_rules = ['DOMAIN-SUFFIX,' + suffix + ',' + AI_GROUP for suffix in X_SUFFIXES]
        need(all(rule in rules for rule in x_rules) if expect == 'new' else
             all(rule not in rules for rule in x_rules),
             'public_x_ai_rule_' + ('missing' if expect == 'new' else 'unexpected'))
        need('GEOSITE,youtube,非中国大陆的其他' in rules,
             'youtube_exception_changed')
        need(len([row for row in document.get('proxy-groups', [])
                  if row.get('name') == AI_GROUP]) == 1, 'ai_group_missing')
    print('x_ai_public_samples=ok', flush=True)


def backup():
    BACKUPS.mkdir(mode=0o700, parents=True, exist_ok=True)
    folder = BACKUPS / (time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + str(os.getpid()))
    folder.mkdir(mode=0o700)
    entries = []
    for name, paths in PATHS.items():
        for path in paths:
            target = folder / (str(len(entries)) + '.py')
            shutil.copy2(path, target)
            need(sha(target) == OLD[name], 'module_backup_changed')
            entries.append({'name': name, 'path': str(path), 'backup': target.name,
                            'old_sha256': sha(path), 'new_sha256': NEW[name]})
    for label, path in (('receipt', RECEIPT), ('plan', PLAN), ('runtime', RUNTIME)):
        target = folder / (label + '.json')
        shutil.copy2(path, target)
        target.chmod(0o600)
    manifest = folder / 'manifest.json'
    manifest.write_text(json.dumps(entries, indent=2), encoding='utf-8')
    manifest.chmod(0o600)
    return folder, entries


def backup_still_current(folder, entries):
    for item in entries:
        need(sha(folder / item['backup']) == item['old_sha256'] and
             sha(item['path']) == item['old_sha256'], 'module_changed_after_backup')
    for label, path in (('receipt', RECEIPT), ('plan', PLAN), ('runtime', RUNTIME)):
        need(path.is_file() and sha(path) == sha(folder / (label + '.json')),
             'authority_changed_after_backup_' + label)


def restore_modules(folder, entries):
    for item in entries:
        path = Path(item['path'])
        need(sha(path) == item['new_sha256'], 'rollback_source_changed')
        source = folder / item['backup']
        need(sha(source) == item['old_sha256'], 'rollback_backup_changed')
        atomic(path, source.read_bytes())


def rollback_check(folder, entries):
    from release_reconcile import (authority_from_boot, fingerprint,
                                   wait_current_main_ack, BINARY_SHA)
    from main_guard import ActualMainGuard
    from policy_inputs import policy
    for item in entries:
        need(sha(item['path']) == item['old_sha256'], 'rollback_module_mismatch')
    need(sha(PLAN) == sha(folder / 'plan.json') and
         sha(RUNTIME) == sha(folder / 'runtime.json'),
         'rollback_authority_mismatch')
    snapshot = receipt_current()
    authority, _ = authority_from_boot()
    guard = ActualMainGuard(authority, rule_set_loader=policy.load_rule_sets,
                            expected_binary_sha256=BINARY_SHA)
    proof = wait_current_main_ack(authority, guard, fingerprint(snapshot), timeout=25)
    need(proof.get('verified') is True, 'rollback_main_ack_missing')
    need(all(active(unit) for unit in WEB), 'rollback_web_unit_inactive')
    public_check(expect='old')


def apply():
    check()
    folder, entries = backup()
    prior = stop_writers()
    changed = []
    receipt_moved = False
    stale = RECEIPT.with_name(RECEIPT.name + '.x-ai-' + folder.name + '.stale')
    try:
        from release_reconcile import release_lock
        with release_lock():
            backup_still_current(folder, entries)
            need(not stale.exists(), 'stale_receipt_path_exists')
            for item in entries:
                path = Path(item['path'])
                need(sha(path) == item['old_sha256'], 'source_changed_during_pause')
                candidate = CANDIDATE / item['name']
                need(sha(candidate) == NEW[item['name']], 'candidate_changed_during_pause')
                atomic(path, candidate.read_bytes())
                changed.append(item)
            command(sys.executable, str(Path(__file__)), '--mode', 'native',
                    '--expect', 'new', timeout=130)
            for unit in WEB:
                command('systemctl', 'restart', unit, timeout=40)
            for unit in ('dmit-direct-staging.service', *WEB):
                need(active(unit), 'post_install_unit_inactive')
            public_check()
            need(sha(RECEIPT) == sha(folder / 'receipt.json'),
                 'receipt_changed_during_install')
            os.replace(RECEIPT, stale)
            receipt_moved = True
            (folder / 'stale-receipt-path.txt').write_text(str(stale), encoding='ascii')
        resume_writers(prior)
        print('x_ai_installed=ok backup=' + str(folder), flush=True)
        print('x_ai_next=run_dmit_routing_reconcile_then_verify', flush=True)
    except BaseException as error:
        rollback_ok = False
        if not receipt_moved:
            if not changed:
                rollback_ok = True
                print('x_ai_preinstall_abort=no_modules_changed', flush=True)
            else:
                try:
                    from release_reconcile import release_lock
                    with release_lock():
                        restore_modules(folder, changed)
                        command(sys.executable, str(Path(__file__)), '--mode', 'native',
                                '--expect', 'old', timeout=130)
                        for unit in WEB:
                            command('systemctl', 'restart', unit, timeout=40)
                        rollback_check(folder, entries)
                    rollback_ok = True
                    print('x_ai_rollback=restored_before_commit', flush=True)
                except BaseException:
                    print('x_ai_rollback=needs_manual_review backup=' + str(folder), flush=True)
        elif receipt_moved:
            print('x_ai_release=forward_repair_required backup=' + str(folder), flush=True)
        if rollback_ok:
            try:
                resume_writers(prior)
            except BaseException:
                print('x_ai_writer_resume=needs_manual_review', flush=True)
        else:
            print('x_ai_writers=remain_paused_for_manual_review', flush=True)
        raise error


def verify(backup_name):
    from release_reconcile import authority_from_boot, fingerprint, load, receipt_for
    need(bool(backup_name) and re.fullmatch(r'[0-9]{8}T[0-9]{6}Z-[0-9]+', backup_name),
         'explicit_backup_name_required')
    folder = BACKUPS / backup_name
    need(folder.is_dir() and not folder.is_symlink() and folder.parent == BACKUPS,
         'release_backup_missing')
    marker = folder / 'stale-receipt-path.txt'
    need(marker.is_file() and not marker.is_symlink(), 'release_commit_marker_missing')
    stale = RECEIPT.with_name(RECEIPT.name + '.x-ai-' + backup_name + '.stale')
    need(marker.read_text(encoding='ascii') == str(stale) and stale.is_file() and
         not stale.is_symlink() and sha(stale) == sha(folder / 'receipt.json'),
         'stale_receipt_backup_changed')
    need(RECEIPT.is_file() and EVIDENCE.is_file() and
         RECEIPT.stat().st_mtime_ns > marker.stat().st_mtime_ns and
         EVIDENCE.stat().st_mtime_ns > marker.stat().st_mtime_ns,
         'fresh_full_layer_receipt_missing')
    authority, _ = authority_from_boot()
    snapshot = authority.snapshot()
    need(load(RECEIPT) == receipt_for(snapshot), 'new_full_layer_receipt_mismatch')
    evidence = load(EVIDENCE)
    need(evidence.get('authority') == fingerprint(snapshot) and
         evidence.get('main_ack', {}).get('verified') is True and
         all(evidence.get(key, {}).get('verified') is True
             for key in ('clients', 'edges', 'statistics')),
         'full_layer_evidence_incomplete')
    for name, paths in PATHS.items():
        for path in paths:
            need(sha(path) == NEW[name], 'installed_module_changed')
    for unit in ('dmit-direct-staging.service', *WEB, *TIMERS, *WRITERS):
        need(active(unit), 'post_release_unit_inactive')
    need(not active('dmit-routing-reconcile.service'), 'reconcile_still_running')
    public_check()
    print('x_ai_release_verified=ok', flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', required=True,
                        choices=('check', 'apply', 'native', 'verify'))
    parser.add_argument('--backup', help='Exact backup folder name printed by apply; verify mode only')
    parser.add_argument('--expect', choices=('old', 'new'), help='Expected native rules; native mode only')
    args = parser.parse_args()
    if args.mode == 'native':
        need(args.expect is not None, 'explicit_native_expectation_required')
        native(args.expect)
    elif args.mode == 'check':
        check()
    elif args.mode == 'apply':
        apply()
    else:
        verify(args.backup)


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        code = str(error)
        safe = code if re.fullmatch('[a-zA-Z0-9_]{1,100}', code) else type(error).__name__
        print('x_ai_safe_error=' + safe, flush=True)
        raise SystemExit(1)
