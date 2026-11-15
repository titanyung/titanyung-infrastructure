#!/usr/bin/env python3
"""Durable, generation-bound access worker. Never logs credentials or raw errors."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import signal
import time

from access_policy import bound_job_allowed
from identity import IdentityResolver, physical_client_id
from lifecycle import LifecycleStore, LostLease


def execute_one(store, resolver, *, store_path, worker_id='access-worker', factories=None):
    job = store.claim_job(worker_id, lease_seconds=900)
    if job is None:
        return False
    try:
        action = job['kind']
        if action not in {'revoke', 'restore'}:
            raise ValueError('invalid_worker_action')
        subject = resolver.by_client_id(job['client_id'])
        if subject.username != job['username'] or subject.client_id != job['client_id']:
            raise ValueError('worker_identity_binding_changed')
        guard = lambda name: name == subject.username and bound_job_allowed(
            name, subject.client_id, job['generation'], action, path=store_path)
        if not guard(subject.username):
            raise ValueError('worker_intent_superseded')
        if factories is None:
            from production_adapter import create_coordinator, create_restoration_coordinator
            factories = {'revoke': create_coordinator, 'restore': create_restoration_coordinator}
        keyword = 'deny_guard' if action == 'revoke' else 'restore_guard'
        coordinator = factories[action](**{keyword: guard},
            state_dir='/var/lib/submerge-user-access/runtime')
        result = getattr(coordinator, action)(subject.username,
            expected_client_id=physical_client_id(subject.client_id), generation=job['generation'])
        complete = result.get('status') == 'complete' and guard(subject.username)
        # An execution edge is confirmed only after its loaded process ACKs
        # the same authoritative cohort. Missing registry is an intentional
        # no-op for the pre-edge deployment and independent test fixtures.
        if complete and Path('/etc/submerge-edge/edges.json').is_file():
            import sys
            if '/opt/submerge-edge' not in sys.path:
                sys.path.insert(0, '/opt/submerge-edge')
            from edge_controller import synchronize_subject
            edge_result = synchronize_subject(subject.username,
                enabled=action == 'restore', generation=job['generation'])
            complete = edge_result['complete'] and guard(subject.username)
        store.finish_job(job['job_id'], job['lease_token'], succeeded=complete,
            **({} if complete else {'error_code': action + '_verification_pending'}))
        print(json.dumps({'event': action, 'client_id': subject.client_id,
            'generation': job['generation'], 'verified': complete}), flush=True)
    except LostLease:
        print(json.dumps({'event': 'superseded_job_ignored'}), flush=True)
    except Exception as error:
        # Detailed diagnostics remain only in the root-only adapter journals.
        code = type(error).__name__.lower()
        if not re.fullmatch(r'[a-z0-9_]{1,48}', code):
            code = 'executor_failure'
        try:
            store.finish_job(job['job_id'], job['lease_token'], succeeded=False,
                error_code='worker_' + code)
        except LostLease:
            pass
        print(json.dumps({'event': 'worker_retry', 'error_code': code}), flush=True)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--store', default='/var/lib/submerge-user-access/control.db')
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    store = LifecycleStore(args.store)
    resolver = IdentityResolver()
    running = True
    def stop(*_):
        nonlocal running
        running = False
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while running:
        worked = execute_one(store, resolver, store_path=args.store)
        if args.once:
            break
        if not worked:
            time.sleep(1)


if __name__ == '__main__':
    main()
