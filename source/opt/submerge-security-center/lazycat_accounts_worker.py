#!/usr/bin/env python3
"""One DMIT worker: observe LC status; execute only explicit durable requests.

Uses the existing coordinator lock, native authority, pinned SSH transport and
Publisher generation/ack protocol.  No S-UI flag or DMIT runtime is changed.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import sys
import time

from lazycat_accounts import (AccountError, AccountService, EDGE_ID, MasterAuthority,
    Store, canonical, error_code, need, validate_loaded)


def native_reader():
    from network_runtime import load_network_plan, validate_loaded_server_policy
    from edge_bundle import _cohort
    path = Path('/run/dmit-direct-staging/config.json')
    raw = path.read_bytes()
    document = json.loads(raw)
    validate_loaded_server_policy(document, load_network_plan())
    cohort = _cohort([row for row in document['inbounds'] if row.get('type') == 'anytls'])
    names = sorted(cohort['usernames'])
    return {'usernames': names, 'sha256': hashlib.sha256(raw).hexdigest()}


def lazycat_edge(registry_reader):
    rows = [row for row in registry_reader() if row.get('edge_id') == EDGE_ID]
    need(len(rows) == 1 and rows[0].get('enabled') is True
         and rows[0].get('execution') != 'local_authority' and rows[0].get('scope') == 'ai',
         'lazycat_registry_binding_invalid')
    return rows[0]


class FencedAuthority:
    def __init__(self, base, master, snapshot, subject, *, lease_guard=None):
        self.base, self.master, self.snapshot, self.subject = base, master, snapshot, subject
        self.lease_guard = lease_guard

    def check(self):
        if self.lease_guard is not None:
            self.lease_guard()
        current = self.master.snapshot()
        need(current['ready'] and current['token'] == self.snapshot['token'],
             'master_authority_superseded')
        return current

    def fingerprint(self, edge):
        self.check()
        # Preserve the background coordinator's fingerprint format. Changing it
        # here would make the normal Publisher unnecessarily republish/restart
        # an otherwise identical cohort immediately after every manual request.
        return self.base.fingerprint(edge)

    @property
    def plan(self):
        # V4 Publisher reads the plan only for an explicitly failed owned pool.
        # Expose this one read-only authority input, keeping the same fence.
        self.check()
        return self.base.plan

    def build(self, edge, generation, *, bootstrap_health_proof=None):
        self.check()
        # Preserve the legacy no-keyword call when there is no V4 proof.
        bundle = (self.base.build(edge, generation,
                    bootstrap_health_proof=bootstrap_health_proof)
                  if bootstrap_health_proof is not None
                  else self.base.build(edge, generation))
        need(sorted(bundle.manifest['accounts']['usernames']) == self.snapshot['usernames'],
             'bundle_master_cohort_mismatch')
        self.check()
        return bundle


class FencedTransport:
    def __init__(self, base, fence):
        self.base, self.fence = base, fence

    def __getattr__(self, name):
        return getattr(self.base, name)

    def apply(self, *args, **kwargs):
        self.fence.check()
        value = self.base.apply(*args, **kwargs)
        self.fence.check()
        return value


class Worker:
    def __init__(self, *, store, master, base_authority, publisher_factory,
                 registry_reader, transport_factory, coordinator_lock,
                 controller_state_reader, clock=None):
        self.store, self.master, self.base_authority = store, master, base_authority
        self.publisher_factory, self.registry_reader = publisher_factory, registry_reader
        self.transport_factory, self.coordinator_lock = transport_factory, coordinator_lock
        self.controller_state_reader = controller_state_reader
        self.clock = clock or (lambda: int(time.time()))

    def observe(self):
        """Only remote status; no synchronize/apply/health/reload operation."""
        try:
            snapshot = self.master.snapshot()
            edge = lazycat_edge(self.registry_reader)
            value = validate_loaded(self.transport_factory(edge).status())
            controller = self.controller_state_reader(edge)
            ack = controller.get('last_ack') or {}
            need(controller.get('pending_generation') is None
                 and value['generation'] == ack.get('generation')
                 and value['cohort_sha256'] == ack.get('cohort_sha256')
                 and value['manifest_sha256'] == ack.get('manifest_sha256'),
                 'lazycat_controller_ack_mismatch')
            need(self.master.snapshot()['token'] == snapshot['token'], 'master_authority_superseded')
            self.store.set_cache({'verified': True, 'loaded': value,
                'authority_token': snapshot['token'], 'confirmed_at': controller.get('confirmed_at'),
                'error': controller.get('last_error')})
            return True
        except Exception as error:
            previous = self.store.cached() or {}
            self.store.set_cache({'verified': False, 'error': error_code(error),
                'confirmed_at': previous.get('confirmed_at'),
                'last_known_generation': previous.get('loaded', {}).get('generation') or
                    previous.get('last_known_generation')})
            return False

    def once(self, *, observe_if_idle=True):
        job = self.store.claim()
        if job is None:
            if observe_if_idle:
                self.observe()
            return False
        try:
            with self.coordinator_lock():
                snapshot = self.master.snapshot()
                subjects = [row for row in snapshot['rows'] if row['client_id'] == job['client_id']
                            and row['username'] == job['username']]
                need(len(subjects) == 1, 'master_identity_binding_changed')
                subject = subjects[0]
                need(snapshot['ready'], 'master_native_not_converged')
                need(not subject['enabled'] or subject['native_loaded'], 'master_native_missing')
                edge = lazycat_edge(self.registry_reader)
                fence = FencedAuthority(self.base_authority, self.master, snapshot, subject,
                                       lease_guard=lambda: self.store.require_lease(job))
                publisher = self.publisher_factory(authority=fence,
                    transport_factory=lambda current: FencedTransport(self.transport_factory(current), fence))
                result = publisher.synchronize(edge, subject=subject['username'],
                    enabled=subject['enabled'], source_generation=subject['source_generation'])
                fence.check()
                need(result.get('status') == 'confirmed' and result.get('edge_id') == EDGE_ID,
                     'lazycat_sync_not_confirmed')
                self.store.finish(job, result={'generation': result['generation'],
                    'source_generation': subject['source_generation'], 'source_revision': snapshot['token'],
                    'enabled': subject['enabled'],
                    'idempotent': result.get('idempotent', False), 'checked_at': self.clock()})
        except Exception as error:
            try:
                self.store.finish(job, error=error_code(error))
            except AccountError as lost:
                if str(lost) != 'account_job_lease_lost':
                    raise
        self.observe()
        return True


def production_worker(db_path=None):
    from control_backend import ControlBackend
    from edge_controller import Authority, Publisher, STATE, private_json, registry, transport_for
    from topology_enrollment_runtime import create_coordinator
    backend = ControlBackend()
    coordinator = create_coordinator()
    return Worker(store=Store(db_path) if db_path else Store(),
        master=MasterAuthority(backend, native_reader), base_authority=Authority(),
        publisher_factory=Publisher, registry_reader=registry, transport_factory=transport_for,
        coordinator_lock=coordinator._lock,
        controller_state_reader=lambda edge: private_json(STATE / (edge['edge_id'] + '.json'), missing={}))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--observe-only', action='store_true',
                        help='Only read remote loaded status; never claim or dispatch queued requests')
    args = parser.parse_args(argv)
    os.umask(0o077)
    sys.path[:0] = ['/opt/submerge-edge', '/opt/submerge-user-access',
                    '/opt/submerge-topology', '/opt/submerge-client-policy', '/opt/submerge']
    worker = production_worker()
    if args.observe_only:
        verified = worker.observe()
        print(json.dumps({'event': 'lazycat_status_observation', 'verified': verified}))
        return 0 if verified else 1
    last_observation = 0
    while True:
        handled = worker.once(observe_if_idle=args.once)
        if args.once:
            return 0
        if handled or time.monotonic() - last_observation >= 30:
            if not handled:
                worker.observe()
            last_observation = time.monotonic()
        # Polling sleeps do not hold the coordinator, Publisher, or SQLite lock.
        time.sleep(2 if handled else 10)


if __name__ == '__main__':
    raise SystemExit(main())
