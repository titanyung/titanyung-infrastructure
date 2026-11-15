#!/usr/bin/env python3
"""One-shot verified edge status and generation-bound AI mode control.

No service is restarted, no public API is added, and no configuration is edited.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
import time

from edge_apply import (ApplyError, EdgeApply, MAX_FILE, MAX_MANIFEST, SystemdRunner,
    atomic, canonical, digest, legal_health_modes, need, read_private, strict_json,
    validate_config, validate_manifest, verified_hot_mode, verify_process)


class EdgeStatus:
    def __init__(self, root, edge_id, runner=None, require_root_owner=True,
                 process_validator=verify_process):
        root = Path(root).absolute()
        need(root.is_dir() and (root / 'generations').is_dir() and
             (root / 'state.json').is_file(), 'edge_not_applied')
        self.manager = EdgeApply(root, edge_id, runner or SystemdRunner(), require_root_owner)
        self.root, self.edge_id = root, edge_id
        self.runner = self.manager.runner
        self.require_root_owner = require_root_owner
        self.process_validator = process_validator

    def current(self):
        state = self.manager.state()
        need(state.get('pending_generation') is None, 'edge_activation_pending')
        generation = state.get('current_generation')
        need(type(generation) is int and generation > 0, 'edge_not_applied')
        revision = self.manager.revision(generation)
        pointer = self.root / 'current'
        need(pointer.is_symlink() and pointer.resolve() == revision.resolve(), 'current_pointer_mismatch')
        manifest = strict_json(read_private(revision / 'manifest.json', MAX_MANIFEST,
                                           self.require_root_owner))
        expected_hash = state.get('current_manifest_sha256')
        validate_manifest(manifest, expected_hash, self.root, self.edge_id)
        need(manifest['generation'] == generation, 'current_manifest_generation_mismatch')
        self.manager.verify_revision(revision, manifest)
        config = revision / manifest['config_path']
        document = strict_json(read_private(config, MAX_FILE, self.require_root_owner))
        validate_config(document, manifest, revision)
        names = manifest['accounts']['usernames']
        status = self.runner.status()
        if not names:
            need(state.get('current_enforcement') == 'service_stopped_no_accounts' and
                 not status['active'] and status['pid'] == 0, 'deny_all_not_confirmed')
        else:
            need(state.get('current_enforcement') == 'running_verified' and
                 status['active'] and status['pid'] > 0, 'edge_not_running')
            proof = self.process_validator(status['pid'], revision / manifest['binary_path'], config)
            need(proof, 'running_process_not_verified')
            self.manager.dependencies(manifest)
        return state, revision, manifest, document, status

    def redacted(self, state, manifest, status, mode=None):
        return {'schema': 1, 'verified': True, 'edge_id': self.edge_id,
            'generation': manifest['generation'],
            'manifest_sha256': state['current_manifest_sha256'],
            'cohort_sha256': manifest['accounts']['cohort_sha256'],
            'cohort_inbound_count': manifest['cohort_inbound_count'],
            'active_usernames': list(manifest['accounts']['usernames']),
            'active_user_count': len(manifest['accounts']['usernames']),
            'enforcement': state['current_enforcement'], 'pid': status['pid'],
            'active': status['active'], 'mode': mode,
            'verified_at': int(time.time())}

    def status(self):
        with self.manager.lock():
            state, revision, manifest, document, process = self.current()
            if not manifest['accounts']['usernames']:
                return self.redacted(state, manifest, process)
            value = self.runner.control(revision / manifest['config_path'])
            mode = value.get('mode')
            need(mode in legal_health_modes(document), 'runtime_mode_not_in_policy')
            after = self.runner.status()
            need(after == process, 'process_changed_during_status')
            result = self.redacted(state, manifest, process, mode)
            expected = verified_hot_mode(self.root, self.edge_id, manifest,
                state['current_manifest_sha256'], document, self.require_root_owner)
            expected = expected or manifest['initial_clash_mode']
            result.update(health_mode_expected=expected, health_state_matches=(mode == expected))
            return result

    def set_health(self, generation, mode):
        need(type(generation) is int and generation > 0, 'invalid_generation')
        need(isinstance(mode, str) and re.fullmatch(r'ai-z[01]s[01]l[01](?:p[uln])?', mode), 'unknown_health_mode')
        with self.manager.lock():
            state, revision, manifest, document, process = self.current()
            need(generation == manifest['generation'], 'health_generation_mismatch')
            need(manifest['accounts']['usernames'], 'health_mode_unavailable_when_denied_all')
            need(mode in legal_health_modes(document), 'health_mode_not_in_manifest_rules')
            config = revision / manifest['config_path']
            self.runner.control(config, 'PATCH', {'mode': mode})
            response = self.runner.control(config)
            need(response.get('mode') == mode, 'health_mode_patch_not_confirmed')
            after = self.runner.status()
            need(after == process, 'process_changed_during_health_update')
            need(self.process_validator(process['pid'], revision / manifest['binary_path'], config),
                 'running_process_not_verified')
            record = {'schema': 1, 'edge_id': self.edge_id, 'generation': generation,
                'manifest_sha256': state['current_manifest_sha256'], 'mode': mode,
                'pid': process['pid'], 'updated_at': int(time.time())}
            atomic(self.root / 'health-state.json', canonical(record))
            result = self.redacted(state, manifest, process, mode)
            result.update(health_applied=True, restarted=False, health_state_matches=True)
            return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('status', 'set-health'))
    parser.add_argument('--identity', default='/etc/lazycat-edge/identity.json')
    parser.add_argument('--generation', type=int)
    parser.add_argument('--mode')
    args = parser.parse_args(argv)
    try:
        identity = strict_json(read_private(args.identity, 16384))
        need(isinstance(identity, dict) and set(identity) == {'edge_id', 'install_root', 'unit'} and
             identity['unit'] == 'lazycat-edge.service', 'invalid_local_edge_identity')
        service = EdgeStatus(identity['install_root'], identity['edge_id'],
                             runner=SystemdRunner(identity['unit']))
        if args.action == 'status':
            need(args.generation is None and args.mode is None, 'unexpected_status_arguments')
            result = service.status()
        else:
            need(args.generation is not None and args.mode is not None, 'health_arguments_required')
            result = service.set_health(args.generation, args.mode)
        print(canonical(result).decode('utf-8'))
        return 0
    except Exception as error:
        code = str(error) if isinstance(error, ApplyError) else type(error).__name__.lower()
        if not re.fullmatch(r'[a-z0-9_]{1,96}', code):
            code = 'edge_status_failed'
        print(json.dumps({'verified': False, 'status': 'failed', 'code': code}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
