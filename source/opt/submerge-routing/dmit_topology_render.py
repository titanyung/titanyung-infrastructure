#!/usr/bin/env python3
"""Render the two active DMIT listeners from verified, current S-UI bindings.

The root-only template supplies existing TLS, API and BT quarantine settings.
Retired static outbound definitions are removed by build_dmit_config. Trial
``test`` is accepted only with --allow-trial-test and its exact legacy grant.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import stat
import tempfile
import time

from new_enrollment import DB, PRIVATE, MAPS, EnrollmentError, read_sui_identity, _json
from zoro_runtime import TRANSPORT_PATH, TAIWAN_TRANSPORT_PATH, build_dmit_config

NETWORK_PLAN_PATH = Path('/etc/submerge-topology/network-plan.json')


def read_private(path):
    path = Path(path)
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(str(path), flags)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077):
            raise EnrollmentError('renderer_private_file_permissions_invalid')
        raw = stream.read(16 * 1024 * 1024 + 1)
    if len(raw) > 16 * 1024 * 1024:
        raise EnrollmentError('renderer_private_document_too_large')
    document = _json(raw)
    if not isinstance(document, dict):
        raise EnrollmentError('renderer_private_document_invalid')
    return document


def build_bound_config(template, private, maps, transport, *, read_identity,
                       allow_trial=False, direct_port=31117, zoro_port=29513,
                       direct_listen='127.0.0.1', zoro_listen='0.0.0.0',taiwan_transport=None,
                       network_plan=None, rule_set_loader=None, as_of=None):
    from network_runtime import revised
    revision = revised(network_plan)
    users = private.get('users') if isinstance(private, dict) else None
    if not isinstance(users, list) or (not users and not revision) or len(maps) != 2:
        raise EnrollmentError('renderer_private_users_invalid')
    if any(not isinstance(row, dict) or not isinstance(row.get('name'), str) or
           not row['name'] or not isinstance(row.get('password'), str) or
           len(row['password']) < 24 for row in users):
        raise EnrollmentError('renderer_private_users_invalid')
    if len({row['name'] for row in users}) != len(users) or len({row['password'] for row in users}) != len(users):
        raise EnrollmentError('renderer_credentials_not_unique')
    for mapping in maps:
        if (not isinstance(mapping, dict) or any(not isinstance(key, str) or
                not isinstance(value, str) or len(value) < 24 for key, value in mapping.items()) or
                len(set(mapping.values())) != len(mapping)):
            raise EnrollmentError('renderer_map_invalid')
    selected = []
    for row in users:
        if os.environ.get('USER_ACCESS_CONTROL_DB'):
            import sys
            if '/opt/submerge-user-access' not in sys.path:
                sys.path.insert(0, '/opt/submerge-user-access')
            from access_policy import render_allowed
            if not render_allowed(row['name']):
                continue
        if row['name'] == 'test' and not allow_trial:
            continue
        try:
            identity = read_identity(row['name'], allow_trial=row['name'] == 'test' and allow_trial)
        except EnrollmentError:
            # Disabled/removed/ungranted/malformed identities must not enter
            # either listener, and one invalid historical row cannot block
            # unrelated ordinary subscribers or disable their listeners.
            continue
        if identity.name != row['name'] or identity.sub_secret != row['name']:
            raise EnrollmentError('renderer_sui_binding_invalid')
        if any(mapping.get(identity.sub_secret) != row['password'] for mapping in maps):
            raise EnrollmentError('renderer_map_binding_invalid')
        selected.append(copy.deepcopy(row))
    if not selected and not revision:
        raise EnrollmentError('renderer_no_enabled_users')
    source = copy.deepcopy(template)
    origins = [item for item in source.get('inbounds', []) if isinstance(item, dict)
               and item.get('type') == 'anytls' and item.get('tag') == 'dmit-direct-stage']
    if len(origins) != 1:
        raise EnrollmentError('renderer_template_inbound_invalid')
    origins[0]['users'] = selected
    if network_plan is not None:
        from network_runtime import build_network_config
        if revision:
            from bootstrap_revision import assert_fresh_boundary
            # This low-level renderer cannot claim full-layer catch-up. The
            # root bootstrap owner must reconcile/install the plan first.
            if type(as_of) is not int:
                raise EnrollmentError('renderer_explicit_bootstrap_epoch_required')
            assert_fresh_boundary(network_plan, as_of)
        return build_network_config(source, network_plan, users=selected,
            ports={'dmit-direct-stage': direct_port},
            listen={'dmit-direct-stage': direct_listen}, clash_port=31991, api_port=31993,
            rule_set_loader=rule_set_loader)
    return build_dmit_config(source, transport, direct_port=direct_port, zoro_port=zoro_port,
        direct_listen=direct_listen, zoro_listen=zoro_listen,
        clash_port=31991, api_port=31993,taiwan_transport=taiwan_transport)


def write_candidate(path, document):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=str(path.parent))
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(document, stream, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main(args):
    if os.geteuid() != 0:
        raise EnrollmentError('root_required')
    template, private = map(read_private, (args.template, args.private))
    plan = read_private(args.network_plan) if os.path.lexists(str(args.network_plan)) else None
    from network_runtime import revised
    if revised(plan):
        return revision_main(args)
    transport = read_private(args.transport) if plan is None else None
    maps = [read_private(item) for item in args.maps]
    taiwan=(read_private(args.taiwan_transport) if plan is None and Path(args.taiwan_transport).exists()
            else None)
    identity_reader = lambda name, **kw: read_sui_identity(name, args.db, **kw)
    candidate = build_bound_config(template, private, maps, transport,
        read_identity=identity_reader, allow_trial=(args.allow_trial_test or
            private.get('topology_trial_test_enabled') is True),
        direct_port=args.direct_port, zoro_port=args.zoro_port,
        direct_listen=args.direct_listen, zoro_listen=args.zoro_listen,taiwan_transport=taiwan,
        network_plan=plan)
    write_candidate(args.output, candidate)
    print(json.dumps({'rendered': True, 'listeners': len(candidate['inbounds']),
                      'users': len(candidate['inbounds'][0]['users']), 'credentials': 'hidden'}))
    return 0


def revision_main(args):
    from bootstrap_revision import BootAuthority, install_bootstrap, installed_condition, prepare_bootstrap
    from desired_accounts import Paths
    from main_policy_cas import Transaction
    from server_route_policy import load_rule_sets
    from policy_inputs import need
    now = int(time.time())
    authority = BootAuthority(Paths(runtime=args.output, plan=args.network_plan, private=args.private,
        map0=args.maps[0], map1=args.maps[1], sui_db=args.db,
        control_db=os.environ.get('USER_ACCESS_CONTROL_DB', '/var/lib/submerge-user-access/control.db')),
        template=args.template, template_sha256=args.template_sha256,
        identity_reader=lambda name, **kw: read_sui_identity(name, args.db, **kw))
    if args.revision_condition:
        return installed_condition(authority, rule_set_loader=load_rule_sets, now=now)
    need(args.revision_bootstrap and args.catchup_receipt and args.durable_receipt,
         'explicit_new_revision_bootstrap_and_full_layer_receipt_required')
    receipt = read_private(args.catchup_receipt)
    # The receipt's exact as_of binds all acknowledged layers. It may be older
    # than now only while no retirement boundary has since been crossed.
    transaction = Transaction(authority, rule_set_loader=load_rule_sets)
    prepared = prepare_bootstrap(transaction, receipt.get('as_of'))
    def publish(payload, durable):
        # Atomic regular-file replacements, serialized by the admission CAS.
        # Final durable receipt binds both files. A partial failure never ACKs
        # native startup and leaves the systemd condition failed.
        from policy_inputs import canonical
        write_revision_bytes(args.output, payload['runtime_bytes'])
        write_revision_bytes(args.network_plan, payload['plan_bytes'])
        write_revision_bytes(args.durable_receipt, canonical(durable))
    result = install_bootstrap(transaction, prepared, catchup_receipt=receipt, writer=publish, now=now)
    print(json.dumps(result))
    return result['condition_exit_code']


def write_revision_bytes(path, raw):
    """Preserve the exact CAS bytes/digests; legacy writer stays unchanged."""
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=str(path.parent))
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name != 'nt':
            directory = os.open(str(path.parent), os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--template', default='/etc/submerge-topology/dmit-template.json')
    parser.add_argument('--private', default=str(PRIVATE))
    parser.add_argument('--maps', nargs=2, default=[str(item) for item in MAPS])
    parser.add_argument('--transport', default=str(TRANSPORT_PATH))
    parser.add_argument('--taiwan-transport',default=str(TAIWAN_TRANSPORT_PATH))
    parser.add_argument('--network-plan', default=str(NETWORK_PLAN_PATH))
    parser.add_argument('--db', default=str(DB))
    parser.add_argument('--output', default='/run/dmit-direct-staging/config.json')
    parser.add_argument('--allow-trial-test', action='store_true')
    parser.add_argument('--direct-port', type=int, default=31117)
    parser.add_argument('--zoro-port', type=int, default=29513)
    parser.add_argument('--direct-listen', default='127.0.0.1')
    parser.add_argument('--zoro-listen', default='0.0.0.0')
    parser.add_argument('--revision-bootstrap', action='store_true')
    parser.add_argument('--revision-condition', action='store_true')
    parser.add_argument('--template-sha256')
    parser.add_argument('--catchup-receipt')
    parser.add_argument('--durable-receipt', default='/var/lib/submerge-topology/main-bootstrap.json')
    args = parser.parse_args()
    try:
        code = main(args)
    except Exception as error:
        # ExecCondition 1 means an intentional skip; errors must be 255 so
        # systemd records a failed condition instead of pretending deny-all.
        if args.revision_bootstrap or args.revision_condition:
            print('topology renderer failed: ' + type(error).__name__)
            raise SystemExit(255) from None
        raise SystemExit('topology renderer failed: ' + type(error).__name__) from None
    raise SystemExit(code)
