"""New-revision bootstrap closure; legacy boot behavior is not changed.

Preparation is pure except fresh authority reads under its existing admission
lock. Publishing requires the owner's full-layer catch-up receipt and callback.
The callback runs under Transaction.checked_install, never a new boot lock.
"""
import copy
from dataclasses import replace
import json
from pathlib import Path

from desired_accounts import Authority, read_file
from policy_inputs import canonical, need, runtime, sha, users
from reconcile_policy import availability, reconcile_plan

LAYERS = {'clients', 'statistics', 'edges'}


class BootAuthority(Authority):
    """Missing /run may use a hash-bound root-private TLS/transport template.

    Only the source runtime falls back. Desired users still come from the live
    private/maps/S-UI/lifecycle authority. Template users are never desired users.
    Invalid, symlinked, oversized or unreadable /run is an error, not fallback.
    """
    def __init__(self, paths=None, *, template='/etc/submerge-topology/dmit-template.json',
                 template_sha256=None, **kwargs):
        super().__init__(paths, **kwargs)
        self.template = str(template)
        self.template_sha256 = template_sha256

    def snapshot(self):
        try:
            read_file(self.paths.runtime, require_root=self.require_root)
        except FileNotFoundError:
            need(isinstance(self.template_sha256, str) and len(self.template_sha256) == 64,
                 'verified_boot_template_digest_required')
            raw = read_file(self.template, require_root=self.require_root)
            need(sha(raw) == self.template_sha256, 'verified_boot_template_changed')
            selected = Authority(replace(self.paths, runtime=self.template), identity_reader=self.identity_reader,
                                 require_root=self.require_root, clock=self.clock)
            value = selected.snapshot()
            need(value['source_runtime_sha256'] == self.template_sha256, 'boot_template_changed_during_snapshot')
            value['bootstrap_runtime_source'] = 'verified_private_template'
            return value
        value = super().snapshot()
        value['bootstrap_runtime_source'] = 'current_runtime'
        return value


def assert_fresh_boundary(plan, now):
    need(runtime.revised(plan), 'new_revision_bootstrap_required')
    runtime.validate_network_plan(plan)
    need(type(now) is int and now >= plan['server_policy']['routing_revision']['as_of'],
         'boot_clock_before_compiled_revision')
    fresh = reconcile_plan(plan, now)
    need(availability(plan) == availability(fresh), 'root_full_layer_catchup_required_before_native_start')
    return True


def prepare_bootstrap(transaction, as_of):
    """Always refresh explicit as_of and desired accounts, including zero.

    No publication or claim about clients/statistics/edges happens here.
    A full-layer receipt must bind this exact result before installation.
    """
    need(type(as_of) is int and as_of > 0, 'explicit_bootstrap_epoch_required')
    prepared = transaction.reconcile(as_of, force=True)
    need('runtime' in prepared and runtime.revised(prepared['plan']), 'new_revision_bootstrap_required')
    prepared['bootstrap'] = {'scope': 'main_only_prepared', 'publication_allowed': False,
        'full_layer_catchup_required': True, 'as_of': as_of,
        'condition_exit_code': 0 if prepared['manifest']['user_count'] else 1}
    return prepared


def validate_catchup_receipt(receipt, prepared):
    keys = {'schema', 'status', 'as_of', 'plan_sha256', 'cohort_sha256', 'desired_token_sha256', 'layers'}
    need(isinstance(receipt, dict) and set(receipt) == keys and receipt['schema'] == 1
         and receipt['status'] == 'completed', 'root_full_layer_catchup_receipt_required')
    manifest = prepared['manifest']
    need(receipt['as_of'] == prepared['plan']['server_policy']['routing_revision']['as_of']
         and all(receipt[key] == manifest[key] for key in ('plan_sha256', 'cohort_sha256', 'desired_token_sha256')),
         'full_layer_catchup_receipt_does_not_bind_prepared_bootstrap')
    need(isinstance(receipt['layers'], dict) and set(receipt['layers']) == LAYERS
         and all(value is True for value in receipt['layers'].values()), 'full_layer_catchup_not_acknowledged')
    return True


def durable_receipt(prepared):
    """Credential-free authority for consumers after RuntimeDirectory removal."""
    manifest = prepared['manifest']
    return {'schema': 1, 'status': 'prepared_empty' if not manifest['user_count'] else 'prepared_active',
        'as_of': prepared['plan']['server_policy']['routing_revision']['as_of'],
        **{key: manifest[key] for key in ('plan_sha256', 'runtime_sha256', 'cohort_sha256',
                                        'desired_token_sha256', 'user_count', 'runtime_mode')},
        'template_users_are_authority': False, 'native_running_acknowledged': False}


def install_bootstrap(transaction, prepared, *, catchup_receipt, writer, now):
    """Owner writes plan/runtime/durable receipt atomically under admission CAS.

    Writer(payload, durable_receipt) must fail closed if publication fails. It
    must not restart synchronously via a condition which acquires this same
    lock. No saved credential-bearing runtime is accepted as rollback input.
    """
    validate_catchup_receipt(catchup_receipt, prepared)
    assert_fresh_boundary(prepared['plan'], now)
    with transaction.checked_install(prepared) as payload:
        receipt = durable_receipt(prepared)
        writer(payload, copy.deepcopy(receipt))
    return {'status': 'installed_empty_native_skipped' if not receipt['user_count'] else 'installed_pending_native_ack',
        'condition_exit_code': 0 if receipt['user_count'] else 1,
        'cohort_sha256': receipt['cohort_sha256'], 'runtime_mode': receipt['runtime_mode'],
        'native_running_acknowledged': False, 'full_layer_catchup_receipt_verified': True}


def installed_condition(authority, *, rule_set_loader, now):
    """Nonlocking gate for a deploy owner ALREADY holding the common lock.

    This performs no write. Boot-time catch-up and missing-/run recovery belong
    in prepare/install above. It can also fail closed outside an external lock,
    but it is not an account-CAS publication or a native running ACK.
    """
    current = authority.snapshot()
    need(current.get('bootstrap_runtime_source') != 'verified_private_template', 'boot_runtime_not_published')
    assert_fresh_boundary(current['plan'], now)
    runtime.validate_loaded_server_policy(current['runtime'], current['plan'], rule_set_loader=rule_set_loader)
    need(users(current['runtime']) == current['desired_users'], 'boot_runtime_desired_cohort_not_current')
    return 0 if current['desired_users'] else 1


def render_dropin(*, template_sha256, catchup_receipt='/var/lib/submerge-topology/full-layer-catchup.json',
                  durable='/var/lib/submerge-topology/main-bootstrap.json', prepared=False):
    import re
    need(isinstance(template_sha256, str) and re.fullmatch('[a-f0-9]{64}', template_sha256),
         'verified_boot_template_digest_required')
    for path in (catchup_receipt, durable):
        need(re.fullmatch(r'/[A-Za-z0-9_./-]+', path) and '..' not in Path(path).parts,
             'safe_absolute_bootstrap_receipt_path_required')
    mode = '--revision-condition' if prepared else '--revision-bootstrap'
    command = '/usr/bin/python3 /opt/submerge-topology/dmit_topology_render.py ' + mode
    command += ' --template-sha256 ' + template_sha256
    if not prepared:
        command += ' --catchup-receipt ' + catchup_receipt + ' --durable-receipt ' + durable
    return '[Service]\nRuntimeDirectoryPreserve=yes\nExecCondition=\nExecCondition=' + command + '\nExecStartPre=\n'\
        'ExecStartPre=/root/lazycat-test-config/sing-box check -c /run/dmit-direct-staging/config.json\n'
