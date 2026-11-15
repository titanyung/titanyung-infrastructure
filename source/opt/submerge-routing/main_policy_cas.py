"""Prepare and rebase main-policy transactions under the real admission lock.

No service mutation is implemented here. A deployment owner must enter
checked_install(), atomically install its private payload, and independently
restart/ack the native process. Rollback is freshly rendered with CURRENT
desired accounts; restoring a saved credential-bearing runtime is forbidden.
"""
import contextlib, copy, json, os
from pathlib import Path
from policy_inputs import canonical,sha,need,build_native,descriptor,runtime
from desired_accounts import read_file

class Transaction:
    def __init__(self,authority,*,rule_set_loader,input_guards=None):
        self.authority=authority;self.loader=rule_set_loader;self.input_guards=dict(input_guards or {})

    def _prepare(self,snapshot,target_plan):
        need(snapshot['desired_users'] or runtime.revised(target_plan),
             'empty_cohort_legacy_rollback_requires_verified_stop')
        native=build_native(snapshot['runtime'],target_plan,snapshot['desired_users'],rule_set_loader=self.loader)
        manifest=descriptor(target_plan,native,source_plan_raw=snapshot['source_plan_raw'],
            source_runtime_raw=snapshot['source_runtime_raw'],desired_token=snapshot['desired_token_sha256'])
        manifest['input_guards']=copy.deepcopy(self.input_guards)
        return {'plan':copy.deepcopy(target_plan),'runtime':native,'manifest':manifest,
                'account_sources_verified':snapshot.get('account_sources_verified') is True}

    def prepare(self,target_plan):
        with self.authority.lock():return self._prepare(self.authority.snapshot(),target_plan)

    def _assert_current(self,prepared,snapshot):
        manifest=prepared['manifest']
        need(sha(canonical(prepared['plan']))==manifest['plan_sha256']
             and sha(canonical(prepared['runtime']))==manifest['runtime_sha256'],'prepared_policy_payload_changed')
        need(snapshot.get('account_sources_verified') is True,'fresh_account_sources_required')
        for field in ('source_plan_sha256','source_runtime_sha256','desired_token_sha256','cohort_sha256'):
            need(snapshot[field]==manifest[field],'main_policy_source_or_desired_cohort_changed')
        for path,expected in manifest.get('input_guards',{}).items():
            need(sha(read_file(path,require_root=self.authority.require_root))==expected,'private_integration_input_changed')
        runtime.validate_loaded_server_policy(prepared['runtime'],prepared['plan'],rule_set_loader=self.loader)
        return True

    @contextlib.contextmanager
    def checked_install(self,prepared):
        """Keep admission CAS lock through the owner's install/restart/ACK.

        Never place only a precheck before an unrelated lock or a delayed
        systemd restart. Source/Cohort drift means discard and prepare again.
        """
        with self.authority.lock():
            current=self.authority.snapshot();self._assert_current(prepared,current)
            yield {'plan_bytes':canonical(prepared['plan']),'runtime_bytes':canonical(prepared['runtime']),
                   'manifest':copy.deepcopy(prepared['manifest']),
                   'runtime_mode':prepared['manifest']['runtime_mode']}

    def prepare_rebased_rollback(self,previous_policy_plan):
        # Intentionally no API accepts previous_runtime bytes: they may contain
        # a subscriber revoked or rotated after this migration began.
        with self.authority.lock():
            current=self.authority.snapshot()
            result=self._prepare(current,previous_policy_plan)
            result['manifest']['rollback_strategy']='previous_policy_current_desired_accounts'
            return result

    def reconcile(self,as_of,*,force=False):
        from reconcile_policy import reconcile_plan,availability
        with self.authority.lock():
            current=self.authority.snapshot()
            revised=reconcile_plan(current['plan'],as_of)
            if not force and availability(current['plan'])==availability(revised):
                return {'status':'already_current','production_changed':False,
                        'compiled_as_of':current['plan']['server_policy']['routing_revision']['as_of']}
            result=self._prepare(current,revised)
            result['manifest']['reconciler_as_of']=as_of
            return result

def write_private(prepared,folder):
    folder=Path(folder);need(folder.is_absolute() and not folder.exists() and not folder.is_symlink(),
                            'new_private_staging_folder_required')
    folder.mkdir(mode=0o700,parents=True);folder.chmod(0o700)
    for name,value in (('network-plan.json',prepared['plan']),('runtime.json',prepared['runtime']),
                       ('candidate-manifest.json',prepared['manifest'])):
        path=folder/name;path.write_bytes(canonical(value));path.chmod(0o600)
    return {'status':'prepared_only','folder':str(folder),'manifest_sha256':sha(canonical(prepared['manifest'])),
            'cohort_sha256':prepared['manifest']['cohort_sha256'],'users':prepared['manifest']['user_count'],
            'account_sources_verified':prepared['account_sources_verified'],'production_changed':False}
