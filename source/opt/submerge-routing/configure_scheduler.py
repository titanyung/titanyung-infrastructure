"""Install reviewed scheduler/settings; default prepares, --enable gates on ACKs."""
import argparse,datetime,hashlib,json,os,subprocess,tempfile
from pathlib import Path
import release_reconcile as owner
from prepared_restart import atomic,private
from routing_contract import UZUMA_HKT_RETIRE_AT

HERE=Path(__file__).resolve().parent
UNITS=('dmit-routing-reconcile.service','dmit-routing-reconcile.timer')

def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def configure(settings_path,*,enable=False,expected_existing_settings_sha256=None,unit_sources=None):
    owner.need(os.geteuid()==0,'scheduler_root_required')
    settings=owner.settings_document(settings_path)
    preparation=owner.load(settings['statistics_prepare_descriptor'])
    activation=owner.load(settings['statistics_activation_descriptor'])
    owner.need({'network_module_dir','runtime','network_plan','sampler_preparation','requirements','sites',
                'hkt_reverse_evidence','node_protection_inventory','output'}<=set(preparation),
               'scheduler_actual_statistics_preparation_descriptor_required')
    owner.need({'service_roles','service_audit'}<=set(activation)
               and set(activation['service_roles'])=={'collector','dashboard','routing_ui','security_ui'},
               'scheduler_actual_audited_statistics_roles_required')
    # No placeholders: private accepted inventory/evidence/sampler documents
    # must exist even for preparation; activation performs their full audits.
    for key in ('sampler_preparation','requirements','sites','hkt_reverse_evidence','node_protection_inventory'):
        owner.load(preparation[key])
    raw=owner.canonical(settings);destination=Path(owner.SETTINGS)
    if destination.exists():
        current=owner.sha(private(destination))
        owner.need(current in {owner.sha(raw),expected_existing_settings_sha256},'scheduler_settings_source_cas')
    sources=unit_sources or {name:HERE/name for name in UNITS}
    material={}
    for name in UNITS:
        source=Path(sources[name]);body=source.read_bytes();target=Path('/etc/systemd/system')/name
        owner.need(not target.is_symlink(),'scheduler_unit_symlink')
        owner.need(not target.exists() or target.read_bytes()==body,'scheduler_existing_unit_cas')
        material[target]=body
    # Validate file/unit syntax before changing PID1's unit view.
    result=subprocess.run(['systemd-analyze','verify',*[str(sources[name]) for name in UNITS]],
                          stdin=subprocess.DEVNULL,capture_output=True,timeout=30)
    owner.need(result.returncode==0,'scheduler_native_unit_syntax_failed')
    if enable:
        live=owner.LiveOwner(settings)
        current,boundary=live.current()
        owner.need(live.already_current(current,boundary),'scheduler_actual_full_layer_commit_required_before_enable')
        contract=current['plan']['server_policy']['routing_revision']
        # The timer is scoped to the three approved retirements.
        fixed=datetime.timezone(datetime.timedelta(hours=8))
        actual=[datetime.datetime.fromtimestamp(epoch,fixed).isoformat() for epoch in
                (contract['lazycat_hkt_retire_at'],contract['taiwan_retire_at'],UZUMA_HKT_RETIRE_AT)]
        owner.need(actual==['2026-11-17T00:00:00+08:00','2026-12-06T00:00:00+08:00',
                            '2026-12-10T00:00:00+08:00'],
                   'scheduler_exact_approved_cutoffs_changed')
        boot=owner.systemctl('show',owner.BOOT,'--property=ExecStart','--value',timeout=5).decode()
        owner.need('/opt/submerge-routing/release_reconcile.py --preboot' in boot,
                   'scheduler_actual_boot_entry_must_use_preboot_owner')
    atomic(destination,raw)
    for target,body in material.items():atomic(target,body);target.chmod(0o644)
    owner.systemctl('daemon-reload')
    if enable:
        owner.systemctl('enable','--now','dmit-routing-reconcile.timer')
        owner.need(owner.systemctl('is-enabled','dmit-routing-reconcile.timer').decode().strip()=='enabled',
                   'scheduler_persistence_not_enabled')
        owner.need(owner.systemctl('is-active','dmit-routing-reconcile.timer').decode().strip()=='active',
                   'scheduler_timer_not_active')
    proof={'status':'scheduler_enabled_after_actual_commit' if enable else 'scheduler_prepared_not_enabled',
        'settings_sha256':digest(destination),'unit_hashes':{str(path):digest(path) for path in material},
        'timer_enabled':enable,'exact_cutoffs_singapore':['2026-11-17T00:00:00+08:00','2026-12-06T00:00:00+08:00',
                                                         '2026-12-10T00:00:00+08:00'],
        'persistent':True,'client_mode_or_tun_changed':False,'provider_upstream_refreshed':False}
    return proof

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--settings',required=True)
    p.add_argument('--enable',action='store_true');p.add_argument('--expected-existing-settings-sha256')
    a=p.parse_args(argv)
    result=configure(a.settings,enable=a.enable,expected_existing_settings_sha256=a.expected_existing_settings_sha256)
    print(json.dumps(result))

if __name__=='__main__':main()
