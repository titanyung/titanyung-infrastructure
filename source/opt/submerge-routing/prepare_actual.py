"""Prepare actual-source main plan/runtime privately. Never installs/restarts.

plan-only output is for integration review. A production payload must be
prepared again from fresh Authority.snapshot() under the admission CAS lock.
"""
import argparse,copy,json,os
from pathlib import Path
from policy_inputs import build_plan,build_native,canonical,sha,users,descriptor,policy,need
from main_policy_cas import Transaction,write_private
from desired_accounts import Authority,Paths,read_file

def load(path):return json.loads(Path(path).read_bytes())

def prepare(args):
    source_main=Path(args.source_main);source_plan=Path(args.source_plan)
    source_raw=source_main.read_bytes();plan_raw=source_plan.read_bytes()
    current,old=map(json.loads,(source_raw,plan_raw))
    side,registry,contract,transport=map(load,(args.side_runtime,args.registry,args.contract,args.hkt_transport))
    target=build_plan(old,current,side,registry,contract,transport,
                      native_hkt_ports={'dmit-uzuma-hkt':29520,'mobile-dmit-uzuma-hkt':29620})
    guards={str(Path(path).resolve()):sha(Path(path).read_bytes()) for path in
            (args.side_runtime,args.registry,args.contract,args.hkt_transport)}
    if args.plan_only:
        output=Path(args.output);need(output.is_absolute() and not output.exists(),'new_private_plan_folder_required')
        output.mkdir(mode=0o700,parents=True);output.chmod(0o700)
        path=output/'network-plan.json';path.write_bytes(canonical(target));path.chmod(0o600)
        proof={'status':'actual_plan_prepared_only','plan_sha256':sha(canonical(target)),
               'source_runtime_sha256':sha(source_raw),'source_plan_sha256':sha(plan_raw),
               'input_guards':guards,'actual_native_assets_checked':False,'latest_cohort_ack_verified':False,
               'activation_allowed':False,'production_changed':False}
        (output/'plan-proof.json').write_bytes(canonical(proof));(output/'plan-proof.json').chmod(0o600)
        return proof
    authority=Authority(Paths(runtime=str(source_main),plan=str(source_plan)))
    transaction=Transaction(authority,rule_set_loader=policy.load_rule_sets,input_guards=guards)
    with authority.lock():
        fresh=authority.snapshot()
        # A target from a stale plan/transport snapshot cannot override a
        # concurrent source policy change even when the account names match.
        need(fresh['source_runtime_sha256']==sha(source_raw) and fresh['source_plan_sha256']==sha(plan_raw),
             'source_changed_before_locked_prepare')
        prepared=transaction._prepare(fresh,target)
    return write_private(prepared,args.output)

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare',action='store_true');parser.add_argument('--plan-only',action='store_true')
    parser.add_argument('--source-main',default='/run/dmit-direct-staging/config.json')
    parser.add_argument('--source-plan',default='/etc/submerge-topology/network-plan.json')
    parser.add_argument('--side-runtime',default='/var/lib/lazycat-edge/current/config/runtime.json')
    parser.add_argument('--registry',default='/etc/submerge-edge/edges.json')
    parser.add_argument('--contract');parser.add_argument('--hkt-transport');parser.add_argument('--output')
    args=parser.parse_args(argv)
    if not args.prepare:
        print(json.dumps({'status':'dry_run','network_requests':0,'production_changed':False}));return 0
    try:
        need(all((args.contract,args.hkt_transport,args.output)),'complete_actual_contract_and_hkt_inputs_required')
        print(json.dumps(prepare(args)));return 0
    except Exception as error:
        # No raw native/API/SQLite exception or credential-bearing body escapes.
        from policy_inputs import InputError
        print(json.dumps({'status':'failed','code':str(error) if isinstance(error,InputError) else type(error).__name__,
                          'production_changed':False,'credentials_printed':False}));return 1

if __name__=='__main__':raise SystemExit(main())
