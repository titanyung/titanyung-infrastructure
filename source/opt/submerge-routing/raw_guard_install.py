"""Install only the revision's exact dedicated inet raw-port guard table."""
import argparse,json,subprocess
from desired_accounts import read_file
from raw_ingress_guard import document,TABLE
from policy_inputs import need

def apply(plan):
    value=document(plan)
    old=subprocess.run(['nft','-nn','list','table','inet',TABLE],capture_output=True,text=True,timeout=5)
    if old.returncode==0:need('comment "routing-revision-20261109"' in old.stdout,'foreign_raw_guard_table')
    script=value['replace'] if old.returncode==0 else value['create']
    for args in (['nft','-c','-f','-'],['nft','-f','-']):
        p=subprocess.run(args,input=script.encode(),capture_output=True,timeout=8)
        need(p.returncode==0,'raw_guard_apply_failed')
    check=subprocess.run(['nft','-nn','list','table','inet',TABLE],capture_output=True,text=True,timeout=5)
    need(check.returncode==0 and 'routing-revision-20261109' in check.stdout,'raw_guard_not_verified')
    return {'status':'applied','table':TABLE,'raw_ports':value['ports'],'ipv4_and_ipv6':True,
            'other_tables_touched':False,'public_alias_ports_affected':False}

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--apply',action='store_true');p.add_argument('--plan',default='/etc/submerge-topology/network-plan.json');a=p.parse_args(argv)
    if not a.apply:print(json.dumps({'status':'dry_run','changed':False}));return 0
    try:print(json.dumps(apply(json.loads(read_file(a.plan)))));return 0
    except Exception as e:print(json.dumps({'status':'failed','error_type':type(e).__name__}));return 1
if __name__=='__main__':raise SystemExit(main())
