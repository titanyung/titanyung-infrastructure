"""Reject only legacy external DMIT proxy ports at the explicit SG deadline."""
import argparse, datetime, json, subprocess, time
from pathlib import Path
from client_policy import DEADLINE, front_ports, load_policy

TABLE='dmit_client_revision_v2'
def rules():
    ports=sorted({p for k in ('desktop','mobile') for p in front_ports(k,new=False).values()})
    return ('table inet '+TABLE+' {\n chain input {\n'
        ' type filter hook input priority -5; policy accept;\n'
        ' iifname != "lo" tcp dport { '+', '.join(map(str,ports))+' } counter reject with tcp reset\n'
        ' }\n}\n')

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
    if load_policy() is None:raise ValueError('revision_not_active')
    if args.check:
        subprocess.run(['nft','--check','--file','-'],input=rules().encode(),check=True)
        print(json.dumps({'checked':True,'deadline':DEADLINE,'ports':12}));return
    if time.time()<DEADLINE:
        print(json.dumps({'state':'pending','deadline':DEADLINE}));return
    present=subprocess.run(['nft','list','table','inet',TABLE],capture_output=True)
    if present.returncode==0:
        current=present.stdout.decode()
        if 'iifname != "lo"' not in current or 'reject with tcp reset' not in current:
            raise ValueError('deadline_table_drift')
        print(json.dumps({'state':'enforced','already_present':True}));return
    subprocess.run(['nft','--file','-'],input=rules().encode(),check=True)
    Path('/var/lib/submerge-client-policy').mkdir(mode=0o700,exist_ok=True)
    record={'event':'legacy_proxy_deadline_enforced','at':int(time.time()),'deadline':DEADLINE,
            'table':TABLE,'local_direct_affected':False,'new_revision_affected':False}
    with open('/var/lib/submerge-client-policy/deadline-audit.jsonl','a') as stream:
        stream.write(json.dumps(record)+'\n')
    print(json.dumps(record))

if __name__=='__main__':main()
