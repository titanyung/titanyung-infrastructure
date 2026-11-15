#!/usr/bin/env python3
"""Fetch a private forced-command snapshot over pinned SSH and replace its mirror."""
import argparse
import json
import subprocess
import sys
import tempfile
import time

from daily_accounting import DEFAULT_DB, DailyLedger, import_snapshot

MAX_SNAPSHOT_BYTES=32*1024*1024


def fetch_snapshot(args):
    command=['ssh','-F','/dev/null','-T','-p',str(args.port),'-i',args.identity,
        '-o','IdentitiesOnly=yes','-o','BatchMode=yes','-o','ConnectTimeout=8',
        '-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+args.known_hosts,
        '-o','ForwardAgent=no','-o','ClearAllForwardings=yes',args.host,'daily-snapshot']
    with tempfile.TemporaryFile() as output:
        process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.DEVNULL)
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill();process.wait()
            raise RuntimeError('snapshot transport timeout')
        if process.returncode!=0:raise RuntimeError('snapshot transport failed')
        size=output.tell()
        if not 1<=size<=MAX_SNAPSHOT_BYTES:raise ValueError('snapshot size outside bound')
        output.seek(0)
        return json.load(output)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',required=True,choices=('BWH',))
    parser.add_argument('--host',required=True)
    parser.add_argument('--port',required=True,type=int)
    parser.add_argument('--identity',required=True)
    parser.add_argument('--known-hosts',required=True)
    parser.add_argument('--db',default=DEFAULT_DB)
    args=parser.parse_args()
    try:
        with DailyLedger(args.db,source_key='DMIT'):pass
        payload=fetch_snapshot(args)
        result=import_snapshot(args.db,payload,expected_source_key=args.source)
        print('daily mirror '+result['status']+' source='+args.source+' rows='+str(result['rows']))
        return 0
    except Exception as error:
        try:
            with DailyLedger(args.db,source_key='DMIT') as ledger:
                ledger.record_gap('mirror_source_unavailable',host=args.source,runtime='daily-mirror')
        except Exception:
            pass
        # Never place remote output, usernames, paths, or secrets into journals.
        print('daily mirror unavailable: '+type(error).__name__,file=sys.stderr)
        return 1


if __name__=='__main__':raise SystemExit(main())
