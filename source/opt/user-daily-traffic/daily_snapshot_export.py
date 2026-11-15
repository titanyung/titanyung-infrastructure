#!/usr/bin/env python3
"""Export the daily ledger as a consistent read-only JSON snapshot on stdout."""
import argparse
import json
import sys

from daily_accounting import DEFAULT_DB, export_snapshot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', default=DEFAULT_DB)
    args = parser.parse_args()
    try:
        payload = export_snapshot(args.db)
    except Exception as error:
        # Keep private paths, users and database contents out of journal logs.
        print('daily snapshot unavailable: ' + type(error).__name__, file=sys.stderr)
        return 1
    json.dump(payload, sys.stdout, ensure_ascii=False, separators=(',', ':'))
    sys.stdout.write('\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
