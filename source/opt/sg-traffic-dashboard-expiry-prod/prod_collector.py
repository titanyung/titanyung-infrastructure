#!/usr/bin/env python3
"""Production whole-host sampler with expiry boundaries and record retention."""

import concurrent.futures
import importlib.util
import os
import time


PRODUCTION_DB = "/var/lib/sg-traffic-dashboard/whole.db"
PRODUCTION_COLLECTOR = "/opt/sg-traffic-dashboard/whole-vps-collector.py"


def require_production_target():
    db_path = os.environ.get("WHOLE_TRAFFIC_DB", PRODUCTION_DB)
    source = os.environ.get("DASHBOARD_BASE_COLLECTOR", PRODUCTION_COLLECTOR)
    if os.path.realpath(db_path) != os.path.realpath(PRODUCTION_DB):
        raise SystemExit("Production whole.db required")
    if os.path.realpath(source) != os.path.realpath(PRODUCTION_COLLECTOR):
        raise SystemExit("Audited production collector required")
    if os.environ.get("EXPIRY_STAGE_PREVIEW_NOW") or os.environ.get(
            "EXPIRY_STAGE_FIXTURE_ONLY"):
        raise SystemExit("Fixture clock forbidden in production")
    return db_path, source


def collect_once(base, conn, now, active_hosts, may_store_measurement,
                 capture_due, prune_rolling):
    """Retain the old collector's sample/record order except freeze first."""
    hosts = active_hosts(base.HOSTS, now)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(hosts))) as pool:
        for server, item, error in pool.map(base.sample, hosts.items()):
            if not may_store_measurement(server, item, int(time.time())):
                continue
            try:
                base.store(conn, server, item, error)
            except (ValueError, TypeError, KeyError):
                base.store(conn, server, None, "InvalidSample")
    # In-place record UPSERTs can include traffic after the cutoff.  Seal the
    # last pre-cutoff view before importing any newer records.
    capture_due(conn, int(time.time()))
    for origin in base.RECORD_HOSTS:
        base.sync_records(conn, origin)
    prune_rolling(conn, int(time.time()))
    conn.commit()


def main():
    db_path, source = require_production_target()
    spec = importlib.util.spec_from_file_location("audited_production_collector", source)
    if spec is None or spec.loader is None:
        raise SystemExit("Audited production collector unavailable")
    base = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(base)
    base.DB = db_path
    from expiry_policy import active_hosts, may_store_measurement
    from expiry_stage import capture_due, ensure_schema, prune_rolling
    conn = base.connect()
    ensure_schema(conn)
    conn.commit()
    while True:
        began = time.monotonic()
        collect_once(base, conn, int(time.time()), active_hosts,
                     may_store_measurement, capture_due, prune_rolling)
        time.sleep(max(1, 60 - (time.monotonic() - began)))


if __name__ == "__main__":
    main()
