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
                 prune_rolling):
    """Sample active hosts and retain ordinary history without legacy expiry.

    Retired hosts and peers already have immutable manifest snapshots. Running
    the old calendar capture again would create redundant future snapshots of
    those retired services and rescan their historical sessions.
    """
    hosts = active_hosts(base.HOSTS, now)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(hosts))) as pool:
        for server, item, error in pool.map(base.sample, hosts.items()):
            if not may_store_measurement(server, item, int(time.time())):
                continue
            try:
                base.store(conn, server, item, error)
            except (ValueError, TypeError, KeyError):
                base.store(conn, server, None, "InvalidSample")
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
    from topology_archive import install_collector
    install_collector(base)
    base.DB = db_path
    from expiry_policy import active_hosts, may_store_measurement
    from topology_archive import read_manifest
    manifest = read_manifest()
    from network_stats import is_revision, active_host_names
    if is_revision(manifest):
        from revision_inventory import sample_allowed
        active_hosts = lambda commands, now: {host: command for host, command in commands.items()
                                             if host in active_host_names(manifest, now)}
        may_store_measurement = lambda host, item, now: (host in active_host_names(manifest, now)
            and (item is None or sample_allowed(manifest['revision_inventory'], host, item['ts'], now=now)))
    if manifest.get('network_plan') == 'network-plan-20261106':
        # These are renewed active services; old calendar retirement rules
        # remain intact for history but cannot stop a resumed sampler.
        active_names = frozenset(manifest['active_hosts'])
        active_hosts = lambda commands, now: {host: command for host, command in commands.items()
                                             if host in active_names}
        may_store_measurement = lambda host, item, now: host in active_names
    from expiry_stage import ensure_schema, prune_rolling
    conn = base.connect()
    ensure_schema(conn)
    conn.commit()
    while True:
        began = time.monotonic()
        collect_once(base, conn, int(time.time()), active_hosts,
                     may_store_measurement, prune_rolling)
        time.sleep(max(1, 60 - (time.monotonic() - began)))


if __name__ == "__main__":
    main()
