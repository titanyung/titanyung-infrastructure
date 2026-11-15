#!/usr/bin/env python3
"""Read-only, redacted whole-host and application traffic counters."""

import json
import os
import sqlite3
import subprocess
import time


START = int(os.environ.get("TRAFFIC_START_TS", "1790831700"))
NOW = int(time.time())
CUTOFF = max(START, NOW - 30 * 86400)


def eth0():
    with open("/proc/net/dev", encoding="utf-8") as stream:
        for line in stream:
            name, sep, counters = line.partition(":")
            if sep and name.strip() == "eth0":
                values = counters.split()
                return {"rx": int(values[0]), "tx": int(values[8])}
    raise RuntimeError("eth0 is missing")


def read_db(path, query, args=()):
    if not os.path.isfile(path):
        return []
    conn = sqlite3.connect("file:" + path + "?mode=ro", uri=True, timeout=5)
    try:
        return conn.execute(query, args).fetchall()
    finally:
        conn.close()


def sui_outbound():
    rows = read_db(
        "/usr/local/s-ui/db/s-ui.db",
        "SELECT tag, SUM(traffic) FROM stats WHERE resource='outbound' "
        "AND date_time>=? GROUP BY tag", (CUTOFF,),
    )
    return {str(tag): int(total) for tag, total in rows}


def static_egress():
    path = ("/var/lib/bwh-traffic-dashboard/traffic.db" if os.path.isfile(
            "/var/lib/bwh-traffic-dashboard/traffic.db") else
            "/var/lib/sg-traffic-dashboard/traffic.db")
    if not os.path.isfile(path):
        return {}
    conn = sqlite3.connect("file:" + path + "?mode=ro", uri=True, timeout=2)
    try:
        exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='static_egress_totals'").fetchone()
        if not exists:
            return {}
        rows = conn.execute(
            "SELECT provider,upload+download FROM static_egress_totals").fetchall()
        return {str(provider): int(total) for provider, total in rows}
    finally:
        conn.close()


def static_wire():
    path = "/var/lib/static-provider-wire-meter/samples.json"
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as stream:
            state = json.load(stream)
        with open("/var/lib/static-provider-wire-meter/manifest.json",
                  encoding="utf-8") as stream:
            manifest = json.load(stream)
        totals = state.get("totals", {})
        expected = {f"{name}-{direction}" for name in
                    ("nexip", "ip2up", "proxyhive") for direction in ("rx", "tx")}
        if set(totals) != expected or any(
                not isinstance(totals[key], int) or totals[key] < 0 for key in expected):
            return None
        sampled_at = int(state["ts"])
        started_at = int(manifest["created_at"])
        if (sampled_at > NOW + 120 or sampled_at < NOW - 120 or
                started_at > sampled_at or int(state.get("discontinuities", 0)) < 0):
            return None
        return {"ts": sampled_at, "started_at": started_at, "totals": totals,
                "discontinuities": int(state.get("discontinuities", 0))}
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        # A failed meter must not suppress unrelated whole-host NIC samples.
        # The dashboard keeps its last valid meter timestamp visible.
        return None


def hk_routes():
    rows = read_db(
        "/var/lib/hk-traffic-dashboard/traffic.db",
        "SELECT route_class, SUM(upload+download) FROM traffic_hourly_route "
        "WHERE hour>=? GROUP BY route_class", (CUTOFF - CUTOFF % 3600,),
    )
    return {str(tag): int(total) for tag, total in rows}


def nosla_counters():
    try:
        output = subprocess.check_output(
            ["nft", "-j", "list", "table", "inet", "dashboard_accounting"],
            text=True, timeout=5, stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return {}
    counters = {}
    for item in json.loads(output).get("nftables", []):
        rule = item.get("rule", {})
        comment = rule.get("comment")
        if not comment:
            continue
        for expr in rule.get("expr", []):
            if "counter" in expr:
                counters[comment] = int(expr["counter"].get("bytes", 0))
    return counters


with open("/proc/sys/kernel/random/boot_id", encoding="utf-8") as stream:
    boot = stream.read().strip()
print(json.dumps({"ts": NOW, "boot": boot, "nic": eth0(),
                  "sui_outbound": sui_outbound(), "static_egress": static_egress(),
                  "static_wire": static_wire(),
                  "hk_routes": hk_routes(),
                  "nosla_counters": nosla_counters()}, separators=(",", ":")))
