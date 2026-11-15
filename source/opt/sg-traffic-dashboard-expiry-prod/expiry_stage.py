"""Isolated, testable expiry snapshots for the unified traffic dashboard.

This module never changes a live host, subscription, or source database.  A
staging collector calls ``capture_due`` against its own SQLite database; a
staging dashboard overlays the resulting immutable cards with ``merge_whole``.
The normal 30-day access-record queries and 31-day physical cleanup remain
unchanged.  All times are epoch seconds and boundaries use Asia/Singapore.
"""

import json
import sqlite3
import time

from expiry_policy import (EXPIRY_DATES, HOST_SERVICES, OUTBOUND_TAGS,
                           active_hosts, expires_at, freeze_at)


WINDOW = 30 * 86400
PHYSICAL_RETENTION = 31 * 86400
TRAFFIC_START = 1790831700
OUTBOUND_INGRESSES = ("DMIT", "BWH", "GoMami")
_CARD_FIELDS = ("in", "out", "today_in", "today_out", "sampled_at", "proxy_app",
                "proxy_wire", "mapping_wire", "direct", "kookeey", "bytevirt",
                "lazycat", "lazycat_hkt")


def ensure_schema(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS expiry_snapshots (
          service TEXT PRIMARY KEY,
          kind TEXT NOT NULL CHECK(kind IN ('host','outbound')),
          expires_at INTEGER NOT NULL,
          freeze_at INTEGER NOT NULL,
          captured_at INTEGER NOT NULL,
          measured_at INTEGER,
          snapshot_json TEXT NOT NULL,
          CHECK(measured_at IS NULL OR measured_at <= freeze_at)
        )
    """)


def _empty_card():
    result = {key: None for key in _CARD_FIELDS}
    result["details"] = {}
    return result


def _object(value):
    try:
        parsed = json.loads(value or "{}")
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _counters(value):
    result = {}
    for key, raw in _object(value).items():
        try:
            amount = int(raw)
        except (TypeError, ValueError):
            continue
        if amount >= 0:
            result[str(key)] = amount
    return result


def _latest(conn, server, cutoff):
    return conn.execute(
        "SELECT ts,sui_json,hk_json FROM samples WHERE server=? AND ts<=? "
        "ORDER BY ts DESC LIMIT 1", (server, cutoff)).fetchone()


def _start(cutoff):
    return max(TRAFFIC_START, cutoff - WINDOW + 1)


def _midnight(cutoff):
    # Singapore does not observe daylight saving time.
    return cutoff - ((cutoff + 8 * 3600) % 86400)


def _user_usage(conn, server, cutoff):
    # unified_records is UPSERTed in place, not event-sourced.  Once a row is
    # updated after midnight, its byte counters cannot be reconstructed at
    # 23:59:59.  Exclude such rows instead of overstating the frozen period.
    columns = {row[1] for row in conn.execute(
        "PRAGMA table_info(unified_records)")}
    required = {"user", "ingress", "route_type", "started", "changed",
                "ended", "traffic_known", "upload", "download"}
    if not required.issubset(columns):
        return []
    rows = conn.execute(
        "SELECT user,SUM(upload+download) total FROM unified_records "
        "WHERE ingress=? AND started>=? AND started<=? AND changed<=? "
        "AND (ended IS NULL OR ended<=?) AND traffic_known=1 "
        "AND route_type IN ('直连','中转') GROUP BY user ORDER BY total DESC",
        (server, _start(cutoff), cutoff, cutoff, cutoff))
    return [{"user": str(user), "total": int(total)} for user, total in rows]


def _host_snapshot(conn, server, cutoff):
    card = _empty_card()
    card["historical_user_usage"] = _user_usage(conn, server, cutoff)
    latest = _latest(conn, server, cutoff)
    if latest is None:
        return card, None
    measured = int(latest[0])
    card["sampled_at"] = measured  # Never substitute the freeze boundary.
    start = _start(cutoff)
    totals = conn.execute(
        "SELECT COUNT(*),SUM(delta_rx),SUM(delta_tx),"
        "SUM(CASE WHEN ts>=? THEN delta_rx ELSE 0 END),"
        "SUM(CASE WHEN ts>=? THEN delta_tx ELSE 0 END) "
        "FROM samples WHERE server=? AND ts>=? AND ts<=?",
        (_midnight(cutoff), _midnight(cutoff), server, start, cutoff),
    ).fetchone()
    if int(totals[0]) == 0:
        return card, measured
    card.update({"in": int(totals[1] or 0), "out": int(totals[2] or 0),
                 "today_in": int(totals[3] or 0),
                 "today_out": int(totals[4] or 0)})
    if server in ("BWH", "GoMami"):
        sui = _counters(latest[1])
        if server == "GoMami":
            first = conn.execute(
                "SELECT sui_json FROM samples WHERE server=? AND ts>=? "
                "AND ts<=? ORDER BY ts ASC LIMIT 1",
                (server, start, cutoff)).fetchone()
            baseline = _counters(first[0]) if first else {}
            sui = {key: max(0, value - baseline.get(key, 0))
                   for key, value in sui.items()}
        # A missing outbound tag is unavailable data, not a measured zero.
        card["direct"] = sui.get("direct")
        card["kookeey"] = sui.get("residential-out")
        card["proxy_app"] = sum(sui.values()) if sui else None
        card["details"] = {"outbound_tags": sui}
        hk = _latest(conn, "ByteVirt-HK ISP", cutoff)
        hk_routes = _counters(hk[2]) if hk else {}
        if server == "BWH":
            card["bytevirt"] = hk_routes.get("bwh_bytevirt_hk_isp")
            if card["proxy_app"] is not None and card["bytevirt"] is not None:
                card["proxy_app"] += card["bytevirt"]
        else:
            first = conn.execute(
                "SELECT MIN(ts) FROM samples WHERE server=? AND ts>=? "
                "AND ts<=?", (server, start, cutoff)).fetchone()[0]
            if first is not None:
                card["bytevirt"] = int(conn.execute(
                    "SELECT COALESCE(SUM(upload+download),0) FROM unified_records "
                    "WHERE origin='hk' AND traffic_known=1 "
                    "AND source>='103.26.8.100:' AND source<'103.26.8.100;' "
                    "AND started>=? AND started<=?",
                    (first, cutoff)).fetchone()[0])
    elif server == "NoSLA":
        values = conn.execute(
            "SELECT SUM(proxy_wire),SUM(mapping_wire) FROM categories "
            "WHERE server=? AND ts>=? AND ts<=?",
            (server, start, cutoff)).fetchone()
        card["proxy_wire"] = int(values[0] or 0)
        card["mapping_wire"] = int(values[1] or 0)
        hk = _latest(conn, "ByteVirt-HK ISP", cutoff)
        card["bytevirt"] = _counters(hk[2]).get("bytevirt_hk_isp", 0) if hk else 0
    return card, measured


def _outbound_snapshot(conn, service, cutoff):
    if service in ("ip2up.com", "proxyhive.io"):
        return _static_snapshot(conn, service, cutoff)
    tag = OUTBOUND_TAGS[service]
    ingresses = {}
    measured = None
    for server in OUTBOUND_INGRESSES:
        row = _latest(conn, server, cutoff)
        values = _counters(row[1]) if row else {}
        found = tag in values
        actual = int(row[0]) if found else None
        ingresses[server] = {"bytes": values[tag] if found else None,
                             "measured_at": actual,
                             "source_tag": tag if found else None}
        if actual is not None:
            measured = max(measured or actual, actual)
    return {"ingresses": ingresses,
            "note": "采样时各入口的应用计数；缺失标签表示未采集，非零流量证明。"}, measured


def _static_snapshot(conn, service, cutoff):
    """Keep only actual pre-cutoff application and wire observations."""
    tag = OUTBOUND_TAGS[service]
    wire_prefix = {"ip2up.com": "ip2up", "proxyhive.io": "proxyhive"}[service]
    result = {"ingresses": {}, "static_wire": {},
              "note": "入口专用应用计数加可核实的 S-UI 应用记录；网线量独立展示，不与应用量相加。截止点和实测时间分开保存。"}
    measured = None
    columns = {row[1] for row in conn.execute("PRAGMA table_info(unified_records)")}
    sui_available = {"id", "origin", "relay", "ingress", "route_type", "started",
                     "changed", "ended", "traffic_known", "upload", "download"}.issubset(columns)
    wire_columns = {row[1] for row in conn.execute("PRAGMA table_info(static_wire_samples)")}
    for server in ("DMIT", "BWH"):
        row = _latest(conn, server, cutoff)
        counters = _counters(row[1]) if row else {}
        actual = int(row[0]) if tag in counters else None
        value = counters.get(tag)
        sui_total = None
        if sui_available:
            sui = conn.execute(
                "SELECT COUNT(*),SUM(upload+download),MAX(changed) FROM unified_records "
                "WHERE relay=? AND ingress=? AND started>=? AND started<=? "
                "AND changed<=? AND (ended IS NULL OR ended<=?) AND traffic_known=1 "
                "AND route_type='中转' AND origin IN ('dmit','bwh') "
                "AND id>='sui:' AND id<'sui;'",
                (service, server, _start(cutoff), cutoff, cutoff, cutoff)).fetchone()
            if int(sui[0]):
                sui_total = int(sui[1])
                if value is not None:
                    value += sui_total
                    actual = max(actual, int(sui[2]))
        result["ingresses"][server] = {"bytes": value, "measured_at": actual,
            "source_tag": tag if tag in counters else None, "sui_bytes": sui_total}
        if actual is not None:
            measured = max(measured or actual, actual)
        wire = None
        if {"server", "ts", "totals_json", "discontinuities", "started_at"}.issubset(wire_columns):
            wire = conn.execute(
                "SELECT ts,totals_json,discontinuities,started_at FROM static_wire_samples "
                "WHERE server=? AND ts<=? ORDER BY ts DESC LIMIT 1", (server, cutoff)).fetchone()
        values = _counters(wire[1]) if wire else {}
        rx_key, tx_key = wire_prefix + "-rx", wire_prefix + "-tx"
        if all(key in values for key in (rx_key, tx_key)):
            actual_wire = int(wire[0])
            result["static_wire"][server] = {"rx": values[rx_key], "tx": values[tx_key],
                "measured_at": actual_wire, "discontinuities": int(wire[2]), "started_at": int(wire[3])}
            measured = max(measured or actual_wire, actual_wire)
        else:
            result["static_wire"][server] = None
    return result, measured


def _overlay_static(result, service, snapshot, metadata):
    """Freeze this provider only; host totals and other exits remain live."""
    for server in ("DMIT", "BWH"):
        if server not in result["servers"]:
            continue
        card = dict(result["servers"][server])
        application = (snapshot.get("ingresses") or {}).get(server) or {}
        card["static_outbound"] = dict(card.get("static_outbound") or {})
        card["static_outbound"][service] = application.get("bytes")
        card["static_wire"] = dict(card.get("static_wire") or {})
        wire = (snapshot.get("static_wire") or {}).get(server)
        card["static_wire"][service] = (
            {key: wire[key] for key in ("rx", "tx")} if wire is not None else None)
        card["static_provider_expiry"] = dict(card.get("static_provider_expiry") or {})
        card["static_provider_expiry"][service] = dict(metadata,
            application_measured_at=application.get("measured_at"),
            wire_measured_at=wire.get("measured_at") if wire else None)
        result["servers"][server] = card


def capture_due(conn, now=None):
    """Freeze once at/after midnight, using only actual measurements <= cutoff.

    Returns newly frozen service names.  Re-running is idempotent; an existing
    snapshot with a different boundary is treated as a configuration error.
    """
    now = int(time.time() if now is None else now)
    ensure_schema(conn)
    captured = []
    with conn:
        for service in EXPIRY_DATES:
            expiry = expires_at(service)
            if now < expiry:
                continue
            cutoff = freeze_at(service)
            existing = conn.execute(
                "SELECT expires_at,freeze_at FROM expiry_snapshots WHERE service=?",
                (service,)).fetchone()
            if existing:
                if tuple(existing) != (expiry, cutoff):
                    raise ValueError("expiry boundary changed for " + service)
                continue
            if service in HOST_SERVICES:
                kind = "host"
                snapshot, measured = _host_snapshot(conn, service, cutoff)
            else:
                kind = "outbound"
                snapshot, measured = _outbound_snapshot(conn, service, cutoff)
            # A missing source is not a zero-byte final sample.  Leave the
            # service pending and retry if a late pre-cutoff row arrives.
            if measured is None:
                continue
            if measured is not None and measured > cutoff:
                raise ValueError("post-expiry measurement for " + service)
            conn.execute(
                "INSERT INTO expiry_snapshots VALUES(?,?,?,?,?,?,?)",
                (service, kind, expiry, cutoff, now, measured,
                 json.dumps(snapshot, ensure_ascii=False, separators=(",", ":"))))
            captured.append(service)
    return captured


def prune_rolling(conn, now):
    """Match the existing 31-day physical retention; never purge snapshots."""
    cutoff = int(now) - PHYSICAL_RETENTION
    with conn:
        conn.execute("DELETE FROM samples WHERE ts<?", (cutoff,))
        conn.execute("DELETE FROM categories WHERE ts<?", (cutoff,))
        conn.execute("DELETE FROM unified_records WHERE started<?", (cutoff,))


def merge_whole(live, conn, now):
    """Overlay immutable expired cards without inflating current totals."""
    result = dict(live)
    result["servers"] = dict(live.get("servers") or {})
    result["summary"] = dict(live.get("summary") or {})
    result["retired_services"] = {}
    found = set()
    try:
        saved = conn.execute(
            "SELECT service,kind,expires_at,freeze_at,captured_at,measured_at,"
            "snapshot_json FROM expiry_snapshots").fetchall()
    except sqlite3.OperationalError as exc:
        if "no such table: expiry_snapshots" not in str(exc):
            raise
        saved = []
    for service, kind, expiry, cutoff, captured, measured, raw in saved:
        if int(now) < int(expiry):
            continue
        found.add(service)
        snapshot = json.loads(raw)
        metadata = {"expired": True, "expires_at": expiry, "freeze_at": cutoff,
                    "captured_at": captured, "last_measured_at": measured}
        if kind == "host":
            old = result["servers"].get(service) or {}
            if old.get("sampled_at"):
                for current, field in (("today_in", "today_in"),
                                       ("today_out", "today_out"),
                                       ("month_in", "in"), ("month_out", "out")):
                    result["summary"][current] = max(
                        0, int(result["summary"].get(current) or 0)
                        - int(old.get(field) or 0))
            card = dict(snapshot)
            card.update(metadata)
            result["servers"][service] = card
        else:
            result["retired_services"][service] = dict(snapshot, **metadata)
            if service in ("ip2up.com", "proxyhive.io"):
                _overlay_static(result, service, snapshot, metadata)
    # If the collector is late or unavailable at midnight, do not display
    # post-expiry live numbers as a supposed frozen snapshot.
    for service in EXPIRY_DATES:
        if service in found or int(now) < expires_at(service):
            continue
        pending = {"expired": True, "snapshot_pending": True,
                   "expires_at": expires_at(service),
                   "freeze_at": freeze_at(service), "last_measured_at": None}
        if service in HOST_SERVICES:
            old = result["servers"].get(service) or {}
            if old.get("sampled_at"):
                for current, field in (("today_in", "today_in"),
                                       ("today_out", "today_out"),
                                       ("month_in", "in"), ("month_out", "out")):
                    result["summary"][current] = max(
                        0, int(result["summary"].get(current) or 0)
                        - int(old.get(field) or 0))
            result["servers"][service] = dict(_empty_card(), **pending)
        else:
            result["retired_services"][service] = dict(
                {"ingresses": {}, "note": "冻结快照待核实。"}, **pending)
            if service in ("ip2up.com", "proxyhive.io"):
                _overlay_static(result, service, {}, pending)
    return result
