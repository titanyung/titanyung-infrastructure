#!/usr/bin/env python3
"""Idempotent production expiry capture after Singapore midnight or reboot."""

import os
import sqlite3
import time


PRODUCTION_DB = "/var/lib/sg-traffic-dashboard/whole.db"


def capture_once(db_path, now, ensure_schema, capture_due):
    if not os.path.isfile(db_path):
        raise ValueError("Production whole.db absent")
    conn = sqlite3.connect(db_path, timeout=15)
    try:
        conn.execute("PRAGMA busy_timeout=15000")
        ensure_schema(conn)
        saved = capture_due(conn, now)
        conn.commit()
        return saved
    finally:
        conn.close()


def main():
    db_path = os.environ.get("WHOLE_TRAFFIC_DB", PRODUCTION_DB)
    if os.path.realpath(db_path) != os.path.realpath(PRODUCTION_DB):
        raise SystemExit("Production whole.db required")
    if os.environ.get("EXPIRY_STAGE_PREVIEW_NOW") or os.environ.get(
            "EXPIRY_STAGE_FIXTURE_ONLY"):
        raise SystemExit("Fixture clock forbidden in production")
    from expiry_stage import capture_due, ensure_schema
    saved = capture_once(db_path, int(time.time()), ensure_schema, capture_due)
    print("production_expiry_capture_ok=yes new_snapshots=%d" % len(saved))


if __name__ == "__main__":
    main()
