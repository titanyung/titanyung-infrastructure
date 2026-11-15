"""One-time production start-date correction after confirming there are no bills."""

import sqlite3
from datetime import datetime


DATABASE = "/var/lib/ledger-system/ledger.db"
OLD_START = "2026-10-03 02:18:48"
NEW_START = "2026-10-13 00:00:00"


def main():
    if datetime.now().strftime("%Y-%m-%d") != "2026-10-13":
        raise SystemExit("Today is no longer 2026-10-13; stop and review")
    conn = sqlite3.connect(DATABASE, timeout=15)
    try:
        conn.execute("PRAGMA busy_timeout=15000")
        conn.execute("BEGIN IMMEDIATE")
        old = conn.execute("SELECT started_at FROM settings WHERE id=1").fetchone()[0]
        bills = conn.execute("SELECT COUNT(*) FROM bills").fetchone()[0]
        ingests = conn.execute("SELECT COUNT(*) FROM ingest_requests").fetchone()[0]
        if old != OLD_START or bills != 0 or ingests != 0:
            raise RuntimeError("Ledger state changed; no start-date update made")
        conn.execute("UPDATE settings SET started_at=? WHERE id=1", (NEW_START,))
        conn.commit()
        print("Ledger formal start:", NEW_START, "(no bills deleted)")
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()
