#!/usr/bin/env python3
from pathlib import Path
from datetime import datetime, timedelta, timezone
import sqlite3
import os

RETENTION_DAYS = 7
CUTOFF = datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)

DB_CANDIDATES = [
    "/var/lib/submerge/security.db",
    "/var/lib/submerge/security.sqlite3",
    "/var/lib/submerge/submerge_security.db",
    "/var/lib/submerge/submerge_security.sqlite3",
    "/var/lib/submerge/security_admin.db",
    "/var/lib/submerge/security_admin.sqlite3",
]

ACCESS_LOG_DIRS = [
    "/var/log/submerge-access",
]

TIME_COLS = [
    "created_at", "time", "minute", "ts", "timestamp",
    "date_time", "access_time", "log_time", "last_pull_time",
]

TABLE_KEYWORDS = [
    "subscription", "traffic", "access", "log", "logs", "minute"
]

def parse_dt(v):
    if v is None:
        return None

    if isinstance(v, (int, float)):
        # 兼容秒/毫秒
        if v > 10_000_000_000:
            v = v / 1000.0
        try:
            return datetime.fromtimestamp(v, timezone.utc)
        except Exception:
            return None

    s = str(v).strip()
    if not s:
        return None

    tries = []

    tries.append(s)
    if s.endswith("Z"):
        tries.append(s[:-1] + "+00:00")
    if " " in s and "T" not in s:
        tries.append(s.replace(" ", "T", 1))
        if s.endswith("Z"):
            tries.append(s[:-1].replace(" ", "T", 1) + "+00:00")

    for x in tries:
        try:
            dt = datetime.fromisoformat(x)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            pass

    fmts = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
    ]
    for fmt in fmts:
        try:
            dt = datetime.strptime(s, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            pass

    return None

def should_check_table(table_name, columns):
    name = table_name.lower()
    if any(k in name for k in TABLE_KEYWORDS):
        return True

    colset = {c.lower() for c in columns}
    interesting = {
        "subid", "ua", "ip", "bytes", "requests", "status",
        "unique_ips", "avg_request_time", "target_host", "protocol",
        "inbound"
    }
    return bool(colset & interesting)

def cleanup_sqlite(db_path):
    deleted_total = 0
    if not os.path.exists(db_path):
        return deleted_total

    conn = sqlite3.connect(db_path)
    try:
        tables = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        ]

        for table in tables:
            esc_table = table.replace('"', '""')
            cols_info = conn.execute(f'PRAGMA table_info("{esc_table}")').fetchall()
            cols = [r[1] for r in cols_info]
            if not cols:
                continue

            if not should_check_table(table, cols):
                continue

            time_col = None
            lower_map = {c.lower(): c for c in cols}
            for c in TIME_COLS:
                if c.lower() in lower_map:
                    time_col = lower_map[c.lower()]
                    break

            if not time_col:
                continue

            esc_col = time_col.replace('"', '""')

            try:
                rows = conn.execute(
                    f'SELECT rowid, "{esc_col}" FROM "{esc_table}"'
                ).fetchall()
            except Exception:
                continue

            to_delete = []
            for rowid, raw_time in rows:
                dt = parse_dt(raw_time)
                if dt and dt < CUTOFF:
                    to_delete.append((rowid,))

            if to_delete:
                conn.executemany(
                    f'DELETE FROM "{esc_table}" WHERE rowid=?',
                    to_delete
                )
                deleted_total += len(to_delete)
                print(f"[sqlite] {db_path} | {table} 删除 {len(to_delete)} 条")

        conn.commit()
    finally:
        conn.close()

    return deleted_total

def cleanup_access_files():
    removed = 0
    for d in ACCESS_LOG_DIRS:
        p = Path(d)
        if not p.exists():
            continue
        for f in p.glob("*"):
            if not f.is_file():
                continue
            try:
                mtime = datetime.fromtimestamp(f.stat().st_mtime, timezone.utc)
                if mtime < CUTOFF:
                    f.unlink(missing_ok=True)
                    removed += 1
                    print(f"[file] 删除 {f}")
            except Exception as e:
                print(f"[file] 跳过 {f}: {e}")
    return removed

def main():
    total_rows = 0
    for db in DB_CANDIDATES:
        try:
            total_rows += cleanup_sqlite(db)
        except Exception as e:
            print(f"[sqlite] 清理失败 {db}: {e}")

    removed_files = cleanup_access_files()

    print("====================================")
    print("7天清理完成")
    print("删除数据库记录:", total_rows)
    print("删除日志文件:", removed_files)
    print("截止时间(UTC):", CUTOFF.isoformat())
    print("====================================")

if __name__ == "__main__":
    main()
