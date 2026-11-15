#!/usr/bin/env python3
import collections
import os
import re
import sqlite3
import subprocess
import time

DB = os.environ.get("TRAFFIC_DB", "/var/lib/hk-traffic-dashboard/traffic.db")
API_URL = os.environ.get("BOX_API_URL", "http://127.0.0.1:10086")
NOSLA_API_URL = os.environ.get("NOSLA_API_URL", "http://216.23.117.226:10087")
NOSLA_SECRET_FILE = os.environ.get(
    "NOSLA_API_SECRET_FILE",
    "/etc/hk-traffic-dashboard/nosla-api.secret",
)
NOSLA_IP = "216.23.117.226"
HK_ISP_IP = "61.15.36.199"
BWH_IP = "45.78.70.23"
RELAY_PATH = "NoSLA 三网 · 中转至：bytevirt-HK ISP"
POLL = float(os.environ.get("POLL_INTERVAL", "1"))
RETENTION_DAYS = 30
ANSI = re.compile(r"\x1b\[[0-9;]*m")
SIZE_RE = re.compile(r"([0-9]+(?:\.[0-9]+)?)\s*(B|KB|KIB|MB|MIB|GB|GIB|TB|TIB)", re.I)
UNITS = {"B": 1, "KB": 1000, "KIB": 1024, "MB": 1000**2, "MIB": 1024**2,
         "GB": 1000**3, "GIB": 1024**3, "TB": 1000**4, "TIB": 1024**4}


def connect():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    db = sqlite3.connect(DB, timeout=20)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")
    db.executescript("""
    CREATE TABLE IF NOT EXISTS traffic_hourly (
      hour INTEGER NOT NULL,
      user TEXT NOT NULL,
      upload INTEGER NOT NULL DEFAULT 0,
      download INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (hour, user)
    );
    CREATE TABLE IF NOT EXISTS traffic_hourly_route (
      hour INTEGER NOT NULL,
      user TEXT NOT NULL,
      route_class TEXT NOT NULL,
      upload INTEGER NOT NULL DEFAULT 0,
      download INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (hour, user, route_class)
    );
    CREATE TABLE IF NOT EXISTS access_records (
      id TEXT PRIMARY KEY,
      user TEXT NOT NULL,
      source TEXT,
      destination TEXT,
      path TEXT NOT NULL DEFAULT 'ByteVirt 香港 ISP',
      protocol TEXT,
      started INTEGER NOT NULL,
      last_seen INTEGER NOT NULL,
      ended INTEGER,
      upload INTEGER NOT NULL DEFAULT 0,
      download INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'active'
    );
    CREATE INDEX IF NOT EXISTS idx_access_user_started ON access_records(user, started DESC);
    CREATE INDEX IF NOT EXISTS idx_access_started ON access_records(started DESC);
    CREATE TABLE IF NOT EXISTS security_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts INTEGER NOT NULL,
      user TEXT,
      source TEXT,
      kind TEXT NOT NULL,
      detail TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_security_ts ON security_events(ts DESC);
    """)
    columns = {row[1] for row in db.execute("PRAGMA table_info(access_records)")}
    if "path" not in columns:
        db.execute(
            "ALTER TABLE access_records "
            "ADD COLUMN path TEXT NOT NULL DEFAULT 'ByteVirt 香港 ISP'"
        )
    if "route_class" not in columns:
        db.execute(
            "ALTER TABLE access_records "
            "ADD COLUMN route_class TEXT NOT NULL DEFAULT 'bytevirt_direct'"
        )
    db.execute("UPDATE access_records SET route_class='nosla', path='NoSLA 三网' "
               "WHERE path IN ('NoSLA', 'NoSLA 三网')")
    db.execute("UPDATE access_records SET route_class='bytevirt_hk_isp', path=? "
               "WHERE path IN ('NoSLA → ByteVirt 香港 ISP', ?)",
               (RELAY_PATH, RELAY_PATH))
    db.execute("UPDATE access_records SET route_class='bytevirt_direct', "
               "path='ByteVirt 香港 ISP（直连，未经过 NoSLA）' "
               "WHERE path='ByteVirt 香港 ISP'")
    db.commit()
    return db


def size_bytes(text):
    found = SIZE_RE.findall(text or "")
    vals = [int(float(v) * UNITS[u.upper()]) for v, u in found]
    if len(vals) >= 2:
        return vals[-2], vals[-1]
    if len(vals) == 1:
        return 0, vals[0]
    nums = re.findall(r"\b\d+\b", text or "")
    return (0, int(nums[-1])) if nums else (0, 0)


def read_secret(path):
    try:
        with open(path, "r", encoding="utf-8") as file:
            return file.read().strip()
    except Exception:
        return ""


def list_connections(api_url, source_name, secret=""):
    cmd = [
        "/usr/bin/sing-box", "api", "--url", api_url,
    ]
    if secret:
        cmd.extend(["--secret", secret])
    cmd.extend([
        "connection", "list", "--columns",
        "id,user,source,destination,protocol,total",
    ])
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, timeout=5)
    if proc.returncode:
        return []
    rows = []
    for raw in proc.stdout.splitlines():
        line = ANSI.sub("", raw).strip()
        if not line or line.upper().startswith("ID ") or line.upper() == "ID":
            continue
        parts = re.split(r"\s{2,}", line, maxsplit=5)
        if len(parts) < 5:
            parts = line.split(None, 5)
        if len(parts) < 5:
            continue
        while len(parts) < 6:
            parts.append("")
        raw_cid, user, source, destination, protocol, total = parts[:6]
        if not raw_cid or raw_cid.lower() in {"id", "no"}:
            continue
        cid = f"{source_name}:{raw_cid}"
        if source_name == "nosla" and destination.startswith(HK_ISP_IP + ":2443"):
            route_class, path = "bytevirt_hk_isp", RELAY_PATH
        elif source_name == "nosla":
            route_class, path = "nosla", "NoSLA 三网"
        elif source.startswith(NOSLA_IP + ":"):
            route_class, path = "bytevirt_hk_isp", RELAY_PATH
        elif source.startswith(BWH_IP + ":"):
            route_class, path = "bwh_bytevirt_hk_isp", "BWHLA · 中转至：bytevirt-HK ISP"
        else:
            route_class = "bytevirt_direct"
            path = "ByteVirt 香港 ISP（直连，未经过 NoSLA）"
        up, down = size_bytes(total)
        rows.append({
            "id": cid,
            "raw_id": raw_cid,
            "user": user or "unknown",
            "source": source,
            "destination": destination,
            "protocol": protocol or "unknown",
            "path": path,
            "route_class": route_class,
            "api_url": api_url,
            "api_secret": secret,
            "upload": up,
            "download": down,
        })
    return rows


def close_connection(row):
    cmd = ["/usr/bin/sing-box", "api", "--url", row["api_url"]]
    if row.get("api_secret"):
        cmd.extend(["--secret", row["api_secret"]])
    cmd.extend(["connection", "close", row["raw_id"]])
    subprocess.run(cmd, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=4)


def event(db, now, row, kind, detail):
    db.execute("INSERT INTO security_events(ts,user,source,kind,detail) VALUES(?,?,?,?,?)",
               (now, row.get("user"), row.get("source"), kind, detail))


def main():
    db = connect()
    nosla_secret = read_secret(NOSLA_SECRET_FILE)
    previous = {}
    recent_destinations = collections.defaultdict(collections.deque)
    last_cleanup = 0
    while True:
        now = int(time.time())
        try:
            rows = list_connections(API_URL, "hk")
            if nosla_secret:
                rows.extend(list_connections(NOSLA_API_URL, "nosla", nosla_secret))
            current = {}
            for row in rows:
                cid = row["id"]
                current[cid] = row
                # A connection may predate a collector restart or a dashboard
                # reset. Its existing lifetime bytes are a baseline, not new
                # traffic since this collector began observing it.
                old = previous.get(cid, row)
                du = max(0, row["upload"] - old["upload"])
                dd = max(0, row["download"] - old["download"])
                hour = now - now % 3600
                db.execute("""
                    INSERT INTO traffic_hourly(hour,user,upload,download) VALUES(?,?,?,?)
                    ON CONFLICT(hour,user) DO UPDATE SET
                      upload=upload+excluded.upload, download=download+excluded.download
                """, (hour, row["user"], du, dd))
                db.execute("""
                    INSERT INTO traffic_hourly_route(hour,user,route_class,upload,download)
                    VALUES(?,?,?,?,?)
                    ON CONFLICT(hour,user,route_class) DO UPDATE SET
                      upload=upload+excluded.upload, download=download+excluded.download
                """, (hour, row["user"], row["route_class"], du, dd))
                db.execute("""
                    INSERT INTO access_records(id,user,source,destination,path,route_class,protocol,started,last_seen,upload,download,status)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,'active')
                    ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen,
                      path=excluded.path, route_class=excluded.route_class,
                      upload=access_records.upload+excluded.upload,
                      download=access_records.download+excluded.download,
                      status='active', ended=NULL
                """, (cid, row["user"], row["source"], row["destination"],
                      row["path"], row["route_class"], row["protocol"], now, now,
                      du, dd))

                proto = row["protocol"].lower()
                if "bittorrent" in proto:
                    close_connection(row)
                    event(db, now, row, "bt-block", "BitTorrent connection rejected")
                elif row["download"] > 8 * 1024**3:
                    close_connection(row)
                    event(db, now, row, "bulk-download-block", "Single connection exceeded 8 GiB")

                dq = recent_destinations[row["user"]]
                dq.append((now, row["destination"]))
                while dq and dq[0][0] < now - 60:
                    dq.popleft()
                if len({d for _, d in dq}) > 160:
                    close_connection(row)
                    event(db, now, row, "scan-block", "More than 160 destinations in 60 seconds")
                    dq.clear()

            for cid, old in previous.items():
                if cid not in current:
                    db.execute("UPDATE access_records SET ended=?,status='closed' WHERE id=?",
                               (now, cid))
            previous = current

            if now - last_cleanup >= 3600:
                cutoff = now - RETENTION_DAYS * 86400
                db.execute("DELETE FROM traffic_hourly WHERE hour < ?", (cutoff,))
                db.execute("DELETE FROM traffic_hourly_route WHERE hour < ?", (cutoff,))
                db.execute("DELETE FROM access_records WHERE started < ?", (cutoff,))
                db.execute("DELETE FROM security_events WHERE ts < ?", (cutoff,))
                db.execute("UPDATE access_records SET ended=?,status='closed' WHERE status='active' AND last_seen < ?",
                           (now, now - 30))
                last_cleanup = now
            db.commit()
        except Exception as exc:
            try:
                with open("/var/log/hk-traffic-collector.log", "a", encoding="utf-8") as out:
                    # subprocess exceptions may embed --secret in their argv.
                    out.write(f"{now} {type(exc).__name__}\n")
            except Exception:
                pass
        time.sleep(POLL)


if __name__ == "__main__":
    main()
