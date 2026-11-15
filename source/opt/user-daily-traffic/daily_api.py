"""Read-only, loopback API for the per-user daily application-traffic ledger."""
from __future__ import annotations

import json
import os
import sqlite3
import urllib.parse
from datetime import date, datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from daily_accounting import read_daily

SG = timezone(timedelta(hours=8), "Asia/Singapore")
DB_PATH = os.environ.get("USER_DAILY_DB", "/var/lib/user-daily-traffic/daily.db")
PORT = int(os.environ.get("USER_DAILY_PORT", "18113"))


def parse_query(raw):
    query = urllib.parse.parse_qs(raw, keep_blank_values=True)
    if set(query) - {"from", "to", "user", "limit", "offset"}:
        raise ValueError("unknown filter")
    if any(len(values) != 1 for values in query.values()):
        raise ValueError("duplicate filter")
    today = datetime.now(SG).date()
    start = date.fromisoformat(query.get("from", [today.isoformat()])[0])
    end = date.fromisoformat(query.get("to", [today.isoformat()])[0])
    if start > end or (end - start).days > 30 or end > today:
        raise ValueError("date range must be within 31 days and not in the future")
    user = query.get("user", [""])[0]
    if len(user) > 128 or any(ord(char) < 32 for char in user):
        raise ValueError("invalid user")
    limit = int(query.get("limit", ["100"])[0])
    offset = int(query.get("offset", ["0"])[0])
    if not 1 <= limit <= 200 or not 0 <= offset <= 100000:
        raise ValueError("invalid pagination")
    return start.isoformat(), end.isoformat(), user, limit, offset


class Handler(BaseHTTPRequestHandler):
    server_version = "DailyUserTraffic/1"

    def log_message(self, *_):
        return

    def send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/health":
            return self.send_json(200 if Path(DB_PATH).is_file() else 503,
                                  {"ok": Path(DB_PATH).is_file(), "timezone": "Asia/Singapore"})
        if parsed.path != "/api/user-daily":
            return self.send_json(404, {"error": "not_found"})
        try:
            start, end, user, limit, offset = parse_query(parsed.query)
        except (ValueError, TypeError):
            return self.send_json(400, {"error": "invalid_filter"})
        try:
            if not Path(DB_PATH).is_file():
                return self.send_json(503, {"error": "daily_ledger_not_ready"})
            payload = read_daily(DB_PATH, start, end, user=user, limit=limit, offset=offset)
            payload.update({"from": start, "to": end, "limit": limit, "offset": offset})
            return self.send_json(200, payload)
        except (sqlite3.Error, OSError, ValueError):
            return self.send_json(503, {"error": "daily_ledger_unavailable"})

    def do_POST(self):
        return self.send_json(405, {"error": "read_only"})


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
