#!/usr/bin/env python3
"""Print only non-sensitive shape and latency of the local production API."""

import json
import time
import urllib.request


ORIGIN = "http://127.0.0.1:8099"


def fetch(path, timeout):
    started = time.monotonic()
    with urllib.request.urlopen(ORIGIN + path, timeout=timeout) as response:
        body = response.read()
        status = response.status
    return status, round(time.monotonic() - started, 3), body


def main():
    status, elapsed, _ = fetch("/api/health", 10)
    print("health_status=%d health_seconds=%s" % (status, elapsed))
    status, elapsed, body = fetch("/api/data", 45)
    payload = json.loads(body)
    whole = payload.get("whole") or {}
    print("data_status=%d data_seconds=%s bytes=%d" %
          (status, elapsed, len(body)))
    print("top_keys=" + ",".join(sorted(payload)))
    print("summary_keys=" + ",".join(sorted(payload.get("summary") or {})))
    for name in ("users", "sources", "events", "records", "record_users"):
        print("%s_count=%d" % (name, len(payload.get(name) or [])))
    print("whole_server_count=%d" % len(whole.get("servers") or {}))
    print("records_total=" + str(payload.get("records_total")))


if __name__ == "__main__":
    main()
