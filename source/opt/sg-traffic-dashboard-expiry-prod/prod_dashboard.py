#!/usr/bin/env python3
"""Expiry overlay for the existing production dashboard, without replacing it.

The original app continues to build the complete aggregate payload, including
live connections, blocks, users, remote sources and 30-day records.  Only its
whole-host card builder is overlaid with immutable expiry snapshots.
"""

import importlib.util
import os
import sqlite3
import time
import urllib.parse
from contextlib import closing
from pathlib import Path


PRODUCTION_DB = "/var/lib/sg-traffic-dashboard/whole.db"
PRODUCTION_APP = "/opt/sg-traffic-dashboard/app.py"
PRODUCTION_PORT = 8099
SCRIPT_PATH = "/expiry-archive.js"
SCRIPT_TAG = '<script src="%s"></script>' % SCRIPT_PATH


def require_production_target():
    db_path = os.environ.get("WHOLE_TRAFFIC_DB", PRODUCTION_DB)
    port = int(os.environ.get("TRAFFIC_PORT", str(PRODUCTION_PORT)))
    app_path = os.environ.get("DASHBOARD_BASE_APP", PRODUCTION_APP)
    if os.path.realpath(db_path) != os.path.realpath(PRODUCTION_DB):
        raise SystemExit("Production whole.db required")
    if port != PRODUCTION_PORT:
        raise SystemExit("Production port required")
    if os.path.realpath(app_path) != os.path.realpath(PRODUCTION_APP):
        raise SystemExit("Audited production app required")
    if os.environ.get("EXPIRY_STAGE_PREVIEW_NOW") or os.environ.get(
            "EXPIRY_STAGE_FIXTURE_ONLY"):
        raise SystemExit("Fixture clock forbidden in production")
    return db_path, port, app_path


def readonly_db(path):
    return sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro",
                           uri=True, timeout=5)


def configure(base, db_path, merge_whole, js_path):
    """Return a handler while retaining the audited app's aggregate route."""
    original_whole = base.whole_payload

    def expiry_whole_payload():
        live = original_whole()
        if not os.path.isfile(db_path):
            return live
        with closing(readonly_db(db_path)) as conn:
            return merge_whole(live, conn, int(time.time()))

    # aggregate_payload() resolves this module global at request time.  It
    # still performs the original local/remote aggregation and record query.
    base.whole_payload = expiry_whole_payload

    class ProductionExpiryHandler(base.Handler):
        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path not in ("/", SCRIPT_PATH):
                return super().do_GET()
            # Preserve the audited handler's direct-loopback rate limit.  The
            # public Nginx Basic Auth remains upstream and is not changed.
            ip = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()
            if base.rate_limited(ip):
                return self.send_common(429, "text/plain; charset=utf-8",
                                        b"Too many requests")
            if parsed.path == SCRIPT_PATH:
                with open(js_path, "rb") as source:
                    body = source.read()
                return self.send_common(200, "text/javascript; charset=utf-8", body)
            if os.path.isfile(base.PAGE_PATH):
                with open(base.PAGE_PATH, "r", encoding="utf-8") as source:
                    page = source.read()
            else:
                page = base.PAGE
            if SCRIPT_TAG not in page:
                if "</body>" not in page:
                    return self.send_common(500, "text/plain; charset=utf-8",
                                            b"Page insertion point absent")
                page = page.replace("</body>", SCRIPT_TAG + "</body>", 1)
            return self.send_common(200, "text/html; charset=utf-8", page.encode())

    return ProductionExpiryHandler


def main():
    db_path, port, app_path = require_production_target()
    spec = importlib.util.spec_from_file_location("audited_production_app", app_path)
    if spec is None or spec.loader is None:
        raise SystemExit("Audited production app unavailable")
    base = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(base)
    from expiry_stage import merge_whole
    js_path = os.path.join(os.path.dirname(__file__), "expiry-ui.js")
    if not os.path.isfile(js_path):
        raise SystemExit("Expiry UI script unavailable")
    handler = configure(base, db_path, merge_whole, js_path)
    base.ThreadingHTTPServer(("127.0.0.1", port), handler).serve_forever()


if __name__ == "__main__":
    main()
